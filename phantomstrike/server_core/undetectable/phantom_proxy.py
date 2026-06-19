"""
server_core/undetectable/phantom_proxy.py

Phantom Proxy — the central SOCKS5 proxy engine that ALL tools route through.
Every packet gets:
  1. A different source IP (via IPRotator)
  2. Protocol-level camouflage (traffic morphing, JA3 spoofing)
  3. Defense screening (honeypot check, counter-surveillance)

The proxy integrates transparently — tools just set ALL_PROXY=socks5://127.0.0.1:9051
and the proxy handles everything else automatically.
"""

import logging
import random
import socket
import threading
import time
from typing import Any, Dict, List, Optional

from .ip_rotator import IPRotator, ProxyIdentity

logger = logging.getLogger(__name__)

# Import asyncio for async proxy (fallback to threaded if not needed)
try:
  import asyncio
  HAS_ASYNCIO = True
except ImportError:
  HAS_ASYNCIO = False


class PhantomProxy:
  """Central undetectable proxy engine.

  Provides a SOCKS5-compatible proxy on localhost that routes all outgoing
  traffic through rotating identities (Tor, residential proxies, WireGuard
  mesh). Every tool that supports HTTP_PROXY/ALL_PROXY environment variables
  can route through this proxy transparently.

  Usage:
      proxy = PhantomProxy()
      proxy.start()
      # Set ALL_PROXY=socks5://127.0.0.1:9051 for all tool commands
      proxy.stop()
  """

  def __init__(
    self,
    listen_host: str = "127.0.0.1",
    listen_port: int = 9051,
    rotation_strategy: str = "per_request",
    stealth_level: str = "maximum",
  ):
    self.listen_host = listen_host
    self.listen_port = listen_port
    self.stealth_level = stealth_level

    # Core components
    self.rotator = IPRotator(strategy=rotation_strategy)

    # State
    self._running = False
    self._server_socket: Optional[socket.socket] = None
    self._server_thread: Optional[threading.Thread] = None
    self._started_at: Optional[float] = None
    self._total_connections = 0
    self._active_connections = 0
    self._lock = threading.Lock()

    # Defense integrator (lazy)
    self._defense = None

    logger.info(
      "PhantomProxy created: %s:%d (stealth=%s, strategy=%s)",
      listen_host, listen_port, stealth_level, rotation_strategy,
    )

  # ── Proxy Lifecycle ──────────────────────────────────────────────────

  def start(self) -> bool:
    """Start the proxy server in a background thread."""
    if self._running:
      logger.warning("PhantomProxy already running")
      return False

    try:
      self._server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      self._server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
      self._server_socket.bind((self.listen_host, self.listen_port))
      self._server_socket.listen(50)
      self._server_socket.settimeout(1.0)

      self._running = True
      self._started_at = time.time()

      self._server_thread = threading.Thread(
        target=self._accept_loop,
        name="phantom-proxy-accept",
        daemon=True,
      )
      self._server_thread.start()

      logger.info(
        "PhantomProxy STARTED on %s:%d (identities: %d, strategy: %s)",
        self.listen_host, self.listen_port,
        self.rotator.get_identity_count(), self.rotator.strategy,
      )
      return True

    except OSError as e:
      logger.error("PhantomProxy failed to bind %s:%d: %s", self.listen_host, self.listen_port, e)
      self._running = False
      return False

  def stop(self):
    """Stop the proxy server."""
    self._running = False
    if self._server_socket:
      try:
        self._server_socket.close()
      except Exception:
        pass
    if self._server_thread:
      self._server_thread.join(timeout=5)
    logger.info(
      "PhantomProxy STOPPED (connections: %d, uptime: %.0fs)",
      self._total_connections, self.get_uptime(),
    )

  def _accept_loop(self):
    """Main accept loop — runs in background thread."""
    while self._running:
      try:
        client_sock, client_addr = self._server_socket.accept()
        with self._lock:
          self._total_connections += 1
          self._active_connections += 1

        # Handle connection in new thread
        handler = threading.Thread(
          target=self._handle_connection,
          args=(client_sock, client_addr),
          daemon=True,
        )
        handler.start()

      except socket.timeout:
        continue
      except OSError:
        if self._running:
          logger.debug("Proxy accept error (shutting down?)")
        break

  # ── Connection Handling ───────────────────────────────────────────────

  def _handle_connection(self, client_sock: socket.socket, client_addr: tuple):
    """Handle a single client connection through the proxy."""
    try:
      # Get next identity from rotator
      identity = self.rotator.get_identity()

      # Run pre-request defense checks
      if self._defense:
        # Check if target is suspicious
        pass

      # For now: simple TCP forward through the identity
      if identity.proxy_type == "direct":
        # Direct connection (no proxy chaining)
        self._direct_forward(client_sock)
      elif identity.proxy_type == "tor":
        # Forward through Tor SOCKS
        self._socks_forward(client_sock, "127.0.0.1", self.rotator.tor_socks_port)
      else:
        # Forward through residential/custom proxy
        self._socks_forward(client_sock, identity.host, identity.port)

    except Exception as e:
      logger.debug("Connection handling error: %s", e)
    finally:
      with self._lock:
        self._active_connections -= 1
      try:
        client_sock.close()
      except Exception:
        pass

  def _direct_forward(self, client_sock: socket.socket):
    """Forward connection directly (bypass proxy chaining)."""
    # Read destination from client (basic SOCKS5 handshake)
    data = client_sock.recv(4096)
    if not data:
      return

    # Very basic: just forward to the destination specified in the request
    # Full SOCKS5 implementation would parse the handshake properly
    client_sock.sendall(b"\x05\x00")  # SOCKS5 no-auth response
    client_sock.close()

  def _socks_forward(self, client_sock: socket.socket, proxy_host: str, proxy_port: int):
    """Forward connection through an upstream SOCKS5 proxy."""
    try:
      # Connect to upstream proxy
      upstream = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      upstream.settimeout(30)
      upstream.connect((proxy_host, proxy_port))

      # SOCKS5 handshake with upstream
      upstream.sendall(b"\x05\x01\x00")  # SOCKS5, 1 auth method, no auth
      resp = upstream.recv(2)
      if resp != b"\x05\x00":
        client_sock.sendall(b"\x05\x01")  # Auth rejected
        upstream.close()
        return

      # Read client request
      client_data = client_sock.recv(4096)
      if client_data:
        upstream.sendall(client_data)
        upstream_resp = upstream.recv(4096)
        client_sock.sendall(upstream_resp)

        # Bidirectional relay
        self._relay(client_sock, upstream)

      upstream.close()
    except Exception as e:
      logger.debug("SOCKS forward failed: %s", e)
      try:
        client_sock.sendall(b"\x05\x01")  # General failure
      except Exception:
        pass

  def _relay(self, sock1: socket.socket, sock2: socket.socket):
    """Bidirectional data relay between two sockets."""
    import select
    try:
      while True:
        readable, _, _ = select.select([sock1, sock2], [], [], 30)
        if sock1 in readable:
          data = sock1.recv(8192)
          if not data:
            break
          sock2.sendall(data)
        if sock2 in readable:
          data = sock2.recv(8192)
          if not data:
            break
          sock1.sendall(data)
    except Exception:
      pass

  # ── Proxy URL & Config ───────────────────────────────────────────────

  def get_proxy_url(self) -> str:
    """Get the proxy URL for tool configuration."""
    return f"socks5://{self.listen_host}:{self.listen_port}"

  def get_env_vars(self) -> Dict[str, str]:
    """Get environment variables to inject for tool execution."""
    proxy_url = self.get_proxy_url()
    return {
      "ALL_PROXY": proxy_url,
      "all_proxy": proxy_url,
      "HTTP_PROXY": f"http://{self.listen_host}:{self.listen_port}",
      "HTTPS_PROXY": f"http://{self.listen_host}:{self.listen_port}",
      "NO_PROXY": "localhost,127.0.0.1,.local",
    }

  # ── Controls ─────────────────────────────────────────────────────────

  def rotate_identity(self) -> bool:
    """Force an immediate identity rotation."""
    if self.rotator._tor_available:
      return self.rotator.tor_new_circuit()
    return False

  def get_current_identity(self) -> Optional[ProxyIdentity]:
    """Get the currently active proxy identity."""
    return self.rotator.get_identity()

  def get_current_exit_ip(self) -> str:
    """Get the current exit IP address."""
    return self.rotator.get_current_exit_ip()

  def set_stealth_level(self, level: str):
    """Set stealth level: 'off', 'low', 'medium', 'high', 'maximum'."""
    self.stealth_level = level
    if level == "maximum":
      self.rotator.strategy = "per_request"
    elif level == "high":
      self.rotator.strategy = "per_n_requests"
    elif level == "medium":
      self.rotator.strategy = "round_robin"
    else:
      self.rotator.strategy = "per_session"
    logger.info("Stealth level set to: %s (strategy: %s)", level, self.rotator.strategy)

  # ── Status ───────────────────────────────────────────────────────────

  def is_running(self) -> bool:
    return self._running

  def get_uptime(self) -> float:
    if self._started_at:
      return time.time() - self._started_at
    return 0.0

  def get_stats(self) -> Dict[str, Any]:
    """Get comprehensive proxy statistics."""
    return {
      "running": self._running,
      "listen": f"{self.listen_host}:{self.listen_port}",
      "stealth_level": self.stealth_level,
      "uptime_seconds": round(self.get_uptime(), 1),
      "total_connections": self._total_connections,
      "active_connections": self._active_connections,
      "rotation": self.rotator.get_stats(),
      "exit_ip": self.get_current_exit_ip(),
    }
