"""
server_core/undetectable/ip_rotator.py

IP Rotation Engine — continuously changing source identity for every request.
Supports Tor circuit rotation, residential proxy pools, WireGuard mesh,
and MAC address randomization to make traffic untraceable.
"""

import logging
import random
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class ProxyIdentity:
  """Single proxy hop identity."""
  proxy_type: str  # tor, residential, wireguard, custom
  host: str
  port: int
  username: str = ""
  password: str = ""
  exit_ip: str = ""
  country: str = ""
  isp: str = ""
  circuit_id: str = ""
  created_at: float = field(default_factory=time.time)
  request_count: int = 0
  max_requests: int = 50


class IPRotator:
  """Multi-source IP rotation engine.

  Rotates through Tor circuits, residential proxy pools, and WireGuard
  exit nodes. Each request gets a different source IP. Supports:
    - Tor circuit rotation (per-request or per-N-requests)
    - Residential proxy pool (BrightData, ProxyRack, etc.)
    - WireGuard mesh exit node rotation
    - Custom SOCKS5 proxy chaining
  """

  # Rotation strategies
  ROTATION_STRATEGIES = [
    "per_request",   # New identity for every request (maximum stealth)
    "per_n_requests", # New identity every N requests
    "per_session",    # New identity per tool session
    "round_robin",    # Cycle through available identities
    "random",         # Random identity per request
  ]

  def __init__(
    self,
    strategy: str = "per_request",
    max_per_identity: int = 50,
    tor_control_port: int = 9051,
    tor_socks_port: int = 9050,
    residential_proxies: Optional[List[Dict[str, Any]]] = None,
    wireguard_peers: Optional[List[Dict[str, Any]]] = None,
  ):
    self.strategy = strategy
    self.max_per_identity = max_per_identity
    self.tor_control_port = tor_control_port
    self.tor_socks_port = tor_socks_port

    self._residential_proxies = residential_proxies or []
    self._wireguard_peers = wireguard_peers or []
    self._identities: List[ProxyIdentity] = []
    self._current_index = 0
    self._lock = threading.Lock()
    self._circuit_counter = 0
    self._total_requests = 0
    self._tor_available = False

    self._init_identities()

  # ── Identity Initialization ──────────────────────────────────────────

  def _init_identities(self):
    """Build initial identity pool from available sources."""
    # Check Tor
    self._tor_available = self._check_tor()

    # Add Tor identities (virtual — each circuit rotation = new identity)
    if self._tor_available:
      for _ in range(3):
        self._identities.append(ProxyIdentity(
          proxy_type="tor",
          host="127.0.0.1",
          port=self.tor_socks_port,
        ))

    # Add residential proxy identities
    for rp in self._residential_proxies:
      self._identities.append(ProxyIdentity(
        proxy_type="residential",
        host=rp.get("host", ""),
        port=rp.get("port", 8080),
        username=rp.get("username", ""),
        password=rp.get("password", ""),
        country=rp.get("country", ""),
        isp=rp.get("isp", ""),
      ))

    # Add WireGuard peer identities
    for peer in self._wireguard_peers:
      self._identities.append(ProxyIdentity(
        proxy_type="wireguard",
        host=peer.get("endpoint", ""),
        port=peer.get("port", 51820),
        exit_ip=peer.get("exit_ip", ""),
      ))

    # Fallback: direct (no proxy) — used only when no other identities available
    if not self._identities:
      self._identities.append(ProxyIdentity(
        proxy_type="direct",
        host="", port=0,
      ))

    logger.info(
      "IPRotator initialized: %d identities (tor=%s, residential=%d, wg=%d, strategy=%s)",
      len(self._identities), self._tor_available,
      len(self._residential_proxies), len(self._wireguard_peers), self.strategy,
    )

  # ── Tor Check ────────────────────────────────────────────────────────

  def _check_tor(self) -> bool:
    """Check if Tor is running and controllable."""
    try:
      import socket
      s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      s.settimeout(2)
      result = s.connect_ex(("127.0.0.1", self.tor_socks_port))
      s.close()
      if result == 0:
        logger.info("Tor SOCKS proxy detected on port %d", self.tor_socks_port)
        return True
    except Exception:
      pass

    try:
      s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      s.settimeout(2)
      result = s.connect_ex(("127.0.0.1", 9050))
      s.close()
      if result == 0:
        self.tor_socks_port = 9050
        logger.info("Tor SOCKS proxy detected on port 9050")
        return True
    except Exception:
      pass

    logger.info("Tor not detected — will use available identities only")
    return False

  def tor_new_circuit(self) -> bool:
    """Request a new Tor circuit via control port."""
    try:
      from stem import Signal
      from stem.control import Controller

      with Controller.from_port(port=self.tor_control_port) as controller:
        controller.authenticate()
        controller.signal(Signal.NEWNYM)
        self._circuit_counter += 1
        logger.debug("Tor circuit rotated (#%d)", self._circuit_counter)
        return True
    except ImportError:
      logger.debug("Stem library not installed — Tor circuit rotation unavailable")
      return False
    except Exception as e:
      logger.debug("Tor circuit rotation failed: %s", e)
      return False

  # ── Identity Selection ───────────────────────────────────────────────

  def get_identity(self) -> ProxyIdentity:
    """Get the next identity based on rotation strategy."""
    with self._lock:
      self._total_requests += 1

      if not self._identities:
        return ProxyIdentity(proxy_type="direct", host="", port=0)

      if self.strategy == "per_request":
        # Rotate Tor circuit if available, then cycle identity
        if self._tor_available:
          self.tor_new_circuit()
        identity = self._identities[self._current_index % len(self._identities)]
        self._current_index += 1

      elif self.strategy == "per_n_requests":
        identity = self._identities[self._current_index % len(self._identities)]
        identity.request_count += 1
        if identity.request_count >= self.max_per_identity:
          self._current_index += 1
          if self._tor_available:
            self.tor_new_circuit()

      elif self.strategy == "round_robin":
        identity = self._identities[self._current_index % len(self._identities)]
        self._current_index += 1

      elif self.strategy == "random":
        identity = random.choice(self._identities)

      else:  # per_session or default
        identity = self._identities[self._current_index % len(self._identities)]

      return identity

  def get_current_exit_ip(self) -> str:
    """Get the current exit IP by making a request through the proxy."""
    try:
      import requests
      identity = self.get_identity()
      if identity.proxy_type == "tor":
        proxies = {"http": f"socks5h://127.0.0.1:{self.tor_socks_port}",
                   "https": f"socks5h://127.0.0.1:{self.tor_socks_port}"}
        resp = requests.get("https://check.torproject.org/api/ip", proxies=proxies, timeout=10)
        data = resp.json()
        return data.get("IP", "unknown")
      elif identity.proxy_type == "direct":
        resp = requests.get("https://api.ipify.org?format=json", timeout=5)
        return resp.json().get("ip", "unknown")
      else:
        return identity.exit_ip or "unknown"
    except Exception:
      return "unknown"

  # ── Status & Stats ───────────────────────────────────────────────────

  def get_stats(self) -> Dict[str, Any]:
    """Get current rotation statistics."""
    return {
      "total_requests": self._total_requests,
      "total_identities": len(self._identities),
      "current_index": self._current_index,
      "strategy": self.strategy,
      "tor_available": self._tor_available,
      "tor_circuits_rotated": self._circuit_counter,
      "identities": [
        {
          "type": i.proxy_type,
          "host": i.host,
          "port": i.port,
          "country": i.country,
          "request_count": i.request_count,
        }
        for i in self._identities[:10]
      ],
    }

  def add_residential_proxy(self, host: str, port: int, username: str = "", password: str = ""):
    """Add a residential proxy to the pool."""
    with self._lock:
      self._residential_proxies.append({"host": host, "port": port, "username": username, "password": password})
      self._identities.append(ProxyIdentity(
        proxy_type="residential", host=host, port=port, username=username, password=password,
      ))
      logger.info("Added residential proxy: %s:%d (total: %d)", host, port, len(self._identities))

  def get_identity_count(self) -> int:
    return len(self._identities)
