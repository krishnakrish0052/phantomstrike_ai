"""
server_core/undetectable/ — PhantomStrike Undetectable Proxy Engine

Routes ALL tool traffic through continuously rotating identities:
  - PhantomProxy — SOCKS5 proxy server (:9051) for transparent routing
  - IPRotator — Tor circuit rotation + residential proxy pool + WireGuard mesh
  - TrafficCamouflage — Protocol impersonation, JA3/JA4 randomization
  - ProxyConfig — Configuration profiles for different stealth levels
"""

from .phantom_proxy import PhantomProxy
from .ip_rotator import IPRotator

__all__ = ["PhantomProxy", "IPRotator"]
