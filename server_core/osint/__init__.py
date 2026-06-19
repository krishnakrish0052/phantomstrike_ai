"""
server_core/osint/ — PhantomStrike OSINT Intelligence Engine

Provides unified OSINT capabilities:
  - IP intelligence (geolocation, Shodan, Censys, proxy/VPN detection)
  - Phone number tracing (carrier, location, line type, validation)
  - Email intelligence (breach lookup, verification, MX checks)
  - Social media profiling (cross-platform account discovery)
  - Dark web monitoring (.onion scanning, threat actor tracking)
  - People search (aggregated public records)
  - Domain intelligence (WHOIS history, DNS history, cert transparency)
"""

from .ip_intel import IPIntel
from .phone_tracer import PhoneTracer
from .email_tracer import EmailTracer
from .social_profiler import SocialProfiler
from .dark_web_monitor import DarkWebMonitor

__all__ = [
  "IPIntel",
  "PhoneTracer",
  "EmailTracer",
  "SocialProfiler",
  "DarkWebMonitor",
]
