"""
Honeypot Detector — identifies honeypots before engagement.

Detection methods:
  - Known honeypot IP ranges (Cowrie, Conpot, Dionaea, Kippo, etc.)
  - Banner pattern matching for common honeypot daemons
  - GreyNoise API integration
  - Port-pattern heuristics (all 65535 ports open = likely honeypot)
  - Shodan honeyscore fallback
"""

import ipaddress
import logging
import re
import socket
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)

# ── Known honeypot IP ranges ────────────────────────────────────────────────
# Based on public research and common honeypot deployments
KNOWN_HONEYPOT_RANGES: List[str] = [
    # Cowrie / SSH honeypots
    "5.9.0.0/16",        # Hetzner (common honeypot host)
    "192.42.116.0/22",   # SURFnet honeypot research
    "91.121.0.0/16",     # OVH (common honeypot deployments)
    "78.46.0.0/15",      # Hetzner range
    "188.40.0.0/16",     # Hetzner range
    "46.4.0.0/16",       # Hetzner range
    "176.9.0.0/16",      # Hetzner range
    # Known honeypot-as-a-service ranges
    "104.16.0.0/12",     # Cloudflare (SH service hosts)
    "104.234.0.0/16",    # AbuseCH deployment range
]

# ── Honeypot banner signatures ──────────────────────────────────────────────
# Regex patterns that match known honeypot service banners
HONEYPOT_BANNER_PATTERNS: Dict[str, re.Pattern] = {
    "cowrie": re.compile(
        r"(?i)(cowrie|kippo|sshesame|honeytrap)",
    ),
    "conpot": re.compile(
        r"(?i)(conpot|siemens.*simatic|modbus.*honeypot)",
    ),
    "dionaea": re.compile(
        r"(?i)(dionaea|nepenthes|mwcollect|mwc\d)",
    ),
    "glutton": re.compile(
        r"(?i)(glutton.*honeypot)",
    ),
    "elasticpot": re.compile(
        r"(?i)(elasticpot|elastichoney)",
    ),
    "honeyd": re.compile(
        r"(?i)(honeyd|honeynet.*virtual)",
    ),
    "t-pot": re.compile(
        r"(?i)(t-pot|tpotce|deutsche telekom.*honeypot)",
    ),
    "mailoney": re.compile(
        r"(?i)(mailoney|smtp.*honeypot)",
    ),
    "heralding": re.compile(
        r"(?i)(heralding|capture.*credentials.*honeypot)",
    ),
    "ciscoasa": re.compile(
        r"(?i)(ciscoasa.*honeypot)",
    ),
    "wordpot": re.compile(
        r"(?i)(wordpot|wp.*honeypot|snap.*honeypot)",
    ),
}

# ── Known honeypot hostnames ────────────────────────────────────────────────
KNOWN_HONEYPOT_HOSTNAMES: Set[str] = {
    "honeypot", "honeynet", "trap", "decoy", "honeytrap",
    "cowrie", "dionaea", "conpot", "glutton",
    "kippo", "kippo2", "nepenthes", "mwcollect",
}

# ── Known honeypot provider ASNs ────────────────────────────────────────────
KNOWN_HONEYPOT_ASNS: Set[int] = {
    24940,   # Hetzner Online GmbH
    16276,   # OVH SAS
    12876,   # Online S.A.S. (Scaleway)
    14061,   # DigitalOcean (popular for honeypots)
    20473,   # Vultr
}


class HoneypotDetector:
    """Detects honeypots using multiple layered approaches.

    Methods (in priority order):
      1. Known IP range static check (fast, offline)
      2. Hostname pattern check
      3. GreyNoise API lookup (community + RIOT)
      4. Port-pattern heuristic (all-ports-open detection)
      5. Banner signature matching (post-connection)
    """

    def __init__(self):
        self._known_ranges: List[ipaddress.IPv4Network] = []
        for cidr in KNOWN_HONEYPOT_RANGES:
            try:
                self._known_ranges.append(ipaddress.IPv4Network(cidr))
            except ValueError as exc:
                logger.warning("Invalid honeypot CIDR %s: %s", cidr, exc)

        self._greynoise_api_key: Optional[str] = None
        self._shodan_api_key: Optional[str] = None

        # Attempt to load API keys from config
        try:
            import server_core.config_core as config_core
            self._greynoise_api_key = config_core.get("GREYNOISE_API_KEY", None)
            self._shodan_api_key = config_core.get("SHODAN_API_KEY", None)
        except Exception:
            pass

        # Cache for API results to avoid redundant lookups
        self._cache: Dict[str, bool] = {}
        self._cache_lock = __import__('threading').Lock()

    # ── Public API ──────────────────────────────────────────────────────────

    def is_honeypot(self, target: str) -> bool:
        """Primary entry point. Returns True if the target is likely a honeypot.

        Checks run in order from fastest/cheapest to slowest/most expensive.
        First positive match short-circuits.
        """
        target = target.strip()
        if not target:
            return False

        # Check cache
        with self._cache_lock:
            if target in self._cache:
                return self._cache[target]

        result = False

        # Layer 1: Known IP range
        if self._check_ip_range(target):
            result = True

        # Layer 2: Hostname pattern
        elif self._check_hostname_pattern(target):
            result = True

        # Layer 3: GreyNoise (if API key available)
        elif not result and self._greynoise_api_key:
            try:
                if self._check_greynoise(target):
                    result = True
            except Exception:
                pass

        # Layer 4: Shodan Honeyscore (if API key available)
        elif not result and self._shodan_api_key:
            try:
                if self._check_shodan_honeyscore(target):
                    result = True
            except Exception:
                pass

        with self._cache_lock:
            self._cache[target] = result

        if result:
            logger.warning("HoneypotDetector: %s classified as honeypot", target)

        return result

    def check_banner(self, banner_text: str) -> Optional[str]:
        """Check a service banner against known honeypot signatures.

        Returns the name of the matched honeypot type, or None if clean.
        """
        for name, pattern in HONEYPOT_BANNER_PATTERNS.items():
            if pattern.search(banner_text):
                logger.warning("HoneypotDetector: banner matched %s", name)
                return name
        return None

    def check_port_pattern(self, host: str, open_ports: List[int]) -> bool:
        """Check if port pattern indicates a honeypot.

        Heuristics:
          - All ports open (simulated host)
          - Very high number of open ports (>1000)
          - All ports reporting identical service banners
        """
        if len(open_ports) > 1000:
            logger.warning("HoneypotDetector: %s has %d open ports — suspicious", host, len(open_ports))
            return True

        # Check for "all ports open" pattern (65535 ports)
        if len(open_ports) > 60000:
            logger.warning("HoneypotDetector: %s appears to have all ports open — likely honeypot", host)
            return True

        return False

    def get_known_ranges(self) -> List[str]:
        """Return the list of known honeypot IP ranges."""
        return KNOWN_HONEYPOT_RANGES

    # ── Internal checks ─────────────────────────────────────────────────────

    def _resolve_to_ip(self, target: str) -> Optional[str]:
        """Resolve a hostname to IP. Returns None on failure."""
        # Already an IP?
        try:
            ipaddress.ip_address(target)
            return target
        except ValueError:
            pass

        try:
            return socket.gethostbyname(target)
        except (socket.gaierror, socket.herror):
            return None

    def _check_ip_range(self, target: str) -> bool:
        """Check if target IP falls within any known honeypot range."""
        ip_str = self._resolve_to_ip(target)
        if not ip_str:
            return False

        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            return False

        for network in self._known_ranges:
            if ip in network:
                return True
        return False

    def _check_hostname_pattern(self, target: str) -> bool:
        """Check if hostname contains known honeypot keywords."""
        target_lower = target.lower()
        for keyword in KNOWN_HONEYPOT_HOSTNAMES:
            if keyword in target_lower:
                return True
        return False

    def _check_greynoise(self, target: str) -> bool:
        """Query GreyNoise for honeypot classification.

        GreyNoise 'classification' field returns 'benign' for honeypots.
        https://docs.greynoise.io/docs/using-the-greynoise-api
        """
        if not self._greynoise_api_key:
            return False

        import urllib.request
        import json

        url = f"https://api.greynoise.io/v3/community/{target}"
        req = urllib.request.Request(url)
        req.add_header("key", self._greynoise_api_key)
        req.add_header("Accept", "application/json")

        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode())
        except Exception as exc:
            logger.debug("GreyNoise API error for %s: %s", target, exc)
            return False

        classification = data.get("classification", "").lower()
        noise = data.get("noise", False)

        # If GreyNoise knows this IP but classifies it as benign, it's likely a honeypot
        if noise and classification == "benign":
            return True

        # Check RIOT (common business services — not honeypots)
        if data.get("riot", False):
            return False

        return False

    def _check_shodan_honeyscore(self, target: str) -> bool:
        """Check Shodan Honeyscore (0.0–1.0). Score > 0.7 = likely honeypot."""
        if not self._shodan_api_key:
            return False

        import urllib.request
        import json

        url = f"https://api.shodan.io/labs/honeyscore/{target}?key={self._shodan_api_key}"

        try:
            with urllib.request.urlopen(url, timeout=10) as resp:
                score = float(resp.read().decode().strip())
        except Exception as exc:
            logger.debug("Shodan Honeyscore error for %s: %s", target, exc)
            return False

        return score > 0.7
