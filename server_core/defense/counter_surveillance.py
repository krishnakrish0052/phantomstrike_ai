"""
Counter-Surveillance — detects when targets are tracing back.

Monitors for:
  - Reverse-DNS lookups on our exit IPs
  - Increased scanning activity targeting our infrastructure
  - Response anomalies indicating defensive investigation
  - Timing-based detection (artificial delays = active analysis)
  - Header anomalies from WAF/IDS engaging in counter-recon
"""

import logging
import re
import time
from collections import deque
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)

# ── Counter-surveillance indicators ─────────────────────────────────────────
# These patterns in responses suggest the target is actively investigating us
COUNTER_SURVEILLANCE_PATTERNS: Dict[str, re.Pattern] = {
    "reverse_dns_lookup": re.compile(
        r"(?i)(reverse.*dns|rdns.*lookup|whois.*query|looking.*up.*"
        r"|geoip.*check|ip.*intelligence|abuseipdb|greynoise)",
    ),
    "counter_scan": re.compile(
        r"(?i)(scanning.*back|return.*scan|counter.*scan|"
        r"retaliatory|active.*defense|strikeback)",
    ),
    "threat_intel_platform": re.compile(
        r"(?i)(threat.*intel.*platform|tip.*correlation|"
        r"crowdstrike|anomali|recorded.*future|mandiant|fireeye)",
    ),
    "deception_technology": re.compile(
        r"(?i)(deception.*grid|trapx|illusive|smokescreen|"
        r"covalence|countercept|attivo|fidelis.*deception)",
    ),
    "identity_trace": re.compile(
        r"(?i)(trace.*route.*origin|fingerprint.*attacker|"
        r"browser.*fingerprint|tor.*exit.*node|proxy.*origin)",
    ),
    "law_enforcement": re.compile(
        r"(?i)(law.*enforcement|fbi|cia|nca|interpol|cyber.*crime.*unit|"
        r"digital.*forensics.*unit)",
    ),
    "honeypot_directive": re.compile(
        r"(?i)(you.*have.*accessed.*honeypot|this.*is.*a.*trap|"
        r"your.*activity.*is.*logged|this.*system.*is.*monitored)",
    ),
}

# ── Response anomaly patterns ───────────────────────────────────────────────
# Headers that suggest the server is performing counter-intel
COUNTER_SURVEILLANCE_HEADERS: Set[str] = {
    "x-threat-response",
    "x-deception",
    "x-counter-intel",
    "x-ip-intelligence",
    "x-attacker-profile",
    "x-malicious-ip",
    "x-threatscore",
    "x-defender-action",
}

# ── Suspicious timing thresholds ────────────────────────────────────────────
# If a target's response time is artificially inflated (> 5s for simple requests),
# it may indicate active analysis or deliberate slowdown to fingerprint us
SUSPICIOUS_RESPONSE_DELAY_MS = 5000


class CounterSurveillance:
    """Detects when targets are tracing back or performing counter-recon.

    Monitors exit IPs for reverse-DNS lookups, tracks scanning patterns
    targeting our infrastructure, and detects response anomalies that
    indicate the defender is actively investigating our operations.
    """

    def __init__(self):
        # Rolling window of recent response times for anomaly detection
        self._response_times: deque = deque(maxlen=100)
        self._suspicious_ips: Set[str] = set()
        self._rdns_events: List[Dict[str, Any]] = []
        self._scan_events: List[Dict[str, Any]] = []

        # Our exit IPs (populated as we use proxies/tor)
        self._exit_ips: Set[str] = set()
        self._exit_ips_lock = __import__('threading').Lock()

        # Track per-target request counts for burst detection
        self._request_counts: Dict[str, int] = {}
        self._first_request_time: Dict[str, float] = {}

    # ── Public API ──────────────────────────────────────────────────────────

    def is_tracing_back(self, target: str) -> bool:
        """Check if the target exhibits counter-surveillance behavior.

        Returns True if the target is actively trying to trace us.
        """
        target = target.strip()
        if not target:
            return False

        # Check if target is known-suspicious
        if target in self._suspicious_ips:
            return True

        return False

    def analyze_response(self, target: str, headers: Dict[str, str],
                         body: str, elapsed_ms: float) -> Dict[str, Any]:
        """Analyze a response for counter-surveillance indicators.

        Returns a dict with 'suspicious' (bool) and 'indicators' (list of matched types).
        """
        indicators: List[str] = []
        result: Dict[str, Any] = {
            "suspicious": False,
            "indicators": [],
            "target": target,
            "timestamp": time.time(),
        }

        # 1. Check headers for counter-surveillance headers
        for header_name in COUNTER_SURVEILLANCE_HEADERS:
            if header_name.lower() in {k.lower() for k in headers}:
                indicators.append(f"counter_surveillance_header:{header_name}")
                logger.warning(
                    "CounterSurveillance: %s returned header %s", target, header_name
                )

        # 2. Check body for counter-surveillance patterns
        body_lower = body.lower()
        for pattern_name, pattern in COUNTER_SURVEILLANCE_PATTERNS.items():
            if pattern.search(body):
                indicators.append(f"response_pattern:{pattern_name}")
                logger.warning(
                    "CounterSurveillance: %s matched pattern %s", target, pattern_name
                )

        # 3. Check for suspicious response delays
        if elapsed_ms > SUSPICIOUS_RESPONSE_DELAY_MS:
            # Only flag if this is anomalous compared to baseline
            avg = self._get_average_response_time()
            if avg > 0 and elapsed_ms > avg * 3:
                indicators.append("suspicious_delay")
                logger.warning(
                    "CounterSurveillance: %s response time %.0fms (avg: %.0fms)",
                    target, elapsed_ms, avg,
                )

        # 4. Track response time for baseline
        self._response_times.append(elapsed_ms)

        if indicators:
            result["suspicious"] = True
            result["indicators"] = indicators
            self._suspicious_ips.add(target)

        return result

    def register_exit_ip(self, ip: str) -> None:
        """Register one of our exit IPs for RDNS monitoring."""
        with self._exit_ips_lock:
            self._exit_ips.add(ip)
        logger.debug("CounterSurveillance: registered exit IP %s", ip)

    def get_exit_ips(self) -> List[str]:
        """Return list of registered exit IPs."""
        with self._exit_ips_lock:
            return sorted(self._exit_ips)

    def get_recent_events(self, limit: int = 20) -> List[Dict[str, Any]]:
        """Return recent counter-surveillance events."""
        events = self._rdns_events + self._scan_events
        events.sort(key=lambda e: e.get("timestamp", 0), reverse=True)
        return events[:limit]

    def get_status(self) -> Dict[str, Any]:
        """Return current counter-surveillance status."""
        return {
            "exit_ips": list(self._exit_ips),
            "suspicious_ips": list(self._suspicious_ips),
            "rdns_events_count": len(self._rdns_events),
            "scan_events_count": len(self._scan_events),
            "average_response_ms": self._get_average_response_time(),
        }

    # ── Internal helpers ────────────────────────────────────────────────────

    def _get_average_response_time(self) -> float:
        """Calculate average response time from rolling window."""
        if not self._response_times:
            return 0.0
        return sum(self._response_times) / len(self._response_times)

    def _record_rdns_event(self, target: str, details: str = "") -> None:
        """Log a reverse-DNS lookup event."""
        self._rdns_events.append({
            "type": "reverse_dns",
            "target": target,
            "details": details,
            "timestamp": time.time(),
        })
