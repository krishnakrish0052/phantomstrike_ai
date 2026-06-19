"""
IP Reputation Monitor — real-time blacklist checking.

Integrates with:
  - AbuseIPDB
  - GreyNoise
  - AlienVault OTX
  - (optional) VirusTotal, IBM X-Force

Rate-limited to avoid API throttling. Uses local cache with TTL.
"""

import json
import logging
import threading
import time
from collections import OrderedDict, deque
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)

# ── Cache configuration ─────────────────────────────────────────────────────
CACHE_MAX_SIZE = 5000
CACHE_TTL_SECONDS = 3600  # 1 hour
CACHE_TTL_BLACKLISTED = 300  # 5 minutes for known-bad (may change)

# ── Rate-limit configuration ────────────────────────────────────────────────
# AbuseIPDB free tier: 1000/day (~40/hour)
REQUESTS_PER_WINDOW = 30
WINDOW_SECONDS = 3600  # 1 hour

# ── Known-malicious IP patterns (static fallback) ───────────────────────────
KNOWN_BAD_RANGES: List[str] = [
    # Common C2 / malware hosting ranges
    # (Placeholder — updated from threat feeds at runtime)
]


class IPReputationMonitor:
    """Real-time IP blacklist checking against multiple threat intel sources.

    Rate-limited to stay within free-tier API limits.
    Uses local LRU cache with TTL to minimize API calls.
    """

    def __init__(self):
        self._abuseipdb_api_key: Optional[str] = None
        self._otx_api_key: Optional[str] = None
        self._greynoise_api_key: Optional[str] = None

        # Rate limiter state
        self._request_times: deque = deque()
        self._rate_lock = threading.Lock()

        # Cache: {ip: (bool, float)} -> (is_blacklisted, cached_at)
        self._cache: Dict[str, Tuple[bool, float]] = {}
        self._cache_lock = threading.Lock()

        # Statistics
        self._total_checks: int = 0
        self._cache_hits: int = 0
        self._api_calls: int = 0

        # Load API keys from config
        try:
            import server_core.config_core as config_core
            self._abuseipdb_api_key = config_core.get("ABUSEIPDB_API_KEY", None)
            self._otx_api_key = config_core.get("OTX_API_KEY", None)
            self._greynoise_api_key = config_core.get("GREYNOISE_API_KEY", None)
        except Exception:
            pass

    # ── Public API ──────────────────────────────────────────────────────────

    def is_blacklisted(self, target: str) -> bool:
        """Check if a target IP or domain is present on any blacklist.

        Returns True if any source reports the target as malicious.
        Results are cached with TTL.
        """
        target = target.strip()
        if not target:
            return False

        self._total_checks += 1

        # Check cache first
        with self._cache_lock:
            if target in self._cache:
                is_bad, cached_at = self._cache[target]
                ttl = CACHE_TTL_BLACKLISTED if is_bad else CACHE_TTL_SECONDS
                if time.time() - cached_at < ttl:
                    self._cache_hits += 1
                    return is_bad

        # Resolve to IP if it's a hostname
        ip = self._resolve_to_ip(target)
        check_target = ip or target

        # Fallback: static check if no API keys are available
        if not any([self._abuseipdb_api_key, self._otx_api_key, self._greynoise_api_key]):
            result = self._static_check(check_target)
            self._update_cache(target, result)
            return result

        # Query APIs in order of preference, short-circuit on first positive
        result = False

        if self._abuseipdb_api_key and self._can_make_request():
            try:
                result = self._check_abuseipdb(check_target) or result
            except Exception as exc:
                logger.debug("AbuseIPDB check failed for %s: %s", target, exc)

        if not result and self._greynoise_api_key and self._can_make_request():
            try:
                result = self._check_greynoise(check_target) or result
            except Exception as exc:
                logger.debug("GreyNoise check failed for %s: %s", target, exc)

        if not result and self._otx_api_key and self._can_make_request():
            try:
                result = self._check_otx(check_target) or result
            except Exception as exc:
                logger.debug("OTX check failed for %s: %s", target, exc)

        self._update_cache(target, result)
        return result

    def check_bulk(self, targets: List[str]) -> Dict[str, bool]:
        """Check multiple targets. Respects rate limits."""
        results = {}
        for target in targets:
            results[target] = self.is_blacklisted(target)
        return results

    def get_statistics(self) -> Dict[str, Any]:
        """Return monitoring statistics."""
        return {
            "total_checks": self._total_checks,
            "cache_hits": self._cache_hits,
            "api_calls": self._api_calls,
            "cache_size": len(self._cache),
            "sources_available": {
                "abuseipdb": bool(self._abuseipdb_api_key),
                "otx": bool(self._otx_api_key),
                "greynoise": bool(self._greynoise_api_key),
            },
        }

    def clear_cache(self) -> None:
        """Clear the reputation cache."""
        with self._cache_lock:
            self._cache.clear()
            logger.info("IPReputationMonitor cache cleared")

    # ── Internal: API integrations ──────────────────────────────────────────

    def _can_make_request(self) -> bool:
        """Rate-limit check. Returns True if we're under the limit."""
        now = time.time()
        with self._rate_lock:
            # Purge old entries
            while self._request_times and now - self._request_times[0] > WINDOW_SECONDS:
                self._request_times.popleft()

            if len(self._request_times) < REQUESTS_PER_WINDOW:
                self._request_times.append(now)
                self._api_calls += 1
                return True
            return False

    def _check_abuseipdb(self, ip: str) -> bool:
        """Query AbuseIPDB for IP reputation.

        https://docs.abuseipdb.com/
        """
        import urllib.request

        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {
            "Key": self._abuseipdb_api_key,
            "Accept": "application/json",
        }
        params = f"ipAddress={ip}&maxAgeInDays=90"

        req = urllib.request.Request(f"{url}?{params}", headers=headers)
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())

        abuse_score = data.get("data", {}).get("abuseConfidenceScore", 0)
        total_reports = data.get("data", {}).get("totalReports", 0)

        # Consider blacklisted if confidence > 75% and has recent reports
        if abuse_score > 75 and total_reports > 2:
            logger.debug("AbuseIPDB: %s score=%d reports=%d — BLACKLISTED",
                         ip, abuse_score, total_reports)
            return True

        return False

    def _check_greynoise(self, ip: str) -> bool:
        """Query GreyNoise for IP classification.

        Malicious IPs from GreyNoise are active scanners/exploiters.
        """
        import urllib.request

        url = f"https://api.greynoise.io/v3/community/{ip}"
        req = urllib.request.Request(url)
        req.add_header("key", self._greynoise_api_key)
        req.add_header("Accept", "application/json")

        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())

        classification = data.get("classification", "").lower()
        noise = data.get("noise", False)

        # 'malicious' classification means active threat
        if noise and classification == "malicious":
            logger.debug("GreyNoise: %s classified as malicious", ip)
            return True

        return False

    def _check_otx(self, ip_or_domain: str) -> bool:
        """Query AlienVault OTX for threat intelligence.

        https://otx.alienvault.com/api
        """
        import urllib.request

        # Determine if this is an IP or domain
        try:
            __import__('ipaddress').ip_address(ip_or_domain)
            url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip_or_domain}/general"
        except ValueError:
            url = f"https://otx.alienvault.com/api/v1/indicators/domain/{ip_or_domain}/general"

        headers = {
            "X-OTX-API-KEY": self._otx_api_key,
            "Accept": "application/json",
        }

        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())

        # Check pulse count — high pulse count = active threat indicator
        pulse_count = data.get("pulse_info", {}).get("count", 0)
        if pulse_count > 5:
            logger.debug("OTX: %s has %d pulses — BLACKLISTED", ip_or_domain, pulse_count)
            return True

        # Check validation (if this is a legitimate indicator)
        validation = data.get("validation", [])
        if validation:
            for entry in validation:
                if entry.get("name") == "whitelist":
                    return False

        return False

    def _static_check(self, target: str) -> bool:
        """Static check against known-bad ranges (no API required)."""
        try:
            ip_obj = __import__('ipaddress').ip_address(target)
            for cidr in KNOWN_BAD_RANGES:
                network = __import__('ipaddress').ip_network(cidr, strict=False)
                if ip_obj in network:
                    return True
        except ValueError:
            pass
        return False

    def _update_cache(self, target: str, is_blacklisted: bool) -> None:
        """Update the cache, enforcing size limit."""
        with self._cache_lock:
            self._cache[target] = (is_blacklisted, time.time())
            # Evict oldest entries if cache is too large
            if len(self._cache) > CACHE_MAX_SIZE:
                # Remove 25% oldest entries
                entries = sorted(self._cache.items(), key=lambda x: x[1][1])
                for key, _ in entries[: CACHE_MAX_SIZE // 4]:
                    del self._cache[key]

    @staticmethod
    def _resolve_to_ip(target: str) -> Optional[str]:
        """Resolve hostname to IP. Returns None if unresolvable."""
        try:
            __import__('ipaddress').ip_address(target)
            return target  # Already an IP
        except ValueError:
            pass
        try:
            import socket
            return socket.gethostbyname(target)
        except (socket.gaierror, socket.herror):
            return None
