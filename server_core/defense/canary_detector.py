"""
Canary Detector — identifies canary tokens, honey tokens, and tripwires.

Detects:
  - DNS canary domains (unique subdomains that alert when resolved)
  - URL canary patterns (AWS keys, embedded tracking URLs)
  - Tracking beacons (1x1 pixel images, web bugs)
  - Email canary addresses
  - AWS/Azure/GCP canary tokens
  - Unique string tokens planted in responses
"""

import hashlib
import logging
import re
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger(__name__)

# ── Canary token patterns ───────────────────────────────────────────────────

# Canary DNS domains — resolving these alerts the defender
CANARY_DNS_PATTERN = re.compile(
    r"(?i)(?:canarytokens\.(?:com|org|net)|canary\.tools|"
    r"canary\.redteam\.tools|canarydrop\.com)",
)

# Canary URL patterns — common canary token service URLs
CANARY_URL_PATTERNS: List[re.Pattern] = [
    # Thinkst Canary (canarytokens.org)
    re.compile(r"https?://canarytokens\.\w+"),
    # Generic canary endpoints
    re.compile(r"https?://[^/]+/canary(?:token|drop|trigger)[^/]*"),
    # AWS canary keys (AKIAIOSFODNN7EXAMPLE style)
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    # Azure canary
    re.compile(r"(?i)azur[e3]?\s*canary"),
    # GCP canary
    re.compile(r"(?i)gcp\s*canary"),
]

# Tracking beacon patterns (1x1 pixel images, web bugs)
TRACKING_BEACON_PATTERNS: List[re.Pattern] = [
    # 1x1 tracking pixels
    re.compile(r'<img[^>]*(?:width|height)\s*=\s*["\']1["\'][^>]*>', re.IGNORECASE),
    # Web bugs
    re.compile(r'<img[^>]*src=["\'][^"\']*/(?:track|beacon|bug|pixel)[^"\']*["\'][^>]*>', re.IGNORECASE),
    # CSS-based tracking
    re.compile(r'url\(["\']?(?:https?:)?//[^)"\']*/(?:track|beacon|pixel)', re.IGNORECASE),
    # JavaScript beacon API
    re.compile(r'navigator\.sendBeacon\s*\(', re.IGNORECASE),
    # WebRTC tracking
    re.compile(r'(?:RTCPeerConnection|createDataChannel).*?track', re.IGNORECASE),
]

# Email canary address patterns
EMAIL_CANARY_PATTERNS: List[re.Pattern] = [
    re.compile(r"[a-zA-Z0-9._%+-]+@canarytokens\.\w+"),
    re.compile(r"(?i)canary@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"),
    re.compile(r"(?i)honeypot@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"),
]

# Unique token patterns — high-entropy strings planted as tripwires
TRIPWIRE_TOKEN_PATTERNS: List[re.Pattern] = [
    # Thinkst canary token format
    re.compile(r"[a-f0-9]{32}\.canarytokens\.\w+"),
    # Generic 64-char hex tokens that might be canaries
    re.compile(r"canary[a-f0-9]{32,64}"),
    # Base64-encoded canary indicators
    re.compile(r"(?i)(?:dG9rZW58Y2FuYXJ5|canary|honeytoken|tripwire)[a-zA-Z0-9+/=]{16,}"),
]

# Suspicious comments/HTML comments containing tracking
SUSPICIOUS_COMMENT_PATTERNS: List[re.Pattern] = [
    re.compile(r"<!--\s*(?:canary|honeypot|tripwire|tracker)"),
    re.compile(r"<!--\s*[a-f0-9]{40,}"),  # Long hex string in HTML comment
    re.compile(r"(?i)<meta[^>]*name\s*=\s*[\"'](?:canary|trap|honeypot)[\"']"),
]

# SQL canary patterns — planted in database responses
SQL_CANARY_PATTERNS: List[re.Pattern] = [
    re.compile(r"(?i)(?:canary_record|canary_row|honey_record)"),
    re.compile(r"(?i)(?:tripwire_row|canary_entry|decoys?)"),
]

# ── Blocklist of known canary domains ───────────────────────────────────────
KNOWN_CANARY_DOMAINS: Set[str] = {
    "canarytokens.com",
    "canarytokens.org",
    "canary.tools",
    "canarydrop.com",
    "canary.redteam.tools",
    "thinkst.com",
    "honeypot.net",
    "traphouse.net",
}


class CanaryDetector:
    """Detects canary tokens, honey tokens, and tripwires in responses.

    Scans HTTP response bodies, headers, URLs, and raw text for patterns
    that indicate the target is using canary technology to detect intrusions.
    """

    def __init__(self):
        self._detection_count: int = 0
        self._detection_log: List[Dict[str, Any]] = []
        self._seen_hashes: Set[str] = set()  # Deduplicate alerts

    # ── Public API ──────────────────────────────────────────────────────────

    def detect(self, data: str) -> bool:
        """Scan text/response data for canary tokens and tripwires.

        Returns True if any canary indicator is detected.
        The caller should trigger emergency termination.
        """
        if not data:
            return False

        data_hash = hashlib.sha256(data.encode('utf-8', errors='replace')).hexdigest()
        if data_hash in self._seen_hashes:
            return False  # Already scanned this exact content
        self._seen_hashes.add(data_hash)

        detections: List[str] = []

        # 1. DNS canary domains
        if CANARY_DNS_PATTERN.search(data):
            detections.append("dns_canary_domain")

        # 2. Known canary domains
        data_lower = data.lower()
        for domain in KNOWN_CANARY_DOMAINS:
            if domain in data_lower:
                detections.append(f"known_canary_domain:{domain}")

        # 3. Canary URL patterns
        for pattern in CANARY_URL_PATTERNS:
            if pattern.search(data):
                detections.append("canary_url_pattern")
                break

        # 4. Tracking beacons
        for pattern in TRACKING_BEACON_PATTERNS:
            if pattern.search(data):
                detections.append("tracking_beacon")
                break

        # 5. Email canary addresses
        for pattern in EMAIL_CANARY_PATTERNS:
            if pattern.search(data):
                detections.append("email_canary")
                break

        # 6. Tripwire tokens
        for pattern in TRIPWIRE_TOKEN_PATTERNS:
            if pattern.search(data):
                detections.append("tripwire_token")
                break

        # 7. Suspicious HTML comments
        for pattern in SUSPICIOUS_COMMENT_PATTERNS:
            if pattern.search(data):
                detections.append("suspicious_comment")
                break

        # 8. SQL canary patterns
        for pattern in SQL_CANARY_PATTERNS:
            if pattern.search(data):
                detections.append("sql_canary")
                break

        if detections:
            self._detection_count += 1
            import time
            self._detection_log.append({
                "timestamp": time.time(),
                "detection_types": detections,
                "data_preview": data[:200] if len(data) > 200 else data,
                "data_hash": data_hash,
            })
            logger.critical(
                "CanaryDetector: detected %s — %s", detections, data[:100]
            )
            return True

        return False

    def check_url(self, url: str) -> Optional[List[str]]:
        """Check a single URL for canary patterns. Returns list of matched types."""
        detections: List[str] = []

        url_lower = url.lower()
        for domain in KNOWN_CANARY_DOMAINS:
            if domain in url_lower:
                detections.append(f"known_canary_domain:{domain}")

        if CANARY_DNS_PATTERN.search(url):
            detections.append("dns_canary_domain")

        for pattern in CANARY_URL_PATTERNS:
            if pattern.search(url):
                detections.append("canary_url_pattern")
                break

        return detections if detections else None

    def check_email(self, email: str) -> bool:
        """Check if an email address is a canary address."""
        for pattern in EMAIL_CANARY_PATTERNS:
            if pattern.search(email):
                return True
        return False

    def get_statistics(self) -> Dict[str, Any]:
        """Return detection statistics."""
        return {
            "total_detections": self._detection_count,
            "recent_detections": self._detection_log[-10:],
            "unique_content_hashes_seen": len(self._seen_hashes),
        }

    def clear_log(self) -> None:
        """Clear detection log."""
        self._detection_log = []
        self._detection_count = 0
        logger.info("CanaryDetector detection log cleared")
