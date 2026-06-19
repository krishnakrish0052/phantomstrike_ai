"""
Central Defense Coordinator — orchestrates all self-defense subsystems.

Monitors for honeypots, counter-surveillance, IP blacklisting, canary tokens,
and active defense measures. Can auto-terminate operations when threat level
reaches critical.
"""

import logging
import os
import threading
import time
from typing import Any, Dict, List, Optional

from .honeypot_detector import HoneypotDetector
from .counter_surveillance import CounterSurveillance
from .ip_reputation import IPReputationMonitor
from .canary_detector import CanaryDetector

logger = logging.getLogger(__name__)

# ── Threat-level constants ──────────────────────────────────────────────────
THREAT_NORMAL = 0
THREAT_ELEVATED = 1
THREAT_HIGH = 2
THREAT_CRITICAL = 3

THREAT_LABELS = {
    0: "normal",
    1: "elevated",
    2: "high",
    3: "critical",
}


class DefenseCoordinator:
    """Real-time self-defense against counter-hacking and detection.

    Monitors for honeypots, counter-surveillance, IP blacklisting,
    canary tokens, and active defense measures. Can auto-terminate
    operations when threat level reaches critical.
    """

    def __init__(self):
        self.threat_level: int = 0  # 0=normal, 1=elevated, 2=high, 3=critical
        self._lock = threading.Lock()

        # Subsystems — each falls back gracefully to a no-op if deps are missing
        try:
            self.honeypot_detector = HoneypotDetector()
        except Exception:
            logger.warning("HoneypotDetector failed to initialize — honeypot checks disabled")
            self.honeypot_detector = None

        try:
            self.counter_surveillance = CounterSurveillance()
        except Exception:
            logger.warning("CounterSurveillance failed to initialize — counter-surveillance disabled")
            self.counter_surveillance = None

        try:
            self.ip_monitor = IPReputationMonitor()
        except Exception:
            logger.warning("IPReputationMonitor failed to initialize — IP reputation checks disabled")
            self.ip_monitor = None

        try:
            self.canary_detector = CanaryDetector()
        except Exception:
            logger.warning("CanaryDetector failed to initialize — canary detection disabled")
            self.canary_detector = None

        self._alerts: List[Dict[str, Any]] = []
        self._terminated: bool = False
        self._termination_reason: Optional[str] = None
        self._operation_count: int = 0
        self._blocked_count: int = 0

    # ── Pre-request check (run BEFORE every tool execution) ──────────────────

    def pre_request_check(self, target: str) -> bool:
        """Run BEFORE every tool execution. Returns False if unsafe.

        Checks:
          1. Honeypot database — immediate CRITICAL block
          2. IP reputation — elevates threat level
          3. Counter-surveillance — checks if target is tracing back

        Returns True only if threat_level < CRITICAL.
        """
        if self._terminated:
            return False

        self._operation_count += 1

        # 1. Check honeypot database
        if self.honeypot_detector and self.honeypot_detector.is_honeypot(target):
            with self._lock:
                self.threat_level = 3
                self._alerts.append({
                    "type": "honeypot_detected",
                    "target": target,
                    "action": "blocked",
                    "timestamp": time.time(),
                })
            self._blocked_count += 1
            logger.critical("Honeypot detected at target %s — operation blocked", target)
            return False

        # 2. Check IP reputation
        if self.ip_monitor and self.ip_monitor.is_blacklisted(target):
            with self._lock:
                self.threat_level = max(self.threat_level, 2)
                self._alerts.append({
                    "type": "ip_blacklisted",
                    "target": target,
                    "timestamp": time.time(),
                })
            logger.warning("Target %s found on IP blacklist — threat level elevated", target)

        # 3. Counter-surveillance check
        if self.counter_surveillance and self.counter_surveillance.is_tracing_back(target):
            with self._lock:
                self.threat_level = max(self.threat_level, 2)
                self._alerts.append({
                    "type": "counter_surveillance_detected",
                    "target": target,
                    "timestamp": time.time(),
                })
            logger.warning("Counter-surveillance detected from target %s", target)

        return self.threat_level < 3

    # ── Post-request check (run AFTER every tool execution) ──────────────────

    def post_request_check(self, response_data: str) -> bool:
        """Run AFTER every tool execution. Detects tripwires in responses.

        Scans response text/headers for canary tokens, honey tokens,
        and tripwire patterns. Triggers CRITICAL auto-terminate if found.
        """
        if self._terminated:
            return False

        if self.canary_detector and self.canary_detector.detect(response_data):
            self.auto_terminate("canary_token_detected")
            return False

        return True

    # ── Auto-termination ────────────────────────────────────────────────────

    def auto_terminate(self, reason: str) -> None:
        """Emergency termination — kill all sessions, rotate identities, wipe evidence.

        Called when threat level reaches CRITICAL or a canary token is detected.
        Sets `_terminated = True` so all future pre_request_check calls return False.
        """
        with self._lock:
            self._terminated = True
            self._termination_reason = reason
            self.threat_level = 3
            self._alerts.append({
                "type": "auto_terminated",
                "reason": reason,
                "timestamp": time.time(),
            })

        logger.critical("EMERGENCY TERMINATION triggered: %s", reason)

        # Kill all active tool processes — best-effort, delegated to process manager
        try:
            from server_core.singletons import enhanced_process_manager
            enhanced_process_manager.terminate_all()
        except Exception:
            logger.warning("Could not terminate processes via enhanced_process_manager")

        # Wipe temp files produced during this session
        try:
            import shutil
            import tempfile
            tmp_root = tempfile.gettempdir()
            for pattern in ["nyxstrike_*", "phantomstrike_*", "hexstrike_*"]:
                import glob
                for fpath in glob.glob(f"{tmp_root}/{pattern}"):
                    try:
                        if os.path.isdir(fpath):
                            shutil.rmtree(fpath, ignore_errors=True)
                        else:
                            os.remove(fpath)
                    except Exception:
                        pass
        except Exception:
            pass

        # Log the termination event for audit
        logger.info(
            "DefenseCoordinator terminated: reason=%s operations=%d blocked=%d alerts=%d",
            reason, self._operation_count, self._blocked_count, len(self._alerts),
        )

    # ── Status queries ──────────────────────────────────────────────────────

    def get_alerts(self) -> List[Dict[str, Any]]:
        """Return all active alerts (most recent first)."""
        with self._lock:
            return list(reversed(self._alerts))

    def get_status(self) -> Dict[str, Any]:
        """Return comprehensive defense status."""
        with self._lock:
            return {
                "threat_level": self.threat_level,
                "threat_label": THREAT_LABELS.get(self.threat_level, "unknown"),
                "terminated": self._terminated,
                "termination_reason": self._termination_reason,
                "alert_count": len(self._alerts),
                "recent_alerts": self._alerts[-10:] if self._alerts else [],
                "operation_count": self._operation_count,
                "blocked_count": self._blocked_count,
                "subsystems": {
                    "honeypot_detector": "active" if self.honeypot_detector else "disabled",
                    "counter_surveillance": "active" if self.counter_surveillance else "disabled",
                    "ip_reputation": "active" if self.ip_monitor else "disabled",
                    "canary_detector": "active" if self.canary_detector else "disabled",
                },
            }

    # ── Manual control ──────────────────────────────────────────────────────

    def reset(self) -> None:
        """Reset threat level and cleared alerts. Does NOT unset _terminated."""
        with self._lock:
            if not self._terminated:
                self.threat_level = 0
                self._alerts = []
                logger.info("DefenseCoordinator reset to normal")
