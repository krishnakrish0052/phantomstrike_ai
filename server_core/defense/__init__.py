"""
Self-Defense Engine
Real-time protection against counter-hacking, honeypots, and detection.
"""

from .defense_coordinator import DefenseCoordinator
from .honeypot_detector import HoneypotDetector
from .counter_surveillance import CounterSurveillance
from .ip_reputation import IPReputationMonitor
from .canary_detector import CanaryDetector

__all__ = [
    "DefenseCoordinator",
    "HoneypotDetector",
    "CounterSurveillance",
    "IPReputationMonitor",
    "CanaryDetector",
]
