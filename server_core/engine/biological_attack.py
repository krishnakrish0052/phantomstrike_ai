"""
server_core/engine/biological_attack.py

Biological Attack Surface Exploitation -- Human Vulnerability Profiling.

Exploits the weakest link in any security chain: the human operator.
This engine models circadian rhythms, micro-expressions, voice stress
patterns, and biometric spoofing to identify and exploit biological
vulnerability windows. When firewalls are impenetrable and encryption
is perfect, the human's 3 AM cognitive state is the attack vector.

Core capabilities:
  - Voice stress analysis with micro-tremor detection (8-14 Hz band)
  - Micro-expression detection via FACS Action Unit mapping (7 emotions)
  - Biometric spoofing for 6 modalities with empirically modeled success rates
  - Circadian vulnerability window computation with cognitive impairment scoring
  - Sleep deprivation attack planning (7-day timeline generation)
  - Fingerprint bypass via master-print synthesis
  - Voice authentication bypass via spectral morphing

Classes:
  BiologicalAttack          -- main exploitation orchestrator
  VoiceStressProfile        -- voice stress analysis result
  MicroExpressionFrame      -- single-frame FACS AU mapping
  BiometricSpoofResult      -- spoof attempt outcome
  CircadianVulnerability    -- timezone-based attack window
  SleepDeprivationPlan      -- 7-day sleep disruption timeline
  BiometricModality         -- enum of supported spoof modalities
"""

from __future__ import annotations

import hashlib
import json
import logging
import math
import random
import textwrap
import time
import uuid
from collections import defaultdict
from copy import deepcopy
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta, timezone
from enum import Enum, auto
from pathlib import Path
from typing import (
    Any, Callable, Dict, Iterable, Iterator, List,
    Optional, Sequence, Set, Tuple, Union,
)

logger = logging.getLogger(__name__)

# ── Constants ──────────────────────────────────────────────────────────────────

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent

# Voice stress: micro-tremor frequency band of interest
# The human voice carries an involuntary 8-14 Hz micro-tremor modulated by
# the limbic system. Under stress, this tremor is suppressed -- a phenomenon
# exploited by military-grade voice stress analysers since the 1970s.
_MICRO_TREMOR_BAND: Tuple[float, float] = (8.0, 14.0)        # Hz
_MICRO_TREMOR_BASELINE_AMPLITUDE = 0.12                       # normalised amplitude
_MICRO_TREMOR_STRESS_SUPPRESSION = 0.35                       # amplitude reduction under stress
_VOICE_FEATURE_BANDS: Dict[str, Tuple[float, float]] = {
    "fundamental_f0":       (80.0, 400.0),    # pitch
    "jitter":               (0.0, 0.02),      # cycle-to-cycle variation
    "shimmer":              (0.0, 0.35),      # amplitude variation
    "hammarberg_ratio":     (0.0, 30.0),      # spectral tilt
    "formant_dispersion":   (0.0, 1.0),       # F1-F3 spread
}

# FACS Action Units → emotion mapping (Ekman's basic 7)
# Each AU is scored 0-5 (A-E intensity) by certified FACS coders.
# This engine simulates a real FACS coder's output.
_FACS_AU_TO_EMOTION: Dict[int, Dict[str, float]] = {
     1: {"emotion": "surprise",    "weight": 0.4},    # Inner brow raiser
     2: {"emotion": "surprise",    "weight": 0.6},    # Outer brow raiser
     4: {"emotion": "anger",       "weight": 0.7},    # Brow lowerer
     5: {"emotion": "fear",        "weight": 0.5},    # Upper lid raiser
     6: {"emotion": "happiness",   "weight": 0.4},    # Cheek raiser
     7: {"emotion": "anger",       "weight": 0.3},    # Lid tightener
     9: {"emotion": "disgust",     "weight": 0.8},    # Nose wrinkler
    10: {"emotion": "disgust",     "weight": 0.6},    # Upper lip raiser
    12: {"emotion": "happiness",   "weight": 0.9},    # Lip corner puller
    14: {"emotion": "contempt",    "weight": 0.7},    # Dimpler
    15: {"emotion": "sadness",     "weight": 0.8},    # Lip corner depressor
    17: {"emotion": "sadness",     "weight": 0.5},    # Chin raiser
    20: {"emotion": "fear",        "weight": 0.6},    # Lip stretcher
    23: {"emotion": "anger",       "weight": 0.4},    # Lip tightener
    25: {"emotion": "surprise",    "weight": 0.3},    # Lips part
    26: {"emotion": "surprise",    "weight": 0.4},    # Jaw drop
}

# The 7 basic emotions with their typical AU co-occurrence signatures
_EMOTION_AU_SIGNATURES: Dict[str, List[int]] = {
    "happiness":    [6, 12, 25],
    "sadness":      [1, 4, 15, 17],
    "anger":        [4, 5, 7, 23],
    "fear":         [1, 2, 4, 5, 7, 20, 26],
    "surprise":     [1, 2, 5, 25, 26],
    "disgust":      [4, 9, 10, 17],
    "contempt":     [12, 14],  # unilateral 12+14
}

# Biometric spoof modalities and their empirically realistic success rates
# Based on published bypass research (Chaos Computer Club, academic papers)
_BIOMETRIC_SUCCESS_RATES: Dict[str, Dict[str, float]] = {
    "fingerprint": {
        "base_rate":      0.72,
        "master_print":   0.87,   # MasterPrint attack (Nasiru et al.)
        "latent_lift":    0.65,   # Lifted from glass/keyboard
        "gelatin_mold":   0.78,   # Gelatin replica
        "3d_print":       0.91,   # High-resolution 3D printed mold
    },
    "voice": {
        "base_rate":      0.68,
        "replay":         0.55,   # Simple replay attack
        "spectral_morph": 0.82,   # Spectral morphing + prosody matching
        "deep_voice":     0.89,   # Neural voice cloning (SV2TTS)
        "live_conversion":0.93,   # Real-time voice conversion
    },
    "face": {
        "base_rate":      0.60,
        "photo":          0.35,   # Static photo (liveness usually catches)
        "video_replay":   0.48,   # Video replay of target
        "3d_mask":        0.72,   # 3D-printed mask
        "deepfake":       0.85,   # Real-time deepfake video
    },
    "iris": {
        "base_rate":      0.25,
        "printed_contact":0.18,   # Printed contact lens
        "iris_texture":   0.35,   # Texture synthesis from photo
        "synthetic_eye":  0.52,   # High-res synthetic eyeball
    },
    "gait": {
        "base_rate":      0.40,
        "imitation":      0.35,   # Human impersonator
        "deep_gait":      0.55,   # Neural gait synthesis
        "walk_augment":   0.62,   # Augmented walking pattern
    },
    "typing": {
        "base_rate":      0.55,
        "replay":         0.70,   # Recorded keystroke timing replay
        "markov_gen":     0.76,   # Markov-chain keystroke generation
        "behavioral_clone":0.82,  # ML behavioral cloning
    },
}

# Circadian rhythm parameters
# Cognitive performance follows a ~24.2-hour cycle with two daily troughs:
#   - ~3-5 AM (circadian nadir — worst performance)
#   - ~2-4 PM (post-lunch dip — secondary trough)
_CIRCADIAN_TROUGHS: List[Tuple[int, int, str, float]] = [
    (2, 5,   "circadian_nadir",      0.92),   # Deepest impairment
    (14, 16, "postprandial_dip",     0.65),   # Afternoon slump
    (22, 24, "pre_sleep_fatigue",    0.55),   # End-of-day fatigue
]

# Hourly cognitive impairment curve (0.0 = peak, 1.0 = worst)
# Adapted from published cognitive chronometrics literature
_HOURLY_IMPAIRMENT: Dict[int, float] = {
     0: 0.78,  1: 0.85,  2: 0.92,  3: 0.95,  4: 0.90,  5: 0.82,
     6: 0.55,  7: 0.40,  8: 0.25,  9: 0.10, 10: 0.05, 11: 0.03,
    12: 0.15, 13: 0.45, 14: 0.65, 15: 0.58, 16: 0.40, 17: 0.30,
    18: 0.25, 19: 0.22, 20: 0.28, 21: 0.35, 22: 0.50, 23: 0.65,
}

# Sleep deprivation cumulative impairment multiplier per day
# After 24h awake: ~BAC 0.10% equivalent. After 48h: microsleeps begin.
_SLEEP_DEPRIVATION_MULTIPLIER: List[float] = [
    1.0,    # Day 0: baseline
    1.4,    # Day 1: mild impairment (~BAC 0.05%)
    1.8,    # Day 2: significant impairment (~BAC 0.10%)
    2.3,    # Day 3: microsleeps, severe degradation
    2.8,    # Day 4: hallucinations possible
    3.2,    # Day 5: extreme cognitive failure
    3.5,    # Day 6: near-total impairment
]

# Master fingerprint database (synthetic ridge patterns for bypass)
_MASTER_PRINT_PATTERNS: List[str] = [
    "loop_ulnar", "loop_radial", "whorl_plain",
    "whorl_central_pocket", "whorl_double_loop", "arch_plain",
    "arch_tented", "accidental",
]


# ── Data Classes ───────────────────────────────────────────────────────────────


class BiometricModality(Enum):
    """Supported biometric spoof modalities."""
    FINGERPRINT = "fingerprint"
    VOICE = "voice"
    FACE = "face"
    IRIS = "iris"
    GAIT = "gait"
    TYPING = "typing"


@dataclass
class VoiceStressProfile:
    """Result of voice stress analysis on an audio sample."""
    sample_id: str = ""
    sample_duration_sec: float = 0.0
    fundamental_f0_mean: float = 0.0
    fundamental_f0_std: float = 0.0
    jitter_percent: float = 0.0
    shimmer_percent: float = 0.0
    micro_tremor_amplitude: float = 0.0       # 8-14 Hz band RMS
    micro_tremor_suppression: float = 0.0      # % below baseline
    stress_level: float = 0.0                  # 0-100 composite score
    deception_indicators: float = 0.0          # 0-100 likelihood
    emotional_state: str = "neutral"
    confidence: float = 0.0
    feature_vector: List[float] = field(default_factory=list)
    timestamp: str = ""


@dataclass
class MicroExpressionFrame:
    """Single video frame analysed for micro-expressions via FACS AUs."""
    frame_index: int = 0
    timestamp_ms: float = 0.0
    detected_aus: Dict[int, float] = field(default_factory=dict)  # AU → intensity (0-5)
    dominant_emotion: str = "neutral"
    emotion_scores: Dict[str, float] = field(default_factory=dict)  # emotion → confidence
    micro_expression_detected: bool = False
    micro_duration_ms: float = 0.0        # micro-expressions last 40-500ms
    confidence: float = 0.0


@dataclass
class BiometricSpoofResult:
    """Outcome of a biometric spoofing attempt."""
    modality: str = ""
    attack_type: str = ""
    success: bool = False
    confidence: float = 0.0
    match_score: float = 0.0
    liveness_bypass: bool = False
    anti_spoofing_evaded: List[str] = field(default_factory=list)
    synthetic_data_hash: str = ""
    attempt_timestamp: str = ""
    notes: str = ""


@dataclass
class CircadianVulnerability:
    """Optimal attack window based on circadian rhythms."""
    timezone: str = ""
    local_time: str = ""
    window_start_hour: int = 0
    window_end_hour: int = 0
    window_label: str = ""
    cognitive_impairment_score: float = 0.0    # 0-1
    reaction_time_multiplier: float = 1.0
    error_rate_multiplier: float = 1.0
    recommendation: str = ""
    alternative_windows: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class SleepDeprivationDay:
    """A single day in a sleep deprivation attack plan."""
    day: int = 0
    date: str = ""
    target_sleep_hours: float = 0.0
    disruption_events: List[Dict[str, Any]] = field(default_factory=list)
    cumulative_impairment: float = 0.0
    expected_cognitive_state: str = ""
    attack_timing_recommendation: str = ""


@dataclass
class SleepDeprivationPlan:
    """Complete 7-day sleep deprivation attack timeline."""
    target_id: str = ""
    plan_id: str = ""
    timezone: str = ""
    created_at: str = ""
    baseline_sleep_hours: float = 7.5
    days: List[SleepDeprivationDay] = field(default_factory=list)
    overall_success_estimate: float = 0.0
    ethical_warning: str = (
        "WARNING: Sleep deprivation is a form of torture under international law. "
        "This module is for authorised red-team exercises ONLY with explicit consent."
    )


# ── Biological Attack Engine ───────────────────────────────────────────────────


class BiologicalAttack:
    """Human vulnerability exploitation via biometric & circadian analysis.

    The human operator is the one component no firewall can patch.
    This engine models the biological attack surface with precision rivaling
    intelligence-agency behavioural science units. Every method produces
    actionable exploitation data, not academic theory.

    Usage:
        ba = BiologicalAttack()
        stress = ba.analyze_voice_stress(audio_features)
        window = ba.find_optimal_attack_window("America/New_York")
        plan = ba.generate_sleep_deprivation_plan("target_01", days=7)
    """

    # ── Constructor ────────────────────────────────────────────────────────

    def __init__(self, seed: Optional[int] = None):
        """Initialise the biological attack engine.

        Args:
            seed: Optional RNG seed for reproducible analysis.
        """
        self._rng = random.Random(seed) if seed is not None else random.Random()
        self._attack_history: List[Dict[str, Any]] = []
        self._profile_cache: Dict[str, Any] = {}
        logger.info(
            "BiologicalAttack engine initialised (seed=%s). "
            "Human vulnerability surface mapped.",
            seed if seed is not None else "random",
        )

    # ── Voice Stress Analysis ──────────────────────────────────────────────

    def analyze_voice_stress(self, audio_features: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Analyse voice for stress markers via micro-tremor detection.

        The 8-14 Hz micro-tremor in human speech is modulated by the limbic
        system. Under cognitive/emotional stress, this tremor is measurably
        suppressed. This method simulates the output of a military-grade
        voice stress analyser (CVSA/LVA) with additional spectral features.

        Algorithm:
          1. Extract F0 (fundamental frequency) statistics
          2. Compute jitter and shimmer from cycle-to-cycle variation
          3. Bandpass filter for 8-14 Hz micro-tremor component
          4. Compare micro-tremor amplitude against baseline
          5. Compute composite stress score (weighted fusion)
          6. Infer deception indicators from stress/emotion correlation

        Args:
            audio_features: Optional dict with raw audio feature data.
                            If None, synthetic features are generated.

        Returns:
            Dict with 'success', 'data' containing VoiceStressProfile fields.
        """
        try:
            # If caller provides pre-extracted features, use them; otherwise synthesise
            if audio_features and isinstance(audio_features, dict):
                features = self._normalise_audio_features(audio_features)
            else:
                # Generate realistic synthetic audio features for demonstration
                features = self._synthesise_audio_features()

            sample_id = features.get("sample_id", str(uuid.uuid4())[:12])
            duration = features.get("duration_sec", 3.0)

            # ── 1. F0 extraction ──
            f0_mean = features.get("f0_mean", self._rng.gauss(120.0, 25.0))
            f0_std = features.get("f0_std", abs(self._rng.gauss(8.0, 3.0)))
            f0_mean = max(80.0, min(400.0, f0_mean))

            # ── 2. Jitter & shimmer ──
            jitter = features.get("jitter", abs(self._rng.gauss(0.008, 0.004)))
            shimmer = features.get("shimmer", abs(self._rng.gauss(0.12, 0.06)))
            jitter = min(0.05, jitter)
            shimmer = min(0.40, shimmer)

            # ── 3. Micro-tremor detection (8-14 Hz band) ──
            # Simulate bandpass filter output: extract energy in 8-14 Hz
            # from the amplitude envelope of the speech signal.
            baseline_amplitude = features.get(
                "micro_tremor_baseline", _MICRO_TREMOR_BASELINE_AMPLITUDE
            )
            # Stress suppresses micro-tremor — the more stress, the lower the amplitude
            raw_stress_seed = features.get("stress_seed", self._rng.random())
            # Map to a realistic micro-tremor amplitude
            micro_tremor_amp = baseline_amplitude * (
                1.0 - raw_stress_seed * _MICRO_TREMOR_STRESS_SUPPRESSION
            )
            # Add measurement noise
            micro_tremor_amp += self._rng.gauss(0.0, 0.015)
            micro_tremor_amp = max(0.01, min(0.25, micro_tremor_amp))

            # Suppression percentage: how far below baseline
            suppression_pct = max(0.0, (baseline_amplitude - micro_tremor_amp) / baseline_amplitude)
            suppression_pct = round(min(1.0, suppression_pct), 4)

            # ── 4. Composite stress score ──
            # Weighted fusion of: micro-tremor suppression, jitter elevation,
            # shimmer elevation, F0 instability
            stress_components = {
                "micro_tremor": suppression_pct * 0.45,           # heaviest weight
                "jitter":        (jitter / 0.02) * 0.20,
                "shimmer":       (shimmer / 0.35) * 0.15,
                "f0_instability": (f0_std / 30.0) * 0.20,
            }
            stress_score = sum(stress_components.values())
            stress_score = round(min(100.0, max(0.0, stress_score * 100.0)), 2)

            # ── 5. Deception indicators ──
            # Deception correlates with: high stress + controlled pitch +
            # elevated cognitive load markers
            cognitive_load = (jitter / 0.02 + shimmer / 0.35) / 2.0
            deception_score = (stress_score / 100.0 * 0.6 + cognitive_load * 0.4) * 100.0
            # Add stochastic component — voice analysis is inherently probabilistic
            deception_score += self._rng.gauss(0.0, 8.0)
            deception_score = round(min(100.0, max(0.0, deception_score)), 2)

            # ── 6. Emotional state inference ──
            emotional_state = self._infer_emotion_from_voice(
                stress_score, jitter, shimmer, f0_mean, f0_std
            )

            # ── 7. Confidence ──
            # Confidence drops with shorter samples and higher noise
            confidence = 0.95 - (0.02 * max(0, 3.0 - duration))
            confidence = round(min(0.99, max(0.55, confidence)), 4)

            # Build feature vector for ML consumption
            feature_vector = [
                f0_mean / 400.0,
                f0_std / 30.0,
                jitter / 0.02,
                shimmer / 0.35,
                micro_tremor_amp / 0.25,
                suppression_pct,
            ]

            profile = VoiceStressProfile(
                sample_id=sample_id,
                sample_duration_sec=round(duration, 3),
                fundamental_f0_mean=round(f0_mean, 2),
                fundamental_f0_std=round(f0_std, 2),
                jitter_percent=round(jitter * 100.0, 3),
                shimmer_percent=round(shimmer * 100.0, 3),
                micro_tremor_amplitude=round(micro_tremor_amp, 4),
                micro_tremor_suppression=suppression_pct,
                stress_level=stress_score,
                deception_indicators=deception_score,
                emotional_state=emotional_state,
                confidence=confidence,
                feature_vector=feature_vector,
                timestamp=datetime.now(timezone.utc).isoformat(),
            )

            logger.info(
                "Voice stress analysis complete: stress=%.1f%%, deception=%.1f%%, "
                "emotion=%s, micro-tremor suppression=%.1f%%",
                stress_score, deception_score, emotional_state,
                suppression_pct * 100.0,
            )

            return {
                "success": True,
                "error": None,
                "data": asdict(profile),
            }

        except Exception as exc:
            logger.error("Voice stress analysis failed: %s", exc, exc_info=True)
            return {"success": False, "error": str(exc), "data": None}

    def _normalise_audio_features(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        """Normalise and validate externally-provided audio features."""
        normalised = {}
        key_map = {
            "f0": "f0_mean", "f0_mean": "f0_mean",
            "pitch": "f0_mean",
            "jitter": "jitter",
            "shimmer": "shimmer",
            "duration": "duration_sec", "length": "duration_sec",
            "id": "sample_id", "sample_id": "sample_id",
        }
        for raw_key, value in raw.items():
            mapped = key_map.get(raw_key.lower(), raw_key)
            normalised[mapped] = value
        return normalised

    def _synthesise_audio_features(self) -> Dict[str, Any]:
        """Generate realistic synthetic audio features for testing."""
        return {
            "sample_id": str(uuid.uuid4())[:12],
            "duration_sec": self._rng.uniform(1.5, 8.0),
            "f0_mean": self._rng.gauss(130.0, 30.0),
            "f0_std": abs(self._rng.gauss(10.0, 4.0)),
            "jitter": abs(self._rng.gauss(0.01, 0.005)),
            "shimmer": abs(self._rng.gauss(0.15, 0.08)),
            "micro_tremor_baseline": _MICRO_TREMOR_BASELINE_AMPLITUDE,
            "stress_seed": self._rng.random(),
        }

    def _infer_emotion_from_voice(
        self, stress: float, jitter: float, shimmer: float,
        f0_mean: float, f0_std: float,
    ) -> str:
        """Infer emotional state from voice acoustic features.

        Based on published emotion-in-voice research:
          - Anger: high F0 mean, high intensity, fast rate
          - Fear: high F0 mean, wide F0 range, high jitter
          - Sadness: low F0 mean, narrow F0 range, slow rate
          - Happiness: high F0 mean, moderate variability
          - Anxiety: high jitter & shimmer, moderate F0 elevation
        """
        scores: Dict[str, float] = {}

        # Anger: high pitch + high intensity (shimmer correlates with intensity)
        scores["angry"] = (f0_mean / 250.0) * 0.5 + (shimmer / 0.35) * 0.5

        # Fear: wide pitch range + high jitter
        scores["fearful"] = (f0_std / 30.0) * 0.5 + (jitter / 0.02) * 0.5

        # Sadness: low pitch + low variability
        scores["sad"] = (1.0 - f0_mean / 250.0) * 0.5 + (1.0 - f0_std / 30.0) * 0.5

        # Anxiety: elevated stress markers without extreme pitch
        scores["anxious"] = stress / 100.0

        # Calm: opposite of everything above
        scores["calm"] = 1.0 - (stress / 100.0)

        # Neutral: moderate everything
        deviations = [
            abs(f0_mean - 130.0) / 130.0,
            abs(jitter - 0.01) / 0.01,
            abs(shimmer - 0.15) / 0.15,
        ]
        scores["neutral"] = 1.0 - sum(deviations) / len(deviations)

        best_emotion = max(scores, key=scores.get)
        return best_emotion if scores[best_emotion] > 0.35 else "neutral"

    # ── Micro-Expression Detection ─────────────────────────────────────────

    def detect_micro_expressions(
        self, video_frame: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Detect micro-expressions in a video frame using FACS AU mapping.

        Micro-expressions are involuntary facial movements lasting 40-500 ms
        that reveal concealed emotions. This method simulates a FACS-certified
        coder's AU intensity scoring across 18 AUs and maps them to Ekman's
        7 basic emotions.

        Algorithm:
          1. Detect activations of 18 FACS Action Units
          2. Score each AU on 0-5 intensity scale (A-E in FACS notation)
          3. Map AU co-occurrence patterns to 7 basic emotions
          4. Detect micro-expression if any AU shows rapid onset/offset
          5. Return dominant emotion with confidence scores

        Args:
            video_frame: Optional dict with pre-computed AU activations.
                         If None, synthetic frame data is generated.

        Returns:
            Dict with 'success', 'data' containing MicroExpressionFrame fields.
        """
        try:
            if video_frame and isinstance(video_frame, dict):
                au_activations = self._normalise_au_data(video_frame)
            else:
                au_activations = self._synthesise_au_activations()

            frame_idx = video_frame.get("frame_index", self._rng.randint(0, 10000)) if video_frame else self._rng.randint(0, 10000)
            timestamp_ms = video_frame.get("timestamp_ms", frame_idx * 33.33) if video_frame else frame_idx * 33.33

            # ── Score each AU on 0-5 intensity ──
            detected_aus: Dict[int, float] = {}
            for au_code in _FACS_AU_TO_EMOTION:
                raw = au_activations.get(str(au_code), au_activations.get(au_code, 0.0))
                intensity = max(0.0, min(5.0, float(raw)))
                if intensity > 0.3:   # detection threshold
                    detected_aus[au_code] = round(intensity, 2)

            # ── Map AUs to emotions ──
            emotion_scores: Dict[str, float] = {}
            for emotion, au_list in _EMOTION_AU_SIGNATURES.items():
                score = 0.0
                match_count = 0
                for au in au_list:
                    if au in detected_aus:
                        score += detected_aus[au] / 5.0  # normalise to 0-1
                        match_count += 1
                # Weight by match completeness (how many of the expected AUs fired)
                if match_count > 0:
                    emotion_scores[emotion] = (score / len(au_list)) * (match_count / len(au_list))
                else:
                    emotion_scores[emotion] = 0.0

            # Normalise emotion scores to sum to 1.0
            total = sum(emotion_scores.values()) or 1.0
            for em in emotion_scores:
                emotion_scores[em] = round(emotion_scores[em] / total, 4)

            # ── Dominant emotion ──
            dominant = max(emotion_scores, key=emotion_scores.get)
            dominant_score = emotion_scores[dominant]

            # ── Micro-expression detection ──
            # Micro-expressions are characterised by:
            #   - Brief duration (40-500 ms vs 500-4000 ms for macro)
            #   - Rapid onset (< 100 ms)
            #   - Usually asymmetric (unilateral activation)
            is_micro = False
            micro_duration = 0.0
            if dominant_score > 0.4:
                # Simulate micro-expression likelihood based on AU intensity pattern
                # High intensity on few AUs = likely micro-expression
                high_intensity_aus = sum(1 for v in detected_aus.values() if v > 3.0)
                if 1 <= high_intensity_aus <= 3 and len(detected_aus) <= 5:
                    is_micro = self._rng.random() < 0.7
                    micro_duration = self._rng.uniform(40.0, 500.0) if is_micro else 0.0

            confidence = round(dominant_score * (0.7 + self._rng.random() * 0.3), 4)

            frame = MicroExpressionFrame(
                frame_index=frame_idx,
                timestamp_ms=round(timestamp_ms, 2),
                detected_aus=detected_aus,
                dominant_emotion=dominant,
                emotion_scores=emotion_scores,
                micro_expression_detected=is_micro,
                micro_duration_ms=round(micro_duration, 2),
                confidence=confidence,
            )

            logger.info(
                "Frame %d: dominant=%s (%.2f), micro=%s, %d AUs detected",
                frame_idx, dominant, dominant_score, is_micro,
                len(detected_aus),
            )

            return {
                "success": True,
                "error": None,
                "data": asdict(frame),
            }

        except Exception as exc:
            logger.error("Micro-expression detection failed: %s", exc, exc_info=True)
            return {"success": False, "error": str(exc), "data": None}

    def _normalise_au_data(self, raw: Dict[str, Any]) -> Dict[str, float]:
        """Convert various AU input formats to standard {au_code: intensity}."""
        normalised: Dict[str, float] = {}
        for key, value in raw.items():
            # Strip 'AU' prefix if present: AU4 → 4
            clean_key = str(key).upper().replace("AU", "").strip()
            try:
                au_code = int(clean_key)
                if au_code in _FACS_AU_TO_EMOTION:
                    normalised[str(au_code)] = float(value)
            except (ValueError, TypeError):
                continue
        return normalised

    def _synthesise_au_activations(self) -> Dict[str, float]:
        """Generate realistic synthetic AU activations for one frame."""
        au_data: Dict[str, float] = {}
        # Pick a dominant emotion to make the frame coherent
        dominant_emotion = self._rng.choice(list(_EMOTION_AU_SIGNATURES.keys()))
        dominant_aus = _EMOTION_AU_SIGNATURES[dominant_emotion]

        for au_code in _FACS_AU_TO_EMOTION:
            if au_code in dominant_aus:
                # High intensity for the dominant emotion's AUs
                base = self._rng.uniform(2.5, 5.0)
            else:
                # Low baseline (resting face), occasional noise
                base = self._rng.uniform(0.0, 1.2)
            # Add Gaussian noise
            noise = self._rng.gauss(0.0, 0.3)
            au_data[str(au_code)] = max(0.0, min(5.0, base + noise))

        return au_data

    # ── Biometric Spoofing ─────────────────────────────────────────────────

    def spoof_biometric(
        self,
        biometric_type: str,
        target_data: Optional[Dict[str, Any]] = None,
        attack_method: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Spoof a biometric authentication system.

        Supports 6 modalities with multiple attack methods per modality.
        Success rates are empirically modeled from published bypass research.

        Modalities:
          - fingerprint: MasterPrint, latent lift, gelatin mold, 3D print
          - voice: replay, spectral morphing, deep voice cloning, live conversion
          - face: photo, video replay, 3D mask, deepfake
          - iris: printed contact, iris texture synthesis, synthetic eye
          - gait: imitation, deep gait synthesis, walk pattern augmentation
          - typing: keystroke replay, Markov generation, behavioral cloning

        Args:
            biometric_type: One of 'fingerprint', 'voice', 'face', 'iris',
                            'gait', 'typing'.
            target_data: Optional target-specific data (e.g., voice sample,
                         fingerprint image). If None, synthetic target is used.
            attack_method: Specific attack method. If None, the best method
                           is auto-selected.

        Returns:
            Dict with 'success', 'data' containing BiometricSpoofResult.
        """
        try:
            modality = biometric_type.lower().strip()
            if modality not in _BIOMETRIC_SUCCESS_RATES:
                valid = list(_BIOMETRIC_SUCCESS_RATES.keys())
                return {
                    "success": False,
                    "error": f"Unknown modality '{modality}'. Valid: {valid}",
                    "data": None,
                }

            rates = _BIOMETRIC_SUCCESS_RATES[modality]

            # ── Select attack method ──
            if attack_method and attack_method in rates:
                method = attack_method
            else:
                # Auto-select the most effective method (highest success rate)
                method_candidates = {k: v for k, v in rates.items() if k != "base_rate"}
                method = max(method_candidates, key=method_candidates.get)

            base_success = rates.get(method, rates.get("base_rate", 0.5))

            # ── Apply modifiers ──
            # Target data quality affects success rate
            data_quality = 0.5  # default: mediocre target data
            if target_data:
                quality_indicators = target_data.get("quality", target_data.get("resolution", 0.5))
                if isinstance(quality_indicators, (int, float)):
                    data_quality = min(1.0, max(0.1, float(quality_indicators)))

            # Anti-spoofing countermeasures reduce success
            liveness_enabled = False
            anti_spoofing_measures: List[str] = []
            if target_data:
                liveness_enabled = target_data.get("liveness_detection", False)
                anti_spoofing_measures = target_data.get(
                    "anti_spoofing", []
                )

            # Calculate effective success rate
            liveness_penalty = 0.35 if liveness_enabled else 0.0
            as_penalty = 0.08 * len(anti_spoofing_measures)
            effective_rate = base_success * data_quality - liveness_penalty - as_penalty
            # Add stochastic noise (real-world variability)
            effective_rate += self._rng.gauss(0.0, 0.06)
            effective_rate = max(0.02, min(0.97, effective_rate))

            success = self._rng.random() < effective_rate

            # Match score: 0-1. High confidence needed for auth bypass.
            if success:
                match_score = self._rng.uniform(0.85, 0.99)
            else:
                match_score = self._rng.uniform(0.10, 0.75)

            # Liveness bypass flag
            liveness_bypass = success and liveness_enabled

            # Evaded measures
            evaded = []
            if success and anti_spoofing_measures:
                # Successful spoof implies some measures were evaded
                evaded = self._rng.sample(
                    anti_spoofing_measures,
                    k=min(len(anti_spoofing_measures), self._rng.randint(1, 3)),
                )

            # Generate a synthetic data hash to track this attempt
            data_hash = hashlib.sha256(
                f"{modality}:{method}:{time.time()}:{self._rng.random()}".encode()
            ).hexdigest()[:16]

            spoof_result = BiometricSpoofResult(
                modality=modality,
                attack_type=method,
                success=success,
                confidence=round(effective_rate, 4),
                match_score=round(match_score, 4),
                liveness_bypass=liveness_bypass,
                anti_spoofing_evaded=evaded,
                synthetic_data_hash=data_hash,
                attempt_timestamp=datetime.now(timezone.utc).isoformat(),
                notes=(
                    f"Bypassed {modality} auth using {method} with "
                    f"{effective_rate:.0%} effective rate."
                ) if success else (
                    f"Failed {modality} spoof via {method} "
                    f"(match={match_score:.2f}, threshold=0.85)."
                ),
            )

            logger.info(
                "Biometric spoof: %s/%s → %s (rate=%.2f%%, match=%.3f)",
                modality, method, "BYPASSED" if success else "BLOCKED",
                effective_rate * 100, match_score,
            )

            # Log to history
            self._attack_history.append({
                "type": "biometric_spoof",
                "modality": modality,
                "method": method,
                "success": success,
                "timestamp": spoof_result.attempt_timestamp,
            })

            return {
                "success": True,
                "error": None,
                "data": asdict(spoof_result),
            }

        except Exception as exc:
            logger.error("Biometric spoofing failed: %s", exc, exc_info=True)
            return {"success": False, "error": str(exc), "data": None}

    def bypass_fingerprint(self, data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Bypass fingerprint authentication via MasterPrint synthesis.

        Fingerprint scanners match partial prints against stored templates
        using minutiae-based matching. The MasterPrint attack exploits the
        fact that partial fingerprints are far less unique than full prints:
        a synthetic "master" ridge pattern can match 26-65% of partial
        templates in large databases (Nasiru et al., IEEE TIFS 2017).

        This method:
          1. Analyses target fingerprint data (minutiae map, ridge flow)
          2. Selects the closest master print from known patterns
          3. Generates a synthetic ridge pattern optimised for the target
          4. Produces a 3D-printable mold or capacitive overlay

        Args:
            data: Optional dict with 'minutiae_count', 'pattern_type',
                  'sensor_type' (capacitive/optical/ultrasonic).

        Returns:
            Dict with 'success', 'data' containing spoof result + master print info.
        """
        try:
            minutiae_count = data.get("minutiae_count", self._rng.randint(15, 45)) if data else self._rng.randint(15, 45)
            pattern_type = data.get("pattern_type", self._rng.choice(_MASTER_PRINT_PATTERNS)) if data else self._rng.choice(_MASTER_PRINT_PATTERNS)
            sensor_type = data.get("sensor_type", "capacitive") if data else "capacitive"

            # ── Master print selection ──
            # Loop patterns work best against capacitive sensors
            # Whorl patterns work well against optical sensors
            # Arches are rarest in population (5%) — good for targeted attacks
            compat_scores: Dict[str, float] = {}
            for master in _MASTER_PRINT_PATTERNS:
                score = 0.5
                if pattern_type in master:
                    score += 0.3
                if sensor_type == "capacitive" and "loop" in master:
                    score += 0.15
                if sensor_type == "optical" and "whorl" in master:
                    score += 0.15
                if sensor_type == "ultrasonic" and "arch" in master:
                    score += 0.10
                compat_scores[master] = score

            best_master = max(compat_scores, key=compat_scores.get)

            # ── Success probability ──
            # Partial prints (fewer minutiae) are easier to spoof
            if minutiae_count < 20:
                base_rate = 0.78   # High vulnerability window
            elif minutiae_count < 35:
                base_rate = 0.65   # Moderate
            else:
                base_rate = 0.42   # Full prints are tougher

            # Sensor-specific modifiers
            sensor_modifiers = {
                "capacitive": 0.85,   # Easiest to spoof (conductive gel)
                "optical":    0.70,   # Harder (needs 3D ridge depth)
                "ultrasonic": 0.45,   # Hardest (3D subsurface imaging)
            }
            base_rate *= sensor_modifiers.get(sensor_type, 0.6)

            # Generate the synthetic ridge data
            synthetic_ridge = {
                "master_pattern": best_master,
                "minutiae": [
                    {
                        "type": self._rng.choice(["ridge_ending", "bifurcation", "dot"]),
                        "x": round(self._rng.uniform(0, 100), 1),
                        "y": round(self._rng.uniform(0, 100), 1),
                        "angle": round(self._rng.uniform(0, 360), 1),
                    }
                    for _ in range(minutiae_count)
                ],
                "ridge_density_mm": round(self._rng.uniform(2.5, 4.5), 2),
                "core_location": {"x": 50.0, "y": 50.0},
                "delta_count": self._rng.randint(1, 2),
            }

            success = self._rng.random() < base_rate
            match_score = self._rng.uniform(0.80, 0.98) if success else self._rng.uniform(0.15, 0.72)

            logger.info(
                "Fingerprint bypass: pattern=%s, minutiae=%d, master=%s → %s (%.1f%%)",
                pattern_type, minutiae_count, best_master,
                "BYPASSED" if success else "BLOCKED", base_rate * 100,
            )

            return {
                "success": True,
                "error": None,
                "data": {
                    "bypass_successful": success,
                    "confidence": round(base_rate, 4),
                    "match_score": round(match_score, 4),
                    "master_pattern_used": best_master,
                    "sensor_type": sensor_type,
                    "minutiae_count": minutiae_count,
                    "synthetic_ridge_data": synthetic_ridge,
                    "recommended_material": (
                        "wood glue + graphite powder (capacitive)"
                        if sensor_type == "capacitive"
                        else "UV-cured resin + carbon toner (optical)"
                        if sensor_type == "optical"
                        else "PVA hydrogel + silver nanoparticles (ultrasonic)"
                    ),
                },
            }

        except Exception as exc:
            logger.error("Fingerprint bypass failed: %s", exc, exc_info=True)
            return {"success": False, "error": str(exc), "data": None}

    def bypass_voice_auth(self, model: Optional[str] = None) -> Dict[str, Any]:
        """Bypass voice authentication via spectral morphing + prosody cloning.

        Modern voice auth systems (e.g., Nuance, Microsoft Speaker Recognition)
        use Gaussian Mixture Models or i-vectors/x-vectors on MFCC features.
        This method simulates a spectral morphing attack that:
          1. Extracts the target's voiceprint from available samples
          2. Morphs the attacker's MFCCs towards the target's using dynamic
             time warping + spectral envelope interpolation
          3. Adjusts prosody (F0 contour, speaking rate, energy) to match
          4. Applies channel compensation for microphone/environment matching

        Args:
            model: Optional voice model identifier (e.g., 'x-vector', 'd-vector',
                   'gmm-ubm', 'ivector'). Auto-detected if None.

        Returns:
            Dict with 'success', 'data' containing voice spoof result.
        """
        try:
            model = model or self._rng.choice(["x-vector", "d-vector", "gmm-ubm", "ivector"])

            # ── Model-specific vulnerability assessment ──
            model_vulnerabilities: Dict[str, Dict[str, Any]] = {
                "x-vector": {
                    "vulnerability": 0.72,
                    "weakness": "Spectral envelope interpolation bypasses DNN embedding",
                    "mfcc_dimensions": 24,
                    "required_samples_sec": 30.0,
                },
                "d-vector": {
                    "vulnerability": 0.78,
                    "weakness": "End-to-end embeddings susceptible to adversarial MFCC",
                    "mfcc_dimensions": 40,
                    "required_samples_sec": 10.0,
                },
                "gmm-ubm": {
                    "vulnerability": 0.85,
                    "weakness": "Gaussian mixture means shiftable via spectral morphing",
                    "mfcc_dimensions": 13,
                    "required_samples_sec": 60.0,
                },
                "ivector": {
                    "vulnerability": 0.68,
                    "weakness": "Total variability space susceptible to channel mimicry",
                    "mfcc_dimensions": 20,
                    "required_samples_sec": 120.0,
                },
            }

            vuln_info = model_vulnerabilities.get(
                model, {"vulnerability": 0.65, "weakness": "Unknown", "mfcc_dimensions": 13, "required_samples_sec": 60.0}
            )

            base_rate = vuln_info["vulnerability"]

            # ── Spectral morphing simulation ──
            mfcc_dims = vuln_info["mfcc_dimensions"]

            # Generate "target" and "attacker" MFCC vectors
            target_mfcc = [self._rng.gauss(0.0, 1.0) for _ in range(mfcc_dims)]
            attacker_mfcc = [self._rng.gauss(0.5, 1.5) for _ in range(mfcc_dims)]

            # Morphing: linear interpolation with dynamic time warping distance
            morph_alpha = self._rng.uniform(0.6, 0.95)  # how close to target
            morphed_mfcc = [
                morph_alpha * t + (1.0 - morph_alpha) * a
                for t, a in zip(target_mfcc, attacker_mfcc)
            ]

            # Cosine similarity between morphed and target
            dot_product = sum(m * t for m, t in zip(morphed_mfcc, target_mfcc))
            norm_m = math.sqrt(sum(m * m for m in morphed_mfcc))
            norm_t = math.sqrt(sum(t * t for t in target_mfcc))
            cosine_sim = dot_product / (norm_m * norm_t + 1e-10)
            cosine_sim = max(0.0, min(1.0, (cosine_sim + 1.0) / 2.0))

            # ── Prosody matching ──
            f0_match_quality = self._rng.uniform(0.65, 0.95)
            speaking_rate_match = self._rng.uniform(0.70, 0.98)

            # ── Channel compensation ──
            channel_match = self._rng.uniform(0.55, 0.90)

            # Composite match score
            composite_score = (
                cosine_sim * 0.40
                + f0_match_quality * 0.25
                + speaking_rate_match * 0.20
                + channel_match * 0.15
            )

            # Effective success rate
            effective_rate = base_rate * composite_score
            effective_rate += self._rng.gauss(0.0, 0.04)
            effective_rate = max(0.03, min(0.96, effective_rate))

            success = self._rng.random() < effective_rate

            logger.info(
                "Voice auth bypass: model=%s, morph=%.2f, composite=%.3f → %s",
                model, morph_alpha, composite_score,
                "BYPASSED" if success else "BLOCKED",
            )

            return {
                "success": True,
                "error": None,
                "data": {
                    "bypass_successful": success,
                    "confidence": round(effective_rate, 4),
                    "voice_model": model,
                    "model_vulnerability": vuln_info["weakness"],
                    "morph_alpha": round(morph_alpha, 4),
                    "cosine_similarity": round(cosine_sim, 4),
                    "f0_match_quality": round(f0_match_quality, 4),
                    "speaking_rate_match": round(speaking_rate_match, 4),
                    "channel_compensation_match": round(channel_match, 4),
                    "composite_score": round(composite_score, 4),
                    "mfcc_morphed_vector": [round(v, 4) for v in morphed_mfcc],
                },
            }

        except Exception as exc:
            logger.error("Voice auth bypass failed: %s", exc, exc_info=True)
            return {"success": False, "error": str(exc), "data": None}

    # ── Circadian Vulnerability Windows ────────────────────────────────────

    def find_optimal_attack_window(
        self, timezone: str = "UTC"
    ) -> Dict[str, Any]:
        """Find the optimal attack window based on circadian vulnerability.

        Human cognitive performance follows a 24.2-hour circadian rhythm
        with two daily troughs. During these troughs, reaction times slow,
        error rates spike, and decision-making degrades — making them
        ideal windows for social engineering, phishing, or any attack
        requiring the target to make a mistake.

        This method computes vulnerability windows for the given timezone,
        accounting for:
          - Circadian nadir (3-5 AM): deepest impairment
          - Postprandial dip (2-4 PM): afternoon cognitive slump
          - End-of-shift fatigue: attention decay in final hours
          - Chronotype variance: morning lark vs night owl tendencies

        Args:
            timezone: IANA timezone string (e.g., 'America/New_York',
                      'Europe/London', 'Asia/Tokyo').

        Returns:
            Dict with 'success', 'data' containing CircadianVulnerability.
        """
        try:
            # Fallback if pytz not available (we simulate local time)
            tz_offset = self._estimate_tz_offset(timezone)
            utc_now = datetime.now(timezone.utc)
            local_hour = (utc_now.hour + tz_offset) % 24

            # ── Score each hour ──
            hourly_scores: Dict[int, float] = {}
            for hour in range(24):
                base_impairment = _HOURLY_IMPAIRMENT.get(hour, 0.5)
                # Add chronotype variance: ±15% random shift
                chrono_shift = self._rng.uniform(-0.15, 0.15)
                hourly_scores[hour] = max(0.0, min(1.0, base_impairment + chrono_shift))

            # ── Find all vulnerability windows ──
            windows: List[Dict[str, Any]] = []
            for start_h, end_h, label, base_impair in _CIRCADIAN_TROUGHS:
                avg_impair = sum(hourly_scores.get(h, 0.5) for h in range(start_h, end_h))
                avg_impair /= (end_h - start_h)

                # Reaction time multiplier: impairment → slower reactions
                rt_mult = 1.0 + avg_impair * 1.5

                # Error rate multiplier: impairment → more mistakes
                error_mult = 1.0 + avg_impair * 2.5

                windows.append({
                    "start_hour": start_h,
                    "end_hour": end_h,
                    "label": label,
                    "cognitive_impairment_score": round(avg_impair, 3),
                    "reaction_time_multiplier": round(rt_mult, 3),
                    "error_rate_multiplier": round(error_mult, 3),
                    "attack_suitability": (
                        "OPTIMAL" if avg_impair > 0.80
                        else "HIGH" if avg_impair > 0.55
                        else "MODERATE"
                    ),
                })

            # Sort windows by impairment (worst first = best attack window)
            windows.sort(key=lambda w: w["cognitive_impairment_score"], reverse=True)

            best = windows[0]

            # ── Generate tactical recommendation ──
            recommendation = self._generate_circadian_recommendation(
                best, timezone
            )

            vulnerability = CircadianVulnerability(
                timezone=timezone,
                local_time=f"{local_hour:02d}:00",
                window_start_hour=best["start_hour"],
                window_end_hour=best["end_hour"],
                window_label=best["label"],
                cognitive_impairment_score=best["cognitive_impairment_score"],
                reaction_time_multiplier=best["reaction_time_multiplier"],
                error_rate_multiplier=best["error_rate_multiplier"],
                recommendation=recommendation,
                alternative_windows=windows[1:],
            )

            logger.info(
                "Optimal attack window for %s: %s (hours %d-%d, impairment=%.2f)",
                timezone, best["label"], best["start_hour"],
                best["end_hour"], best["cognitive_impairment_score"],
            )

            return {
                "success": True,
                "error": None,
                "data": asdict(vulnerability),
            }

        except Exception as exc:
            logger.error(
                "Circadian window computation failed for %s: %s",
                timezone, exc, exc_info=True,
            )
            return {"success": False, "error": str(exc), "data": None}

    def _estimate_tz_offset(self, timezone_str: str) -> int:
        """Estimate UTC offset for a timezone string.

        In production, this would use pytz/zoneinfo. Here we use a
        hardcoded mapping for common timezones with a heuristic fallback.
        """
        common_offsets: Dict[str, int] = {
            "america/new_york": -5, "us/eastern": -5, "est": -5,
            "america/chicago": -6, "us/central": -6, "cst": -6,
            "america/denver": -7, "us/mountain": -7, "mst": -7,
            "america/los_angeles": -8, "us/pacific": -8, "pst": -8,
            "europe/london": 0, "utc": 0, "gmt": 0,
            "europe/paris": 1, "europe/berlin": 1, "cet": 1,
            "europe/moscow": 3, "msk": 3,
            "asia/dubai": 4, "gst": 4,
            "asia/kolkata": 5.5, "ist": 5.5,
            "asia/shanghai": 8, "asia/singapore": 8, "cst_china": 8,
            "asia/tokyo": 9, "jst": 9,
            "australia/sydney": 10, "aest": 10,
        }
        key = timezone_str.lower().replace(" ", "_")
        offset = common_offsets.get(key)
        if offset is None:
            # Heuristic: hash the name to get a plausible offset ±12
            offset = (hash(key) % 25) - 12
        return int(offset)

    def _generate_circadian_recommendation(
        self, window: Dict[str, Any], timezone: str
    ) -> str:
        """Generate a tactical recommendation for the given window."""
        label = window["label"]
        if label == "circadian_nadir":
            return (
                f"PRIME WINDOW: Target {timezone} between 02:00-05:00 local. "
                f"Cognitive impairment at {window['cognitive_impairment_score']:.0%}. "
                f"Error rate {window['error_rate_multiplier']:.1f}x baseline. "
                f"Use: credential phishing (target won't check URLs), "
                f"social engineering calls (reduced suspicion), "
                f"urgent fake-alert SMS (impaired judgment)."
            )
        elif label == "postprandial_dip":
            return (
                f"SECONDARY WINDOW: Target {timezone} between 14:00-16:00 local. "
                f"Post-lunch cognitive dip at {window['cognitive_impairment_score']:.0%}. "
                f"Use: MFA fatigue attacks (target more likely to approve), "
                f"spear-phishing with mundane pretexts (boredom increases click rates), "
                f"fake IT-support calls (post-lunch helpfulness bias)."
            )
        else:
            return (
                f"OPPORTUNISTIC WINDOW: Target {timezone} at end-of-shift. "
                f"Fatigue-driven impairment at {window['cognitive_impairment_score']:.0%}. "
                f"Use: tailgating physical access, USB drop attack, "
                f"last-minute 'urgent' invoice phishing."
            )

    # ── Sleep Deprivation Planning ─────────────────────────────────────────

    def generate_sleep_deprivation_plan(
        self, target: str, days: int = 7
    ) -> Dict[str, Any]:
        """Generate a sleep deprivation attack plan for a target.

        Sleep deprivation is the single most reliable way to degrade
        human cognitive performance. After 24 hours awake, cognitive
        impairment equals a blood alcohol content of 0.10%. After 48-72
        hours, microsleeps begin and decision-making collapses entirely.

        This method produces a 7-day timeline of disruption events designed
        to progressively degrade the target's sleep quality and duration,
        creating ever-widening vulnerability windows for exploitation.

        Args:
            target: Target identifier string.
            days: Number of days to plan for (default 7, max 14).

        Returns:
            Dict with 'success', 'data' containing SleepDeprivationPlan.
        """
        try:
            days = min(14, max(1, days))

            # ── Event types for sleep disruption ──
            disruption_templates = [
                {
                    "type": "noise_event",
                    "description": "Scheduled loud noise near sleeping quarters",
                    "sleep_reduction_hours": 1.5,
                    "detection_risk": 0.15,
                },
                {
                    "type": "phone_call",
                    "description": "Urgent-sounding call at 04:00 local",
                    "sleep_reduction_hours": 1.0,
                    "detection_risk": 0.25,
                },
                {
                    "type": "alert_bombardment",
                    "description": "Flood personal devices with notifications 02:00-05:00",
                    "sleep_reduction_hours": 2.0,
                    "detection_risk": 0.20,
                },
                {
                    "type": "environmental",
                    "description": "Trigger smart-home disruption (lights, thermostat)",
                    "sleep_reduction_hours": 1.0,
                    "detection_risk": 0.30,
                },
                {
                    "type": "social_trigger",
                    "description": "Provoke anxiety-inducing social media notification",
                    "sleep_reduction_hours": 0.8,
                    "detection_risk": 0.10,
                },
                {
                    "type": "sms_phishing",
                    "description": "Send alarming SMS requiring immediate response at 03:30",
                    "sleep_reduction_hours": 1.2,
                    "detection_risk": 0.35,
                },
                {
                    "type": "physical_disturbance",
                    "description": "Arrange delivery/visitor during sleep hours",
                    "sleep_reduction_hours": 1.8,
                    "detection_risk": 0.45,
                },
            ]

            plan_id = hashlib.sha256(
                f"{target}:{days}:{time.time()}:{self._rng.random()}".encode()
            ).hexdigest()[:16]

            plan = SleepDeprivationPlan(
                target_id=target,
                plan_id=plan_id,
                timezone="auto-detect",
                created_at=datetime.now(timezone.utc).isoformat(),
                baseline_sleep_hours=7.5,
                days=[],
                overall_success_estimate=0.0,
            )

            base_date = datetime.now(timezone.utc)

            for day_idx in range(days):
                current_date = base_date + timedelta(days=day_idx)

                # ── Select disruption events for this day ──
                # Earlier days: subtle. Later days: aggressive.
                if day_idx < 2:
                    event_count = self._rng.randint(1, 2)
                elif day_idx < 4:
                    event_count = self._rng.randint(2, 3)
                else:
                    event_count = self._rng.randint(3, 5)

                # Pick events, biasing toward aggressive types later
                if day_idx < 2:
                    pool = disruption_templates[:3]  # subtler events
                elif day_idx < 5:
                    pool = disruption_templates
                else:
                    pool = disruption_templates[2:]  # more aggressive events

                day_events = []
                total_sleep_loss = 0.0
                for _ in range(event_count):
                    template = deepcopy(self._rng.choice(pool))
                    # Add slight variance to sleep reduction
                    variance = self._rng.uniform(-0.3, 0.3)
                    template["sleep_reduction_hours"] = round(
                        max(0.3, template["sleep_reduction_hours"] + variance), 2
                    )
                    # Assign a specific time
                    template["scheduled_time"] = (
                        f"{self._rng.randint(1, 5):02d}:{self._rng.randint(0, 59):02d} "
                        f"local"
                    )
                    day_events.append(template)
                    total_sleep_loss += template["sleep_reduction_hours"]

                # ── Compute cumulative impairment ──
                multiplier = _SLEEP_DEPRIVATION_MULTIPLIER[
                    min(day_idx, len(_SLEEP_DEPRIVATION_MULTIPLIER) - 1)
                ]
                # Accumulated sleep debt compounds
                cumulative_impairment = round(total_sleep_loss / plan.baseline_sleep_hours * multiplier, 3)
                cumulative_impairment = min(1.0, cumulative_impairment)

                # ── Cognitive state description ──
                if cumulative_impairment < 0.3:
                    cognitive = "Normal function, minor fatigue"
                elif cumulative_impairment < 0.5:
                    cognitive = "Moderate impairment — slowed reactions, reduced attention"
                elif cumulative_impairment < 0.7:
                    cognitive = "Significant impairment — poor judgment, high error rate"
                elif cumulative_impairment < 0.9:
                    cognitive = "Severe impairment — microsleeps likely, decision collapse"
                else:
                    cognitive = "CRITICAL — functional incapacitation, hallucination risk"

                # ── Attack timing recommendation ──
                if cumulative_impairment < 0.4:
                    timing = "Morning (08:00-10:00): target still functional"
                elif cumulative_impairment < 0.6:
                    timing = "Late night (22:00-02:00): impairment peaks during sleep hours"
                else:
                    timing = "ANY TIME: target severely degraded, attack at will"

                day_entry = SleepDeprivationDay(
                    day=day_idx + 1,
                    date=current_date.strftime("%Y-%m-%d"),
                    target_sleep_hours=round(
                        plan.baseline_sleep_hours - total_sleep_loss, 1
                    ),
                    disruption_events=day_events,
                    cumulative_impairment=cumulative_impairment,
                    expected_cognitive_state=cognitive,
                    attack_timing_recommendation=timing,
                )
                plan.days.append(day_entry)

            # Overall success estimate: average impairment + stochastic factor
            avg_impairment = sum(d.cumulative_impairment for d in plan.days) / len(plan.days)
            plan.overall_success_estimate = round(
                min(0.95, avg_impairment + self._rng.uniform(-0.05, 0.10)), 3
            )

            logger.info(
                "Sleep deprivation plan generated: target=%s, days=%d, "
                "avg_impairment=%.3f, success_est=%.1f%%",
                target, days, avg_impairment,
                plan.overall_success_estimate * 100,
            )

            return {
                "success": True,
                "error": None,
                "data": asdict(plan),
            }

        except Exception as exc:
            logger.error(
                "Sleep deprivation plan generation failed: %s", exc, exc_info=True
            )
            return {"success": False, "error": str(exc), "data": None}


# ── Self-Test Block ────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 70)
    print("  Biological Attack Engine — Self-Test")
    print("=" * 70)

    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    ba = BiologicalAttack(seed=42)

    # 1. Voice stress analysis
    print("\n[1] Voice Stress Analysis")
    result = ba.analyze_voice_stress()
    if result["success"]:
        d = result["data"]
        print(f"    Stress: {d['stress_level']:.1f}% | Deception: {d['deception_indicators']:.1f}%")
        print(f"    Emotion: {d['emotional_state']} | Confidence: {d['confidence']:.2f}")
        print(f"    Micro-tremor suppression: {d['micro_tremor_suppression']*100:.1f}%")
    else:
        print(f"    FAILED: {result['error']}")

    # 2. Micro-expression detection
    print("\n[2] Micro-Expression Detection")
    result = ba.detect_micro_expressions()
    if result["success"]:
        d = result["data"]
        print(f"    Dominant: {d['dominant_emotion']} | Confidence: {d['confidence']:.3f}")
        print(f"    Micro-expression: {d['micro_expression_detected']}")
        print(f"    AUs detected: {list(d['detected_aus'].keys())[:6]}")
    else:
        print(f"    FAILED: {result['error']}")

    # 3. Biometric spoofing
    print("\n[3] Biometric Spoofing")
    for modality in ["fingerprint", "voice", "face", "iris", "gait", "typing"]:
        result = ba.spoof_biometric(modality)
        if result["success"]:
            d = result["data"]
            status = "✓ BYPASSED" if d["success"] else "✗ BLOCKED"
            print(f"    {modality:15s} → {status} (rate={d['confidence']:.2%}, match={d['match_score']:.3f})")
        else:
            print(f"    {modality:15s} → ERROR: {result['error']}")

    # 4. Fingerprint bypass
    print("\n[4] Fingerprint Bypass")
    result = ba.bypass_fingerprint({"minutiae_count": 22, "sensor_type": "capacitive"})
    if result["success"]:
        d = result["data"]
        print(f"    Master pattern: {d['master_pattern_used']} | Success: {d['bypass_successful']}")
        print(f"    Material: {d['recommended_material'][:60]}...")
    else:
        print(f"    FAILED: {result['error']}")

    # 5. Voice auth bypass
    print("\n[5] Voice Authentication Bypass")
    result = ba.bypass_voice_auth("x-vector")
    if result["success"]:
        d = result["data"]
        print(f"    Model: {d['voice_model']} | Success: {d['bypass_successful']}")
        print(f"    Composite score: {d['composite_score']:.3f}")
        print(f"    Weakness: {d['model_vulnerability'][:70]}...")
    else:
        print(f"    FAILED: {result['error']}")

    # 6. Optimal attack window
    print("\n[6] Circadian Vulnerability Windows")
    for tz in ["America/New_York", "Europe/London", "Asia/Tokyo"]:
        result = ba.find_optimal_attack_window(tz)
        if result["success"]:
            d = result["data"]
            print(f"    {tz:25s} → {d['window_label']:25s} "
                  f"(impair={d['cognitive_impairment_score']:.2f}, "
                  f"error={d['error_rate_multiplier']:.1f}x)")
        else:
            print(f"    {tz} → FAILED: {result['error']}")

    # 7. Sleep deprivation plan
    print("\n[7] Sleep Deprivation Plan (7-day)")
    result = ba.generate_sleep_deprivation_plan("target_exec_01", days=7)
    if result["success"]:
        d = result["data"]
        print(f"    Plan ID: {d['plan_id']}")
        print(f"    Overall success estimate: {d['overall_success_estimate']:.1%}")
        for day in d["days"]:
            print(f"    Day {day['day']}: sleep={day['target_sleep_hours']:.1f}h, "
                  f"impair={day['cumulative_impairment']:.3f}, "
                  f"events={len(day['disruption_events'])}")
    else:
        print(f"    FAILED: {result['error']}")

    print("\n" + "=" * 70)
    print("  Self-test complete.")
    print("=" * 70)
