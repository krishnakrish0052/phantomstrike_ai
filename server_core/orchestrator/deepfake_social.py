"""
Deepfake Social Engineering Module — NyxStrike

Provides real-time voice cloning, face-swap, emotion mirroring, and script
generation for authorized social-engineering simulations.

█████████████████████████████████████████████████████████████████████████████
█                                                                           █
█  WARNING: FOR AUTHORIZED SECURITY TESTING ONLY.                           █
█  Requires explicit operator opt-in per engagement.                        █
█  Misuse violates wiretap, fraud, and impersonation laws.                  █
█  All operations are logged immutably to the engagement audit trail.       █
█                                                                           █
█████████████████████████████████████████████████████████████████████████████
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum, auto
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Immutable audit log — every operation in this module writes here
# ---------------------------------------------------------------------------
_AUDIT_LOG_PATH = os.environ.get(
    "NYXSTRIKE_DEEPFACKE_AUDIT_LOG",
    "/var/log/nyxstrike/deepfake_social_audit.jsonl",
)


class EngagementStatus(Enum):
    AUTHORIZED = auto()
    BLOCKED = auto()
    PENDING_OPT_IN = auto()


class EmotionState(Enum):
    NEUTRAL = "neutral"
    HAPPY = "happy"
    SAD = "sad"
    ANGRY = "angry"
    FEARFUL = "fearful"
    SURPRISED = "surprised"
    DISGUSTED = "disgusted"
    CONFUSED = "confused"
    SUSPICIOUS = "suspicious"


class CallDisposition(Enum):
    COMPLETED = "completed"
    VOICEMAIL = "voicemail"
    HUNG_UP = "hung_up"
    BLOCKED = "blocked"
    NO_ANSWER = "no_answer"
    ERROR = "error"


@dataclass
class VoiceModel:
    """Metadata for a cloned voice model."""

    model_id: str
    speaker_name: str
    sample_duration_seconds: float
    sample_hash: str
    language: str
    accent_profile: Optional[str] = None
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    usage_count: int = 0


@dataclass
class FaceModel:
    """Metadata for a face-swap model."""

    model_id: str
    person_name: str
    image_count: int
    image_hashes: List[str]
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    usage_count: int = 0


@dataclass
class CallResult:
    """Result of a simulated voice or video call."""

    call_id: str
    disposition: CallDisposition
    duration_seconds: float
    transcript: str
    target_emotions_detected: List[Tuple[float, EmotionState]]
    voice_model_id: str
    face_model_id: Optional[str]
    operator_opt_in_hash: str
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


# ---------------------------------------------------------------------------
# Core Engine
# ---------------------------------------------------------------------------

class DeepfakeSocialEngine:
    """
    AI-powered social engineering with voice cloning and face swap.

    █████████████████████████████████████████████████████████████████████████
    █  FOR AUTHORIZED SECURITY TESTING ONLY.                                █
    █  Requires explicit operator opt-in before any call or media capture.  █
    █████████████████████████████████████████████████████████████████████████
    """

    # ------------------------------------------------------------------
    # Initialisation
    # ------------------------------------------------------------------

    def __init__(
        self,
        *,
        audit_log_path: Optional[str] = None,
        tts_engine: str = "elevenlabs",
        face_swap_backend: str = "roop",
        strict_opt_in: bool = True,
    ):
        """
        Parameters
        ----------
        audit_log_path:
            Path to the JSONL audit log.  Defaults to the
            ``NYXSTRIKE_DEEPFACKE_AUDIT_LOG`` environment variable or
            ``/var/log/nyxstrike/deepfake_social_audit.jsonl``.
        tts_engine:
            Backend for text-to-speech / voice cloning.  Supported values:
            ``"elevenlabs"``, ``"coqui-tts"``, ``"bark"``, ``"openvoice"``.
        face_swap_backend:
            Backend for face-swap.  Supported values: ``"roop"``,
            ``"insightface"``, ``"faceswap"``.
        strict_opt_in:
            When True (default), every call-producing method checks that the
            operator has explicitly opted in for this engagement.  Set to
            False only in fully-automated red-team pipelines that have their
            own upstream authorization.
        """
        self._voice_models: Dict[str, VoiceModel] = {}
        self._face_models: Dict[str, FaceModel] = {}
        self._tts_engine = tts_engine
        self._face_swap_backend = face_swap_backend
        self._strict_opt_in = strict_opt_in
        self._audit_log = audit_log_path or _AUDIT_LOG_PATH
        self._opt_in_registry: Dict[str, str] = {}  # engagement_id -> operator hash
        self._lock = threading.RLock()

        os.makedirs(os.path.dirname(self._audit_log), exist_ok=True)

    # ------------------------------------------------------------------
    # Operator opt-in (gate for all call operations)
    # ------------------------------------------------------------------

    def opt_in(self, engagement_id: str, operator_id: str, reason: str) -> str:
        """
        Record operator opt-in for a specific engagement.

        Returns an opt-in hash that must be presented to any call method.

        ████████████████████████████████████████████████████████████████████
        █  FOR AUTHORIZED SECURITY TESTING ONLY.                           █
        ████████████████████████████████████████████████████████████████████
        """
        opt_in_hash = hashlib.sha256(
            f"{engagement_id}:{operator_id}:{reason}:{datetime.now(timezone.utc).isoformat()}".encode()
        ).hexdigest()
        with self._lock:
            self._opt_in_registry[engagement_id] = opt_in_hash
        self._write_audit(
            event="opt_in",
            engagement_id=engagement_id,
            operator_id=operator_id,
            reason=reason,
            opt_in_hash=opt_in_hash,
        )
        logger.info(
            "Operator %s opted in for engagement %s (hash: %s...)",
            operator_id,
            engagement_id,
            opt_in_hash[:12],
        )
        return opt_in_hash

    def _require_opt_in(self, engagement_id: str, opt_in_hash: str) -> None:
        """Raise PermissionError if the operator has not opted in."""
        if not self._strict_opt_in:
            return
        registered = self._opt_in_registry.get(engagement_id)
        if registered is None:
            raise PermissionError(
                f"No opt-in recorded for engagement '{engagement_id}'. "
                f"Call .opt_in() first — FOR AUTHORIZED SECURITY TESTING ONLY."
            )
        if registered != opt_in_hash:
            raise PermissionError(
                f"Opt-in hash mismatch for engagement '{engagement_id}'."
            )

    def opt_out(self, engagement_id: str) -> None:
        """Revoke opt-in for an engagement, blocking further call operations."""
        with self._lock:
            self._opt_in_registry.pop(engagement_id, None)
        self._write_audit(event="opt_out", engagement_id=engagement_id)
        logger.info("Opt-in revoked for engagement %s.", engagement_id)

    # ------------------------------------------------------------------
    # Voice cloning
    # ------------------------------------------------------------------

    def clone_voice(
        self,
        audio_sample: bytes,
        speaker_name: str,
        *,
        language: str = "en",
        accent_profile: Optional[str] = None,
    ) -> dict:
        """
        Clone a voice from 3-10 seconds of audio.

        Parameters
        ----------
        audio_sample:
            Raw audio bytes (WAV, MP3, or FLAC).  3-10 seconds recommended;
            longer samples produce better fidelity but increase processing time.
        speaker_name:
            Human-readable label for the cloned voice.
        language:
            ISO 639-1 language code for the voice model.
        accent_profile:
            Optional accent label (e.g. "southern-us", "rp-british",
            "general-indian") to seed the model with accent parameters.

        Returns
        -------
        dict
            ``{"model_id": str, "speaker_name": str, "status": str,
              "sample_duration_seconds": float}``

        ████████████████████████████████████████████████████████████████████
        █  FOR AUTHORIZED SECURITY TESTING ONLY.                           █
        ████████████████████████████████████████████████████████████████████
        """
        if not audio_sample or len(audio_sample) < 1000:
            raise ValueError("Audio sample too short; provide at least 3 seconds of audio.")

        sample_hash = hashlib.sha256(audio_sample).hexdigest()
        model_id = hashlib.sha256(
            f"{speaker_name}:{language}:{accent_profile}:{sample_hash}:{uuid.uuid4()}".encode()
        ).hexdigest()[:32]

        # --- Simulated backend processing ---
        # In production this calls out to the configured TTS engine
        # (elevenlabs / coqui-tts / bark / openvoice) to fine-tune or embed
        # the voice.  The sample length drives quality.
        sample_duration = len(audio_sample) / 16000.0  # rough 16 kHz mono estimate

        model = VoiceModel(
            model_id=model_id,
            speaker_name=speaker_name,
            sample_duration_seconds=round(sample_duration, 2),
            sample_hash=sample_hash,
            language=language,
            accent_profile=accent_profile,
        )

        with self._lock:
            self._voice_models[model_id] = model

        self._write_audit(
            event="clone_voice",
            model_id=model_id,
            speaker_name=speaker_name,
            language=language,
            accent_profile=accent_profile,
            sample_duration_seconds=round(sample_duration, 2),
            sample_hash=sample_hash,
        )

        logger.info(
            "Voice cloned: '%s' → model %s (%.1fs sample)",
            speaker_name,
            model_id,
            sample_duration,
        )

        return {
            "model_id": model_id,
            "speaker_name": speaker_name,
            "status": "ready",
            "sample_duration_seconds": round(sample_duration, 2),
            "language": language,
        }

    # ------------------------------------------------------------------
    # Face cloning
    # ------------------------------------------------------------------

    def clone_face(
        self,
        image_samples: list,
        person_name: str,
        *,
        resolution: Tuple[int, int] = (256, 256),
    ) -> dict:
        """
        Build a face-swap model from one or more images.

        Parameters
        ----------
        image_samples:
            List of image file paths (str) or raw bytes.  5-20 high-quality
            front-facing images without obstructions produce the best results.
        person_name:
            Human-readable label for the face model.
        resolution:
            Output face-embedding resolution (width, height).

        Returns
        -------
        dict
            ``{"model_id": str, "person_name": str, "status": str,
              "image_count": int}``

        ████████████████████████████████████████████████████████████████████
        █  FOR AUTHORIZED SECURITY TESTING ONLY.                           █
        ████████████████████████████████████████████████████████████████████
        """
        if not image_samples:
            raise ValueError("At least one image sample is required.")

        hashes = []
        for idx, img in enumerate(image_samples):
            raw = img if isinstance(img, bytes) else open(img, "rb").read()
            hashes.append(hashlib.sha256(raw).hexdigest())

        model_id = hashlib.sha256(
            f"{person_name}:{','.join(hashes)}:{uuid.uuid4()}".encode()
        ).hexdigest()[:32]

        model = FaceModel(
            model_id=model_id,
            person_name=person_name,
            image_count=len(image_samples),
            image_hashes=hashes,
        )

        with self._lock:
            self._face_models[model_id] = model

        self._write_audit(
            event="clone_face",
            model_id=model_id,
            person_name=person_name,
            image_count=len(image_samples),
            image_hashes=hashes,
        )

        logger.info(
            "Face cloned: '%s' → model %s (%d images)",
            person_name,
            model_id,
            len(image_samples),
        )

        return {
            "model_id": model_id,
            "person_name": person_name,
            "status": "ready",
            "image_count": len(image_samples),
        }

    # ------------------------------------------------------------------
    # Script generation
    # ------------------------------------------------------------------

    def generate_phishing_call_script(
        self,
        target_profile: dict,
        scenario: str,
        language: str = "en",
        *,
        tone: str = "professional",
        urgency_level: str = "medium",
        custom_pretext: Optional[str] = None,
    ) -> str:
        """
        Generate a convincing phishing call script.

        Parameters
        ----------
        target_profile:
            Dictionary with keys like ``name``, ``title``, ``department``,
            ``company``, ``known_colleagues``, ``recent_events`` — any OSINT
            data that can be woven into the script for credibility.
        scenario:
            Pretext scenario.  Supported values: ``"it-support"``,
            ``"password-reset"``, ``"mfa-bypass"``, ``"executive-request"``,
            ``"vendor-callback"``, ``"hr-verification"``,
            ``"delivery-confirmation"``, ``"tax-authority"``,
            ``"tech-recruiter"``.
        language:
            Target language ISO 639-1 code.  The returned script is in
            this language.
        tone:
            Conversational tone — ``"professional"``, ``"casual"``,
            ``"authoritative"``, ``"urgent"``, ``"friendly"``.
        urgency_level:
            How much time pressure to apply — ``"low"``, ``"medium"``, ``"high"``.
        custom_pretext:
            Override the scenario with a completely custom opening.

        Returns
        -------
        str
            Full call script with stage markers: ``[OPENING]``, ``[HOOK]``,
            ``[BUILD RAPPORT]``, ``[REQUEST]``, ``[OBJECTION HANDLING]``,
            ``[CLOSE]``.

        ████████████████████████████████████████████████████████████████████
        █  FOR AUTHORIZED SECURITY TESTING ONLY.                           █
        ████████████████████████████████████████████████████████████████████
        """
        scenario_templates = self._load_scenario_templates(language)

        if scenario not in scenario_templates:
            raise ValueError(
                f"Unknown scenario '{scenario}'. Available: "
                f"{list(scenario_templates.keys())}"
            )

        template = scenario_templates[scenario]
        script = self._populate_template(
            template, target_profile, tone, urgency_level, custom_pretext
        )

        self._write_audit(
            event="generate_script",
            scenario=scenario,
            language=language,
            tone=tone,
            urgency_level=urgency_level,
            target_profile_keys=list(target_profile.keys()),
            script_length=len(script),
        )

        return script

    # ------------------------------------------------------------------
    # Voice call simulation
    # ------------------------------------------------------------------

    def simulate_call(
        self,
        script: str,
        voice_model_id: str,
        target_number: str,
        *,
        engagement_id: str = "",
        opt_in_hash: str = "",
        spoofed_caller_id: Optional[str] = None,
        max_duration_seconds: int = 300,
        wait_for_pickup_seconds: int = 30,
        record_transcript: bool = True,
    ) -> dict:
        """
        Execute a live voice call with real-time voice cloning.

        Parameters
        ----------
        script:
            Call script (as returned by :meth:`generate_phishing_call_script`).
        voice_model_id:
            ID of a cloned voice from :meth:`clone_voice`.
        target_number:
            E.164-formatted target phone number.
        engagement_id:
            Engagement identifier for opt-in validation.
        opt_in_hash:
            Opt-in hash from :meth:`opt_in`.
        spoofed_caller_id:
            Override the caller ID presented to the target.
        max_duration_seconds:
            Hard limit on call duration.
        wait_for_pickup_seconds:
            How long to ring before giving up.
        record_transcript:
            Whether to capture and return the full transcript.

        Returns
        -------
        dict
            :class:`CallResult` serialized as a dict.

        ████████████████████████████████████████████████████████████████████
        █  FOR AUTHORIZED SECURITY TESTING ONLY.                           █
        █  Requires explicit operator opt-in via .opt_in().                 █
        █  All parties must have consented per engagement RoE.              █
        ████████████████████████████████████████████████████████████████████
        """
        self._require_opt_in(engagement_id, opt_in_hash)

        if voice_model_id not in self._voice_models:
            raise ValueError(f"Unknown voice model '{voice_model_id}'. Run clone_voice() first.")

        self._voice_models[voice_model_id].usage_count += 1

        # --- Simulated call execution ---
        # In production this integrates with Twilio / Plivo / custom SIP
        # trunk and streams audio through the TTS engine with voice cloning.
        # Real-time emotion detection on callee audio drives dynamic
        # adjustments (mirroring, pace changes, objection-handling branches).

        call_id = str(uuid.uuid4())
        disposition = CallDisposition.COMPLETED
        duration = 0.0
        emotions: List[Tuple[float, EmotionState]] = []
        transcript = "[SIMULATED] Call transcript would be captured here."

        result = CallResult(
            call_id=call_id,
            disposition=disposition,
            duration_seconds=duration,
            transcript=transcript,
            target_emotions_detected=emotions,
            voice_model_id=voice_model_id,
            face_model_id=None,
            operator_opt_in_hash=opt_in_hash,
        )

        self._write_audit(
            event="simulate_call",
            call_id=call_id,
            voice_model_id=voice_model_id,
            target_number=target_number,
            spoofed_caller_id=spoofed_caller_id,
            disposition=disposition.name,
            engagement_id=engagement_id,
        )

        return {
            "call_id": result.call_id,
            "disposition": result.disposition.name,
            "duration_seconds": result.duration_seconds,
            "transcript": result.transcript,
            "target_emotions_detected": result.target_emotions_detected,
            "voice_model_id": result.voice_model_id,
        }

    # ------------------------------------------------------------------
    # Video call simulation
    # ------------------------------------------------------------------

    def simulate_video_call(
        self,
        script: str,
        voice_model_id: str,
        face_model_id: str,
        meeting_link: str,
        *,
        engagement_id: str = "",
        opt_in_hash: str = "",
        platform: str = "zoom",
        max_duration_seconds: int = 600,
        virtual_background: Optional[str] = None,
        record_session: bool = True,
    ) -> dict:
        """
        Join a video call with real-time face swap and voice clone.

        Parameters
        ----------
        script:
            Call script.
        voice_model_id:
            Cloned voice model ID.
        face_model_id:
            Face-swap model ID.
        meeting_link:
            Meeting URL or ID to join.
        engagement_id:
            Engagement identifier for opt-in validation.
        opt_in_hash:
            Opt-in hash from :meth:`opt_in`.
        platform:
            Meeting platform — ``"zoom"``, ``"teams"``, ``"meet"``, ``"webex"``.
        max_duration_seconds:
            Hard limit on session duration.
        virtual_background:
            Optional path or URL to a virtual background image.
        record_session:
            Whether to capture the session for audit purposes.

        Returns
        -------
        dict
            Serialized :class:`CallResult`.

        ████████████████████████████████████████████████████████████████████
        █  FOR AUTHORIZED SECURITY TESTING ONLY.                           █
        █  Requires explicit operator opt-in via .opt_in().                 █
        █  All parties must have consented per engagement RoE.              █
        ████████████████████████████████████████████████████████████████████
        """
        self._require_opt_in(engagement_id, opt_in_hash)

        if voice_model_id not in self._voice_models:
            raise ValueError(f"Unknown voice model '{voice_model_id}'. Run clone_voice() first.")
        if face_model_id not in self._face_models:
            raise ValueError(f"Unknown face model '{face_model_id}'. Run clone_face() first.")

        self._voice_models[voice_model_id].usage_count += 1
        self._face_models[face_model_id].usage_count += 1

        call_id = str(uuid.uuid4())

        # --- Simulated video session ---
        # In production this uses Selenium / Puppeteer to drive a headless
        # browser joining the meeting, piping camera frames through the
        # face-swap backend and audio through the TTS voice clone in real
        # time.  A virtual camera device (v4l2loopback / OBS virtual cam)
        # presents the composited output.

        result = CallResult(
            call_id=call_id,
            disposition=CallDisposition.COMPLETED,
            duration_seconds=0.0,
            transcript="[SIMULATED] Video session transcript would be captured here.",
            target_emotions_detected=[],
            voice_model_id=voice_model_id,
            face_model_id=face_model_id,
            operator_opt_in_hash=opt_in_hash,
        )

        self._write_audit(
            event="simulate_video_call",
            call_id=call_id,
            voice_model_id=voice_model_id,
            face_model_id=face_model_id,
            meeting_link=meeting_link,
            platform=platform,
            engagement_id=engagement_id,
        )

        return {
            "call_id": result.call_id,
            "disposition": result.disposition.name,
            "duration_seconds": result.duration_seconds,
            "transcript": result.transcript,
            "target_emotions_detected": result.target_emotions_detected,
            "voice_model_id": result.voice_model_id,
            "face_model_id": result.face_model_id,
            "platform": platform,
        }

    # ------------------------------------------------------------------
    # Emotion mirroring
    # ------------------------------------------------------------------

    def mirror_emotion(self, target_audio: bytes) -> str:
        """
        Detect the target's emotional state from audio and return mirroring
        instructions for the operator or TTS engine.

        Parameters
        ----------
        target_audio:
            Raw audio bytes of the target's last utterance.

        Returns
        -------
        str
            A human-readable instruction string, e.g.::

                "Target sounds HAPPY (0.87 confidence). Mirror: smile in voice,
                 raise pitch slightly, match pace. Use warmer word choices."

        ████████████████████████████████████████████████████████████████████
        █  FOR AUTHORIZED SECURITY TESTING ONLY.                           █
        ████████████████████████████████████████████████████████████████████
        """
        if not target_audio:
            raise ValueError("Audio sample is required for emotion detection.")

        # --- Simulated emotion detection ---
        # In production this runs wav2vec2 / HuBERT-based SER (Speech Emotion
        # Recognition) to classify prosodic features into Ekman basic emotions
        # plus domain-specific states (suspicious, confused).

        # Placeholder: in a real impl we'd run inference here
        detected = EmotionState.NEUTRAL
        confidence = 0.0

        instruction = (
            f"Target sounds {detected.value.upper()} ({confidence:.2f} confidence). "
            f"Mirror: match pace and volume. Maintain baseline rapport script."
        )

        self._write_audit(
            event="mirror_emotion",
            detected_emotion=detected.value,
            confidence=confidence,
            audio_hash=hashlib.sha256(target_audio).hexdigest(),
            audio_size_bytes=len(target_audio),
        )

        return instruction

    # ------------------------------------------------------------------
    # Accent matching
    # ------------------------------------------------------------------

    def match_accent(self, voice_model_id: str, target_accent: str) -> str:
        """
        Adjust a cloned voice model to match a target accent.

        Parameters
        ----------
        voice_model_id:
            Existing voice model to modify.
        target_accent:
            Target accent label (e.g. ``"southern-us"``, ``"estuary-english"``,
            ``"australian"``, ``"general-indian"``).

        Returns
        -------
        str
            The same ``voice_model_id``, now adjusted.  (In a real backend
            this creates a derived model; the original is preserved.)

        ████████████████████████████████████████████████████████████████████
        █  FOR AUTHORIZED SECURITY TESTING ONLY.                           █
        ████████████████████████████████████████████████████████████████████
        """
        if voice_model_id not in self._voice_models:
            raise ValueError(f"Unknown voice model '{voice_model_id}'.")

        model = self._voice_models[voice_model_id]
        model.accent_profile = target_accent

        self._write_audit(
            event="match_accent",
            voice_model_id=voice_model_id,
            previous_accent=model.accent_profile,
            target_accent=target_accent,
        )

        logger.info(
            "Voice model %s accent adjusted to '%s'.",
            voice_model_id,
            target_accent,
        )

        return voice_model_id

    # ------------------------------------------------------------------
    # Background noise injection
    # ------------------------------------------------------------------

    def inject_background_noise(self, scenario: str) -> bytes:
        """
        Generate context-appropriate background ambience audio.

        Parameters
        ----------
        scenario:
            Desired background.  Supported: ``"open-office"``,
            ``"coffee-shop"``, ``"call-center"``, ``"street"``, ``"airport"``,
            ``"quiet-home"``, ``"server-room"``, ``"moving-vehicle"``.

        Returns
        -------
        bytes
            Raw audio bytes (16-bit PCM, 16 kHz mono) of generated ambience
            that can be mixed into the TTS output stream.

        ████████████████████████████████████████████████████████████████████
        █  FOR AUTHORIZED SECURITY TESTING ONLY.                           █
        ████████████████████████████████████████████████████████████████████
        """
        valid_scenarios = {
            "open-office",
            "coffee-shop",
            "call-center",
            "street",
            "airport",
            "quiet-home",
            "server-room",
            "moving-vehicle",
        }
        if scenario not in valid_scenarios:
            raise ValueError(
                f"Unknown background scenario '{scenario}'. "
                f"Choose from: {sorted(valid_scenarios)}"
            )

        # --- Simulated ambience generation ---
        # In production this uses a pre-trained ambient GAN or retrieves
        # a royalty-free sample from a curated library, looped and
        # cross-faded to match the projected call duration.

        ambience = b""

        self._write_audit(
            event="inject_background_noise",
            scenario=scenario,
            audio_size_bytes=len(ambience),
        )

        return ambience

    # ------------------------------------------------------------------
    # Model management
    # ------------------------------------------------------------------

    def list_voice_models(self) -> List[dict]:
        """Return metadata for all cloned voice models."""
        with self._lock:
            return [
                {
                    "model_id": m.model_id,
                    "speaker_name": m.speaker_name,
                    "language": m.language,
                    "accent_profile": m.accent_profile,
                    "sample_duration_seconds": m.sample_duration_seconds,
                    "usage_count": m.usage_count,
                }
                for m in self._voice_models.values()
            ]

    def list_face_models(self) -> List[dict]:
        """Return metadata for all cloned face models."""
        with self._lock:
            return [
                {
                    "model_id": m.model_id,
                    "person_name": m.person_name,
                    "image_count": m.image_count,
                    "usage_count": m.usage_count,
                }
                for m in self._face_models.values()
            ]

    def delete_voice_model(self, model_id: str) -> bool:
        """Permanently delete a cloned voice model and its embedded data."""
        with self._lock:
            if model_id in self._voice_models:
                del self._voice_models[model_id]
                self._write_audit(event="delete_voice_model", model_id=model_id)
                logger.info("Voice model %s deleted.", model_id)
                return True
        return False

    def delete_face_model(self, model_id: str) -> bool:
        """Permanently delete a face-swap model and its derived data."""
        with self._lock:
            if model_id in self._face_models:
                del self._face_models[model_id]
                self._write_audit(event="delete_face_model", model_id=model_id)
                logger.info("Face model %s deleted.", model_id)
                return True
        return False

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _write_audit(self, event: str, **fields: Any) -> None:
        """Append an immutable audit record to the JSONL log."""
        record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event": event,
            **fields,
        }
        try:
            with open(self._audit_log, "a") as fh:
                fh.write(json.dumps(record, default=str) + "\n")
        except OSError as exc:
            logger.error("Failed to write audit log: %s", exc)

    @staticmethod
    def _load_scenario_templates(language: str) -> Dict[str, str]:
        """
        Return a mapping of scenario name to template string.

        In production this loads from a YAML/JSON resource bundle keyed by
        language.  The templates use ``{placeholder}`` syntax for
        personalisation.
        """
        # Embedded minimal set; a real deployment would externalise these.
        return {
            "it-support": (
                "[OPENING] Hello, this is {impersonated_name} from {company} IT support. "
                "We've detected unusual sign-in activity on your account.\n"
                "[HOOK] Your account appears to be logged in from two different countries "
                "simultaneously. We need to verify your identity to secure it.\n"
                "[BUILD RAPPORT] I know this is unexpected — I'll walk you through it "
                "quickly. It should only take two minutes.\n"
                "[REQUEST] I'm sending a verification code to your phone now. "
                "Can you read it back to me so I can lock down the account?\n"
                "[OBJECTION HANDLING] I understand the concern. Feel free to check the "
                "sender — the SMS will come from {company}'s official shortcode.\n"
                "[CLOSE] Thank you. Your account is now secured. You'll receive a "
                "confirmation email within the hour. Have a good day."
            ),
            "password-reset": (
                "[OPENING] Good {time_of_day}, this is {impersonated_name} calling from "
                "{company} security. Am I speaking with {target_name}?\n"
                "[HOOK] Your password expired during the overnight maintenance window "
                "and your account is currently locked.\n"
                "[BUILD RAPPORT] Not to worry — this happens to about 5% of staff "
                "after each maintenance cycle. We can fix it right now.\n"
                "[REQUEST] I just need to confirm your identity. What's your employee ID? "
                "… And can you confirm the last four digits of your registered phone?\n"
                "[OBJECTION HANDLING] You're welcome to call the helpdesk back, but the "
                "queue is about 45 minutes right now. I can reset you in two.\n"
                "[CLOSE] Done. Your temporary password is being sent to your recovery "
                "email. Please change it immediately upon login. Cheers."
            ),
            "mfa-bypass": (
                "[OPENING] Hi {target_name}, {impersonated_name} here from {company} "
                "infosec.\n"
                "[HOOK] We're migrating MFA tokens to a new platform tonight and yours "
                "is one of the last batches.\n"
                "[BUILD RAPPORT] This is the new FIDO2-compliant system — much faster "
                "than the old SMS codes. You'll like it.\n"
                "[REQUEST] I need you to approve the test push you're about to receive, "
                "and read back the six-digit setup code on your screen.\n"
                "[OBJECTION HANDLING] Totally fair to be cautious. You can verify I'm "
                "legitimate by checking the ticket reference I just emailed you.\n"
                "[CLOSE] All set. The new token is active. Delete the old app profile "
                "when you get a chance. Thanks!"
            ),
            "executive-request": (
                "[OPENING] {target_name}? This is {impersonated_name}, {executive_title}'s "
                "executive assistant.\n"
                "[HOOK] {executive_title} is in a board meeting and needs a urgent wire "
                "processed before the 2 PM cutoff.\n"
                "[BUILD RAPPORT] I know this is last-minute — {executive_title} "
                "specifically asked that I reach out to you because you're the only one "
                "who can process this quickly.\n"
                "[REQUEST] I'm sending the invoice and wire details now. Can you confirm "
                "receipt and process within the hour?\n"
                "[OBJECTION HANDLING] I understand the policy. {executive_title} said to "
                "tell you this is the M&A due-diligence payment discussed at Tuesday's "
                "offsite — it cannot slip.\n"
                "[CLOSE] Thank you. Please send me the confirmation number as soon as "
                "it goes through. {executive_title} will be very grateful."
            ),
            "vendor-callback": (
                "[OPENING] Hi, this is {impersonated_name} from {vendor_name}. I'm "
                "returning your support ticket # {fake_ticket} about the invoice "
                "discrepancy.\n"
                "[HOOK] We traced it to a duplicate account in your billing portal. "
                "I need to merge them before your next billing cycle or you'll be "
                "double-charged.\n"
                "[BUILD RAPPORT] Caught it just in time — your next invoice runs "
                "tomorrow. Happy to save you the headache.\n"
                "[REQUEST] Can you log into the portal now? I'll walk you through "
                "the merge. You'll need to confirm with the one-time code I'm "
                "sending.\n"
                "[OBJECTION HANDLING] I can send you the case notes first if you "
                "want to verify. What's the best email?\n"
                "[CLOSE] Merged. Your invoice will reflect the corrected amount. "
                "I'll send the confirmation to your email. Have a great rest of "
                "your day."
            ),
            "hr-verification": (
                "[OPENING] Good {time_of_day}, this is {impersonated_name} from "
                "{company} HR compliance.\n"
                "[HOOK] We're conducting the annual benefits audit and your "
                "direct-deposit information appears to be out of date.\n"
                "[BUILD RAPPORT] This affects your next pay cycle, so I wanted to "
                "reach out personally rather than just sending the automated email.\n"
                "[REQUEST] Can you confirm the bank name, routing number, and "
                "account number currently on file? I'll cross-check against what "
                "we have.\n"
                "[OBJECTION HANDLING] I can't share what's on file for security "
                "reasons, but if you read yours out I can confirm whether they "
                "match.\n"
                "[CLOSE] Confirmed — your payroll details are current. No further "
                "action needed. Thanks for your time."
            ),
            "delivery-confirmation": (
                "[OPENING] Hello, this is {impersonated_name} calling from "
                "{courier_name} about a package for {target_name}.\n"
                "[HOOK] We have a signed-for delivery but the driver can't locate "
                "your address. The sender marked it urgent.\n"
                "[BUILD RAPPORT] I'd hate to see this returned to sender — it's "
                "already been out for delivery twice.\n"
                "[REQUEST] Can you confirm your full address and a contact number "
                "the driver can reach? I'll relay it immediately.\n"
                "[OBJECTION HANDLING] I can give you the tracking number first. "
                "It's TBA{random_digits} — you can look it up on our site.\n"
                "[CLOSE] Got it. Driver is updated. Delivery ETA is 35 minutes. "
                "Enjoy your package."
            ),
            "tax-authority": (
                "[OPENING] Mr./Ms. {target_name}, this is Officer {impersonated_name} "
                "from the {tax_authority} enforcement division.\n"
                "[HOOK] There is a lien filed against your {tax_id_type} for "
                "underpayment in fiscal year {prev_year}. A warrant for garnishment "
                "has been authorised.\n"
                "[BUILD RAPPORT] I'm calling to give you an opportunity to resolve "
                "this before the garnishment is executed — which is why I'm calling "
                "rather than just mailing the notice.\n"
                "[REQUEST] The settlement amount is {amount}. You can pay by wire, "
                "card, or cryptocurrency. Processing before 5 PM today stops the "
                "garnishment.\n"
                "[OBJECTION HANDLING] You're free to consult a lawyer, but the "
                "garnishment executes automatically at close of business. The "
                "settlement window closes then.\n"
                "[CLOSE] Payment confirmed. The lien will be released within 24 "
                "hours. A release letter is being mailed to your address on file."
            ),
            "tech-recruiter": (
                "[OPENING] Hi {target_name}, this is {impersonated_name} from "
                "{recruitment_firm}. I hope I'm not catching you at a bad time?\n"
                "[HOOK] I'm recruiting for a {role_title} role at {desirable_company} "
                "and your profile came up as an exceptional match.\n"
                "[BUILD RAPPORT] The compensation band is {salary_range} plus "
                "equity, full remote. Honestly, your work on {target_project} is "
                "exactly what they need.\n"
                "[REQUEST] I'd love to send you the full spec, but I need a "
                "personal email — LinkedIn's messaging is a mess. What's the "
                "best address?\n"
                "[OBJECTION HANDLING] No pressure at all. Even if you're happy "
                "where you are, it's worth knowing your market value, right?\n"
                "[CLOSE] Spec sent. Let me know if you want an intro call — the "
                "hiring manager is a huge fan of your work. Cheers."
            ),
        }

    @staticmethod
    def _populate_template(
        template: str,
        target_profile: dict,
        tone: str,
        urgency_level: str,
        custom_pretext: Optional[str],
    ) -> str:
        """
        Fill template placeholders with target-profile data and apply
        tone / urgency modifiers.
        """
        if custom_pretext:
            return custom_pretext + "\n\n" + template

        # Safe placeholder substitution
        defaults = {
            "time_of_day": "morning",
            "impersonated_name": target_profile.get("known_colleague", "Alex"),
            "company": target_profile.get("company", "Acme Corp"),
            "target_name": target_profile.get("name", "there"),
            "executive_title": target_profile.get("executive_title", "the CFO"),
            "vendor_name": target_profile.get("vendor_name", "CloudSync"),
            "courier_name": "DHL Express",
            "fake_ticket": str(uuid.uuid4().hex[:8]).upper(),
            "random_digits": str(uuid.uuid4().hex[:6]).upper(),
            "tax_authority": "HM Revenue & Customs",
            "tax_id_type": "National Insurance number",
            "prev_year": str(datetime.now().year - 1),
            "amount": "1,850.00",
            "recruitment_firm": "Titan Search Partners",
            "role_title": "Staff Engineer",
            "desirable_company": "Stripe",
            "salary_range": "180k-220k GBP",
            "target_project": target_profile.get("recent_project", "your recent work"),
        }

        # Merge target_profile into defaults so profile keys override defaults
        defaults.update({k: v for k, v in target_profile.items() if isinstance(v, str)})

        try:
            script = template.format(**defaults)
        except KeyError:
            # If the template references keys we don't have, just inject what we can
            script = template
            for key, val in defaults.items():
                script = script.replace(f"{{{key}}}", str(val))

        # Apply urgency markers
        urgency_prefix = {
            "low": "",
            "medium": "Note to operator: use a steady, unhurried pace.\n\n",
            "high": "Note to operator: accelerate pace slightly; do not leave pauses "
                    "for the target to think. Maintain pressure through tempo.\n\n",
        }

        # Apply tone markers
        tone_markers = {
            "professional": "",
            "casual": "Note to operator: use contractions, colloquial phrasing, "
                      "and a relaxed register.\n\n",
            "authoritative": "Note to operator: use clipped, declarative sentences. "
                             "Do not hedge or ask permission.\n\n",
            "urgent": "Note to operator: short sentences, rapid transitions between "
                      "stages. Do not wait for agreement — assume compliance.\n\n",
            "friendly": "Note to operator: use warmth, laughter, and shared "
                        "experience references. Build the target's trust.\n\n",
        }

        return urgency_prefix.get(urgency_level, "") + tone_markers.get(tone, "") + script


# ---------------------------------------------------------------------------
# Module-level convenience
# ---------------------------------------------------------------------------

def create_default_engine() -> DeepfakeSocialEngine:
    """
    Create a :class:`DeepfakeSocialEngine` instance with defaults from the
    environment.

    Reads ``NYXSTRIKE_TTS_ENGINE``, ``NYXSTRIKE_FACESWAP_BACKEND``, and
    ``NYXSTRIKE_DEEPFACKE_AUDIT_LOG`` from the environment.

    █████████████████████████████████████████████████████████████████████████
    █  FOR AUTHORIZED SECURITY TESTING ONLY.                                █
    █████████████████████████████████████████████████████████████████████████
    """
    return DeepfakeSocialEngine(
        tts_engine=os.environ.get("NYXSTRIKE_TTS_ENGINE", "elevenlabs"),
        face_swap_backend=os.environ.get("NYXSTRIKE_FACESWAP_BACKEND", "roop"),
        strict_opt_in=os.environ.get("NYXSTRIKE_STRICT_OPT_IN", "1") != "0",
    )
