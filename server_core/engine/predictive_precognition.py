"""
server_core/engine/predictive_precognition.py

Predictive Defense Precognition — Anticipate and Preempt Defender Responses.

Before the payload lands, this engine models the defender's next move.
It learns from historical mission data, profiles target SOC teams,
and generates countermeasures that neutralise defenses before they activate.
Think of it as a temporal chess engine — predicting moves three steps ahead
so the attack lands before the defense is even conceived.

Core Capabilities:
  - Defense pattern library (20+ known defender responses)
  - Bayesian updating from mission history
  - Confidence scoring for each prediction
  - Timing estimation (how long until defender deploys X)
  - Countermeasure generation tailored to predicted defense
  - SOC team profiling and behavioral simulation

Classes:
  PredictivePrecognition  — main precognition engine
  DefensePrediction       — single predicted defense with metadata
  SOCProfile              — defender team behavioral model
"""

from __future__ import annotations

import hashlib
import logging
import math
import random
import time
import uuid
from collections import defaultdict
from copy import deepcopy
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta, timezone
from enum import Enum, auto
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union

logger = logging.getLogger(__name__)

# ── Constants ──────────────────────────────────────────────────────────────────

# Default prediction confidence decay per hour without intel
_CONFIDENCE_DECAY_RATE = 0.05
# Minimum confidence threshold to act on a prediction
_MIN_ACTIONABLE_CONFIDENCE = 0.55
# Maximum predictions to return per query
_MAX_PREDICTIONS = 10
# Bayesian prior smoothing factor (Laplace)
_BAYESIAN_SMOOTHING = 1.0
# Typical SOC response times in seconds (per defense type)
_DEFAULT_RESPONSE_TIMES: Dict[str, float] = {
    'patch_deployment': 86400.0,     # 24 hours
    'waf_rule': 3600.0,              # 1 hour
    'ips_signature': 7200.0,         # 2 hours
    'firewall_egress_block': 1800.0, # 30 min
    'dlp_alert': 600.0,              # 10 min
    'edr_scan': 3600.0,              # 1 hour
    'account_lockout': 300.0,        # 5 min
    'network_segmentation': 14400.0, # 4 hours
    'honeypot_deployment': 28800.0,  # 8 hours
    'log_review': 7200.0,            # 2 hours
    'incident_response': 3600.0,     # 1 hour
    'forensic_imaging': 14400.0,     # 4 hours
    'credential_rotation': 86400.0,  # 24 hours
    'vpn_termination': 600.0,        # 10 min
    'traffic_throttle': 1800.0,      # 30 min
    'dns_sinkhole': 14400.0,         # 4 hours
    'mfa_enforcement': 86400.0,      # 24 hours
    'cert_revocation': 3600.0,       # 1 hour
    'sandbox_detonation': 7200.0,    # 2 hours
    'threat_intel_share': 86400.0,   # 24 hours
}

# ── Dataclasses ────────────────────────────────────────────────────────────────


class DefenderTier(Enum):
    """Defender capability tier — affects response speed and sophistication."""
    NOVICE = auto()       # Small business, no dedicated SOC
    INTERMEDIATE = auto()  # Mid-size, part-time SOC
    ADVANCED = auto()      # Enterprise SOC, 24/7
    ELITE = auto()         # Government/military grade, APT hunters
    UNKNOWN = auto()


@dataclass
class SOCProfile:
    """Behavioral profile of a defender team."""
    tier: DefenderTier = DefenderTier.UNKNOWN
    avg_response_time: float = 3600.0  # seconds
    tool_stack: List[str] = field(default_factory=list)
    shift_pattern: str = '8x5'  # 8x5, 12x7, 24x7
    alert_fatigue_level: float = 0.3
    automation_level: float = 0.2
    known_blind_spots: List[str] = field(default_factory=list)
    historical_accuracy: float = 0.7

    def response_speed_multiplier(self) -> float:
        """How much faster/slower than baseline this SOC responds."""
        tier_mult = {
            DefenderTier.NOVICE: 2.0,
            DefenderTier.INTERMEDIATE: 1.3,
            DefenderTier.ADVANCED: 1.0,
            DefenderTier.ELITE: 0.6,
            DefenderTier.UNKNOWN: 1.2,
        }
        fatigue_penalty = 1.0 + self.alert_fatigue_level * 0.5
        automation_bonus = 1.0 - self.automation_level * 0.4
        return tier_mult[self.tier] * fatigue_penalty * automation_bonus


@dataclass
class DefensePrediction:
    """A single predicted defender response."""
    defense_type: str
    confidence: float
    estimated_deployment_time: float  # seconds from now
    trigger_action: str
    countermeasure: str
    likelihood_rank: int = 1
    soc_tier_required: DefenderTier = DefenderTier.INTERMEDIATE

    def to_dict(self) -> Dict[str, Any]:
        return {
            **asdict(self),
            'soc_tier_required': self.soc_tier_required.name,
            'deployment_time_human': str(timedelta(
                seconds=int(self.estimated_deployment_time)
            )),
        }


# ── PredictivePrecognition ─────────────────────────────────────────────────────


class PredictivePrecognition:
    """Predict defender responses and preempt them before activation.

    This engine models the defender's decision tree, applies Bayesian
    inference over historical mission outcomes, and generates specific
    countermeasures tailored to each predicted defense.

    Usage:
        pp = PredictivePrecognition(hive_mind=hm)
        predictions = pp.predict_defender_response('cve_exploited')
        preempt = pp.preempt_defense('cve_exploited', context={...})
    """

    # ── Expanded defense patterns — 20+ entries ──
    DEFENSE_PATTERNS: Dict[str, List[str]] = {
        'cve_exploited': [
            'patch_deployment', 'waf_rule', 'ips_signature',
            'vulnerability_scan', 'threat_intel_share',
        ],
        'data_exfiltrated': [
            'firewall_egress_block', 'dlp_alert', 'network_segmentation',
            'traffic_throttle', 'dns_sinkhole', 'forensic_imaging',
        ],
        'privilege_escalated': [
            'edr_scan', 'account_lockout', 'credential_rotation',
            'kernel_audit', 'mfa_enforcement',
        ],
        'lateral_movement': [
            'network_segmentation', 'honeypot_deployment', 'log_review',
            'kerberos_audit', 'smb_signing_enforce', 'vlan_isolation',
        ],
        'persistence_deployed': [
            'startup_scan', 'registry_audit', 'scheduled_task_review',
            'wmi_audit', 'autorun_enumeration',
        ],
        'c2_established': [
            'firewall_egress_block', 'dns_sinkhole', 'ips_signature',
            'proxy_block', 'cert_revocation', 'sandbox_detonation',
        ],
        'credential_dump': [
            'account_lockout', 'credential_rotation', 'edr_scan',
            'lsass_protection', 'mfa_enforcement',
        ],
        'ransomware_deployed': [
            'network_isolation', 'backup_verification', 'incident_response',
            'forensic_imaging', 'decryptor_deployment',
        ],
        'insider_threat': [
            'account_lockout', 'dlp_alert', 'hr_investigation',
            'vpn_termination', 'legal_review', 'access_revoke',
        ],
        'phishing_campaign': [
            'email_quarantine', 'url_blocks', 'user_training_alert',
            'spf_dkim_check', 'incident_response',
        ],
        'ddos_attack': [
            'traffic_throttle', 'cdn_failover', 'rate_limiting',
            'null_routing', 'isp_coordination',
        ],
        'dns_poisoning': [
            'dns_sinkhole', 'dnssec_enforcement', 'cache_flush',
            'resolver_rotation',
        ],
        'supply_chain': [
            'dependency_audit', 'vendor_review', 'binary_verification',
            'build_pipeline_freeze',
        ],
        'cloud_compromise': [
            'iam_rotation', 'api_key_revoke', 'cloudtrail_audit',
            'bucket_permission_review', 'kms_rotation',
        ],
        'webapp_exploit': [
            'waf_rule', 'rate_limiting', 'input_validation_patch',
            'sql_injection_blocks', 'rce_signature',
        ],
        'social_engineering': [
            'employee_alert', 'mfa_enforcement', 'vpn_termination',
            'helpdesk_alert', 'badge_reissue',
        ],
        'physical_breach': [
            'access_card_revoke', 'physical_lockdown', 'guard_dispatch',
            'camera_review', 'badge_reissue',
        ],
        'iot_compromise': [
            'firmware_scan', 'network_isolation', 'vendor_notification',
            'device_quarantine',
        ],
        'zero_day_exploit': [
            'sandbox_detonation', 'threat_intel_share', 'emergency_patch',
            'ips_signature', 'vendor_escalation',
        ],
        'reconnaissance': [
            'honeypot_deployment', 'traffic_analysis', 'log_review',
            'port_knocking', 'decoy_service',
        ],
        'data_destruction': [
            'backup_restore', 'forensic_imaging', 'incident_response',
            'legal_hold', 'chain_of_custody',
        ],
    }

    # ── Countermeasure library ──
    COUNTERMEASURES: Dict[str, List[str]] = {
        'patch_deployment': [
            'exploit_alternative_cve', 'timing_shift_pre_patch',
            'persistence_pre_patch_reboot',
        ],
        'waf_rule': [
            'payload_obfuscation', 'protocol_level_evasion',
            'header_normalisation_bypass',
        ],
        'ips_signature': [
            'traffic_fragmentation', 'encryption_wrap',
            'signature_mutation',
        ],
        'firewall_egress_block': [
            'protocol_tunneling', 'dns_exfil', 'icmp_covert_channel',
            'alternate_egress_port',
        ],
        'edr_scan': [
            'process_hollowing', 'memory_only_payload',
            'edr_blinding_technique',
        ],
        'account_lockout': [
            'credential_cache', 'alternate_account', 'kerberos_ticket_reuse',
        ],
        'network_segmentation': [
            'pivot_through_shared_service', 'dual_homed_host',
            'management_interface_bypass',
        ],
        'honeypot_deployment': [
            'honeypot_detection', 'avoid_decoy_services',
            'traffic_pattern_analysis',
        ],
        'log_review': [
            'log_tampering', 'log_flood', 'timestamp_corruption',
        ],
        'dlp_alert': [
            'data_chunking', 'steganography', 'compression_obfuscation',
        ],
        'credential_rotation': [
            'token_reuse_window', 'skeleton_key', 'shadow_credentials',
        ],
        'dns_sinkhole': [
            'direct_ip_communication', 'alternate_dns_resolver',
            'doh_tunneling',
        ],
        'mfa_enforcement': [
            'mfa_fatigue', 'sim_swap', 'token_theft',
        ],
        'sandbox_detonation': [
            'sandbox_detection', 'time_delayed_execution',
            'environmental_keying',
        ],
        'forensic_imaging': [
            'anti_forensics', 'memory_only_operations',
            'wipe_on_detection',
        ],
    }

    def __init__(self, hive_mind: Any = None):
        self.hive_mind = hive_mind
        self._mission_history: List[Dict[str, Any]] = []
        self._soc_profiles: Dict[str, SOCProfile] = {}
        self._bayesian_priors: Dict[str, Dict[str, float]] = defaultdict(
            lambda: defaultdict(lambda: _BAYESIAN_SMOOTHING)
        )
        # ── operator persona: the temporal strategist ──
        logger.debug("PredictivePrecognition initialised — "
                     "defender decision tree loaded, Bayesian engine primed.")

    # ── Predict Defender Response ───────────────────────────────────────────

    def predict_defender_response(
        self,
        action_type: str,
        target_profile: Optional[SOCProfile] = None,
        max_predictions: int = _MAX_PREDICTIONS,
    ) -> List[Dict[str, Any]]:
        """Predict what defenses will be deployed in response to an action.

        Args:
            action_type: The attack action triggering the prediction (e.g. 'cve_exploited').
            target_profile: Known SOC profile of the target.
            max_predictions: Maximum number of predictions to return.

        Returns:
            List of prediction dicts with defense, confidence, timing, countermeasure.
        """
        # Get base defense list
        base_defenses = self.DEFENSE_PATTERNS.get(
            action_type,
            ['log_review', 'incident_response'],  # fallback
        )

        predictions = []
        profile = target_profile or SOCProfile()

        for rank, defense_type in enumerate(base_defenses, 1):
            # ── Bayesian confidence calculation ──
            prior = self._bayesian_priors.get(action_type, {}).get(
                defense_type, _BAYESIAN_SMOOTHING
            )
            # Evidence from mission history
            evidence_count = sum(
                1 for m in self._mission_history
                if m.get('action_type') == action_type
                and defense_type in m.get('defenses_triggered', [])
            )
            total_actions = max(
                sum(
                    1 for m in self._mission_history
                    if m.get('action_type') == action_type
                ),
                1,
            )
            # Bayesian update: P(defense | action)
            confidence = (prior + evidence_count) / (
                _BAYESIAN_SMOOTHING + total_actions
            )

            # Adjust for SOC tier
            tier_modifier = 1.0
            if profile.tier == DefenderTier.ELITE:
                tier_modifier = 1.3  # Elite defenders are more predictable
            elif profile.tier == DefenderTier.NOVICE:
                tier_modifier = 0.8  # Novices are erratic
            confidence = min(confidence * tier_modifier, 1.0)

            # ── Timing estimation ──
            base_time = _DEFAULT_RESPONSE_TIMES.get(
                defense_type, 3600.0
            )
            response_time = base_time * profile.response_speed_multiplier()

            # Add noise (real-world variance ±30%)
            noise = random.uniform(0.7, 1.3)
            estimated_time = response_time * noise

            # ── Countermeasure selection ──
            countermeasures = self.COUNTERMEASURES.get(
                defense_type,
                ['generic_evasion'],
            )
            countermeasure = random.choice(countermeasures)

            predictions.append({
                'defense_type': defense_type,
                'confidence': round(confidence, 4),
                'estimated_deployment_seconds': round(estimated_time, 1),
                'estimated_deployment_human': str(timedelta(
                    seconds=int(estimated_time)
                )),
                'trigger_action': action_type,
                'countermeasure': countermeasure,
                'likelihood_rank': rank,
                'actionable': confidence >= _MIN_ACTIONABLE_CONFIDENCE,
                'soc_tier_applicable': profile.tier.name,
            })

        # Sort by confidence descending, limit
        predictions.sort(key=lambda p: p['confidence'], reverse=True)
        predictions = predictions[:max_predictions]

        logger.info(
            f"Predicted {len(predictions)} defender responses for "
            f"'{action_type}' (top confidence: {predictions[0]['confidence']:.2%})"
        )
        return predictions

    # ── Preempt Defense ─────────────────────────────────────────────────────

    def preempt_defense(
        self,
        action_type: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Generate a preemption plan for the predicted defender response.

        Args:
            action_type: The attack action being preempted.
            context: Mission context (urgency, resources, target info).

        Returns:
            Dict with 'predicted_defenses', 'countermeasures', 'preempted'.
        """
        context = context or {}

        # Build SOC profile from context if available
        soc_profile = None
        if context.get('soc_tier'):
            tier_map = {
                'novice': DefenderTier.NOVICE,
                'intermediate': DefenderTier.INTERMEDIATE,
                'advanced': DefenderTier.ADVANCED,
                'elite': DefenderTier.ELITE,
            }
            soc_profile = SOCProfile(
                tier=tier_map.get(context['soc_tier'], DefenderTier.UNKNOWN),
                automation_level=context.get('automation_level', 0.2),
                alert_fatigue_level=context.get('alert_fatigue_level', 0.3),
            )

        predictions = self.predict_defender_response(
            action_type, target_profile=soc_profile
        )

        # Filter to actionable (above confidence threshold)
        actionable = [p for p in predictions if p['actionable']]

        # Build countermeasure timeline
        countermeasures = []
        for p in actionable:
            countermeasures.append({
                'defense': p['defense_type'],
                'countermeasure': p['countermeasure'],
                'deploy_by_seconds': max(
                    0, p['estimated_deployment_seconds'] * 0.8
                ),  # Deploy before they do (80% buffer)
                'confidence': p['confidence'],
            })

        # Sort by urgency (soonest deployment first)
        countermeasures.sort(key=lambda c: c['deploy_by_seconds'])

        result = {
            'action': action_type,
            'predicted_defenses': [p['defense_type'] for p in predictions],
            'actionable_predictions': len(actionable),
            'countermeasures': countermeasures,
            'preempted': len(actionable) > 0,
            'total_predictions': len(predictions),
            'top_confidence': predictions[0]['confidence'] if predictions else 0.0,
            'preemption_window_seconds': (
                predictions[0]['estimated_deployment_seconds']
                if predictions else float('inf')
            ),
            'success': True,
        }

        logger.info(
            f"Preemption plan for '{action_type}': "
            f"{len(countermeasures)} countermeasures generated"
        )
        return result

    # ── Learn Defense Patterns ──────────────────────────────────────────────

    def learn_defense_patterns(
        self,
        mission_history: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Update Bayesian priors from completed mission data.

        Each mission entry should contain:
        - action_type: the attack action performed
        - defenses_triggered: list of defenses that were deployed
        - outcome: 'success' or 'failure'

        Args:
            mission_history: List of mission outcome records.

        Returns:
            Dict with updated prior counts and learning stats.
        """
        new_evidence = 0
        updated_actions = set()

        for mission in mission_history:
            action_type = mission.get('action_type', '')
            defenses = mission.get('defenses_triggered', [])
            outcome = mission.get('outcome', 'success')

            if not action_type:
                continue

            # Update Bayesian priors
            for defense in defenses:
                current = self._bayesian_priors[action_type][defense]
                # Weighted update: success = less weight (defense was ineffective)
                weight = 0.5 if outcome == 'success' else 1.5
                self._bayesian_priors[action_type][defense] = current + weight
                new_evidence += 1

            updated_actions.add(action_type)

            # Store in mission history
            self._mission_history.append({
                **mission,
                'learned_at': datetime.now(timezone.utc).isoformat(),
            })

        # Prune old history (keep last 1000 missions)
        if len(self._mission_history) > 1000:
            self._mission_history = self._mission_history[-1000:]

        logger.info(
            f"Learned from {len(mission_history)} missions: "
            f"{new_evidence} new evidence points, "
            f"{len(updated_actions)} action types updated"
        )
        return {
            'missions_processed': len(mission_history),
            'new_evidence_points': new_evidence,
            'updated_action_types': list(updated_actions),
            'total_history': len(self._mission_history),
            'success': True,
        }

    # ── Simulate Defender Behavior ──────────────────────────────────────────

    def simulate_defender_behavior(
        self,
        target_profile: Optional[SOCProfile] = None,
        action: Optional[str] = None,
        simulation_hours: float = 24.0,
    ) -> Dict[str, Any]:
        """Run a Monte Carlo simulation of defender behavior over time.

        Models the defender's detection, triage, and response cascade
        to estimate probabilities of various defense deployments.

        Args:
            target_profile: SOC profile to simulate.
            action: Attack action to simulate against (uses all if None).
            simulation_hours: Time window for simulation.

        Returns:
            Dict with simulation results, timeline, and probability distributions.
        """
        profile = target_profile or SOCProfile()
        actions_to_simulate = (
            [action] if action else list(self.DEFENSE_PATTERNS.keys())
        )

        simulation_steps = int(simulation_hours * 6)  # 10-min resolution
        timeline = []
        defense_probabilities: Dict[str, float] = defaultdict(float)

        # Monte Carlo with 100 samples
        MONTE_CARLO_SAMPLES = 100

        for sim_action in actions_to_simulate:
            defenses = self.DEFENSE_PATTERNS.get(sim_action, [])

            for _ in range(MONTE_CARLO_SAMPLES):
                # Simulate detection delay
                detection_delay = (
                    profile.avg_response_time
                    * profile.response_speed_multiplier()
                    * random.uniform(0.5, 2.0)
                )

                for defense in defenses:
                    # Probability this defense is deployed
                    deploy_prob = random.uniform(0.3, 0.95)
                    # Adjust for tier
                    if profile.tier == DefenderTier.ELITE:
                        deploy_prob *= 1.2
                    elif profile.tier == DefenderTier.NOVICE:
                        deploy_prob *= 0.6
                    deploy_prob = min(deploy_prob, 1.0)

                    if random.random() < deploy_prob:
                        deploy_time = detection_delay + random.uniform(
                            0, _DEFAULT_RESPONSE_TIMES.get(defense, 3600)
                        )
                        if deploy_time <= simulation_hours * 3600:
                            defense_probabilities[defense] += 1.0 / MONTE_CARLO_SAMPLES

        # Normalise to probabilities
        result_distribution = {
            defense: round(prob / len(actions_to_simulate), 4)
            for defense, prob in defense_probabilities.items()
        }

        # Top 5 most likely defenses
        top_defenses = sorted(
            result_distribution.items(),
            key=lambda x: x[1],
            reverse=True,
        )[:5]

        logger.info(
            f"Defender simulation complete: {simulation_hours}h window, "
            f"{MONTE_CARLO_SAMPLES} samples, {len(result_distribution)} defenses modeled"
        )
        return {
            'simulation_hours': simulation_hours,
            'actions_simulated': len(actions_to_simulate),
            'monte_carlo_samples': MONTE_CARLO_SAMPLES,
            'defense_probabilities': result_distribution,
            'top_likely_defenses': [
                {'defense': d, 'probability': p}
                for d, p in top_defenses
            ],
            'soc_tier': profile.tier.name,
            'success': True,
        }

    # ── Deploy Countermeasure ───────────────────────────────────────────────

    def deploy_countermeasure(
        self,
        predicted_defense: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Generate a specific countermeasure plan for a predicted defense.

        Args:
            predicted_defense: The defense type to counter.
            context: Additional mission context.

        Returns:
            Dict with countermeasure plan and deployment instructions.
        """
        countermeasures = self.COUNTERMEASURES.get(
            predicted_defense,
            ['generic_evasion_technique'],
        )

        # Select the best countermeasure (could use ML ranking here)
        selected = countermeasures[0]

        # Generate deployment steps
        steps = [
            f"Monitor for indicators of {predicted_defense} deployment",
            f"Prepare {selected} technique for immediate execution",
            f"Test countermeasure in staging environment",
            f"Deploy {selected} upon first sign of {predicted_defense}",
            f"Verify countermeasure effectiveness post-deployment",
        ]

        result = {
            'predicted_defense': predicted_defense,
            'countermeasure': selected,
            'alternative_countermeasures': countermeasures[1:],
            'deployment_steps': steps,
            'estimated_effectiveness': round(random.uniform(0.65, 0.95), 2),
            'context': context or {},
            'success': True,
        }

        logger.debug(
            f"Countermeasure deployed for '{predicted_defense}': {selected}"
        )
        return result

    # ── Estimate Response Timing ────────────────────────────────────────────

    def estimate_timing(
        self,
        defense_type: str,
        soc_profile: Optional[SOCProfile] = None,
    ) -> Dict[str, Any]:
        """Estimate how long until a defender deploys a specific defense.

        Args:
            defense_type: The defense to estimate timing for.
            soc_profile: Known SOC profile for adjustment.

        Returns:
            Dict with timing estimates and confidence intervals.
        """
        base_time = _DEFAULT_RESPONSE_TIMES.get(defense_type, 3600.0)
        profile = soc_profile or SOCProfile()

        multiplier = profile.response_speed_multiplier()
        estimated = base_time * multiplier

        # Confidence interval (±25%)
        lower = estimated * 0.75
        upper = estimated * 1.25

        result = {
            'defense_type': defense_type,
            'base_response_time_seconds': base_time,
            'estimated_response_time_seconds': round(estimated, 1),
            'estimated_response_time_human': str(timedelta(
                seconds=int(estimated)
            )),
            'confidence_interval_lower': round(lower, 1),
            'confidence_interval_upper': round(upper, 1),
            'soc_tier': profile.tier.name,
            'success': True,
        }

        logger.debug(
            f"Timing estimate for '{defense_type}': "
            f"{result['estimated_response_time_human']}"
        )
        return result

    # ── SOC Profile Management ──────────────────────────────────────────────

    def profile_soc(
        self,
        target_id: str,
        intel: Dict[str, Any],
    ) -> SOCProfile:
        """Build or update an SOC profile from intelligence data.

        Args:
            target_id: Unique identifier for the target organization.
            intel: Intelligence data (tools observed, response times, etc.).

        Returns:
            The created or updated SOCProfile.
        """
        tier = DefenderTier.UNKNOWN
        tier_str = intel.get('tier', '').upper()
        if 'ELITE' in tier_str or 'GOV' in tier_str:
            tier = DefenderTier.ELITE
        elif 'ADVANCED' in tier_str or 'ENTERPRISE' in tier_str:
            tier = DefenderTier.ADVANCED
        elif 'INTERMEDIATE' in tier_str or 'MID' in tier_str:
            tier = DefenderTier.INTERMEDIATE
        elif 'NOVICE' in tier_str or 'SMALL' in tier_str:
            tier = DefenderTier.NOVICE

        profile = SOCProfile(
            tier=tier,
            avg_response_time=intel.get('avg_response_time', 3600.0),
            tool_stack=intel.get('tools', []),
            shift_pattern=intel.get('shift_pattern', '8x5'),
            alert_fatigue_level=intel.get('alert_fatigue_level', 0.3),
            automation_level=intel.get('automation_level', 0.2),
            known_blind_spots=intel.get('blind_spots', []),
            historical_accuracy=intel.get('accuracy', 0.7),
        )

        self._soc_profiles[target_id] = profile
        logger.info(
            f"SOC profile created for '{target_id}': tier={tier.name}, "
            f"avg_response={profile.avg_response_time}s"
        )
        return profile

    def get_soc_profile(self, target_id: str) -> Optional[SOCProfile]:
        """Retrieve a known SOC profile."""
        return self._soc_profiles.get(target_id)

    # ── Utility ─────────────────────────────────────────────────────────────

    def get_prior_table(self) -> Dict[str, Dict[str, float]]:
        """Export the current Bayesian prior table."""
        return {
            action: dict(defenses)
            for action, defenses in self._bayesian_priors.items()
        }

    def reset(self) -> None:
        """Clear all learned state — fresh temporal canvas."""
        self._mission_history.clear()
        self._soc_profiles.clear()
        self._bayesian_priors.clear()
        logger.debug("PredictivePrecognition reset — all priors wiped.")
