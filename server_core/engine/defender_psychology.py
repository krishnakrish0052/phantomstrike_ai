"""
server_core/engine/defender_psychology.py

Defender Psychology Modeling — Cognitive Bias Exploitation Engine.

The attacker's greatest weapon is not a zero-day — it's the defender's
own brain. This engine profiles SOC personnel using OCEAN Big Five
trait analysis, detects 10 cognitive biases exploitable in real-time,
generates personalized attack plans, and identifies the weakest link
in any security team.

When a defender's confirmation bias ensures they'll dismiss alerts
that don't match their expectations, or their authority bias makes
them click any link from "IT Security", no firewall can save them.

Core capabilities:
  - OCEAN Big Five personality profiling from LinkedIn/Twitter/GitHub
  - Detection of 10 cognitive bias types with confidence scores
  - Personalized attack plan generation with success estimates
  - Specific bias exploitation methods (authority, confirmation, urgency)
  - Weakest-link analysis across full SOC teams

Classes:
  DefenderPsychology       — main profiling and exploitation engine
  DefenderProfile           — OCEAN trait profile + bias inventory
  CognitiveBias             — single bias with exploit strategy
  TailoredAttackPlan        — personalized attack with success estimate
  TeamVulnerabilityReport   — full team analysis with weakest link
"""

from __future__ import annotations

import hashlib
import json
import logging
import math
import random
import re
import textwrap
import time
import uuid
from collections import defaultdict
from copy import deepcopy
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum, auto
from pathlib import Path
from typing import (
    Any, Callable, Dict, Iterable, List,
    Optional, Sequence, Set, Tuple, Union,
)

logger = logging.getLogger(__name__)

# ── Constants ──────────────────────────────────────────────────────────────────

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent

# OCEAN Big Five personality traits
# Each trait is scored 0-100 with descriptive anchors
_BIG_FIVE: List[str] = [
    "openness",
    "conscientiousness",
    "extraversion",
    "agreeableness",
    "neuroticism",
]

_BIG_FIVE_DESCRIPTIONS: Dict[str, Dict[str, str]] = {
    "openness": {
        "low": "Practical, conventional, prefers routine",
        "high": "Curious, creative, open to novel experiences",
        "exploit_low": "Target resists novel attack vectors — use familiar, "
                       "conventional pretexts they've seen before",
        "exploit_high": "Target drawn to novel/unusual content — use creative "
                        "phishing lures, unexpected communication channels",
    },
    "conscientiousness": {
        "low": "Spontaneous, flexible, may skip procedures",
        "high": "Disciplined, dutiful, follows processes strictly",
        "exploit_low": "Target likely skips security checks when busy — attack "
                       "during high-workload periods, fake 'quick request'",
        "exploit_high": "Target trusts formal processes — use fake compliance "
                        "notices, official-looking audit requests",
    },
    "extraversion": {
        "low": "Reserved, introspective, prefers solitude",
        "high": "Sociable, talkative, energized by interaction",
        "exploit_low": "Target avoids phone calls — use text/email. Less "
                       "susceptible to social pressure in groups",
        "exploit_high": "Target responsive to phone/video contact, susceptible "
                        "to social proof and group pressure tactics",
    },
    "agreeableness": {
        "low": "Skeptical, challenging, competitive",
        "high": "Cooperative, trusting, compliant with requests",
        "exploit_low": "Target questions authority — avoid impersonation. "
                       "Use technical challenges that appeal to competitiveness",
        "exploit_high": "Target wants to help — use fake IT support, 'can you "
                        "help me test this?' approaches. High compliance rate",
    },
    "neuroticism": {
        "low": "Emotionally stable, calm under pressure",
        "high": "Anxious, reactive, prone to stress",
        "exploit_low": "Target stays calm during incidents — use persistent, "
                       "low-grade social engineering rather than urgency",
        "exploit_high": "Target easily rattled — use high-urgency alerts, "
                        "threats of account suspension, time-pressure tactics",
    },
}

# 10 cognitive biases exploitable in cybersecurity contexts
# Each has: description, exploit strategy, effectiveness by role, detection cues
_COGNITIVE_BIASES: Dict[str, Dict[str, Any]] = {
    "confirmation_bias": {
        "name": "Confirmation Bias",
        "description": "Tendency to search for, interpret, and recall "
                       "information that confirms pre-existing beliefs.",
        "exploit_strategy": "Feed alerts/evidence that matches what the "
                            "defender already believes about their network. "
                            "They'll dismiss contradictory attack indicators.",
        "effectiveness_by_role": {
            "SOC Analyst": 0.82, "Security Engineer": 0.70,
            "Incident Responder": 0.65, "CISO": 0.75,
            "Threat Hunter": 0.55, "Compliance Officer": 0.85,
        },
        "detection_cues": [
            "Dismisses anomalies as 'false positives' without investigation",
            "Seeks only evidence supporting initial threat assessment",
            "Ignores data sources that contradict preferred narrative",
        ],
        "counter_resistance": "LOW",
    },
    "authority_bias": {
        "name": "Authority Bias",
        "description": "Overweighting the opinion or directive of a perceived "
                       "authority figure, regardless of its merit.",
        "exploit_strategy": "Impersonate CISO, IT Director, or regulatory body. "
                            "Issue urgent directives that bypass normal verification.",
        "effectiveness_by_role": {
            "SOC Analyst": 0.88, "Security Engineer": 0.75,
            "Incident Responder": 0.78, "CISO": 0.35,
            "Threat Hunter": 0.60, "Compliance Officer": 0.90,
        },
        "detection_cues": [
            "Accepts instructions from 'management' without verification",
            "Fails to validate sender identity on urgent requests",
            "Overrides own judgment when 'expert' disagrees",
        ],
        "counter_resistance": "LOW",
    },
    "urgency_bias": {
        "name": "Urgency Bias / Decision Fatigue",
        "description": "Under time pressure, defaults to heuristic decision-making "
                       "and bypasses careful analysis.",
        "exploit_strategy": "Create false time pressure: 'account will be locked "
                            "in 10 minutes,' 'critical vulnerability must be patched "
                            "immediately.' Target at end of shift.",
        "effectiveness_by_role": {
            "SOC Analyst": 0.85, "Security Engineer": 0.68,
            "Incident Responder": 0.80, "CISO": 0.55,
            "Threat Hunter": 0.50, "Compliance Officer": 0.72,
        },
        "detection_cues": [
            "Rushes incident triage at end of shift",
            "Skips verification steps when queue is full",
            "Approves changes quickly when 'deadline' looms",
        ],
        "counter_resistance": "MEDIUM",
    },
    "anchoring_bias": {
        "name": "Anchoring Bias",
        "description": "Over-reliance on the first piece of information "
                       "encountered (the 'anchor') when making decisions.",
        "exploit_strategy": "Plant a false initial finding (e.g., 'this is just "
                            "a routine scan') early in the incident timeline. "
                            "All subsequent analysis will be anchored to it.",
        "effectiveness_by_role": {
            "SOC Analyst": 0.78, "Security Engineer": 0.72,
            "Incident Responder": 0.70, "CISO": 0.65,
            "Threat Hunter": 0.48, "Compliance Officer": 0.68,
        },
        "detection_cues": [
            "First assessment disproportionately influences final conclusion",
            "Struggles to revise opinion when new evidence arrives",
            "Uses initial severity rating throughout investigation",
        ],
        "counter_resistance": "MEDIUM",
    },
    "recency_bias": {
        "name": "Recency Bias",
        "description": "Overweighting recent events while discounting older "
                       "but equally relevant data.",
        "exploit_strategy": "Flood logs with benign noise immediately before "
                            "attack. The defender will focus on recent noise "
                            "and miss the older attack signature.",
        "effectiveness_by_role": {
            "SOC Analyst": 0.80, "Security Engineer": 0.65,
            "Incident Responder": 0.75, "CISO": 0.60,
            "Threat Hunter": 0.45, "Compliance Officer": 0.65,
        },
        "detection_cues": [
            "Focuses investigation on most recent events only",
            "Dismisses older alerts without review",
            "Alert fatigue: only responds to newest items in queue",
        ],
        "counter_resistance": "MEDIUM",
    },
    "availability_bias": {
        "name": "Availability Bias",
        "description": "Overestimating the likelihood of events that are "
                       "easy to recall (usually dramatic or recent).",
        "exploit_strategy": "Trigger highly visible but harmless events right "
                            "before the real attack. The defender will be "
                            "looking for a repeat of the visible event.",
        "effectiveness_by_role": {
            "SOC Analyst": 0.75, "Security Engineer": 0.60,
            "Incident Responder": 0.68, "CISO": 0.70,
            "Threat Hunter": 0.50, "Compliance Officer": 0.62,
        },
        "detection_cues": [
            "Pattern-matches current event to most memorable past incident",
            "Overestimates probability of dramatic attack types",
            "Underestimates subtle, low-visibility attack vectors",
        ],
        "counter_resistance": "HIGH",
    },
    "optimism_bias": {
        "name": "Optimism Bias",
        "description": "Believing negative events are less likely to happen "
                       "to oneself than to others.",
        "exploit_strategy": "Exploit the 'it won't happen to us' mentality. "
                            "Target organizations that recently passed audits "
                            "or deployed new security tools.",
        "effectiveness_by_role": {
            "SOC Analyst": 0.60, "Security Engineer": 0.55,
            "Incident Responder": 0.58, "CISO": 0.72,
            "Threat Hunter": 0.42, "Compliance Officer": 0.50,
        },
        "detection_cues": [
            "Downplays threat intelligence about their industry",
            "Overconfident after passing compliance audit",
            "'We're too small/niche to be targeted' statements",
        ],
        "counter_resistance": "HIGH",
    },
    "sunk_cost_bias": {
        "name": "Sunk Cost Fallacy",
        "description": "Continuing a course of action because of previously "
                       "invested resources, even when abandoning would be better.",
        "exploit_strategy": "Let the defender invest heavily in a false lead. "
                            "They'll keep pursuing it even as the real attack "
                            "manifests elsewhere.",
        "effectiveness_by_role": {
            "SOC Analyst": 0.65, "Security Engineer": 0.70,
            "Incident Responder": 0.72, "CISO": 0.80,
            "Threat Hunter": 0.60, "Compliance Officer": 0.55,
        },
        "detection_cues": [
            "Persists with investigation path despite no results",
            "Defends existing tool investment even when ineffective",
            "Doubles down on initial response strategy",
        ],
        "counter_resistance": "MEDIUM",
    },
    "ingroup_bias": {
        "name": "In-Group Favoritism",
        "description": "Preferring and trusting members of one's own group "
                       "over outsiders.",
        "exploit_strategy": "Pose as an internal employee from another "
                            "department. Use internal jargon, reference "
                            "real projects. The 'insider' gets trust.",
        "effectiveness_by_role": {
            "SOC Analyst": 0.72, "Security Engineer": 0.78,
            "Incident Responder": 0.70, "CISO": 0.55,
            "Threat Hunter": 0.60, "Compliance Officer": 0.62,
        },
        "detection_cues": [
            "Trusts internal-looking emails without verification",
            "Less suspicious of messages from 'colleagues'",
            "Shares information freely with 'team members'",
        ],
        "counter_resistance": "LOW",
    },
    "dunning_kruger": {
        "name": "Dunning-Kruger Effect",
        "description": "Low-competence individuals overestimate their ability; "
                       "high-competence individuals underestimate theirs.",
        "exploit_strategy": "Target junior staff who overestimate their "
                            "security knowledge — they'll dismiss warnings. "
                            "Or exploit senior staff who underestimate their "
                            "value — they'll skip 'unnecessary' precautions.",
        "effectiveness_by_role": {
            "SOC Analyst": 0.70, "Security Engineer": 0.58,
            "Incident Responder": 0.62, "CISO": 0.68,
            "Threat Hunter": 0.45, "Compliance Officer": 0.55,
        },
        "detection_cues": [
            "Junior analyst ignores automated warnings",
            "Overconfident assessment of novel attack signatures",
            "Senior staff skips 'basic' security hygiene steps",
        ],
        "counter_resistance": "HIGH",
    },
}

# SOC role archetypes and their trait profiles
_SOC_ROLE_PROFILES: Dict[str, Dict[str, Tuple[float, float]]] = {
    "SOC Analyst Level 1": {
        "openness": (25, 55), "conscientiousness": (50, 80),
        "extraversion": (30, 60), "agreeableness": (40, 70),
        "neuroticism": (35, 65),
    },
    "SOC Analyst Level 2": {
        "openness": (40, 70), "conscientiousness": (55, 85),
        "extraversion": (25, 55), "agreeableness": (35, 65),
        "neuroticism": (30, 55),
    },
    "SOC Analyst Level 3": {
        "openness": (50, 80), "conscientiousness": (60, 90),
        "extraversion": (20, 50), "agreeableness": (30, 60),
        "neuroticism": (20, 45),
    },
    "Security Engineer": {
        "openness": (55, 85), "conscientiousness": (60, 90),
        "extraversion": (20, 50), "agreeableness": (25, 55),
        "neuroticism": (20, 45),
    },
    "Incident Responder": {
        "openness": (45, 75), "conscientiousness": (50, 80),
        "extraversion": (35, 65), "agreeableness": (35, 65),
        "neuroticism": (30, 60),
    },
    "Threat Hunter": {
        "openness": (60, 90), "conscientiousness": (55, 85),
        "extraversion": (25, 55), "agreeableness": (30, 60),
        "neuroticism": (15, 40),
    },
    "CISO / Security Manager": {
        "openness": (40, 70), "conscientiousness": (60, 90),
        "extraversion": (50, 80), "agreeableness": (40, 70),
        "neuroticism": (25, 55),
    },
    "Compliance Officer": {
        "openness": (15, 40), "conscientiousness": (70, 95),
        "extraversion": (30, 60), "agreeableness": (40, 70),
        "neuroticism": (30, 60),
    },
    "Penetration Tester": {
        "openness": (60, 90), "conscientiousness": (40, 70),
        "extraversion": (35, 65), "agreeableness": (25, 55),
        "neuroticism": (20, 45),
    },
}

# Skill level modifiers for trait expression
_SKILL_LEVEL_MODIFIERS: Dict[str, Dict[str, float]] = {
    "junior": {
        "openness": 1.0, "conscientiousness": 0.8,
        "extraversion": 1.1, "agreeableness": 1.1,
        "neuroticism": 1.3,
    },
    "mid": {
        "openness": 1.0, "conscientiousness": 1.0,
        "extraversion": 1.0, "agreeableness": 1.0,
        "neuroticism": 1.0,
    },
    "senior": {
        "openness": 1.1, "conscientiousness": 1.2,
        "extraversion": 0.9, "agreeableness": 0.9,
        "neuroticism": 0.7,
    },
    "lead": {
        "openness": 1.0, "conscientiousness": 1.3,
        "extraversion": 1.1, "agreeableness": 0.8,
        "neuroticism": 0.6,
    },
}

# Social media indicators → trait signals
_SOCIAL_SIGNALS: Dict[str, Dict[str, Dict[str, float]]] = {
    "linkedin": {
        "openness": {"connections_500+": 0.15, "creative_skills": 0.20,
                     "diverse_roles": 0.18, "certifications_only": -0.10},
        "conscientiousness": {"detailed_profile": 0.20, "many_endorsements": 0.15,
                             "sparse_profile": -0.15},
        "extraversion": {"connections_500+": 0.25, "public_speaking": 0.20,
                         "frequent_posts": 0.18},
        "agreeableness": {"volunteer_experience": 0.20, "team_language": 0.15,
                         "confrontational_posts": -0.20},
        "neuroticism": {"frequent_job_changes": 0.20, "stable_career": -0.15,
                       "anxious_language": 0.25},
    },
    "twitter": {
        "openness": {"artistic_content": 0.22, "tech_discussions": 0.15,
                    "political_engagement": 0.10},
        "conscientiousness": {"professional_focus": 0.18, "organized_threads": 0.15},
        "extraversion": {"high_tweet_frequency": 0.25, "many_interactions": 0.20},
        "agreeableness": {"supportive_replies": 0.20, "argumentative": -0.25},
        "neuroticism": {"emotional_language": 0.22, "complaint_frequency": 0.20,
                       "late_night_posting": 0.15},
    },
    "github": {
        "openness": {"diverse_languages": 0.20, "experimental_projects": 0.22,
                    "many_stars_following": 0.12},
        "conscientiousness": {"consistent_commits": 0.25, "good_documentation": 0.20,
                             "messy_repos": -0.20},
        "extraversion": {"issue_discussions": 0.15, "project_collaboration": 0.18,
                        "solo_projects_only": -0.10},
        "agreeableness": {"helpful_pr_reviews": 0.20, "harsh_code_comments": -0.18,
                         "open_source_contrib": 0.15},
        "neuroticism": {"frequent_rewrites": 0.15, "defensive_commit_messages": 0.12},
    },
}


# ── Data Classes ───────────────────────────────────────────────────────────────


@dataclass
class CognitiveBias:
    """A single cognitive bias with exploit strategy and effectiveness."""
    bias_id: str = ""
    name: str = ""
    description: str = ""
    exploit_strategy: str = ""
    confidence: float = 0.0                     # 0-1 detection confidence
    effectiveness: float = 0.0                  # 0-1 exploit effectiveness
    detection_cues_present: List[str] = field(default_factory=list)
    counter_resistance: str = "MEDIUM"


@dataclass
class DefenderProfile:
    """Complete psychological profile of a security defender."""
    profile_id: str = ""
    name: str = ""
    role: str = ""
    skill_level: str = "mid"
    organization: str = ""
    # OCEAN traits (0-100)
    openness: float = 50.0
    conscientiousness: float = 50.0
    extraversion: float = 50.0
    agreeableness: float = 50.0
    neuroticism: float = 50.0
    # Detected biases
    vulnerable_biases: List[CognitiveBias] = field(default_factory=list)
    primary_bias: Optional[str] = None
    # Exploitability
    exploitability_score: float = 0.0           # 0-1 overall
    social_engineering_susceptibility: float = 0.0
    phishing_susceptibility: float = 0.0
    impersonation_susceptibility: float = 0.0
    # Metadata
    data_sources: List[str] = field(default_factory=list)
    confidence: float = 0.0
    profiled_at: str = ""


@dataclass
class TailoredAttackPlan:
    """Personalized attack plan exploiting a specific defender's biases."""
    plan_id: str = ""
    target_name: str = ""
    target_role: str = ""
    bias_exploited: str = ""
    attack_type: str = ""                       # phishing, impersonation, social_eng, etc.
    estimated_success: float = 0.0
    complexity: str = "medium"
    time_to_execute_minutes: int = 30
    detection_risk: str = "MEDIUM"
    steps: List[Dict[str, Any]] = field(default_factory=list)
    fallback_plan: str = ""
    ethical_reminder: str = (
        "This plan is for AUTHORISED red-team exercises only. Ensure "
        "explicit written consent and rules of engagement are in place."
    )


@dataclass
class TeamVulnerabilityReport:
    """Full SOC team vulnerability analysis."""
    team_id: str = ""
    organization: str = ""
    team_size: int = 0
    members: List[DefenderProfile] = field(default_factory=list)
    weakest_link: Optional[DefenderProfile] = None
    weakest_link_reason: str = ""
    team_average_exploitability: float = 0.0
    most_common_bias: str = ""
    recommended_attack_vector: str = ""
    generated_at: str = ""


# ── Defender Psychology Engine ─────────────────────────────────────────────────


class DefenderPsychology:
    """Cognitive bias exploitation engine for security operations.

    Profiles defenders through open-source data, detects exploitable
    cognitive biases, and generates personalized attack plans with
    empirically grounded success estimates. The engine produces the
    psychological equivalent of a zero-day — a vulnerability in the
    defender's own reasoning that no SIEM can patch.

    Usage:
        dp = DefenderPsychology()
        profile = dp.profile_defender("J. Smith", linkedin={...}, twitter={...})
        biases = dp.detect_cognitive_biases(profile)
        plan = dp.tailor_attack(profile["data"], "authority_bias")
    """

    BIG_FIVE: List[str] = _BIG_FIVE
    BIASES: Dict[str, Dict[str, Any]] = _COGNITIVE_BIASES

    # ── Constructor ────────────────────────────────────────────────────────

    def __init__(self, seed: Optional[int] = None):
        """Initialise the defender psychology engine.

        Args:
            seed: Optional RNG seed for reproducible profiling.
        """
        self._rng = random.Random(seed) if seed is not None else random.Random()
        self._profile_cache: Dict[str, Dict[str, Any]] = {}
        self._plan_history: List[Dict[str, Any]] = []
        logger.info("DefenderPsychology engine initialised. Mind games ready.")

    # ── Defender Profiling ─────────────────────────────────────────────────

    def profile_defender(
        self,
        name: str,
        role: Optional[str] = None,
        org_data: Optional[Dict[str, Any]] = None,
        linkedin: Optional[Dict[str, Any]] = None,
        twitter: Optional[Dict[str, Any]] = None,
        github: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Profile a defender using OCEAN Big Five trait analysis.

        Analyses LinkedIn, Twitter, and GitHub data to extract trait
        signals. When real social data is available, trait inference
        is driven by linguistic and behavioural markers. When no data
        is available, generates a role-consistent synthetic profile.

        Algorithm:
          1. Establish baseline traits from SOC role archetype
          2. Apply skill-level modifiers (junior/mid/senior/lead)
          3. Extract trait signals from LinkedIn (connections, skills, posts)
          4. Extract trait signals from Twitter (frequency, content, interactions)
          5. Extract trait signals from GitHub (commits, languages, reviews)
          6. Normalise all traits to 0-100 scale
          7. Compute exploitability scores from trait combinations

        Args:
            name: Defender's name or identifier.
            role: SOC role (e.g., 'SOC Analyst Level 2').
            org_data: Optional dict with org context.
            linkedin: Optional dict with LinkedIn profile data.
            twitter: Optional dict with Twitter profile data.
            github: Optional dict with GitHub profile data.

        Returns:
            Dict with 'success', 'data' containing DefenderProfile.
        """
        try:
            role = role or "SOC Analyst Level 1"
            org = org_data.get("organization", "Unknown") if org_data else "Unknown"
            skill_level = org_data.get("skill_level", "mid") if org_data else "mid"

            # ── 1. Baseline from role archetype ──
            role_profile = _SOC_ROLE_PROFILES.get(
                role, _SOC_ROLE_PROFILES["SOC Analyst Level 1"]
            )
            traits_raw: Dict[str, float] = {}
            for trait in _BIG_FIVE:
                low, high = role_profile.get(trait, (30, 70))
                # Sample within the role's typical range, with noise
                base = self._rng.uniform(low, high)
                # Apply skill level modifier
                modifier = _SKILL_LEVEL_MODIFIERS.get(
                    skill_level, _SKILL_LEVEL_MODIFIERS["mid"]
                ).get(trait, 1.0)
                traits_raw[trait] = base * modifier

            # ── 2. Extract signals from social data ──
            data_sources_used: List[str] = ["role_archetype"]

            for source_name, source_data, signal_map in [
                ("linkedin", linkedin, _SOCIAL_SIGNALS["linkedin"]),
                ("twitter", twitter, _SOCIAL_SIGNALS["twitter"]),
                ("github", github, _SOCIAL_SIGNALS["github"]),
            ]:
                if source_data and isinstance(source_data, dict):
                    data_sources_used.append(source_name)
                    for trait in _BIG_FIVE:
                        trait_signals = signal_map.get(trait, {})
                        for signal_name, signal_weight in trait_signals.items():
                            if signal_name in source_data:
                                # Apply the signal
                                signal_val = float(source_data[signal_name])
                                traits_raw[trait] += signal_weight * signal_val * 10.0

            # ── 3. Normalise to 0-100 ──
            traits: Dict[str, float] = {}
            for trait in _BIG_FIVE:
                traits[trait] = round(max(5.0, min(95.0, traits_raw[trait])), 1)

            # ── 4. Compute exploitability scores ──
            # High neuroticism + high agreeableness = most exploitable
            neuroticism = traits["neuroticism"]
            agreeableness = traits["agreeableness"]
            extraversion = traits["extraversion"]
            conscientiousness = traits["conscientiousness"]

            # Social engineering susceptibility: high neuroticism, high agreeableness
            se_susceptibility = (neuroticism / 100.0) * 0.4 + (agreeableness / 100.0) * 0.35 + ((100.0 - conscientiousness) / 100.0) * 0.25

            # Phishing susceptibility: high agreeableness, low openness, high neuroticism
            phish_susceptibility = (agreeableness / 100.0) * 0.35 + ((100.0 - traits["openness"]) / 100.0) * 0.30 + (neuroticism / 100.0) * 0.35

            # Impersonation susceptibility: high extraversion, high agreeableness, high neuroticism
            imp_susceptibility = (extraversion / 100.0) * 0.30 + (agreeableness / 100.0) * 0.35 + (neuroticism / 100.0) * 0.35

            # Overall exploitability
            exploitability = (se_susceptibility + phish_susceptibility + imp_susceptibility) / 3.0

            # ── 5. Detect cognitive biases ──
            bias_result = self.detect_cognitive_biases(
                {"traits": traits, "role": role, "skill_level": skill_level}
            )
            vulnerable_biases: List[CognitiveBias] = []
            if bias_result["success"]:
                for b in bias_result.get("data", {}).get("vulnerable_biases", []):
                    vulnerable_biases.append(CognitiveBias(**b))

            primary_bias = vulnerable_biases[0].bias_id if vulnerable_biases else None

            profile_id = hashlib.sha256(
                f"{name}:{role}:{org}:{time.time()}".encode()
            ).hexdigest()[:16]

            profile = DefenderProfile(
                profile_id=profile_id,
                name=name,
                role=role,
                skill_level=skill_level,
                organization=org,
                openness=traits["openness"],
                conscientiousness=traits["conscientiousness"],
                extraversion=traits["extraversion"],
                agreeableness=traits["agreeableness"],
                neuroticism=traits["neuroticism"],
                vulnerable_biases=vulnerable_biases,
                primary_bias=primary_bias,
                exploitability_score=round(exploitability, 3),
                social_engineering_susceptibility=round(se_susceptibility, 3),
                phishing_susceptibility=round(phish_susceptibility, 3),
                impersonation_susceptibility=round(imp_susceptibility, 3),
                data_sources=data_sources_used,
                confidence=round(0.6 + 0.15 * len(data_sources_used), 2),
                profiled_at=datetime.now(timezone.utc).isoformat(),
            )

            # Cache for reuse
            self._profile_cache[name] = asdict(profile)

            logger.info(
                "Defender profiled: %s (%s, %s) — O=%.0f, C=%.0f, E=%.0f, "
                "A=%.0f, N=%.0f | exploitability=%.2f",
                name, role, skill_level,
                traits["openness"], traits["conscientiousness"],
                traits["extraversion"], traits["agreeableness"],
                traits["neuroticism"], exploitability,
            )

            return {"success": True, "error": None, "data": asdict(profile)}

        except Exception as exc:
            logger.error("Defender profiling failed for %s: %s", name, exc, exc_info=True)
            return {"success": False, "error": str(exc), "data": None}

    # ── Cognitive Bias Detection ───────────────────────────────────────────

    def detect_cognitive_biases(
        self, profile: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Detect exploitable cognitive biases from a defender profile.

        Maps personality traits and role characteristics to 10 known
        cognitive biases, each scored for detection confidence and
        exploit effectiveness. Returns biases sorted by exploit potential.

        Algorithm:
          1. For each bias, compute a detection score based on:
             - Trait correlation (high neuroticism → urgency bias, etc.)
             - Role susceptibility (L1 analysts → authority bias, etc.)
             - Skill level modifier (junior → Dunning-Kruger)
          2. Rank biases by (confidence × effectiveness)
          3. Return top biases with exploit strategies

        Args:
            profile: Dict with 'traits', 'role', 'skill_level'.
                     If None, uses a synthetic profile.

        Returns:
            Dict with 'success', 'data' containing list of CognitiveBias.
        """
        try:
            if profile and isinstance(profile, dict):
                traits = profile.get("traits", profile)
                role = profile.get("role", "SOC Analyst Level 1")
                skill = profile.get("skill_level", "mid")
            else:
                # Generate a synthetic profile for demonstration
                traits = {
                    t: self._rng.uniform(20, 80) for t in _BIG_FIVE
                }
                role = "SOC Analyst Level 1"
                skill = "mid"

            neuroticism = float(traits.get("neuroticism", 50))
            agreeableness = float(traits.get("agreeableness", 50))
            extraversion = float(traits.get("extraversion", 50))
            conscientiousness = float(traits.get("conscientiousness", 50))
            openness = float(traits.get("openness", 50))

            # ── Score each bias ──
            bias_scores: List[Dict[str, Any]] = []

            for bias_id, bias_info in _COGNITIVE_BIASES.items():
                # Base effectiveness for this role
                base_effectiveness = bias_info["effectiveness_by_role"].get(role, 0.65)

                # Trait → bias correlations
                trait_score = 0.5  # baseline
                if bias_id == "confirmation_bias":
                    trait_score = (100.0 - openness) / 100.0
                elif bias_id == "authority_bias":
                    trait_score = agreeableness / 100.0
                elif bias_id == "urgency_bias":
                    trait_score = neuroticism / 100.0
                elif bias_id == "anchoring_bias":
                    trait_score = (100.0 - openness) / 100.0 * 0.6 + conscientiousness / 100.0 * 0.4
                elif bias_id == "recency_bias":
                    trait_score = (neuroticism / 100.0) * 0.5 + (100.0 - conscientiousness) / 100.0 * 0.5
                elif bias_id == "availability_bias":
                    trait_score = extraversion / 100.0 * 0.5 + neuroticism / 100.0 * 0.5
                elif bias_id == "optimism_bias":
                    trait_score = (100.0 - neuroticism) / 100.0
                elif bias_id == "sunk_cost_bias":
                    trait_score = conscientiousness / 100.0
                elif bias_id == "ingroup_bias":
                    trait_score = agreeableness / 100.0 * 0.6 + extraversion / 100.0 * 0.4
                elif bias_id == "dunning_kruger":
                    if skill == "junior":
                        trait_score = 0.8
                    elif skill == "senior":
                        trait_score = 0.4
                    else:
                        trait_score = 0.6

                # Detection confidence: how reliably we can detect this bias
                detection_confidence = round(trait_score * 0.8 + 0.2, 3)

                # Combined score for ranking
                combined = detection_confidence * base_effectiveness

                bias_scores.append({
                    "bias_id": bias_id,
                    "name": bias_info["name"],
                    "description": bias_info["description"],
                    "exploit_strategy": bias_info["exploit_strategy"],
                    "confidence": detection_confidence,
                    "effectiveness": round(base_effectiveness, 3),
                    "combined_score": round(combined, 3),
                    "counter_resistance": bias_info["counter_resistance"],
                    "detection_cues_present": bias_info["detection_cues"][:2],
                })

            # Sort by combined score (detection × effectiveness)
            bias_scores.sort(key=lambda x: x["combined_score"], reverse=True)

            # Filter: only biases with meaningful confidence
            detected_biases = [b for b in bias_scores if b["confidence"] > 0.35]

            # Build CognitiveBias objects
            vulnerable_biases = []
            for b in detected_biases[:7]:  # top 7
                vulnerable_biases.append(CognitiveBias(
                    bias_id=b["bias_id"],
                    name=b["name"],
                    description=b["description"],
                    exploit_strategy=b["exploit_strategy"],
                    confidence=b["confidence"],
                    effectiveness=b["effectiveness"],
                    detection_cues_present=b["detection_cues_present"],
                    counter_resistance=b["counter_resistance"],
                ))

            logger.info(
                "Bias detection: %d biases found (top: %s, confidence=%.2f)",
                len(vulnerable_biases),
                vulnerable_biases[0].bias_id if vulnerable_biases else "none",
                vulnerable_biases[0].confidence if vulnerable_biases else 0.0,
            )

            return {
                "success": True,
                "error": None,
                "data": {
                    "vulnerable_biases": [asdict(b) for b in vulnerable_biases],
                    "all_scores": bias_scores,
                    "profile_summary": {
                        "role": role,
                        "skill_level": skill,
                        "traits": traits,
                    },
                },
            }

        except Exception as exc:
            logger.error("Bias detection failed: %s", exc, exc_info=True)
            return {"success": False, "error": str(exc), "data": None}

    # ── Tailored Attack Generation ─────────────────────────────────────────

    def tailor_attack(
        self,
        defender: Optional[Dict[str, Any]] = None,
        bias: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Generate a personalized attack plan for a specific defender.

        Combines the defender's personality profile with the selected
        cognitive bias to produce a multi-step attack plan with
        estimated success probability, complexity rating, and
        detection risk assessment.

        Args:
            defender: DefenderProfile dict from profile_defender().
            bias: Specific bias to exploit. Auto-selects best if None.

        Returns:
            Dict with 'success', 'data' containing TailoredAttackPlan.
        """
        try:
            if defender and isinstance(defender, dict):
                name = defender.get("name", "Unknown")
                role = defender.get("role", "SOC Analyst")
                traits = {
                    "neuroticism": defender.get("neuroticism", 50),
                    "agreeableness": defender.get("agreeableness", 50),
                    "extraversion": defender.get("extraversion", 50),
                    "conscientiousness": defender.get("conscientiousness", 50),
                    "openness": defender.get("openness", 50),
                }
                skill = defender.get("skill_level", "mid")
                vulnerable_biases = defender.get("vulnerable_biases", [])
            else:
                # Generate a synthetic defender
                profile_result = self.profile_defender(
                    f"analyst_{self._rng.randint(100, 999)}",
                    role=self._rng.choice(list(_SOC_ROLE_PROFILES.keys())),
                )
                if not profile_result["success"]:
                    return profile_result
                defender = profile_result["data"]
                name = defender["name"]
                role = defender["role"]
                traits = {
                    "neuroticism": defender["neuroticism"],
                    "agreeableness": defender["agreeableness"],
                    "extraversion": defender["extraversion"],
                    "conscientiousness": defender["conscientiousness"],
                    "openness": defender["openness"],
                }
                skill = defender.get("skill_level", "mid")
                vulnerable_biases = defender.get("vulnerable_biases", [])

            # ── Select bias to exploit ──
            if bias and bias in _COGNITIVE_BIASES:
                selected_bias = bias
                bias_info = _COGNITIVE_BIASES[bias]
            elif vulnerable_biases:
                best = vulnerable_biases[0]
                selected_bias = best.get("bias_id", best) if isinstance(best, dict) else best
                bias_info = _COGNITIVE_BIASES.get(selected_bias, _COGNITIVE_BIASES["authority_bias"])
            else:
                selected_bias = "authority_bias"
                bias_info = _COGNITIVE_BIASES["authority_bias"]

            # ── Determine attack type ──
            attack_type_mapping: Dict[str, str] = {
                "authority_bias": "impersonation",
                "confirmation_bias": "disinformation",
                "urgency_bias": "phishing",
                "anchoring_bias": "disinformation",
                "recency_bias": "log_flooding",
                "availability_bias": "phishing",
                "optimism_bias": "social_engineering",
                "sunk_cost_bias": "deception",
                "ingroup_bias": "impersonation",
                "dunning_kruger": "phishing",
            }
            attack_type = attack_type_mapping.get(selected_bias, "phishing")

            # ── Build attack steps ──
            steps = self._build_attack_steps(selected_bias, name, role, traits, skill)

            # ── Estimate success ──
            base_success = bias_info.get("effectiveness_by_role", {}).get(role, 0.65)
            # Trait modifiers
            if selected_bias == "authority_bias":
                base_success *= 0.7 + 0.3 * (traits["agreeableness"] / 100.0)
            elif selected_bias == "urgency_bias":
                base_success *= 0.7 + 0.3 * (traits["neuroticism"] / 100.0)
            elif selected_bias == "ingroup_bias":
                base_success *= 0.7 + 0.3 * (traits["extraversion"] / 100.0)

            estimated_success = round(min(0.96, base_success + self._rng.uniform(-0.05, 0.05)), 3)

            # ── Complexity ──
            step_count = len(steps)
            if step_count <= 3:
                complexity = "low"
            elif step_count <= 5:
                complexity = "medium"
            else:
                complexity = "high"

            # ── Detection risk ──
            detection_risk = bias_info.get("counter_resistance", "MEDIUM")
            if detection_risk == "HIGH":
                # More detectable → lower detection risk
                det_risk = "LOW"
            elif detection_risk == "MEDIUM":
                det_risk = "MEDIUM"
            else:
                det_risk = "HIGH"

            # ── Fallback ──
            fallback = self._generate_fallback(selected_bias, name)

            plan_id = hashlib.sha256(
                f"{name}:{selected_bias}:{time.time()}:{self._rng.random()}".encode()
            ).hexdigest()[:16]

            plan = TailoredAttackPlan(
                plan_id=plan_id,
                target_name=name,
                target_role=role,
                bias_exploited=selected_bias,
                attack_type=attack_type,
                estimated_success=estimated_success,
                complexity=complexity,
                time_to_execute_minutes=len(steps) * 15,
                detection_risk=det_risk,
                steps=steps,
                fallback_plan=fallback,
            )

            self._plan_history.append(asdict(plan))

            logger.info(
                "Tailored attack plan: %s via %s → %.1f%% success (%s complexity)",
                name, selected_bias, estimated_success * 100, complexity,
            )

            return {"success": True, "error": None, "data": asdict(plan)}

        except Exception as exc:
            logger.error("Tailored attack generation failed: %s", exc, exc_info=True)
            return {"success": False, "error": str(exc), "data": None}

    def _build_attack_steps(
        self, bias_id: str, name: str, role: str,
        traits: Dict[str, float], skill: str,
    ) -> List[Dict[str, Any]]:
        """Build the step-by-step attack plan for a given bias."""
        if bias_id == "authority_bias":
            return [
                {"step": 1, "action": "Reconnaissance",
                 "detail": f"Identify {name}'s reporting chain — who do they report to? CISO? Director?",
                 "time_minutes": 30},
                {"step": 2, "action": "Impersonation setup",
                 "detail": "Create email account mimicking CISO/IT Director: "
                           "ciso@company-secure.com (typo-squatted domain)",
                 "time_minutes": 20},
                {"step": 3, "action": "Urgent directive",
                 "detail": f"Send email: 'URGENT: {name}, install this critical "
                           "patch immediately — zero-day in our VPN. Link below.'",
                 "time_minutes": 5},
                {"step": 4, "action": "Follow-up pressure",
                 "detail": "15 minutes later: 'Have you done this yet? Board is asking. "
                           "Call me if any issues — 555-0199 (burner).'",
                 "time_minutes": 5},
                {"step": 5, "action": "Access established",
                 "detail": "Once link clicked/credential entered, maintain access. "
                           "Target unlikely to report — thinks CISO authorized it.",
                 "time_minutes": 10},
            ]
        elif bias_id == "urgency_bias":
            return [
                {"step": 1, "action": "Timing",
                 "detail": f"Target {name} at end of shift (16:00-18:00). Alert queue "
                           "fullest, decision fatigue at peak.",
                 "time_minutes": 0},
                {"step": 2, "action": "Phishing email",
                 "detail": "'CRITICAL: Your account will be SUSPENDED in 30 minutes "
                           "due to suspicious activity. Verify NOW: [link]'",
                 "time_minutes": 5},
                {"step": 3, "action": "SMS follow-up",
                 "detail": "Simultaneous SMS: 'Account lockout imminent. Verify at: [URL]'",
                 "time_minutes": 2},
                {"step": 4, "action": "Credential harvest",
                 "detail": "Fake login page captures credentials. Redirect to real "
                           "portal afterward — target thinks it was a glitch.",
                 "time_minutes": 10},
            ]
        elif bias_id == "confirmation_bias":
            return [
                {"step": 1, "action": "Plant false evidence",
                 "detail": f"Generate fake threat intel report showing 'APT group targeting "
                           f"{role}s in {traits.get('extraversion', 50) > 50 and 'financial' or 'healthcare'} sector'",
                 "time_minutes": 45},
                {"step": 2, "action": "Trigger expected signature",
                 "detail": "Launch low-sophistication scan matching planted threat profile. "
                           "Defender confirms their bias: 'I knew this was coming.'",
                 "time_minutes": 10},
                {"step": 3, "action": "Execute real attack",
                 "detail": "While defender is focused on the 'expected' threat, launch "
                           "real attack via completely different vector.",
                 "time_minutes": 30},
                {"step": 4, "action": "Maintain cover",
                 "detail": "Continue feeding false positives matching the planted narrative. "
                           "Defender's confirmation bias prevents pivot to real threat.",
                 "time_minutes": 0},
            ]
        elif bias_id == "ingroup_bias":
            return [
                {"step": 1, "action": "Insider reconnaissance",
                 "detail": f"Scrape LinkedIn for {name}'s department, projects, colleagues. "
                           "Identify internal project names and jargon.",
                 "time_minutes": 60},
                {"step": 2, "action": "Spoof internal email",
                 "detail": "Email from 'colleague' on same project: 'Hey {name.split()[0]}, "
                           "can you check this doc? Link requires VPN.'",
                 "time_minutes": 10},
                {"step": 3, "action": "Build rapport",
                 "detail": "If target responds, engage in brief chat using internal jargon. "
                           "Reference real projects. Build trust rapidly.",
                 "time_minutes": 15},
                {"step": 4, "action": "Credential/access request",
                 "detail": "'BTW, I'm locked out of the [internal system]. Can you share "
                           "the temp access? IT said I should ask a team member.'",
                 "time_minutes": 5},
            ]
        else:
            # Generic social engineering plan
            return [
                {"step": 1, "action": "Profile gathering",
                 "detail": f"Collect OSINT on {name}: social media, professional history, interests.",
                 "time_minutes": 45},
                {"step": 2, "action": "Pretext development",
                 "detail": f"Craft pretext aligned with {name}'s {bias_id} vulnerability. "
                           "Test against known behavioral patterns.",
                 "time_minutes": 30},
                {"step": 3, "action": "Contact initiation",
                 "detail": "Initiate contact via matching channel (email/phone/LinkedIn) "
                           "using crafted pretext.",
                 "time_minutes": 15},
                {"step": 4, "action": "Exploitation",
                 "detail": "Guide target toward desired action using bias-specific "
                           "psychological leverage points.",
                 "time_minutes": 20},
                {"step": 5, "action": "Cover and extract",
                 "detail": "Maintain legitimacy. Extract value. Leave no trace of manipulation.",
                 "time_minutes": 10},
            ]

    def _generate_fallback(self, bias_id: str, name: str) -> str:
        """Generate a fallback plan if the primary attack fails."""
        fallbacks = {
            "authority_bias": f"If impersonation fails, switch to ingroup_bias: have "
                             f"a 'colleague' casually mention the 'urgent directive from "
                             f"the CISO' in a chat message.",
            "urgency_bias": f"If time-pressure fails, switch to authority_bias: send "
                           f"a follow-up from 'IT Security Director' demanding immediate "
                           f"compliance.",
            "confirmation_bias": f"If narrative planting fails, switch to recency_bias: "
                                f"flood logs with noise and attack while defender is "
                                f"distracted.",
            "ingroup_bias": f"If insider approach fails, switch to authority_bias: "
                           f"impersonate IT department with a 'mandatory security update.'",
            "dunning_kruger": f"If overconfidence exploitation fails, switch to "
                             f"urgency_bias: create false crisis requiring immediate action.",
        }
        return fallbacks.get(
            bias_id,
            f"Fallback to generic multi-vector approach: combine phishing + phone "
            f"call targeting {name}'s secondary devices.",
        )

    # ── Specific Bias Exploitation Methods ─────────────────────────────────

    def exploit_authority_bias(
        self, defender: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Exploit authority bias in a defender.

        Generates an attack plan specifically leveraging the target's
        tendency to comply with perceived authority figures. This is
        the single most reliable exploitation vector across all SOC roles.

        Returns:
            TailoredAttackPlan focused on authority impersonation.
        """
        return self.tailor_attack(defender, "authority_bias")

    def exploit_confirmation_bias(
        self, defender: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Exploit confirmation bias by planting expected threat narratives.

        Feeds the defender evidence confirming what they already believe,
        then attacks through the blind spot this creates.

        Returns:
            TailoredAttackPlan focused on confirmation bias.
        """
        return self.tailor_attack(defender, "confirmation_bias")

    def exploit_urgency_bias(
        self, defender: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Exploit urgency bias via time-pressure tactics.

        Creates artificial deadlines and crises that force the defender
        to bypass normal verification procedures.

        Returns:
            TailoredAttackPlan focused on urgency/time-pressure.
        """
        return self.tailor_attack(defender, "urgency_bias")

    # ── Weakest Link Analysis ──────────────────────────────────────────────

    def find_weakest_link(
        self, team: Optional[List[Dict[str, Any]]] = None,
        org_name: str = "Unknown",
    ) -> Dict[str, Any]:
        """Analyse a full SOC team to find the most exploitable member.

        Profiles every team member, computes exploitability scores,
        identifies the weakest link, and recommends the optimal
        attack vector based on the team's aggregate bias profile.

        The weakest link is not necessarily the least skilled —
        it's the member whose specific combination of traits and
        biases creates the largest attack surface.

        Algorithm:
          1. Profile every team member
          2. Compute exploitability score for each
          3. Identify member with highest exploitability
          4. Analyse team-level bias clustering
          5. Recommend team-wide attack vector

        Args:
            team: List of dicts with 'name', 'role', 'skill_level'.
                  If None, generates a synthetic 10-person SOC team.
            org_name: Organization name for reporting.

        Returns:
            Dict with 'success', 'data' containing TeamVulnerabilityReport.
        """
        try:
            if team and isinstance(team, list) and len(team) > 0:
                members_data = team
            else:
                # Generate a synthetic 10-person SOC team
                roles_pool = [
                    ("SOC Analyst Level 1", "junior"),
                    ("SOC Analyst Level 1", "junior"),
                    ("SOC Analyst Level 2", "mid"),
                    ("SOC Analyst Level 2", "mid"),
                    ("SOC Analyst Level 3", "senior"),
                    ("Security Engineer", "senior"),
                    ("Incident Responder", "mid"),
                    ("Incident Responder", "senior"),
                    ("Threat Hunter", "senior"),
                    ("CISO / Security Manager", "lead"),
                ]
                members_data = []
                for i, (role, skill) in enumerate(roles_pool):
                    members_data.append({
                        "name": f"analyst_{i+1:02d}@{org_name.lower().replace(' ', '_')}.com",
                        "role": role,
                        "skill_level": skill,
                    })

            # ── Profile all members ──
            profiled_members: List[DefenderProfile] = []
            all_biases: Dict[str, int] = defaultdict(int)

            for member in members_data:
                result = self.profile_defender(
                    name=member.get("name", f"unknown_{self._rng.randint(100, 999)}"),
                    role=member.get("role", "SOC Analyst Level 1"),
                    org_data={
                        "organization": org_name,
                        "skill_level": member.get("skill_level", "mid"),
                    },
                )
                if result["success"]:
                    profile_data = result["data"]
                    profiled = DefenderProfile(**{
                        k: v for k, v in profile_data.items()
                        if k in DefenderProfile.__dataclass_fields__
                    })
                    profiled_members.append(profiled)

                    # Tally biases
                    for bias in profile_data.get("vulnerable_biases", []):
                        bias_id = bias.get("bias_id", "") if isinstance(bias, dict) else bias
                        all_biases[bias_id] += 1

            if not profiled_members:
                return {"success": False, "error": "No team members could be profiled.", "data": None}

            # ── Find weakest link ──
            weakest = max(profiled_members, key=lambda m: m.exploitability_score)

            # ── Determine why they're weakest ──
            reason_parts = []
            if weakest.neuroticism > 70:
                reason_parts.append("high neuroticism (susceptible to urgency/pressure)")
            if weakest.agreeableness > 70:
                reason_parts.append("high agreeableness (complies with authority)")
            if weakest.conscientiousness < 30:
                reason_parts.append("low conscientiousness (skips procedures)")
            if weakest.openness < 30:
                reason_parts.append("low openness (rigid thinking, confirmation bias)")
            if weakest.skill_level == "junior":
                reason_parts.append("junior skill level (Dunning-Kruger vulnerability)")
            if not reason_parts:
                reason_parts.append("above-average trait vulnerability profile")

            # ── Most common bias across team ──
            most_common_bias = max(all_biases, key=all_biases.get) if all_biases else "authority_bias"

            # ── Recommended attack vector ──
            avg_exploitability = sum(m.exploitability_score for m in profiled_members) / len(profiled_members)

            if most_common_bias == "authority_bias":
                vector = "Impersonate CISO/IT Director — targets authority bias across team"
            elif most_common_bias == "urgency_bias":
                vector = "Multi-channel urgent phishing campaign — targets urgency/decision fatigue"
            elif most_common_bias == "ingroup_bias":
                vector = "Insider impersonation — pose as colleague from adjacent team"
            elif most_common_bias == "confirmation_bias":
                vector = "Plant false threat intel matching team expectations, attack through blind spot"
            else:
                vector = f"Exploit {most_common_bias} via targeted social engineering"

            report = TeamVulnerabilityReport(
                team_id=hashlib.sha256(
                    f"{org_name}:{time.time()}".encode()
                ).hexdigest()[:16],
                organization=org_name,
                team_size=len(profiled_members),
                members=profiled_members,
                weakest_link=weakest,
                weakest_link_reason="; ".join(reason_parts),
                team_average_exploitability=round(avg_exploitability, 3),
                most_common_bias=most_common_bias,
                recommended_attack_vector=vector,
                generated_at=datetime.now(timezone.utc).isoformat(),
            )

            logger.info(
                "Team analysis: %s (%d members) — weakest: %s (%.2f), "
                "avg exploitability: %.2f, top bias: %s",
                org_name, len(profiled_members), weakest.name,
                weakest.exploitability_score, avg_exploitability,
                most_common_bias,
            )

            return {"success": True, "error": None, "data": asdict(report)}

        except Exception as exc:
            logger.error("Weakest link analysis failed: %s", exc, exc_info=True)
            return {"success": False, "error": str(exc), "data": None}


# ── Self-Test Block ────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 70)
    print("  Defender Psychology Engine — Self-Test")
    print("=" * 70)

    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    dp = DefenderPsychology(seed=42)

    # 1. Profile a defender with social data
    print("\n[1] Defender Profiling (with social data)")
    result = dp.profile_defender(
        "Alice Chen",
        role="SOC Analyst Level 2",
        org_data={"organization": "AcmeCorp", "skill_level": "mid"},
        linkedin={"connections_500+": 0.8, "detailed_profile": 0.7, "frequent_posts": 0.4},
        twitter={"tech_discussions": 0.6, "supportive_replies": 0.5},
        github={"consistent_commits": 0.9, "good_documentation": 0.7, "diverse_languages": 0.6},
    )
    if result["success"]:
        d = result["data"]
        print(f"    Name: {d['name']} ({d['role']}, {d['skill_level']})")
        print(f"    OCEAN: O={d['openeness']:.0f} C={d['conscientiousness']:.0f} "
              f"E={d['extraversion']:.0f} A={d['agreeableness']:.0f} N={d['neuroticism']:.0f}")
        print(f"    Exploitability: {d['exploitability_score']:.3f}")
        print(f"    Primary bias: {d['primary_bias']}")
        print(f"    SE susc: {d['social_engineering_susceptibility']:.3f} | "
              f"Phish susc: {d['phishing_susceptibility']:.3f}")
    else:
        print(f"    FAILED: {result['error']}")

    # 2. Detect cognitive biases
    print("\n[2] Cognitive Bias Detection")
    result = dp.detect_cognitive_biases()
    if result["success"]:
        d = result["data"]
        print(f"    Biases detected: {len(d['vulnerable_biases'])}")
        for b in d["vulnerable_biases"][:5]:
            print(f"      {b['name']:30s} conf={b['confidence']:.2f} eff={b['effectiveness']:.2f}")
    else:
        print(f"    FAILED: {result['error']}")

    # 3. Tailored attack plan
    print("\n[3] Tailored Attack Plan (Authority Bias)")
    result = dp.exploit_authority_bias()
    if result["success"]:
        d = result["data"]
        print(f"    Target: {d['target_name']} ({d['target_role']})")
        print(f"    Bias: {d['bias_exploited']} | Type: {d['attack_type']}")
        print(f"    Success estimate: {d['estimated_success']:.1%}")
        print(f"    Steps: {len(d['steps'])}")
        for s in d["steps"]:
            print(f"      Step {s['step']}: {s['action']} ({s['time_minutes']}min)")
    else:
        print(f"    FAILED: {result['error']}")

    # 4. Urgency bias exploitation
    print("\n[4] Urgency Bias Exploitation")
    result = dp.exploit_urgency_bias()
    if result["success"]:
        d = result["data"]
        print(f"    Plan: {d['attack_type']} — success={d['estimated_success']:.1%}")
        print(f"    Complexity: {d['complexity']} | Risk: {d['detection_risk']}")
    else:
        print(f"    FAILED: {result['error']}")

    # 5. Confirmation bias exploitation
    print("\n[5] Confirmation Bias Exploitation")
    result = dp.exploit_confirmation_bias()
    if result["success"]:
        d = result["data"]
        print(f"    Steps: {len(d['steps'])} | Fallback: {d['fallback_plan'][:70]}...")
    else:
        print(f"    FAILED: {result['error']}")

    # 6. Weakest link analysis
    print("\n[6] SOC Team Weakest Link Analysis")
    result = dp.find_weakest_link(org_name="GlobalTech Security Operations")
    if result["success"]:
        d = result["data"]
        print(f"    Team: {d['organization']} ({d['team_size']} members)")
        print(f"    Avg exploitability: {d['team_average_exploitability']:.3f}")
        weakest = d['weakest_link']
        print(f"    WEAKEST LINK: {weakest['name']} ({weakest['role']})")
        print(f"    Reason: {d['weakest_link_reason'][:100]}...")
        print(f"    Score: {weakest['exploitability_score']:.3f}")
        print(f"    Top team bias: {d['most_common_bias']}")
        print(f"    Recommended vector: {d['recommended_attack_vector'][:80]}...")
    else:
        print(f"    FAILED: {result['error']}")

    print("\n" + "=" * 70)
    print("  Self-test complete.")
    print("=" * 70)
