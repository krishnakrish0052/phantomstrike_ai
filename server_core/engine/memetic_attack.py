"""
server_core/engine/memetic_attack.py

Memetic Attack Vectors — Information Warfare and Narrative Propagation.

When bits alone won't break the target, memes will. This engine crafts,
propagates, and measures information campaigns designed to distract,
discredit, or destabilise target organisations. From social media
astroturfing to internal Slack/Teams seed narratives — memetic warfare
turns the defender's own attention into their greatest vulnerability.

Narrative Types:
  - distraction          — Create noise to pull SOC focus elsewhere
  - reputation_damage    — Leak damaging information (real or fabricated)
  - credibility_undermine — Erode trust in the defender's own tools/team
  - false_flag           — Pin the attack on a third party
  - panic_induce         — Trigger overreaction and resource exhaustion

Platform Targets:
  - Twitter/X, LinkedIn, Reddit, internal Slack/Teams, Discord, Telegram

Classes:
  MemeticAttack       — main campaign orchestrator
  NarrativeTemplate   — configurable narrative blueprint
  ViralSimulation     — propagation model with platform-specific dynamics
  CampaignMetrics     — impact measurement container
"""

from __future__ import annotations

import hashlib
import logging
import math
import random
import time
import uuid
from collections import defaultdict, deque
from copy import deepcopy
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta, timezone
from enum import Enum, auto
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union

logger = logging.getLogger(__name__)

# ── Constants ──────────────────────────────────────────────────────────────────

_NARRATIVE_TYPES = {
    'distraction': {
        'tone': 'urgent',
        'target': 'soc_team',
        'virality_base': 0.55,
        'decay_hours': 6.0,
    },
    'reputation_damage': {
        'tone': 'scandalous',
        'target': 'public',
        'virality_base': 0.75,
        'decay_hours': 48.0,
    },
    'credibility_undermine': {
        'tone': 'doubtful',
        'target': 'industry_peers',
        'virality_base': 0.45,
        'decay_hours': 24.0,
    },
    'false_flag': {
        'tone': 'accusatory',
        'target': 'security_community',
        'virality_base': 0.65,
        'decay_hours': 36.0,
    },
    'panic_induce': {
        'tone': 'alarming',
        'target': 'employees',
        'virality_base': 0.85,
        'decay_hours': 4.0,
    },
}

_PLATFORM_REACH_FACTORS: Dict[str, float] = {
    'twitter': 1.0,
    'linkedin': 0.7,
    'reddit': 0.8,
    'slack': 0.3,
    'teams': 0.25,
    'discord': 0.4,
    'telegram': 0.5,
    'facebook': 0.9,
    'instagram': 0.85,
}

_PLATFORM_POST_LIMITS: Dict[str, int] = {
    'twitter': 280,
    'linkedin': 3000,
    'reddit': 40000,
    'slack': 40000,
    'teams': 25000,
    'discord': 2000,
    'telegram': 4096,
    'facebook': 63206,
    'instagram': 2200,
}

# ── Dataclasses ────────────────────────────────────────────────────────────────


class NarrativeTone(Enum):
    URGENT = auto()
    SCANDALOUS = auto()
    DOUBTFUL = auto()
    ACCUSATORY = auto()
    ALARMING = auto()
    TECHNICAL = auto()
    CASUAL = auto()


class Platform(Enum):
    TWITTER = 'twitter'
    LINKEDIN = 'linkedin'
    REDDIT = 'reddit'
    SLACK = 'slack'
    TEAMS = 'teams'
    DISCORD = 'discord'
    TELEGRAM = 'telegram'
    FACEBOOK = 'facebook'
    INSTAGRAM = 'instagram'


@dataclass
class NarrativeTemplate:
    """Blueprint for a memetic narrative."""
    narrative_type: str
    template_text: str
    tone: NarrativeTone = NarrativeTone.URGENT
    target_audience: str = 'public'
    required_placeholders: List[str] = field(default_factory=list)
    suggested_hashtags: List[str] = field(default_factory=list)
    virality_base: float = 0.5
    decay_hours: float = 24.0

    def fill(self, **kwargs: Any) -> str:
        """Fill template placeholders with provided values."""
        result = self.template_text
        for key, value in kwargs.items():
            result = result.replace(f'{{{key}}}', str(value))
        return result


@dataclass
class ViralSimulation:
    """Propagation simulation results for a narrative."""
    platform: str
    initial_reach: int
    peak_reach: int
    total_impressions: int
    engagement_rate: float
    shares: int
    comments: int
    half_life_hours: float
    propagation_curve: List[Tuple[float, int]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class CampaignMetrics:
    """Aggregated metrics for a memetic campaign."""
    campaign_id: str
    narrative_type: str
    platforms_deployed: List[str]
    total_impressions: int
    total_engagements: int
    peak_reach: int
    duration_hours: float
    soc_distraction_score: float
    narrative_penetration: float
    active: bool = True


# ── MemeticAttack ──────────────────────────────────────────────────────────────


class MemeticAttack:
    """Orchestrate information warfare campaigns against targets.

    Generates narratives, crafts platform-specific posts, simulates
    virality, measures impact, and coordinates timing with physical/cyber
    attack timelines for maximum distraction effect.

    Usage:
        ma = MemeticAttack(target_org='AcmeCorp')
        campaign = ma.generate_narrative('distraction', objective='cover_exfil')
        post = ma.craft_social_post(campaign, 'twitter')
        impact = ma.simulate_virality(campaign['narrative'], 'soc_team')
    """

    # ── Narrative templates ─────────────────────────────────────────────────
    NARRATIVES: Dict[str, NarrativeTemplate] = {
        'competitor_breach': NarrativeTemplate(
            narrative_type='distraction',
            template_text=(
                "BREAKING: Multiple sources confirm a major data breach at {company}. "
                "Customer PII and internal documents allegedly exfiltrated. "
                "{company} shares down {percent}% in after-hours trading. "
                "Security researchers are tracking the incident under #{hashtag}."
            ),
            tone=NarrativeTone.URGENT,
            target_audience='public',
            required_placeholders=['company', 'percent', 'hashtag'],
            suggested_hashtags=['#DataBreach', '#CyberAttack', '#InfoSec'],
            virality_base=0.78,
            decay_hours=36.0,
        ),
        'vendor_vuln': NarrativeTemplate(
            narrative_type='reputation_damage',
            template_text=(
                "CRITICAL: Unpatched zero-day discovered in {software} v{version}. "
                "Affects all deployments since {release_date}. CVE assignment pending. "
                "Exploit code has been circulating on underground forums since {leak_date}. "
                "Users advised to disable {feature} immediately."
            ),
            tone=NarrativeTone.SCANDALOUS,
            target_audience='industry_peers',
            required_placeholders=['software', 'version', 'release_date', 'leak_date', 'feature'],
            suggested_hashtags=['#ZeroDay', '#Vulnerability', '#CVE'],
            virality_base=0.72,
            decay_hours=48.0,
        ),
        'industry_alert': NarrativeTemplate(
            narrative_type='panic_induce',
            template_text=(
                "URGENT CISA Alert: Coordinated attacks targeting the {industry} sector. "
                "Threat actors leveraging {technique} to compromise {target_system}. "
                "{affected_count}+ organisations impacted in the last {hours}h. "
                "Immediate action required: {mitigation}."
            ),
            tone=NarrativeTone.ALARMING,
            target_audience='employees',
            required_placeholders=['industry', 'technique', 'target_system', 'affected_count', 'hours', 'mitigation'],
            suggested_hashtags=['#CISA', '#ThreatIntel', '#CyberAlert'],
            virality_base=0.82,
            decay_hours=6.0,
        ),
        'internal_drama': NarrativeTemplate(
            narrative_type='credibility_undermine',
            template_text=(
                "LEAKED: Internal memo reveals mass layoffs at {company}. "
                "{department} department being cut by {percent}%. "
                "Multiple senior engineers from the security team have already "
                "updated their LinkedIn profiles to #OpenToWork."
            ),
            tone=NarrativeTone.DOUBTFUL,
            target_audience='employees',
            required_placeholders=['company', 'department', 'percent'],
            suggested_hashtags=['#Layoffs', '#TechNews', '#OpenToWork'],
            virality_base=0.68,
            decay_hours=24.0,
        ),
        'regulatory_action': NarrativeTemplate(
            narrative_type='reputation_damage',
            template_text=(
                "DEVELOPING: {agency} opens formal investigation into {company} "
                "over alleged {violation_type} violations. Penalties could reach "
                "{penalty_amount} under {regulation}. Legal experts calling this "
                "'{legal_quote}' for the {industry} sector."
            ),
            tone=NarrativeTone.SCANDALOUS,
            target_audience='public',
            required_placeholders=['agency', 'company', 'violation_type', 'penalty_amount', 'regulation', 'industry', 'legal_quote'],
            suggested_hashtags=['#Regulation', '#Compliance', '#Investigation'],
            virality_base=0.74,
            decay_hours=72.0,
        ),
        'false_flag_attribution': NarrativeTemplate(
            narrative_type='false_flag',
            template_text=(
                "FORENSIC ANALYSIS: The recent attack on {company} bears all "
                "hallmarks of {attacker_group}. Identical TTPs to their {previous_op} "
                "operation. Infrastructure overlaps with known {attacker_group} "
                "C2 nodes documented by {threat_intel_vendor}. Attribution confidence: {confidence}%."
            ),
            tone=NarrativeTone.ACCUSATORY,
            target_audience='security_community',
            required_placeholders=['company', 'attacker_group', 'previous_op', 'threat_intel_vendor', 'confidence'],
            suggested_hashtags=['#ThreatIntel', '#Attribution', '#APT'],
            virality_base=0.66,
            decay_hours=36.0,
        ),
        'product_failure': NarrativeTemplate(
            narrative_type='credibility_undermine',
            template_text=(
                "WHISTLEBLOWER: {company}'s flagship {product} has a critical "
                "architectural flaw that exposes {data_type} for {affected_users}+ "
                "users. Internal tickets dating back to {discovery_date} show "
                "engineering knew but management suppressed. Screenshots attached."
            ),
            tone=NarrativeTone.SCANDALOUS,
            target_audience='public',
            required_placeholders=['company', 'product', 'data_type', 'affected_users', 'discovery_date'],
            suggested_hashtags=['#Whistleblower', '#TechFail', '#SecurityFail'],
            virality_base=0.80,
            decay_hours=48.0,
        ),
    }

    def __init__(
        self,
        target_org: str = '',
        hive_mind: Any = None,
    ):
        self.target_org = target_org
        self.hive_mind = hive_mind
        self._active_campaigns: Dict[str, CampaignMetrics] = {}
        self._narrative_history: List[Dict[str, Any]] = []
        self._simulation_cache: Dict[str, ViralSimulation] = {}
        # ── operator persona: the memetic architect ──
        logger.debug(
            f"MemeticAttack initialised for target '{target_org}' — "
            "narrative templates loaded, virality engine primed."
        )

    # ── Generate Narrative ──────────────────────────────────────────────────

    def generate_narrative(
        self,
        narrative_type: str,
        objective: str = '',
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Generate a tailored narrative for the target organisation.

        Args:
            narrative_type: One of 'distraction', 'reputation_damage',
                           'credibility_undermine', 'false_flag', 'panic_induce'.
            objective: The operational objective this narrative supports.
            context: Additional data for template placeholders.

        Returns:
            Dict with narrative text, metadata, and campaign ID.
        """
        context = context or {}

        # Select appropriate template based on type
        matching_templates = [
            t for t in self.NARRATIVES.values()
            if t.narrative_type == narrative_type
        ]
        if not matching_templates:
            # Fallback: pick any template
            matching_templates = list(self.NARRATIVES.values())

        template = random.choice(matching_templates)

        # Fill placeholders
        fill_values = {
            'company': self.target_org or context.get('company', 'UnknownCorp'),
            'software': context.get('software', 'Apache'),
            'industry': context.get('industry', 'technology'),
            'percent': context.get('percent', random.randint(3, 15)),
            'hashtag': context.get('hashtag', 'CyberAttack'),
            'version': context.get('version', '2024.1'),
            'release_date': context.get('release_date', 'January 2024'),
            'leak_date': context.get('leak_date', 'last week'),
            'feature': context.get('feature', 'admin panel'),
            'technique': context.get('technique', 'spear-phishing'),
            'target_system': context.get('target_system', 'Active Directory'),
            'affected_count': context.get('affected_count', random.randint(10, 500)),
            'hours': context.get('hours', random.randint(2, 72)),
            'mitigation': context.get('mitigation', 'Apply emergency patches'),
            'department': context.get('department', 'Security Operations'),
            'agency': context.get('agency', 'FTC'),
            'violation_type': context.get('violation_type', 'GDPR'),
            'penalty_amount': context.get('penalty_amount', '€20 million'),
            'regulation': context.get('regulation', 'GDPR Article 83'),
            'legal_quote': context.get('legal_quote', 'a watershed moment'),
            'attacker_group': context.get('attacker_group', 'APT29'),
            'previous_op': context.get('previous_op', 'SolarWinds'),
            'threat_intel_vendor': context.get('threat_intel_vendor', 'Mandiant'),
            'confidence': context.get('confidence', random.randint(70, 95)),
            'product': context.get('product', 'CloudShield'),
            'data_type': context.get('data_type', 'encrypted customer records'),
            'affected_users': context.get('affected_users', random.randint(100000, 5000000)),
            'discovery_date': context.get('discovery_date', 'March 2023'),
        }

        narrative_text = template.fill(**fill_values)

        campaign_id = f"memetic_{int(datetime.now(timezone.utc).timestamp())}_{uuid.uuid4().hex[:8]}"

        result = {
            'id': campaign_id,
            'narrative': narrative_text,
            'narrative_type': narrative_type,
            'template_used': next(
                k for k, v in self.NARRATIVES.items() if v == template
            ),
            'tone': template.tone.name,
            'target_audience': template.target_audience,
            'objective': objective,
            'suggested_hashtags': template.suggested_hashtags,
            'virality_base': template.virality_base,
            'decay_hours': template.decay_hours,
            'status': 'generated',
            'created_at': datetime.now(timezone.utc).isoformat(),
            'estimated_reach': random.randint(10000, 500000),
            'success': True,
        }

        self._narrative_history.append(result)
        logger.info(
            f"Narrative generated: type={narrative_type}, "
            f"id={campaign_id}, tone={template.tone.name}"
        )
        return result

    # ── Craft Social Post ───────────────────────────────────────────────────

    def craft_social_post(
        self,
        narrative: Dict[str, Any],
        platform: str,
    ) -> Dict[str, Any]:
        """Adapt a narrative into a platform-specific social media post.

        Args:
            narrative: Narrative dict from generate_narrative().
            platform: Target platform (twitter, linkedin, reddit, slack, etc.).

        Returns:
            Dict with crafted post text and platform metadata.
        """
        platform = platform.lower()
        narrative_text = narrative.get('narrative', '')
        narrative_type = narrative.get('narrative_type', 'distraction')

        # Platform-specific adaptations
        adaptations: Dict[str, Callable[[str], str]] = {
            'twitter': lambda t: (
                t[:277] + '...' if len(t) > 280 else t
            ),
            'linkedin': lambda t: (
                f"{t}\n\n#cybersecurity #infosec #technews"
            ),
            'reddit': lambda t: (
                f"[News] {t}\n\nSources: investigating, will update."
            ),
            'slack': lambda t: (
                f"@channel :warning: {t}"
            ),
            'teams': lambda t: (
                f"<at>everyone</at> {t}"
            ),
            'discord': lambda t: (
                f"@everyone 🚨 {t}"
            ),
            'telegram': lambda t: (
                f"🔴 URGENT: {t}"
            ),
        }

        adapter = adaptations.get(platform, lambda t: t)
        post_text = adapter(narrative_text)

        # Truncate to platform limit
        char_limit = _PLATFORM_POST_LIMITS.get(platform, 5000)
        if len(post_text) > char_limit:
            post_text = post_text[:char_limit - 3] + '...'

        # Add hashtags if platform supports them
        hashtags = narrative.get('suggested_hashtags', [])
        hashtag_text = ' '.join(f'#{h}' for h in hashtags) if hashtags else ''

        if platform in ('twitter', 'linkedin', 'instagram', 'facebook'):
            remaining = char_limit - len(post_text) - len(hashtag_text) - 2
            if remaining > 0:
                post_text = f"{post_text}\n\n{hashtag_text}"

        result = {
            'platform': platform,
            'post_text': post_text,
            'character_count': len(post_text),
            'within_limit': len(post_text) <= char_limit,
            'platform_limit': char_limit,
            'narrative_id': narrative.get('id', ''),
            'recommended_posting_time': (
                datetime.now(timezone.utc)
                + timedelta(hours=random.uniform(0.5, 4.0))
            ).isoformat(),
            'success': True,
        }

        logger.debug(
            f"Crafted post for {platform}: {len(post_text)} chars, "
            f"limit={char_limit}"
        )
        return result

    # ── Simulate Virality ───────────────────────────────────────────────────

    def simulate_virality(
        self,
        narrative: Dict[str, Any],
        target_audience: str = 'public',
        platform: str = 'twitter',
    ) -> Dict[str, Any]:
        """Simulate how a narrative propagates through a target audience.

        Uses a basic SIR (Susceptible-Infected-Recovered) compartmental model
        adapted for information spread with platform-specific dynamics.

        Args:
            narrative: The narrative dict to simulate.
            target_audience: Audience segment ('soc_team', 'public', etc.).
            platform: Primary platform for seeding.

        Returns:
            Dict with virality metrics and propagation forecast.
        """
        platform_factor = _PLATFORM_REACH_FACTORS.get(platform, 0.5)
        virality_base = narrative.get('virality_base', 0.5)
        decay_hours = narrative.get('decay_hours', 24.0)

        # Audience size estimates
        audience_sizes = {
            'soc_team': random.randint(5, 50),
            'employees': random.randint(100, 50000),
            'industry_peers': random.randint(500, 100000),
            'security_community': random.randint(1000, 200000),
            'public': random.randint(10000, 5000000),
        }
        population = audience_sizes.get(target_audience, 10000)

        # SIR model parameters
        beta = virality_base * platform_factor * 0.3  # transmission rate
        gamma = 1.0 / (decay_hours * 6)  # recovery rate (10-min steps)
        steps = int(decay_hours * 6)  # 10-minute resolution

        susceptible = population - 1.0
        infected = 1.0
        recovered = 0.0
        peak_infected = 1.0
        propagation_curve: List[Tuple[float, int]] = []

        for step in range(steps):
            new_infections = beta * susceptible * infected / population
            new_recoveries = gamma * infected

            susceptible -= new_infections
            infected += new_infections - new_recoveries
            recovered += new_recoveries

            if infected > peak_infected:
                peak_infected = infected

            if step % 6 == 0:  # Record hourly
                propagation_curve.append((
                    step / 6.0,
                    int(infected),
                ))

            if infected < 0.5:
                break

        # Engagement metrics
        total_infected = population - susceptible
        engagement_rate = virality_base * platform_factor * random.uniform(0.5, 1.5)
        shares = int(total_infected * engagement_rate * 0.3)
        comments = int(total_infected * engagement_rate * 0.1)

        # Distraction score: how effectively this pulls SOC attention
        soc_distraction = virality_base * platform_factor
        if target_audience == 'soc_team':
            soc_distraction *= 1.5  # Directly targeting SOC is more effective

        result = {
            'platform': platform,
            'target_audience': target_audience,
            'population_size': population,
            'initial_reach': 1,
            'peak_reach': int(peak_infected),
            'total_impressions': int(total_infected),
            'engagement_rate': round(engagement_rate, 4),
            'shares': shares,
            'comments': comments,
            'half_life_hours': round(decay_hours * 0.5, 1),
            'propagation_curve': propagation_curve,
            'simulation_steps': steps,
            'soc_distraction_score': round(soc_distraction, 4),
            'narrative_id': narrative.get('id', ''),
            'success': True,
        }

        # Cache for later reference
        cache_key = f"{narrative.get('id', '')}_{platform}_{target_audience}"
        self._simulation_cache[cache_key] = ViralSimulation(
            platform=platform,
            initial_reach=1,
            peak_reach=int(peak_infected),
            total_impressions=int(total_infected),
            engagement_rate=engagement_rate,
            shares=shares,
            comments=comments,
            half_life_hours=decay_hours * 0.5,
            propagation_curve=propagation_curve,
        )

        logger.info(
            f"Virality simulation: {platform}/{target_audience} — "
            f"peak={int(peak_infected)}, impressions={int(total_infected)}, "
            f"distraction_score={soc_distraction:.3f}"
        )
        return result

    # ── Time Attack with Narrative ──────────────────────────────────────────

    def time_attack_with_narrative(
        self,
        attack_timeline: List[Dict[str, Any]],
        narrative: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Coordinate narrative release with attack timeline for maximum effect.

        Args:
            attack_timeline: List of {'action': str, 'timestamp': ISO str} events.
            narrative: The narrative to synchronise.

        Returns:
            Dict with coordinated timeline and sync recommendations.
        """
        narrative_type = narrative.get('narrative_type', 'distraction')
        sync_plan = []

        # Default: release narrative 5-15 minutes before critical actions
        for idx, event in enumerate(attack_timeline):
            event_time = datetime.fromisoformat(
                event['timestamp'].replace('Z', '+00:00')
            )

            if event.get('critical', False):
                # Release narrative before critical action
                narrative_time = event_time - timedelta(
                    minutes=random.randint(5, 15)
                )
                sync_plan.append({
                    'event_index': idx,
                    'event_action': event['action'],
                    'narrative_release': narrative_time.isoformat(),
                    'event_time': event_time.isoformat(),
                    'offset_seconds': (event_time - narrative_time).total_seconds(),
                    'strategy': 'preemptive_distraction',
                })

        # Add follow-up narratives for sustained SOC fatigue
        if sync_plan:
            last_event_time = max(
                datetime.fromisoformat(s['event_time'].replace('Z', '+00:00'))
                for s in sync_plan
            )
            for i in range(2):  # Two follow-up waves
                follow_up_time = last_event_time + timedelta(
                    hours=random.uniform(2, 6) * (i + 1)
                )
                sync_plan.append({
                    'event_index': -1,
                    'event_action': f'follow_up_wave_{i + 1}',
                    'narrative_release': follow_up_time.isoformat(),
                    'event_time': follow_up_time.isoformat(),
                    'offset_seconds': 0,
                    'strategy': 'sustain_distraction',
                })

        result = {
            'narrative_id': narrative.get('id', ''),
            'narrative_type': narrative_type,
            'attack_events': len(attack_timeline),
            'sync_points': len(sync_plan),
            'coordinated_timeline': sync_plan,
            'total_coverage_hours': (
                (sync_plan[-1]['event_time'] if sync_plan else 'N/A')
            ),
            'success': True,
        }

        logger.info(
            f"Attack-narrative sync: {len(sync_plan)} sync points "
            f"for {len(attack_timeline)} attack events"
        )
        return result

    # ── Measure Narrative Impact ────────────────────────────────────────────

    def measure_narrative_impact(
        self,
        narrative_id: str,
    ) -> Dict[str, Any]:
        """Measure the effectiveness of a deployed narrative.

        Args:
            narrative_id: The campaign/narrative ID to measure.

        Returns:
            Dict with impact metrics and effectiveness score.
        """
        # Find the narrative in history
        narrative = None
        for n in self._narrative_history:
            if n.get('id') == narrative_id:
                narrative = n
                break

        if not narrative:
            return {
                'narrative_id': narrative_id,
                'found': False,
                'error': 'Narrative not found in history',
                'success': False,
            }

        # Gather all simulation data for this narrative
        sims = {
            k: v for k, v in self._simulation_cache.items()
            if k.startswith(narrative_id)
        }

        total_impressions = sum(s.total_impressions for s in sims.values())
        total_engagements = sum(s.shares + s.comments for s in sims.values())
        peak_reach = max((s.peak_reach for s in sims.values()), default=0)

        # Calculate SOC fatigue impact
        soc_distraction = max(
            (s.engagement_rate for s in sims.values()),
            default=0.0,
        )
        narrative_type_data = _NARRATIVE_TYPES.get(
            narrative.get('narrative_type', 'distraction'),
            _NARRATIVE_TYPES['distraction'],
        )
        impact_score = (
            soc_distraction
            * narrative_type_data['virality_base']
            * min(total_impressions / 100000, 1.0)
        )

        result = {
            'narrative_id': narrative_id,
            'found': True,
            'narrative_type': narrative.get('narrative_type', 'unknown'),
            'total_impressions': total_impressions,
            'total_engagements': total_engagements,
            'peak_reach': peak_reach,
            'platforms_measured': len(sims),
            'soc_distraction_score': round(soc_distraction, 4),
            'impact_score': round(impact_score, 4),
            'effectiveness': (
                'HIGH' if impact_score > 0.5
                else 'MODERATE' if impact_score > 0.2
                else 'LOW'
            ),
            'created_at': narrative.get('created_at', ''),
            'success': True,
        }

        logger.info(
            f"Narrative impact: {narrative_id} — "
            f"score={impact_score:.3f}, effectiveness={result['effectiveness']}"
        )
        return result

    # ── Generate Distraction Campaign ───────────────────────────────────────

    def generate_distraction_campaign(
        self,
        soc_team_profiles: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """Generate a multi-platform distraction campaign targeting SOC teams.

        Creates a coordinated set of narratives across platforms designed
        to exhaust SOC attention and create blind spots for the real attack.

        Args:
            soc_team_profiles: Known SOC team member profiles (roles, interests).

        Returns:
            Dict with campaign plan and platform-specific posts.
        """
        soc_profiles = soc_team_profiles or [
            {'role': 'SOC Analyst L1', 'interests': ['malware', 'phishing']},
            {'role': 'SOC Analyst L2', 'interests': ['threat hunting', 'SIEM']},
            {'role': 'Incident Responder', 'interests': ['forensics', 'IR playbooks']},
        ]

        # Diversify narratives to cover different SOC attention channels
        narrative_plan = [
            {
                'narrative_type': 'panic_induce',
                'platforms': ['twitter', 'reddit'],
                'timing': 'immediate',
                'target': 'alert_fatigue',
            },
            {
                'narrative_type': 'credibility_undermine',
                'platforms': ['linkedin', 'slack'],
                'timing': '+30min',
                'target': 'team_morale',
            },
            {
                'narrative_type': 'distraction',
                'platforms': ['discord', 'telegram'],
                'timing': '+60min',
                'target': 'attention_diversion',
            },
        ]

        campaigns = []
        for plan in narrative_plan:
            narrative = self.generate_narrative(
                plan['narrative_type'],
                objective='soc_distraction',
                context={
                    'company': self.target_org,
                    'industry': 'technology',
                },
            )

            platform_posts = []
            for platform in plan['platforms']:
                post = self.craft_social_post(narrative, platform)
                sim = self.simulate_virality(
                    narrative, target_audience='soc_team', platform=platform
                )
                platform_posts.append({
                    'platform': platform,
                    'post': post,
                    'virality': sim,
                })

            campaigns.append({
                'phase': plan['narrative_type'],
                'timing': plan['timing'],
                'target_effect': plan['target'],
                'narrative': narrative,
                'platform_posts': platform_posts,
            })

        # Aggregate campaign metrics
        total_impressions = sum(
            pp['virality'].get('total_impressions', 0)
            for c in campaigns
            for pp in c['platform_posts']
        )

        result = {
            'campaign_id': f'distraction_{int(time.time())}',
            'target_org': self.target_org,
            'soc_profiles_targeted': len(soc_profiles),
            'narrative_phases': len(campaigns),
            'platforms_used': list(set(
                pp['platform']
                for c in campaigns
                for pp in c['platform_posts']
            )),
            'total_estimated_impressions': total_impressions,
            'phases': campaigns,
            'status': 'planned',
            'success': True,
        }

        logger.info(
            f"Distraction campaign generated: {len(campaigns)} phases, "
            f"{result['platforms_used']} platforms, "
            f"{total_impressions:,} est. impressions"
        )
        return result

    # ── Utility ─────────────────────────────────────────────────────────────

    def create_campaign(
        self,
        narrative_type: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Legacy wrapper — delegates to generate_narrative."""
        return self.generate_narrative(narrative_type, objective='', context=context)

    def get_active_campaigns(self) -> List[Dict[str, Any]]:
        """Return all active campaign metrics."""
        return [
            asdict(m) for m in self._active_campaigns.values()
            if m.active
        ]

    def get_narrative_types(self) -> Dict[str, Dict[str, Any]]:
        """Return available narrative types and their properties."""
        return deepcopy(_NARRATIVE_TYPES)

    def reset(self) -> None:
        """Clear all campaigns and history."""
        self._active_campaigns.clear()
        self._narrative_history.clear()
        self._simulation_cache.clear()
        logger.debug("MemeticAttack reset — all campaigns wiped.")
