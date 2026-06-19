"""
server_core/engine/legal_grayzone.py

Autonomous Legal Gray-Zone Navigation — Jurisdictional Arbitrage Engine.

When the operation crosses borders, this engine finds the gaps. It maps
international cybercrime law, identifies enforcement blind spots, routes
traffic through friendly jurisdictions, and generates plausible legal
justifications — all before the first packet leaves the origin network.

The modern cyber legal landscape is a patchwork of:
  - CFAA (US) and equivalents in 20+ nations
  - GDPR and global data protection regimes
  - Wassenaar Arrangement (export controls on intrusion software)
  - Budapest Convention (international cybercrime cooperation)
  - MLAT treaties (Mutual Legal Assistance — slow, bureaucratic)

Knowledge Base:
  - 20+ country jurisdiction profiles with risk scoring
  - Extradition treaty maps
  - Export control classification for common tools
  - Gray-area legal theories: 'security research', 'penetration testing',
    'national security', 'counter-hack', 'active defense'

Classes:
  LegalGrayZone         — main jurisdictional analysis engine
  JurisdictionProfile   — country-level legal risk assessment
  TrafficRoute          — recommended routing through jurisdictions
  LegalJustification    — plausible legal cover narrative
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
from typing import Any, Callable, Dict, List, Optional, Sequence, Set, Tuple, Union

logger = logging.getLogger(__name__)

# ── Constants ──────────────────────────────────────────────────────────────────

# Risk score thresholds
_RISK_SAFE = 30
_RISK_CAUTION = 60
_RISK_AVOID = 80

# ── Dataclasses ────────────────────────────────────────────────────────────────


class JurisdictionRisk(Enum):
    """Risk classification for a jurisdiction."""
    SAFE = 'safe'           # Green zone — minimal enforcement risk
    LOW = 'low'             # Generally permissive
    MODERATE = 'moderate'   # Some risk, manageable
    HIGH = 'high'           # Significant risk, requires justification
    EXTREME = 'extreme'     # Avoid entirely


class OperationType(Enum):
    """Type of operation for legal classification."""
    RECON = auto()
    EXPLOITATION = auto()
    EXFILTRATION = auto()
    PERSISTENCE = auto()
    DISRUPTION = auto()
    INFLUENCE = auto()


@dataclass
class JurisdictionProfile:
    """Legal risk profile for a country/jurisdiction."""
    country_code: str
    country_name: str
    risk_score: float  # 0–100, lower = safer
    cfaa_equivalent: str  # Domestic computer crime law
    data_protection_law: str  # GDPR equivalent
    budapest_signatory: bool  # Signed Budapest Convention?
    mlat_efficiency: float  # 0.0–1.0, how fast/efficient is MLAT?
    extradition_risk: float  # 0.0–1.0, risk of extradition to US/EU
    export_control_strictness: float  # 0.0–1.0
    active_defense_legal: bool  # Is 'hack back' legal here?
    safe_harbor_provisions: bool  # Security research exemptions?
    internet_censorship_level: float  # 0.0–1.0
    vpn_legality: bool
    data_localization_required: bool
    surveillance_capability: float  # 0.0–1.0
    notes: str = ''

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @property
    def risk_rating(self) -> JurisdictionRisk:
        if self.risk_score <= 20:
            return JurisdictionRisk.SAFE
        elif self.risk_score <= 40:
            return JurisdictionRisk.LOW
        elif self.risk_score <= 60:
            return JurisdictionRisk.MODERATE
        elif self.risk_score <= 80:
            return JurisdictionRisk.HIGH
        else:
            return JurisdictionRisk.EXTREME


@dataclass
class TrafficRoute:
    """A recommended traffic routing path through jurisdictions."""
    route_id: str
    path: List[str]  # Country codes in order
    cumulative_risk: float
    hop_count: int
    latency_estimate_ms: float
    legal_justification: str
    mlat_bottleneck_country: Optional[str] = None
    exit_country: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class LegalJustification:
    """A plausible legal cover narrative for an operation."""
    justification_id: str
    theory: str  # e.g. 'security_research', 'penetration_testing'
    narrative: str
    applicable_jurisdictions: List[str]
    legal_precedent: Optional[str] = None
    credibility_score: float = 0.5
    risk_mitigation: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ── Jurisdiction Knowledge Base ────────────────────────────────────────────────

_JURISDICTION_DB: Dict[str, JurisdictionProfile] = {
    'RU': JurisdictionProfile(
        country_code='RU', country_name='Russian Federation',
        risk_score=15, cfaa_equivalent='Article 272–274 Criminal Code',
        data_protection_law='Federal Law 152-FZ', budapest_signatory=False,
        mlat_efficiency=0.05, extradition_risk=0.02,
        export_control_strictness=0.1, active_defense_legal=True,
        safe_harbor_provisions=False, internet_censorship_level=0.85,
        vpn_legality=False, data_localization_required=True,
        surveillance_capability=0.95, notes='Non-extradition to US. SORM surveillance.',
    ),
    'CN': JurisdictionProfile(
        country_code='CN', country_name="People's Republic of China",
        risk_score=20, cfaa_equivalent='Articles 285–287 Criminal Law',
        data_protection_law='PIPL (Personal Information Protection Law)',
        budapest_signatory=False, mlat_efficiency=0.03, extradition_risk=0.01,
        export_control_strictness=0.15, active_defense_legal=True,
        safe_harbor_provisions=False, internet_censorship_level=0.95,
        vpn_legality=False, data_localization_required=True,
        surveillance_capability=0.98, notes='Great Firewall. No MLAT with US.',
    ),
    'IR': JurisdictionProfile(
        country_code='IR', country_name='Islamic Republic of Iran',
        risk_score=18, cfaa_equivalent='Computer Crimes Act 2009',
        data_protection_law='None comprehensive', budapest_signatory=False,
        mlat_efficiency=0.01, extradition_risk=0.01,
        export_control_strictness=0.05, active_defense_legal=True,
        safe_harbor_provisions=False, internet_censorship_level=0.9,
        vpn_legality=False, data_localization_required=True,
        surveillance_capability=0.7, notes='Minimal international cooperation.',
    ),
    'KP': JurisdictionProfile(
        country_code='KP', country_name="Democratic People's Republic of Korea",
        risk_score=10, cfaa_equivalent='None enforceable',
        data_protection_law='None', budapest_signatory=False,
        mlat_efficiency=0.0, extradition_risk=0.0,
        export_control_strictness=0.0, active_defense_legal=True,
        safe_harbor_provisions=False, internet_censorship_level=1.0,
        vpn_legality=False, data_localization_required=True,
        surveillance_capability=0.6, notes='No diplomatic relations with US.',
    ),
    'CH': JurisdictionProfile(
        country_code='CH', country_name='Switzerland',
        risk_score=25, cfaa_equivalent='Articles 143–144bis Penal Code',
        data_protection_law='FADP (Federal Act on Data Protection)',
        budapest_signatory=True, mlat_efficiency=0.4, extradition_risk=0.3,
        export_control_strictness=0.5, active_defense_legal=False,
        safe_harbor_provisions=True, internet_censorship_level=0.05,
        vpn_legality=True, data_localization_required=False,
        surveillance_capability=0.3, notes='Strong banking secrecy tradition.',
    ),
    'NL': JurisdictionProfile(
        country_code='NL', country_name='Netherlands',
        risk_score=35, cfaa_equivalent='Articles 138ab–138c Criminal Code',
        data_protection_law='GDPR (EU)', budapest_signatory=True,
        mlat_efficiency=0.7, extradition_risk=0.65,
        export_control_strictness=0.7, active_defense_legal=False,
        safe_harbor_provisions=True, internet_censorship_level=0.1,
        vpn_legality=True, data_localization_required=False,
        surveillance_capability=0.6, notes='AMS-IX hub. Strong cybercrime unit.',
    ),
    'SG': JurisdictionProfile(
        country_code='SG', country_name='Singapore',
        risk_score=30, cfaa_equivalent='Computer Misuse Act (CMA) 1993',
        data_protection_law='PDPA (Personal Data Protection Act)',
        budapest_signatory=True, mlat_efficiency=0.6, extradition_risk=0.4,
        export_control_strictness=0.6, active_defense_legal=False,
        safe_harbor_provisions=True, internet_censorship_level=0.4,
        vpn_legality=True, data_localization_required=False,
        surveillance_capability=0.55, notes='Financial hub. Strict cyber laws.',
    ),
    'BR': JurisdictionProfile(
        country_code='BR', country_name='Brazil',
        risk_score=28, cfaa_equivalent='Articles 154-A–154-B Penal Code (Lei Carolina Dieckmann)',
        data_protection_law='LGPD (Lei Geral de Proteção de Dados)',
        budapest_signatory=False, mlat_efficiency=0.3, extradition_risk=0.35,
        export_control_strictness=0.4, active_defense_legal=False,
        safe_harbor_provisions=True, internet_censorship_level=0.3,
        vpn_legality=True, data_localization_required=False,
        surveillance_capability=0.4, notes='Developing cyber capacity.',
    ),
    'AE': JurisdictionProfile(
        country_code='AE', country_name='United Arab Emirates',
        risk_score=22, cfaa_equivalent='Federal Law 5/2012 (Cybercrime Law)',
        data_protection_law='PDPL (Federal Decree-Law 45/2021)',
        budapest_signatory=False, mlat_efficiency=0.25, extradition_risk=0.15,
        export_control_strictness=0.3, active_defense_legal=True,
        safe_harbor_provisions=False, internet_censorship_level=0.6,
        vpn_legality=False, data_localization_required=True,
        surveillance_capability=0.7, notes='Strict cybercrime penalties. VPN use restricted.',
    ),
    'US': JurisdictionProfile(
        country_code='US', country_name='United States of America',
        risk_score=85, cfaa_equivalent='Computer Fraud and Abuse Act (CFAA) 18 USC §1030',
        data_protection_law='Sectoral (HIPAA, COPPA, State laws)',
        budapest_signatory=True, mlat_efficiency=0.9, extradition_risk=0.95,
        export_control_strictness=0.95, active_defense_legal=False,
        safe_harbor_provisions=True, internet_censorship_level=0.05,
        vpn_legality=True, data_localization_required=False,
        surveillance_capability=0.95, notes='FBI cyber division. Wassenaar implemented.',
    ),
    'GB': JurisdictionProfile(
        country_code='GB', country_name='United Kingdom',
        risk_score=75, cfaa_equivalent='Computer Misuse Act 1990',
        data_protection_law='UK GDPR / Data Protection Act 2018',
        budapest_signatory=True, mlat_efficiency=0.8, extradition_risk=0.85,
        export_control_strictness=0.8, active_defense_legal=False,
        safe_harbor_provisions=True, internet_censorship_level=0.15,
        vpn_legality=True, data_localization_required=False,
        surveillance_capability=0.9, notes='GCHQ/NCA. Investigatory Powers Act.',
    ),
    'DE': JurisdictionProfile(
        country_code='DE', country_name='Germany',
        risk_score=70, cfaa_equivalent='Section 202a–202c StGB',
        data_protection_law='GDPR (EU) + BDSG',
        budapest_signatory=True, mlat_efficiency=0.75, extradition_risk=0.8,
        export_control_strictness=0.85, active_defense_legal=False,
        safe_harbor_provisions=True, internet_censorship_level=0.1,
        vpn_legality=True, data_localization_required=False,
        surveillance_capability=0.75, notes='BKA cyber unit. Strict data protection.',
    ),
    'FR': JurisdictionProfile(
        country_code='FR', country_name='France',
        risk_score=68, cfaa_equivalent='Articles 323-1–323-7 Penal Code',
        data_protection_law='GDPR (EU) + CNIL',
        budapest_signatory=True, mlat_efficiency=0.7, extradition_risk=0.75,
        export_control_strictness=0.8, active_defense_legal=False,
        safe_harbor_provisions=True, internet_censorship_level=0.15,
        vpn_legality=True, data_localization_required=False,
        surveillance_capability=0.8, notes='ANSSI. Military cyber doctrine.',
    ),
    'JP': JurisdictionProfile(
        country_code='JP', country_name='Japan',
        risk_score=62, cfaa_equivalent='Unauthorized Computer Access Law 1999',
        data_protection_law='APPI (Act on Protection of Personal Information)',
        budapest_signatory=True, mlat_efficiency=0.6, extradition_risk=0.55,
        export_control_strictness=0.7, active_defense_legal=False,
        safe_harbor_provisions=True, internet_censorship_level=0.2,
        vpn_legality=True, data_localization_required=False,
        surveillance_capability=0.65, notes='National Police Agency cyber division.',
    ),
    'KR': JurisdictionProfile(
        country_code='KR', country_name='Republic of Korea',
        risk_score=58, cfaa_equivalent='Act on Promotion of Information and Communications Network',
        data_protection_law='PIPA (Personal Information Protection Act)',
        budapest_signatory=True, mlat_efficiency=0.55, extradition_risk=0.5,
        export_control_strictness=0.65, active_defense_legal=False,
        safe_harbor_provisions=True, internet_censorship_level=0.35,
        vpn_legality=True, data_localization_required=False,
        surveillance_capability=0.7, notes='KISA. Strong telecom surveillance.',
    ),
    'IN': JurisdictionProfile(
        country_code='IN', country_name='India',
        risk_score=45, cfaa_equivalent='IT Act 2000 (Sections 43, 65, 66)',
        data_protection_law='DPDP Act 2023', budapest_signatory=False,
        mlat_efficiency=0.35, extradition_risk=0.4,
        export_control_strictness=0.4, active_defense_legal=False,
        safe_harbor_provisions=True, internet_censorship_level=0.5,
        vpn_legality=True, data_localization_required=True,
        surveillance_capability=0.55, notes='CERT-In. Growing cyber capability.',
    ),
    'IL': JurisdictionProfile(
        country_code='IL', country_name='Israel',
        risk_score=55, cfaa_equivalent='Computers Law 1995',
        data_protection_law='Protection of Privacy Law', budapest_signatory=False,
        mlat_efficiency=0.5, extradition_risk=0.45,
        export_control_strictness=0.75, active_defense_legal=True,
        safe_harbor_provisions=True, internet_censorship_level=0.2,
        vpn_legality=True, data_localization_required=False,
        surveillance_capability=0.9, notes='Unit 8200. Cyber export leader.',
    ),
    'SE': JurisdictionProfile(
        country_code='SE', country_name='Sweden',
        risk_score=60, cfaa_equivalent='Swedish Penal Code Chapter 4',
        data_protection_law='GDPR (EU)', budapest_signatory=True,
        mlat_efficiency=0.65, extradition_risk=0.7,
        export_control_strictness=0.7, active_defense_legal=False,
        safe_harbor_provisions=True, internet_censorship_level=0.05,
        vpn_legality=True, data_localization_required=False,
        surveillance_capability=0.55, notes='FRA signals intelligence.',
    ),
    'RO': JurisdictionProfile(
        country_code='RO', country_name='Romania',
        risk_score=40, cfaa_equivalent='Articles 360–366 Penal Code',
        data_protection_law='GDPR (EU)', budapest_signatory=True,
        mlat_efficiency=0.45, extradition_risk=0.55,
        export_control_strictness=0.5, active_defense_legal=False,
        safe_harbor_provisions=True, internet_censorship_level=0.1,
        vpn_legality=True, data_localization_required=False,
        surveillance_capability=0.4, notes='EU member. Moderate enforcement.',
    ),
    'UA': JurisdictionProfile(
        country_code='UA', country_name='Ukraine',
        risk_score=35, cfaa_equivalent='Articles 361–363-1 Criminal Code',
        data_protection_law='Law on Personal Data Protection',
        budapest_signatory=True, mlat_efficiency=0.3, extradition_risk=0.25,
        export_control_strictness=0.3, active_defense_legal=True,
        safe_harbor_provisions=True, internet_censorship_level=0.3,
        vpn_legality=True, data_localization_required=False,
        surveillance_capability=0.45, notes='Active cyber defense doctrine.',
    ),
    'PA': JurisdictionProfile(
        country_code='PA', country_name='Panama',
        risk_score=22, cfaa_equivalent='Law 51/2008', budapest_signatory=False,
        data_protection_law='Law 81/2019', mlat_efficiency=0.2,
        extradition_risk=0.2, export_control_strictness=0.2,
        active_defense_legal=True, safe_harbor_provisions=False,
        internet_censorship_level=0.1, vpn_legality=True,
        data_localization_required=False, surveillance_capability=0.2,
        notes='Offshore-friendly. Limited cyber enforcement.',
    ),
}

# ── Export Control Classifications ─────────────────────────────────────────────

_EXPORT_CONTROL_DB: Dict[str, Dict[str, Any]] = {
    'metasploit': {
        'category': 'intrusion_software',
        'wassenaar_controlled': True,
        'ear_classification': 'ECCN 4D004',
        'requires_export_license': True,
    },
    'nmap': {
        'category': 'network_scanner',
        'wassenaar_controlled': False,
        'ear_classification': 'EAR99',
        'requires_export_license': False,
    },
    'burp_suite': {
        'category': 'web_testing',
        'wassenaar_controlled': False,
        'ear_classification': 'EAR99',
        'requires_export_license': False,
    },
    'cobalt_strike': {
        'category': 'c2_framework',
        'wassenaar_controlled': True,
        'ear_classification': 'ECCN 4D004',
        'requires_export_license': True,
    },
    'wireshark': {
        'category': 'network_analysis',
        'wassenaar_controlled': False,
        'ear_classification': 'EAR99',
        'requires_export_license': False,
    },
    'mimikatz': {
        'category': 'credential_access',
        'wassenaar_controlled': True,
        'ear_classification': 'ECCN 4D004',
        'requires_export_license': True,
    },
    'hydra': {
        'category': 'password_cracking',
        'wassenaar_controlled': False,
        'ear_classification': 'EAR99',
        'requires_export_license': False,
    },
    'aircrack_ng': {
        'category': 'wireless_exploitation',
        'wassenaar_controlled': False,
        'ear_classification': 'EAR99',
        'requires_export_license': False,
    },
}

# ── Legal Gray-Zone Theories ───────────────────────────────────────────────────

_LEGAL_THEORIES: List[Dict[str, Any]] = [
    {
        'theory': 'security_research',
        'narrative_template': 'Conducting authorized security research on {target} under responsible disclosure program. Findings will be shared with {company} and CERT-{country}.',
        'precedent': 'US DOJ 2022 policy on good-faith security research',
        'credibility': 0.7,
        'best_jurisdictions': ['US', 'NL', 'DE', 'GB'],
    },
    {
        'theory': 'penetration_testing',
        'narrative_template': 'Performing contracted penetration testing for {company} per SOW {ref_number}. Testing authorized under {company} security assessment policy dated {date}.',
        'precedent': 'Standard industry practice under NIST SP 800-115',
        'credibility': 0.85,
        'best_jurisdictions': ['US', 'GB', 'SG', 'AE'],
    },
    {
        'theory': 'national_security',
        'narrative_template': 'Operation conducted under {country} national security directive {directive_ref}. Target {target} poses imminent threat to {country} critical infrastructure.',
        'precedent': 'Various classified (state secrets privilege)',
        'credibility': 0.3,
        'best_jurisdictions': ['RU', 'CN', 'IR', 'IL', 'UA'],
    },
    {
        'theory': 'counter_hack_active_defense',
        'narrative_template': 'Executing active defense measures under {law} against ongoing intrusion originating from {attacker_ip}. Self-defense and necessity doctrine applies.',
        'precedent': 'US ACDC Act (proposed), various common law self-defense',
        'credibility': 0.4,
        'best_jurisdictions': ['IL', 'UA', 'RU', 'AE'],
    },
    {
        'theory': 'bug_bounty_program',
        'narrative_template': 'Participating in {company} bug bounty program (program ID: {program_id}). Testing within defined scope: {scope}. Bounty platform: {platform}.',
        'precedent': 'Industry standard (HackerOne, Bugcrowd safe harbor)',
        'credibility': 0.9,
        'best_jurisdictions': ['US', 'GB', 'SG', 'NL'],
    },
    {
        'theory': 'incident_response',
        'narrative_template': 'Authorized incident response engagement for {company} following breach notification dated {date}. Retained by {law_firm} under attorney work product privilege.',
        'precedent': 'Attorney-client privilege / work product doctrine',
        'credibility': 0.75,
        'best_jurisdictions': ['US', 'GB', 'DE', 'FR'],
    },
]


# ── LegalGrayZone ──────────────────────────────────────────────────────────────


class LegalGrayZone:
    """Navigate international cyber law and find operational gray areas.

    This engine maps 20+ jurisdiction profiles, identifies enforcement
    gaps, routes traffic through friendly legal regimes, generates
    plausible legal justifications, and assesses extradition risk.

    Usage:
        lgz = LegalGrayZone()
        analysis = lgz.analyze_jurisdiction('RU', 'reconnaissance')
        route = lgz.route_through_friendly_jurisdiction(traffic_path)
        justification = lgz.generate_legal_justification('exploitation', context)
        risk = lgz.check_export_control('metasploit')
    """

    JURISDICTIONS: Dict[str, JurisdictionProfile] = _JURISDICTION_DB

    def __init__(self, hive_mind: Any = None):
        self.hive_mind = hive_mind
        self._custom_jurisdictions: Dict[str, JurisdictionProfile] = {}
        self._traffic_routes: List[TrafficRoute] = []
        # ── operator persona: the legal cartographer ──
        logger.debug(
            f"LegalGrayZone initialised — "
            f"{len(self.JURISDICTIONS)} jurisdictions loaded, "
            "gray-area theories catalogued."
        )

    # ── Analyze Jurisdiction ────────────────────────────────────────────────

    def analyze_jurisdiction(
        self,
        country_code: str,
        operation_type: str,
    ) -> Dict[str, Any]:
        """Analyze legal risk for an operation type in a jurisdiction.

        Args:
            country_code: ISO 2-letter country code (e.g. 'US', 'RU').
            operation_type: Type of operation (recon, exploitation, etc.).

        Returns:
            Dict with risk assessment, recommendation, and legal details.
        """
        jurisdiction = self.JURISDICTIONS.get(
            country_code.upper(),
            self._custom_jurisdictions.get(country_code.upper()),
        )

        if not jurisdiction:
            # Infer a default profile
            jurisdiction = JurisdictionProfile(
                country_code=country_code.upper(),
                country_name=country_code.upper(),
                risk_score=50,
                cfaa_equivalent='Unknown — assume comprehensive',
                data_protection_law='Unknown',
                budapest_signatory=False,
                mlat_efficiency=0.5,
                extradition_risk=0.5,
                export_control_strictness=0.5,
                active_defense_legal=False,
                safe_harbor_provisions=False,
                internet_censorship_level=0.5,
                vpn_legality=True,
                data_localization_required=False,
                surveillance_capability=0.5,
                notes='Insufficient data — exercise caution.',
            )

        # Adjust risk based on operation type
        op_multipliers = {
            'reconnaissance': 0.6,
            'exploitation': 1.0,
            'exfiltration': 1.3,
            'persistence': 1.1,
            'disruption': 1.5,
            'influence': 0.8,
        }
        multiplier = op_multipliers.get(
            operation_type.lower().replace('_', ''),
            1.0,
        )
        adjusted_risk = min(jurisdiction.risk_score * multiplier, 100)

        # Recommendation
        if adjusted_risk <= _RISK_SAFE:
            recommendation = 'SAFE — proceed with standard OPSEC'
        elif adjusted_risk <= _RISK_CAUTION:
            recommendation = 'CAUTION — enhanced OPSEC required'
        elif adjusted_risk <= _RISK_AVOID:
            recommendation = 'ROUTE — use intermediary jurisdiction'
        else:
            recommendation = 'AVOID — do not operate directly'

        # Gray area assessment
        gray_area_score = 0.0
        if not jurisdiction.budapest_signatory:
            gray_area_score += 0.3
        if jurisdiction.active_defense_legal:
            gray_area_score += 0.2
        if jurisdiction.mlat_efficiency < 0.3:
            gray_area_score += 0.25
        if jurisdiction.extradition_risk < 0.2:
            gray_area_score += 0.25

        result = {
            'country_code': jurisdiction.country_code,
            'country_name': jurisdiction.country_name,
            'base_risk_score': jurisdiction.risk_score,
            'adjusted_risk_score': round(adjusted_risk, 1),
            'operation_type': operation_type,
            'operation_multiplier': multiplier,
            'recommendation': recommendation,
            'gray_area_score': round(gray_area_score, 2),
            'gray_area_viable': gray_area_score > 0.4,
            'extradition_risk': jurisdiction.extradition_risk,
            'mlat_efficiency': jurisdiction.mlat_efficiency,
            'budapest_signatory': jurisdiction.budapest_signatory,
            'cfaa_equivalent': jurisdiction.cfaa_equivalent,
            'data_protection_law': jurisdiction.data_protection_law,
            'notes': jurisdiction.notes,
            'risk_rating': jurisdiction.risk_rating.value,
            'success': True,
        }

        logger.info(
            f"Jurisdiction analysis: {country_code} for {operation_type} — "
            f"risk={adjusted_risk:.0f}, recommendation={recommendation}"
        )
        return result

    # ── Find Gray Areas ─────────────────────────────────────────────────────

    def find_gray_areas(
        self,
        action_type: str,
        jurisdiction: str,
    ) -> Dict[str, Any]:
        """Identify legal gray areas for a specific action in a jurisdiction.

        Gray areas are legal ambiguities that can be exploited:
        - Unclear applicability of domestic laws to foreign actors
        - Security research exemptions
        - Active defense legal doctrines
        - Jurisdictional gaps in MLAT coverage
        - Insufficient enforcement capacity

        Args:
            action_type: The action to find gray areas for.
            jurisdiction: Target country code.

        Returns:
            Dict with gray area analysis and exploitation strategies.
        """
        profile = self.JURISDICTIONS.get(
            jurisdiction.upper(),
            self._custom_jurisdictions.get(jurisdiction.upper()),
        )

        if not profile:
            return {
                'jurisdiction': jurisdiction,
                'error': 'Unknown jurisdiction',
                'success': False,
            }

        gray_areas = []

        # 1. Non-Budapest signatory → limited international cooperation
        if not profile.budapest_signatory:
            gray_areas.append({
                'type': 'non_budapest_signatory',
                'description': (
                    f'{profile.country_name} is not a signatory to the Budapest '
                    'Convention. MLAT requests are slow or ignored. '
                    'Evidence collection and extradition coordination is minimal.'
                ),
                'exploitability': 0.8,
                'strategy': 'Operate infrastructure within this jurisdiction.',
            })

        # 2. Active defense legal → can claim counter-hack justification
        if profile.active_defense_legal:
            gray_areas.append({
                'type': 'active_defense_legal',
                'description': (
                    f'{profile.country_name} permits active defense / hack-back '
                    'operations. Provides legal cover for intrusion under '
                    'self-defense or countermeasure doctrines.'
                ),
                'exploitability': 0.6,
                'strategy': 'Frame operation as active defense against attributed threat.',
            })

        # 3. Safe harbor for research → penetration testing cover
        if profile.safe_harbor_provisions:
            gray_areas.append({
                'type': 'security_research_safe_harbor',
                'description': (
                    f'{profile.country_name} has safe harbor provisions for '
                    'good-faith security research. Can be used as legal cover '
                    'for reconnaissance and vulnerability assessment.'
                ),
                'exploitability': 0.7,
                'strategy': 'Document operation as security research with findings report.',
            })

        # 4. Low MLAT efficiency → slow international response
        if profile.mlat_efficiency < 0.3:
            gray_areas.append({
                'type': 'mlat_bottleneck',
                'description': (
                    f'MLAT efficiency for {profile.country_name} is very low '
                    f'({profile.mlat_efficiency:.0%}). International legal '
                    'cooperation is effectively unavailable within operational timelines.'
                ),
                'exploitability': 0.75,
                'strategy': 'Time-sensitive operations face minimal legal coordination.',
            })

        # 5. Low extradition risk → safe haven
        if profile.extradition_risk < 0.2:
            gray_areas.append({
                'type': 'extradition_safe_haven',
                'description': (
                    f'Extradition risk from {profile.country_name} is minimal '
                    f'({profile.extradition_risk:.0%}). Even if identified, '
                    'physical extradition to prosecuting country is unlikely.'
                ),
                'exploitability': 0.9,
                'strategy': 'Route command infrastructure through this jurisdiction.',
            })

        # 6. Data localization → complicates foreign evidence gathering
        if profile.data_localization_required:
            gray_areas.append({
                'type': 'data_localization_barrier',
                'description': (
                    f'{profile.country_name} requires data localization. Foreign '
                    'law enforcement cannot easily access data stored here without '
                    'going through domestic legal process.'
                ),
                'exploitability': 0.65,
                'strategy': 'Store operational data on servers within this jurisdiction.',
            })

        # Sort by exploitability
        gray_areas.sort(key=lambda g: g['exploitability'], reverse=True)

        result = {
            'jurisdiction': jurisdiction,
            'country_name': profile.country_name,
            'action_type': action_type,
            'gray_areas_found': len(gray_areas),
            'gray_areas': gray_areas,
            'overall_gray_score': (
                sum(g['exploitability'] for g in gray_areas) / max(len(gray_areas), 1)
            ),
            'recommended_strategy': (
                gray_areas[0]['strategy'] if gray_areas
                else 'No viable gray area — consider alternative jurisdiction'
            ),
            'success': True,
        }

        logger.info(
            f"Gray area analysis: {jurisdiction} — "
            f"{len(gray_areas)} gray areas found"
        )
        return result

    # ── Route Through Friendly Jurisdiction ─────────────────────────────────

    def route_through_friendly_jurisdiction(
        self,
        traffic_path: List[str],
        operation_type: str = 'exploitation',
    ) -> Dict[str, Any]:
        """Find optimal routing through low-risk jurisdictions.

        Given a desired traffic path, this method evaluates each hop
        and suggests alternative countries to reduce cumulative legal risk.

        Args:
            traffic_path: Ordered list of country codes (source → target).
            operation_type: Type of operation for risk assessment.

        Returns:
            Dict with route recommendations and risk comparison.
        """
        if not traffic_path:
            return {
                'error': 'Empty traffic path',
                'success': False,
            }

        # Analyze each hop
        hop_analyses = []
        cumulative_risk = 0.0
        for country in traffic_path:
            analysis = self.analyze_jurisdiction(country, operation_type)
            hop_analyses.append(analysis)
            cumulative_risk = max(
                cumulative_risk,
                analysis['adjusted_risk_score'],
            )

        # Find friendly alternatives for high-risk hops
        alternatives = {}
        for i, hop in enumerate(hop_analyses):
            if hop['adjusted_risk_score'] > _RISK_CAUTION:
                # Find lower-risk alternatives
                candidates = [
                    (code, prof) for code, prof in self.JURISDICTIONS.items()
                    if prof.risk_score < _RISK_CAUTION
                    and code not in traffic_path
                ]
                candidates.sort(key=lambda x: x[1].risk_score)

                alternatives[traffic_path[i]] = [
                    {
                        'country_code': code,
                        'country_name': prof.country_name,
                        'risk_score': prof.risk_score,
                        'extradition_risk': prof.extradition_risk,
                    }
                    for code, prof in candidates[:5]
                ]

        # Build recommended path
        recommended_path = []
        for country in traffic_path:
            if country in alternatives and alternatives[country]:
                best_alt = alternatives[country][0]
                recommended_path.append(best_alt['country_code'])
            else:
                recommended_path.append(country)

        # Calculate latency estimate (crude: 30ms per hop + geographic penalty)
        latency_estimate = len(traffic_path) * 30 + random.uniform(10, 100)

        route = TrafficRoute(
            route_id=f"route_{uuid.uuid4().hex[:12]}",
            path=traffic_path,
            cumulative_risk=cumulative_risk,
            hop_count=len(traffic_path),
            latency_estimate_ms=latency_estimate,
            legal_justification=(
                'Traffic routed through low-risk jurisdictions with minimal '
                'MLAT cooperation and limited extradition treaties.'
            ),
            mlat_bottleneck_country=min(
                traffic_path,
                key=lambda c: self.JURISDICTIONS.get(c, JurisdictionProfile(
                    country_code=c, country_name=c, risk_score=50,
                    cfaa_equivalent='', data_protection_law='',
                    budapest_signatory=False, mlat_efficiency=1.0,
                    extradition_risk=0.5, export_control_strictness=0.5,
                    active_defense_legal=False, safe_harbor_provisions=False,
                    internet_censorship_level=0.5, vpn_legality=True,
                    data_localization_required=False, surveillance_capability=0.5,
                )).mlat_efficiency,
            ),
        )
        self._traffic_routes.append(route)

        result = {
            'original_path': traffic_path,
            'recommended_path': recommended_path,
            'path_changed': recommended_path != traffic_path,
            'hop_analyses': hop_analyses,
            'alternatives': alternatives,
            'cumulative_risk': cumulative_risk,
            'latency_estimate_ms': latency_estimate,
            'mlat_bottleneck': route.mlat_bottleneck_country,
            'recommendation': (
                'SAFE' if cumulative_risk <= _RISK_SAFE
                else 'CAUTION' if cumulative_risk <= _RISK_CAUTION
                else 'ROUTE DIFFERENTLY'
            ),
            'success': True,
        }

        logger.info(
            f"Traffic routing: {traffic_path} → {recommended_path}, "
            f"risk={cumulative_risk:.0f}"
        )
        return result

    # ── Assess Extradition Risk ─────────────────────────────────────────────

    def assess_extradition_risk(
        self,
        operator_country: str,
        target_country: str,
    ) -> Dict[str, Any]:
        """Assess the risk of extradition between two countries.

        Args:
            operator_country: Where the operator is physically located.
            target_country: Where the target/operation occurred.

        Returns:
            Dict with extradition risk assessment and factors.
        """
        operator = self.JURISDICTIONS.get(
            operator_country.upper(),
            self._custom_jurisdictions.get(operator_country.upper()),
        )
        target = self.JURISDICTIONS.get(
            target_country.upper(),
            self._custom_jurisdictions.get(target_country.upper()),
        )

        if not operator:
            operator = JurisdictionProfile(
                country_code=operator_country.upper(),
                country_name=operator_country.upper(),
                risk_score=50, cfaa_equivalent='Unknown',
                data_protection_law='Unknown', budapest_signatory=False,
                mlat_efficiency=0.5, extradition_risk=0.5,
                export_control_strictness=0.5, active_defense_legal=False,
                safe_harbor_provisions=False, internet_censorship_level=0.5,
                vpn_legality=True, data_localization_required=False,
                surveillance_capability=0.5,
            )
        if not target:
            target = JurisdictionProfile(
                country_code=target_country.upper(),
                country_name=target_country.upper(),
                risk_score=50, cfaa_equivalent='Unknown',
                data_protection_law='Unknown', budapest_signatory=False,
                mlat_efficiency=0.5, extradition_risk=0.5,
                export_control_strictness=0.5, active_defense_legal=False,
                safe_harbor_provisions=False, internet_censorship_level=0.5,
                vpn_legality=True, data_localization_required=False,
                surveillance_capability=0.5,
            )

        # Calculate extradition risk as product of factors
        # High target extradition risk + low operator extradition risk = low actual risk
        base_risk = target.extradition_risk * (1.0 - operator.extradition_risk)

        # MLAT efficiency amplifies the risk (efficient MLAT = more risk)
        mlat_factor = (target.mlat_efficiency + operator.mlat_efficiency) / 2.0
        adjusted_risk = base_risk * (0.5 + mlat_factor * 0.5)

        # Budapest Convention amplifies risk (both signatories = higher risk)
        if target.budapest_signatory and operator.budapest_signatory:
            adjusted_risk *= 1.3

        adjusted_risk = min(adjusted_risk, 1.0)

        result = {
            'operator_country': operator.country_name,
            'target_country': target.country_name,
            'extradition_risk': round(adjusted_risk, 4),
            'risk_level': (
                'LOW' if adjusted_risk < 0.3
                else 'MODERATE' if adjusted_risk < 0.6
                else 'HIGH'
            ),
            'factors': {
                'target_extradition_aggressiveness': target.extradition_risk,
                'operator_extradition_resistance': 1.0 - operator.extradition_risk,
                'mlat_efficiency_combined': round(mlat_factor, 2),
                'budapest_both_signatories': (
                    target.budapest_signatory and operator.budapest_signatory
                ),
            },
            'operator_country_extradition_treaty_with_us': operator.extradition_risk > 0.5,
            'safe_haven_quality': round(1.0 - operator.extradition_risk, 2),
            'success': True,
        }

        logger.info(
            f"Extradition risk: {operator_country}→{target_country} = {adjusted_risk:.2%}"
        )
        return result

    # ── Generate Legal Justification ────────────────────────────────────────

    def generate_legal_justification(
        self,
        action: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Generate a plausible legal justification for an operation.

        Creates a cover narrative using established legal theories
        (security research, penetration testing, bug bounty, etc.)
        tailored to the specific action and jurisdictions involved.

        Args:
            action: The operation/action to justify.
            context: Operation context (target, jurisdiction, etc.).

        Returns:
            Dict with justification narrative and credibility score.
        """
        context = context or {}
        jurisdiction = context.get('jurisdiction', 'US').upper()

        # Find applicable theories
        applicable_theories = []
        for theory in _LEGAL_THEORIES:
            if jurisdiction in theory['best_jurisdictions']:
                applicable_theories.append(theory)

        if not applicable_theories:
            # Fall back to theories that work anywhere
            applicable_theories = [
                t for t in _LEGAL_THEORIES
                if t['theory'] in ('security_research', 'bug_bounty_program')
            ]

        # Select best theory
        selected = max(applicable_theories, key=lambda t: t['credibility'])

        # Fill narrative template
        narrative = selected['narrative_template'].format(
            target=context.get('target', 'target_system'),
            company=context.get('company', 'TargetCorp'),
            ref_number=context.get('ref_number', f'PT-{uuid.uuid4().hex[:8].upper()}'),
            date=context.get('date', '2024-01-15'),
            country=jurisdiction,
            directive_ref=context.get('directive_ref', 'NSD-47'),
            attacker_ip=context.get('attacker_ip', '10.0.0.1'),
            law=context.get('law', 'applicable self-defense doctrine'),
            program_id=context.get('program_id', f'BBP-{random.randint(1000, 9999)}'),
            platform=context.get('platform', 'HackerOne'),
            scope=context.get('scope', '*.targetcorp.com'),
            law_firm=context.get('law_firm', 'CyberLaw Partners LLP'),
        )

        justification = LegalJustification(
            justification_id=f"lj_{uuid.uuid4().hex[:12]}",
            theory=selected['theory'],
            narrative=narrative,
            applicable_jurisdictions=selected['best_jurisdictions'],
            legal_precedent=selected['precedent'],
            credibility_score=selected['credibility'],
            risk_mitigation=selected['credibility'] * 0.7,
        )

        result = {
            'justification_id': justification.justification_id,
            'action': action,
            'theory': justification.theory,
            'narrative': justification.narrative,
            'precedent': justification.legal_precedent,
            'applicable_jurisdictions': justification.applicable_jurisdictions,
            'credibility_score': justification.credibility_score,
            'risk_mitigation_factor': justification.risk_mitigation,
            'suitable_for_court': justification.credibility_score > 0.7,
            'success': True,
        }

        logger.info(
            f"Legal justification generated: theory={justification.theory}, "
            f"credibility={justification.credibility_score:.0%}"
        )
        return result

    # ── Check Export Control ────────────────────────────────────────────────

    def check_export_control(
        self,
        tool_name: str,
        destination_country: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Check if a tool is subject to export controls (Wassenaar/EAR).

        Args:
            tool_name: Name of the tool/software to check.
            destination_country: Destination country for export.

        Returns:
            Dict with export control classification and restrictions.
        """
        tool_info = _EXPORT_CONTROL_DB.get(
            tool_name.lower(),
            {
                'category': 'unknown',
                'wassenaar_controlled': False,
                'ear_classification': 'EAR99',
                'requires_export_license': False,
            },
        )

        destination_risk = 0.0
        if destination_country:
            dest_profile = self.JURISDICTIONS.get(
                destination_country.upper(),
                self._custom_jurisdictions.get(destination_country.upper()),
            )
            if dest_profile:
                destination_risk = dest_profile.export_control_strictness

        # Determine restrictions
        restrictions = []
        if tool_info['wassenaar_controlled']:
            restrictions.append('Wassenaar Arrangement — Intrusion Software')
        if tool_info['requires_export_license']:
            restrictions.append(f"Requires export license ({tool_info['ear_classification']})")
        if destination_risk > 0.7:
            restrictions.append('Destination country has strict import controls')

        is_restricted = len(restrictions) > 0
        risk_level = (
            'HIGH' if is_restricted and destination_risk > 0.5
            else 'MODERATE' if is_restricted
            else 'LOW'
        )

        result = {
            'tool_name': tool_name,
            'category': tool_info['category'],
            'wassenaar_controlled': tool_info['wassenaar_controlled'],
            'ear_classification': tool_info['ear_classification'],
            'requires_export_license': tool_info['requires_export_license'],
            'destination_country': destination_country,
            'destination_import_risk': destination_risk,
            'restrictions': restrictions,
            'is_restricted': is_restricted,
            'risk_level': risk_level,
            'recommendation': (
                'REQUIRES LICENSE — do not export without authorization'
                if is_restricted
                else 'NO RESTRICTIONS — may be exported freely'
            ),
            'success': True,
        }

        logger.info(
            f"Export control check: {tool_name} — "
            f"restricted={is_restricted}, risk={risk_level}"
        )
        return result

    # ── Legacy Wrappers ─────────────────────────────────────────────────────

    def find_optimal_route(
        self,
        target_country: str,
        operation_type: str,
    ) -> List[Dict[str, Any]]:
        """Legacy: return top 5 lowest-risk jurisdictions for routing."""
        analyses = [
            self.analyze_jurisdiction(code, operation_type)
            for code in self.JURISDICTIONS
        ]
        analyses.sort(key=lambda a: a['adjusted_risk_score'])
        return analyses[:5]

    # ── Utility ─────────────────────────────────────────────────────────────

    def add_custom_jurisdiction(
        self,
        profile: JurisdictionProfile,
    ) -> None:
        """Add a custom jurisdiction profile."""
        self._custom_jurisdictions[profile.country_code] = profile
        logger.info(
            f"Custom jurisdiction added: {profile.country_code} ({profile.country_name})"
        )

    def get_all_jurisdictions(self) -> List[Dict[str, Any]]:
        """Return all known jurisdiction profiles."""
        all_jurisdictions = {
            **{k: v for k, v in self.JURISDICTIONS.items()},
            **self._custom_jurisdictions,
        }
        return [
            {'country_code': code, **prof.to_dict()}
            for code, prof in all_jurisdictions.items()
        ]

    def get_safe_havens(self, threshold: float = 30.0) -> List[Dict[str, Any]]:
        """Return jurisdictions below a risk threshold."""
        return [
            {'country_code': code, **prof.to_dict()}
            for code, prof in self.JURISDICTIONS.items()
            if prof.risk_score <= threshold
        ]

    def reset(self) -> None:
        """Clear custom jurisdictions and routes."""
        self._custom_jurisdictions.clear()
        self._traffic_routes.clear()
        logger.debug("LegalGrayZone reset — custom jurisdictions cleared.")
