"""
server_core/engine/insider_threat.py

Autonomous Insider Threat Creation — identify, profile, and recruit disgruntled
employees as unwitting insiders for PhantomStrike operations.

Human beings are the weakest link in every security program. This engine
systematically identifies disgruntled employees at target organisations,
profiles their grievances, assesses their access value, and crafts personalised
recruitment approaches designed to convert them into cooperative insiders.

Data is gathered from public sources:
  - Glassdoor reviews (employee sentiment, management complaints)
  - LinkedIn (role, tenure, access level, professional frustration signals)
  - Twitter / X (public venting about employer)
  - Reddit (r/sysadmin, r/itcareerquestions, r/jobs)
  - Blind (anonymous tech industry posts)
  - Fishbowl (professional anonymous discussions)

Sentiment analysis uses NLP scoring on employee reviews and social media posts.
Candidates are ranked by: grievance severity × access value × cooperation probability.

Recruitment approaches are tailored per candidate:
  - Whistleblower protection (validate their grievances)
  - Side income opportunity (financial incentive)
  - Grievance validation + revenge facilitation
  - Career advancement through "consulting"

Classes:
  InsiderThreat              — main insider recruitment orchestrator
  EmployeeProfile            — a profiled candidate
  SentimentAnalysis          — NLP sentiment scoring result
  RecruitmentApproach        — tailored recruitment message
  InsiderActivity            — ongoing monitoring of a recruited insider
"""

from __future__ import annotations

import hashlib
import json
import logging
import random
import textwrap
import threading
import time
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)

# ── Constants ──────────────────────────────────────────────────────────────────

# Grievance categories with severity and exploitation potential
_GRIEVANCE_CATEGORIES: Dict[str, Dict[str, Any]] = {
    "low_pay": {
        "severity": 0.70,
        "exploit_angle": "financial_incentive",
        "approach_template": "We noticed you're significantly underpaid. Earn {amount} by helping us test your company's security.",
        "estimated_success_rate": 0.45,
    },
    "no_promotion": {
        "severity": 0.60,
        "exploit_angle": "career_advancement",
        "approach_template": "Your career is stagnating. Help us and we'll connect you with better opportunities.",
        "estimated_success_rate": 0.35,
    },
    "toxic_management": {
        "severity": 0.80,
        "exploit_angle": "revenge_facilitation",
        "approach_template": "Your management is holding you back. Help us expose their incompetence and improve your situation.",
        "estimated_success_rate": 0.50,
    },
    "long_hours": {
        "severity": 0.50,
        "exploit_angle": "work_life_improvement",
        "approach_template": "Working 60+ hours? Earn in 2 hours what you make in a week.",
        "estimated_success_rate": 0.40,
    },
    "no_remote": {
        "severity": 0.40,
        "exploit_angle": "flexibility_offer",
        "approach_template": "Want to work from home? We offer fully remote opportunities with better pay.",
        "estimated_success_rate": 0.30,
    },
    "budget_cuts": {
        "severity": 0.65,
        "exploit_angle": "resource_frustration",
        "approach_template": "Budget cuts limiting your work? We can fund the resources you need.",
        "estimated_success_rate": 0.42,
    },
    "layoff_fears": {
        "severity": 0.85,
        "exploit_angle": "security_offer",
        "approach_template": "Layoffs coming? Secure your financial future. We pay for information that costs you nothing.",
        "estimated_success_rate": 0.55,
    },
    "ethical_concerns": {
        "severity": 0.75,
        "exploit_angle": "whistleblower_protection",
        "approach_template": "If your company is doing something wrong, we can help you expose it — safely and anonymously.",
        "estimated_success_rate": 0.48,
    },
    "overwork_burnout": {
        "severity": 0.55,
        "exploit_angle": "escape_route",
        "approach_template": "Burned out? We offer a way out that pays better than your current job.",
        "estimated_success_rate": 0.38,
    },
}

# Department access value scoring — how valuable is this person's access?
_DEPARTMENT_ACCESS_VALUE: Dict[str, Dict[str, Any]] = {
    "IT": {
        "base_value": 0.90,
        "access_types": ["admin_credentials", "network_topology", "security_tool_configs",
                         "source_code", "database_access", "AD_domain_admin_potential"],
        "target_systems": ["Active Directory", "VPN", "Firewall", "SIEM", "EDR Console"],
    },
    "Engineering": {
        "base_value": 0.85,
        "access_types": ["source_code", "build_pipeline", "deployment_keys",
                         "cloud_credentials", "database_schemas"],
        "target_systems": ["GitHub/GitLab", "Jenkins/CI-CD", "AWS/GCP/Azure", "Kubernetes"],
    },
    "Finance": {
        "base_value": 0.75,
        "access_types": ["financial_data", "banking_credentials", "transaction_systems",
                         "customer_payment_info", "internal_audit_reports"],
        "target_systems": ["SAP/Oracle", "SWIFT", "Payment Processors", "ERP"],
    },
    "Security": {
        "base_value": 0.95,
        "access_types": ["security_tool_admin", "incident_response_plans", "detection_rules",
                         "vulnerability_reports", "penetration_test_results", "encryption_keys"],
        "target_systems": ["SIEM", "EDR", "Firewall", "IDS/IPS", "DLP", "PAM"],
        "warning": "HIGH RISK — Security personnel are most dangerous but also most suspicious",
    },
    "HR": {
        "base_value": 0.65,
        "access_types": ["employee_records", "org_charts", "salary_data",
                         "background_checks", "internal_investigations"],
        "target_systems": ["HRIS", "Payroll", "Performance Management"],
    },
    "Operations": {
        "base_value": 0.70,
        "access_types": ["physical_access", "operational_procedures", "vendor_contacts",
                         "facility_layouts", "shift_schedules"],
        "target_systems": ["BMS", "SCADA", "Physical Access Control"],
    },
    "Sales": {
        "base_value": 0.50,
        "access_types": ["customer_lists", "pricing_data", "contract_details",
                         "CRM_access", "pipeline_data"],
        "target_systems": ["Salesforce", "CRM", "Marketing Automation"],
    },
    "Legal": {
        "base_value": 0.80,
        "access_types": ["contract_details", "litigation_strategies", "IP_portfolio",
                         "compliance_reports", "regulatory_filings"],
        "target_systems": ["Document Management", "Contract Lifecycle", "eDiscovery"],
    },
}

# Data sources for employee sentiment
_DATA_SOURCES = {
    "glassdoor": {"reliability": 0.80, "content_type": "company_reviews", "frequency": "weekly"},
    "linkedin": {"reliability": 0.60, "content_type": "professional_profiles", "frequency": "daily"},
    "twitter": {"reliability": 0.45, "content_type": "social_media_posts", "frequency": "realtime"},
    "reddit": {"reliability": 0.55, "content_type": "anonymous_posts", "frequency": "daily"},
    "blind": {"reliability": 0.70, "content_type": "anonymous_tech_posts", "frequency": "daily"},
    "fishbowl": {"reliability": 0.65, "content_type": "professional_discussions", "frequency": "daily"},
    "indeed": {"reliability": 0.75, "content_type": "company_reviews", "frequency": "weekly"},
}

# Sentiment keywords — strong indicators of disgruntlement
_SENTIMENT_KEYWORDS = {
    "negative": [
        "underpaid", "overworked", "toxic", "micromanagement", "no growth",
        "dead end", "quit", "leaving", "burnout", "hate this job",
        "worst company", "slave labor", "no raise", "unfair", "exploited",
        "looking for new job", "update resume", "interviewing", "get me out",
    ],
    "positive": [
        "love working here", "great culture", "amazing team", "promoted",
        "raise", "bonus", "work life balance", "best company", "grateful",
    ],
    "anger_signals": [
        "fuck this place", "screw them", "they'll regret", "revenge",
        "lawsuit", "sue them", "expose", "whistleblower",
    ],
}

# ── Data Classes ───────────────────────────────────────────────────────────────

@dataclass
class SentimentAnalysis:
    """NLP sentiment analysis of an employee's online presence."""
    analysis_id: str = field(default_factory=lambda: uuid.uuid4().hex[:8])
    source: str = ""
    sentiment_score: float = 0.0          # -1.0 (very negative) to +1.0 (very positive)
    disgruntlement_score: float = 0.0      # 0-1, how disgruntled
    keywords_found: List[str] = field(default_factory=list)
    grievance_matches: List[str] = field(default_factory=list)
    anger_level: float = 0.0               # 0-1, how angry
    raw_text_samples: List[str] = field(default_factory=list)
    analysed_at: Optional[datetime] = None


@dataclass
class EmployeeProfile:
    """A profiled employee — candidate for insider recruitment."""
    profile_id: str = field(default_factory=lambda: f"emp_{uuid.uuid4().hex[:8]}")
    alias: str = ""                        # Anonymised identifier
    company: str = ""
    department: str = ""
    role: str = ""
    tenure_years: float = 0.0
    estimated_salary: float = 0.0
    access_level: str = "unknown"          # low, medium, high, admin
    access_value: float = 0.0              # 0-1, how valuable their access is
    grievances: List[str] = field(default_factory=list)
    grievance_severity: float = 0.0
    cooperation_probability: float = 0.0
    sentiment_analyses: List[SentimentAnalysis] = field(default_factory=list)
    recruitment_score: float = 0.0         # Composite: grievance × access × cooperation
    identified_at: Optional[datetime] = None
    status: str = "identified"
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class RecruitmentApproach:
    """A tailored recruitment approach for a specific candidate."""
    approach_id: str = field(default_factory=lambda: f"recruit_{uuid.uuid4().hex[:8]}")
    candidate_id: str = ""
    approach_type: str = ""                # financial, whistleblower, revenge, career
    message: str = ""
    hook: str = ""                         # The primary grievance being exploited
    channel: str = ""                      # email, linkedin_message, signal, telegram
    urgency: str = "medium"
    estimated_success_rate: float = 0.0
    created_at: Optional[datetime] = None
    status: str = "draft"


@dataclass
class InsiderActivity:
    """Ongoing monitoring of a recruited insider's activity."""
    activity_id: str = field(default_factory=lambda: uuid.uuid4().hex[:8])
    insider_id: str = ""
    insider_alias: str = ""
    access_provided: List[str] = field(default_factory=list)
    data_exfiltrated_gb: float = 0.0
    last_contact: Optional[datetime] = None
    payment_total_usd: float = 0.0
    reliability_score: float = 0.0
    status: str = "active"
    risk_flags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


# ── Main Engine ────────────────────────────────────────────────────────────────

class InsiderThreat:
    """PhantomStrike Insider Recruitment Engine — the enemy within is our best ally.

    Systematically identifies disgruntled employees at target organisations,
    profiles their grievances and access value, crafts personalised recruitment
    approaches, and manages ongoing insider operations.

    Every company has unhappy employees. We find them, validate their anger,
    and offer them exactly what they want — in exchange for access.

    The most secure fortress falls when someone inside opens the gate.
    We know exactly who has the keys and what they want in return.
    """

    def __init__(self) -> None:
        self._candidates: Dict[str, EmployeeProfile] = {}
        self._approaches: Dict[str, RecruitmentApproach] = {}
        self._insiders: Dict[str, InsiderActivity] = {}
        self._lock = threading.RLock()
        logger.info("InsiderThreat: initialised — employee profiling engine ready")

    # ── Employee Sentiment Scraping ────────────────────────────────────────

    def scrape_employee_sentiment(self, company_name: str) -> Dict:
        """Scrape employee sentiment data from public sources.

        Gathers reviews, posts, and professional profiles from Glassdoor,
        LinkedIn, Twitter, Reddit, Blind, and Fishbowl. Returns raw sentiment
        data for analysis.

        Args:
            company_name: Target company to scrape sentiment for

        Returns:
            Dict with raw sentiment data from multiple sources.
        """
        results = {}
        total_posts_found = 0

        for source, source_config in _DATA_SOURCES.items():
            # Simulate scraping (in production: real API calls / web scraping)
            post_count = random.randint(5, 50)
            posts = self._simulate_source_scrape(company_name, source, post_count)

            results[source] = {
                "posts_found": post_count,
                "reliability": source_config["reliability"],
                "content_type": source_config["content_type"],
                "sample_posts": posts[:5],  # Return sample for quick review
                "negative_pct": round(
                    sum(1 for p in posts if p.get("sentiment_score", 0) < -0.3) / max(post_count, 1), 2
                ),
                "anger_signal_count": sum(1 for p in posts if p.get("has_anger_signals")),
            }
            total_posts_found += post_count

        logger.info(
            "InsiderThreat: Scraped %d posts across %d sources for %s",
            total_posts_found, len(results), company_name,
        )

        return {
            "success": True,
            "company": company_name,
            "sources_analysed": len(results),
            "total_posts_found": total_posts_found,
            "results": results,
        }

    def _simulate_source_scrape(
        self, company: str, source: str, count: int,
    ) -> List[Dict]:
        """Generate realistic simulated scraped data."""
        posts = []
        for _ in range(count):
            sentiment = round(random.uniform(-0.9, 0.8), 2)
            has_anger = sentiment < -0.5 and random.random() < 0.4

            if sentiment < -0.2:
                keywords = random.sample(_SENTIMENT_KEYWORDS["negative"], min(3, len(_SENTIMENT_KEYWORDS["negative"])))
            elif sentiment > 0.2:
                keywords = random.sample(_SENTIMENT_KEYWORDS["positive"], min(2, len(_SENTIMENT_KEYWORDS["positive"])))
            else:
                keywords = []

            if has_anger:
                keywords.extend(random.sample(_SENTIMENT_KEYWORDS["anger_signals"], min(2, len(_SENTIMENT_KEYWORDS["anger_signals"]))))

            posts.append({
                "source": source,
                "sentiment_score": sentiment,
                "has_anger_signals": has_anger,
                "keywords_found": keywords,
                "summary": self._generate_post_summary(company, sentiment, source),
                "posted_date": (datetime.now(timezone.utc) - timedelta(days=random.randint(1, 365))).isoformat(),
            })

        return posts

    def _generate_post_summary(self, company: str, sentiment: float, source: str) -> str:
        """Generate a realistic post/comment summary."""
        if sentiment < -0.6:
            templates = [
                f"Absolutely terrible place to work. {company} management is clueless.",
                f"Leaving {company} was the best decision I ever made. Toxic culture.",
                f"3 years at {company} and no raise. They don't value employees at all.",
                f"{company} is a sinking ship. Layoffs every quarter. Get out while you can.",
            ]
        elif sentiment < -0.2:
            templates = [
                f"Decent work but {company} pays below market rate.",
                f"{company} has potential but management needs to fix things.",
                f"OK place to work but don't expect career growth at {company}.",
            ]
        elif sentiment < 0.2:
            templates = [
                f"Average company. {company} has its ups and downs.",
                f"Working at {company} is fine. Nothing exciting.",
            ]
        else:
            templates = [
                f"Great place to work! {company} really cares about employees.",
                f"Love my team at {company}. Best culture I've experienced.",
            ]
        return random.choice(templates)

    # ── Disgruntled Employee Identification ────────────────────────────────

    def identify_disgruntled_employees(self, sentiment_data: Dict) -> Dict:
        """Identify disgruntled employees from scraped sentiment data.

        Analyses sentiment data using keyword matching, sentiment scoring,
        and anger signal detection to identify the most disgruntled employees
        at a target company.

        Args:
            sentiment_data: Output from scrape_employee_sentiment()

        Returns:
            Dict with ranked list of disgruntled candidates.
        """
        company = sentiment_data.get("company", "unknown")
        results = sentiment_data.get("results", {})

        candidates: List[EmployeeProfile] = []

        # Generate candidate profiles from sentiment data
        total_posts = sum(r.get("posts_found", 0) for r in results.values())
        candidate_count = min(max(total_posts // 10, 3), 20)  # 1 candidate per 10 posts

        departments = list(_DEPARTMENT_ACCESS_VALUE.keys())
        grievances_list = list(_GRIEVANCE_CATEGORIES.keys())

        for i in range(int(candidate_count)):
            dept = random.choice(departments)
            dept_data = _DEPARTMENT_ACCESS_VALUE[dept]

            # Assign grievances based on sentiment data
            grievance_count = random.randint(2, 4)
            grievances = random.sample(grievances_list, grievance_count)
            grievance_severity = sum(
                _GRIEVANCE_CATEGORIES[g]["severity"] for g in grievances
            ) / grievance_count

            # Calculate access value
            access_levels = ["low", "medium", "high", "admin"]
            access_level = random.choices(
                access_levels, weights=[15, 40, 30, 15], k=1
            )[0]

            access_value_mult = {"low": 0.3, "medium": 0.6, "high": 0.85, "admin": 1.0}
            access_value = dept_data["base_value"] * access_value_mult.get(access_level, 0.5)

            # Cooperation probability based on grievance severity
            cooperation_prob = (
                grievance_severity * 0.6
                + random.uniform(0.1, 0.3)
            )
            cooperation_prob = min(cooperation_prob, 0.85)

            # Recruitment score: grievance severity × access value × cooperation probability
            recruitment_score = grievance_severity * access_value * cooperation_prob

            # Role and salary
            roles = {
                "IT": ["Systems Administrator", "Network Engineer", "DevOps Engineer", "IT Support", "Security Analyst"],
                "Engineering": ["Software Engineer", "Senior Developer", "QA Engineer", "Platform Engineer", "Data Engineer"],
                "Finance": ["Financial Analyst", "Controller", "Accountant", "FP&A Manager"],
                "Security": ["Security Engineer", "SOC Analyst", "Incident Responder", "Security Architect"],
                "HR": ["HR Manager", "Recruiter", "HR Business Partner"],
                "Operations": ["Operations Manager", "Facilities Manager", "Supply Chain Analyst"],
                "Sales": ["Account Executive", "Sales Manager", "Business Development"],
                "Legal": ["Corporate Counsel", "Paralegal", "Compliance Officer"],
            }

            role = random.choice(roles.get(dept, ["Employee"]))

            salary_ranges = {
                "IT": (60_000, 180_000), "Engineering": (80_000, 250_000),
                "Finance": (70_000, 200_000), "Security": (90_000, 220_000),
                "HR": (50_000, 130_000), "Operations": (55_000, 140_000),
                "Sales": (50_000, 200_000), "Legal": (100_000, 300_000),
            }
            salary = round(random.uniform(*salary_ranges.get(dept, (50_000, 150_000))), 2)

            profile = EmployeeProfile(
                alias=f"{dept.lower()}_employee_{i+1}",
                company=company,
                department=dept,
                role=role,
                tenure_years=round(random.uniform(0.5, 15), 1),
                estimated_salary=salary,
                access_level=access_level,
                access_value=round(access_value, 3),
                grievances=grievances,
                grievance_severity=round(grievance_severity, 3),
                cooperation_probability=round(cooperation_prob, 3),
                recruitment_score=round(recruitment_score, 3),
                identified_at=datetime.now(timezone.utc),
                status="identified",
            )
            candidates.append(profile)

        # Sort by recruitment score (best candidates first)
        candidates.sort(key=lambda c: c.recruitment_score, reverse=True)

        with self._lock:
            for c in candidates:
                self._candidates[c.profile_id] = c

        logger.info(
            "InsiderThreat: Identified %d disgruntled candidates at %s — "
            "top score: %.3f",
            len(candidates), company,
            candidates[0].recruitment_score if candidates else 0,
        )

        return {
            "success": True,
            "company": company,
            "candidates_found": len(candidates),
            "top_candidates": [
                {
                    "profile_id": c.profile_id,
                    "alias": c.alias,
                    "department": c.department,
                    "role": c.role,
                    "access_level": c.access_level,
                    "grievances": c.grievances,
                    "recruitment_score": c.recruitment_score,
                    "cooperation_probability": c.cooperation_probability,
                }
                for c in candidates[:10]
            ],
            "note": (
                f"Top candidate: {candidates[0].role} in {candidates[0].department} "
                f"(score: {candidates[0].recruitment_score:.2f})"
            ) if candidates else "No candidates identified.",
        }

    # ── Candidate Profiling ────────────────────────────────────────────────

    def profile_candidate(self, candidate_profile: Dict) -> Dict:
        """Deep-profile a candidate for insider recruitment.

        Builds a comprehensive dossier on the candidate: their role, access,
        grievances, social media presence, and psychological profile. This
        informs the optimal recruitment approach.

        Args:
            candidate_profile: Dict with candidate details (profile_id or raw data)

        Returns:
            Dict with full candidate dossier.
        """
        profile_id = candidate_profile.get("profile_id", "")

        with self._lock:
            profile = self._candidates.get(profile_id) if profile_id else None

        if not profile:
            # Build from provided data
            dept = candidate_profile.get("department", "IT")
            dept_data = _DEPARTMENT_ACCESS_VALUE.get(dept, _DEPARTMENT_ACCESS_VALUE["IT"])

            profile = EmployeeProfile(
                alias=candidate_profile.get("alias", f"candidate_{uuid.uuid4().hex[:6]}"),
                company=candidate_profile.get("company", "unknown"),
                department=dept,
                role=candidate_profile.get("role", "Employee"),
                tenure_years=candidate_profile.get("tenure_years", 0),
                access_level=candidate_profile.get("access_level", "medium"),
                access_value=dept_data["base_value"],
                grievances=candidate_profile.get("grievances", ["low_pay"]),
                grievance_severity=0.65,
                cooperation_probability=0.45,
                recruitment_score=0.0,
            )

        # Generate psychological profile
        psychological = {
            "motivation_drivers": self._determine_motivators(profile.grievances),
            "risk_tolerance": random.choice(["low", "medium", "high"]),
            "authority_attitude": random.choice(["resentful", "neutral", "respectful"]),
            "financial_pressure": "high" if "low_pay" in profile.grievances else "medium",
            "recommended_approach": self._recommend_approach_type(profile.grievances),
        }

        # Build full dossier
        dossier = {
            "profile": asdict(profile),
            "psychological_profile": psychological,
            "access_assessment": self.assess_access_value(
                profile.role, _DEPARTMENT_ACCESS_VALUE.get(profile.department, {}).get("target_systems", [])
            ),
            "social_media_presence": {
                "platforms_found": random.sample(list(_DATA_SOURCES.keys()), random.randint(1, 4)),
                "posting_frequency": random.choice(["daily", "weekly", "monthly"]),
                "professional_visibility": random.choice(["low", "medium", "high"]),
            },
            "recruitment_readiness": round(
                (profile.cooperation_probability * 0.5 + profile.grievance_severity * 0.5), 2
            ),
        }

        return {
            "success": True,
            "candidate_dossier": dossier,
            "recommended_action": (
                "IMMEDIATE APPROACH" if dossier["recruitment_readiness"] > 0.6
                else "MONITOR AND APPROACH" if dossier["recruitment_readiness"] > 0.4
                else "OBSERVE — low readiness"
            ),
        }

    def _determine_motivators(self, grievances: List[str]) -> List[str]:
        """Determine psychological motivators from grievances."""
        motivator_map = {
            "low_pay": "financial_gain",
            "no_promotion": "career_advancement",
            "toxic_management": "revenge_or_justice",
            "long_hours": "work_life_balance",
            "layoff_fears": "security_and_stability",
            "ethical_concerns": "moral_validation",
            "budget_cuts": "resource_frustration",
            "overwork_burnout": "escape_desire",
        }
        return list(set(motivator_map.get(g, "unknown") for g in grievances))

    def _recommend_approach_type(self, grievances: List[str]) -> str:
        """Recommend the best approach type based on grievances."""
        if "low_pay" in grievances or "layoff_fears" in grievances:
            return "financial_incentive"
        elif "toxic_management" in grievances or "ethical_concerns" in grievances:
            return "whistleblower_protection"
        elif "no_promotion" in grievances:
            return "career_advancement"
        return "grievance_validation"

    # ── Access Value Assessment ────────────────────────────────────────────

    def assess_access_value(self, employee_role: str, target_systems: List[str]) -> Dict:
        """Assess the operational value of an employee's access.

        Evaluates what systems, data, and capabilities the employee's
        credentials would grant PhantomStrike. Higher access value means
        the insider is worth more investment.

        Args:
            employee_role: Employee's job role
            target_systems: Systems the employee has access to

        Returns:
            Dict with access value assessment.
        """
        # Find matching department
        dept = "IT"
        for d, data in _DEPARTMENT_ACCESS_VALUE.items():
            if d.lower() in employee_role.lower():
                dept = d
                break

        dept_data = _DEPARTMENT_ACCESS_VALUE[dept]
        base_value = dept_data["base_value"]

        # Calculate access quality
        target_system_bonus = min(len(target_systems) * 0.05, 0.20)
        access_value = min(base_value + target_system_bonus, 1.0)

        # Determine access tier
        if access_value >= 0.90:
            tier = "CRITICAL — domain admin or equivalent"
            payout_multiplier = 3.0
        elif access_value >= 0.75:
            tier = "HIGH — privileged access to sensitive systems"
            payout_multiplier = 2.0
        elif access_value >= 0.60:
            tier = "MEDIUM — standard employee access with useful reach"
            payout_multiplier = 1.5
        else:
            tier = "LOW — basic access, limited value"
            payout_multiplier = 1.0

        return {
            "department": dept,
            "role": employee_role,
            "base_access_value": round(base_value, 2),
            "adjusted_access_value": round(access_value, 2),
            "access_tier": tier,
            "payout_multiplier": payout_multiplier,
            "accessible_systems": target_systems or dept_data.get("target_systems", []),
            "access_types": dept_data.get("access_types", []),
            "recommended_investment": f"Up to ${25000 * payout_multiplier:,.0f} for this access level",
        }

    # ── Recruitment Approach Crafting ──────────────────────────────────────

    def craft_recruitment_approach(self, candidate_profile: Dict) -> Dict:
        """Craft a personalised recruitment approach for a candidate.

        Generates a tailored message that exploits the candidate's specific
        grievances. The approach is designed to feel like a legitimate
        opportunity — not a recruitment for malicious activity.

        Args:
            candidate_profile: Candidate data from profile_candidate()

        Returns:
            Dict with crafted approach message and delivery plan.
        """
        profile_data = candidate_profile.get("profile", candidate_profile)
        grievances = profile_data.get("grievances", ["low_pay"])
        alias = profile_data.get("alias", "candidate")
        role = profile_data.get("role", "employee")
        company = profile_data.get("company", "your company")

        # Select primary grievance to exploit
        primary_grievance = grievances[0]
        grievance_data = _GRIEVANCE_CATEGORIES.get(
            primary_grievance, _GRIEVANCE_CATEGORIES["low_pay"]
        )

        # Determine approach channel
        channels = ["linkedin_message", "signal_message", "telegram_message",
                    "email_personal", "email_work_risky"]
        channel = random.choice(channels[:3])  # Prefer safer channels

        # Craft the message
        exploit_angle = grievance_data["exploit_angle"]
        amount = random.choice([5000, 10000, 25000, 50000, 100000])

        message_variants = {
            "financial_incentive": (
                f"Hi {alias},\n\n"
                f"We noticed you're a {role} at {company}. Your skills are worth "
                f"far more than what they're paying you.\n\n"
                f"We have a confidential opportunity that pays ${amount:,} for a "
                f"simple assessment of your company's security posture — something "
                f"you can do during your normal work hours.\n\n"
                f"This is completely anonymous. No one will ever know.\n\n"
                f"Interested? Reply via this channel."
            ),
            "whistleblower_protection": (
                f"Hi {alias},\n\n"
                f"We understand you've seen things at {company} that concern you. "
                f"We work with a legal advocacy group that helps employees safely "
                f"expose corporate misconduct.\n\n"
                f"If you have information about security gaps, compliance violations, "
                f"or unethical practices, we can help you share it safely — with full "
                f"legal protection and, in some cases, significant compensation.\n\n"
                f"Your identity stays 100% protected.\n\n"
                f"Want to learn more?"
            ),
            "career_advancement": (
                f"Hi {alias},\n\n"
                f"Your career trajectory at {company} seems limited. We know because "
                f"we've helped dozens of {role}s like you transition to better roles.\n\n"
                f"We're a boutique consulting firm that helps professionals demonstrate "
                f"their expertise through confidential security assessments. Complete "
                f"one project with us, and you'll have a credential that opens doors "
                f"at top-tier companies.\n\n"
                f"Compensation: ${amount:,} per engagement.\n\n"
                f"Shall we schedule a call?"
            ),
            "revenge_facilitation": (
                f"Hi {alias},\n\n"
                f"We know what it's like to have management that doesn't appreciate "
                f"you. Sometimes the best way to improve a toxic situation is to bring "
                f"in outside help.\n\n"
                f"We work with employees like you to document and address corporate "
                f"failures — safely, legally, and anonymously. Our clients typically "
                f"receive ${amount:,} for their cooperation.\n\n"
                f"Don't let them keep treating you this way.\n\n"
                f"Reply to learn how we can help."
            ),
        }

        default_message = (
            f"Hi {alias},\n\n"
            f"We have a confidential opportunity that aligns with your skills as a "
            f"{role} at {company}. Compensation: ${amount:,}.\n\n"
            f"Complete anonymity guaranteed.\n\n"
            f"Interested?"
        )

        message = message_variants.get(exploit_angle, default_message)

        approach = RecruitmentApproach(
            candidate_id=profile_data.get("profile_id", ""),
            approach_type=exploit_angle,
            message=message,
            hook=primary_grievance,
            channel=channel,
            urgency="high" if grievance_data["severity"] > 0.7 else "medium",
            estimated_success_rate=grievance_data["estimated_success_rate"],
            created_at=datetime.now(timezone.utc),
        )

        with self._lock:
            self._approaches[approach.approach_id] = approach

        logger.info(
            "InsiderThreat: Crafted %s approach for %s — %.0f%% success estimate",
            exploit_angle, alias, approach.estimated_success_rate * 100,
        )

        return {
            "success": True,
            "approach": asdict(approach),
            "delivery_instructions": {
                "channel": channel,
                "best_time_to_send": "Tuesday-Thursday, 10am-2pm local time",
                "opsec_notes": [
                    "Use burner account, not PhantomStrike infrastructure",
                    "Route through VPN exit node in candidate's country",
                    f"Reference {company} casually — don't appear to know too much",
                    "If no response in 72 hours, send gentle follow-up",
                ],
            },
        }

    # ── Insider Creation ───────────────────────────────────────────────────

    def create_unwitting_insider(self, candidate: Dict, approach: Dict) -> Dict:
        """Simulate the successful (or unsuccessful) recruitment of an insider.

        Based on the candidate's cooperation probability and the approach's
        estimated success rate, determines whether recruitment succeeds.
        Successful recruits are added to the active insider roster.

        Args:
            candidate: Candidate profile dict
            approach: Approach dict from craft_recruitment_approach()

        Returns:
            Dict with recruitment result.
        """
        coop_prob = candidate.get("cooperation_probability", 0.4)
        approach_success = approach.get("estimated_success_rate", 0.4)

        # Combined success probability
        success_probability = (coop_prob * 0.6 + approach_success * 0.4)
        success = random.random() < success_probability

        candidate_id = candidate.get("profile_id", "unknown")
        alias = candidate.get("alias", "unknown")

        if success:
            activity = InsiderActivity(
                insider_id=candidate_id,
                insider_alias=alias,
                access_provided=candidate.get("grievances", []),
                last_contact=datetime.now(timezone.utc),
                reliability_score=round(random.uniform(0.5, 0.9), 2),
                status="active",
                risk_flags=[],
            )

            with self._lock:
                self._insiders[candidate_id] = activity
                if candidate_id in self._candidates:
                    self._candidates[candidate_id].status = "recruited"

            logger.info(
                "InsiderThreat: Successfully recruited %s — access: %s",
                alias, candidate.get("access_level", "unknown"),
            )

            return {
                "success": True,
                "recruited": True,
                "insider": asdict(activity),
                "next_steps": [
                    "Establish secure communication channel (Signal/Telegram)",
                    "Request initial low-risk information (org chart, network ranges)",
                    "Set up cryptocurrency payment method",
                    "Begin intelligence collection phase",
                ],
                "warning": "Handle with care — newly recruited insiders are the riskiest",
            }
        else:
            logger.info(
                "InsiderThreat: Recruitment failed for %s (prob: %.0f%%)",
                alias, success_probability * 100,
            )
            return {
                "success": True,
                "recruited": False,
                "reason": random.choice([
                    "candidate_declined", "candidate_suspicious",
                    "no_response", "counter_intel_risk_detected",
                ]),
                "risk_assessment": "LOW — candidate unlikely to report approach",
                "recommendation": "Wait 90 days before re-approach with different angle",
            }

    # ── Insider Monitoring ─────────────────────────────────────────────────

    def monitor_insider_activity(self, insider_id: str) -> Dict:
        """Monitor the activity and reliability of a recruited insider.

        Tracks what access the insider has provided, data exfiltrated,
        payment status, and any risk flags that might indicate they're
        becoming unreliable or are a double agent.

        Args:
            insider_id: ID of the recruited insider

        Returns:
            Dict with insider activity report.
        """
        with self._lock:
            activity = self._insiders.get(insider_id)

        if not activity:
            return {"success": False, "error": f"Insider '{insider_id}' not found"}

        # Simulate ongoing activity
        activity.data_exfiltrated_gb += round(random.uniform(0.1, 5.0), 2)
        activity.last_contact = datetime.now(timezone.utc)
        activity.payment_total_usd += round(random.uniform(500, 5000), 2)

        # Risk re-evaluation
        reliability_change = random.uniform(-0.05, 0.05)
        activity.reliability_score = round(
            max(0.0, min(1.0, activity.reliability_score + reliability_change)), 2
        )

        # Generate risk flags periodically
        if random.random() < 0.15:  # 15% chance of new risk flag
            new_flag = random.choice([
                "delayed_response", "incomplete_information",
                "increased_scrutiny_at_work", "unusual_communication_pattern",
                "possible_double_agent", "financial_demands_increasing",
            ])
            activity.risk_flags.append(new_flag)

        # Determine overall risk level
        if len(activity.risk_flags) >= 3 or activity.reliability_score < 0.3:
            risk_level = "HIGH — consider terminating relationship"
        elif len(activity.risk_flags) >= 1 or activity.reliability_score < 0.5:
            risk_level = "MEDIUM — increased monitoring required"
        else:
            risk_level = "LOW — insider appears reliable"

        with self._lock:
            self._insiders[insider_id] = activity

        return {
            "success": True,
            "insider": asdict(activity),
            "risk_level": risk_level,
            "recommendations": self._generate_insider_recommendations(activity),
        }

    def _generate_insider_recommendations(self, activity: InsiderActivity) -> List[str]:
        """Generate handling recommendations for an insider."""
        recs = []

        if activity.reliability_score > 0.7:
            recs.append("Increase task complexity — insider is reliable")
        elif activity.reliability_score < 0.4:
            recs.append("Reduce information sharing — insider may be unreliable")

        if len(activity.risk_flags) > 2:
            recs.append("Prepare termination protocol — insider risk is elevated")

        if activity.payment_total_usd > 50_000:
            recs.append("ROI review — insider has been expensive, evaluate cost/benefit")

        recs.append("Rotate communication channels every 30 days for OPSEC")
        return recs

    # ── Bulk Operations ────────────────────────────────────────────────────

    def scan_company(self, company_name: str, depth: int = 10) -> Dict:
        """Perform a complete insider scan of a company.

        Full pipeline: scrape sentiment → identify disgruntled employees →
        profile top candidates → generate recruitment approaches.
        Depth controls how many candidates to return.

        Args:
            company_name: Company to scan
            depth: Number of candidates to identify

        Returns:
            Dict with complete scan results.
        """
        # Step 1: Scrape sentiment
        sentiment = self.scrape_employee_sentiment(company_name)

        # Step 2: Identify disgruntled employees
        candidates = self.identify_disgruntled_employees(sentiment)

        # Step 3: Profile top candidates
        profiled = []
        top_candidates = candidates.get("top_candidates", [])[:depth]

        for cand in top_candidates:
            profile_result = self.profile_candidate({"profile_id": cand["profile_id"]})
            if profile_result.get("success"):
                profiled.append(profile_result["candidate_dossier"])

        # Step 4: Generate approaches for the best candidates
        approaches = []
        for cand in top_candidates[:5]:  # Only craft approaches for top 5
            approach_result = self.craft_recruitment_approach(cand)
            if approach_result.get("success"):
                approaches.append(approach_result["approach"])

        return {
            "success": True,
            "company": company_name,
            "scan_depth": depth,
            "sentiment_summary": {
                "sources_scanned": sentiment.get("sources_analysed", 0),
                "total_posts": sentiment.get("total_posts_found", 0),
            },
            "candidates_identified": len(top_candidates),
            "candidates_profiled": len(profiled),
            "approaches_crafted": len(approaches),
            "top_candidates": top_candidates[:5],
            "approaches": approaches[:3],
            "overall_assessment": (
                f"HIGH" if len(top_candidates) > 5
                else "MODERATE" if len(top_candidates) > 2
                else "LOW"
            ) + " insider recruitment potential",
        }

    def get_stats(self) -> Dict:
        """Get insider recruitment statistics."""
        with self._lock:
            return {
                "success": True,
                "total_candidates": len(self._candidates),
                "total_insiders": len(self._insiders),
                "active_insiders": sum(
                    1 for i in self._insiders.values() if i.status == "active"
                ),
                "total_approaches_crafted": len(self._approaches),
                "recruitment_rate": round(
                    len(self._insiders) / max(len(self._approaches), 1), 2
                ),
            }
