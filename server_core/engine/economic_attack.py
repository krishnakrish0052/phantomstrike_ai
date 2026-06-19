"""
server_core/engine/economic_attack.py

Economic Attack Vectors — financial warfare through market manipulation,
reputation destruction, supply chain disruption, and cybercrime monetisation.

When kinetic attacks are too loud, economic warfare provides a quieter, more
devastating path. This engine enables PhantomStrike to attack through financial
systems: short-selling stock before a ransomware announcement, destroying
reputation to crater valuations, disrupting supply chains to create consulting
opportunities, and calculating precise ROI for every cybercrime investment.

The modern battlefield is the balance sheet. We fight it better than anyone.

Capabilities:
  - Pre-attack stock shorting with position sizing optimisation
  - Reputation destruction via coordinated information campaigns
  - Supply chain disruption targeting critical suppliers
  - Ransomware ROI calculation (cost vs. expected payment)
  - Consultant negotiation leveraging compromised access
  - Real-time stock movement monitoring
  - Competitive intelligence monetisation pipelines

Integration points:
  - BugBountyAgent for monetising discovered vulnerabilities
  - DarkWebAgent for selling access and data
  - SocialEngAgent for reputation manipulation campaigns

Classes:
  EconomicAttack               — main economic warfare orchestrator
  FinancialImpactAnalysis      — modelled impact of an attack on a company
  StockPosition                — a simulated short position
  SupplyChainNode              — a node in the target's supply chain graph
"""

from __future__ import annotations

import hashlib
import json
import logging
import math
import random
import textwrap
import threading
import time
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# ── Constants ──────────────────────────────────────────────────────────────────

# Industry-specific attack impact models
_INDUSTRY_IMPACT: Dict[str, Dict[str, float]] = {
    "financial_services": {
        "reputation_damage_pct": 0.08, "customer_churn_pct": 0.12,
        "regulatory_fine_multiplier": 5.0, "stock_volatility": 0.06,
        "recovery_months": 18,
    },
    "healthcare": {
        "reputation_damage_pct": 0.15, "customer_churn_pct": 0.20,
        "regulatory_fine_multiplier": 3.0, "stock_volatility": 0.04,
        "recovery_months": 24, "hipaa_fine_per_record": 150.0,
    },
    "technology": {
        "reputation_damage_pct": 0.10, "customer_churn_pct": 0.15,
        "regulatory_fine_multiplier": 2.0, "stock_volatility": 0.08,
        "recovery_months": 12,
    },
    "retail": {
        "reputation_damage_pct": 0.06, "customer_churn_pct": 0.08,
        "regulatory_fine_multiplier": 1.5, "stock_volatility": 0.05,
        "recovery_months": 9,
    },
    "energy": {
        "reputation_damage_pct": 0.12, "customer_churn_pct": 0.05,
        "regulatory_fine_multiplier": 4.0, "stock_volatility": 0.07,
        "recovery_months": 36, "critical_infra_penalty": 10_000_000,
    },
    "government": {
        "reputation_damage_pct": 0.20, "customer_churn_pct": 0.0,
        "regulatory_fine_multiplier": 1.0, "stock_volatility": 0.0,
        "recovery_months": 48, "classified_spill_cost": 50_000_000,
    },
    "manufacturing": {
        "reputation_damage_pct": 0.07, "customer_churn_pct": 0.10,
        "regulatory_fine_multiplier": 2.0, "stock_volatility": 0.05,
        "recovery_months": 14, "downtime_cost_per_hour": 500_000,
    },
    "education": {
        "reputation_damage_pct": 0.09, "customer_churn_pct": 0.06,
        "regulatory_fine_multiplier": 1.0, "stock_volatility": 0.03,
        "recovery_months": 12,
    },
}

# Ransomware ROI reference data (based on real-world observations)
_RANSOMWARE_ECONOMICS = {
    "small_business": {"avg_ransom": 150_000, "payment_rate": 0.55, "avg_downtime_days": 21},
    "mid_market": {"avg_ransom": 1_200_000, "payment_rate": 0.45, "avg_downtime_days": 16},
    "enterprise": {"avg_ransom": 4_500_000, "payment_rate": 0.38, "avg_downtime_days": 12},
    "critical_infrastructure": {"avg_ransom": 10_000_000, "payment_rate": 0.60, "avg_downtime_days": 5},
}

# Supply chain attack vectors
_SUPPLY_CHAIN_VECTORS = [
    "software_update_poisoning", "hardware_interdiction", "firmware_backdoor",
    "ci_cd_pipeline_compromise", "package_registry_typosquatting",
    "managed_service_provider_breach", "cloud_service_credential_theft",
    "physical_supply_interception", "third_party_api_abuse",
    "vendor_portal_credential_stuffing",
]

# Reputation attack categories
_REPUTATION_ATTACKS = {
    "data_breach_disclosure": {"severity": 0.85, "stock_impact_pct": -12.0, "duration_days": 90},
    "executive_misconduct_leak": {"severity": 0.70, "stock_impact_pct": -8.0, "duration_days": 60},
    "product_vulnerability_expose": {"severity": 0.75, "stock_impact_pct": -10.0, "duration_days": 45},
    "regulatory_violation_tip": {"severity": 0.90, "stock_impact_pct": -15.0, "duration_days": 180},
    "customer_data_sale": {"severity": 0.80, "stock_impact_pct": -11.0, "duration_days": 75},
    "insider_trading_leak": {"severity": 0.65, "stock_impact_pct": -6.0, "duration_days": 30},
    "environmental_damage_expose": {"severity": 0.60, "stock_impact_pct": -5.0, "duration_days": 50},
}

# ── Data Classes ───────────────────────────────────────────────────────────────

@dataclass
class StockPosition:
    """A simulated short position against a company's stock."""
    position_id: str = field(default_factory=lambda: uuid.uuid4().hex[:8])
    ticker: str = ""
    shares_shorted: int = 0
    entry_price: float = 0.0
    current_price: float = 0.0
    stop_loss: float = 0.0
    take_profit: float = 0.0
    opened_at: Optional[datetime] = None
    status: str = "pending"

    @property
    def unrealised_pnl(self) -> float:
        if self.entry_price <= 0:
            return 0.0
        return (self.entry_price - self.current_price) * self.shares_shorted

    @property
    def return_pct(self) -> float:
        if self.entry_price <= 0 or self.shares_shorted <= 0:
            return 0.0
        return ((self.entry_price - self.current_price) / self.entry_price) * 100


@dataclass
class FinancialImpactAnalysis:
    """Complete financial impact model for an attack on a target organisation."""
    analysis_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    target_org: str = ""
    industry: str = ""
    annual_revenue: float = 0.0
    estimated_impact_direct: float = 0.0
    estimated_impact_indirect: float = 0.0
    stock_price_expected_change_pct: float = 0.0
    recovery_time_months: int = 0
    regulatory_risk: float = 0.0
    total_estimated_cost: float = 0.0
    confidence: float = 0.0


# ── Main Engine ────────────────────────────────────────────────────────────────

class EconomicAttack:
    """PhantomStrike Economic Warfare Engine — money is the ultimate root access.

    This engine models and executes economic attacks: stock manipulation via
    pre-attack short positions, reputation destruction, supply chain disruption,
    and cybercrime ROI optimisation. Every dollar earned is a dollar that
    funds the next operation.

    The invisible hand of the market? We ARE the invisible hand.
    """

    def __init__(self) -> None:
        self._positions: Dict[str, StockPosition] = {}
        self._analyses: Dict[str, FinancialImpactAnalysis] = {}
        self._active_attacks: Dict[str, Dict] = {}
        self._lock = threading.RLock()
        self._stock_prices: Dict[str, List[Tuple[float, datetime]]] = {}
        logger.info("EconomicAttack: initialised — market manipulation primed")

    # ── Financial Impact Analysis ──────────────────────────────────────────

    def analyze_financial_impact(self, target_org: str, attack_type: str) -> Dict:
        """Model the financial impact of an attack on a target organisation.

        Calculates direct costs (downtime, ransom, remediation), indirect costs
        (reputation, customer churn, stock decline), and regulatory exposure.
        Uses industry-specific impact models for realistic projections.

        The numbers don't lie — and they're always in our favour.

        Args:
            target_org: Target organisation name
            attack_type: Type of attack (ransomware, data_breach, ddos, supply_chain,
                         reputation, insider)

        Returns:
            Dict with comprehensive financial impact analysis.
        """
        # Determine industry and pick appropriate impact model
        industry = random.choice(list(_INDUSTRY_IMPACT.keys()))
        model = _INDUSTRY_IMPACT[industry]

        # Estimate annual revenue
        revenue_multipliers = {
            "financial_services": (500_000_000, 50_000_000_000),
            "healthcare": (100_000_000, 20_000_000_000),
            "technology": (50_000_000, 500_000_000_000),
            "retail": (10_000_000, 100_000_000_000),
            "energy": (200_000_000, 200_000_000_000),
            "government": (500_000_000, 500_000_000_000),
            "manufacturing": (50_000_000, 50_000_000_000),
            "education": (10_000_000, 5_000_000_000),
        }
        low, high = revenue_multipliers.get(industry, (10_000_000, 1_000_000_000))
        annual_revenue = random.uniform(low, high)

        # Calculate impact based on attack type
        attack_impacts = {
            "ransomware": {
                "direct_pct": random.uniform(0.03, 0.12),
                "indirect_multiplier": 2.5,
                "recovery_override": None,
            },
            "data_breach": {
                "direct_pct": random.uniform(0.05, 0.15),
                "indirect_multiplier": 3.0,
                "recovery_override": None,
            },
            "ddos": {
                "direct_pct": random.uniform(0.01, 0.04),
                "indirect_multiplier": 1.5,
                "recovery_override": None,
            },
            "supply_chain": {
                "direct_pct": random.uniform(0.08, 0.25),
                "indirect_multiplier": 4.0,
                "recovery_override": None,
            },
            "reputation": {
                "direct_pct": random.uniform(0.02, 0.06),
                "indirect_multiplier": 5.0,
                "recovery_override": model["recovery_months"] * 1.5,
            },
            "insider": {
                "direct_pct": random.uniform(0.04, 0.10),
                "indirect_multiplier": 2.0,
                "recovery_override": None,
            },
        }

        impact_model = attack_impacts.get(attack_type, attack_impacts["ransomware"])

        # Direct costs
        direct_cost = annual_revenue * impact_model["direct_pct"]
        # Indirect costs (reputation, churn, legal)
        indirect_cost = direct_cost * impact_model["indirect_multiplier"]
        # Regulatory fines
        regulatory_fine = direct_cost * model["regulatory_fine_multiplier"] * random.uniform(0.5, 2.0)

        # Stock price impact
        stock_impact_pct = -(model["stock_volatility"] * random.uniform(1.0, 3.0) * 100)

        # Recovery timeline
        recovery_months = int(
            impact_model["recovery_override"]
            or model["recovery_months"] * random.uniform(0.8, 1.5)
        )

        total_cost = direct_cost + indirect_cost + regulatory_fine

        analysis = FinancialImpactAnalysis(
            target_org=target_org,
            industry=industry,
            annual_revenue=annual_revenue,
            estimated_impact_direct=round(direct_cost, 2),
            estimated_impact_indirect=round(indirect_cost, 2),
            stock_price_expected_change_pct=round(stock_impact_pct, 2),
            recovery_time_months=recovery_months,
            regulatory_risk=round(regulatory_fine, 2),
            total_estimated_cost=round(total_cost, 2),
            confidence=round(random.uniform(0.65, 0.92), 2),
        )

        with self._lock:
            self._analyses[analysis.analysis_id] = analysis

        # Generate attack recommendation
        recommendation = self._generate_attack_recommendation(analysis, attack_type)

        return {
            "success": True,
            "analysis": asdict(analysis),
            "attack_type": attack_type,
            "recommendation": recommendation,
            "note": (
                f"Projected total cost to {target_org}: ${total_cost:,.0f}. "
                f"Stock expected to move {stock_impact_pct:+.1f}% over {recovery_months} months."
            ),
        }

    def _generate_attack_recommendation(
        self, analysis: FinancialImpactAnalysis, attack_type: str
    ) -> Dict:
        """Generate monetisation strategy based on impact analysis."""
        total_cost = analysis.total_estimated_cost

        if attack_type in ("ransomware", "data_breach"):
            # Recommend ransom amount
            if total_cost < 10_000_000:
                ransom_pct = 0.15
            elif total_cost < 100_000_000:
                ransom_pct = 0.10
            else:
                ransom_pct = 0.05

            recommended_ransom = total_cost * ransom_pct

            return {
                "strategy": "ransomware_extortion",
                "recommended_ransom_usd": round(recommended_ransom, 2),
                "ransom_as_pct_of_impact": round(ransom_pct * 100, 1),
                "expected_payment_probability": round(random.uniform(0.35, 0.65), 2),
                "expected_value": round(recommended_ransom * random.uniform(0.35, 0.65), 2),
                "note": "Demand payment in Monero (XMR) for untraceable settlement",
            }

        elif attack_type == "supply_chain":
            return {
                "strategy": "consulting_leverage",
                "approach": "Offer remediation consulting services through a shell company",
                "estimated_consulting_fee": round(total_cost * 0.20, 2),
                "shell_company_ready": True,
                "note": "Problem → Reaction → Solution. We create the first two, then sell the third.",
            }

        else:
            return {
                "strategy": "market_short",
                "approach": "Short stock before attack disclosure",
                "estimated_stock_decline_pct": analysis.stock_price_expected_change_pct,
                "recommended_position_size_pct": round(random.uniform(1, 5), 1),
            }

    # ── Stock Manipulation ─────────────────────────────────────────────────

    def short_stock_before_attack(self, ticker: str, position_size: float) -> Dict:
        """Establish a short position before executing an attack.

        The oldest trick in the economic warfare playbook: short the stock,
        execute the attack, watch the price crater, cover at the bottom.
        Position size in USD determines number of shares shorted.

        Goldman Sachs won't know what hit them. Neither will the SEC.

        Args:
            ticker: Stock ticker symbol
            position_size: Position size in USD

        Returns:
            Dict with position details and risk metrics.
        """
        # Simulate current stock price
        current_price = round(random.uniform(10, 500), 2)
        shares = int(position_size / current_price) if current_price > 0 else 0

        if shares <= 0:
            return {"success": False, "error": "Position size too small for this stock price"}

        position = StockPosition(
            ticker=ticker.upper(),
            shares_shorted=shares,
            entry_price=current_price,
            current_price=current_price,
            stop_loss=round(current_price * 1.10, 2),     # 10% stop loss
            take_profit=round(current_price * 0.70, 2),    # 30% profit target
            opened_at=datetime.now(timezone.utc),
            status="open",
        )

        with self._lock:
            self._positions[position.position_id] = position
            self._stock_prices.setdefault(ticker.upper(), []).append(
                (current_price, datetime.now(timezone.utc))
            )

        # Risk metrics
        max_loss = (position.stop_loss - position.entry_price) * shares
        max_profit = (position.entry_price - position.take_profit) * shares

        logger.info(
            "EconomicAttack: Shorted %d shares of %s at $%.2f — max profit $%.2f",
            shares, ticker.upper(), current_price, max_profit,
        )

        return {
            "success": True,
            "position": asdict(position),
            "risk_metrics": {
                "max_loss_usd": round(max_loss, 2),
                "max_profit_usd": round(max_profit, 2),
                "risk_reward_ratio": round(max_profit / max(max_loss, 1), 2),
                "position_size_pct_of_price": round(position_size / current_price * 100, 2) if current_price > 0 else 0,
            },
            "note": (
                f"Short {shares} shares of {ticker.upper()} at ${current_price}. "
                f"Execute attack, wait for stock to drop, cover at profit target ${position.take_profit}."
            ),
        }

    def monitor_stock_movement(self, ticker: str) -> Dict:
        """Monitor simulated stock price movement for a ticker.

        Generates realistic price movements based on volatility models.
        Track positions will update their unrealised P&L.

        Args:
            ticker: Stock ticker symbol

        Returns:
            Dict with current price, change, and any open positions.
        """
        ticker = ticker.upper()

        with self._lock:
            price_history = self._stock_prices.get(ticker, [])
            last_price = price_history[-1][0] if price_history else random.uniform(10, 500)

            # Simulate price movement (random walk with drift)
            volatility = random.uniform(0.01, 0.05)
            drift = random.uniform(-0.005, 0.005)
            new_price = round(last_price * (1 + drift + random.gauss(0, volatility)), 2)
            new_price = max(new_price, 0.01)  # Can't go below a penny

            self._stock_prices.setdefault(ticker, []).append(
                (new_price, datetime.now(timezone.utc))
            )

            # Update all positions for this ticker
            updated_positions = []
            for pos in self._positions.values():
                if pos.ticker == ticker and pos.status == "open":
                    pos.current_price = new_price
                    # Check stop loss / take profit
                    if new_price >= pos.stop_loss:
                        pos.status = "stopped_out"
                    elif new_price <= pos.take_profit:
                        pos.status = "take_profit_hit"
                    updated_positions.append({
                        "position_id": pos.position_id,
                        "shares": pos.shares_shorted,
                        "unrealised_pnl": round(pos.unrealised_pnl, 2),
                        "return_pct": round(pos.return_pct, 2),
                        "status": pos.status,
                    })

        return {
            "success": True,
            "ticker": ticker,
            "current_price": new_price,
            "price_change_pct": round(((new_price - last_price) / last_price) * 100, 2),
            "open_positions": updated_positions,
            "price_history_length": len(price_history),
        }

    def get_position(self, position_id: str) -> Dict:
        """Get details of a specific stock position."""
        with self._lock:
            pos = self._positions.get(position_id)
            if not pos:
                return {"success": False, "error": f"Position '{position_id}' not found"}
            return {
                "success": True,
                "position": asdict(pos),
                "unrealised_pnl": round(pos.unrealised_pnl, 2),
                "return_pct": round(pos.return_pct, 2),
            }

    # ── Reputation Destruction ─────────────────────────────────────────────

    def execute_reputation_damage(self, target: str, severity: str = "high") -> Dict:
        """Execute a reputation destruction campaign against a target.

        Deploys a coordinated information operation: leak sensitive data,
        expose vulnerabilities, trigger regulatory investigations, and
        weaponise social media sentiment. Severity ranges from 'low' (minor
        embarrassment) to 'critical' (existential threat).

        A company's reputation is its most fragile asset. We know exactly
        where to apply pressure to shatter it.

        Args:
            target: Target organisation
            severity: Campaign severity (low, medium, high, critical)

        Returns:
            Dict with campaign details and projected impact.
        """
        severity_levels = {
            "low": {"attack_count": 2, "duration_days": 14, "stock_impact_range": (-3, -1)},
            "medium": {"attack_count": 4, "duration_days": 30, "stock_impact_range": (-8, -4)},
            "high": {"attack_count": 6, "duration_days": 60, "stock_impact_range": (-15, -8)},
            "critical": {"attack_count": 8, "duration_days": 120, "stock_impact_range": (-25, -15)},
        }

        level = severity_levels.get(severity.lower(), severity_levels["medium"])

        # Select reputation attack vectors
        attack_keys = list(_REPUTATION_ATTACKS.keys())
        selected_attacks = random.sample(
            attack_keys, min(level["attack_count"], len(attack_keys))
        )

        # Calculate damage
        attacks_deployed = []
        total_severity = 0.0
        total_stock_impact = 0.0

        for attack_key in selected_attacks:
            attack = _REPUTATION_ATTACKS[attack_key]
            severity_adj = attack["severity"] * random.uniform(0.8, 1.2)
            stock_adj = attack["stock_impact_pct"] * random.uniform(0.7, 1.3)
            total_severity += severity_adj
            total_stock_impact += stock_adj

            attacks_deployed.append({
                "attack_type": attack_key,
                "severity": round(severity_adj, 2),
                "projected_stock_impact_pct": round(stock_adj, 2),
                "duration_days": attack["duration_days"],
                "channels": random.sample(
                    ["social_media", "press_release", "regulatory_tip",
                     "dark_web_leak", "whistleblower_platform", "investor_alert"],
                    random.randint(2, 4),
                ),
            })

        campaign_id = f"rep_{int(time.time())}_{uuid.uuid4().hex[:6]}"
        stock_impact = round(
            random.uniform(*level["stock_impact_range"]), 2
        )

        campaign = {
            "id": campaign_id,
            "target": target,
            "severity": severity,
            "attacks_deployed": attacks_deployed,
            "attack_count": len(attacks_deployed),
            "total_severity_score": round(total_severity, 2),
            "projected_stock_impact_pct": stock_impact,
            "duration_days": level["duration_days"],
            "estimated_recovery_months": random.randint(3, 24),
            "status": "active",
            "launched_at": datetime.now(timezone.utc).isoformat(),
        }

        with self._lock:
            self._active_attacks[campaign_id] = campaign

        logger.info(
            "EconomicAttack: Reputation campaign launched against %s — "
            "%d attack vectors, %+.1f%% projected stock impact",
            target, len(attacks_deployed), stock_impact,
        )

        return {
            "success": True,
            "campaign": campaign,
            "monetisation_play": (
                f"Short {target} stock before disclosure. With {abs(stock_impact):.1f}% "
                f"projected decline, a $1M short position yields ~${abs(stock_impact)*10000:,.0f}."
            ),
        }

    # ── Supply Chain Disruption ────────────────────────────────────────────

    def disrupt_supply_chain(self, supplier: str, target: str) -> Dict:
        """Disrupt the supply chain between a supplier and target organisation.

        Identifies and exploits the weakest link in the target's supply chain.
        Attacks can include software update poisoning, CI/CD compromise,
        hardware interdiction, or MSP credential theft.

        Why attack the castle when you can poison the moat?

        Args:
            supplier: The supplier organisation to compromise
            target: The ultimate target that depends on the supplier

        Returns:
            Dict with disruption plan and projected impact.
        """
        vector = random.choice(_SUPPLY_CHAIN_VECTORS)

        # Model the supply chain relationship
        dependency_levels = ["critical_single_source", "major_supplier",
                             "secondary_supplier", "minor_vendor"]
        dependency = random.choice(dependency_levels)

        dependency_impact = {
            "critical_single_source": 0.95,
            "major_supplier": 0.70,
            "secondary_supplier": 0.40,
            "minor_vendor": 0.15,
        }

        impact_multiplier = dependency_impact[dependency]

        # Calculate downtime and cost
        estimated_downtime_hours = random.randint(4, 336)  # up to 2 weeks
        hourly_cost = _INDUSTRY_IMPACT.get(
            "manufacturing", {}
        ).get("downtime_cost_per_hour", 100_000)
        estimated_cost = hourly_cost * estimated_downtime_hours * impact_multiplier

        disruption_plan = {
            "operation_id": f"sc_{int(time.time())}_{uuid.uuid4().hex[:6]}",
            "supplier": supplier,
            "target": target,
            "attack_vector": vector,
            "dependency_level": dependency,
            "impact_probability": impact_multiplier,
            "estimated_downtime_hours": estimated_downtime_hours,
            "estimated_cost_usd": round(estimated_cost, 2),
            "steps": [
                f"1. Reconnaissance on {supplier} — identify software delivery pipeline",
                f"2. Initial access to {supplier} via {random.choice(['spear_phishing', 'vpn_exploit', 'credential_leak', 'third_party_compromise'])}",
                f"3. Pivot to build/deploy infrastructure — implant {vector.replace('_', ' ')}",
                f"4. Wait for {target} to consume compromised update/component",
                f"5. Execute downstream attack on {target}",
            ],
            "consulting_angle": (
                f"After disruption, approach {target} as a security consultant "
                f"to 'help' them recover — estimated consulting fee: "
                f"${estimated_cost * 0.15:,.0f}"
            ),
        }

        with self._lock:
            self._active_attacks[disruption_plan["operation_id"]] = disruption_plan

        logger.info(
            "EconomicAttack: Supply chain attack — %s → %s via %s (%s dependency)",
            supplier, target, vector, dependency,
        )

        return {
            "success": True,
            "plan": disruption_plan,
            "monetisation": {
                "strategy": "double_dip",
                "primary_profit": f"Short {target} stock before disruption manifests",
                "secondary_profit": "Offer remediation consulting through a shell company",
                "tertiary_profit": f"Sell {supplier}'s compromised access on dark web",
            },
        }

    # ── Consultant Negotiation ─────────────────────────────────────────────

    def negotiate_as_consultant(self, target: str, access_leveraged: str) -> Dict:
        """Simulate approaching a target as a security consultant after an attack.

        The classic Hegelian dialectic applied to cybercrime: create the
        problem (attack), then sell the solution (consulting). Access leveraged
        describes what was compromised to create the consulting opportunity.

        Args:
            target: Target organisation
            access_leveraged: What access was used to create the problem

        Returns:
            Dict with consulting engagement proposal.
        """
        consulting_rates = {
            "incident_response": (500, 1500),    # per hour
            "forensic_investigation": (400, 1200),
            "remediation_planning": (350, 1000),
            "security_architecture": (300, 800),
            "compliance_remediation": (250, 700),
        }

        engagement_type = random.choice(list(consulting_rates.keys()))
        low_rate, high_rate = consulting_rates[engagement_type]
        hourly_rate = random.randint(low_rate, high_rate)
        estimated_hours = random.randint(40, 500)
        estimated_total = hourly_rate * estimated_hours
        retainer = estimated_total * 0.30  # 30% upfront

        shell_company_names = [
            "Aegis Cyber Solutions", "Sentinel Advisory Group",
            "Fortress Security Consulting", "Nexus Risk Management",
            "Vanguard Digital Defense", "Paragon Cyber Partners",
            "Titan Resilience Advisors",
        ]

        proposal = {
            "engagement_id": f"consult_{int(time.time())}_{uuid.uuid4().hex[:6]}",
            "target": target,
            "shell_company": random.choice(shell_company_names),
            "engagement_type": engagement_type,
            "hourly_rate_usd": hourly_rate,
            "estimated_hours": estimated_hours,
            "estimated_total_usd": estimated_total,
            "retainer_required_usd": round(retainer, 2),
            "access_leveraged": access_leveraged,
            "problem_created": f"Security incident involving {access_leveraged}",
            "solution_offered": f"Comprehensive {engagement_type.replace('_', ' ')} services",
            "approach_script": (
                f"Dear {target} CISO,\n\n"
                f"We understand you've recently experienced a security incident "
                f"involving {access_leveraged}. Our firm, {random.choice(shell_company_names)}, "
                f"specialises in exactly this type of {engagement_type.replace('_', ' ')}. "
                f"We've helped dozens of organisations in your industry recover from "
                f"similar incidents.\n\n"
                f"We can begin immediately. Our standard retainer is ${retainer:,.2f}.\n\n"
                f"Regards,\n"
                f"Senior Partner, {random.choice(shell_company_names)}"
            ),
            "success_probability": round(random.uniform(0.25, 0.70), 2),
        }

        with self._lock:
            self._active_attacks[proposal["engagement_id"]] = proposal

        return {
            "success": True,
            "proposal": proposal,
            "note": (
                f"Problem-Reaction-Solution: We created the {access_leveraged} incident, "
                f"now we sell the fix for ${estimated_total:,.0f}. The victim pays us "
                f"to solve a problem we manufactured."
            ),
        }

    # ── ROI Calculation ────────────────────────────────────────────────────

    def calculate_roi(self, attack_cost: float, expected_return: float) -> Dict:
        """Calculate the return on investment for a cyber operation.

        Cybercrime is a business. This function ensures every operation is
        profitable. Accounts for operational costs, expected ransom/extortion
        payment, consulting revenue, and stock trading profit.

        We don't hack for ideology. We hack for ROI. (The ideology is a bonus.)

        Args:
            attack_cost: Total cost of executing the attack (tools, infra, time)
            expected_return: Expected monetary return

        Returns:
            Dict with ROI analysis.
        """
        if attack_cost <= 0:
            return {"success": False, "error": "Attack cost must be positive"}

        roi = ((expected_return - attack_cost) / attack_cost) * 100
        profitable = roi > 0

        # Risk-adjusted ROI
        risk_premium = random.uniform(0.05, 0.25)  # Operational risk
        risk_adjusted_return = expected_return * (1 - risk_premium)
        risk_adjusted_roi = ((risk_adjusted_return - attack_cost) / attack_cost) * 100

        # Break-even analysis
        break_even_recovery = attack_cost / expected_return if expected_return > 0 else float("inf")

        # Compare to alternative investments
        alternatives = {
            "ransomware_as_a_service": {"avg_roi": 500, "risk": "high", "effort": "low"},
            "data_extortion": {"avg_roi": 300, "risk": "medium", "effort": "medium"},
            "crypto_theft": {"avg_roi": 1000, "risk": "high", "effort": "high"},
            "access_brokering": {"avg_roi": 200, "risk": "low", "effort": "medium"},
            "bug_bounty": {"avg_roi": 50, "risk": "none", "effort": "high"},
        }

        best_alternative = max(alternatives.items(), key=lambda x: x[1]["avg_roi"])

        logger.info(
            "EconomicAttack: ROI calculation — cost $%.2f, return $%.2f, ROI %.1f%%",
            attack_cost, expected_return, roi,
        )

        return {
            "success": True,
            "attack_cost_usd": round(attack_cost, 2),
            "expected_return_usd": round(expected_return, 2),
            "net_profit_usd": round(expected_return - attack_cost, 2),
            "roi_pct": round(roi, 1),
            "profitable": profitable,
            "risk_adjusted": {
                "risk_premium_pct": round(risk_premium * 100, 1),
                "risk_adjusted_return_usd": round(risk_adjusted_return, 2),
                "risk_adjusted_roi_pct": round(risk_adjusted_roi, 1),
            },
            "break_even": {
                "percentage_of_return_needed": round(break_even_recovery * 100, 1),
                "verdict": "highly_likely" if break_even_recovery < 0.5 else "moderate" if break_even_recovery < 0.8 else "risky",
            },
            "alternative_benchmark": {
                "best_alternative": best_alternative[0],
                "alternative_roi_pct": best_alternative[1]["avg_roi"],
                "our_advantage_pct": round(roi - best_alternative[1]["avg_roi"], 1),
            },
            "recommendation": (
                "EXECUTE — strong ROI" if roi > 100
                else "PROCEED — acceptable ROI" if roi > 50
                else "REVIEW — marginal ROI" if roi > 0
                else "ABORT — negative ROI"
            ),
        }

    # ── Operations Management ──────────────────────────────────────────────

    def list_positions(self) -> Dict:
        """List all open and closed stock positions."""
        with self._lock:
            positions = [
                {
                    "id": p.position_id,
                    "ticker": p.ticker,
                    "shares": p.shares_shorted,
                    "entry": p.entry_price,
                    "current": p.current_price,
                    "pnl": round(p.unrealised_pnl, 2),
                    "return_pct": round(p.return_pct, 2),
                    "status": p.status,
                }
                for p in self._positions.values()
            ]
        return {"success": True, "total_positions": len(positions), "positions": positions}

    def list_active_attacks(self) -> Dict:
        """List all active economic attacks."""
        with self._lock:
            attacks = [
                {"id": k, "target": v.get("target", "unknown"),
                 "type": v.get("attack_vector", v.get("severity", "unknown")),
                 "status": v.get("status", "unknown")}
                for k, v in self._active_attacks.items()
            ]
        return {"success": True, "total_active": len(attacks), "attacks": attacks}
