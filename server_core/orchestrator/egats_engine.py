"""
server_core/orchestrator/egats_engine.py

EGATS — Evidence-Guided Attack Tree Search

Ported from PentestGPT V2 research. Scores attack paths by difficulty,
evidence confidence, historical success, and context requirements. Uses
UCB-style node selection with evidence-based pruning to find optimal
attack paths through large trees without exhaustive enumeration.

Core insight: attack paths are not equally easy. By scoring each node on
difficulty (0-100, lower is easier), evidence confidence (0.0-1.0),
historical success rate (from agent_learnings DB), and context load
(tokens needed), the engine can rank paths and prune dead-ends before
dispatching agents — saving both time and LLM context budget.

Integration points:
  - PhantomStrikeDB.agent_learnings  — historical_success data
  - TaskDecomposer.decompose()       — goal→sub-goal decomposition
  - OrchestratorAgent                — consumer; selects path, dispatches agents
  - HiveMind / AgentMemory           — context source for difficulty scoring
"""

from __future__ import annotations

import json
import logging
import math
import random
import hashlib
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# AttackTreeNode
# ---------------------------------------------------------------------------


@dataclass
class AttackTreeNode:
    """A single node in the attack tree representing a tactical sub-goal.

    Each node maps to an agent_type that can execute it. The engine scores
    nodes on four dimensions and uses UCB to select the best child at each
    level, pruning branches that fall below evidence or difficulty thresholds.
    """

    goal: str
    difficulty_score: float = 50.0  # 0-100, lower = easier
    evidence_confidence: float = 0.5  # 0.0-1.0
    context_load: int = 0  # estimated tokens needed
    historical_success: float = 0.5  # from agent_learnings table, 0.0-1.0
    children: List[AttackTreeNode] = field(default_factory=list)
    agent_type: str = "recon"
    required_tools: List[str] = field(default_factory=list)
    estimated_time: int = 0  # seconds
    prerequisites: List[str] = field(default_factory=list)

    # Internal bookkeeping for UCB
    visits: int = 0  # times this node was selected in simulations
    total_value: float = 0.0  # accumulated reward for UCB

    def __hash__(self) -> int:
        return hash(
            (
                self.goal,
                self.agent_type,
                tuple(sorted(self.prerequisites)),
            )
        )

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, AttackTreeNode):
            return False
        return (
            self.goal == other.goal
            and self.agent_type == other.agent_type
            and sorted(self.prerequisites) == sorted(other.prerequisites)
        )

    @property
    def composite_score(self) -> float:
        """Single blended score 0-1 where higher is better.

        Weights:
          - difficulty (inverted):  0.35 — easier paths score higher
          - evidence_confidence:    0.30 — well-evidenced paths score higher
          - historical_success:     0.25 — proven techniques score higher
          - context_efficiency:     0.10 — lower context load scores higher
        """
        difficulty_norm = 1.0 - (self.difficulty_score / 100.0)
        context_norm = max(0.0, 1.0 - (self.context_load / 4096.0))
        return (
            0.35 * difficulty_norm
            + 0.30 * self.evidence_confidence
            + 0.25 * self.historical_success
            + 0.10 * context_norm
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "goal": self.goal,
            "difficulty_score": self.difficulty_score,
            "evidence_confidence": self.evidence_confidence,
            "context_load": self.context_load,
            "historical_success": self.historical_success,
            "composite_score": round(self.composite_score, 4),
            "agent_type": self.agent_type,
            "required_tools": self.required_tools,
            "estimated_time": self.estimated_time,
            "prerequisites": self.prerequisites,
            "visits": self.visits,
            "children": [c.to_dict() for c in self.children],
        }

    def __repr__(self) -> str:
        return (
            f"AttackTreeNode(goal={self.goal!r}, comp={self.composite_score:.3f}, "
            f"agent={self.agent_type}, children={len(self.children)})"
        )


# ---------------------------------------------------------------------------
# Goal decomposition templates (standalone — no LLM dependency)
# ---------------------------------------------------------------------------

# Maps high-level goal patterns to ordered sub-goal decompositions.
# Each sub-goal tuple is (goal_description, agent_type, tools, est_seconds).
_DECOMPOSITION_TEMPLATES: Dict[str, List[Tuple[str, str, List[str], int]]] = {
    # ── Web application compromise ──
    "web_compromise": [
        ("Enumerate subdomains and technology stack", "recon",
         ["dns_enum", "shodan_query", "google_dork", "social_profile_scan"], 120),
        ("Port scan and service fingerprinting", "recon",
         ["port_scan", "service_banner_grab", "http_dirbust"], 180),
        ("Vulnerability assessment", "vuln",
         ["nuclei", "nikto", "cve_lookup", "sqli_detect", "xss_detect"], 300),
        ("Initial exploitation", "exploit",
         ["sqli_detect", "xss_detect", "csrf_check", "ssrf_probe", "file_inclusion_test"], 300),
        ("Post-exploitation and privilege escalation", "post_exploit",
         ["linpeas_runner", "sudo_check", "suid_find", "shell", "file_browser"], 300),
        ("Persistence installation", "persistence",
         ["ssh_key_plant", "cron_job_install", "systemd_service_hook"], 180),
        ("Data exfiltration", "exfil",
         ["http_post_data", "dns_tunnel_exfil", "compression"], 180),
        ("Cover tracks and cleanup", "cleanup",
         ["log_wiper", "process_killer", "connection_killer"], 120),
    ],
    # ── Privilege escalation ──
    "privesc": [
        ("Enumerate local users, groups, and permissions", "post_exploit",
         ["host_enum", "user_enum", "group_enum", "sudo_check"], 120),
        ("Identify misconfigurations and SUID binaries", "post_exploit",
         ["suid_find", "cron_hijack", "capability_enum", "linpeas_runner"], 180),
        ("Exploit privilege escalation vector", "privesc",
         ["kernel_exploit", "sudo_bypass", "cron_hijack"], 300),
        ("Verify root / admin access", "privesc",
         ["execute_command", "shell"], 60),
    ],
    # ── Lateral movement ──
    "lateral_movement": [
        ("Discover internal network topology", "recon",
         ["host_enum", "service_enum", "share_enum", "port_scan"], 180),
        ("Harvest credentials from current host", "cred_access",
         ["mimikatz_dump", "lsass_dump", "browser_pass_grab", "sam_dump"], 240),
        ("Test credential validity on discovered hosts", "cred_access",
         ["pass_the_hash", "kerberos_ticket_forge", "ssh_cred_stuff"], 300),
        ("Establish session on target host", "lateral_move",
         ["wmi_exec", "psexec", "ssh_agent_forward", "pass_the_hash"], 240),
        ("Verify access and escalate if needed", "privesc",
         ["linpeas_runner", "winpeas_runner", "sudo_check"], 180),
    ],
    # ── Credential access ──
    "credential_access": [
        ("Dump local credential stores", "cred_access",
         ["mimikatz_dump", "lsass_dump", "sam_dump"], 180),
        ("Extract browser and application credentials", "cred_access",
         ["browser_pass_grab", "kerberos_ticket_extract"], 120),
        ("Crack or reuse harvested hashes", "cred_access",
         ["pass_the_hash", "kerberos_ticket_forge"], 180),
        ("Validate credentials against target services", "recon",
         ["ssh_cred_stuff", "rdp_bruteforce", "ldap_inject"], 240),
    ],
    # ── Data exfiltration ──
    "exfil": [
        ("Locate valuable data on compromised host", "post_exploit",
         ["file_find_pattern", "db_dump", "share_enum"], 180),
        ("Stage data for extraction", "exfil",
         ["compression", "file_browser"], 120),
        ("Establish exfiltration channel", "exfil",
         ["http_post_data", "dns_tunnel_exfil", "icmp_exfil", "cloud_upload"], 240),
        ("Verify data integrity at destination", "exfil",
         ["execute_command"], 60),
        ("Clean exfiltration artifacts", "cleanup",
         ["log_wiper", "timestamp_stomp"], 120),
    ],
    # ── Generic / default decomposition ──
    "generic": [
        ("Passive reconnaissance and target profiling", "recon",
         ["dns_lookup", "whois_lookup", "shodan_query", "google_dork"], 180),
        ("Active scanning and service enumeration", "recon",
         ["port_scan", "service_banner_grab", "http_dirbust", "subdomain_bruteforce"], 240),
        ("Vulnerability identification", "vuln",
         ["nuclei", "cve_lookup", "sqli_detect", "xss_detect"], 300),
        ("Exploitation and initial access", "exploit",
         ["exploit_generator", "sqlmap", "ssh_cred_stuff"], 300),
        ("Post-exploitation and persistence", "post_exploit",
         ["linpeas_runner", "ssh_key_plant", "file_browser"], 240),
        ("Data collection and exfiltration", "exfil",
         ["http_post_data", "db_dump", "compression"], 180),
        ("Cleanup and log sanitization", "cleanup",
         ["log_wiper", "process_killer", "connection_killer"], 120),
    ],
}

# Keywords to determine which decomposition template to use.
_TEMPLATE_KEYWORDS: List[Tuple[List[str], str]] = [
    (["privesc", "privilege escalation", "escalat", "root", "admin", "sudo", "suid"], "privesc"),
    (["lateral", "pivot", "move", "propagat", "network spread"], "lateral_movement"),
    (["credential", "password", "hash", "token", "dump", "lsass", "mimikatz"], "credential_access"),
    (["exfil", "extract", "steal", "download", "data theft", "loot"], "exfil"),
    (["web", "http", "injection", "sqli", "xss", "csrf", "ssrf", "app"], "web_compromise"),
]


# ---------------------------------------------------------------------------
# TDA — Task Difficulty Assessment
# ---------------------------------------------------------------------------

class TaskDifficultyAssessor:
    """Scores the difficulty of an attack goal (0-100, lower is easier).

    Factors considered:
      - Target complexity (services exposed, port count, technology stack diversity)
      - Available tools and their maturity
      - Known defenses (WAF, EDR, SIEM, rate limiting detected)
      - Historical success rate for similar goals
      - Context requirements (tokens needed for the LLM prompt)

    This is called by EGATSEngine.score_difficulty() and _create_node().
    """

    # Defensive technology keywords to detect
    DEFENSE_SIGNATURES: Dict[str, float] = {
        # WAFs — add 8-15 difficulty
        "cloudflare": 12.0,
        "cloudfront": 8.0,
        "akamai": 12.0,
        "imperva": 14.0,
        "f5": 13.0,
        "barracuda": 10.0,
        "modsecurity": 9.0,
        "aws_waf": 11.0,
        "azure_waf": 11.0,
        "fortinet": 12.0,
        # EDR / AV — add 10-18 difficulty
        "crowdstrike": 18.0,
        "sentinelone": 17.0,
        "carbon black": 16.0,
        "defender": 14.0,
        "symantec": 13.0,
        "mcafee": 12.0,
        "trend micro": 12.0,
        "kaspersky": 14.0,
        "sophos": 11.0,
        "eset": 10.0,
        "bitdefender": 11.0,
        "cylance": 14.0,
        # SIEM / monitoring — add 8-15 difficulty
        "splunk": 13.0,
        "elastic": 10.0,
        "elk": 10.0,
        "qradar": 12.0,
        "arcsight": 12.0,
        "sumo logic": 9.0,
        "datadog": 8.0,
        "new relic": 7.0,
        # Rate limiting / IDS
        "fail2ban": 6.0,
        "snort": 9.0,
        "suricata": 9.0,
        "ossec": 8.0,
        "wazuh": 8.0,
    }

    # Base difficulty per agent_type (some agent roles are inherently harder)
    AGENT_BASE_DIFFICULTY: Dict[str, float] = {
        "recon": 20.0,
        "vuln": 30.0,
        "exploit": 45.0,
        "post_exploit": 35.0,
        "privesc": 50.0,
        "cred_access": 40.0,
        "lateral_move": 48.0,
        "persistence": 35.0,
        "exfil": 38.0,
        "cleanup": 22.0,
        "webapp": 42.0,
        "cloud": 40.0,
        "supply_chain": 55.0,
        "social_eng": 35.0,
        "bug_bounty": 32.0,
        "reverse_engineering": 60.0,
        "iot": 55.0,
        "scada": 65.0,
        "automotive": 60.0,
        "satellite": 70.0,
        "blockchain": 50.0,
        "ai_exploit": 62.0,
        "mobile": 45.0,
        "telecom": 48.0,
        "physical": 30.0,
        "darkweb": 40.0,
        "drone": 55.0,
        "nuclear_opsec": 80.0,
        "emergency": 10.0,
        "opsec": 25.0,
        "decoy": 20.0,
        "counter_surveillance": 30.0,
        "reverse_trace": 35.0,
        "trace_buster": 28.0,
        "auto_fixer": 5.0,
        "orchestrator": 15.0,
    }

    @classmethod
    def assess(
        cls,
        goal: str,
        agent_type: str,
        context: Dict[str, Any],
        tools_available: List[str],
    ) -> float:
        """Score the difficulty of achieving `goal` with `agent_type` in `context`.

        Returns a float 0-100 where lower is easier.
        """
        score = cls.AGENT_BASE_DIFFICULTY.get(agent_type, 35.0)

        goal_lower = goal.lower()

        # ── 1. Target complexity (from context) ──
        score += cls._target_complexity_penalty(context)

        # ── 2. Defensive posture penalty ──
        score += cls._defense_penalty(context, goal_lower)

        # ── 3. Tool availability bonus ──
        score += cls._tool_bonus(agent_type, tools_available)

        # ── 4. Context uncertainty penalty ──
        score += cls._uncertainty_penalty(context)

        # ── 5. Goal specificity bonus (specific goals are easier) ──
        score += cls._specificity_bonus(goal_lower)

        return max(0.0, min(score, 100.0))

    @classmethod
    def _target_complexity_penalty(cls, context: Dict[str, Any]) -> float:
        """Penalize based on number of services, hosts, and technology diversity."""
        penalty = 0.0

        # Count discovered hosts
        hosts = context.get("discovered_hosts", [])
        if isinstance(hosts, list):
            num_hosts = len(hosts)
            if num_hosts > 20:
                penalty += 12.0
            elif num_hosts > 10:
                penalty += 8.0
            elif num_hosts > 5:
                penalty += 5.0
            elif num_hosts > 1:
                penalty += 2.0

        # Count discovered services
        services = context.get("discovered_services", [])
        if isinstance(services, list):
            num_services = len(services)
            if num_services > 30:
                penalty += 15.0
            elif num_services > 15:
                penalty += 10.0
            elif num_services > 5:
                penalty += 5.0

        # Technology diversity (count unique service names/banners)
        tech_names: Set[str] = set()
        for svc in (services if isinstance(services, list) else []):
            if isinstance(svc, dict):
                name = svc.get("service", svc.get("name", ""))
                if name:
                    tech_names.add(name.lower())
        if len(tech_names) > 10:
            penalty += 8.0
        elif len(tech_names) > 5:
            penalty += 4.0

        return penalty

    @classmethod
    def _defense_penalty(cls, context: Dict[str, Any], goal_lower: str) -> float:
        """Penalize for known defensive technologies in context."""
        penalty = 0.0

        # Check context fields for defense keywords
        context_str = json.dumps(context, default=str).lower()
        for defense, weight in cls.DEFENSE_SIGNATURES.items():
            if defense in context_str or defense in goal_lower:
                penalty += weight
                break  # Only count the highest-impact defense once per category

        # Check threat level from HiveMind
        threat = context.get("current_threat_level", 0)
        if isinstance(threat, (int, float)):
            penalty += min(threat * 0.15, 15.0)  # Up to +15 for threat level 100

        # Check for defense alerts
        alerts = context.get("defense_alerts", [])
        if isinstance(alerts, list) and len(alerts) > 0:
            penalty += min(len(alerts) * 2.0, 10.0)

        return min(penalty, 30.0)  # Cap defense penalty

    @classmethod
    def _tool_bonus(cls, agent_type: str, tools_available: List[str]) -> float:
        """Bonus (negative = easier) when relevant tools are available."""
        if not tools_available:
            return 8.0  # No tools = harder

        # More specialized tools = easier
        tool_count = len(tools_available)
        if tool_count >= 8:
            return -10.0
        elif tool_count >= 5:
            return -6.0
        elif tool_count >= 3:
            return -3.0
        elif tool_count >= 1:
            return 0.0
        return 5.0

    @classmethod
    def _uncertainty_penalty(cls, context: Dict[str, Any]) -> float:
        """Penalize when key intel is missing."""
        penalty = 0.0

        if not context.get("discovered_hosts"):
            penalty += 4.0
        if not context.get("discovered_services"):
            penalty += 3.0
        if not context.get("discovered_vulns"):
            penalty += 3.0
        if not context.get("target_profile"):
            penalty += 2.0

        return penalty

    @classmethod
    def _specificity_bonus(cls, goal_lower: str) -> float:
        """More specific goals are easier to act on (negative = bonus)."""
        # Check for specific indicators: IPs, ports, CVE IDs, software names
        specificity_score = 0.0

        # IP address present
        if any(
            char.isdigit() for char in goal_lower
        ) and "." in goal_lower:
            specificity_score -= 4.0

        # CVE reference
        if "cve-" in goal_lower:
            specificity_score -= 8.0

        # Specific port mentioned
        if any(
            f"port {p}" in goal_lower or f":{p}" in goal_lower for p in ["80", "443", "22", "21", "445", "3389", "8080", "3306", "5432"]
        ):
            specificity_score -= 3.0

        # Specific software named
        for sw in ["apache", "nginx", "tomcat", "iis", "wordpress", "drupal", "joomla",
                    "mysql", "postgresql", "mongodb", "redis", "elasticsearch"]:
            if sw in goal_lower:
                specificity_score -= 3.0
                break

        return max(specificity_score, -10.0)


# ---------------------------------------------------------------------------
# EGATS Engine
# ---------------------------------------------------------------------------


class EGATSEngine:
    """Evidence-Guided Attack Tree Search with difficulty scoring.

    Builds an attack tree from a high-level goal, scores each node on four
    dimensions, uses UCB-style selection to find the optimal path, and prunes
    branches that fail evidence or difficulty thresholds.

    Usage::

        engine = EGATSEngine(db=phantomstrike_db)
        tree = engine.build_tree("Get root on 10.0.0.5", context)
        path = engine.select_best_path(tree)
        for node in path:
            print(f"  -> {node.agent_type}: {node.goal} (score={node.composite_score:.3f})")
        # Generate alternatives
        candidates = engine.generate_candidate_paths("Get root on 10.0.0.5", context, count=5)
    """

    # UCB exploration constant. Higher = more exploration of untried nodes.
    UCB_C: float = 1.414  # sqrt(2) — standard UCB1 constant

    # Pruning thresholds
    MIN_EVIDENCE_CONFIDENCE: float = 0.2
    MAX_DIFFICULTY_SCORE: float = 90.0  # prune nodes harder than this
    MIN_HISTORICAL_SUCCESS: float = 0.05  # prune techniques that almost never work

    # Tree building limits
    MAX_TREE_DEPTH: int = 12
    MAX_CHILDREN_PER_NODE: int = 15

    def __init__(self, db=None):
        """Initialize the EGATS engine.

        Args:
            db: Optional PhantomStrikeDB instance for agent_learnings lookups.
                When None, historical_success defaults to 0.5.
        """
        self.db = db
        self._tree_cache: Dict[str, AttackTreeNode] = {}
        self._learning_cache: Dict[str, float] = {}
        self._assessor = TaskDifficultyAssessor()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def build_tree(self, goal: str, context: Dict[str, Any]) -> AttackTreeNode:
        """Build a complete attack tree from the goal and current context.

        Recursively decomposes the goal into sub-goals, scores each node, and
        populates children. Uses decomposition templates (no LLM needed).

        Args:
            goal: High-level mission objective (e.g., "Get root access").
            context: Current mission context dict (HiveMind get_context() output).

        Returns:
            The root AttackTreeNode of the built tree.
        """
        cache_key = self._cache_key(goal, context)
        if cache_key in self._tree_cache:
            logger.debug("EGATS tree cache hit for: %s", goal[:60])
            return self._tree_cache[cache_key]

        logger.info("EGATS building attack tree for goal: %s", goal[:80])

        root = AttackTreeNode(
            goal=goal,
            difficulty_score=0.0,
            evidence_confidence=1.0,
            context_load=0,
            historical_success=0.7,
            children=[],
            agent_type="orchestrator",
            required_tools=[],
            estimated_time=0,
            prerequisites=[],
        )

        # Decompose into sub-goals
        sub_goals = self._decompose_goal(goal, context)
        for sg_spec in sub_goals:
            node = self._create_node(sg_spec, context, depth=1)
            root.children.append(node)

        # Recursively expand each child to MAX_TREE_DEPTH
        for child in root.children:
            self._expand_node(child, context, depth=2)

        # Cache the tree
        self._tree_cache[cache_key] = root
        logger.info(
            "EGATS tree built: %d root children, depth<=%d",
            len(root.children),
            self.MAX_TREE_DEPTH,
        )
        return root

    def select_best_path(
        self, root: AttackTreeNode, max_depth: int = 10
    ) -> List[AttackTreeNode]:
        """UCB-style selection with difficulty penalties and evidence pruning.

        Walks down the tree from the root, selecting the best child at each
        level using the UCB formula. Stops when a leaf is reached, the depth
        limit is hit, or all children are pruned.

        Args:
            root: The root node (typically from build_tree()).
            max_depth: Maximum number of nodes in the returned path.

        Returns:
            Ordered list of nodes forming the selected attack path,
            starting with root.
        """
        path: List[AttackTreeNode] = [root]
        current = root

        for _ in range(max_depth):
            if not current.children:
                break

            # Filter out pruned children
            viable = [
                c for c in current.children if not self.prune_by_evidence(c)
            ]

            if not viable:
                logger.debug(
                    "EGATS: all children pruned at goal=%s, terminating path",
                    current.goal[:40],
                )
                break

            if len(viable) == 1:
                best_child = viable[0]
            else:
                best_child = self._ucb_select(viable)

            best_child.visits += 1
            path.append(best_child)
            current = best_child

        return path

    def prune_by_evidence(self, node: AttackTreeNode) -> bool:
        """Determine if a node should be pruned from the search.

        Pruning rules (any one triggers prune):
          1. evidence_confidence < MIN_EVIDENCE_CONFIDENCE
          2. difficulty_score > MAX_DIFFICULTY_SCORE
          3. historical_success < MIN_HISTORICAL_SUCCESS (and has been tried)

        Returns True if the node should be pruned.
        """
        if node.evidence_confidence < self.MIN_EVIDENCE_CONFIDENCE:
            logger.debug(
                "EGATS prune: low evidence (%.2f) for %s",
                node.evidence_confidence,
                node.goal[:40],
            )
            return True

        if node.difficulty_score > self.MAX_DIFFICULTY_SCORE:
            logger.debug(
                "EGATS prune: high difficulty (%.1f) for %s",
                node.difficulty_score,
                node.goal[:40],
            )
            return True

        if node.historical_success < self.MIN_HISTORICAL_SUCCESS and node.visits > 0:
            logger.debug(
                "EGATS prune: low historical success (%.2f) for %s",
                node.historical_success,
                node.goal[:40],
            )
            return True

        return False

    def score_difficulty(self, goal: str, context: Dict[str, Any]) -> float:
        """TDA (Task Difficulty Assessment): Score 0-100 based on multiple factors.

        Uses TaskDifficultyAssessor with context-derived signals:
          - Target complexity (services, ports, technology diversity)
          - Available tools for this goal
          - Known defenses (WAF, EDR, SIEM detected)
          - Historical success rate for similar goals

        Args:
            goal: The attack sub-goal to score.
            context: HiveMind context dict.

        Returns:
            Difficulty score 0-100 (lower = easier).
        """
        return self._assessor.assess(
            goal=goal,
            agent_type=self._infer_agent_type(goal, context),
            context=context,
            tools_available=self._infer_tools(goal, context),
        )

    def generate_candidate_paths(
        self,
        goal: str,
        context: Dict[str, Any],
        exclude: Optional[Set[str]] = None,
        count: int = 20,
    ) -> List[List[AttackTreeNode]]:
        """Generate multiple candidate attack paths, ranked by composite score.

        Builds a tree, then uses randomized UCB selection (UCB with noise
        injection) to produce diverse paths. Paths containing excluded sub-goals
        are filtered out.

        Args:
            goal: Mission objective.
            context: HiveMind context dict.
            exclude: Set of goal strings to exclude from paths.
            count: Number of candidate paths to generate.

        Returns:
            List of paths (each a list of AttackTreeNode), sorted best-first
            by mean composite score.
        """
        tree = self.build_tree(goal, context)
        exclude_set = exclude or set()
        candidates: List[List[AttackTreeNode]] = []
        seen_path_hashes: Set[str] = set()

        for _ in range(count * 2):  # Oversample to get enough unique paths
            if len(candidates) >= count:
                break

            path = self._randomized_select(tree, exclude_set)
            if not path or len(path) < 2:
                continue

            # Hash the path for deduplication
            path_hash = self._path_hash(path)
            if path_hash in seen_path_hashes:
                continue
            seen_path_hashes.add(path_hash)

            candidates.append(path)

        # Sort by mean composite score descending
        candidates.sort(
            key=lambda p: sum(n.composite_score for n in p) / max(len(p), 1),
            reverse=True,
        )

        return candidates[:count]

    # ------------------------------------------------------------------
    # Internal: Goal decomposition
    # ------------------------------------------------------------------

    def _decompose_goal(
        self, goal: str, context: Dict[str, Any]
    ) -> List[Tuple[str, str, List[str], int]]:
        """Break a high-level goal into ordered sub-goals.

        Returns a list of (goal_text, agent_type, tools, est_seconds) tuples.
        Uses keyword matching against decomposition templates. Falls back to
        the 'generic' template.
        """
        goal_lower = goal.lower()

        # Try to match a specific template
        for keywords, template_name in _TEMPLATE_KEYWORDS:
            for kw in keywords:
                if kw in goal_lower:
                    logger.debug(
                        "EGATS: matched template '%s' via keyword '%s'",
                        template_name,
                        kw,
                    )
                    return list(
                        _DECOMPOSITION_TEMPLATES.get(
                            template_name,
                            _DECOMPOSITION_TEMPLATES["generic"],
                        )
                    )

        # Check context for hints about the mission type
        mission_phase = context.get("mission_phase", "").lower()
        if "lateral" in mission_phase:
            return list(_DECOMPOSITION_TEMPLATES["lateral_movement"])
        if "privesc" in mission_phase or "post" in mission_phase:
            return list(_DECOMPOSITION_TEMPLATES["privesc"])
        if "exfil" in mission_phase:
            return list(_DECOMPOSITION_TEMPLATES["exfil"])

        # Default
        logger.debug("EGATS: using generic decomposition template")
        return list(_DECOMPOSITION_TEMPLATES["generic"])

    # ------------------------------------------------------------------
    # Internal: Node creation
    # ------------------------------------------------------------------

    def _create_node(
        self,
        sub_goal_spec: Tuple[str, str, List[str], int],
        context: Dict[str, Any],
        depth: int = 0,
    ) -> AttackTreeNode:
        """Create a scored AttackTreeNode from a sub-goal specification.

        Args:
            sub_goal_spec: (goal_text, agent_type, tools, est_seconds) tuple.
            context: HiveMind context dict.
            depth: Current depth in the tree.

        Returns:
            A fully scored AttackTreeNode with children.
        """
        goal_text, agent_type, tools, est_seconds = sub_goal_spec

        # Score difficulty
        difficulty = self.score_difficulty(goal_text, context)

        # Estimate evidence confidence from context richness
        evidence = self._estimate_evidence(goal_text, agent_type, context)

        # Fetch historical success from agent_learnings
        hist_success = self._get_historical_success(
            technique=self._technique_key(goal_text, agent_type),
            agent_type=agent_type,
        )

        # Estimate context load (tokens)
        context_load = self._estimate_context_load(goal_text, context)

        node = AttackTreeNode(
            goal=goal_text,
            difficulty_score=difficulty,
            evidence_confidence=evidence,
            context_load=context_load,
            historical_success=hist_success,
            children=[],
            agent_type=agent_type,
            required_tools=list(tools),
            estimated_time=est_seconds,
            prerequisites=self._infer_prerequisites(goal_text, agent_type, context),
        )

        return node

    def _expand_node(
        self,
        node: AttackTreeNode,
        context: Dict[str, Any],
        depth: int,
    ) -> None:
        """Recursively expand a node with sub-goal children up to MAX_TREE_DEPTH."""
        if depth >= self.MAX_TREE_DEPTH:
            return
        if len(node.children) >= self.MAX_CHILDREN_PER_NODE:
            return

        # Try to decompose the node's goal further
        sub_specs = self._decompose_goal(node.goal, context)

        # Filter: don't duplicate the same agent_type at the same level
        seen_types: Set[str] = set()
        for child in node.children:
            seen_types.add(child.agent_type)

        added = 0
        for spec in sub_specs:
            if added >= self.MAX_CHILDREN_PER_NODE:
                break
            agent_type = spec[1]
            if agent_type in seen_types:
                continue
            seen_types.add(agent_type)

            child = self._create_node(spec, context, depth)
            node.children.append(child)
            added += 1

            # Recurse
            self._expand_node(child, context, depth + 1)

    # ------------------------------------------------------------------
    # Internal: UCB selection
    # ------------------------------------------------------------------

    def _ucb_select(self, nodes: List[AttackTreeNode]) -> AttackTreeNode:
        """Select the best child node using the UCB1 formula.

        UCB = composite_score + C * sqrt(ln(N_parent) / N_child)

        The composite_score provides exploitation (we prefer high-scoring nodes),
        while the exploration term gives untried nodes (low N_child) a bonus.

        Args:
            nodes: List of candidate child nodes (already filtered by prune).

        Returns:
            The node with the highest UCB value.
        """
        if not nodes:
            raise ValueError("_ucb_select called with empty node list")

        if len(nodes) == 1:
            return nodes[0]

        # Total visits across all candidates (simulates parent visits)
        total_visits = sum(max(n.visits, 1) for n in nodes)
        # Add a synthetic "parent visit" term for the ln(N_parent) part
        parent_visits = total_visits + 1

        best_node = nodes[0]
        best_ucb = -float("inf")

        for node in nodes:
            # Exploitation: composite score (0-1)
            exploit = node.composite_score

            # Exploration: bonus for less-visited nodes
            n_visits = max(node.visits, 1)
            explore = self.UCB_C * math.sqrt(
                math.log(parent_visits) / n_visits
            )

            # Add a small difficulty-penalty term to UCB
            # (nodes that are too difficult get a slight penalty even in UCB)
            difficulty_penalty = max(0.0, (node.difficulty_score - 70.0) / 100.0) * 0.15

            ucb = exploit + explore - difficulty_penalty

            if ucb > best_ucb:
                best_ucb = ucb
                best_node = node

        return best_node

    def _randomized_select(
        self,
        root: AttackTreeNode,
        exclude_set: Set[str],
        temperature: float = 0.3,
    ) -> List[AttackTreeNode]:
        """Select a path using softmax over composite scores (for diversity).

        Adds Gaussian noise scaled by temperature to UCB values, then greedily
        selects. This produces diverse paths across multiple calls.

        Args:
            root: Root node.
            exclude_set: Goal strings to skip.
            temperature: Noise scale (0 = deterministic UCB, higher = more random).

        Returns:
            A single path (list of nodes).
        """
        path: List[AttackTreeNode] = [root]
        current = root

        for _ in range(self.MAX_TREE_DEPTH):
            # Gather viable children (not pruned, not excluded)
            viable = []
            for c in current.children:
                if c.goal in exclude_set:
                    continue
                if self.prune_by_evidence(c):
                    continue
                viable.append(c)

            if not viable:
                break

            if len(viable) == 1:
                best = viable[0]
            else:
                # Score each child with noise
                scores: List[float] = []
                for node in viable:
                    noise = random.gauss(0, temperature)
                    scores.append(node.composite_score + noise)

                best_idx = max(range(len(scores)), key=lambda i: scores[i])
                best = viable[best_idx]

            best.visits += 1
            path.append(best)
            current = best

        return path

    # ------------------------------------------------------------------
    # Internal: evidence estimation
    # ------------------------------------------------------------------

    def _estimate_evidence(
        self,
        goal: str,
        agent_type: str,
        context: Dict[str, Any],
    ) -> float:
        """Estimate evidence confidence (0-1) based on context richness.

        Higher when context contains relevant intel for the agent:
          - recon agents: hosts discovered, target profile
          - vuln agents: services, CVEs cached
          - exploit agents: vulns found, creds discovered
          - post_exploit agents: active sessions, compromised hosts
          - exfil agents: files found, active sessions
        """
        base = 0.4

        # Check what intel is available
        has_hosts = bool(context.get("discovered_hosts"))
        has_services = bool(context.get("discovered_services"))
        has_vulns = bool(context.get("discovered_vulns"))
        has_creds = bool(context.get("discovered_creds"))
        has_sessions = bool(context.get("active_sessions"))
        has_owned = bool(context.get("compromised_hosts"))
        has_files = bool(context.get("discovered_files"))
        has_profile = bool(context.get("target_profile"))

        if agent_type in ("recon", "webapp", "cloud", "supply_chain"):
            if has_hosts:
                base += 0.15
            if has_profile:
                base += 0.10
            if has_services:
                base += 0.10

        elif agent_type in ("vuln", "exploit", "bug_bounty"):
            if has_services:
                base += 0.15
            if has_vulns:
                base += 0.20
            if has_creds:
                base += 0.10
            if has_sessions:
                base += 0.05

        elif agent_type in ("post_exploit", "privesc", "lateral_move",
                             "persistence", "cred_access", "reverse_engineering"):
            if has_sessions:
                base += 0.20
            if has_owned:
                base += 0.15
            if has_creds:
                base += 0.10

        elif agent_type in ("exfil", "cleanup"):
            if has_files:
                base += 0.15
            if has_sessions:
                base += 0.15
            if has_owned:
                base += 0.10

        else:
            # Domain / defense / specialist agents
            if has_hosts:
                base += 0.10
            if has_services:
                base += 0.05
            if has_profile:
                base += 0.05

        return min(base, 1.0)

    # ------------------------------------------------------------------
    # Internal: historical success from agent_learnings
    # ------------------------------------------------------------------

    def _get_historical_success(
        self,
        technique: str,
        agent_type: str = "",
    ) -> float:
        """Query agent_learnings for historical success rate.

        Uses the technique key to look up:
          - effectiveness_score (pre-computed)
          - success_count / (success_count + failure_count)

        Falls back to 0.5 when no data is available.

        Args:
            technique: Technique key (e.g., "sqli_detect", "port_scan").
            agent_type: Agent type for broader fallback queries.

        Returns:
            Historical success rate 0.0-1.0.
        """
        # Check in-memory cache first
        cache_key = f"{technique}:{agent_type}"
        if cache_key in self._learning_cache:
            return self._learning_cache[cache_key]

        if self.db is None:
            self._learning_cache[cache_key] = 0.5
            return 0.5

        try:
            # Query by technique name
            result = self._query_learning(technique)
            if result is not None:
                self._learning_cache[cache_key] = result
                return result

            # Fallback: query by agent_type
            if agent_type:
                result = self._query_learning(agent_type)
                if result is not None:
                    self._learning_cache[cache_key] = result
                    return result

        except Exception as exc:
            logger.debug("agent_learnings query failed: %s", exc)

        # Default prior: neutral
        self._learning_cache[cache_key] = 0.5
        return 0.5

    def _query_learning(self, key: str) -> Optional[float]:
        """Query a single row from agent_learnings by technique.

        Returns effectiveness_score if available, otherwise computes from
        success_count / total. Returns None if no matching row found.
        """
        if self.db is None:
            return None

        try:
            with self.db._lock:
                cur = self.db._conn.execute(
                    """
                    SELECT technique, success_count, failure_count, effectiveness_score
                    FROM agent_learnings
                    WHERE technique = ? OR technique LIKE ?
                    LIMIT 1
                    """,
                    (key, f"%{key}%"),
                )
                row = cur.fetchone()
                if row is None:
                    return None

                technique, success_count, failure_count, eff_score = row

                # Prefer the pre-computed effectiveness_score
                if eff_score is not None and eff_score > 0.0:
                    return float(eff_score)

                # Compute from counts
                total = success_count + failure_count
                if total > 0:
                    # Apply Laplace smoothing for low-sample techniques
                    smoothed = (success_count + 1) / (total + 2)
                    return round(smoothed, 4)

                return None

        except Exception:
            return None

    def record_outcome(
        self,
        technique: str,
        success: bool,
        target_type: str = "",
        execution_time: float = 0.0,
        defense_triggers: Optional[List[str]] = None,
    ) -> None:
        """Record an attack outcome in agent_learnings for future scoring.

        Args:
            technique: Technique or tool name used.
            success: Whether the technique succeeded.
            target_type: Type of target (e.g., 'linux', 'windows', 'webapp').
            execution_time: Time in seconds taken to execute.
            defense_triggers: List of defense systems triggered.
        """
        if self.db is None:
            return

        defense_json = json.dumps(defense_triggers or [])

        try:
            with self.db._lock:
                # Check if technique row exists
                cur = self.db._conn.execute(
                    "SELECT id, success_count, failure_count, avg_execution_time FROM agent_learnings WHERE technique = ?",
                    (technique,),
                )
                row = cur.fetchone()

                if row is None:
                    # Insert new row
                    sc = 1 if success else 0
                    fc = 0 if success else 1
                    eff = 0.75 if success else 0.25
                    self.db._conn.execute(
                        """
                        INSERT INTO agent_learnings
                          (technique, target_type, success_count, failure_count,
                           defense_triggers, avg_execution_time, last_used_at, effectiveness_score)
                        VALUES (?, ?, ?, ?, ?, ?, datetime('now'), ?)
                        """,
                        (technique, target_type, sc, fc, defense_json, execution_time, eff),
                    )
                else:
                    row_id, old_sc, old_fc, old_avg = row
                    new_sc = old_sc + (1 if success else 0)
                    new_fc = old_fc + (0 if success else 1)
                    total = new_sc + new_fc

                    # Exponential moving average for execution time
                    alpha = 0.3
                    new_avg = (
                        alpha * execution_time + (1 - alpha) * (old_avg or execution_time)
                        if old_avg
                        else execution_time
                    )

                    # Compute new effectiveness score with Laplace smoothing
                    new_eff = (new_sc + 1) / (total + 2)

                    self.db._conn.execute(
                        """
                        UPDATE agent_learnings
                        SET success_count = ?, failure_count = ?,
                            avg_execution_time = ?, effectiveness_score = ?,
                            last_used_at = datetime('now'),
                            defense_triggers = ?
                        WHERE id = ?
                        """,
                        (new_sc, new_fc, round(new_avg, 3), round(new_eff, 4), defense_json, row_id),
                    )

                self.db._conn.commit()

                # Invalidate cache entries that might match
                self._learning_cache.pop(f"{technique}:", None)
                self._learning_cache.pop(f"{technique}:{target_type}", None)

                logger.debug(
                    "EGATS recorded outcome: %s -> %s (eff=%.3f)",
                    technique,
                    "success" if success else "failure",
                    self._get_historical_success(technique, target_type),
                )

        except Exception as exc:
            logger.warning("EGATS record_outcome failed: %s", exc)

    # ------------------------------------------------------------------
    # Internal: context load estimation
    # ------------------------------------------------------------------

    @staticmethod
    def _estimate_context_load(goal: str, context: Dict[str, Any]) -> int:
        """Estimate how many tokens the LLM prompt for this goal would consume.

        Rough heuristic: count characters in the serialized context subset
        relevant to the goal + the goal text itself.
        """
        # Goal text tokens (rough: 1 token ~ 4 chars)
        goal_tokens = len(goal) // 4

        # Context tokens: estimate from key fields
        context_tokens = 0
        for key in (
            "discovered_hosts",
            "discovered_services",
            "discovered_vulns",
            "discovered_creds",
            "active_sessions",
            "compromised_hosts",
        ):
            val = context.get(key, [])
            if isinstance(val, list):
                # Rough: 50 chars per item when serialized
                context_tokens += min(len(val), 20) * 50 // 4

        # Cap at a reasonable max
        total = goal_tokens + context_tokens
        return min(total, 8192)

    # ------------------------------------------------------------------
    # Internal: helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _technique_key(goal: str, agent_type: str) -> str:
        """Derive a technique key from goal + agent_type for DB lookups."""
        # Simplify: use agent_type as the technique key, refining with goal keywords
        goal_lower = goal.lower()

        # Map common goal keywords to specific techniques
        keyword_map = {
            "port scan": "port_scan",
            "service": "service_banner_grab",
            "subdomain": "subdomain_bruteforce",
            "vulnerability": "nuclei",
            "sqli": "sqli_detect",
            "xss": "xss_detect",
            "exploit": "exploit_generator",
            "privesc": "linpeas_runner",
            "escalat": "linpeas_runner",
            "persist": "ssh_key_plant",
            "backdoor": "cron_job_install",
            "credential": "mimikatz_dump",
            "password": "mimikatz_dump",
            "hash": "pass_the_hash",
            "lateral": "pass_the_hash",
            "pivot": "wmi_exec",
            "exfil": "http_post_data",
            "clean": "log_wiper",
            "wipe": "log_wiper",
            "dump": "db_dump",
            "database": "db_dump",
        }

        for kw, technique in keyword_map.items():
            if kw in goal_lower:
                return technique

        return agent_type

    @staticmethod
    def _infer_agent_type(goal: str, context: Dict[str, Any]) -> str:
        """Infer the likely agent_type from a goal string."""
        goal_lower = goal.lower()

        type_keywords: List[Tuple[List[str], str]] = [
            (["recon", "enumerate", "discover", "scan", "fingerprint", "profile", "map"], "recon"),
            (["vulnerability", "vuln", "cve", "assess", "audit"], "vuln"),
            (["exploit", "breach", "compromise", "attack", "bypass"], "exploit"),
            (["privesc", "escalat", "root", "admin", "sudo", "privilege"], "privesc"),
            (["persist", "backdoor", "maintain", "stay"], "persistence"),
            (["lateral", "pivot", "move", "propagat", "spread"], "lateral_move"),
            (["credential", "password", "hash", "token", "dump"], "cred_access"),
            (["exfil", "extract", "steal", "download", "transfer"], "exfil"),
            (["clean", "wipe", "cover", "erase", "sanitize", "remove trace"], "cleanup"),
            (["post", "collect", "gather", "enumerate host"], "post_exploit"),
        ]

        for keywords, atype in type_keywords:
            for kw in keywords:
                if kw in goal_lower:
                    return atype

        return "recon"  # safest default

    @staticmethod
    def _infer_tools(goal: str, context: Dict[str, Any]) -> List[str]:
        """Infer tools likely needed for a goal based on keywords."""
        goal_lower = goal.lower()
        tools: List[str] = []

        tool_keywords: List[Tuple[str, str]] = [
            ("port scan", "port_scan"),
            ("nmap", "port_scan"),
            ("subdomain", "subdomain_bruteforce"),
            ("dns", "dns_lookup"),
            ("whois", "whois_lookup"),
            ("shodan", "shodan_query"),
            ("sqli", "sqli_detect"),
            ("xss", "xss_detect"),
            ("csrf", "csrf_check"),
            ("ssrf", "ssrf_probe"),
            ("sqlmap", "sqli_detect"),
            ("nuclei", "nuclei"),
            ("nikto", "nikto"),
            ("cve", "cve_lookup"),
            ("mimikatz", "mimikatz_dump"),
            ("lsass", "lsass_dump"),
            ("hash", "pass_the_hash"),
            ("kerberos", "kerberos_ticket_forge"),
            ("pass the hash", "pass_the_hash"),
            ("psexec", "psexec"),
            ("wmi", "wmi_exec"),
            ("ssh", "ssh_cred_stuff"),
            ("rdp", "rdp_bruteforce"),
            ("linpeas", "linpeas_runner"),
            ("winpeas", "winpeas_runner"),
            ("suid", "suid_find"),
            ("sudo", "sudo_check"),
            ("cron", "cron_job_install"),
            ("systemd", "systemd_service_hook"),
            ("log", "log_wiper"),
            ("wipe", "log_wiper"),
            ("exfil", "http_post_data"),
            ("dns tunnel", "dns_tunnel_exfil"),
            ("icmp", "icmp_exfil"),
            ("cloud", "cloud_upload"),
            ("persist", "ssh_key_plant"),
            ("backdoor", "cron_job_install"),
        ]

        for kw, tool in tool_keywords:
            if kw in goal_lower and tool not in tools:
                tools.append(tool)

        return tools if tools else ["execute_command"]

    @staticmethod
    def _infer_prerequisites(
        goal: str, agent_type: str, context: Dict[str, Any]
    ) -> List[str]:
        """Infer what must be true before this node can execute.

        Based on agent_type and context state.
        """
        prereqs: List[str] = []

        if agent_type in ("vuln",):
            prereqs.append("reconnaissance_completed")
            prereqs.append("services_identified")
        elif agent_type in ("exploit", "webapp"):
            prereqs.append("vulnerabilities_identified")
            prereqs.append("target_accessible")
        elif agent_type in ("privesc",):
            prereqs.append("initial_access_obtained")
            prereqs.append("session_active")
        elif agent_type in ("lateral_move",):
            prereqs.append("internal_network_mapped")
            prereqs.append("credentials_harvested")
        elif agent_type in ("persistence",):
            prereqs.append("privileged_access_obtained")
        elif agent_type in ("cred_access",):
            prereqs.append("session_active")
        elif agent_type in ("exfil",):
            prereqs.append("data_identified")
            prereqs.append("exfil_channel_available")
        elif agent_type in ("cleanup",):
            prereqs.append("mission_objectives_complete")
        elif agent_type in ("post_exploit",):
            prereqs.append("initial_access_obtained")

        return prereqs

    @staticmethod
    def _cache_key(goal: str, context: Dict[str, Any]) -> str:
        """Generate a deterministic cache key from goal + context fingerprint."""
        # Use mission_id if available for stability
        mission_id = context.get("mission_id", "")
        mission_phase = context.get("mission_phase", "")

        # Hash the goal + mission identifiers
        material = f"{goal}|{mission_id}|{mission_phase}"
        return hashlib.sha256(material.encode()).hexdigest()[:16]

    @staticmethod
    def _path_hash(path: List[AttackTreeNode]) -> str:
        """Hash a path for deduplication."""
        material = "->".join(f"{n.agent_type}:{n.goal[:30]}" for n in path)
        return hashlib.md5(material.encode()).hexdigest()  # noqa: S324 — not security-sensitive

    # ------------------------------------------------------------------
    # Tree utilities
    # ------------------------------------------------------------------

    def clear_cache(self) -> None:
        """Clear the internal tree and learning caches."""
        self._tree_cache.clear()
        self._learning_cache.clear()
        logger.debug("EGATS caches cleared")

    def get_tree_stats(self, root: AttackTreeNode) -> Dict[str, Any]:
        """Return summary statistics for a tree."""
        total_nodes = 0
        total_leaf_nodes = 0
        max_depth = 0
        agent_counts: Dict[str, int] = defaultdict(int)
        avg_difficulty = 0.0
        avg_evidence = 0.0
        difficulty_sum = 0.0
        evidence_sum = 0.0

        def _walk(node: AttackTreeNode, depth: int):
            nonlocal total_nodes, total_leaf_nodes, max_depth, difficulty_sum, evidence_sum
            total_nodes += 1
            max_depth = max(max_depth, depth)
            difficulty_sum += node.difficulty_score
            evidence_sum += node.evidence_confidence
            agent_counts[node.agent_type] += 1

            if not node.children:
                total_leaf_nodes += 1
            else:
                for child in node.children:
                    _walk(child, depth + 1)

        _walk(root, 0)

        if total_nodes > 0:
            avg_difficulty = difficulty_sum / total_nodes
            avg_evidence = evidence_sum / total_nodes

        return {
            "total_nodes": total_nodes,
            "leaf_nodes": total_leaf_nodes,
            "max_depth": max_depth,
            "avg_difficulty": round(avg_difficulty, 2),
            "avg_evidence_confidence": round(avg_evidence, 4),
            "agent_type_distribution": dict(agent_counts),
        }

    def serialize_tree(self, root: AttackTreeNode) -> Dict[str, Any]:
        """Serialize the full tree to a JSON-serializable dict."""
        return root.to_dict()

    def find_paths_by_agent(
        self, root: AttackTreeNode, agent_type: str
    ) -> List[List[AttackTreeNode]]:
        """Find all paths through the tree that include a specific agent_type."""
        results: List[List[AttackTreeNode]] = []

        def _dfs(node: AttackTreeNode, current_path: List[AttackTreeNode]):
            new_path = current_path + [node]
            if node.agent_type == agent_type and len(new_path) > 1:
                results.append(list(new_path))
            for child in node.children:
                _dfs(child, new_path)

        _dfs(root, [])
        return results
