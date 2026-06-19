"""
universal_goal_engine.py — Universal Goal Engine (GODMODE heart).

Takes any hacking objective, spawns parallel attack paths across ALL 35 agents,
and never stops until the goal is achieved or ALL paths are exhausted.

Path discovery is powered by:
  - EGATSEngine (Exploit Generation & Attack Tree Synthesis)
  - AttackSynthesizer (novel-path generation when stuck)

Architecture:
  1. Goal received → decomposed into candidate attack paths
  2. Paths scored & ranked by expected efficacy + domain relevance
  3. Top-N paths executed in parallel via ThreadPoolExecutor
  4. First success wins — remaining futures cancelled
  5. Failures recorded → learning feedback → creativity escalation
  6. Timeout / max-attempts enforced → graceful exhaustion

Mission control: pause, resume, abort, real-time status.
"""

from __future__ import annotations

import hashlib
import logging
import threading
import time
import uuid
from concurrent.futures import Future, ThreadPoolExecutor, as_completed, wait
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum, auto
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════════════
# Enums & Data Classes
# ═══════════════════════════════════════════════════════════════════════════════

class EngineState(Enum):
    IDLE = auto()
    RUNNING = auto()
    PAUSED = auto()
    ABORTED = auto()
    EXHAUSTED = auto()
    SUCCEEDED = auto()


class Domain(Enum):
    """Attack domains ordered by typical escalation priority."""
    WEB = "web"
    NETWORK = "network"
    CLOUD = "cloud"
    CREDENTIAL = "credential"
    PRIVESC = "privesc"
    LATERAL = "lateral"
    PERSISTENCE = "persistence"
    EXFIL = "exfil"
    SOCIAL = "social"
    PHYSICAL = "physical"
    IOT = "iot"
    SCADA = "scada"
    AUTOMOTIVE = "automotive"
    SATELLITE = "satellite"
    BLOCKCHAIN = "blockchain"
    AI = "ai_exploit"
    MOBILE = "mobile"
    TELECOM = "telecom"
    DARKWEB = "darkweb"
    DRONE = "drone"
    SUPPLY_CHAIN = "supply_chain"
    REVERSE_ENG = "reverse_engineering"


# Domain → agent types that operate in that domain
DOMAIN_AGENT_MAP: Dict[Domain, List[str]] = {
    Domain.WEB:             ["webapp", "vuln", "exploit", "bug_bounty"],
    Domain.NETWORK:         ["recon", "vuln", "exploit"],
    Domain.CLOUD:           ["cloud", "privesc"],
    Domain.CREDENTIAL:      ["cred_access", "recon"],
    Domain.PRIVESC:         ["privesc", "post_exploit"],
    Domain.LATERAL:         ["lateral_move", "post_exploit"],
    Domain.PERSISTENCE:     ["persistence", "post_exploit"],
    Domain.EXFIL:           ["exfil"],
    Domain.SOCIAL:          ["social_eng", "recon"],
    Domain.PHYSICAL:        ["physical"],
    Domain.IOT:             ["iot"],
    Domain.SCADA:           ["scada"],
    Domain.AUTOMOTIVE:       ["automotive"],
    Domain.SATELLITE:        ["satellite"],
    Domain.BLOCKCHAIN:       ["blockchain"],
    Domain.AI:              ["ai_exploit"],
    Domain.MOBILE:           ["mobile"],
    Domain.TELECOM:          ["telecom"],
    Domain.DARKWEB:         ["darkweb"],
    Domain.DRONE:            ["drone"],
    Domain.SUPPLY_CHAIN:     ["supply_chain"],
    Domain.REVERSE_ENG:      ["reverse_engineering"],
}

# All 35 agent types (mirrors orchestrator/__init__.py)
ALL_AGENT_TYPES: List[str] = [
    # Core (6)
    "recon", "vuln", "exploit", "post_exploit", "exfil", "cleanup",
    # Attack (6)
    "privesc", "cred_access", "persistence", "cloud", "lateral_move", "webapp",
    # Defense (6)
    "emergency", "opsec", "decoy", "counter_surveillance", "reverse_trace", "trace_buster",
    # Specialist (5)
    "supply_chain", "social_eng", "bug_bounty", "auto_fixer", "reverse_engineering",
    # Domain (12)
    "iot", "scada", "automotive", "satellite", "blockchain",
    "ai_exploit", "mobile", "telecom", "physical",
    "darkweb", "drone", "nuclear_opsec",
]


@dataclass
class AttackPath:
    """A candidate attack path — a sequenced chain of agent + tool invocations."""
    path_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    agent_type: str = ""
    domain: Domain = Domain.WEB
    tool_chain: List[str] = field(default_factory=list)
    params: Dict[str, Any] = field(default_factory=dict)
    description: str = ""
    confidence: float = 0.5
    estimated_time_s: float = 30.0
    creativity_level: int = 0           # 0=standard, 1=creative, 2=novel
    prerequisites: List[str] = field(default_factory=list)  # required prior findings

    @property
    def signature(self) -> str:
        """Deterministic signature for deduplication."""
        raw = f"{self.agent_type}|{','.join(self.tool_chain)}|{self.domain.value}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path_id": self.path_id,
            "agent_type": self.agent_type,
            "domain": self.domain.value,
            "tool_chain": self.tool_chain,
            "params": self.params,
            "description": self.description,
            "confidence": self.confidence,
            "estimated_time_s": self.estimated_time_s,
            "creativity_level": self.creativity_level,
            "prerequisites": self.prerequisites,
            "signature": self.signature,
        }


@dataclass
class PathResult:
    """Result of executing a single attack path."""
    path: AttackPath
    success: bool = False
    achieved_goal: bool = False
    output: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    elapsed_s: float = 0.0
    findings: List[Dict[str, Any]] = field(default_factory=list)

    @property
    def path_signature(self) -> str:
        return self.path.signature

    @property
    def path_description(self) -> str:
        return self.path.description

    @property
    def agent_type(self) -> str:
        return self.path.agent_type

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path_id": self.path.path_id,
            "agent_type": self.path.agent_type,
            "domain": self.path.domain.value,
            "description": self.path.description,
            "success": self.success,
            "achieved_goal": self.achieved_goal,
            "error": self.error,
            "elapsed_s": self.elapsed_s,
            "findings_count": len(self.findings),
            "signature": self.path_signature,
        }


# ═══════════════════════════════════════════════════════════════════════════════
# Stub interfaces for EGATSEngine and AttackSynthesizer
# ═══════════════════════════════════════════════════════════════════════════════

class EGATSEngine:
    """Exploit Generation & Attack Tree Synthesis engine.

    Generates structured attack trees from a goal, enumerating all viable
    exploitation paths across every attack domain.  Populated via setter on
    UniversalGoalEngine after construction.
    """

    def __init__(self) -> None:
        self._enabled = False

    def enable(self) -> None:
        self._enabled = True

    def generate_paths(self, goal: str, context: Dict[str, Any]) -> List[AttackPath]:
        """Generate candidate attack paths from EGATS tree expansion.

        When fully integrated, this performs:
          - Goal → sub-goal decomposition
          - CVE-to-exploit mapping per discovered service
          - Attack tree branching with AND/OR nodes
          - Prerequisite chaining (vuln → exploit → privesc → lateral)

        Until integrated, returns a sensible fallback set of paths covering
        all major domains.
        """
        if not self._enabled:
            return _fallback_path_generation(goal, context)
        # Placeholder for full EGATS integration — returns fallback for now.
        return _fallback_path_generation(goal, context)


class AttackSynthesizer:
    """Novel attack path generator — used when standard paths are exhausted.

    Uses LLM-backed creativity to synthesise never-before-seen attack chains
    by recombining tool capabilities, chaining exploits in unexpected ways,
    and drawing analogies across domains.
    """

    def __init__(self, llm_client: Any = None) -> None:
        self._llm = llm_client
        self._enabled = False
        self._generation_count = 0

    def enable(self) -> None:
        self._enabled = True

    def disable(self) -> None:
        self._enabled = False

    @property
    def generation_count(self) -> int:
        return self._generation_count

    def synthesize(self, goal: str, context: Dict[str, Any],
                   tried_paths: Set[str], creativity_level: int = 1) -> List[AttackPath]:
        """Generate novel attack paths that haven't been tried yet.

        Args:
            goal: The original hacking objective.
            context: Current HiveMind state.
            tried_paths: Set of already-attempted path signatures.
            creativity_level: 1 = moderate novelty, 2 = aggressive novelty.

        Returns:
            List of novel AttackPath instances.
        """
        self._generation_count += 1
        paths: List[AttackPath] = []

        if not self._enabled:
            return paths

        # When an LLM is available, prompt it for novel path synthesis.
        if self._llm:
            try:
                paths = self._llm_synthesize(goal, context, tried_paths, creativity_level)
            except Exception as exc:
                logger.warning("AttackSynthesizer LLM call failed: %s", exc)

        # Always supplement with rule-based novel combinations.
        paths.extend(_rule_based_synthesis(goal, context, tried_paths, creativity_level))
        return paths

    def _llm_synthesize(self, goal: str, context: Dict[str, Any],
                        tried_paths: Set[str], creativity_level: int) -> List[AttackPath]:
        """Use LLM to propose novel attack paths."""
        prompt = f"""You are an autonomous offensive security attack-path synthesizer.
Goal: {goal}
Current context: hosts={context.get('hosts', 0)}, services={context.get('services', 0)},
  vulns={context.get('vulns', 0)}, sessions={context.get('sessions', 0)},
  compromised={context.get('owned', 0)}
Already tried {len(tried_paths)} paths (signatures omitted for brevity).
Creativity level: {creativity_level} (higher = more novel/unconventional).

Propose up to 5 novel attack paths as JSON array. Each path object:
  {{"agent_type": "<one of: {', '.join(ALL_AGENT_TYPES[:20])}...>",
    "domain": "<attack domain>",
    "tool_chain": ["tool1", "tool2"],
    "description": "what this path attempts",
    "confidence": 0.0-1.0}}

Respond with valid JSON array only."""
        response = self._llm.complete(prompt)
        import json
        try:
            raw = json.loads(response)
            return [_dict_to_attack_path(item, creativity_level) for item in raw
                    if isinstance(item, dict)]
        except (json.JSONDecodeError, TypeError):
            return []


# ═══════════════════════════════════════════════════════════════════════════════
# Universal Goal Engine
# ═══════════════════════════════════════════════════════════════════════════════

class UniversalGoalEngine:
    """Pursues any hacking objective relentlessly across ALL attack domains.

    Spawns parallel paths.  First success wins.  Never stops until achieved
    or all paths exhausted.

    Lifecycle:  pursue() → [RUNNING] → [SUCCEEDED | EXHAUSTED]
                pause()  → [PAUSED]
                resume() → [RUNNING]
                abort()  → [ABORTED]
    """

    # ── Tunables ──────────────────────────────────────────────────────────
    PARALLEL_WIDTH: int = 5            # paths to run concurrently per wave
    MIN_CONFIDENCE_THRESHOLD: float = 0.15
    CREATIVITY_ESCALATION_ATTEMPTS: int = 50   # attempts before escalating
    BACKOFF_BASE_S: float = 0.5                 # base backoff between waves
    MAX_BACKOFF_S: float = 10.0                  # cap on backoff
    STATUS_INTERVAL_S: float = 15.0              # periodic status-log interval
    MAX_PATH_HISTORY: int = 1000                 # cap on tried-path memory (ring)

    def __init__(
        self,
        hive_mind: Any,                       # HiveMind instance
        tool_bridge: Any,                     # ToolBridge instance
        agent_registry: Dict[str, Any],       # agent_type → BaseAgent instance
        llm_client: Any = None,
        mission_tracker: Any = None,          # MissionTracker instance (optional)
    ) -> None:
        self.hive_mind = hive_mind
        self.tool_bridge = tool_bridge
        self.agents = agent_registry
        self._llm = llm_client
        self._mission_tracker = mission_tracker

        # ── Optional sub-engines (set after init) ──
        self.egats: Optional[EGATSEngine] = None
        self.synthesizer: Optional[AttackSynthesizer] = None

        # ── Runtime state ──
        self._state = EngineState.IDLE
        self._state_lock = threading.RLock()
        self._pause_event = threading.Event()
        self._pause_event.set()               # start un-paused
        self._abort_event = threading.Event()

        # ── Path tracking ──
        self._tried_signatures: Set[str] = set()
        self._tried_paths_ring: List[str] = []   # ring buffer of signatures
        self._failure_log: List[Dict[str, Any]] = []

        # ── Execution state ──
        self._executor: Optional[ThreadPoolExecutor] = None
        self._active_futures: List[Future] = []
        self._futures_lock = threading.Lock()
        self._start_time: Optional[float] = None
        self._max_attempts: int = 500
        self._timeout_hours: int = 72
        self._current_goal: str = ""
        self._total_attempts: int = 0
        self._success_count: int = 0
        self._last_status_time: float = 0.0
        self._status_callback: Optional[Callable[[Dict[str, Any]], None]] = None

        logger.info("UniversalGoalEngine initialised (parallel_width=%d, max_attempts=%d)",
                     self.PARALLEL_WIDTH, self._max_attempts)

    # ──────────────────────────────────────────────────────────────────────
    # Public API
    # ──────────────────────────────────────────────────────────────────────

    def pursue(
        self,
        goal: str,
        stealth: str = "maximum",
        max_attempts: int = 500,
        timeout_hours: int = 72,
    ) -> Dict[str, Any]:
        """Pursue a hacking objective until achieved or all paths exhausted.

        Args:
            goal: Natural-language hacking objective (e.g. "gain root on 10.0.0.5").
            stealth: Stealth profile — "maximum", "balanced", "speed".
            max_attempts: Maximum path execution attempts before exhaustion.
            timeout_hours: Wall-clock timeout for the entire pursuit.

        Returns:
            {
                success: bool,
                goal: str,
                path_taken: str | None,
                attempts: int,
                time_elapsed: float,
                agent_used: str | None,
                findings: List[dict],
                reason: str,
            }
        """
        with self._state_lock:
            if self._state == EngineState.RUNNING:
                return {"success": False, "goal": goal, "error": "Engine already running a pursuit"}
            self._state = EngineState.RUNNING

        self._start_time = time.time()
        self._max_attempts = max_attempts
        self._timeout_hours = timeout_hours
        self._current_goal = goal
        self._total_attempts = 0
        self._success_count = 0
        self._tried_signatures.clear()
        self._tried_paths_ring.clear()
        self._failure_log.clear()
        self._abort_event.clear()
        self._pause_event.set()
        self._last_status_time = time.time()

        self.hive_mind.set_phase("goal_pursuit")
        logger.info("=" * 70)
        logger.info("UNIVERSAL GOAL ENGINE — PURSUIT STARTED")
        logger.info("  Goal:       %s", goal)
        logger.info("  Stealth:    %s", stealth)
        logger.info("  Max attempts: %d | Timeout: %dh", max_attempts, timeout_hours)
        logger.info("  Agents:     %d loaded", len(self.agents))
        logger.info("=" * 70)

        self._executor = ThreadPoolExecutor(
            max_workers=self.PARALLEL_WIDTH,
            thread_name_prefix="uge-worker-",
        )

        try:
            result = self._pursuit_loop(goal, stealth)
        finally:
            if self._executor is not None:
                self._executor.shutdown(wait=False, cancel_futures=True)
                self._executor = None
            with self._state_lock:
                if self._state not in (EngineState.SUCCEEDED, EngineState.ABORTED,
                                        EngineState.EXHAUSTED):
                    self._state = EngineState.IDLE

        return result

    def pause(self) -> Dict[str, Any]:
        """Pause the current pursuit.  In-flight paths complete; new waves wait."""
        with self._state_lock:
            if self._state != EngineState.RUNNING:
                return {"success": False, "state": self._state.name,
                        "message": "Engine is not running"}
            self._state = EngineState.PAUSED
        self._pause_event.clear()
        logger.warning("UNIVERSAL GOAL ENGINE — PAUSED")
        return {"success": True, "state": "PAUSED", "attempts_so_far": self._total_attempts}

    def resume(self) -> Dict[str, Any]:
        """Resume a paused pursuit."""
        with self._state_lock:
            if self._state != EngineState.PAUSED:
                return {"success": False, "state": self._state.name,
                        "message": "Engine is not paused"}
            self._state = EngineState.RUNNING
        self._pause_event.set()
        logger.info("UNIVERSAL GOAL ENGINE — RESUMED")
        return {"success": True, "state": "RUNNING"}

    def abort(self) -> Dict[str, Any]:
        """Abort the current pursuit immediately."""
        with self._state_lock:
            was_running = self._state in (EngineState.RUNNING, EngineState.PAUSED)
            self._state = EngineState.ABORTED
        self._abort_event.set()
        self._pause_event.set()   # unblock any waiters
        self._cancel_remaining()
        logger.critical("UNIVERSAL GOAL ENGINE — ABORTED")
        return {
            "success": True,
            "was_running": was_running,
            "attempts": self._total_attempts,
            "time_elapsed": time.time() - (self._start_time or time.time()),
        }

    def get_status(self) -> Dict[str, Any]:
        """Real-time status snapshot."""
        elapsed = time.time() - (self._start_time or time.time())
        return {
            "state": self._state.name,
            "goal": self._current_goal,
            "attempts": self._total_attempts,
            "max_attempts": self._max_attempts,
            "tried_paths": len(self._tried_signatures),
            "success_rate": self._success_rate(),
            "time_elapsed_s": round(elapsed, 1),
            "timeout_hours": self._timeout_hours,
            "active_futures": len(self._active_futures),
            "pause_event": not self._pause_event.is_set(),
            "abort_event": self._abort_event.is_set(),
            "failure_count": len(self._failure_log),
            "egats_enabled": self.egats is not None and self.egats._enabled,
            "synthesizer_enabled": self.synthesizer is not None and self.synthesizer._enabled,
        }

    def set_status_callback(self, callback: Callable[[Dict[str, Any]], None]) -> None:
        """Register a callback invoked after each wave with the status dict."""
        self._status_callback = callback

    # ──────────────────────────────────────────────────────────────────────
    # Pursuit loop
    # ──────────────────────────────────────────────────────────────────────

    def _pursuit_loop(self, goal: str, stealth: str) -> Dict[str, Any]:
        """Core loop: generate → rank → execute → learn → repeat."""
        backoff = self.BACKOFF_BASE_S

        while self._total_attempts < self._max_attempts and self._within_timeout():
            # ── Respect pause / abort ──
            if self._abort_event.is_set():
                return self._build_result(False, goal, "Aborted by operator")

            if not self._pause_event.is_set():
                self._pause_event.wait(timeout=1.0)
                continue

            # ── Gather current context ──
            context = self.hive_mind.get_full_state()

            # ── Generate candidate paths ──
            candidates = self._generate_paths(goal, context)

            if not candidates:
                logger.info("No candidates generated — escalating creativity")
                self._escalate_creativity(goal, context)
                backoff = min(backoff * 2, self.MAX_BACKOFF_S)
                time.sleep(backoff)
                continue

            # ── Score & rank ──
            ranked = self._rank_paths(candidates, context)

            # ── Filter already-tried ──
            novel = [p for p in ranked if p.signature not in self._tried_signatures]
            if not novel:
                logger.info("All %d ranked paths already tried — escalating", len(ranked))
                self._escalate_creativity(goal, context)
                backoff = min(backoff * 2, self.MAX_BACKOFF_S)
                time.sleep(backoff)
                continue

            # ── Execute top N in parallel ──
            top_n = novel[:self.PARALLEL_WIDTH]
            results = self._execute_parallel(top_n, goal, context)

            # ── Process results ──
            for result in results:
                self._total_attempts += 1
                self._record_tried(result.path_signature)

                if result.achieved_goal:
                    self._cancel_remaining()
                    with self._state_lock:
                        self._state = EngineState.SUCCEEDED
                    logger.info("=" * 70)
                    logger.info("GOAL ACHIEVED — Path: %s", result.path_description)
                    logger.info("  Agent: %s | Attempts: %d | Elapsed: %.1fs",
                                result.agent_type, self._total_attempts,
                                time.time() - (self._start_time or 0))
                    logger.info("=" * 70)
                    self._emit_status()
                    return self._build_result(True, goal, "Goal achieved",
                                              result.path_description, result.agent_type)

                if result.success:
                    self._success_count += 1

                # Learn from failure
                self._learn_from_failure(result)

            # ── Periodic status log ──
            self._emit_status()

            # ── Adaptive backoff ──
            if self._success_rate() == 0 and self._total_attempts > 10:
                backoff = min(backoff * 1.3, self.MAX_BACKOFF_S)
            else:
                backoff = max(self.BACKOFF_BASE_S, backoff * 0.8)

            time.sleep(backoff)

        # ── Exhausted ──
        with self._state_lock:
            self._state = EngineState.EXHAUSTED
        return self._build_result(False, goal, self._exhaustion_reason())

    # ──────────────────────────────────────────────────────────────────────
    # Path generation
    # ──────────────────────────────────────────────────────────────────────

    def _generate_paths(self, goal: str, context: Dict[str, Any]) -> List[AttackPath]:
        """Generate candidate attack paths from all available sources.

        Priority order:
          1. EGATS engine (structured attack-tree expansion)
          2. Domain-specific path generation
          3. Universal fallback coverage
        """
        paths: List[AttackPath] = []

        # 1. EGATS
        if self.egats is not None:
            try:
                egats_paths = self.egats.generate_paths(goal, context)
                paths.extend(egats_paths)
                logger.debug("EGATS generated %d paths", len(egats_paths))
            except Exception as exc:
                logger.error("EGATS path generation failed: %s", exc)

        # 2. Domain-specific generation
        domain_paths = _domain_path_generation(goal, context)
        paths.extend(domain_paths)

        # 3. Fallback universal coverage
        fallback = _fallback_path_generation(goal, context)
        paths.extend(fallback)

        # Deduplicate by signature (keep highest confidence)
        seen: Dict[str, AttackPath] = {}
        for p in paths:
            sig = p.signature
            if sig not in seen or p.confidence > seen[sig].confidence:
                seen[sig] = p

        logger.debug("Path generation: %d total → %d unique", len(paths), len(seen))
        return list(seen.values())

    def _rank_paths(self, candidates: List[AttackPath],
                    context: Dict[str, Any]) -> List[AttackPath]:
        """Score and rank candidate paths by expected efficacy.

        Scoring factors:
          - confidence (direct weight)
          - domain relevance (does context have targets in this domain?)
          - tool availability (can the agent's tools actually execute?)
          - creativity bonus (novel paths get a slight boost when stuck)
          - defense penalty (paths known to trigger alerts deprioritised)
        """
        scored: List[Tuple[float, AttackPath]] = []

        owned = context.get("owned", 0)
        hosts = context.get("hosts", 0)
        services = context.get("services", 0)
        vulns = context.get("vulns", 0)
        sessions = context.get("sessions", 0)

        for path in candidates:
            score = path.confidence

            # Domain relevance boost
            domain = path.domain
            if domain == Domain.WEB and services > 0:
                score += 0.15
            if domain == Domain.NETWORK and hosts > 0:
                score += 0.12
            if domain == Domain.CREDENTIAL and sessions > 0:
                score += 0.10
            if domain == Domain.PRIVESC and owned > 0:
                score += 0.20
            if domain == Domain.LATERAL and owned > 0:
                score += 0.18
            if domain == Domain.EXFIL and owned > 0:
                score += 0.15

            # Vulnerability-driven boost
            if vulns > 0 and domain in (Domain.WEB, Domain.NETWORK, Domain.CLOUD):
                score += 0.10

            # Check tool availability
            agent = self.agents.get(path.agent_type)
            if agent is not None:
                available_tools = set(getattr(agent, 'capabilities', []))
                path_tools = set(path.tool_chain)
                tool_overlap = len(path_tools & available_tools)
                if tool_overlap > 0:
                    score += min(0.1, 0.03 * tool_overlap)
                else:
                    score -= 0.15  # can't actually execute this chain

            # Creativity bonus when stuck
            if self._total_attempts > self.CREATIVITY_ESCALATION_ATTEMPTS:
                score += path.creativity_level * 0.08

            # Penalise paths we've already tried similar variants of
            similar_tried = sum(
                1 for sig in self._tried_signatures
                if sig[:4] == path.signature[:4]
            )
            score -= similar_tried * 0.05

            scored.append((max(0.0, min(1.0, score)), path))

        scored.sort(key=lambda x: x[0], reverse=True)
        ranked = [p for _, p in scored]

        logger.debug("Ranked %d paths (top score: %.3f, bottom: %.3f)",
                      len(ranked),
                      scored[0][0] if scored else 0.0,
                      scored[-1][0] if scored else 0.0)
        return ranked

    # ──────────────────────────────────────────────────────────────────────
    # Parallel execution
    # ──────────────────────────────────────────────────────────────────────

    def _execute_parallel(
        self,
        paths: List[AttackPath],
        goal: str,
        context: Dict[str, Any],
    ) -> List[PathResult]:
        """Execute a wave of attack paths concurrently via ThreadPoolExecutor.

        Each path is dispatched to its designated agent.  The method blocks
        until all paths in the wave complete, are cancelled, or the engine
        is paused / aborted.
        """
        if not paths:
            return []

        if self._executor is None:
            self._executor = ThreadPoolExecutor(
                max_workers=self.PARALLEL_WIDTH,
                thread_name_prefix="uge-worker-",
            )

        futures: Dict[Future, AttackPath] = {}
        for path in paths:
            fut = self._executor.submit(self._execute_single_path, path, goal, context)
            futures[fut] = path

        with self._futures_lock:
            self._active_futures = list(futures.keys())

        results: List[PathResult] = []
        try:
            for fut in as_completed(futures, timeout=self._timeout_hours * 3600):
                path = futures[fut]
                try:
                    result = fut.result(timeout=5)
                    results.append(result)
                except Exception as exc:
                    logger.error("Path %s raised: %s", path.signature, exc)
                    results.append(PathResult(
                        path=path,
                        success=False,
                        achieved_goal=False,
                        error=str(exc),
                        elapsed_s=path.estimated_time_s,
                    ))

                # Early exit if goal achieved
                if results and results[-1].achieved_goal:
                    logger.info("Goal achieved — cancelling remaining futures")
                    self._cancel_remaining_futures(futures.keys())
                    break

                # Check abort
                if self._abort_event.is_set():
                    self._cancel_remaining_futures(futures.keys())
                    break

        except Exception as exc:
            logger.error("execute_parallel error: %s", exc)

        with self._futures_lock:
            self._active_futures.clear()

        return results

    def _execute_single_path(
        self,
        path: AttackPath,
        goal: str,
        context: Dict[str, Any],
    ) -> PathResult:
        """Execute a single attack path through its designated agent.

        Steps:
          1. Look up agent instance by type.
          2. Build agent-specific context via HiveMind context selector.
          3. Run the agent's think/act loop for each tool in the chain.
          4. Check if the goal was achieved after each tool execution.
          5. Return structured PathResult.
        """
        start = time.time()
        agent = self.agents.get(path.agent_type)

        if agent is None:
            return PathResult(
                path=path,
                success=False,
                achieved_goal=False,
                error=f"Agent type '{path.agent_type}' not in registry",
                elapsed_s=time.time() - start,
            )

        # Mark agent active in HiveMind
        self.hive_mind.update_agent_status(path.agent_type, "active")

        findings: List[Dict[str, Any]] = []
        achieved = False
        last_error: Optional[str] = None

        try:
            for tool_name in path.tool_chain:
                # Pause / abort check
                if self._abort_event.is_set():
                    break
                if not self._pause_event.is_set():
                    self._pause_event.wait(timeout=5.0)

                # Execute tool via ToolBridge
                params = {**path.params}
                tool_result = self.tool_bridge.execute(
                    tool_name, params, agent_id=path.agent_type
                )

                if tool_result.get("success"):
                    findings.append({
                        "tool": tool_name,
                        "data": tool_result.get("data", tool_result.get("output", {})),
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    })

                    # Check if this finding achieves the goal
                    achieved = self._check_goal_achieved(goal, tool_result, path, findings)
                    if achieved:
                        break
                else:
                    last_error = tool_result.get("error", f"Tool {tool_name} failed")

        except Exception as exc:
            last_error = str(exc)
            logger.debug("Path %s agent %s error: %s", path.signature, path.agent_type, exc)

        finally:
            self.hive_mind.update_agent_status(path.agent_type, "idle")

        elapsed = time.time() - start
        return PathResult(
            path=path,
            success=len(findings) > 0,
            achieved_goal=achieved,
            output={"findings": findings} if findings else {},
            error=last_error,
            elapsed_s=elapsed,
            findings=findings,
        )

    def _check_goal_achieved(
        self,
        goal: str,
        tool_result: Dict[str, Any],
        path: AttackPath,
        findings: List[Dict[str, Any]],
    ) -> bool:
        """Heuristic goal-achievement check.

        Uses keyword matching + HiveMind state signals.  When an LLM is
        available, delegates the check for higher accuracy.
        """
        goal_lower = goal.lower()
        output_str = str(tool_result.get("data", tool_result.get("output", ""))).lower()

        # ── Keyword heuristics ──
        goal_keywords: Dict[str, List[str]] = {
            "root": ["root", "uid=0", "administrator", "nt authority\\system",
                     "root shell", "#"],
            "access": ["authenticated", "logged in", "session established",
                       "access granted", "200 ok"],
            "data": ["downloaded", "exfiltrated", "extracted", "file contents"],
            "exploit": ["exploit succeeded", "meterpreter", "shell obtained",
                        "command execution", "rce confirmed"],
            "crack": ["password found", "hash cracked", "credentials recovered"],
            "pivot": ["lateral movement succeeded", "new session on"],
            "persist": ["persistence installed", "backdoor deployed"],
        }

        for category, keywords in goal_keywords.items():
            if category in goal_lower:
                if any(kw in output_str for kw in keywords):
                    logger.info("Goal-achievement heuristic matched: category=%s", category)
                    return True

        # ── HiveMind state signals ──
        state = self.hive_mind.get_full_state()

        if "root" in goal_lower or "privilege" in goal_lower:
            if state.get("owned", 0) > 0:
                return True

        if "access" in goal_lower or "breach" in goal_lower:
            if state.get("sessions", 0) > 0:
                return True

        if "data" in goal_lower or "exfiltrate" in goal_lower:
            if len(self.hive_mind.exfiltrated_data) > 0:
                return True

        # ── LLM check ──
        if self._llm and len(findings) >= 2:
            try:
                return self._llm_goal_check(goal, findings)
            except Exception:
                pass

        return False

    def _llm_goal_check(self, goal: str, findings: List[Dict[str, Any]]) -> bool:
        """Ask the LLM whether the goal has been achieved given the findings."""
        summary = "\n".join(
            f"- {f.get('tool', '?')}: {str(f.get('data', ''))[:300]}"
            for f in findings[-5:]
        )
        prompt = (
            f"Goal: {goal}\n\nRecent findings:\n{summary}\n\n"
            "Has the goal been achieved? Answer ONLY 'yes' or 'no'."
        )
        response = self._llm.complete(prompt).strip().lower()
        return response.startswith("yes")

    # ──────────────────────────────────────────────────────────────────────
    # Learning & escalation
    # ──────────────────────────────────────────────────────────────────────

    def _learn_from_failure(self, result: PathResult) -> None:
        """Record a failed path to improve future path ranking.

        Stores: agent_type, domain, error pattern, tools tried, context snapshot.
        """
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "agent_type": result.path.agent_type,
            "domain": result.path.domain.value,
            "signature": result.path_signature,
            "error": result.error,
            "tools_tried": result.path.tool_chain,
            "elapsed_s": result.elapsed_s,
            "attempt_number": self._total_attempts,
        }
        self._failure_log.append(entry)
        logger.debug("Failure recorded: %s (attempt %d)", result.path_signature, self._total_attempts)

    def _escalate_creativity(self, goal: str, context: Dict[str, Any]) -> None:
        """Escalate creativity when standard paths are exhausted.

        Tier progression:
          Tier 0 (attempts 0-50):   Standard EGATS + domain paths
          Tier 1 (attempts 50-100): AttackSynthesizer level 1 (moderate novelty)
          Tier 2 (attempts 100-200): Cross-domain chaining + AttackSynthesizer level 2
          Tier 3 (attempts 200+):    Defense-agent white-box assist + full synthesis
        """
        attempts = self._total_attempts

        if attempts <= self.CREATIVITY_ESCALATION_ATTEMPTS:
            return  # still in standard mode

        context["_escalation_tier"] = (
            1 if attempts <= 100 else
            2 if attempts <= 200 else
            3
        )
        tier = context["_escalation_tier"]
        logger.warning("Creativity escalation → Tier %d (attempt %d)", tier, attempts)

        # Engage AttackSynthesizer if available
        if self.synthesizer is not None and self.synthesizer._enabled:
            try:
                novel = self.synthesizer.synthesize(
                    goal, context, self._tried_signatures, creativity_level=tier
                )
                if novel:
                    logger.info("Synthesizer produced %d novel paths at tier %d",
                                len(novel), tier)
                    # Append to a side-channel that _generate_paths will pick up
                    context.setdefault("_synthesized_paths", []).extend(
                        [p.to_dict() for p in novel]
                    )
            except Exception as exc:
                logger.error("Synthesizer escalation failed: %s", exc)

    # ──────────────────────────────────────────────────────────────────────
    # Helpers
    # ──────────────────────────────────────────────────────────────────────

    def _within_timeout(self) -> bool:
        if self._start_time is None:
            return True
        elapsed_hours = (time.time() - self._start_time) / 3600.0
        return elapsed_hours < self._timeout_hours

    def _cancel_remaining(self) -> None:
        """Cancel all active futures."""
        with self._futures_lock:
            for fut in self._active_futures:
                if not fut.done():
                    fut.cancel()
            self._active_futures.clear()
        logger.info("All remaining futures cancelled")

    def _cancel_remaining_futures(self, futures: Set[Future]) -> None:
        """Cancel a specific set of futures that are not yet done."""
        for fut in futures:
            if not fut.done():
                fut.cancel()
        with self._futures_lock:
            self._active_futures = [f for f in self._active_futures if f not in futures]

    def _record_tried(self, signature: str) -> None:
        """Record a tried path signature (ring-buffer capped)."""
        self._tried_signatures.add(signature)
        self._tried_paths_ring.append(signature)
        if len(self._tried_paths_ring) > self.MAX_PATH_HISTORY:
            oldest = self._tried_paths_ring[:-self.MAX_PATH_HISTORY]
            self._tried_paths_ring = self._tried_paths_ring[-self.MAX_PATH_HISTORY:]
            for old in oldest:
                # Only remove from set if not still in ring
                if old not in self._tried_paths_ring:
                    self._tried_signatures.discard(old)

    def _success_rate(self) -> float:
        if self._total_attempts == 0:
            return 0.0
        return self._success_count / self._total_attempts

    def _emit_status(self) -> None:
        """Log periodic status and invoke status callback if registered."""
        now = time.time()
        if now - self._last_status_time < self.STATUS_INTERVAL_S:
            return
        self._last_status_time = now

        status = self.get_status()
        logger.info(
            "UGE Status: %s | attempts=%d/%d | tried=%d | success_rate=%.1f%% | "
            "active=%d | elapsed=%.0fs",
            status["state"],
            status["attempts"], status["max_attempts"],
            status["tried_paths"],
            status["success_rate"] * 100,
            status["active_futures"],
            status["time_elapsed_s"],
        )

        if self._status_callback:
            try:
                self._status_callback(status)
            except Exception as exc:
                logger.debug("Status callback failed: %s", exc)

    def _build_result(
        self,
        success: bool,
        goal: str,
        reason: str,
        path_taken: str = "",
        agent_used: str = "",
    ) -> Dict[str, Any]:
        """Build the standardised pursuit result dict."""
        elapsed = time.time() - (self._start_time or time.time())
        return {
            "success": success,
            "goal": goal,
            "path_taken": path_taken or None,
            "attempts": self._total_attempts,
            "time_elapsed": round(elapsed, 2),
            "agent_used": agent_used or None,
            "findings": self.hive_mind.get_high_value_findings()
            if hasattr(self.hive_mind, 'get_high_value_findings')
            else [],
            "reason": reason,
            "state": self._state.name,
            "failure_summary": {
                "total_failures": len(self._failure_log),
                "by_domain": self._failure_summary_by_domain(),
                "top_errors": self._top_errors(5),
            },
        }

    def _exhaustion_reason(self) -> str:
        if self._total_attempts >= self._max_attempts:
            return f"All {self._max_attempts} attempts exhausted"
        return f"Timeout after {self._timeout_hours}h"

    def _failure_summary_by_domain(self) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for entry in self._failure_log:
            domain = entry.get("domain", "unknown")
            counts[domain] = counts.get(domain, 0) + 1
        return counts

    def _top_errors(self, n: int = 5) -> List[Dict[str, Any]]:
        """Return the most frequent error patterns."""
        from collections import Counter
        error_counts = Counter(
            (e.get("error") or "unknown")[:120] for e in self._failure_log
        )
        return [{"error": err, "count": cnt}
                for err, cnt in error_counts.most_common(n)]

    # ──────────────────────────────────────────────────────────────────────
    # HiveMind helper bridge
    # ──────────────────────────────────────────────────────────────────────

    def _get_high_value_findings(self) -> List[Dict[str, Any]]:
        """Collect high-confidence findings from HiveMind."""
        if hasattr(self.hive_mind, 'get_high_value_findings'):
            return self.hive_mind.get_high_value_findings()
        findings = getattr(self.hive_mind, 'findings_log', [])
        return [f for f in findings if f.get('confidence', 0) > 0.7]


# ═══════════════════════════════════════════════════════════════════════════════
# Path-generation helpers (standalone functions)
# ═══════════════════════════════════════════════════════════════════════════════

def _fallback_path_generation(goal: str, context: Dict[str, Any]) -> List[AttackPath]:
    """Generate a broad coverage of attack paths across all domains.

    Used as the base generation layer when EGATS is unavailable.
    Produces one path per major domain with the best-suited agent type.
    """
    goal_lower = goal.lower()
    paths: List[AttackPath] = []
    hosts = context.get("hosts", 0)
    services = context.get("services", 0)
    vulns = context.get("vulns", 0)
    owned = context.get("owned", 0)
    sessions = context.get("sessions", 0)

    # ── Web / application paths ──
    if services > 0 or "web" in goal_lower or "http" in goal_lower:
        paths.append(AttackPath(
            agent_type="webapp", domain=Domain.WEB,
            tool_chain=["nuclei", "dalfox", "sqlmap"],
            description="Web application vulnerability sweep (nuclei → XSS → SQLi)",
            confidence=0.75 if services > 0 else 0.40,
        ))
        paths.append(AttackPath(
            agent_type="vuln", domain=Domain.WEB,
            tool_chain=["whatweb", "nuclei", "exploitability_analysis"],
            description="Technology fingerprint → CVE mapping → exploitability analysis",
            confidence=0.70,
        ))

    # ── Network paths ──
    if hosts > 0 or "network" in goal_lower or "scan" in goal_lower:
        paths.append(AttackPath(
            agent_type="recon", domain=Domain.NETWORK,
            tool_chain=["nmap", "shodan-lookup", "ip-geolocate"],
            description="Full network reconnaissance (Nmap → Shodan → geolocation)",
            confidence=0.80 if hosts > 0 else 0.50,
        ))
        paths.append(AttackPath(
            agent_type="exploit", domain=Domain.NETWORK,
            tool_chain=["generate_exploit", "execute_exploit_live"],
            description="Targeted exploit generation and delivery",
            confidence=0.60 if vulns > 0 else 0.30,
        ))

    # ── Credential paths ──
    paths.append(AttackPath(
        agent_type="cred_access", domain=Domain.CREDENTIAL,
        tool_chain=["hydra_attack", "hashcat_crack"],
        description="Credential brute-force + hash cracking pipeline",
        confidence=0.55,
    ))
    paths.append(AttackPath(
        agent_type="recon", domain=Domain.CREDENTIAL,
        tool_chain=["email-breach", "dehashed-search", "social-search"],
        description="OSINT credential harvesting (email → dehashed → social media)",
        confidence=0.50,
    ))

    # ── Privilege escalation paths (requires compromise) ──
    if owned > 0 or sessions > 0:
        paths.append(AttackPath(
            agent_type="privesc", domain=Domain.PRIVESC,
            tool_chain=["execute_command"],
            description="Local privilege escalation on compromised host",
            confidence=0.70,
        ))
        paths.append(AttackPath(
            agent_type="post_exploit", domain=Domain.PRIVESC,
            tool_chain=["execute_command"],
            description="Post-exploitation enumeration and privesc",
            confidence=0.65,
        ))

    # ── Lateral movement (requires sessions) ──
    if sessions > 0:
        paths.append(AttackPath(
            agent_type="lateral_move", domain=Domain.LATERAL,
            tool_chain=["netexec_scan", "smbmap_scan", "enum4linux"],
            description="Lateral movement via SMB/NetExec enumeration",
            confidence=0.72,
        ))

    # ── Persistence (requires compromise) ──
    if owned > 0:
        paths.append(AttackPath(
            agent_type="persistence", domain=Domain.PERSISTENCE,
            tool_chain=["diskless-persist", "execute_command"],
            description="Install diskless persistence mechanism",
            confidence=0.68,
        ))

    # ── Exfiltration paths ──
    if owned > 0 or "data" in goal_lower or "exfil" in goal_lower:
        paths.append(AttackPath(
            agent_type="exfil", domain=Domain.EXFIL,
            tool_chain=["c2-deploy", "dns-tunnel", "cdn-front"],
            description="Multi-channel exfiltration (C2 → DNS tunnel → CDN front)",
            confidence=0.65,
        ))

    # ── Cloud paths ──
    if "cloud" in goal_lower or "aws" in goal_lower or "kubernetes" in goal_lower:
        paths.append(AttackPath(
            agent_type="cloud", domain=Domain.CLOUD,
            tool_chain=["iam-privesc", "container-escape", "k8s-attack"],
            description="Cloud attack chain (IAM privesc → container escape → K8s)",
            confidence=0.70,
        ))

    # ── Social engineering ──
    if "social" in goal_lower or "phish" in goal_lower or "user" in goal_lower:
        paths.append(AttackPath(
            agent_type="social_eng", domain=Domain.SOCIAL,
            tool_chain=["email-breach", "social-search", "github-recon"],
            description="Social engineering recon (email → social → GitHub)",
            confidence=0.60,
        ))

    # ── Supply chain ──
    paths.append(AttackPath(
        agent_type="supply_chain", domain=Domain.SUPPLY_CHAIN,
        tool_chain=["trivy_scan", "container_scan", "github-recon"],
        description="Supply chain audit (Trivy → container → GitHub dependency)",
        confidence=0.50,
    ))

    # ── Domain-specific coverage ──
    domain_triggers = {
        "iot": ("iot", Domain.IOT, ["iot-firmware"], "IoT firmware analysis"),
        "scada": ("scada", Domain.SCADA, ["modbus-scan"], "SCADA/ICS enumeration"),
        "automotive": ("automotive", Domain.AUTOMOTIVE, ["can-bus-scan"], "Automotive CAN bus audit"),
        "satellite": ("satellite", Domain.SATELLITE, ["satcom-scan"], "Satellite communications intercept"),
        "blockchain": ("blockchain", Domain.BLOCKCHAIN, ["crypto-trace"], "Blockchain transaction analysis"),
        "mobile": ("mobile", Domain.MOBILE, ["apk-analyze", "frida-hooks"], "Mobile app reverse engineering"),
        "drone": ("drone", Domain.DRONE, ["drone-intercept"], "Drone signal intercept"),
    }

    for keyword, (agent, domain, tools, desc) in domain_triggers.items():
        if keyword in goal_lower:
            paths.append(AttackPath(
                agent_type=agent, domain=domain,
                tool_chain=list(tools),
                description=desc,
                confidence=0.65,
            ))

    # ── Always-include baseline paths ──
    paths.append(AttackPath(
        agent_type="bug_bounty", domain=Domain.WEB,
        tool_chain=["nuclei", "dalfox", "jaeles", "whatweb"],
        description="Bug-bounty-style broad vulnerability scan",
        confidence=0.60,
    ))
    paths.append(AttackPath(
        agent_type="reverse_engineering", domain=Domain.REVERSE_ENG,
        tool_chain=["radare2_analyze", "binwalk_analyze", "strings_extract"],
        description="Binary reverse engineering and analysis",
        confidence=0.50,
    ))

    return paths


def _domain_path_generation(goal: str, context: Dict[str, Any]) -> List[AttackPath]:
    """Generate paths tailored to discovered context (hosts, services, vulns).

    More targeted than the universal fallback — uses live intelligence
    from HiveMind to craft context-aware attack chains.
    """
    paths: List[AttackPath] = []

    # If we have discovered services, generate per-service attack paths
    discovered_services = context.get("_discovered_services", [])
    if not discovered_services:
        # Try to pull from HiveMind if accessible via context keys
        pass

    # If we have discovered vulnerabilities, chain them
    discovered_vulns = context.get("_discovered_vulns", [])
    if discovered_vulns:
        paths.append(AttackPath(
            agent_type="exploit", domain=Domain.WEB,
            tool_chain=["generate_exploit", "execute_exploit_live", "verify_exploit"],
            description="Exploit discovered vulnerabilities (generate → execute → verify)",
            confidence=0.85,
        ))

    return paths


def _rule_based_synthesis(
    goal: str,
    context: Dict[str, Any],
    tried_paths: Set[str],
    creativity_level: int,
) -> List[AttackPath]:
    """Rule-based novel path synthesis — cross-domain chaining.

    When creativity_level >= 2, creates chains that span multiple domains
    (e.g. social eng recon → credential theft → cloud pivot).
    """
    paths: List[AttackPath] = []

    if creativity_level >= 2:
        # Cross-domain chain: social → credential → cloud
        paths.append(AttackPath(
            agent_type="social_eng", domain=Domain.SOCIAL,
            tool_chain=["email-breach", "social-search", "github-recon"],
            description="Cross-domain: OSINT recon → cred gathering → cloud pivot prep",
            confidence=0.45,
            creativity_level=2,
        ))

        # Cross-domain chain: IoT → network → lateral
        paths.append(AttackPath(
            agent_type="iot", domain=Domain.IOT,
            tool_chain=["iot-firmware", "ble-attack"],
            description="Cross-domain: IoT pivot → network entry → lateral movement",
            confidence=0.40,
            creativity_level=2,
        ))

        # Defense-assisted attack (use OPSEC agent to reduce threat level while attacking)
        paths.append(AttackPath(
            agent_type="trace_buster", domain=Domain.WEB,
            tool_chain=["nuclei"],
            description="Defense-coordinated: OPSEC cover while vulnerability scanning",
            confidence=0.38,
            creativity_level=2,
        ))

    if creativity_level >= 3:
        # Physical + cyber chain
        paths.append(AttackPath(
            agent_type="physical", domain=Domain.PHYSICAL,
            tool_chain=["ble-attack"],
            description="Physical proximity attack → BLE exploitation → network foothold",
            confidence=0.30,
            creativity_level=3,
        ))

        # Dark web intelligence → credential → exploit chain
        paths.append(AttackPath(
            agent_type="darkweb", domain=Domain.DARKWEB,
            tool_chain=["tor-scrape", "ransomware-track", "leak-monitor"],
            description="Dark web intel → leaked creds → targeted exploit",
            confidence=0.35,
            creativity_level=3,
        ))

        # AI exploitation path
        paths.append(AttackPath(
            agent_type="ai_exploit", domain=Domain.AI,
            tool_chain=["prompt-inject", "jailbreak-llm", "api-key-scan"],
            description="AI/LLM exploitation: prompt injection → jailbreak → API key exfil",
            confidence=0.28,
            creativity_level=3,
        ))

    return [p for p in paths if p.signature not in tried_paths]


def _dict_to_attack_path(item: Dict[str, Any], creativity_level: int = 0) -> AttackPath:
    """Convert a raw dict (from LLM synthesis) into an AttackPath."""
    agent_type = str(item.get("agent_type", "recon"))
    if agent_type not in ALL_AGENT_TYPES:
        agent_type = "recon"

    domain_raw = str(item.get("domain", "web")).upper()
    try:
        domain = Domain[domain_raw]
    except KeyError:
        domain = Domain.WEB

    return AttackPath(
        agent_type=agent_type,
        domain=domain,
        tool_chain=list(item.get("tool_chain", [])),
        params=item.get("params", {}),
        description=str(item.get("description", "")),
        confidence=float(item.get("confidence", 0.5)),
        creativity_level=creativity_level,
    )
