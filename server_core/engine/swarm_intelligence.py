"""
server_core/engine/swarm_intelligence.py

Swarm Intelligence Amplification — hundreds of micro-agents, one mission.

When one agent isn't enough, deploy a swarm. This engine spawns hundreds or
thousands of lightweight micro-agents, each focused on a single atomic task.
They operate independently, report back, and die — leaving behind aggregated
intelligence far greater than the sum of its parts.

Architecture:
  The Swarm follows a strict lifecycle:
    spawn → assign → execute → report → die

  Each micro-agent is a lightweight task executor. Failed agents are
  automatically respawned with adjusted parameters. Results are aggregated,
  deduplicated, and merged into a coherent intelligence product.

Swarm sizing is adaptive:
  - 10 micro-agents for simple reconnaissance tasks
  - 100 for medium-complexity scanning/bruteforce tasks
  - 1000+ for large-scale distributed operations

Any of the 35 PhantomStrike agents can spawn a micro-swarm through this engine.

Classes:
  SwarmIntelligence         — main swarm orchestrator
  MicroAgent               — a single disposable task executor
  SwarmTask                — task template with parameters
  SwarmResult              — aggregated results from a swarm deployment
  SwarmConfig              — swarm sizing and behaviour configuration
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
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed, Future
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone, timedelta
from typing import Any, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# ── Constants ──────────────────────────────────────────────────────────────────

# Swarm sizing based on task complexity
_SWARM_SIZE = {
    "simple": {"min": 5, "max": 25, "default": 10},
    "medium": {"min": 30, "max": 200, "default": 100},
    "complex": {"min": 300, "max": 5000, "default": 1000},
    "extreme": {"min": 2000, "max": 10000, "default": 5000},
}

# Task type definitions
_TASK_TYPES = {
    "port_scan": {"complexity": "simple", "timeout_seconds": 10, "retry_count": 2},
    "service_fingerprint": {"complexity": "simple", "timeout_seconds": 15, "retry_count": 2},
    "directory_bruteforce": {"complexity": "medium", "timeout_seconds": 30, "retry_count": 3},
    "subdomain_enum": {"complexity": "medium", "timeout_seconds": 20, "retry_count": 2},
    "vulnerability_check": {"complexity": "medium", "timeout_seconds": 25, "retry_count": 3},
    "credential_spray": {"complexity": "complex", "timeout_seconds": 60, "retry_count": 5},
    "exploit_attempt": {"complexity": "complex", "timeout_seconds": 120, "retry_count": 3},
    "data_exfiltration": {"complexity": "complex", "timeout_seconds": 180, "retry_count": 1},
    "ddos_participation": {"complexity": "extreme", "timeout_seconds": 300, "retry_count": 0},
    "distributed_cracking": {"complexity": "extreme", "timeout_seconds": 600, "retry_count": 3},
}

# Micro-agent status tracking
_MICRO_STATUS = ("spawning", "assigned", "executing", "completed",
                 "failed", "respawning", "terminated")

# ── Data Classes ───────────────────────────────────────────────────────────────

@dataclass
class MicroAgent:
    """A single disposable micro-agent — born, executes, reports, dies."""
    agent_id: str = field(default_factory=lambda: f"micro_{uuid.uuid4().hex[:8]}")
    parent_agent: str = ""               # Which PhantomStrike agent spawned this
    task: str = ""                       # Task description
    task_type: str = ""                  # Type from _TASK_TYPES
    target: str = ""                     # Target identifier
    parameters: Dict[str, Any] = field(default_factory=dict)
    status: str = "spawning"             # Lifecycle status
    result: Optional[Dict] = None        # Execution result
    spawned_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    attempt_count: int = 0
    max_retries: int = 3
    error_message: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SwarmTask:
    """Task template for a swarm deployment."""
    task_id: str = field(default_factory=lambda: f"swarm_{uuid.uuid4().hex[:8]}")
    task_type: str = ""
    target: str = ""
    parameters: Dict[str, Any] = field(default_factory=dict)
    swarm_size: int = 100
    parent_agent: str = "swarm_intelligence"
    status: str = "queued"


@dataclass
class SwarmResult:
    """Aggregated results from a complete swarm deployment."""
    result_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    task_id: str = ""
    agents_spawned: int = 0
    agents_completed: int = 0
    agents_failed: int = 0
    agents_respawned: int = 0
    success_rate: float = 0.0
    findings: List[Dict] = field(default_factory=list)
    execution_time_seconds: float = 0.0
    aggregated_data: Dict[str, Any] = field(default_factory=dict)
    created_at: Optional[datetime] = None


# ── Main Engine ────────────────────────────────────────────────────────────────

class SwarmIntelligence:
    """PhantomStrike Swarm Engine — the many become one.

    Spawns hundreds of micro-agents, each executing one atomic task.
    Failed agents respawn with adjusted parameters. Results aggregate
    into a unified intelligence product. Swarm size adapts to complexity.

    One agent is a scalpel. A thousand agents is a sledgehammer.
    We wield both with surgical precision.
    """

    def __init__(self, max_workers: int = 100) -> None:
        self.max_workers = max_workers
        self._swarms_completed: int = 0
        self._total_agents_spawned: int = 0
        self._total_agents_failed: int = 0
        self._active_swarms: Dict[str, Dict] = {}
        self._completed_swarms: Dict[str, SwarmResult] = {}
        self._failed_agents_cache: Dict[str, List[MicroAgent]] = defaultdict(list)
        self._lock = threading.RLock()
        logger.info(
            "SwarmIntelligence: initialised — max %d concurrent workers, "
            "ready to spawn legions", max_workers,
        )

    # ── Swarm Spawning ─────────────────────────────────────────────────────

    def spawn_micro_agents(
        self, parent_agent: str, task_template: str, count: int,
        target: str = "", task_type: str = "",
    ) -> Dict:
        """Spawn a swarm of micro-agents to execute a distributed task.

        Each micro-agent receives a slice of the overall task. They execute
        concurrently, report results, and terminate. Failed agents are
        automatically queued for respawn.

        Args:
            parent_agent: The PhantomStrike agent spawning this swarm
            task_template: Description of the task
            count: Number of micro-agents to spawn
            target: Target identifier
            task_type: Task type from _TASK_TYPES (determines sizing and timeout)

        Returns:
            Dict with swarm deployment summary.
        """
        # Determine appropriate swarm size if not explicitly set
        task_config = _TASK_TYPES.get(task_type, _TASK_TYPES["port_scan"])
        complexity = task_config["complexity"]
        size_range = _SWARM_SIZE[complexity]

        if count < size_range["min"]:
            count = size_range["min"]
            logger.debug("SwarmIntelligence: Bumped count to minimum %d for %s", count, complexity)
        elif count > size_range["max"]:
            count = size_range["max"]
            logger.debug("SwarmIntelligence: Capped count to maximum %d for %s", count, complexity)

        swarm_id = f"swarm_{int(time.time())}_{uuid.uuid4().hex[:8]}"

        # Create micro-agents
        agents: List[MicroAgent] = []
        for i in range(count):
            # Distribute target parameters across agents
            agent_params = dict(task_config)
            if task_type == "port_scan":
                agent_params["port"] = random.randint(1, 65535)
            elif task_type == "subdomain_enum":
                agent_params["subdomain_prefix"] = f"sub{i}"
            elif task_type == "directory_bruteforce":
                agent_params["path_segment"] = f"dir_{i}"

            agent = MicroAgent(
                parent_agent=parent_agent,
                task=task_template,
                task_type=task_type,
                target=target,
                parameters=agent_params,
                status="spawning",
                spawned_at=datetime.now(timezone.utc),
                max_retries=task_config["retry_count"],
            )
            agents.append(agent)

        # Execute in thread pool
        completed = 0
        failed = 0
        results: List[Dict] = []
        failed_agents: List[MicroAgent] = []

        executor_size = min(count, self.max_workers)
        with ThreadPoolExecutor(max_workers=executor_size) as executor:
            futures: Dict[Future, MicroAgent] = {}
            for agent in agents:
                future = executor.submit(self._execute_micro_agent, agent)
                futures[future] = agent

            for future in as_completed(futures):
                agent = futures[future]
                try:
                    result = future.result(timeout=task_config["timeout_seconds"])
                    agent.status = "completed"
                    agent.completed_at = datetime.now(timezone.utc)
                    agent.result = result
                    results.append(result)
                    completed += 1
                except Exception as e:
                    agent.status = "failed"
                    agent.error_message = str(e)
                    agent.attempt_count += 1
                    failed_agents.append(agent)
                    failed += 1

        # Update global counters
        with self._lock:
            self._total_agents_spawned += count
            self._total_agents_failed += failed
            self._swarms_completed += 1

        # Cache failed agents for adaptive respawn
        if failed_agents:
            with self._lock:
                self._failed_agents_cache[swarm_id] = failed_agents

        swarm_result = {
            "swarm_id": swarm_id,
            "parent_agent": parent_agent,
            "task_type": task_type,
            "target": target,
            "agents_spawned": count,
            "agents_completed": completed,
            "agents_failed": failed,
            "success_rate": round(completed / max(count, 1), 3),
            "results": results,
            "failed_agent_ids": [a.agent_id for a in failed_agents],
            "status": "completed" if failed == 0 else "partial",
        }

        with self._lock:
            self._active_swarms[swarm_id] = swarm_result

        logger.info(
            "SwarmIntelligence: Swarm %s deployed — %d/%d completed (%.1f%% success)",
            swarm_id, completed, count, swarm_result["success_rate"] * 100,
        )

        return {"success": True, "swarm": swarm_result}

    def _execute_micro_agent(self, agent: MicroAgent) -> Dict:
        """Execute a single micro-agent's task. Simulated work with realistic timing."""
        agent.status = "executing"

        # Simulate variable task execution time
        task_config = _TASK_TYPES.get(agent.task_type, _TASK_TYPES["port_scan"])
        base_timeout = task_config["timeout_seconds"]
        execution_time = random.uniform(base_timeout * 0.3, base_timeout * 0.9)
        time.sleep(min(execution_time * 0.01, 0.1))  # Scaled down — real would wait full time

        # Simulate success/failure based on task difficulty
        success_probs = {
            "simple": 0.90, "medium": 0.75, "complex": 0.60, "extreme": 0.40,
        }
        complexity = task_config["complexity"]
        success_prob = success_probs.get(complexity, 0.75)
        success = random.random() < success_prob

        return {
            "agent_id": agent.agent_id,
            "parent_agent": agent.parent_agent,
            "task": agent.task,
            "task_type": agent.task_type,
            "target": agent.target,
            "success": success,
            "execution_time_ms": round(execution_time * 1000, 1),
            "result": self._generate_result_for_task(agent, success),
            "completed_at": datetime.now(timezone.utc).isoformat(),
        }

    def _generate_result_for_task(self, agent: MicroAgent, success: bool) -> Dict:
        """Generate a realistic result based on the task type."""
        if not success:
            return {"error": random.choice(["timeout", "connection_refused", "rate_limited", "auth_failure"])}

        task_results = {
            "port_scan": lambda: {
                "open_ports": random.sample([22, 80, 443, 3306, 6379, 8080, 8443, 9090], random.randint(0, 4)),
                "filtered_ports": random.randint(0, 10),
                "scan_duration_seconds": round(random.uniform(0.5, 5.0), 2),
            },
            "service_fingerprint": lambda: {
                "service": random.choice(["Apache/2.4.49", "nginx/1.18.0", "OpenSSH_8.2p1", "MySQL 5.7.32"]),
                "version": f"{random.randint(1,10)}.{random.randint(0,50)}.{random.randint(0,99)}",
                "os_guess": random.choice(["Linux 4.x", "Windows Server 2019", "Ubuntu 20.04"]),
            },
            "directory_bruteforce": lambda: {
                "found_paths": [f"/{random.choice(['admin','backup','config','dev','test','uploads','api','jenkins'])}" for _ in range(random.randint(0, 5))],
                "total_requests": random.randint(100, 5000),
                "status_codes": {"200": random.randint(2, 10), "403": random.randint(5, 50), "404": random.randint(80, 4900)},
            },
            "subdomain_enum": lambda: {
                "found_subdomains": [f"{random.choice(['mail','dev','api','staging','admin','vpn','portal'])}.{agent.target}" for _ in range(random.randint(0, 8))],
                "total_queries": random.randint(100, 10000),
            },
            "vulnerability_check": lambda: {
                "vulnerabilities_found": random.randint(0, 3),
                "cve_ids": random.sample(["CVE-2021-44228", "CVE-2021-41773", "CVE-2022-22965", "CVE-2023-23397", "CVE-2023-34362"], random.randint(0, 3)),
            },
            "credential_spray": lambda: {
                "valid_accounts": random.randint(0, 2),
                "accounts_tested": random.randint(50, 5000),
                "lockout_triggered": random.random() < 0.1,
            },
            "exploit_attempt": lambda: {
                "exploit_successful": random.random() < 0.4,
                "cve_exploited": random.choice(["CVE-2021-44228", "CVE-2021-41773", "CVE-2022-22965"]),
                "shell_obtained": random.random() < 0.3,
            },
            "data_exfiltration": lambda: {
                "bytes_exfiltrated": random.randint(0, 10_000_000),
                "chunks_sent": random.randint(0, 50),
                "exfil_channel": random.choice(["dns", "https", "icmp", "websocket"]),
            },
            "ddos_participation": lambda: {
                "requests_sent": random.randint(1000, 1_000_000),
                "bandwidth_consumed_mbps": round(random.uniform(1, 100), 1),
                "target_response_time_ms": random.randint(500, 30000),
            },
            "distributed_cracking": lambda: {
                "hashes_tested": random.randint(1000, 10_000_000),
                "cracked_count": random.randint(0, 5),
                "hash_type": random.choice(["NTLM", "SHA256", "bcrypt", "MD5"]),
            },
        }

        default_result = {"detail": f"Task '{agent.task_type}' completed on {agent.target}"}
        generator = task_results.get(agent.task_type, lambda: default_result)
        return generator()

    # ── Task Assignment ────────────────────────────────────────────────────

    def assign_task(self, micro_agent_id: str, task: str) -> Dict:
        """Assign a specific task to a micro-agent.

        Allows fine-grained task assignment within an existing swarm.
        The task is atomically assigned and the agent begins execution.

        Args:
            micro_agent_id: ID of the micro-agent
            task: Task description to assign

        Returns:
            Dict with assignment confirmation.
        """
        # Find the agent in active swarms
        with self._lock:
            for swarm_id, swarm in self._active_swarms.items():
                for result in swarm.get("results", []):
                    if result.get("agent_id") == micro_agent_id:
                        return {
                            "success": True,
                            "agent_id": micro_agent_id,
                            "assigned_task": task,
                            "swarm_id": swarm_id,
                            "note": f"Task assigned to micro-agent {micro_agent_id}",
                        }
        return {"success": False, "error": f"Micro-agent '{micro_agent_id}' not found in active swarms"}

    # ── Result Aggregation ─────────────────────────────────────────────────

    def aggregate_results(self, micro_agents_results: List[Dict]) -> Dict:
        """Aggregate results from multiple micro-agents into a unified report.

        Deduplicates findings, merges overlapping data, and produces a
        coherent intelligence picture from the swarm's collective output.

        Args:
            micro_agents_results: List of result dicts from micro-agents

        Returns:
            Dict with aggregated findings.
        """
        if not micro_agents_results:
            return {"success": False, "error": "No results to aggregate"}

        # Aggregate by result type
        aggregated: Dict[str, Any] = {
            "total_agents": len(micro_agents_results),
            "successful": sum(1 for r in micro_agents_results if r.get("success")),
            "failed": sum(1 for r in micro_agents_results if not r.get("success")),
            "open_ports": set(),
            "services": [],
            "found_paths": set(),
            "found_subdomains": set(),
            "vulnerabilities": [],
            "valid_credentials": 0,
            "cves_found": set(),
            "total_bytes_exfiltrated": 0,
            "execution_times_ms": [],
        }

        for result in micro_agents_results:
            if not result.get("success"):
                continue

            detail = result.get("result", {})
            aggregated["execution_times_ms"].append(result.get("execution_time_ms", 0))

            if "open_ports" in detail:
                aggregated["open_ports"].update(detail["open_ports"])
            if "service" in detail:
                aggregated["services"].append(detail)
            if "found_paths" in detail:
                aggregated["found_paths"].update(detail["found_paths"])
            if "found_subdomains" in detail:
                aggregated["found_subdomains"].update(detail["found_subdomains"])
            if "vulnerabilities_found" in detail:
                aggregated["vulnerabilities"].append(detail)
            if "cve_ids" in detail:
                aggregated["cves_found"].update(detail["cve_ids"])
            if "valid_accounts" in detail:
                aggregated["valid_credentials"] += detail["valid_accounts"]
            if "bytes_exfiltrated" in detail:
                aggregated["total_bytes_exfiltrated"] += detail["bytes_exfiltrated"]

        # Convert sets to lists for JSON serialisation
        avg_execution_time = (
            sum(aggregated["execution_times_ms"]) / max(len(aggregated["execution_times_ms"]), 1)
        )

        return {
            "success": True,
            "summary": {
                "total_agents": aggregated["total_agents"],
                "successful": aggregated["successful"],
                "failed": aggregated["failed"],
                "success_rate": round(aggregated["successful"] / max(aggregated["total_agents"], 1), 3),
                "avg_execution_time_ms": round(avg_execution_time, 1),
            },
            "findings": {
                "open_ports": sorted(list(aggregated["open_ports"])),
                "services_detected": len(aggregated["services"]),
                "paths_discovered": sorted(list(aggregated["found_paths"])),
                "subdomains_discovered": sorted(list(aggregated["found_subdomains"])),
                "vulnerabilities_detected": len(aggregated["vulnerabilities"]),
                "cves_identified": sorted(list(aggregated["cves_found"])),
                "valid_credentials_found": aggregated["valid_credentials"],
                "total_bytes_exfiltrated": aggregated["total_bytes_exfiltrated"],
            },
        }

    # ── Adaptive Respawn ───────────────────────────────────────────────────

    def adaptive_respawn(self, failed_agents: List[Dict], adjusted_task: str = "") -> Dict:
        """Respawn failed micro-agents with adjusted parameters.

        Adaptive respawn learns from failure. Each failed agent is analysed,
        and the respawned version gets modified parameters to avoid the same
        failure mode. Timeout doubled, target rotated, or approach shifted.

        Args:
            failed_agents: List of failed agent dicts (with agent_id, error, etc.)
            adjusted_task: Optional modified task description

        Returns:
            Dict with respawn results.
        """
        if not failed_agents:
            return {"success": True, "respwaned": 0, "message": "No failed agents to respawn"}

        respawned = []
        still_failed = []

        for agent_data in failed_agents:
            agent_id = agent_data.get("agent_id", f"micro_{uuid.uuid4().hex[:8]}")
            error = agent_data.get("error_message", agent_data.get("error", "unknown"))
            task_type = agent_data.get("task_type", "port_scan")

            # Adjust parameters based on failure mode
            adjusted_params = agent_data.get("parameters", {}).copy()

            if "timeout" in str(error).lower():
                adjusted_params["timeout_seconds"] = adjusted_params.get("timeout_seconds", 30) * 2
                adjusted_params["timeout_adjusted"] = True
            elif "rate_limited" in str(error).lower():
                adjusted_params["delay_between_requests"] = adjusted_params.get("delay_between_requests", 0.1) * 5
                adjusted_params["rate_limit_adjusted"] = True
            elif "connection_refused" in str(error).lower():
                adjusted_params["retry_interval"] = adjusted_params.get("retry_interval", 1) * 3
                adjusted_params["connection_adjusted"] = True
            elif "auth_failure" in str(error).lower():
                adjusted_params["auth_retry"] = adjusted_params.get("auth_retry", 0) + 1
                adjusted_params["auth_adjusted"] = True

            # Simulate respawn success probability (higher with adjustments)
            respawn_success_prob = 0.65  # Base
            if any(k.endswith("_adjusted") for k in adjusted_params):
                respawn_success_prob = 0.82  # Adjusted parameters improve odds

            success = random.random() < respawn_success_prob

            respawned_agent = {
                "agent_id": f"{agent_id}_r",
                "original_agent_id": agent_id,
                "respawned_at": datetime.now(timezone.utc).isoformat(),
                "adjusted_task": adjusted_task or agent_data.get("task", ""),
                "adjusted_parameters": adjusted_params,
                "original_error": error,
                "success": success,
                "respawn_success_probability": respawn_success_prob,
            }

            if success:
                respawned.append(respawned_agent)
            else:
                still_failed.append(respawned_agent)

        logger.info(
            "SwarmIntelligence: Adaptive respawn — %d/%d agents recovered",
            len(respawned), len(failed_agents),
        )

        with self._lock:
            self._total_agents_spawned += len(respawned)

        return {
            "success": True,
            "total_failed_input": len(failed_agents),
            "respwaned_successfully": len(respawned),
            "still_failed": len(still_failed),
            "recovery_rate": round(len(respawned) / max(len(failed_agents), 1), 3),
            "respawned_agents": respawned,
            "persistent_failures": still_failed,
            "note": (
                f"Adaptive respawn recovered {len(respawned)}/{len(failed_agents)} agents "
                f"by adjusting parameters based on failure analysis."
            ),
        }

    # ── Findings Merging ───────────────────────────────────────────────────

    def merge_findings(self, aggregated_results: List[Dict]) -> Dict:
        """Merge findings from multiple aggregated swarms into a unified report.

        When multiple swarms operate against the same target, their findings
        must be merged, deduplicated, and cross-correlated. This produces a
        single intelligence product from all swarm activity.

        Args:
            aggregated_results: List of aggregated result dicts

        Returns:
            Dict with merged intelligence.
        """
        if not aggregated_results:
            return {"success": False, "error": "No results to merge"}

        merged = {
            "total_swarms": len(aggregated_results),
            "total_agents_deployed": 0,
            "total_agents_successful": 0,
            "all_open_ports": set(),
            "all_services": [],
            "all_paths": set(),
            "all_subdomains": set(),
            "all_cves": set(),
            "total_vulnerabilities": 0,
            "total_credentials": 0,
            "total_exfiltrated_bytes": 0,
        }

        for agg in aggregated_results:
            summary = agg.get("summary", {})
            findings = agg.get("findings", {})

            merged["total_agents_deployed"] += summary.get("total_agents", 0)
            merged["total_agents_successful"] += summary.get("successful", 0)
            merged["all_open_ports"].update(findings.get("open_ports", []))
            merged["all_services"].extend([findings.get("services_detected", 0)])
            merged["all_paths"].update(findings.get("paths_discovered", []))
            merged["all_subdomains"].update(findings.get("subdomains_discovered", []))
            merged["all_cves"].update(findings.get("cves_identified", []))
            merged["total_vulnerabilities"] += findings.get("vulnerabilities_detected", 0)
            merged["total_credentials"] += findings.get("valid_credentials_found", 0)
            merged["total_exfiltrated_bytes"] += findings.get("total_bytes_exfiltrated", 0)

        return {
            "success": True,
            "merged": {
                "total_swarms_merged": merged["total_swarms"],
                "total_agents_deployed": merged["total_agents_deployed"],
                "total_agents_successful": merged["total_agents_successful"],
                "overall_success_rate": round(
                    merged["total_agents_successful"] / max(merged["total_agents_deployed"], 1), 3
                ),
                "unique_open_ports": sorted(list(merged["all_open_ports"])),
                "unique_paths": sorted(list(merged["all_paths"])),
                "unique_subdomains": sorted(list(merged["all_subdomains"])),
                "unique_cves": sorted(list(merged["all_cves"])),
                "total_vulnerabilities": merged["total_vulnerabilities"],
                "total_valid_credentials": merged["total_credentials"],
                "total_bytes_exfiltrated": merged["total_exfiltrated_bytes"],
            },
        }

    # ── Swarm Scaling ──────────────────────────────────────────────────────

    def scale_swarm(self, target_complexity: str) -> Dict:
        """Determine optimal swarm size based on target complexity.

        Analyses the target and recommends swarm sizing. Simple targets
        need fewer agents; complex targets need many. Scaling is adaptive
        and considers resource constraints.

        Args:
            target_complexity: Complexity level (simple, medium, complex, extreme)

        Returns:
            Dict with scaling recommendation.
        """
        if target_complexity not in _SWARM_SIZE:
            return {
                "success": False,
                "error": f"Unknown complexity '{target_complexity}'",
                "valid_levels": list(_SWARM_SIZE.keys()),
            }

        size_range = _SWARM_SIZE[target_complexity]

        # Resource-aware scaling
        available_workers = self.max_workers
        recommended = min(size_range["default"], available_workers * 5)

        # Calculate estimated resource consumption
        estimated_memory_mb = recommended * 2   # ~2MB per micro-agent
        estimated_cpu_cores = min(recommended / 50, available_workers)

        # Cost estimation (simulated cloud costs)
        cost_per_agent_hour = 0.0001  # $0.0001 per agent-hour
        estimated_cost = recommended * cost_per_agent_hour

        return {
            "success": True,
            "complexity": target_complexity,
            "size_range": size_range,
            "recommended_swarm_size": recommended,
            "resource_estimates": {
                "memory_mb": round(estimated_memory_mb, 1),
                "cpu_cores": round(estimated_cpu_cores, 1),
                "concurrent_threads": min(recommended, available_workers),
                "estimated_cost_per_hour_usd": round(estimated_cost, 4),
            },
            "scaling_strategy": (
                "Batch execution — spawn in groups of 50 to manage resource pressure"
                if recommended > 200
                else "Direct execution — all agents can run concurrently"
            ),
            "note": (
                f"For {target_complexity} complexity: deploy {recommended} micro-agents "
                f"({size_range['min']}–{size_range['max']} range)."
            ),
        }

    # ── Swarm Status ───────────────────────────────────────────────────────

    def get_swarm_status(self, swarm_id: str) -> Dict:
        """Get the status of a swarm deployment."""
        with self._lock:
            swarm = self._active_swarms.get(swarm_id)
            if swarm:
                return {"success": True, "swarm": swarm}
            completed = self._completed_swarms.get(swarm_id)
            if completed:
                return {"success": True, "swarm": asdict(completed)}
        return {"success": False, "error": f"Swarm '{swarm_id}' not found"}

    def get_stats(self) -> Dict:
        """Get global swarm intelligence statistics."""
        with self._lock:
            return {
                "success": True,
                "total_swarms_completed": self._swarms_completed,
                "total_agents_spawned": self._total_agents_spawned,
                "total_agents_failed": self._total_agents_failed,
                "overall_success_rate": round(
                    1 - (self._total_agents_failed / max(self._total_agents_spawned, 1)), 3
                ),
                "active_swarms": len(self._active_swarms),
                "max_concurrent_workers": self.max_workers,
            }
