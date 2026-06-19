"""
server_core/orchestrator/orchestrator_agent.py

Autonomous multi-agent hacking orchestrator.

Takes a single user prompt and decomposes it into mission phases,
dispatching each to a specialized AI agent. Agents share a session
memory for context. Adaptive strategy — if one approach fails,
tries alternatives before failing the phase.
"""

import logging
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Any, Dict, List, Optional

from server_core import ModernVisualEngine
from server_core.orchestrator.agent_base import BaseAgent
from server_core.orchestrator.agent_protocol import AgentContractIssue, validate_agent_registry
from server_core.orchestrator.agent_registry import build_agent_registry
from server_core.orchestrator.agent_memory import AgentMemory
from server_core.orchestrator.mission_tracker import MissionTracker
from server_core.orchestrator.task_decomposer import TaskDecomposer

logger = logging.getLogger(__name__)


class OrchestratorAgent:
    """Autonomous multi-agent hacking orchestrator.

    Takes a single user prompt and decomposes it into mission phases,
    dispatching each to a specialized AI agent (Recon, Vuln, Exploit,
    Post-Exploit, Exfil, Cleanup). Agents share a session memory for
    context. Adaptive strategy — if one approach fails, tries alternatives.
    """

    MAX_RETRIES_PER_PHASE = 2
    DEFAULT_STEALTH = "maximum"

    def __init__(self):
        self.agents: Dict[str, BaseAgent] = build_agent_registry()
        self._validate_agent_contracts()
        self.memory = AgentMemory()
        self.decomposer = TaskDecomposer()
        self.tracker = MissionTracker()
        self._active_missions: Dict[str, Dict[str, Any]] = {}
        self._pause_flags: Dict[str, bool] = {}
        self._abort_flags: Dict[str, bool] = {}
        self._executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="orchestrator-")

    def _validate_agent_contracts(self) -> None:
        issues = validate_agent_registry(self.agents)
        non_base_agents = [
            name for name, agent in self.agents.items()
            if not isinstance(agent, BaseAgent)
        ]
        if non_base_agents:
            issues.extend(
                AgentContractIssue(
                    name=name,
                    reason="registered agent is not BaseAgent-backed",
                )
                for name in non_base_agents
            )
        if issues:
            details = "; ".join(f"{issue.name}: {issue.reason}" for issue in issues)
            raise TypeError(f"Invalid orchestrator agent registry: {details}")

    def execute_mission(
        self,
        prompt: str,
        stealth: str = "maximum",
        mission_id: Optional[str] = None,
        max_phase_duration: int = 600,
    ) -> Dict[str, Any]:
        """Execute a complete autonomous hacking mission.

        Args:
            prompt: The user's natural-language mission description.
            stealth: Stealth level (minimum, medium, maximum, ghost).
            mission_id: Optional pre-assigned mission ID.
            max_phase_duration: Max seconds per phase before timeout.

        Returns:
            Dict with mission_id, status, phases, report.
        """
        # --- Bootstrap mission ---
        mission_id = mission_id or f"mission_{uuid.uuid4().hex[:12]}"
        start_time = time.time()
        self._pause_flags[mission_id] = False
        self._abort_flags[mission_id] = False

        logger.info(
            "%s",
            ModernVisualEngine.create_section_header(
                f"ORCHESTRATOR — MISSION START", "🎯", "CRIMSON"
            ),
        )
        logger.info(
            "Mission %s | Prompt: %s | Stealth: %s",
            mission_id,
            prompt,
            stealth,
        )

        # --- 1. Decompose prompt into mission phases ---
        try:
            phases = self.decomposer.decompose(prompt)
        except Exception as exc:
            logger.error("Decomposition failed: %s", exc)
            return {
                "mission_id": mission_id,
                "success": False,
                "error": f"Task decomposition failed: {str(exc)}",
                "phases": [],
                "report": "",
            }

        self.tracker.start_mission(mission_id, prompt, stealth, phases)

        # --- 2. Execute each phase through the appropriate agent ---
        results: List[Dict[str, Any]] = []
        overall_success = True

        for idx, phase in enumerate(phases):
            if self._abort_flags.get(mission_id):
                logger.warning("Mission %s aborted at phase %d/%d", mission_id, idx + 1, len(phases))
                phase["status"] = "aborted"
                phase["result"] = {"success": False, "error": "Mission aborted by operator"}
                results.append(phase)
                overall_success = False
                break

            while self._pause_flags.get(mission_id):
                time.sleep(1)

            phase_name = phase.get("agent_type", "unknown")
            phase_label = phase.get("label", phase_name)
            logger.info(
                "%s",
                ModernVisualEngine.create_section_header(
                    f"PHASE {idx+1}/{len(phases)} — {phase_label.upper()}",
                    "⚡",
                    "CYBER_ORANGE",
                ),
            )

            agent = self.agents.get(phase_name)
            if agent is None:
                msg = f"No agent registered for type '{phase_name}'"
                logger.error(msg)
                phase["status"] = "failed"
                phase["result"] = {"success": False, "error": msg}
                results.append(phase)
                overall_success = False
                continue

            context = self.memory.get_context()

            # Execute phase with retries / strategy adaptation
            phase_result = self._execute_phase_with_retry(
                agent=agent,
                phase=phase,
                context=context,
                mission_id=mission_id,
                max_duration=max_phase_duration,
            )

            self.memory.store(
                key=phase.get("id", f"phase_{idx}"),
                agent_type=phase_name,
                data=phase_result,
            )

            phase["status"] = "success" if phase_result.get("success") else "failed"
            phase["result"] = phase_result
            results.append(phase)

            if not phase_result.get("success"):
                overall_success = False
                # Non-critical phases may allow continuation
                if phase.get("critical", True):
                    logger.warning(
                        "Critical phase '%s' failed — halting mission %s", phase_label, mission_id
                    )
                    break

            self.tracker.update_phase(mission_id, phase["id"], phase_result)

        # --- 3. Generate final mission report ---
        elapsed = time.time() - start_time
        report = self.tracker.generate_report(mission_id, results, overall_success, elapsed)

        self._active_missions[mission_id] = {
            "mission_id": mission_id,
            "prompt": prompt,
            "stealth": stealth,
            "success": overall_success,
            "phases": results,
            "report": report,
            "started_at": datetime.utcnow().isoformat(),
            "elapsed_seconds": round(elapsed, 2),
        }

        logger.info(
            "%s",
            ModernVisualEngine.create_section_header(
                f"ORCHESTRATOR — MISSION COMPLETE | {'SUCCESS' if overall_success else 'PARTIAL/FAILED'}",
                "🏁",
                "SUCCESS" if overall_success else "ERROR",
            ),
        )

        return {
            "mission_id": mission_id,
            "success": overall_success,
            "phases": results,
            "report": report,
            "elapsed_seconds": round(elapsed, 2),
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _execute_phase_with_retry(
        self,
        agent: Any,
        phase: Dict[str, Any],
        context: Dict[str, Any],
        mission_id: str,
        max_duration: int,
    ) -> Dict[str, Any]:
        """Run a phase with retry + strategy adaptation on failure."""
        attempts = 0
        adapted_phase = dict(phase)
        result: Dict[str, Any] = {}

        while attempts <= self.MAX_RETRIES_PER_PHASE:
            if self._abort_flags.get(mission_id):
                return {"success": False, "error": "Aborted"}

            try:
                result = agent.execute(adapted_phase, context)
                attempts += 1

                if result.get("success"):
                    return result

                logger.warning(
                    "Phase '%s' attempt %d failed: %s",
                    phase.get("label", ""),
                    attempts,
                    result.get("error", "unknown"),
                )

                # Attempt strategy adaptation
                adapted = self._adapt_strategy(phase, result, attempts)
                if adapted:
                    logger.info(
                        "Adapting strategy for phase '%s': %s",
                        phase.get("label", ""),
                        adapted.get("strategy_change", "fallback"),
                    )
                    adapted_phase = adapted
                else:
                    break

            except Exception as exc:
                attempts += 1
                logger.exception("Phase '%s' crashed on attempt %d", phase.get("label", ""), attempts)
                result = {"success": False, "error": str(exc)}
                adapted = self._adapt_strategy(phase, result, attempts)
                if not adapted:
                    break
                adapted_phase = adapted

        return result

    def _adapt_strategy(
        self,
        phase: Dict[str, Any],
        last_result: Dict[str, Any],
        attempt: int,
    ) -> Optional[Dict[str, Any]]:
        """Generate an adapted phase spec when the original approach fails.

        Returns None when no further adaptation is feasible.
        """
        adaptations: List[Dict[str, str]] = [
            {"strategy_change": "increase_timeout", "timeout_multiplier": 2},
            {"strategy_change": "reduce_evasion", "stealth": "minimum"},
            {"strategy_change": "brute_force_fallback", "technique": "exhaustive"},
            {"strategy_change": "use_alternative_tool", "prefer": "builtin"},
        ]

        if attempt >= len(adaptations):
            return None

        adapted = dict(phase)
        adapted.update(adaptations[attempt])
        adapted["_attempt"] = attempt + 1
        return adapted

    # ------------------------------------------------------------------
    # Mission lifecycle control
    # ------------------------------------------------------------------

    def pause_mission(self, mission_id: str) -> Dict[str, Any]:
        """Pause an active mission."""
        self._pause_flags[mission_id] = True
        logger.info("Mission %s paused", mission_id)
        return {"mission_id": mission_id, "status": "paused"}

    def resume_mission(self, mission_id: str) -> Dict[str, Any]:
        """Resume a paused mission."""
        self._pause_flags[mission_id] = False
        logger.info("Mission %s resumed", mission_id)
        return {"mission_id": mission_id, "status": "running"}

    def abort_mission(self, mission_id: str) -> Dict[str, Any]:
        """Emergency abort — stops all phase execution."""
        self._abort_flags[mission_id] = True
        self._pause_flags[mission_id] = False
        logger.warning("Mission %s ABORTED by operator", mission_id)
        return {"mission_id": mission_id, "status": "aborted"}

    def get_mission(self, mission_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve stored mission data."""
        return self._active_missions.get(mission_id)

    def list_missions(self) -> List[Dict[str, Any]]:
        """List all tracked missions."""
        return [
            {
                "mission_id": m["mission_id"],
                "prompt": m["prompt"],
                "success": m["success"],
                "started_at": m["started_at"],
                "elapsed_seconds": m.get("elapsed_seconds", 0),
            }
            for m in self._active_missions.values()
        ]
