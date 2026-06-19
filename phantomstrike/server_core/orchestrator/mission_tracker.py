"""
server_core/orchestrator/mission_tracker.py

Tracks mission progress and generates final reports.

Stores:
  - Mission ID, prompt, start time, status, stealth level
  - Phase progression with timestamps
  - Findings organized by agent
  - Success/failure metrics
  - Generates a Markdown report at completion
"""

import logging
import threading
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from server_core import ModernVisualEngine

logger = logging.getLogger(__name__)


class MissionTracker:
    """Lightweight in-process mission tracker with Markdown report generation."""

    def __init__(self):
        self._lock = threading.Lock()
        self._missions: Dict[str, Dict[str, Any]] = {}

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start_mission(
        self,
        mission_id: str,
        prompt: str,
        stealth: str,
        phases: List[Dict[str, Any]],
    ) -> None:
        """Register a new mission."""
        with self._lock:
            self._missions[mission_id] = {
                "mission_id": mission_id,
                "prompt": prompt,
                "stealth": stealth,
                "status": "running",
                "started_at": datetime.now(timezone.utc).isoformat(),
                "started_epoch": time.time(),
                "completed_at": None,
                "phases": {
                    p["id"]: {
                        "label": p.get("label", p["id"]),
                        "agent_type": p.get("agent_type", "unknown"),
                        "status": "pending",
                        "started_at": None,
                        "completed_at": None,
                        "result": None,
                    }
                    for p in phases
                },
                "findings_by_agent": {},
                "overall_success": None,
            }
            logger.info("Mission %s registered (%d phases)", mission_id, len(phases))

    def update_phase(
        self,
        mission_id: str,
        phase_id: str,
        result: Dict[str, Any],
    ) -> bool:
        """Mark a phase as completed and store its result."""
        with self._lock:
            mission = self._missions.get(mission_id)
            if mission is None:
                logger.warning("update_phase: unknown mission %s", mission_id)
                return False

            phase = mission["phases"].get(phase_id)
            if phase is None:
                logger.warning("update_phase: unknown phase %s in mission %s", phase_id, mission_id)
                return False

            phase["status"] = "success" if result.get("success") else "failed"
            phase["completed_at"] = datetime.now(timezone.utc).isoformat()
            phase["result"] = result

            # Aggregate findings by agent
            agent_type = phase["agent_type"]
            mission["findings_by_agent"].setdefault(agent_type, []).append({
                "phase_id": phase_id,
                "phase_label": phase["label"],
                "success": result.get("success"),
                "data": result.get("data", result.get("output", {})),
            })

            logger.debug("Mission %s phase %s → %s", mission_id, phase_id, phase["status"])
            return True

    def complete_mission(self, mission_id: str, success: bool) -> None:
        """Mark the mission as finished."""
        with self._lock:
            mission = self._missions.get(mission_id)
            if mission:
                mission["status"] = "success" if success else "partial_failure"
                mission["completed_at"] = datetime.now(timezone.utc).isoformat()
                mission["overall_success"] = success

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    def get_mission(self, mission_id: str) -> Optional[Dict[str, Any]]:
        """Return a copy of the mission dict."""
        with self._lock:
            m = self._missions.get(mission_id)
            return dict(m) if m else None

    def list_missions(self) -> List[Dict[str, Any]]:
        """Return lightweight summaries for all missions."""
        with self._lock:
            return [
                {
                    "mission_id": m["mission_id"],
                    "prompt": m["prompt"],
                    "status": m["status"],
                    "stealth": m["stealth"],
                    "started_at": m["started_at"],
                    "completed_at": m.get("completed_at"),
                    "overall_success": m.get("overall_success"),
                    "phase_count": len(m["phases"]),
                }
                for m in self._missions.values()
            ]

    # ------------------------------------------------------------------
    # Report generation
    # ------------------------------------------------------------------

    def generate_report(
        self,
        mission_id: str,
        phase_results: List[Dict[str, Any]],
        overall_success: bool,
        elapsed: float,
    ) -> str:
        """Generate a Markdown mission report."""
        mission = self._missions.get(mission_id)
        prompt = mission["prompt"] if mission else "unknown"
        stealth = mission["stealth"] if mission else "unknown"
        started = mission["started_at"] if mission else "unknown"

        lines: List[str] = []
        lines.append(f"# PhantomStrike Mission Report")
        lines.append("")
        lines.append(f"**Mission ID:** `{mission_id}`")
        lines.append(f"**Status:** {'✅ SUCCESS' if overall_success else '⚠️ PARTIAL / FAILED'}")
        lines.append(f"**Prompt:** {prompt}")
        lines.append(f"**Stealth:** {stealth}")
        lines.append(f"**Started:** {started}")
        lines.append(f"**Elapsed:** {elapsed:.2f}s")
        lines.append("")

        # Phase summary table
        lines.append("## Phase Execution Summary")
        lines.append("")
        lines.append("| # | Phase | Agent | Status | Duration |")
        lines.append("|---|-------|-------|--------|----------|")
        for idx, p in enumerate(phase_results):
            label = p.get("label", p.get("id", "?"))
            agent = p.get("agent_type", "?")
            status = p.get("status", "?")
            status_icon = "✅" if status == "success" else "❌"
            duration = p.get("result", {}).get("elapsed_seconds", "N/A") if p.get("result") else "N/A"
            lines.append(f"| {idx + 1} | {label} | {agent} | {status_icon} {status} | {duration} |")
        lines.append("")

        # Per-phase details
        for idx, p in enumerate(phase_results):
            label = p.get("label", p.get("id", "?"))
            result = p.get("result", {})
            lines.append(f"## Phase {idx + 1}: {label}")
            lines.append("")
            lines.append(f"- **Agent:** {p.get('agent_type', '?')}")
            lines.append(f"- **Success:** {result.get('success', False)}")
            lines.append(f"- **Error:** {result.get('error', 'None')}")
            if result.get("elapsed_seconds"):
                lines.append(f"- **Duration:** {result['elapsed_seconds']}s")

            # Include truncated output if present
            output = result.get("data", result.get("output"))
            if output:
                output_str = str(output)[:1000]
                lines.append("")
                lines.append("```")
                lines.append(output_str)
                lines.append("```")
            lines.append("")

        # Findings by agent
        if mission:
            lines.append("## Findings by Agent")
            lines.append("")
            for agent_type, findings in mission.get("findings_by_agent", {}).items():
                lines.append(f"### {agent_type.title()}")
                for f in findings:
                    icon = "✅" if f["success"] else "❌"
                    lines.append(f"- {icon} **{f['phase_label']}**")
                    data_preview = str(f.get("data", ""))[:200]
                    if data_preview:
                        lines.append(f"  `{data_preview}`")
                lines.append("")

        lines.append("---")
        lines.append(f"*Generated by PhantomStrike Orchestrator at {datetime.now(timezone.utc).isoformat()}*")
        lines.append("")

        report = "\n".join(lines)
        logger.info("%s", ModernVisualEngine.create_section_header("MISSION REPORT GENERATED", "📋", "SUCCESS"))
        return report
