"""
server_api/orchestrator/mission_routes.py

REST API for managing autonomous hacking missions.

Endpoints:
  POST   /api/orchestrator/mission              — Start autonomous mission
  GET    /api/orchestrator/mission/<id>          — Get mission status
  POST   /api/orchestrator/mission/<id>/pause    — Pause mission
  POST   /api/orchestrator/mission/<id>/resume   — Resume paused mission
  POST   /api/orchestrator/mission/<id>/abort    — Emergency abort
  GET    /api/orchestrator/mission/<id>/report   — Download mission report
  GET    /api/orchestrator/missions              — List all missions
"""

import json
import logging
from typing import Any, Dict

from flask import Blueprint, jsonify, request, Response

from server_core import ModernVisualEngine
from server_core.orchestrator import OrchestratorAgent

logger = logging.getLogger(__name__)

api_orchestrator_bp = Blueprint("api_orchestrator", __name__)

# Global singleton — one orchestrator per process
_orchestrator: OrchestratorAgent = OrchestratorAgent()


def _get_orchestrator() -> OrchestratorAgent:
    """Return the global orchestrator singleton (lazy init safe)."""
    global _orchestrator
    if _orchestrator is None:
        _orchestrator = OrchestratorAgent()
    return _orchestrator


# ---------------------------------------------------------------------------
# POST /api/orchestrator/mission
# ---------------------------------------------------------------------------

@api_orchestrator_bp.route("/api/orchestrator/mission", methods=["POST"])
def start_mission():
    """Start an autonomous hacking mission.

    Request body (JSON):
      prompt  (str, required): Natural-language mission description.
      stealth (str, optional): Stealth level — minimum|medium|maximum|ghost.
      max_phase_duration (int, optional): Max seconds per phase (default 600).

    Returns:
      JSON with mission_id, success, phases, report, elapsed_seconds.
    """
    try:
        body: Dict[str, Any] = request.json or {}
        prompt = body.get("prompt", "").strip()
        if not prompt:
            return jsonify({"success": False, "error": "prompt is required"}), 400

        stealth = body.get("stealth", "maximum")
        if stealth not in ("minimum", "medium", "maximum", "ghost"):
            return jsonify({"success": False, "error": f"Invalid stealth level: {stealth}"}), 400

        max_phase_duration = int(body.get("max_phase_duration", 600))

        logger.info(
            "%s",
            ModernVisualEngine.create_section_header("ORCHESTRATOR API — MISSION START", "🚀", "CRIMSON"),
        )
        logger.info("Prompt: %s | Stealth: %s", prompt[:120], stealth)

        orch = _get_orchestrator()
        result = orch.execute_mission(
            prompt=prompt,
            stealth=stealth,
            max_phase_duration=max_phase_duration,
        )

        status_code = 200 if result.get("success") else 500
        return jsonify(result), status_code

    except Exception as exc:
        logger.exception("start_mission failed")
        return jsonify({"success": False, "error": str(exc)}), 500


# ---------------------------------------------------------------------------
# GET /api/orchestrator/mission/<mission_id>
# ---------------------------------------------------------------------------

@api_orchestrator_bp.route("/api/orchestrator/mission/<mission_id>", methods=["GET"])
def get_mission(mission_id: str):
    """Get the full status of a mission including all phase results."""
    try:
        orch = _get_orchestrator()
        mission = orch.get_mission(mission_id)
        if mission is None:
            return jsonify({"success": False, "error": f"Mission '{mission_id}' not found"}), 404

        return jsonify({"success": True, "mission": mission})

    except Exception as exc:
        logger.exception("get_mission failed")
        return jsonify({"success": False, "error": str(exc)}), 500


# ---------------------------------------------------------------------------
# POST /api/orchestrator/mission/<mission_id>/pause
# ---------------------------------------------------------------------------

@api_orchestrator_bp.route("/api/orchestrator/mission/<mission_id>/pause", methods=["POST"])
def pause_mission(mission_id: str):
    """Pause a running mission. Resumable via /resume."""
    try:
        orch = _get_orchestrator()
        result = orch.pause_mission(mission_id)
        return jsonify({"success": True, "data": result})

    except Exception as exc:
        logger.exception("pause_mission failed")
        return jsonify({"success": False, "error": str(exc)}), 500


# ---------------------------------------------------------------------------
# POST /api/orchestrator/mission/<mission_id>/resume
# ---------------------------------------------------------------------------

@api_orchestrator_bp.route("/api/orchestrator/mission/<mission_id>/resume", methods=["POST"])
def resume_mission(mission_id: str):
    """Resume a paused mission."""
    try:
        orch = _get_orchestrator()
        result = orch.resume_mission(mission_id)
        return jsonify({"success": True, "data": result})

    except Exception as exc:
        logger.exception("resume_mission failed")
        return jsonify({"success": False, "error": str(exc)}), 500


# ---------------------------------------------------------------------------
# POST /api/orchestrator/mission/<mission_id>/abort
# ---------------------------------------------------------------------------

@api_orchestrator_bp.route("/api/orchestrator/mission/<mission_id>/abort", methods=["POST"])
def abort_mission(mission_id: str):
    """Emergency abort — stops all phases immediately. Cannot be resumed."""
    try:
        orch = _get_orchestrator()
        result = orch.abort_mission(mission_id)
        return jsonify({"success": True, "data": result})

    except Exception as exc:
        logger.exception("abort_mission failed")
        return jsonify({"success": False, "error": str(exc)}), 500


# ---------------------------------------------------------------------------
# GET /api/orchestrator/mission/<mission_id>/report
# ---------------------------------------------------------------------------

@api_orchestrator_bp.route("/api/orchestrator/mission/<mission_id>/report", methods=["GET"])
def download_report(mission_id: str):
    """Download the mission report as Markdown.

    Query params:
      format (str): 'markdown' (default) or 'json'.
    """
    try:
        orch = _get_orchestrator()
        mission = orch.get_mission(mission_id)
        if mission is None:
            return jsonify({"success": False, "error": f"Mission '{mission_id}' not found"}), 404

        report = mission.get("report", "")
        fmt = request.args.get("format", "markdown")

        if fmt == "json":
            return jsonify({"success": True, "mission_id": mission_id, "report": report})
        else:
            return Response(
                report,
                mimetype="text/markdown",
                headers={
                    "Content-Disposition": f"attachment; filename=mission_{mission_id}.md"
                },
            )

    except Exception as exc:
        logger.exception("download_report failed")
        return jsonify({"success": False, "error": str(exc)}), 500


# ---------------------------------------------------------------------------
# GET /api/orchestrator/missions
# ---------------------------------------------------------------------------

@api_orchestrator_bp.route("/api/orchestrator/missions", methods=["GET"])
def list_missions():
    """List all tracked missions with summary data."""
    try:
        orch = _get_orchestrator()
        missions = orch.list_missions()
        return jsonify({"success": True, "missions": missions, "count": len(missions)})

    except Exception as exc:
        logger.exception("list_missions failed")
        return jsonify({"success": False, "error": str(exc)}), 500
