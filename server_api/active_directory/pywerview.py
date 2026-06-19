from flask import Blueprint, request, jsonify
import logging
import shlex

from server_core.command_executor import execute_command

logger = logging.getLogger(__name__)

api_tool_active_directory_pywerview_bp = Blueprint(
    "api_tool_active_directory_pywerview", __name__
)


@api_tool_active_directory_pywerview_bp.route(
    "/api/tools/active_directory/pywerview", methods=["POST"]
)
def run_pywerview():
    """Execute pywerview for Active Directory enumeration (PowerView Python port).

    Expected JSON payload:
        cmd:         pywerview subcommand (e.g. 'get-netuser', 'get-netgroup')
        target:      target DC hostname or IP
        username:    domain username
        password:    user password or NT hash
        extra_args:  (optional) extra CLI args appended verbatim
    """
    try:
        data = request.get_json(silent=True) or {}
        cmd = (data.get("cmd") or "").strip()
        target = (data.get("target") or "").strip()
        username = (data.get("username") or "").strip()
        password = (data.get("password") or "").strip()
        extra_args = (data.get("extra_args") or "").strip()

        if not cmd:
            return jsonify({"error": "cmd is required"}), 400
        if not target:
            return jsonify({"error": "target is required"}), 400

        # Build the pywerview command
        cmd_parts = [
            "pywerview",
            shlex.quote(cmd),
            "-t", shlex.quote(target),
            "-u", shlex.quote(username),
            "-p", shlex.quote(password),
        ]

        command = " ".join(cmd_parts)

        if extra_args:
            command += f" {shlex.quote(extra_args)}"

        logger.info("Starting pywerview %s on target %s", cmd, target)
        result = execute_command(command)
        logger.info("Completed pywerview %s on target %s", cmd, target)
        return jsonify(result)

    except Exception as e:
        logger.exception("Error in pywerview endpoint")
        return jsonify({"error": f"Server error: {str(e)}"}), 500
