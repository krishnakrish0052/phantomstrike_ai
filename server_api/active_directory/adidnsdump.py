from flask import Blueprint, request, jsonify
import logging
import shlex

from server_core.command_executor import execute_command

logger = logging.getLogger(__name__)

api_tool_active_directory_adidnsdump_bp = Blueprint(
    "api_tool_active_directory_adidnsdump", __name__
)


@api_tool_active_directory_adidnsdump_bp.route(
    "/api/tools/active_directory/adidnsdump", methods=["POST"]
)
def run_adidnsdump():
    """Execute adidnsdump to enumerate DNS records via LDAP.

    Expected JSON payload:
        target:     target DC hostname or IP
        username:   domain username (DOMAIN\\user or user@domain)
        password:   user password or NT hash
        extra_args: (optional) extra CLI args appended verbatim
    """
    try:
        data = request.get_json(silent=True) or {}
        target = (data.get("target") or "").strip()
        username = (data.get("username") or "").strip()
        password = (data.get("password") or "").strip()
        extra_args = (data.get("extra_args") or "").strip()

        if not target:
            return jsonify({"error": "target is required"}), 400

        # Build the adidnsdump command
        cmd_parts = ["adidnsdump"]

        if username:
            cmd_parts.extend(["-u", shlex.quote(username)])
        if password:
            cmd_parts.extend(["-p", shlex.quote(password)])

        cmd_parts.append(shlex.quote(target))

        command = " ".join(cmd_parts)

        if extra_args:
            command += f" {shlex.quote(extra_args)}"

        logger.info("Starting adidnsdump on target %s", target)
        result = execute_command(command)
        logger.info("Completed adidnsdump on target %s", target)
        return jsonify(result)

    except Exception as e:
        logger.exception("Error in adidnsdump endpoint")
        return jsonify({"error": f"Server error: {str(e)}"}), 500
