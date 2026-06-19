from flask import Blueprint, request, jsonify
import logging
import shlex

from server_core.command_executor import execute_command

logger = logging.getLogger(__name__)

api_tool_active_directory_certipy_ad_bp = Blueprint(
    "api_tool_active_directory_certipy_ad", __name__
)


@api_tool_active_directory_certipy_ad_bp.route(
    "/api/tools/active_directory/certipy_ad", methods=["POST"]
)
def run_certipy_ad():
    """Execute certipy-ad for Active Directory certificate services exploitation.

    Expected JSON payload:
        subcommand:  certipy subcommand (e.g. 'req', 'auth', 'find')
        target:      target DC or CA hostname / IP
        username:    domain username (DOMAIN\\user or user@domain)
        password:    user password or NT hash
        dc_ip:       (optional) domain controller IP
        extra_args:  (optional) extra CLI args appended verbatim
    """
    try:
        data = request.get_json(silent=True) or {}
        subcommand = (data.get("subcommand") or "").strip()
        target = (data.get("target") or "").strip()
        username = (data.get("username") or "").strip()
        password = (data.get("password") or "").strip()
        dc_ip = (data.get("dc_ip") or "").strip()
        extra_args = (data.get("extra_args") or "").strip()

        if not subcommand:
            return jsonify({"error": "subcommand is required"}), 400
        if not target:
            return jsonify({"error": "target is required"}), 400

        # Build the certipy-ad command
        cmd_parts = ["certipy-ad", subcommand]
        cmd_parts.extend(["-u", shlex.quote(username)])
        cmd_parts.extend(["-p", shlex.quote(password)])
        cmd_parts.extend(["-target", shlex.quote(target)])

        if dc_ip:
            cmd_parts.extend(["-dc-ip", shlex.quote(dc_ip)])

        command = " ".join(cmd_parts)

        if extra_args:
            command += f" {shlex.quote(extra_args)}"

        logger.info("Starting certipy-ad %s on %s", subcommand, target)
        result = execute_command(command)
        logger.info("Completed certipy-ad %s on %s", subcommand, target)
        return jsonify(result)

    except Exception as e:
        logger.exception("Error in certipy_ad endpoint")
        return jsonify({"error": f"Server error: {str(e)}"}), 500
