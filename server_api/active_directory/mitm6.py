from flask import Blueprint, request, jsonify
import logging
import shlex

from server_core.command_executor import execute_command

logger = logging.getLogger(__name__)

api_tool_active_directory_mitm6_bp = Blueprint(
    "api_tool_active_directory_mitm6", __name__
)


@api_tool_active_directory_mitm6_bp.route(
    "/api/tools/active_directory/mitm6", methods=["POST"]
)
def run_mitm6():
    """Execute mitm6 for IPv6 DNS takeover / WPAD spoofing.

    Expected JSON payload:
        domain:       target AD domain (e.g. 'corp.local')
        interface:    (optional) network interface to listen on
        extra_args:   (optional) extra CLI args appended verbatim
    """
    try:
        data = request.get_json(silent=True) or {}
        domain = (data.get("domain") or "").strip()
        interface = (data.get("interface") or "").strip()
        extra_args = (data.get("extra_args") or "").strip()

        if not domain:
            return jsonify({"error": "domain is required"}), 400

        # Build the mitm6 command
        cmd_parts = ["mitm6", "-d", shlex.quote(domain)]

        if interface:
            cmd_parts.extend(["-i", shlex.quote(interface)])

        command = " ".join(cmd_parts)

        if extra_args:
            command += f" {shlex.quote(extra_args)}"

        logger.info("Starting mitm6 on domain %s", domain)
        result = execute_command(command)
        logger.info("Completed mitm6 on domain %s", domain)
        return jsonify(result)

    except Exception as e:
        logger.exception("Error in mitm6 endpoint")
        return jsonify({"error": f"Server error: {str(e)}"}), 500
