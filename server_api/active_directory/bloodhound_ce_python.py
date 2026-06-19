from flask import Blueprint, request, jsonify
import logging
import shlex

from server_core.command_executor import execute_command

logger = logging.getLogger(__name__)

api_tool_active_directory_bloodhound_ce_python_bp = Blueprint(
    "api_tool_active_directory_bloodhound_ce_python", __name__
)


@api_tool_active_directory_bloodhound_ce_python_bp.route(
    "/api/tools/active_directory/bloodhound_ce_python", methods=["POST"]
)
def run_bloodhound_ce_python():
    """Execute bloodhound-python for Active Directory data collection.

    Expected JSON payload:
        domain:             target AD domain (e.g. 'corp.local')
        username:           domain username
        password:           user password or NT hash
        collection_method:  (optional) collection method (default: 'All')
        dc_ip:              (optional) domain controller IP
        nameserver:         (optional) custom DNS server
        extra_args:         (optional) extra CLI args appended verbatim
    """
    try:
        data = request.get_json(silent=True) or {}
        domain = (data.get("domain") or "").strip()
        username = (data.get("username") or "").strip()
        password = (data.get("password") or "").strip()
        collection_method = (data.get("collection_method") or "All").strip()
        dc_ip = (data.get("dc_ip") or "").strip()
        nameserver = (data.get("nameserver") or "").strip()
        extra_args = (data.get("extra_args") or "").strip()

        if not domain:
            return jsonify({"error": "domain is required"}), 400
        if not username:
            return jsonify({"error": "username is required"}), 400
        if not password:
            return jsonify({"error": "password is required"}), 400

        # Build the bloodhound-python command
        cmd_parts = [
            "bloodhound-python",
            "-u", shlex.quote(username),
            "-p", shlex.quote(password),
            "-d", shlex.quote(domain),
            "-c", shlex.quote(collection_method),
        ]

        if dc_ip:
            cmd_parts.extend(["-dc", shlex.quote(dc_ip)])
        if nameserver:
            cmd_parts.extend(["-ns", shlex.quote(nameserver)])

        command = " ".join(cmd_parts)

        if extra_args:
            command += f" {shlex.quote(extra_args)}"

        logger.info("Starting bloodhound-python on domain %s", domain)
        result = execute_command(command)
        logger.info("Completed bloodhound-python on domain %s", domain)
        return jsonify(result)

    except Exception as e:
        logger.exception("Error in bloodhound_ce_python endpoint")
        return jsonify({"error": f"Server error: {str(e)}"}), 500
