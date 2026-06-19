import shlex
from flask import Blueprint, request, jsonify
import logging

from server_core.command_executor import execute_command

logger = logging.getLogger(__name__)

api_vuln_scan_nuclei_bp = Blueprint("api_vuln_scan_nuclei", __name__)


@api_vuln_scan_nuclei_bp.route("/api/tools/nuclei", methods=["POST"])
def nuclei():
    """Execute Nuclei vulnerability scanner with enhanced logging and intelligent error handling"""
    try:
        params = request.json
        target = params.get("target", "")
        severity = params.get("severity", "")
        tags = params.get("tags", "")
        template = params.get("template", "")
        additional_args = params.get("additional_args", "")

        if not target:
            logger.warning("Nuclei called without target parameter")
            return jsonify({
                "error": "Target parameter is required"
            }), 400

        command = f"nuclei -u {shlex.quote(target)}"

        if severity:
            command += f" -severity {shlex.quote(severity)}"

        if tags:
            command += f" -tags {shlex.quote(tags)}"

        if template:
            command += f" -t {shlex.quote(template)}"

        if additional_args:
            command += f" {shlex.quote(additional_args)}"

        logger.info(f"Starting Nuclei vulnerability scan: {target}")

        result = execute_command(command)

        logger.info(f"Nuclei scan completed for {target}")
        return jsonify(result)

    except Exception as e:
        logger.error(f"Error in nuclei endpoint: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500
