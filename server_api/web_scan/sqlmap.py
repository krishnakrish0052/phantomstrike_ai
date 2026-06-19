from flask import Blueprint, request, jsonify
import logging
from server_core.command_executor import execute_command
from server_core.security import (
    safe_url,
    quote_arg,
    safe_extra_args,
    CommandSanitizationError,
)

logger = logging.getLogger(__name__)

api_web_scan_sqlmap_bp = Blueprint("api_web_scan_sqlmap", __name__)


@api_web_scan_sqlmap_bp.route("/api/tools/sqlmap", methods=["POST"])
def sqlmap():
    """Execute sqlmap with enhanced logging"""
    try:
        params = request.json
        url = params.get("url", "")
        data = params.get("data", "")
        additional_args = params.get("additional_args", "")

        if not url:
            logger.warning("🎯 SQLMap called without URL parameter")
            return jsonify({
                "error": "URL parameter is required"
            }), 400

        # Harden against OS command injection: every user-supplied value is
        # validated/escaped before being interpolated into the shell command.
        try:
            safe_target = safe_url(url)
            command = f"sqlmap -u {safe_target} --batch"
            if data:
                command += f" --data={quote_arg(data)}"
            if additional_args:
                command += f" {safe_extra_args(additional_args)}"
        except CommandSanitizationError as exc:
            logger.warning(f"🚫 Rejected unsafe SQLMap input: {exc}")
            return jsonify({"error": f"Invalid input: {exc}"}), 400

        logger.info(f"💉 Starting SQLMap scan: {url}")
        result = execute_command(command)
        logger.info(f"📊 SQLMap scan completed for {url}")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in sqlmap endpoint: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500
