"""
Execute command with intelligent error handling and recovery API endpoint.
"""

from flask import Blueprint, request, jsonify
from datetime import datetime
from typing import Optional, Dict, Any
import logging

from server_core.recovery_executor import execute_command_with_recovery as _execute_command_with_recovery
from server_core.singletons import cache as _cache

logger = logging.getLogger(__name__)

api_error_handling_execute_with_recovery_bp = Blueprint(
    "api_error_handling_execute_with_recovery", __name__
)


def execute_command_with_recovery(
    tool_name: str,
    command: str,
    parameters: Optional[Dict[str, Any]] = None,
    use_cache: bool = True,
    max_attempts: int = 3,
    timeout: Optional[int] = None,
    target: Optional[str] = None,
) -> Dict[str, Any]:
    # max_attempts is retained for API compatibility; retry policy now lives in RecoveryExecutor.
    return _execute_command_with_recovery(
        command=command,
        use_cache=use_cache,
        cache=_cache,
        timeout=timeout,
        tool=tool_name,
        endpoint="/api/error-handling/execute-with-recovery",
        params=parameters,
        target=target,
    )


@api_error_handling_execute_with_recovery_bp.route(
    "/api/error-handling/execute-with-recovery", methods=["POST"]
)
def execute_with_recovery_endpoint():
    """Execute a command with intelligent error handling and recovery"""
    try:
        data = request.get_json() or {}
        tool_name = data.get("tool_name", "")
        command = data.get("command", "")
        parameters = data.get("parameters", {})
        max_attempts = data.get("max_attempts", 3)
        use_cache = data.get("use_cache", True)
        timeout = data.get("timeout")
        target = data.get("target")

        if not tool_name or not command:
            return jsonify({"error": "tool_name and command are required"}), 400

        result = execute_command_with_recovery(
            tool_name=tool_name,
            command=command,
            parameters=parameters,
            use_cache=use_cache,
            max_attempts=max_attempts,
            timeout=timeout,
            target=target,
        )

        return jsonify({
            "success": result.get("success", False),
            "result": result,
            "timestamp": datetime.now().isoformat()
        })

    except Exception as e:
        logger.error(f"Error executing command with recovery: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500
