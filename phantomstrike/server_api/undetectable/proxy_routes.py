"""
server_api/undetectable/proxy_routes.py

Phantom Proxy API — control the undetectable layer.
Start/stop the proxy, rotate identities, view stats, configure stealth.
"""

import logging
from typing import Any, Dict

from flask import Blueprint, jsonify, request

from server_core import ModernVisualEngine
from server_core.undetectable.phantom_proxy import PhantomProxy
from server_core.undetectable.ip_rotator import IPRotator

logger = logging.getLogger(__name__)

api_undetectable_bp = Blueprint("api_undetectable", __name__)

# Global proxy instance (singleton)
_proxy: PhantomProxy = None


def get_proxy() -> PhantomProxy:
  """Get or create the global PhantomProxy singleton."""
  global _proxy
  if _proxy is None:
    _proxy = PhantomProxy(
      listen_host="127.0.0.1",
      listen_port=9051,
      rotation_strategy="per_request",
      stealth_level="maximum",
    )
  return _proxy


@api_undetectable_bp.route("/api/undetectable/proxy/start", methods=["POST"])
def proxy_start():
  """Start the Phantom Proxy engine."""
  try:
    params = request.json or {}
    stealth = params.get("stealth", "maximum")
    strategy = params.get("strategy", "per_request")

    proxy = get_proxy()
    proxy.set_stealth_level(stealth)
    proxy.rotator.strategy = strategy

    if proxy.is_running():
      return jsonify({"success": True, "message": "Proxy already running", "stats": proxy.get_stats()})

    ok = proxy.start()
    if ok:
      logger.info("%s", ModernVisualEngine.format_tool_status("PhantomProxy", "RUNNING", proxy.get_proxy_url()))
      return jsonify({
        "success": True,
        "message": "Proxy started",
        "proxy_url": proxy.get_proxy_url(),
        "env_vars": proxy.get_env_vars(),
        "exit_ip": proxy.get_current_exit_ip(),
      })
    else:
      return jsonify({"success": False, "error": "Failed to start proxy — port may be in use"}), 500

  except Exception as e:
    logger.error("%s", ModernVisualEngine.format_error_card("ERROR", "PhantomProxy", str(e)))
    return jsonify({"error": str(e), "success": False}), 500


@api_undetectable_bp.route("/api/undetectable/proxy/stop", methods=["POST"])
def proxy_stop():
  """Stop the Phantom Proxy engine."""
  try:
    proxy = get_proxy()
    if not proxy.is_running():
      return jsonify({"success": True, "message": "Proxy not running"})

    proxy.stop()
    return jsonify({"success": True, "message": "Proxy stopped", "uptime": proxy.get_uptime()})
  except Exception as e:
    return jsonify({"error": str(e), "success": False}), 500


@api_undetectable_bp.route("/api/undetectable/proxy/status", methods=["GET"])
def proxy_status():
  """Get current proxy status and stats."""
  try:
    proxy = get_proxy()
    stats = proxy.get_stats()

    return jsonify({
      "success": True,
      **stats,
    })
  except Exception as e:
    return jsonify({"error": str(e), "success": False}), 500


@api_undetectable_bp.route("/api/undetectable/circuit/rotate", methods=["POST"])
def circuit_rotate():
  """Force immediate identity rotation (new Tor circuit)."""
  try:
    proxy = get_proxy()
    ok = proxy.rotate_identity()
    exit_ip = proxy.get_current_exit_ip()

    return jsonify({
      "success": True,
      "rotated": ok,
      "new_exit_ip": exit_ip,
      "method": "tor_new_circuit" if ok else "identity_pool_cycle",
    })
  except Exception as e:
    return jsonify({"error": str(e), "success": False}), 500


@api_undetectable_bp.route("/api/undetectable/proxy/config", methods=["POST"])
def proxy_config():
  """Configure proxy settings — stealth level, rotation strategy."""
  try:
    params = request.json or {}
    stealth = params.get("stealth", "maximum")
    strategy = params.get("strategy", "per_request")

    proxy = get_proxy()
    proxy.set_stealth_level(stealth)
    proxy.rotator.strategy = strategy

    return jsonify({
      "success": True,
      "stealth_level": stealth,
      "rotation_strategy": strategy,
      "available_strategies": IPRotator.ROTATION_STRATEGIES,
    })
  except Exception as e:
    return jsonify({"error": str(e), "success": False}), 500


@api_undetectable_bp.route("/api/undetectable/proxy/test", methods=["POST"])
def proxy_test():
  """Test the proxy by checking the current exit IP."""
  try:
    proxy = get_proxy()
    if not proxy.is_running():
      return jsonify({"success": False, "error": "Proxy not running — start it first"}), 400

    exit_ip = proxy.get_current_exit_ip()

    return jsonify({
      "success": True,
      "exit_ip": exit_ip,
      "proxy_running": True,
      "note": "This is the IP visible to targets. It should differ from your real IP.",
    })
  except Exception as e:
    return jsonify({"error": str(e), "success": False}), 500
