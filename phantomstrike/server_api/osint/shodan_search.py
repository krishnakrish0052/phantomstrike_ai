"""
server_api/osint/shodan_search.py

Shodan API integration — IP lookup, host search, and port intelligence.
"""

import logging

from flask import Blueprint, jsonify, request

from server_core import ModernVisualEngine
from server_core.osint.ip_intel import IPIntel

logger = logging.getLogger(__name__)

api_osint_shodan_bp = Blueprint("api_osint_shodan", __name__)

# Lazy singleton
_ip_intel = None


def _get_ip_intel():
  global _ip_intel
  if _ip_intel is None:
    from server_core.config_core import get as cfg
    _ip_intel = IPIntel(
      shodan_key=cfg("SHODAN_API_KEY", ""),
      censys_id=cfg("CENSYS_API_ID", ""),
      censys_secret=cfg("CENSYS_API_SECRET", ""),
      abuseipdb_key=cfg("ABUSEIPDB_API_KEY", ""),
    )
  return _ip_intel


@api_osint_shodan_bp.route("/api/tools/shodan-lookup", methods=["POST"])
def shodan_lookup():
  """Look up an IP address on Shodan."""
  try:
    params = request.json or {}
    ip_addr = params.get("ip", params.get("target", ""))

    if not ip_addr:
      return jsonify({"error": "IP address required", "success": False}), 400

    ip_intel = _get_ip_intel()
    result = ip_intel.shodan_lookup(ip_addr)

    logger.info("%s", ModernVisualEngine.format_tool_status(
      "ShodanLookup", "SUCCESS" if result.get("success") else "FAILED", ip_addr
    ))

    return jsonify(result)
  except Exception as e:
    logger.error("%s", ModernVisualEngine.format_error_card("ERROR", "Shodan", str(e)))
    return jsonify({"error": str(e), "success": False}), 500


@api_osint_shodan_bp.route("/api/tools/shodan-search", methods=["POST"])
def shodan_search():
  """Search Shodan for hosts matching a query."""
  try:
    params = request.json or {}
    query = params.get("query", "")
    limit = int(params.get("limit", 10))

    if not query:
      return jsonify({"error": "Search query required", "success": False}), 400

    ip_intel = _get_ip_intel()
    result = ip_intel.shodan_search(query, limit=limit)

    return jsonify(result)
  except Exception as e:
    logger.error("%s", ModernVisualEngine.format_error_card("ERROR", "ShodanSearch", str(e)))
    return jsonify({"error": str(e), "success": False}), 500


@api_osint_shodan_bp.route("/api/tools/ip-geolocate", methods=["POST"])
def ip_geolocate():
  """Geolocate and analyze an IP address."""
  try:
    params = request.json or {}
    ip_addr = params.get("ip", params.get("target", ""))

    if not ip_addr:
      return jsonify({"error": "IP address required", "success": False}), 400

    ip_intel = _get_ip_intel()
    result = ip_intel.full_report(ip_addr)

    return jsonify(result)
  except Exception as e:
    logger.error("%s", ModernVisualEngine.format_error_card("ERROR", "IPGeolocate", str(e)))
    return jsonify({"error": str(e), "success": False}), 500


@api_osint_shodan_bp.route("/api/tools/tor-check", methods=["POST"])
def tor_check():
  """Check if an IP is a Tor exit node."""
  try:
    params = request.json or {}
    ip_addr = params.get("ip", "")

    if not ip_addr:
      return jsonify({"error": "IP address required", "success": False}), 400

    ip_intel = _get_ip_intel()
    result = ip_intel.is_tor_exit_node(ip_addr)

    return jsonify(result)
  except Exception as e:
    return jsonify({"error": str(e), "success": False}), 500


@api_osint_shodan_bp.route("/api/tools/vpn-check", methods=["POST"])
def vpn_check():
  """Check if an IP likely belongs to a VPN/proxy/datacenter."""
  try:
    params = request.json or {}
    ip_addr = params.get("ip", "")

    if not ip_addr:
      return jsonify({"error": "IP address required", "success": False}), 400

    ip_intel = _get_ip_intel()
    result = ip_intel.is_vpn_or_proxy(ip_addr)

    return jsonify(result)
  except Exception as e:
    return jsonify({"error": str(e), "success": False}), 500
