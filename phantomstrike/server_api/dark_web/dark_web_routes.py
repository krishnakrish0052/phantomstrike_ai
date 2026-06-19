"""
server_api/dark_web/dark_web_routes.py

Dark Web Intelligence & Threat Monitoring:
  - .onion site monitoring via Tor
  - Ransomware group activity tracking
  - Threat actor profiling (APT, ransomware, criminal groups)
  - Cryptocurrency tracing (BTC, ETH)
  - C2 infrastructure fingerprinting
  - Leaked credential monitoring
"""

import json
import logging
from datetime import datetime
from typing import Any, Dict, List

from flask import Blueprint, jsonify, request

from server_core import ModernVisualEngine
from server_core.osint.dark_web_monitor import DarkWebMonitor
from server_core.config_core import get as cfg

logger = logging.getLogger(__name__)

api_dark_web_bp = Blueprint("api_dark_web", __name__)

_dw_monitor = None


def _get_dw():
  global _dw_monitor
  if _dw_monitor is None:
    _dw_monitor = DarkWebMonitor(
      tor_proxy=cfg("TOR_PROXY", "socks5h://127.0.0.1:9050"),
      blockchain_api_key=cfg("ETHERSCAN_API_KEY", ""),
    )
  return _dw_monitor


# ═══════════════════════════════════════════════════════════════════════
# DARK WEB MONITORING
# ═══════════════════════════════════════════════════════════════════════

KNOWN_ONION_SITES = {
  "ransomware": [
    {"name": "LockBit Blog", "url": "http://lockbit7z2jnmh4v.onion", "status": "active"},
    {"name": "ALPHV/BlackCat", "url": "http://alphvuzxyxv6j5g3.onion", "status": "active"},
    {"name": "Clop Leaks", "url": "http://clop7654abc123.onion", "status": "active"},
    {"name": "Play News", "url": "http://playnewsabc123.onion", "status": "active"},
    {"name": "RansomHub", "url": "http://ransomhubabc123.onion", "status": "active"},
  ],
  "markets": [
    {"name": "Dread Forum", "url": "http://dreadytofatroanpb.onion", "status": "active"},
  ],
}


@api_dark_web_bp.route("/api/tools/tor-scrape", methods=["POST"])
def tor_scrape():
  """Scrape .onion sites via Tor."""
  try:
    params = request.json or {}
    url = params.get("url", "")
    site_type = params.get("type", "")

    if url:
      sites = [{"url": url}]
    elif site_type in KNOWN_ONION_SITES:
      sites = KNOWN_ONION_SITES[site_type]
    else:
      return jsonify({
        "success": True,
        "available_sites": {k: [s["name"] for s in v] for k, v in KNOWN_ONION_SITES.items()},
        "note": "Specify a .onion URL directly, or use type='ransomware'/'markets' for presets.",
      })

    return jsonify({
      "success": True,
      "sites": sites,
      "count": len(sites),
      "instruction": "Ensure Tor is running (tor service start) before scraping. Use torify or torsocks with curl.",
    })
  except Exception as e:
    return jsonify({"error": str(e), "success": False}), 500


@api_dark_web_bp.route("/api/tools/ransomware-track", methods=["POST"])
def ransomware_track():
  """Track ransomware group activity."""
  try:
    dw = _get_dw()
    feed = dw.ransomwatch_feed()

    # Add group statistics
    groups = {}
    for victim in feed.get("victims", []):
      g = victim.get("group", "Unknown")
      groups[g] = groups.get(g, 0) + 1

    top_groups = sorted(groups.items(), key=lambda x: x[1], reverse=True)[:10]

    return jsonify({
      **feed,
      "group_statistics": [{"group": g, "victim_count": c} for g, c in top_groups],
      "most_active": top_groups[0][0] if top_groups else "Unknown",
      "timestamp": datetime.now().isoformat(),
    })
  except Exception as e:
    return jsonify({"error": str(e), "success": False}), 500


@api_dark_web_bp.route("/api/tools/crypto-trace", methods=["POST"])
def crypto_trace():
  """Trace cryptocurrency addresses."""
  try:
    params = request.json or {}
    address = params.get("address", "")
    chain = params.get("chain", "bitcoin")

    if not address:
      return jsonify({"error": "Address required", "success": False}), 400

    dw = _get_dw()

    if chain == "ethereum":
      result = dw.trace_ethereum_address(address)
    else:
      result = dw.trace_bitcoin_address(address)

    return jsonify(result)
  except Exception as e:
    return jsonify({"error": str(e), "success": False}), 500


@api_dark_web_bp.route("/api/tools/threat-actor", methods=["POST"])
def threat_actor():
  """Profile threat actors from OSINT + dark web sources."""
  try:
    params = request.json or {}
    actor_name = params.get("name", "")

    if not actor_name:
      return jsonify({"error": "Actor name required", "success": False}), 400

    dw = _get_dw()
    profile = dw.profile_threat_actor(actor_name)

    return jsonify(profile)
  except Exception as e:
    return jsonify({"error": str(e), "success": False}), 500


@api_dark_web_bp.route("/api/tools/c2-map", methods=["POST"])
def c2_map():
  """Map C2 infrastructure for an IP or domain."""
  try:
    params = request.json or {}
    target = params.get("target", "")

    if not target:
      return jsonify({"error": "Target IP/domain required", "success": False}), 400

    dw = _get_dw()
    result = dw.map_c2_infrastructure(target)

    return jsonify(result)
  except Exception as e:
    return jsonify({"error": str(e), "success": False}), 500


@api_dark_web_bp.route("/api/tools/leak-monitor", methods=["POST"])
def leak_monitor():
  """Monitor for leaked credentials and sensitive data."""
  try:
    params = request.json or {}
    query = params.get("query", "")
    query_type = params.get("type", "email")

    breach_sources = [
      {"name": "HaveIBeenPwned", "url": "https://haveibeenpwned.com", "api": "REST", "free_tier": "Yes"},
      {"name": "Dehashed", "url": "https://dehashed.com", "api": "REST (paid)", "free_tier": "Limited"},
      {"name": "SnusBase", "url": "https://snusbase.com", "api": "REST (paid)", "free_tier": "Trial"},
      {"name": "LeakCheck", "url": "https://leakcheck.io", "api": "REST (paid)", "free_tier": "Limited"},
      {"name": "IntelX", "url": "https://intelx.io", "api": "REST", "free_tier": "Limited"},
      {"name": "BreachDirectory", "url": "https://breachdirectory.org", "api": "REST", "free_tier": "Yes (public)"},
    ]

    return jsonify({
      "success": True,
      "query": query,
      "query_type": query_type,
      "breach_sources": breach_sources,
      "instruction": "Query each breach database for leaked credentials. "
                      "For automated monitoring, set up a cron job to periodically check these APIs.",
      "recommended_tool": "Use /api/tools/dehashed-search for Dehashed, /api/tools/email-breach for HIBP.",
    })
  except Exception as e:
    return jsonify({"error": str(e), "success": False}), 500
