"""
server_api/osint/social_dark_web.py

Social media profiling and dark web monitoring API endpoints.
"""

import logging

from flask import Blueprint, jsonify, request

from server_core import ModernVisualEngine
from server_core.osint.social_profiler import SocialProfiler
from server_core.osint.dark_web_monitor import DarkWebMonitor
from server_core.config_core import get as cfg

logger = logging.getLogger(__name__)

api_osint_social_dw_bp = Blueprint("api_osint_social_dw", __name__)

_social = SocialProfiler()
_dark_web = None


def _get_dark_web():
  global _dark_web
  if _dark_web is None:
    _dark_web = DarkWebMonitor(
      tor_proxy=cfg("TOR_PROXY", "socks5h://127.0.0.1:9050"),
      blockchain_api_key=cfg("ETHERSCAN_API_KEY", ""),
    )
  return _dark_web


# ── Social Media Profiling ─────────────────────────────────────────────

@api_osint_social_dw_bp.route("/api/tools/social-search", methods=["POST"])
def social_search():
  """Search for a username across 30+ social platforms."""
  try:
    params = request.json or {}
    username = params.get("username", "")
    platforms = params.get("platforms")

    if not username:
      return jsonify({"error": "Username required", "success": False}), 400

    result = _social.search_username(username, platforms)

    logger.info("%s", ModernVisualEngine.format_tool_status(
      "SocialSearch", "SUCCESS" if result.get("success") else "FAILED",
      f"{username} -> {result.get('found_count', 0)}/{result.get('total_searched', 0)}"
    ))

    return jsonify(result)
  except Exception as e:
    logger.error("%s", ModernVisualEngine.format_error_card("ERROR", "SocialSearch", str(e)))
    return jsonify({"error": str(e), "success": False}), 500


@api_osint_social_dw_bp.route("/api/tools/github-recon", methods=["POST"])
def github_recon():
  """Deep GitHub profile reconnaissance."""
  try:
    params = request.json or {}
    username = params.get("username", "")

    if not username:
      return jsonify({"error": "GitHub username required", "success": False}), 400

    result = _social.github_deep_profile(username)

    logger.info("%s", ModernVisualEngine.format_tool_status(
      "GitHubRecon", "SUCCESS" if result.get("success") else "FAILED", username
    ))

    return jsonify(result)
  except Exception as e:
    logger.error("%s", ModernVisualEngine.format_error_card("ERROR", "GitHubRecon", str(e)))
    return jsonify({"error": str(e), "success": False}), 500


@api_osint_social_dw_bp.route("/api/tools/google-dork", methods=["POST"])
def google_dork():
  """Generate and execute Google dork queries."""
  try:
    params = request.json or {}
    query = params.get("query", params.get("dork", ""))
    domain = params.get("domain", "")
    dork_type = params.get("type", "general")

    if not query and not domain:
      return jsonify({"error": "Query or domain required", "success": False}), 400

    # Build dork templates
    dorks = {
      "file_disclosure": f'site:{domain} ext:pdf | ext:doc | ext:xls | ext:csv',
      "login_pages": f'site:{domain} inurl:login | inurl:admin | inurl:dashboard',
      "backup_files": f'site:{domain} ext:bak | ext:backup | ext:old | ext:sql',
      "config_files": f'site:{domain} ext:conf | ext:cnf | ext:config | ext:env',
      "error_messages": f'site:{domain} intext:"sql syntax" | intext:"warning" | intext:"error"',
      "exposed_dirs": f'site:{domain} intitle:"index of"',
      "subdomains": f'site:*{domain} -www',
      "passwords": f'site:{domain} intext:password | intext:passwd | intext:pwd filetype:txt',
      "api_keys": f'site:{domain} intext:api_key | intext:apikey | intext:secret | intext:token',
      "general": query,
    }

    dork = dorks.get(dork_type, query) if domain else query

    return jsonify({
      "success": True,
      "dork": dork,
      "type": dork_type,
      "domain": domain,
      "search_url": f"https://www.google.com/search?q={dork.replace(' ', '+')}",
      "note": "Execute the search_url manually or use automated dorking tools",
    })
  except Exception as e:
    return jsonify({"error": str(e), "success": False}), 500


# ── Dark Web Intelligence ──────────────────────────────────────────────

@api_osint_social_dw_bp.route("/api/tools/dark-web", methods=["POST"])
def dark_web_scrape():
  """Scrape a .onion site via Tor."""
  try:
    params = request.json or {}
    url = params.get("url", "")
    action = params.get("action", "scrape")

    if not url:
      return jsonify({"error": ".onion URL required", "success": False}), 400

    dw = _get_dark_web()

    if action == "scrape":
      result = dw.scrape_onion(url)
    elif action == "ransomwatch":
      result = dw.ransomwatch_feed()
    elif action == "ransomware_groups":
      result = dw.list_ransomware_groups()
    else:
      return jsonify({"error": f"Unknown action: {action}", "success": False}), 400

    return jsonify(result)
  except Exception as e:
    logger.error("%s", ModernVisualEngine.format_error_card("ERROR", "DarkWeb", str(e)))
    return jsonify({"error": str(e), "success": False}), 500


@api_osint_social_dw_bp.route("/api/tools/crypto-trace", methods=["POST"])
def crypto_trace():
  """Trace a cryptocurrency address."""
  try:
    params = request.json or {}
    address = params.get("address", "")
    chain = params.get("chain", "bitcoin")

    if not address:
      return jsonify({"error": "Address required", "success": False}), 400

    dw = _get_dark_web()

    if chain == "ethereum":
      result = dw.trace_ethereum_address(address)
    else:
      result = dw.trace_bitcoin_address(address)

    return jsonify(result)
  except Exception as e:
    return jsonify({"error": str(e), "success": False}), 500


@api_osint_social_dw_bp.route("/api/tools/threat-actor", methods=["POST"])
def threat_actor_profile():
  """Profile a threat actor from OSINT sources."""
  try:
    params = request.json or {}
    actor_name = params.get("name", "")

    if not actor_name:
      return jsonify({"error": "Actor name required", "success": False}), 400

    dw = _get_dark_web()
    result = dw.profile_threat_actor(actor_name)

    return jsonify(result)
  except Exception as e:
    return jsonify({"error": str(e), "success": False}), 500


@api_osint_social_dw_bp.route("/api/tools/c2-map", methods=["POST"])
def c2_map():
  """Map C2 infrastructure around an IP or domain."""
  try:
    params = request.json or {}
    target = params.get("target", "")

    if not target:
      return jsonify({"error": "IP or domain required", "success": False}), 400

    dw = _get_dark_web()
    result = dw.map_c2_infrastructure(target)

    return jsonify(result)
  except Exception as e:
    return jsonify({"error": str(e), "success": False}), 500
