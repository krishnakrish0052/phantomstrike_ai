"""
server_api/evasion/evasion_routes.py

Stealth & Evasion API endpoints — payload obfuscation, traffic morphing,
domain fronting, protocol tunneling, AMSI bypass, and anti-forensics.
"""

import base64
import logging

from flask import Blueprint, jsonify, request

from server_core import ModernVisualEngine
from server_core.evasion.payload_encryptor import PayloadEncryptor
from server_core.evasion.traffic_obfuscator import TrafficObfuscator

logger = logging.getLogger(__name__)

api_evasion_bp = Blueprint("api_evasion", __name__)

_payload_enc = PayloadEncryptor()
_traffic_obf = TrafficObfuscator()


# ── Payload Obfuscation ────────────────────────────────────────────────

@api_evasion_bp.route("/api/tools/obfuscate-payload", methods=["POST"])
def obfuscate_payload():
  """Encrypt and obfuscate a payload with chained encryption."""
  try:
    params = request.json or {}
    payload_str = params.get("payload", "")
    chain = params.get("chain", ["aes256", "base64", "xor"])
    key_seed = params.get("key_seed", "")
    fmt = params.get("format", "base64")  # base64 | hex | raw

    if not payload_str:
      return jsonify({"error": "payload required", "success": False}), 400

    # Accept base64-encoded or raw payload
    try:
      payload_bytes = base64.b64decode(payload_str)
    except Exception:
      payload_bytes = payload_str.encode()

    result = _payload_enc.encrypt_chain(payload_bytes, chain, key_seed)
    stealth = _payload_enc.stealth_score(payload_bytes, chain)

    return jsonify({
      **result,
      "stealth_analysis": stealth,
      "formatted_output": (
        result["encrypted_b64"] if fmt == "base64"
        else result["encrypted_hex"] if fmt == "hex"
        else result["encrypted_payload"].hex()
      ),
    })
  except Exception as e:
    logger.error("%s", ModernVisualEngine.format_error_card("ERROR", "ObfuscatePayload", str(e)))
    return jsonify({"error": str(e), "success": False}), 500


@api_evasion_bp.route("/api/tools/polyglot-payload", methods=["POST"])
def polyglot_payload():
  """Embed payload in a legitimate file (PNG/PDF/GIF/JPG polyglot)."""
  try:
    params = request.json or {}
    payload_str = params.get("payload", "")
    carrier = params.get("carrier", "png")

    if not payload_str:
      return jsonify({"error": "payload required", "success": False}), 400

    try:
      payload_bytes = base64.b64decode(payload_str)
    except Exception:
      payload_bytes = payload_str.encode()

    result = _payload_enc.make_polyglot(payload_bytes, carrier)

    return jsonify(result)
  except Exception as e:
    return jsonify({"error": str(e), "success": False}), 500


@api_evasion_bp.route("/api/tools/stealth-score", methods=["POST"])
def stealth_score():
  """Score payload stealthiness (entropy analysis)."""
  try:
    params = request.json or {}
    payload_str = params.get("payload", "")

    if not payload_str:
      return jsonify({"error": "payload required", "success": False}), 400

    try:
      payload_bytes = base64.b64decode(payload_str)
    except Exception:
      payload_bytes = payload_str.encode()

    result = _payload_enc.stealth_score(payload_bytes)

    return jsonify(result)
  except Exception as e:
    return jsonify({"error": str(e), "success": False}), 500


# ── Traffic Obfuscation ────────────────────────────────────────────────

@api_evasion_bp.route("/api/tools/traffic-morph", methods=["POST"])
def traffic_morph():
  """Generate morphed HTTP headers and TLS config for stealth."""
  try:
    params = request.json or {}
    browser = params.get("browser", "random")
    c2_domain = params.get("c2_domain", "")

    headers = _traffic_obf.morph_headers(browser)
    ja3 = _traffic_obf.ja3_config(browser)
    timing = _traffic_obf.randomize_timing()

    result = {
      "success": True,
      "browser_profile": browser,
      "headers": headers,
      "tls_config": ja3,
      "beacon_timing": timing,
    }

    if c2_domain:
      result["domain_fronting"] = _traffic_obf.domain_front_config(c2_domain)

    return jsonify(result)
  except Exception as e:
    logger.error("%s", ModernVisualEngine.format_error_card("ERROR", "TrafficMorph", str(e)))
    return jsonify({"error": str(e), "success": False}), 500


@api_evasion_bp.route("/api/tools/domain-front", methods=["POST"])
def domain_front():
  """Configure domain fronting through CDN."""
  try:
    params = request.json or {}
    c2_domain = params.get("c2_domain", "")
    cdn = params.get("cdn", "cloudflare")

    if not c2_domain:
      return jsonify({"error": "c2_domain required", "success": False}), 400

    result = _traffic_obf.domain_front_config(c2_domain, cdn)
    return jsonify(result)
  except Exception as e:
    return jsonify({"error": str(e), "success": False}), 500


@api_evasion_bp.route("/api/tools/stealth-profile", methods=["POST"])
def stealth_profile():
  """Generate a complete stealth traffic profile."""
  try:
    params = request.json or {}
    c2_domain = params.get("c2_domain", "")
    cdn = params.get("cdn", "cloudflare")

    result = _traffic_obf.full_profile(c2_domain, cdn)
    return jsonify(result)
  except Exception as e:
    return jsonify({"error": str(e), "success": False}), 500


@api_evasion_bp.route("/api/tools/ja3-randomize", methods=["POST"])
def ja3_randomize():
  """Get a JA3 fingerprint from a legitimate browser."""
  try:
    params = request.json or {}
    browser = params.get("browser", "random")

    result = _traffic_obf.ja3_config(browser)
    return jsonify(result)
  except Exception as e:
    return jsonify({"error": str(e), "success": False}), 500
