"""
server_api/osint/phone_email_trace.py

Phone number and email tracing API endpoints.
"""

import logging

from flask import Blueprint, jsonify, request

from server_core import ModernVisualEngine
from server_core.osint.phone_tracer import PhoneTracer
from server_core.osint.email_tracer import EmailTracer
from server_core.config_core import get as cfg

logger = logging.getLogger(__name__)

api_osint_trace_bp = Blueprint("api_osint_trace", __name__)

_phone_tracer = None
_email_tracer = None


def _get_phone():
  global _phone_tracer
  if _phone_tracer is None:
    _phone_tracer = PhoneTracer(numverify_key=cfg("NUMVERIFY_API_KEY", ""))
  return _phone_tracer


def _get_email():
  global _email_tracer
  if _email_tracer is None:
    _email_tracer = EmailTracer(
      hibp_key=cfg("HIBP_API_KEY", ""),
      dehashed_key=cfg("DEHASHED_API_KEY", ""),
      dehashed_email=cfg("DEHASHED_EMAIL", ""),
    )
  return _email_tracer


@api_osint_trace_bp.route("/api/tools/phone-lookup", methods=["POST"])
def phone_lookup():
  """Trace a phone number — carrier, location, line type."""
  try:
    params = request.json or {}
    phone = params.get("phone", params.get("number", ""))

    if not phone:
      return jsonify({"error": "Phone number required", "success": False}), 400

    tracer = _get_phone()
    result = tracer.full_report(phone)

    logger.info("%s", ModernVisualEngine.format_tool_status(
      "PhoneLookup", "SUCCESS" if result.get("success") else "FAILED", phone[:20]
    ))

    return jsonify(result)
  except Exception as e:
    logger.error("%s", ModernVisualEngine.format_error_card("ERROR", "Phone", str(e)))
    return jsonify({"error": str(e), "success": False}), 500


@api_osint_trace_bp.route("/api/tools/email-breach", methods=["POST"])
def email_breach():
  """Check email against breach databases (HIBP, Dehashed)."""
  try:
    params = request.json or {}
    email = params.get("email", "")

    if not email:
      return jsonify({"error": "Email required", "success": False}), 400

    tracer = _get_email()
    result = tracer.full_report(email)

    logger.info("%s", ModernVisualEngine.format_tool_status(
      "EmailBreach", "SUCCESS", email[:30]
    ))

    return jsonify(result)
  except Exception as e:
    logger.error("%s", ModernVisualEngine.format_error_card("ERROR", "EmailBreach", str(e)))
    return jsonify({"error": str(e), "success": False}), 500


@api_osint_trace_bp.route("/api/tools/email-verify", methods=["POST"])
def email_verify():
  """Verify email format, MX records, and check if disposable."""
  try:
    params = request.json or {}
    email = params.get("email", "")

    if not email:
      return jsonify({"error": "Email required", "success": False}), 400

    tracer = _get_email()
    fmt = tracer.validate_format(email)
    mx = tracer.check_mx(email)
    disp = tracer.is_disposable(email)

    return jsonify({
      "success": True,
      "email": email,
      "format_valid": fmt.get("format_valid", False),
      "domain": fmt.get("domain", ""),
      "has_mx": mx.get("has_mx", False),
      "mx_records": mx.get("mx_records", []),
      "is_disposable": disp.get("is_disposable", False),
    })
  except Exception as e:
    return jsonify({"error": str(e), "success": False}), 500


@api_osint_trace_bp.route("/api/tools/email-accounts", methods=["POST"])
def email_accounts():
  """Discover social accounts linked to an email."""
  try:
    params = request.json or {}
    email = params.get("email", "")

    if not email:
      return jsonify({"error": "Email required", "success": False}), 400

    tracer = _get_email()
    result = tracer.discover_accounts(email)

    return jsonify(result)
  except Exception as e:
    return jsonify({"error": str(e), "success": False}), 500


@api_osint_trace_bp.route("/api/tools/dehashed-search", methods=["POST"])
def dehashed_search():
  """Search Dehashed breach database."""
  try:
    params = request.json or {}
    query = params.get("query", "")
    query_type = params.get("type", "email")

    if not query:
      return jsonify({"error": "Search query required", "success": False}), 400

    tracer = _get_email()
    result = tracer.dehashed_search(query, query_type)

    return jsonify(result)
  except Exception as e:
    return jsonify({"error": str(e), "success": False}), 500
