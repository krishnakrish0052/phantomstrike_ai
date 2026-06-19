"""
Defense API Routes
Flask Blueprint exposing the Self-Defense Engine endpoints.

Endpoints:
  GET  /api/defense/status       — current threat level, active alerts
  POST /api/defense/terminate    — trigger emergency termination
  GET  /api/defense/honeypots    — known honeypot database
  POST /api/defense/ip-check     — check if IP/domain is blacklisted
  POST /api/defense/canary-check — scan text/URLs for canary tokens
"""

import logging
import threading

from flask import Blueprint, jsonify, request

logger = logging.getLogger(__name__)

api_defense_bp = Blueprint("api_defense", __name__)

# ── Lazy-loaded defense coordinator singleton ───────────────────────────────
_coordinator = None
_coordinator_lock = threading.Lock()


def _get_coordinator():
    """Get or create the DefenseCoordinator singleton.

    Lazy-initialized so the module imports even if defense deps are missing.
    """
    global _coordinator
    if _coordinator is None:
        with _coordinator_lock:
            if _coordinator is None:
                try:
                    from server_core.defense import DefenseCoordinator
                    _coordinator = DefenseCoordinator()
                    logger.info("DefenseCoordinator initialized")
                except Exception as exc:
                    logger.error("Failed to initialize DefenseCoordinator: %s", exc)
                    return None
    return _coordinator


# ═══════════════════════════════════════════════════════════════════════════════
# GET /api/defense/status
# ═══════════════════════════════════════════════════════════════════════════════
@api_defense_bp.route("/api/defense/status", methods=["GET"])
def defense_status():
    """Return current defense status: threat level, alerts, subsystem health."""
    coordinator = _get_coordinator()
    if not coordinator:
        return jsonify({
            "error": "DefenseCoordinator unavailable",
            "threat_level": 3,
            "threat_label": "critical",
            "terminated": True,
        }), 503

    try:
        status = coordinator.get_status()
        return jsonify(status), 200
    except Exception as exc:
        logger.error("defense_status error: %s", exc)
        return jsonify({"error": str(exc)}), 500


# ═══════════════════════════════════════════════════════════════════════════════
# POST /api/defense/terminate
# ═══════════════════════════════════════════════════════════════════════════════
@api_defense_bp.route("/api/defense/terminate", methods=["POST"])
def defense_terminate():
    """Trigger emergency termination of all operations.

    Request body (optional):
      { "reason": "manual_override" }
    """
    coordinator = _get_coordinator()
    if not coordinator:
        return jsonify({"error": "DefenseCoordinator unavailable"}), 503

    try:
        data = request.get_json(silent=True) or {}
        reason = data.get("reason", "manual_api_trigger")
        coordinator.auto_terminate(reason)
        logger.warning("Emergency termination triggered via API: %s", reason)
        return jsonify({
            "status": "terminated",
            "reason": reason,
            "threat_level": coordinator.threat_level,
        }), 200
    except Exception as exc:
        logger.error("defense_terminate error: %s", exc)
        return jsonify({"error": str(exc)}), 500


# ═══════════════════════════════════════════════════════════════════════════════
# GET /api/defense/honeypots
# ═══════════════════════════════════════════════════════════════════════════════
@api_defense_bp.route("/api/defense/honeypots", methods=["GET"])
def defense_honeypots():
    """Return the known honeypot database: IP ranges, banner patterns, hostnames."""
    try:
        from server_core.defense.honeypot_detector import (
            HoneypotDetector,
            HONEYPOT_BANNER_PATTERNS,
            KNOWN_HONEYPOT_HOSTNAMES,
        )

        detector = HoneypotDetector()

        return jsonify({
            "known_ip_ranges": detector.get_known_ranges(),
            "banner_patterns": sorted(HONEYPOT_BANNER_PATTERNS.keys()),
            "known_hostnames": sorted(KNOWN_HONEYPOT_HOSTNAMES),
        }), 200
    except Exception as exc:
        logger.error("defense_honeypots error: %s", exc)
        return jsonify({"error": str(exc)}), 500


# ═══════════════════════════════════════════════════════════════════════════════
# POST /api/defense/ip-check
# ═══════════════════════════════════════════════════════════════════════════════
@api_defense_bp.route("/api/defense/ip-check", methods=["POST"])
def defense_ip_check():
    """Check if an IP or domain is blacklisted.

    Request body:
      { "target": "192.168.1.1" }
      or
      { "targets": ["1.2.3.4", "example.com"] }
    """
    try:
        from server_core.defense.ip_reputation import IPReputationMonitor

        data = request.get_json(silent=True) or {}
        monitor = IPReputationMonitor()

        # Single target check
        if "target" in data:
            target = data["target"]
            is_blacklisted = monitor.is_blacklisted(target)
            return jsonify({
                "target": target,
                "blacklisted": is_blacklisted,
                "statistics": monitor.get_statistics(),
            }), 200

        # Bulk check
        if "targets" in data:
            targets = data["targets"]
            if not isinstance(targets, list):
                return jsonify({"error": "'targets' must be a list"}), 400
            results = monitor.check_bulk(targets)
            return jsonify({
                "results": results,
                "statistics": monitor.get_statistics(),
            }), 200

        return jsonify({"error": "Provide 'target' or 'targets' in request body"}), 400

    except Exception as exc:
        logger.error("defense_ip_check error: %s", exc)
        return jsonify({"error": str(exc)}), 500


# ═══════════════════════════════════════════════════════════════════════════════
# POST /api/defense/canary-check
# ═══════════════════════════════════════════════════════════════════════════════
@api_defense_bp.route("/api/defense/canary-check", methods=["POST"])
def defense_canary_check():
    """Scan text, URLs, or response data for canary tokens and tripwires.

    Request body (at least one of):
      { "text": "<html>..." }         — scan raw text/response body
      { "url": "https://..." }        — check a single URL
      { "email": "user@domain.com" }  — check a single email address
    """
    try:
        from server_core.defense.canary_detector import CanaryDetector

        data = request.get_json(silent=True) or {}
        detector = CanaryDetector()

        results = {}

        # Scan raw text
        if "text" in data:
            detected = detector.detect(data["text"])
            results["text_scan"] = {
                "canary_detected": detected,
            }

        # Check single URL
        if "url" in data:
            url_detections = detector.check_url(data["url"])
            results["url_check"] = {
                "url": data["url"],
                "canary_detected": url_detections is not None,
                "matched_patterns": url_detections or [],
            }

        # Check email
        if "email" in data:
            email_is_canary = detector.check_email(data["email"])
            results["email_check"] = {
                "email": data["email"],
                "canary_detected": email_is_canary,
            }

        if not results:
            return jsonify({"error": "Provide 'text', 'url', or 'email' in request body"}), 400

        results["statistics"] = detector.get_statistics()
        return jsonify(results), 200

    except Exception as exc:
        logger.error("defense_canary_check error: %s", exc)
        return jsonify({"error": str(exc)}), 500
