"""
server_core/osint/phone_tracer.py

Phone number intelligence — carrier lookup, line type detection,
geolocation, validation, and formatting for international numbers.
"""

import logging
import re
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class PhoneTracer:
  """Phone number intelligence and tracing.

  Provides carrier identification, line type detection (mobile/landline/VoIP),
  geographic region lookup, number validation, and international formatting.
  Uses phone number parsing libraries and free lookup APIs.
  """

  def __init__(self, numverify_key: str = ""):
    self._numverify_key = numverify_key

  # ── Validation & Parsing ─────────────────────────────────────────────

  def validate(self, phone: str) -> Dict[str, Any]:
    """Validate and parse a phone number.

    Returns E.164 format, national format, country, carrier hints,
    and whether the number is valid and possible.
    """
    try:
      import phonenumbers
      from phonenumbers import carrier, geocoder, number_type

      parsed = phonenumbers.parse(phone, None)

      if not phonenumbers.is_valid_number(parsed):
        return {
          "success": True,
          "valid": False,
          "possible": phonenumbers.is_possible_number(parsed),
          "input": phone,
        }

      region = phonenumbers.region_code_for_number(parsed)
      nt = number_type(parsed)
      type_names = {
        0: "FIXED_LINE", 1: "MOBILE", 2: "FIXED_LINE_OR_MOBILE",
        3: "TOLL_FREE", 4: "PREMIUM_RATE", 5: "SHARED_COST",
        6: "VOIP", 7: "PERSONAL_NUMBER", 8: "PAGER",
        9: "UAN", 10: "VOICEMAIL", 99: "UNKNOWN",
      }

      return {
        "success": True,
        "valid": True,
        "possible": True,
        "input": phone,
        "e164": phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164),
        "national": phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.NATIONAL),
        "international": phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
        "country_code": parsed.country_code,
        "region": region,
        "line_type": type_names.get(nt, "UNKNOWN"),
        "carrier_hint": carrier.name_for_number(parsed, "en") if region else "",
        "geolocation": geocoder.description_for_number(parsed, "en") if region else "",
      }
    except ImportError:
      # Fallback: regex-only validation
      cleaned = re.sub(r"[\s\-\(\)\.]+", "", phone)
      if cleaned.startswith("+"):
        cleaned = cleaned[1:]

      if re.match(r"^\d{7,15}$", cleaned):
        return {
          "success": True,
          "valid": True,
          "possible": True,
          "input": phone,
          "e164": f"+{cleaned}",
          "note": "phonenumbers library not installed — limited validation",
        }
      return {"success": True, "valid": False, "input": phone}

    except Exception as e:
      return {"success": False, "error": str(e), "input": phone}

  # ── Carrier Lookup ───────────────────────────────────────────────────

  def numverify_lookup(self, phone: str) -> Dict[str, Any]:
    """Look up phone number via NumVerify API (free tier: 250 req/month).

    Returns carrier, line type, and location data.
    """
    if not self._numverify_key:
      return {"success": False, "error": "NumVerify API key not configured"}

    try:
      import requests
      resp = requests.get(
        "http://apilayer.net/api/validate",
        params={
          "access_key": self._numverify_key,
          "number": phone,
          "format": 1,
        },
        timeout=10,
      )
      data = resp.json()

      if not data.get("valid"):
        return {"success": True, "valid": False, "input": phone}

      return {
        "success": True,
        "valid": True,
        "input": phone,
        "number": data.get("number", ""),
        "local_format": data.get("local_format", ""),
        "international_format": data.get("international_format", ""),
        "country_prefix": data.get("country_prefix", ""),
        "country_code": data.get("country_code", ""),
        "country_name": data.get("country_name", ""),
        "location": data.get("location", ""),
        "carrier": data.get("carrier", ""),
        "line_type": data.get("line_type", ""),
      }
    except Exception as e:
      return {"success": False, "error": str(e)}

  # ── Bulk Validation ──────────────────────────────────────────────────

  def bulk_validate(self, phones: List[str]) -> List[Dict[str, Any]]:
    """Validate a batch of phone numbers."""
    return [self.validate(p) for p in phones]

  # ── Phone Intelligence Report ────────────────────────────────────────

  def full_report(self, phone: str) -> Dict[str, Any]:
    """Generate a comprehensive phone number intelligence report."""
    base = self.validate(phone)
    if not base.get("valid"):
      return base

    numverify = {}
    if self._numverify_key:
      numverify = self.numverify_lookup(phone)

    # Heuristic: check if number belongs to known VoIP/test ranges
    e164 = base.get("e164", "")
    is_voip = base.get("line_type") == "VOIP"
    is_premium = base.get("line_type") in ("PREMIUM_RATE", "SHARED_COST")
    is_tollfree = base.get("line_type") == "TOLL_FREE"

    # Known disposable/temporary number prefixes
    disposable_prefixes = []
    if any(e164.startswith(p) for p in ["+1", "+44"]):
      pass

    return {
      "success": True,
      "phone": phone,
      "validation": base,
      "carrier_data": numverify,
      "risk_assessment": {
        "is_voip": is_voip,
        "is_premium": is_premium,
        "is_tollfree": is_tollfree,
        "is_disposable": False,  # Requires external API
        "risk_level": "HIGH" if is_voip else ("LOW" if base.get("line_type") == "MOBILE" else "MEDIUM"),
      },
    }
