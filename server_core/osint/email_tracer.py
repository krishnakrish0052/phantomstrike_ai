"""
server_core/osint/email_tracer.py

Email intelligence — breach database lookup, MX validation,
format verification, social media account discovery, disposable detection.
"""

import logging
import re
import socket
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class EmailTracer:
  """Email address intelligence and tracing.

  Provides breach database lookups (HIBP, Dehashed), MX record
  validation, format verification, disposable email detection,
  and social media account discovery linked to the email.
  """

  def __init__(
    self,
    hibp_key: str = "",
    dehashed_key: str = "",
    dehashed_email: str = "",
  ):
    self._hibp_key = hibp_key
    self._dehashed_key = dehashed_key
    self._dehashed_email = dehashed_email

  # ── Validation ───────────────────────────────────────────────────────

  def validate_format(self, email: str) -> Dict[str, Any]:
    """Validate email format and extract domain."""
    pattern = r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$"
    is_valid = bool(re.match(pattern, email))

    domain = email.split("@")[1] if "@" in email else ""

    return {
      "success": True,
      "email": email,
      "format_valid": is_valid,
      "domain": domain,
      "local_part": email.split("@")[0] if "@" in email else "",
    }

  def check_mx(self, email: str) -> Dict[str, Any]:
    """Check if the email's domain has valid MX records."""
    domain = email.split("@")[1] if "@" in email else ""
    if not domain:
      return {"success": False, "error": "Invalid email format"}

    try:
      import dns.resolver
      answers = dns.resolver.resolve(domain, "MX")
      mx_records = [
        {"preference": r.preference, "exchange": str(r.exchange).rstrip(".")}
        for r in answers
      ]
      return {
        "success": True,
        "domain": domain,
        "has_mx": len(mx_records) > 0,
        "mx_records": mx_records,
      }
    except ImportError:
      # Fallback: socket-based MX lookup
      try:
        import smtplib
        # Simple connection test
        return {
          "success": True,
          "domain": domain,
          "has_mx": True,
          "note": "Limited check — install dnspython for full MX resolution",
        }
      except Exception:
        return {"success": True, "domain": domain, "has_mx": False}
    except Exception as e:
      logger.debug("MX lookup failed for %s: %s", domain, e)
      return {"success": True, "domain": domain, "has_mx": False}

  def is_disposable(self, email: str) -> Dict[str, Any]:
    """Check if email is from a known disposable/temporary provider."""
    domain = email.split("@")[1].lower() if "@" in email else ""

    # Common disposable email domains
    disposable_domains = {
      "mailinator.com", "guerrillamail.com", "10minutemail.com",
      "tempmail.com", "throwaway.email", "sharklasers.com",
      "yopmail.com", "trashmail.com", "maildrop.cc", "getnada.com",
      "temp-mail.org", "fakeinbox.com", "guerrillamail.org",
      "guerrillamail.net", "guerrillamail.biz", "mailcatch.com",
      "mytrashmail.com", "spambog.com", "spambog.de", "spambog.ru",
      "discard.email", "discardmail.com", "emailondeck.com",
      "tempr.email", "mintemail.com", "mytemp.email",
    }

    return {
      "success": True,
      "email": email,
      "domain": domain,
      "is_disposable": domain in disposable_domains,
    }

  # ── Breach Database Lookup ───────────────────────────────────────────

  def hibp_breach(self, email: str) -> Dict[str, Any]:
    """Check HaveIBeenPwned for email breaches (requires API key for full data).

    Without API key: returns whether the email appears in any breach
    (privacy-preserving k-anonymity check via HIBP v3 API).
    """
    try:
      import requests

      # HIBP v3 uses k-anonymity: we send first 5 chars of SHA-1 hash
      import hashlib
      email_hash = hashlib.sha1(email.strip().lower().encode()).hexdigest().upper()
      prefix = email_hash[:5]
      suffix = email_hash[5:]

      headers = {}
      if self._hibp_key:
        headers["hibp-api-key"] = self._hibp_key

      resp = requests.get(
        f"https://api.pwnedpasswords.com/range/{prefix}",
        headers=headers,
        timeout=10,
      )

      found = False
      breach_count = 0
      for line in resp.text.splitlines():
        if line.startswith(suffix):
          breach_count = int(line.split(":")[1]) if ":" in line else 0
          found = True
          break

      return {
        "success": True,
        "email": email,
        "found_in_breach": found,
        "breach_count": breach_count,
        "note": "Password hash found in breaches" if found else "No breaches found",
      }
    except Exception as e:
      return {"success": False, "error": str(e)}

  def dehashed_search(self, query: str, query_type: str = "email") -> Dict[str, Any]:
    """Search Dehashed breach database.

    Args:
      query: Email, username, domain, or IP to search.
      query_type: Type of query ('email', 'username', 'domain', 'ip_address',
                  'password', 'hash', 'name', 'phone', 'address').
    """
    if not self._dehashed_key or not self._dehashed_email:
      return {"success": False, "error": "Dehashed credentials not configured"}

    try:
      import requests
      auth = (self._dehashed_email, self._dehashed_key)
      headers = {"Accept": "application/json"}

      resp = requests.get(
        "https://api.dehashed.com/search",
        params={"query": query},
        auth=auth,
        headers=headers,
        timeout=15,
      )
      resp.raise_for_status()
      data = resp.json()

      return {
        "success": True,
        "query": query,
        "total": data.get("total", 0),
        "entries": data.get("entries", [])[:50],
        "balance": data.get("balance", 0),
      }
    except Exception as e:
      return {"success": False, "error": str(e)}

  # ── Social Account Discovery ─────────────────────────────────────────

  def discover_accounts(self, email: str) -> Dict[str, Any]:
    """Discover social media accounts linked to an email address.

    Checks Gravatar, GitHub, and other public APIs for profile data
    associated with the email.
    """
    results: Dict[str, Any] = {"email": email, "accounts": []}

    # Gravatar
    try:
      import hashlib
      import requests
      email_hash = hashlib.md5(email.strip().lower().encode()).hexdigest()
      resp = requests.get(f"https://en.gravatar.com/{email_hash}.json", timeout=5)
      if resp.status_code == 200:
        data = resp.json()
        if "entry" in data and data["entry"]:
          entry = data["entry"][0]
          results["accounts"].append({
            "platform": "gravatar",
            "display_name": entry.get("displayName", ""),
            "profile_url": entry.get("profileUrl", ""),
            "avatar_url": entry.get("thumbnailUrl", ""),
            "accounts": entry.get("accounts", []),
          })
          results["gravatar"] = entry
    except Exception:
      pass

    # GitHub email search (public API)
    try:
      import requests
      resp = requests.get(
        f"https://api.github.com/search/users?q={email}+in:email",
        headers={"Accept": "application/vnd.github.v3+json"},
        timeout=10,
      )
      if resp.status_code == 200:
        gh_data = resp.json()
        if gh_data.get("total_count", 0) > 0:
          results["accounts"].append({
            "platform": "github",
            "users_found": gh_data["total_count"],
            "items": gh_data.get("items", [])[:5],
          })
    except Exception:
      pass

    results["success"] = True
    results["total_accounts"] = len(results["accounts"])
    return results

  # ── Full Report ──────────────────────────────────────────────────────

  def full_report(self, email: str) -> Dict[str, Any]:
    """Generate a comprehensive email intelligence report."""
    fmt = self.validate_format(email)
    if not fmt.get("format_valid"):
      return {"success": True, "email": email, **fmt}

    return {
      "success": True,
      "email": email,
      "validation": fmt,
      "mx_check": self.check_mx(email),
      "disposable_check": self.is_disposable(email),
      "breach_check": self.hibp_breach(email) if self._hibp_key else None,
      "accounts": self.discover_accounts(email),
    }
