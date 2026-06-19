"""
server_core/osint/ip_intel.py

IP intelligence engine — geolocation, ASN, proxy/VPN detection,
Shodan/Censys API integration, threat intelligence lookups.
"""

import ipaddress
import json
import logging
import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlencode

import requests

logger = logging.getLogger(__name__)


class IPIntel:
  """Multi-source IP intelligence aggregation.

  Queries free and commercial APIs to build a comprehensive picture of
  any IP address: geolocation, ISP, ASN, hosting provider, proxy/VPN/Tor
  status, open ports (via Shodan), and certificate data (via Censys).
  """

  # Free tier APIs (no key required for basic usage)
  FREQUENCY_API = "http://ip-api.com/json/{ip}?fields=66846719"
  FREQUENCY_BATCH = "http://ip-api.com/batch"

  def __init__(
    self,
    shodan_key: str = "",
    censys_id: str = "",
    censys_secret: str = "",
    abuseipdb_key: str = "",
  ):
    self._shodan_key = shodan_key
    self._censys_id = censys_id
    self._censys_secret = censys_secret
    self._abuseipdb_key = abuseipdb_key

  # ── Helpers ──────────────────────────────────────────────────────────

  def _get(self, url: str, timeout: int = 10, **kwargs) -> Dict[str, Any]:
    try:
      resp = requests.get(url, timeout=timeout, **kwargs)
      resp.raise_for_status()
      return resp.json()
    except Exception as e:
      logger.debug("HTTP GET failed for %s: %s", url[:80], e)
      return {"error": str(e)}

  def _is_ip(self, value: str) -> bool:
    try:
      ipaddress.ip_address(value.strip())
      return True
    except ValueError:
      return False

  # ── IP Geolocation (free) ────────────────────────────────────────────

  def geolocate(self, ip: str) -> Dict[str, Any]:
    """Geolocate an IP using ip-api.com (free, no key needed).

    Returns country, region, city, zip, lat/lon, ISP, org, AS, timezone,
    and whether the IP is a proxy, hosting, or mobile connection.
    """
    if not self._is_ip(ip):
      return {"error": f"Invalid IP address: {ip}", "success": False}

    data = self._get(self.FREQUENCY_API.format(ip=ip))

    if "error" in data or data.get("status") == "fail":
      return {"success": False, "error": data.get("message", "Lookup failed"), "ip": ip}

    return {
      "success": True,
      "ip": ip,
      "country": data.get("country", ""),
      "country_code": data.get("countryCode", ""),
      "region": data.get("regionName", ""),
      "city": data.get("city", ""),
      "zip": data.get("zip", ""),
      "lat": data.get("lat", 0),
      "lon": data.get("lon", 0),
      "timezone": data.get("timezone", ""),
      "isp": data.get("isp", ""),
      "org": data.get("org", ""),
      "as_number": data.get("as", "").split()[0] if data.get("as") else "",
      "as_name": data.get("as", ""),
      "is_proxy": data.get("proxy", False),
      "is_hosting": data.get("hosting", False),
      "is_mobile": data.get("mobile", False),
      "reverse_dns": data.get("reverse", ""),
    }

  # ── Shodan Integration ───────────────────────────────────────────────

  def shodan_lookup(self, ip: str) -> Dict[str, Any]:
    """Look up IP on Shodan — open ports, services, vulns, last scan."""
    if not self._shodan_key:
      return {"success": False, "error": "Shodan API key not configured"}

    if not self._is_ip(ip):
      return {"error": f"Invalid IP: {ip}", "success": False}

    try:
      resp = requests.get(
        f"https://api.shodan.io/shodan/host/{ip}?key={self._shodan_key}",
        timeout=15,
      )
      if resp.status_code == 404:
        return {"success": True, "ip": ip, "found": False, "message": "No Shodan data for this IP"}
      resp.raise_for_status()
      data = resp.json()

      return {
        "success": True,
        "ip": ip,
        "found": True,
        "organization": data.get("org", ""),
        "isp": data.get("isp", ""),
        "asn": data.get("asn", ""),
        "country": data.get("country_name", ""),
        "city": data.get("city", ""),
        "last_update": data.get("last_update", ""),
        "ports": data.get("ports", []),
        "hostnames": data.get("hostnames", []),
        "domains": data.get("domains", []),
        "os": data.get("os", ""),
        "vulns": list(data.get("vulns", []))[:20],
        "services": [
          {
            "port": s["port"],
            "protocol": s.get("transport", "tcp"),
            "service": s.get("product", s.get("_shodan", {}).get("module", "unknown")),
            "version": s.get("version", ""),
            "banner": (s.get("data", "") or "")[:500],
          }
          for s in data.get("data", [])[:20]
        ],
      }
    except requests.HTTPError as e:
      if e.response is not None and e.response.status_code == 401:
        return {"success": False, "error": "Invalid Shodan API key"}
      return {"success": False, "error": str(e)}
    except Exception as e:
      logger.error("Shodan lookup failed: %s", e)
      return {"success": False, "error": str(e)}

  def shodan_search(self, query: str, limit: int = 10) -> Dict[str, Any]:
    """Search Shodan for hosts matching a query string."""
    if not self._shodan_key:
      return {"success": False, "error": "Shodan API key not configured"}

    try:
      resp = requests.get(
        "https://api.shodan.io/shodan/host/search",
        params={"key": self._shodan_key, "query": query, "limit": limit},
        timeout=15,
      )
      resp.raise_for_status()
      data = resp.json()

      return {
        "success": True,
        "total": data.get("total", 0),
        "matches": [
          {
            "ip": m["ip_str"],
            "port": m["port"],
            "org": m.get("org", ""),
            "hostnames": m.get("hostnames", []),
            "domains": m.get("domains", []),
            "location": m.get("location", {}),
            "timestamp": m.get("timestamp", ""),
            "transport": m.get("transport", "tcp"),
            "product": m.get("product", ""),
            "version": m.get("version", ""),
          }
          for m in data.get("matches", [])[:limit]
        ],
      }
    except Exception as e:
      return {"success": False, "error": str(e)}

  # ── Threat Intelligence ──────────────────────────────────────────────

  def abuseipdb_check(self, ip: str, max_age_days: int = 90) -> Dict[str, Any]:
    """Check IP against AbuseIPDB for malicious activity reports."""
    if not self._abuseipdb_key:
      return {"success": False, "error": "AbuseIPDB API key not configured"}

    try:
      resp = requests.get(
        "https://api.abuseipdb.com/api/v2/check",
        headers={"Key": self._abuseipdb_key, "Accept": "application/json"},
        params={"ipAddress": ip, "maxAgeInDays": max_age_days, "verbose": ""},
        timeout=10,
      )
      resp.raise_for_status()
      data = resp.json().get("data", {})

      return {
        "success": True,
        "ip": ip,
        "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
        "total_reports": data.get("totalReports", 0),
        "last_reported_at": data.get("lastReportedAt", ""),
        "is_public": data.get("isPublic", False),
        "is_whitelisted": data.get("isWhitelisted", False),
        "country": data.get("countryName", ""),
        "isp": data.get("isp", ""),
        "domain": data.get("domain", ""),
        "usage_type": data.get("usageType", ""),
      }
    except Exception as e:
      return {"success": False, "error": str(e)}

  def is_tor_exit_node(self, ip: str) -> Dict[str, Any]:
    """Check if an IP is a known Tor exit node."""
    try:
      # Tor exit list via Tor Project's bulk exit list
      resp = requests.get("https://check.torproject.org/exit-addresses", timeout=10)
      is_exit = ip in resp.text
      return {"success": True, "ip": ip, "is_tor_exit_node": is_exit}
    except Exception:
      # Fallback: DNS-based check
      try:
        import socket
        reversed_ip = ".".join(reversed(ip.split(".")))
        query = f"{reversed_ip}.dnsel.torproject.org"
        socket.gethostbyname(query)
        return {"success": True, "ip": ip, "is_tor_exit_node": True}
      except Exception:
        return {"success": True, "ip": ip, "is_tor_exit_node": False}

  def is_vpn_or_proxy(self, ip: str) -> Dict[str, Any]:
    """Heuristic check if IP likely belongs to VPN/proxy/datacenter."""
    geo = self.geolocate(ip)
    if not geo.get("success"):
      return {"success": True, "ip": ip, "likely_proxy": False, "confidence": 0.0}

    score = 0.0
    reasons = []

    if geo.get("is_proxy"):
      score += 0.4
      reasons.append("Marked as proxy by ip-api")
    if geo.get("is_hosting"):
      score += 0.5
      reasons.append("Hosting/datacenter IP")

    # Check org/ISP for known VPN/hosting providers
    org_lower = (geo.get("org", "") + " " + geo.get("isp", "")).lower()
    hosting_keywords = [
      "digitalocean", "aws", "amazon", "google cloud", "azure", "vultr",
      "linode", "ovh", "hetzner", "datacamp", "m247", "hosting",
      "vpngate", "nordvpn", "expressvpn", "protonvpn", "mullvad",
      "private internet access", "cyberghost", "surfshark", "hidemyass",
      "cloudflare warp", "oracle cloud", "alibaba cloud", "tencent cloud",
    ]
    for kw in hosting_keywords:
      if kw in org_lower:
        score += 0.3
        reasons.append(f"Known hosting/VPN provider: {kw}")
        break

    return {
      "success": True,
      "ip": ip,
      "likely_proxy": score >= 0.4,
      "confidence": round(min(score, 1.0), 2),
      "reasons": reasons,
      "isp": geo.get("isp", ""),
      "org": geo.get("org", ""),
    }

  # ── Bulk Operations ──────────────────────────────────────────────────

  def bulk_geolocate(self, ips: List[str]) -> List[Dict[str, Any]]:
    """Batch geolocate up to 100 IPs at once."""
    results = []
    valid_ips = [ip for ip in ips if self._is_ip(ip)]

    # ip-api.com supports batch POST
    try:
      resp = requests.post(
        self.FREQUENCY_BATCH,
        json=[{"query": ip, "fields": "66846719"} for ip in valid_ips[:100]],
        timeout=30,
      )
      data = resp.json()
      for item in data:
        results.append({
          "ip": item.get("query", ""),
          "country": item.get("country", ""),
          "city": item.get("city", ""),
          "isp": item.get("isp", ""),
          "org": item.get("org", ""),
          "is_proxy": item.get("proxy", False),
          "is_hosting": item.get("hosting", False),
        })
    except Exception as e:
      # Fallback: sequential
      for ip in valid_ips[:100]:
        results.append(self.geolocate(ip))

    return results

  # ── Comprehensive IP Report ──────────────────────────────────────────

  def full_report(self, ip: str) -> Dict[str, Any]:
    """Generate a comprehensive IP intelligence report.

    Aggregates geolocation, Shodan, AbuseIPDB, Tor check, and proxy
    detection into a single structured report.
    """
    report = {
      "success": True,
      "ip": ip,
      "geolocation": self.geolocate(ip),
      "tor_check": self.is_tor_exit_node(ip),
      "proxy_check": self.is_vpn_or_proxy(ip),
      "shodan": self.shodan_lookup(ip) if self._shodan_key else None,
      "abuseipdb": self.abuseipdb_check(ip) if self._abuseipdb_key else None,
    }

    # Remove None values
    report = {k: v for k, v in report.items() if v is not None}

    return report
