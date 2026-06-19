"""
server_core/osint/dark_web_monitor.py

Dark web intelligence — .onion site monitoring, ransomware group
tracking, threat actor profiling, cryptocurrency tracing.
"""

import json
import logging
import re
import time
from datetime import datetime
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class DarkWebMonitor:
  """Dark web and threat intelligence monitoring.

  Provides .onion site scraping (via Tor), ransomware group activity
  tracking, threat actor profiling from OSINT sources, cryptocurrency
  transaction tracing, and C2 infrastructure mapping.
  """

  # Known ransomware group identifiers and their typical patterns
  RANSOMWARE_GROUPS = [
    {"name": "LockBit", "aliases": ["lockbit", "lockbit3"], "status": "active"},
    {"name": "ALPHV/BlackCat", "aliases": ["alphv", "blackcat"], "status": "active"},
    {"name": "Clop", "aliases": ["clop", "cl0p"], "status": "active"},
    {"name": "Play", "aliases": ["play", "playcrypt"], "status": "active"},
    {"name": "8Base", "aliases": ["8base"], "status": "active"},
    {"name": "Akira", "aliases": ["akira"], "status": "active"},
    {"name": "BianLian", "aliases": ["bianlian"], "status": "active"},
    {"name": "BlackBasta", "aliases": ["blackbasta"], "status": "active"},
    {"name": "Hunters International", "aliases": ["hunters"], "status": "active"},
    {"name": "Medusa", "aliases": ["medusa", "medusalocker"], "status": "active"},
    {"name": "RansomHub", "aliases": ["ransomhub"], "status": "active"},
    {"name": "Rhysida", "aliases": ["rhysida"], "status": "active"},
  ]

  def __init__(
    self,
    tor_proxy: str = "socks5h://127.0.0.1:9050",
    blockchain_api_key: str = "",
  ):
    self._tor_proxy = tor_proxy
    self._blockchain_key = blockchain_api_key

  # ── Tor Session ──────────────────────────────────────────────────────

  def _tor_session(self) -> Any:
    """Create a requests session routed through Tor."""
    import requests
    session = requests.Session()
    session.proxies = {
      "http": self._tor_proxy,
      "https": self._tor_proxy,
    }
    session.headers.update({
      "User-Agent": "Mozilla/5.0 (Windows NT 10.0; rv:125.0) Gecko/20100101 Firefox/125.0"
    })
    return session

  # ── .onion Site Scraping ─────────────────────────────────────────────

  def scrape_onion(self, onion_url: str) -> Dict[str, Any]:
    """Scrape a .onion site via Tor.

    Args:
      onion_url: Full .onion URL (e.g., 'http://xxx.onion/').

    Returns:
      Dict with scraped content, status code, and headers.
    """
    if not onion_url.endswith(".onion") and ".onion/" not in onion_url:
      return {"success": False, "error": "Not a valid .onion URL"}

    try:
      session = self._tor_session()
      resp = session.get(onion_url, timeout=30)

      return {
        "success": True,
        "url": onion_url,
        "status_code": resp.status_code,
        "headers": dict(resp.headers),
        "content_type": resp.headers.get("content-type", ""),
        "content_size": len(resp.text),
        "content_preview": resp.text[:10000],
        "title": self._extract_title(resp.text),
      }
    except Exception as e:
      return {"success": False, "error": str(e)}

  def _extract_title(self, html: str) -> str:
    """Extract page title from HTML."""
    match = re.search(r"<title>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
    return match.group(1).strip() if match else ""

  # ── Ransomware Group Tracking ────────────────────────────────────────

  def ransomwatch_feed(self) -> Dict[str, Any]:
    """Fetch the latest ransomware activity feed.

    Uses the public ransomwatch API (ransomwhat.telemetry.ltd) to get
    recent ransomware victim posts.
    """
    try:
      import requests
      resp = requests.get(
        "https://api.ransomware.live/v2/recentvictims",
        timeout=15,
      )
      resp.raise_for_status()
      data = resp.json()

      victims = []
      for entry in data[:50]:
        victims.append({
          "group": entry.get("group_name", ""),
          "victim": entry.get("post_title", ""),
          "description": entry.get("description", "")[:500],
          "website": entry.get("website", ""),
          "published": entry.get("published", ""),
          "country": entry.get("country", ""),
          "activity": entry.get("activity", ""),
          "screenshots": entry.get("screenshots", False),
        })

      return {
        "success": True,
        "total": len(victims),
        "victims": victims,
        "timestamp": datetime.now().isoformat(),
      }
    except Exception as e:
      logger.error("Ransomwatch feed failed: %s", e)
      return {"success": False, "error": str(e)}

  def list_ransomware_groups(self) -> Dict[str, Any]:
    """Return the list of tracked ransomware groups with status."""
    return {
      "success": True,
      "total": len(self.RANSOMWARE_GROUPS),
      "groups": self.RANSOMWARE_GROUPS,
    }

  # ── Cryptocurrency Tracing ───────────────────────────────────────────

  def trace_bitcoin_address(self, address: str) -> Dict[str, Any]:
    """Trace a Bitcoin address via Blockchain.com API.

    Returns balance, transaction count, and recent transactions.
    """
    try:
      import requests
      resp = requests.get(
        f"https://blockchain.info/rawaddr/{address}",
        params={"limit": 20, "offset": 0},
        timeout=15,
      )
      if resp.status_code == 429:
        return {"success": False, "error": "Rate limited — try again later"}

      data = resp.json()

      return {
        "success": True,
        "address": address,
        "hash160": data.get("hash160", ""),
        "total_received": data.get("total_received", 0),
        "total_sent": data.get("total_sent", 0),
        "final_balance": data.get("final_balance", 0),
        "n_tx": data.get("n_tx", 0),
        "transactions": [
          {
            "hash": tx["hash"],
            "time": tx.get("time", 0),
            "result": tx.get("result", 0),
            "balance": tx.get("balance", 0),
            "size": tx.get("size", 0),
          }
          for tx in data.get("txs", [])[:10]
        ],
        "balance_btc": data.get("final_balance", 0) / 100000000,
      }
    except Exception as e:
      return {"success": False, "error": str(e)}

  def trace_ethereum_address(self, address: str) -> Dict[str, Any]:
    """Trace an Ethereum address via Etherscan API."""
    try:
      import requests
      api_key = self._blockchain_key or "YourApiKeyToken"
      resp = requests.get(
        "https://api.etherscan.io/api",
        params={
          "module": "account",
          "action": "balance",
          "address": address,
          "tag": "latest",
          "apikey": api_key,
        },
        timeout=10,
      )
      data = resp.json()

      # Also get transaction list
      tx_resp = requests.get(
        "https://api.etherscan.io/api",
        params={
          "module": "account",
          "action": "txlist",
          "address": address,
          "startblock": 0,
          "endblock": 99999999,
          "page": 1,
          "offset": 20,
          "sort": "desc",
          "apikey": api_key,
        },
        timeout=15,
      )
      tx_data = tx_resp.json()

      balance_wei = int(data.get("result", "0"))
      balance_eth = balance_wei / 1e18

      return {
        "success": True,
        "address": address,
        "balance_wei": balance_wei,
        "balance_eth": round(balance_eth, 6),
        "transactions": [
          {
            "hash": tx["hash"],
            "from": tx["from"],
            "to": tx["to"],
            "value_eth": round(int(tx["value"]) / 1e18, 6),
            "timestamp": tx.get("timeStamp", ""),
            "block": tx.get("blockNumber", ""),
          }
          for tx in tx_data.get("result", [])[:10]
        ] if tx_data.get("status") == "1" else [],
      }
    except Exception as e:
      return {"success": False, "error": str(e)}

  # ── Threat Actor Profiling ───────────────────────────────────────────

  def profile_threat_actor(self, actor_name: str) -> Dict[str, Any]:
    """Build a threat actor profile from OSINT sources.

    Cross-references the actor name against known APT groups,
    ransomware operations, and publicly reported campaigns.
    """
    profile: Dict[str, Any] = {
      "name": actor_name,
      "aliases": [],
      "affiliations": [],
      "targeting": [],
      "tools": [],
      "campaigns": [],
      "ransomware_involvement": False,
      "sources": [],
    }

    actor_lower = actor_name.lower()

    # Check against known ransomware groups
    for group in self.RANSOMWARE_GROUPS:
      if actor_lower in [group["name"].lower()] + [a.lower() for a in group["aliases"]]:
        profile["aliases"] = group["aliases"]
        profile["ransomware_involvement"] = True
        profile["affiliations"].append(f"Ransomware: {group['name']}")
        profile["sources"].append("ransomwatch / ransomware.live")

    # Known APT group database (abbreviated)
    apt_groups = {
      "apt28": {"aliases": ["fancy bear", "sofacy", "strontium"], "country": "RU", "targeting": ["government", "military", "defense"]},
      "apt29": {"aliases": ["cozy bear", "the dukes"], "country": "RU", "targeting": ["government", "think tanks", "healthcare"]},
      "apt41": {"aliases": ["winnti", "barium"], "country": "CN", "targeting": ["technology", "gaming", "telecom"]},
      "lazarus": {"aliases": ["hidden cobra", "zinc"], "country": "KP", "targeting": ["financial", "crypto", "defense"]},
      "hafnium": {"aliases": ["hafnium"], "country": "CN", "targeting": ["exchange servers", "technology"]},
      "sandworm": {"aliases": ["voodoo bear", "iron viking"], "country": "RU", "targeting": ["energy", "critical infrastructure"]},
    }

    for apt_id, apt in apt_groups.items():
      if actor_lower == apt_id.lower() or actor_lower in [a.lower() for a in apt["aliases"]]:
        profile["aliases"].extend(apt["aliases"])
        profile["affiliations"].append(f"APT: {apt_id.upper()} ({apt['country']})")
        profile["targeting"] = apt["targeting"]
        profile["sources"].append("MITRE ATT&CK / threat intelligence")

    profile["success"] = True
    return profile

  # ── C2 Infrastructure Mapping ────────────────────────────────────────

  def map_c2_infrastructure(self, ip_or_domain: str) -> Dict[str, Any]:
    """Map potential C2 infrastructure around an IP or domain.

    Uses Shodan/Censys fingerprints and certificate transparency logs
    to find related infrastructure.
    """
    results: Dict[str, Any] = {
      "success": True,
      "target": ip_or_domain,
      "related_ips": [],
      "related_domains": [],
      "certificates": [],
      "open_ports": [],
    }

    # Check if it's an IP or domain
    is_ip = bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip_or_domain))

    if is_ip:
      # Try Shodan for open ports
      try:
        import requests
        # Basic port scan via Shodan InternetDB (free, no API key)
        resp = requests.get(
          f"https://internetdb.shodan.io/{ip_or_domain}",
          timeout=10,
        )
        if resp.status_code == 200:
          data = resp.json()
          results["hostnames"] = data.get("hostnames", [])
          results["open_ports"] = data.get("ports", [])
          results["tags"] = data.get("tags", [])
          results["vulns"] = data.get("vulns", [])
      except Exception:
        pass
    else:
      # For domains: check certificate transparency
      try:
        import requests
        resp = requests.get(
          f"https://crt.sh/?q=%25.{ip_or_domain}&output=json",
          timeout=15,
        )
        if resp.status_code == 200:
          certs = resp.json()
          seen_domains = set()
          for cert in certs[:50]:
            name = cert.get("name_value", "")
            for domain in name.split("\n"):
              domain = domain.strip().lower()
              if domain and domain not in seen_domains:
                seen_domains.add(domain)
                results["related_domains"].append(domain)
      except Exception:
        pass

    return results
