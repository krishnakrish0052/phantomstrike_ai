"""
server_core/osint/social_profiler.py

Cross-platform social media account discovery and profiling.
Searches 30+ platforms for username presence, builds profile metadata,
and maps relationships between accounts.
"""

import json
import logging
import re
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class SocialProfiler:
  """Cross-platform social media account discovery and profiling.

  Searches for username presence across 30+ social platforms,
  extracts public profile metadata, and maps relationships.
  """

  # Platforms with their URL templates and detection methods
  PLATFORMS: List[Dict[str, Any]] = [
    {"name": "GitHub", "url": "https://github.com/{username}", "category": "dev", "check": "status"},
    {"name": "Twitter/X", "url": "https://twitter.com/{username}", "category": "social", "check": "status"},
    {"name": "Instagram", "url": "https://www.instagram.com/{username}/", "category": "social", "check": "status"},
    {"name": "Reddit", "url": "https://www.reddit.com/user/{username}", "category": "social", "check": "status"},
    {"name": "LinkedIn", "url": "https://www.linkedin.com/in/{username}", "category": "professional", "check": "status"},
    {"name": "Facebook", "url": "https://www.facebook.com/{username}", "category": "social", "check": "status"},
    {"name": "YouTube", "url": "https://www.youtube.com/@{username}", "category": "social", "check": "status"},
    {"name": "TikTok", "url": "https://www.tiktok.com/@{username}", "category": "social", "check": "status"},
    {"name": "Medium", "url": "https://medium.com/@{username}", "category": "blog", "check": "status"},
    {"name": "Dev.to", "url": "https://dev.to/{username}", "category": "dev", "check": "status"},
    {"name": "StackOverflow", "url": "https://stackoverflow.com/users/{username}", "category": "dev", "check": "status"},
    {"name": "HackerNews", "url": "https://news.ycombinator.com/user?id={username}", "category": "dev", "check": "status"},
    {"name": "GitLab", "url": "https://gitlab.com/{username}", "category": "dev", "check": "status"},
    {"name": "Bitbucket", "url": "https://bitbucket.org/{username}/", "category": "dev", "check": "status"},
    {"name": "Pinterest", "url": "https://www.pinterest.com/{username}/", "category": "social", "check": "status"},
    {"name": "Snapchat", "url": "https://www.snapchat.com/add/{username}", "category": "social", "check": "status"},
    {"name": "Telegram", "url": "https://t.me/{username}", "category": "messaging", "check": "status"},
    {"name": "Discord", "url": "https://discord.com/users/{username}", "category": "messaging", "check": "status"},
    {"name": "Twitch", "url": "https://www.twitch.tv/{username}", "category": "streaming", "check": "status"},
    {"name": "Spotify", "url": "https://open.spotify.com/user/{username}", "category": "music", "check": "status"},
    {"name": "SoundCloud", "url": "https://soundcloud.com/{username}", "category": "music", "check": "status"},
    {"name": "Patreon", "url": "https://www.patreon.com/{username}", "category": "creator", "check": "status"},
    {"name": "Keybase", "url": "https://keybase.io/{username}", "category": "security", "check": "status"},
    {"name": "HackerOne", "url": "https://hackerone.com/{username}", "category": "security", "check": "status"},
    {"name": "Bugcrowd", "url": "https://bugcrowd.com/{username}", "category": "security", "check": "status"},
    {"name": "DockerHub", "url": "https://hub.docker.com/u/{username}", "category": "dev", "check": "status"},
    {"name": "npm", "url": "https://www.npmjs.com/~{username}", "category": "dev", "check": "status"},
    {"name": "PyPI", "url": "https://pypi.org/user/{username}/", "category": "dev", "check": "status"},
    {"name": "Vimeo", "url": "https://vimeo.com/{username}", "category": "video", "check": "status"},
    {"name": "Dribbble", "url": "https://dribbble.com/{username}", "category": "design", "check": "status"},
  ]

  def __init__(self, timeout: int = 8):
    self._timeout = timeout

  # ── Single Platform Check ────────────────────────────────────────────

  def _check_platform(self, username: str, platform: Dict[str, Any]) -> Dict[str, Any]:
    """Check if a username exists on a single platform."""
    url = platform["url"].format(username=username)
    try:
      import requests
      headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; rv:125.0) Gecko/20100101 Firefox/125.0"
      }
      resp = requests.get(url, headers=headers, timeout=self._timeout, allow_redirects=True)

      # Status-based check: 200 = exists, 404 = not found
      status = resp.status_code
      exists = status == 200

      # Some platforms return 200 with a "not found" indicator
      not_found_patterns = [
        "page not found", "doesn't exist", "not found", "sorry",
        "couldn't find", "no user", "page isn't available",
      ]
      if exists and status == 200:
        text_lower = resp.text.lower()[:500]
        if any(p in text_lower for p in not_found_patterns):
          exists = False

      return {
        "platform": platform["name"],
        "category": platform["category"],
        "url": url,
        "exists": exists,
        "status_code": status,
        "response_size": len(resp.text),
      }
    except Exception as e:
      return {
        "platform": platform["name"],
        "category": platform["category"],
        "url": url,
        "exists": False,
        "error": str(e)[:100],
      }

  # ── Cross-Platform Search ────────────────────────────────────────────

  def search_username(self, username: str, platforms: Optional[List[str]] = None) -> Dict[str, Any]:
    """Search for a username across all configured platforms.

    Args:
      username: The username to search for.
      platforms: Optional list of platform names to search (defaults to all).

    Returns:
      Dict with found accounts, not found, errors, and category breakdown.
    """
    username = username.strip().lower()
    if not re.match(r"^[a-zA-Z0-9._\-]{1,40}$", username):
      return {"success": False, "error": "Invalid username format"}

    targets = self.PLATFORMS
    if platforms:
      targets = [p for p in self.PLATFORMS if p["name"] in platforms]

    import concurrent.futures
    results = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
      futures = {
        executor.submit(self._check_platform, username, platform): platform
        for platform in targets
      }
      for future in concurrent.futures.as_completed(futures):
        results.append(future.result())

    found = [r for r in results if r.get("exists")]
    not_found = [r for r in results if not r.get("exists") and "error" not in r]
    errors = [r for r in results if "error" in r]

    # Category breakdown
    categories: Dict[str, int] = {}
    for r in found:
      cat = r.get("category", "other")
      categories[cat] = categories.get(cat, 0) + 1

    return {
      "success": True,
      "username": username,
      "total_searched": len(targets),
      "found": found,
      "found_count": len(found),
      "not_found": not_found,
      "errors": errors,
      "categories": categories,
      "profile_urls": [r["url"] for r in found],
    }

  # ── Batch Search ─────────────────────────────────────────────────────

  def batch_search(self, usernames: List[str]) -> List[Dict[str, Any]]:
    """Search for multiple usernames."""
    return [self.search_username(u) for u in usernames]

  # ── GitHub Profile Deep Dive ─────────────────────────────────────────

  def github_deep_profile(self, username: str) -> Dict[str, Any]:
    """Extract detailed GitHub profile information."""
    try:
      import requests

      headers = {
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "PhantomStrike-OSINT/2.0",
      }

      resp = requests.get(
        f"https://api.github.com/users/{username}",
        headers=headers,
        timeout=10,
      )

      if resp.status_code == 404:
        return {"success": True, "found": False, "username": username}
      resp.raise_for_status()
      user = resp.json()

      # Get repos
      repos_resp = requests.get(
        f"https://api.github.com/users/{username}/repos?per_page=50&sort=updated",
        headers=headers,
        timeout=10,
      )
      repos = repos_resp.json() if repos_resp.status_code == 200 else []

      # Get orgs
      orgs_resp = requests.get(
        f"https://api.github.com/users/{username}/orgs",
        headers=headers,
        timeout=10,
      )
      orgs = orgs_resp.json() if orgs_resp.status_code == 200 else []

      # Check for leaked secrets in public repos (basic scan)
      leaked_hints = []
      for repo in repos[:10]:
        try:
          # Check for common secret patterns in repo description/topics
          desc = (repo.get("description") or "").lower()
          if any(kw in desc for kw in ["api_key", "password", "secret", "token", "credential"]):
            leaked_hints.append({
              "repo": repo["full_name"],
              "warning": f"Repository description may reference credentials",
            })
        except Exception:
          pass

      return {
        "success": True,
        "found": True,
        "username": username,
        "profile": {
          "name": user.get("name", ""),
          "company": user.get("company", ""),
          "blog": user.get("blog", ""),
          "location": user.get("location", ""),
          "email": user.get("email", ""),
          "bio": user.get("bio", ""),
          "twitter": user.get("twitter_username", ""),
          "public_repos": user.get("public_repos", 0),
          "public_gists": user.get("public_gists", 0),
          "followers": user.get("followers", 0),
          "following": user.get("following", 0),
          "created_at": user.get("created_at", ""),
          "updated_at": user.get("updated_at", ""),
          "hireable": user.get("hireable", False),
        },
        "repositories": [
          {
            "name": r["full_name"],
            "description": r.get("description", ""),
            "language": r.get("language", ""),
            "stars": r.get("stargazers_count", 0),
            "forks": r.get("forks_count", 0),
            "topics": r.get("topics", []),
            "updated_at": r.get("updated_at", ""),
          }
          for r in repos[:20]
        ],
        "organizations": [o["login"] for o in orgs],
        "leaked_secrets_hints": leaked_hints,
      }
    except Exception as e:
      return {"success": False, "error": str(e)}
