"""
server_core/orchestrator/agent_memory.py

Shared session memory for multi-agent context.

Stores discovered IPs, domains, credentials, vulnerabilities, and
tool outputs. Each agent can read all previous agents' findings.
Thread-safe via a reentrant lock.
"""

import logging
import threading
import time
from collections import OrderedDict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# Sentinel for missing keys
_MISSING = object()


class AgentMemory:
    """Thread-safe, append-only session memory shared across agents.

    Design:
      - OrderedDict preserves insertion order (useful for timeline views).
      - Reentrant lock allows the same thread to re-enter calls.
      - Each stored entry records agent_type and timestamp for attribution.
      - Compact summary method for quick context injection into agent prompts.
    """

    MAX_ENTRIES = 10_000

    def __init__(self):
        self._lock = threading.RLock()
        self._store: OrderedDict = OrderedDict()
        self._by_agent: Dict[str, List[str]] = {}  # agent_type → list of keys
        self._by_tag: Dict[str, List[str]] = {}  # tag → list of keys

    # ------------------------------------------------------------------
    # Write
    # ------------------------------------------------------------------

    def store(
        self,
        key: str,
        agent_type: str,
        data: Any,
        tags: Optional[List[str]] = None,
    ) -> None:
        """Store a finding under a unique key.

        Args:
            key: Unique identifier (e.g. phase id).
            agent_type: Which agent produced this (recon, vuln, …).
            data: Arbitrary structured data.
            tags: Optional tags for categorization (ip, domain, cred, etc.).
        """
        with self._lock:
            # Evict oldest if at capacity
            while len(self._store) >= self.MAX_ENTRIES:
                self._store.popitem(last=False)

            entry = {
                "key": key,
                "agent_type": agent_type,
                "data": data,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "epoch": time.time(),
                "tags": tags or [],
            }
            self._store[key] = entry
            self._by_agent.setdefault(agent_type, []).append(key)

            for tag in tags or []:
                self._by_tag.setdefault(tag, []).append(key)

            logger.debug("Memory stored [%s] by '%s'", key, agent_type)

    def update(self, key: str, data: Any, merge: bool = True) -> bool:
        """Update an existing entry, optionally merging dicts.

        Returns True if key existed and was updated.
        """
        with self._lock:
            if key not in self._store:
                return False
            if merge and isinstance(self._store[key]["data"], dict) and isinstance(data, dict):
                self._store[key]["data"].update(data)
            else:
                self._store[key]["data"] = data
            self._store[key]["timestamp"] = datetime.now(timezone.utc).isoformat()
            self._store[key]["epoch"] = time.time()
            return True

    # ------------------------------------------------------------------
    # Read
    # ------------------------------------------------------------------

    def get(self, key: str, default: Any = _MISSING) -> Any:
        """Retrieve a single stored entry by key."""
        with self._lock:
            entry = self._store.get(key)  # noqa: FURB123
            if entry is not None:
                return entry["data"]
        if default is not _MISSING:
            return default
        raise KeyError(key)

    def get_entry(self, key: str) -> Optional[Dict[str, Any]]:
        """Retrieve the full entry dict (including metadata)."""
        with self._lock:
            return self._store.get(key)

    def get_all(self) -> List[Dict[str, Any]]:
        """Return all entries as a list (newest last)."""
        with self._lock:
            return list(self._store.values())

    def get_by_agent(self, agent_type: str) -> List[Dict[str, Any]]:
        """Return all entries produced by a given agent type."""
        with self._lock:
            keys = self._by_agent.get(agent_type, [])
            return [self._store[k] for k in keys if k in self._store]

    def get_by_tag(self, tag: str) -> List[Dict[str, Any]]:
        """Return all entries tagged with the given tag."""
        with self._lock:
            keys = self._by_tag.get(tag, [])
            return [self._store[k] for k in keys if k in self._store]

    # ------------------------------------------------------------------
    # Context snapshot (for injecting into agent prompts)
    # ------------------------------------------------------------------

    def get_context(self, max_summary_items: int = 20) -> Dict[str, Any]:
        """Return a compact context snapshot for the next agent."""
        with self._lock:
            entries = list(self._store.values())
            # Most recent first
            recent = entries[-max_summary_items:] if len(entries) > max_summary_items else entries

            ips: List[str] = []
            domains: List[str] = []
            creds: List[str] = []
            vulns: List[str] = []
            other: List[str] = []

            for e in recent:
                d = e["data"]
                if isinstance(d, dict):
                    for ip in self._extract_strings(d, "ip", "ips", "ip_address"):
                        ips.append(ip)
                    for dom in self._extract_strings(d, "domain", "domains", "hostname", "host"):
                        domains.append(dom)
                    for cred in self._extract_strings(d, "username", "password", "credential", "cred"):
                        creds.append(cred)
                    for v in self._extract_strings(d, "vuln", "vulnerability", "cve"):
                        vulns.append(v)

                # Collect keys for timeline
                other.append(
                    f"[{e['agent_type']}] {e['key']}: {str(d)[:120]}"
                )

            return {
                "total_entries": len(entries),
                "recent_count": len(recent),
                "discovered_ips": list(dict.fromkeys(ips))[:30],
                "discovered_domains": list(dict.fromkeys(domains))[:30],
                "discovered_credentials": list(dict.fromkeys(creds))[:20],
                "discovered_vulnerabilities": list(dict.fromkeys(vulns))[:50],
                "timeline": other[-20:],
            }

    # ------------------------------------------------------------------
    # Utility
    # ------------------------------------------------------------------

    def clear(self) -> None:
        """Purge all memory. Irreversible."""
        with self._lock:
            self._store.clear()
            self._by_agent.clear()
            self._by_tag.clear()
            logger.info("Agent memory cleared")

    def size(self) -> int:
        """Number of stored entries."""
        with self._lock:
            return len(self._store)

    @staticmethod
    def _extract_strings(data: Dict[str, Any], *keys: str) -> List[str]:
        """Extract string values for the given keys from a dict."""
        results: List[str] = []
        for k in keys:
            v = data.get(k)
            if isinstance(v, str):
                results.append(v)
            elif isinstance(v, list):
                results.extend(item for item in v if isinstance(item, str))
        return results
