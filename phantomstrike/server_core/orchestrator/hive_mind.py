"""
Hive Mind v3 — Shared knowledge base for all 35 PhantomStrike agents.

v3 ENHANCEMENTS over v2:
  - Event bus: Agents subscribe to events (NEW_HOST, NEW_VULN, etc.), get notified reactively
  - Snapshots: Periodic JSON snapshots for post-mission analysis
  - ContextSelector: Selective context injection — prevents 18% context-forgetting failures
  - Typed findings: Every finding carries confidence score + evidence chain
  - Thread-safe, persistent to DB, append-only with snapshot capability.
"""
import json
import logging
import threading
import time
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional, Set

logger = logging.getLogger(__name__)

# ── Event types for the event bus ──
class HiveMindEvent:
  NEW_HOST = "new_host"
  NEW_SERVICE = "new_service" 
  NEW_VULN = "new_vuln"
  NEW_CRED = "new_cred"
  NEW_SESSION = "new_session"
  NEW_COMPROMISED = "new_compromised"
  THREAT_LEVEL_CHANGE = "threat_change"
  MISSION_PHASE_CHANGE = "phase_change"
  AGENT_STATUS_CHANGE = "agent_status_change"
  DEFENSE_ALERT = "defense_alert"
  MISSION_TERMINATED = "mission_terminated"

class ContextSelector:
  """Selective context injection — prevents context-forgetting failures.

  PentestGPT V2 research showed that dumping all context causes 18% failure rate
  from context forgetting. This selector provides each agent ONLY what it needs.
  """

  @staticmethod
  def for_agent(agent_type: str, hive: 'HiveMind') -> Dict[str, Any]:
    """Return ONLY the context subset relevant to this agent type."""
    base = {
      "mission_id": hive.mission_id,
      "mission_phase": hive.mission_phase,
      "current_threat_level": hive.current_threat_level,
    }

    if agent_type in ("recon", "webapp", "cloud", "supply_chain"):
      return {**base, "target_profile": dict(hive.target_profile),
              "discovered_hosts": list(hive.discovered_hosts[-50:]),
              "discovered_people": list(hive.discovered_people[-20:])}

    if agent_type in ("vuln", "exploit", "bug_bounty"):
      return {**base, "discovered_hosts": list(hive.discovered_hosts[-50:]),
              "discovered_services": list(hive.discovered_services[-50:]),
              "discovered_vulns": list(hive.discovered_vulns[-50:]),
              "discovered_creds": list(hive.discovered_creds[-20:]),
              "active_sessions": list(hive.active_sessions),
              "target_profile": dict(hive.target_profile)}

    if agent_type in ("post_exploit", "privesc", "lateral_move", "persistence",
                       "cred_access", "reverse_engineering"):
      return {**base, "active_sessions": list(hive.active_sessions),
              "compromised_hosts": list(hive.compromised_hosts[-30:]),
              "discovered_creds": list(hive.discovered_creds[-30:]),
              "discovered_files": list(hive.discovered_files[-30:])}

    if agent_type in ("exfil", "cleanup", "auto_fixer"):
      return {**base, "discovered_files": list(hive.discovered_files[-50:]),
              "exfiltrated_data": list(hive.exfiltrated_data[-50:]),
              "active_sessions": list(hive.active_sessions),
              "compromised_hosts": list(hive.compromised_hosts)}

    if agent_type in ("trace_buster", "decoy", "opsec", "counter_surveillance",
                       "emergency", "reverse_trace"):
      return {**base, "defense_alerts": list(hive.defense_alerts[-30:]),
              "current_threat_level": hive.current_threat_level,
              "identity_rotation_log": list(hive.identity_rotation_log[-20:]),
              "active_sessions": list(hive.active_sessions),
              "agent_status": dict(hive.agent_status)}

    # Domain agents get full state for cross-domain awareness
    if agent_type in ("iot", "scada", "automotive", "satellite", "blockchain",
                       "ai_exploit", "mobile", "telecom", "physical", "darkweb",
                       "drone", "nuclear_opsec"):
      return {**base, "target_profile": dict(hive.target_profile),
              "discovered_hosts": list(hive.discovered_hosts[-30:]),
              "discovered_services": list(hive.discovered_services[-30:]),
              "discovered_vulns": list(hive.discovered_vulns[-30:]),
              "compromised_hosts": list(hive.compromised_hosts[-20:]),
              "active_sessions": list(hive.active_sessions),
              "current_threat_level": hive.current_threat_level}

    return hive.get_full_state()


class HiveMind:
  """Thread-safe shared intelligence across all 35 agents — v3 with event bus."""

  def __init__(self, mission_id: str = "", db=None):
    self.mission_id = mission_id or f"mission_{int(time.time())}"
    self._db = db
    self._lock = threading.RLock()
    self._created_at = time.time()

    # ── Target intelligence ──
    self.target_profile: Dict[str, Any] = {}
    self.discovered_hosts: List[Dict] = []
    self.discovered_services: List[Dict] = []
    self.discovered_vulns: List[Dict] = []
    self.discovered_creds: List[Dict] = []
    self.discovered_files: List[Dict] = []
    self.discovered_people: List[Dict] = []

    # ── Operational state ──
    self.active_sessions: List[Dict] = []
    self.compromised_hosts: List[Dict] = []
    self.persistence_mechanisms: List[Dict] = []
    self.exfiltrated_data: List[Dict] = []

    # ── Defense state ──
    self.defense_alerts: List[Dict] = []
    self.current_threat_level: int = 0
    self.identity_rotation_log: List[Dict] = []
    self._terminated: bool = False

    # ── Mission state ──
    self.mission_phase: str = "initializing"
    self.agent_status: Dict[str, Any] = {}
    self.findings_log: List[Dict] = []
    self.recommendations: List[Dict] = []

    # ── v3: Event bus ──
    self._subscribers: Dict[str, List[Callable]] = {
      HiveMindEvent.NEW_HOST: [],
      HiveMindEvent.NEW_SERVICE: [],
      HiveMindEvent.NEW_VULN: [],
      HiveMindEvent.NEW_CRED: [],
      HiveMindEvent.NEW_SESSION: [],
      HiveMindEvent.NEW_COMPROMISED: [],
      HiveMindEvent.THREAT_LEVEL_CHANGE: [],
      HiveMindEvent.MISSION_PHASE_CHANGE: [],
      HiveMindEvent.AGENT_STATUS_CHANGE: [],
      HiveMindEvent.DEFENSE_ALERT: [],
      HiveMindEvent.MISSION_TERMINATED: [],
    }
    self._event_history: List[Dict] = []

    # ── v3: Snapshots ──
    self._snapshots: List[Dict] = []
    self._last_snapshot_time: float = 0.0
    self._snapshot_interval: float = 60.0  # seconds

    logger.info("HiveMind v3 initialized for %s", self.mission_id)

  # ═══════════════════════════════════════════════════════════════════════════
  # Event Bus
  # ═══════════════════════════════════════════════════════════════════════════

  def subscribe(self, event_type: str, callback: Callable, agent_id: str = "") -> None:
    """Register a callback for an event type. callback receives (event_data: dict)."""
    if event_type not in self._subscribers:
      logger.warning("Unknown event type '%s' — subscription ignored", event_type)
      return
    with self._lock:
      wrapped = lambda data, cb=callback, aid=agent_id: cb({**data, "_agent_id": aid})
      self._subscribers[event_type].append(wrapped)
    logger.debug("Agent %s subscribed to %s", agent_id or "unknown", event_type)

  def unsubscribe(self, event_type: str, callback: Callable) -> None:
    """Remove a subscription."""
    if event_type not in self._subscribers:
      return
    with self._lock:
      self._subscribers[event_type] = [
        cb for cb in self._subscribers[event_type]
        if getattr(cb, '__wrapped__', cb) != callback
      ]

  def publish(self, event_type: str, data: dict) -> None:
    """Notify all subscribers of an event."""
    event = {
      "type": event_type,
      "data": data,
      "timestamp": datetime.now().isoformat(),
      "mission_phase": self.mission_phase,
    }
    with self._lock:
      self._event_history.append(event)

    subscribers = list(self._subscribers.get(event_type, []))
    for callback in subscribers:
      try:
        callback(data)
      except Exception as exc:
        logger.error("Event callback failed for %s: %s", event_type, exc)

  # ═══════════════════════════════════════════════════════════════════════════
  # Data append methods (with event publishing)
  # ═══════════════════════════════════════════════════════════════════════════

  def _append(self, attr: str, item: Dict, agent_id: str = "", event_type: str = ""):
    with self._lock:
      item.setdefault("timestamp", datetime.now().isoformat())
      item.setdefault("added_by", agent_id)
      item.setdefault("confidence", 0.5)  # v3: typed confidence
      getattr(self, attr).append(item)
      self.findings_log.append({
        "type": attr, "data": item, "agent": agent_id,
        "timestamp": item["timestamp"], "confidence": item.get("confidence", 0.5)
      })
    # Persist to DB
    if self._db:
      try:
        self._db.add_mission_finding(
          self.mission_id, 0, attr, "info",
          str(item.get("name", ""))[:100],
          json.dumps(item)[:500], json.dumps(item)
        )
      except Exception:
        pass
    # Publish event
    if event_type:
      self.publish(event_type, {"item": item, "agent": agent_id})
    # Auto-snapshot if interval elapsed
    self._auto_snapshot()

  def add_host(self, host, agent=""): self._append("discovered_hosts", host, agent, HiveMindEvent.NEW_HOST)
  def add_service(self, svc, agent=""): self._append("discovered_services", svc, agent, HiveMindEvent.NEW_SERVICE)
  def add_vuln(self, v, agent=""): self._append("discovered_vulns", v, agent, HiveMindEvent.NEW_VULN)
  def add_cred(self, c, agent=""): self._append("discovered_creds", c, agent, HiveMindEvent.NEW_CRED)
  def add_file(self, f, agent=""): self._append("discovered_files", f, agent)
  def add_person(self, p, agent=""): self._append("discovered_people", p, agent)

  def add_session(self, s, agent=""):
    with self._lock:
      s["established_at"] = datetime.now().isoformat()
      s["added_by"] = agent
      self.active_sessions.append(s)
    self.publish(HiveMindEvent.NEW_SESSION, {"session": s, "agent": agent})

  def add_compromised_host(self, h, agent=""):
    self._append("compromised_hosts", h, agent, HiveMindEvent.NEW_COMPROMISED)

  def add_persistence(self, m, agent=""): self._append("persistence_mechanisms", m, agent)
  def add_exfiltrated(self, d, agent=""): self._append("exfiltrated_data", d, agent)
  def add_finding(self, f, agent=""): self._append("findings_log", f, agent)

  def add_recommendation(self, r, agent=""):
    with self._lock:
      r["timestamp"] = datetime.now().isoformat()
      self.recommendations.append(r)

  def add_alert(self, alert, agent=""):
    with self._lock:
      alert["timestamp"] = datetime.now().isoformat()
      self.defense_alerts.append(alert)
    self.publish(HiveMindEvent.DEFENSE_ALERT, {"alert": alert, "agent": agent})
    if self._db:
      try:
        self._db.log_defense_event(
          alert.get("type", "unknown"), alert.get("threat_level", 0),
          alert.get("target", ""), json.dumps(alert.get("details", {})),
          alert.get("action_taken", "")
        )
      except Exception:
        pass

  # ═══════════════════════════════════════════════════════════════════════════
  # State mutators (with events)
  # ═══════════════════════════════════════════════════════════════════════════

  def set_threat_level(self, level: int, reason="", agent=""):
    with self._lock:
      old = self.current_threat_level
      self.current_threat_level = max(0, min(100, level))
      if self.current_threat_level != old:
        logger.warning("Threat: %d→%d (%s)", old, self.current_threat_level, reason)
        self.publish(HiveMindEvent.THREAT_LEVEL_CHANGE, {
          "old": old, "new": self.current_threat_level, "reason": reason, "agent": agent
        })

  def set_phase(self, phase: str):
    with self._lock:
      old = self.mission_phase
      self.mission_phase = phase
      logger.info("Phase: %s→%s", old, phase)
    self.publish(HiveMindEvent.MISSION_PHASE_CHANGE, {"old": old, "new": phase})

  def update_agent_status(self, agent_id: str, status: str):
    with self._lock:
      self.agent_status[agent_id] = {"status": status, "updated_at": datetime.now().isoformat()}
    self.publish(HiveMindEvent.AGENT_STATUS_CHANGE, {"agent_id": agent_id, "status": status})

  def is_defense_active(self) -> bool: return not self._terminated

  def terminate(self, reason=""):
    with self._lock:
      self._terminated = True
      self.mission_phase = "terminated"
      logger.critical("HIVE MIND TERMINATED: %s", reason)
    self.publish(HiveMindEvent.MISSION_TERMINATED, {"reason": reason})
    # Force final snapshot
    self.snapshot()

  # ═══════════════════════════════════════════════════════════════════════════
  # v3: Snapshots
  # ═══════════════════════════════════════════════════════════════════════════

  def snapshot(self) -> Dict:
    """Serialise full state to a dict for post-mission analysis. Stores in-memory history."""
    with self._lock:
      snap = {
        "timestamp": datetime.now().isoformat(),
        "mission_id": self.mission_id,
        "mission_phase": self.mission_phase,
        "uptime_seconds": round(time.time() - self._created_at, 1),
        "threat_level": self.current_threat_level,
        "terminated": self._terminated,
        "counts": {
          "hosts": len(self.discovered_hosts),
          "services": len(self.discovered_services),
          "vulns": len(self.discovered_vulns),
          "creds": len(self.discovered_creds),
          "files": len(self.discovered_files),
          "people": len(self.discovered_people),
          "sessions": len(self.active_sessions),
          "compromised": len(self.compromised_hosts),
          "persistence": len(self.persistence_mechanisms),
          "exfiltrated": len(self.exfiltrated_data),
          "alerts": len(self.defense_alerts),
          "findings": len(self.findings_log),
          "recommendations": len(self.recommendations),
          "events": len(self._event_history),
        },
        "agent_status": dict(self.agent_status),
        "last_10_findings": [
          {"type": f.get("type"), "agent": f.get("agent"), "ts": f.get("timestamp")}
          for f in self.findings_log[-10:]
        ],
      }
      self._snapshots.append(snap)
      self._last_snapshot_time = time.time()
      return snap

  def _auto_snapshot(self):
    """Take a snapshot if the interval has elapsed (called on every append)."""
    now = time.time()
    if now - self._last_snapshot_time >= self._snapshot_interval:
      self.snapshot()

  def get_snapshots(self) -> List[Dict]:
    with self._lock:
      return list(self._snapshots)

  def get_event_history(self, limit: int = 100) -> List[Dict]:
    with self._lock:
      return list(self._event_history[-limit:])

  # ═══════════════════════════════════════════════════════════════════════════
  # Context queries (uses ContextSelector for selective injection)
  # ═══════════════════════════════════════════════════════════════════════════

  def get_context(self, agent_type: str = "") -> Dict:
    """Get selective context for an agent type. Uses ContextSelector v3."""
    return ContextSelector.for_agent(agent_type, self)

  def get_full_state(self) -> Dict:
    with self._lock:
      return {
        "mission_id": self.mission_id,
        "mission_phase": self.mission_phase,
        "uptime": round(time.time() - self._created_at, 1),
        "hosts": len(self.discovered_hosts),
        "services": len(self.discovered_services),
        "vulns": len(self.discovered_vulns),
        "creds": len(self.discovered_creds),
        "sessions": len(self.active_sessions),
        "owned": len(self.compromised_hosts),
        "threat": self.current_threat_level,
        "alerts": len(self.defense_alerts),
        "terminated": self._terminated,
        "agent_status": dict(self.agent_status),
        "subscriber_counts": {k: len(v) for k, v in self._subscribers.items()},
        "snapshot_count": len(self._snapshots),
        "event_count": len(self._event_history),
      }

  def get_summary(self) -> str:
    s = self.get_full_state()
    return (
      f"Mission {s['mission_id']} [{s['mission_phase']}] | "
      f"Intel: {s['hosts']}h/{s['services']}s/{s['vulns']}v/{s['creds']}c | "
      f"Ops: {s['sessions']}s/{s['owned']}o | "
      f"Defense: {s['threat']}/100 | "
      f"Snaps: {s['snapshot_count']} | Events: {s['event_count']}"
    )

  def get_v3_summary(self) -> str:
    """Extended summary including v3 features."""
    s = self.get_full_state()
    return (
      f"╔══ Hive Mind v3 ══╗\n"
      f"║ Mission: {s['mission_id']} [{s['mission_phase']}]\n"
      f"║ Uptime:  {s['uptime']}s | Threat: {s['threat']}/100\n"
      f"║ Intel:   {s['hosts']} hosts | {s['services']} services | {s['vulns']} vulns | {s['creds']} creds\n"
      f"║ Ops:     {s['sessions']} sessions | {s['owned']} compromised\n"
      f"║ Events:  {s['event_count']} dispatched | {s['snapshot_count']} snapshots\n"
      f"║ Alive:   {'NO — TERMINATED' if s['terminated'] else 'YES'}\n"
      f"╚{'═' * 30}╝"
    )
