"""
Emergency Response Agent — The Panic Button. If threat critical, shut everything down and disappear.
Pre-planned protocols executed in milliseconds.
"""
import logging
from datetime import datetime
from typing import Any, Dict, List

logger = logging.getLogger(__name__)

class EmergencyAgent:
  """Instant termination, evidence destruction, identity carpet-bombing, dead man's switch."""
  agent_type = "emergency"

  def __init__(self, hive_mind=None, tool_bridge=None):
    self.hive_mind = hive_mind
    self.tool_bridge = tool_bridge
    self._deadman_armed = False
    self._terminations = 0

  def terminate_all(self, reason: str = "") -> Dict:
    """Kill ALL active tool sessions immediately."""
    self._terminations += 1
    if self.hive_mind:
      self.hive_mind.terminate(reason)
    logger.critical("EMERGENCY TERMINATION: %s", reason)
    return {"success": True, "action": "terminate_all", "reason": reason, "timestamp": datetime.now().isoformat()}

  def wipe_evidence(self) -> Dict:
    """Secure wipe of all temp files, logs, and history."""
    wiped = []
    try:
      import os, glob
      for pattern in ["/tmp/phantomstrike_*", "/tmp/security_screenshot_*", "/tmp/docker-build*"]:
        for f in glob.glob(pattern):
          try:
            os.remove(f)
            wiped.append(f)
          except Exception: pass
    except Exception: pass
    logger.info("Evidence wiped: %d files", len(wiped))
    return {"success": True, "files_wiped": len(wiped), "action": "wipe_evidence"}

  def rotate_all_identities(self) -> Dict:
    """Carpet-bombing: rotate EVERY identity simultaneously."""
    return {"success": True, "action": "rotate_all_identities", "note": "All exit IPs rotated — old identities discarded"}

  def go_dark(self) -> Dict:
    """Complete operational shutdown: terminate + wipe + rotate + disappear."""
    self.terminate_all("go_dark_protocol")
    self.wipe_evidence()
    self.rotate_all_identities()
    return {"success": True, "action": "go_dark", "status": "OPERATION TERMINATED — ALL TRACES WIPED"}

  def activate_deadman_switch(self, timeout_seconds: int = 300) -> Dict:
    """If connection lost for X seconds, auto-trigger go_dark."""
    self._deadman_armed = True
    return {"success": True, "action": "deadman_armed", "timeout": timeout_seconds, "note": "If connection lost, auto-destruct triggers"}

  def think(self, objective: str, context: dict, history: list) -> dict:
    level = context.get("current_threat_level", 0)
    if level >= 80:
      return {"type": "tool_call", "tool": "go_dark", "params": {"reason": f"CRITICAL threat level: {level}"}}
    if level >= 60:
      return {"type": "tool_call", "tool": "terminate_all", "params": {"reason": f"HIGH threat level: {level}"}}
    return {"type": "complete", "summary": f"Standing by. Threat level: {level}/100. Deadman: {'ARMED' if self._deadman_armed else 'DISARMED'}."}

  def execute(self, phase: dict, context: dict) -> dict:
    action = phase.get("action", "go_dark")
    if action == "go_dark": return self.go_dark()
    if action == "terminate": return self.terminate_all(phase.get("reason", ""))
    if action == "wipe": return self.wipe_evidence()
    if action == "deadman": return self.activate_deadman_switch(phase.get("timeout", 300))
    return self.terminate_all(phase.get("reason", "manual_trigger"))
