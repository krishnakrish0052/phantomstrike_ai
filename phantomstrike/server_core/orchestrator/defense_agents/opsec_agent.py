"""
OPSEC Agent — Security Guardian. Reviews EVERY action before execution. Vetoes dangerous actions.
"""
import logging, re
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

class OPSECAgent:
  """Paranoid by design — audits every tool command, scores risk, suggests alternatives, vetoes when necessary."""
  agent_type = "opsec"

  KNOWN_SIGNATURES = {
    "sqlmap": {"default_ua": "sqlmap/1.0", "risk": 85, "fix": "--random-agent --delay=2"},
    "nmap": {"default_timing": "-T4", "risk": 60, "fix": "-T2 --randomize-hosts --scan-delay 5s"},
    "nuclei": {"default_ua": "Nuclei", "risk": 70, "fix": "-H 'User-Agent: Mozilla/5.0'"},
    "hydra": {"default_tasks": "-t 16", "risk": 80, "fix": "-t 4 -W 5"},
    "dirb": {"default_ua": "DIRB", "risk": 75, "fix": "-a 'Mozilla/5.0'"},
  }
  RISK_THRESHOLD = 80
  _suggested_alternatives: Dict[str, list] = {}

  def __init__(self, hive_mind=None, tool_bridge=None):
    self.hive_mind = hive_mind
    self.tool_bridge = tool_bridge
    self._audit_log = []

  def audit_action(self, tool_name: str, params: Dict) -> Dict:
    """Pre-execution audit. Returns {approved, risk_score, modifications, reason}."""
    risk_score = 20  # base risk
    modifications = {}
    reasons = []

    if tool_name in self.KNOWN_SIGNATURES:
      sig = self.KNOWN_SIGNATURES[tool_name]
      risk_score = sig["risk"]
      modifications["hardening"] = sig["fix"]
      reasons.append(f"Tool has known detectable signature")

    target = str(params.get("target", params.get("url", params.get("ip", ""))))
    if target and any(t in target.lower() for t in ["gov", "mil", "bank", ".edu"]):
      risk_score += 20
      reasons.append("High-sensitivity target domain detected")

    approved = risk_score < self.RISK_THRESHOLD
    self._audit_log.append({"tool": tool_name, "risk": risk_score, "approved": approved, "timestamp": __import__('datetime').datetime.now().isoformat()})

    if self.hive_mind and risk_score > 50:
      self.hive_mind.add_alert({"type": "opsec_audit", "tool": tool_name, "risk_score": risk_score, "approved": approved, "threat_level": 0})

    return {"approved": approved, "risk_score": risk_score, "modifications": modifications, "reasons": reasons,
            "suggestion": f"Risk {risk_score}/100. " + ("APPROVED" if approved else f"VETOED — suggestions:")}

  def suggest_alternatives(self, tool_name: str, params: Dict) -> List[Dict]:
    """Suggest safer alternatives for high-risk actions."""
    if tool_name in self._suggested_alternatives:
      return [{"tool": alt, "risk_reduction": "estimated 50%"} for alt in self._suggested_alternatives[tool_name]]
    return [{"tool": tool_name, "modifications": self.KNOWN_SIGNATURES.get(tool_name, {}).get("fix", ""), "risk_reduction": "~50%"}]

  def think(self, objective: str, context: dict, history: list) -> dict:
    recent_actions = [h for h in history if h.get("action", {}).get("type") == "tool_call"]
    if recent_actions:
      last = recent_actions[-1]
      tool = last.get("action", {}).get("tool", "")
      if tool in self.KNOWN_SIGNATURES:
        return {"type": "complete", "summary": f"Monitoring {tool} — risk: {self.KNOWN_SIGNATURES[tool]['risk']}/100"}
    return {"type": "complete", "summary": "All operations within acceptable OPSEC parameters."}

  def execute(self, phase: dict, context: dict) -> dict:
    return self.audit_action(phase.get("tool_name", ""), phase.get("params", {}))
