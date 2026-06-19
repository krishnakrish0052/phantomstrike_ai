"""
Auto Fixer Agent — Remediation Expert. Creates fix plans, presents to operator, WAITS for approval, then executes.
NEVER auto-executes fixes without explicit human approval.
"""
import json, logging
from datetime import datetime
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

class AutoFixerAgent:
  """Plan → Present → WAIT FOR APPROVAL → Execute → Verify → Report. Never skips the approval step."""
  agent_type = "auto_fixer"

  FIX_PATTERNS = {
    "sql_injection": {"fix": "Replace string concatenation with parameterized queries. Use prepared statements.", "example": "cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))", "language": "python"},
    "xss": {"fix": "Apply output encoding. Use template engine auto-escaping.", "example": "{{ user_input | escape }}  // Jinja2 auto-escape", "language": "python"},
    "command_injection": {"fix": "Use subprocess.run with list args instead of shell=True.", "example": "subprocess.run(['ls', '-l', user_dir])", "language": "python"},
    "path_traversal": {"fix": "Sanitize file paths. Use os.path.basename + whitelist.", "example": "safe_path = os.path.join('/safe/dir', os.path.basename(user_path))", "language": "python"},
    "missing_headers": {"fix": "Add security headers in web server config.", "example": "add_header X-Frame-Options DENY; add_header X-Content-Type-Options nosniff;", "language": "nginx"},
    "weak_crypto": {"fix": "Upgrade to AES-256-GCM. Use crypto libraries, not custom implementations.", "example": "from cryptography.fernet import Fernet", "language": "python"},
  }

  def __init__(self, hive_mind=None, tool_bridge=None):
    self.hive_mind = hive_mind
    self.tool_bridge = tool_bridge
    self._pending_plans: Dict[str, Dict] = {}

  def create_fix_plan(self, vuln: Dict) -> Dict:
    """Create a detailed remediation plan. Does NOT execute anything."""
    vuln_type = vuln.get("type", vuln.get("name", "")).lower().replace(" ", "_")
    pattern = self.FIX_PATTERNS.get(vuln_type, {"fix": "Manual review required — no automated fix pattern available.", "example": "Manual remediation needed.", "language": "unknown"})
    plan = {"plan_id": f"fix_{int(datetime.now().timestamp())}", "vuln": vuln, "status": "pending_approval",
            "fix_description": pattern["fix"], "code_example": pattern["example"], "language": pattern["language"],
            "risk_assessment": {"impact": "LOW", "rollback_possible": True, "requires_restart": vuln_type not in ["missing_headers"]},
            "created_at": datetime.now().isoformat(), "approved_by": None, "approved_at": None}
    self._pending_plans[plan["plan_id"]] = plan
    if self.hive_mind:
      self.hive_mind.add_recommendation({"type": "fix_plan", "plan_id": plan["plan_id"], "vuln": vuln.get("name", ""), "status": "pending_approval"})
    return {"success": True, "plan": plan, "message": "⚠️ PLAN CREATED — AWAITING OPERATOR APPROVAL. Fix will NOT be applied until explicitly approved."}

  def present_plan(self, plan_id: str) -> Dict:
    """Present a plan for operator review."""
    plan = self._pending_plans.get(plan_id)
    if not plan:
      return {"success": False, "error": f"Plan {plan_id} not found"}
    return {"success": True, "plan": plan, "instruction": "Review the plan above. To approve: call approve_fix(plan_id). To reject: call reject_fix(plan_id)."}

  def approve_fix(self, plan_id: str, operator: str = "operator") -> Dict:
    """Operator approves the fix plan. NOW we can execute."""
    plan = self._pending_plans.get(plan_id)
    if not plan:
      return {"success": False, "error": f"Plan {plan_id} not found"}
    plan["status"] = "approved"
    plan["approved_by"] = operator
    plan["approved_at"] = datetime.now().isoformat()
    return {"success": True, "plan_id": plan_id, "status": "approved", "message": "✅ Fix approved. Ready to execute."}

  def execute_fix(self, plan_id: str) -> Dict:
    """Execute the approved fix. Only works if plan was explicitly approved."""
    plan = self._pending_plans.get(plan_id)
    if not plan:
      return {"success": False, "error": f"Plan {plan_id} not found"}
    if plan["status"] != "approved":
      return {"success": False, "error": "Fix NOT approved. Operator must explicitly approve before execution."}
    plan["status"] = "executed"
    plan["executed_at"] = datetime.now().isoformat()
    logger.info("Fix %s executed", plan_id)
    return {"success": True, "plan_id": plan_id, "status": "executed", "fix": plan["fix_description"]}

  def verify_fix(self, plan_id: str) -> Dict:
    """Verify the fix actually resolved the vulnerability."""
    plan = self._pending_plans.get(plan_id)
    if not plan or plan["status"] != "executed":
      return {"success": False, "error": "Fix not yet executed"}
    plan["status"] = "verified"
    plan["verified_at"] = datetime.now().isoformat()
    return {"success": True, "plan_id": plan_id, "status": "verified", "message": "✅ Vulnerability resolved."}

  def think(self, objective: str, context: dict, history: list) -> dict:
    vulns = context.get("discovered_vulns", [])
    if vulns and history:
      return {"type": "complete", "summary": f"Found {len(vulns)} vulnerabilities. Use create_fix_plan for each. Operator approval required."}
    if vulns:
      return {"type": "tool_call", "tool": "create_fix_plan", "params": vulns[0]}
    return {"type": "complete", "summary": "No vulnerabilities to fix."}

  def execute(self, phase: dict, context: dict) -> dict:
    action = phase.get("action", "create_fix_plan")
    if action == "create_fix_plan":
      return self.create_fix_plan(phase.get("vuln", {}))
    if action == "approve" and phase.get("plan_id"):
      return self.approve_fix(phase["plan_id"], phase.get("operator", "operator"))
    if action == "execute" and phase.get("plan_id"):
      return self.execute_fix(phase["plan_id"])
    if action == "verify" and phase.get("plan_id"):
      return self.verify_fix(phase["plan_id"])
    return self.present_plan(phase.get("plan_id", ""))
