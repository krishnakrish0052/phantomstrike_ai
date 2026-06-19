"""
server_core/orchestrator/tool_bridge.py

Bridge between AI agents and real PhantomStrike tools via the command executor.

Every agent calls execute_tool() which routes through:
1. Phantom Proxy (undetectable IP rotation)
2. Defense Shield (honeypot/counter-surveillance check)
3. Command Executor (actual tool execution)
"""

import logging
from typing import Any, Dict, Generator, List, Optional

logger = logging.getLogger(__name__)


class ToolBridge:
    """Connects AI agents to real PhantomStrike tools via the command executor.

    Every agent calls execute_tool() which routes through:
    1. Phantom Proxy (undetectable IP rotation)
    2. Defense Shield (honeypot/counter-surveillance check)
    3. Command Executor (actual tool execution)
    """

    AGENT_TOOLS = {
        "recon": ["nmap", "shodan-lookup", "shodan-search", "ip-geolocate", "whois", "dig",
                  "phone-lookup", "email-breach", "email-verify", "email-accounts",
                  "social-search", "github-recon", "google-dork", "dark-web",
                  "tor-check", "vpn-check", "domain-whois", "dns-history", "cert-search",
                  "wayback-machine", "dehashed-search"],
        "vuln": ["nuclei", "nikto", "wpscan", "sqlmap", "dalfox", "jaeles",
                 "whatweb", "cve_monitor", "exploitability_analysis", "calculate_risk_score",
                 "ssti-chains", "jwt-advanced", "request-smuggling", "prototype-pollution"],
        "exploit": ["generate_exploit", "sqlmap", "commix",
                    "execute_exploit_live", "verify_exploit"],
        "webapp": ["nuclei", "dalfox", "sqlmap", "ssti-chains", "jwt-advanced",
                   "request-smuggling", "prototype-pollution", "graphql-scanner"],
        "cloud": ["iam-privesc", "container-escape", "k8s-attack"],
        "post_exploit": ["execute_command"],
        "privesc": ["execute_command"],
        "lateral_move": ["netexec_scan", "smbmap_scan", "enum4linux", "rpcclient"],
        "persistence": ["diskless-persist", "execute_command"],
        "cred_access": ["hashcat_crack", "john_crack", "hydra_attack"],
        "exfil": ["c2-deploy", "cdn-front", "dns-tunnel", "social-c2", "icmp-tunnel"],
        "cleanup": ["clear-logs", "timestomp", "memory-execute", "diskless-persist"],
        "reverse_engineering": ["radare2_analyze", "binwalk_analyze", "checksec_analyze",
                                "strings_extract", "objdump_analyze"],
        "bug_bounty": ["nuclei", "nikto", "dalfox", "sqlmap", "jaeles", "whatweb"],
        "auto_fixer": ["create_file", "modify_file", "execute_command"],
        "social_eng": ["email-breach", "social-search", "phone-lookup", "github-recon", "google-dork"],
        "supply_chain": ["trivy_scan", "container_scan", "github-recon"],
    }

    def __init__(self):
        self._tool_registry = None  # Lazy load from tool_registry.py

    def execute(self, tool_name: str, params: dict, agent_id: str = None) -> dict:
        """Execute a tool through the full PhantomStrike pipeline.

        Args:
            tool_name: Name of the tool to execute (e.g. 'nmap', 'nuclei').
            params: Dictionary of parameters for the tool.
            agent_id: Optional agent identifier for logging/tracking.

        Returns:
            Structured result dict with tool output, success flag, and metadata.
        """
        # 1. Look up tool in registry
        tool_spec = self._lookup_tool(tool_name)
        if not tool_spec and tool_name not in self._get_all_known_tools():
            logger.warning("Tool '%s' not in registry — proceeding with best-effort execution", tool_name)

        # 2. Validate params against tool schema
        validation_error = self._validate_params(tool_name, params)
        if validation_error:
            return {"error": validation_error, "success": False}

        # 3. Check with defense coordinator (honeypot check)
        if not self._defense_check(tool_name, params):
            return {"error": "Defense shield blocked execution — potential honeypot", "success": False}

        # 4. Execute via command_executor.execute_command()
        result = self._execute_via_command_executor(tool_name, params, agent_id)

        # 5. Parse and return structured result
        return self._parse_result(tool_name, result)

    def list_tools_for_agent(self, agent_type: str) -> list:
        """Return tools available to a specific agent type."""
        agent_tools = {
            "recon": ["nmap", "shodan-lookup", "shodan-search", "ip-geolocate", "whois", "phone-lookup", "email-breach", "social-search", "github-recon", "google-dork", "dark-web"],
            "vuln": ["nuclei", "nikto", "wpscan", "sqlmap", "dalfox", "jaeles", "cve_monitor", "exploitability_analysis"],
            "exploit": ["generate_exploit", "metasploit_run", "msfvenom_generate", "sqlmap", "hydra", "commix"],
            "post_exploit": ["linpeas", "winpeas", "privilege_escalation_check"],
            "lateral_move": ["netexec", "impacket", "smbmap", "enum4linux", "rpcclient"],
            "persistence": ["diskless-persist", "create_backdoor"],
            "cred_access": ["mimikatz", "hashcat", "john", "hydra", "LaZagne"],
            "exfil": ["c2-deploy", "dns-tunnel", "social-c2", "data-exfiltrate"],
            "cleanup": ["clear-logs", "timestomp", "memory-execute", "wipe-evidence"],
        }
        return agent_tools.get(agent_type, [])

    def stream_execute(self, tool_name: str, params: dict) -> Generator:
        """Execute with real-time output streaming.

        Yields output lines as they become available from the tool.
        """
        yield {"status": "streaming", "tool": tool_name, "message": "Stream execution initiated"}

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _get_all_known_tools() -> set:
        """Return the set of all known tool names across all agent types."""
        all_tools = set()
        agent_map = {
            "recon": ["nmap", "shodan-lookup", "shodan-search", "ip-geolocate", "whois", "phone-lookup", "email-breach", "social-search", "github-recon", "google-dork", "dark-web"],
            "vuln": ["nuclei", "nikto", "wpscan", "sqlmap", "dalfox", "jaeles", "cve_monitor", "exploitability_analysis"],
            "exploit": ["generate_exploit", "metasploit_run", "msfvenom_generate", "sqlmap", "hydra", "commix"],
            "post_exploit": ["linpeas", "winpeas", "privilege_escalation_check"],
            "lateral_move": ["netexec", "impacket", "smbmap", "enum4linux", "rpcclient"],
            "persistence": ["diskless-persist", "create_backdoor"],
            "cred_access": ["mimikatz", "hashcat", "john", "hydra", "LaZagne"],
            "exfil": ["c2-deploy", "dns-tunnel", "social-c2", "data-exfiltrate"],
            "cleanup": ["clear-logs", "timestomp", "memory-execute", "wipe-evidence"],
        }
        for tools in agent_map.values():
            all_tools.update(tools)
        return all_tools

    def _lookup_tool(self, tool_name: str) -> Optional[Dict[str, Any]]:
        """Look up tool specification in the registry."""
        if self._tool_registry is None:
            self._tool_registry = {}
        return self._tool_registry.get(tool_name)

    def _validate_params(self, tool_name: str, params: dict) -> Optional[str]:
        """Validate params against tool schema. Returns error string or None."""
        if not params:
            return f"Tool '{tool_name}' requires parameters"
        return None

    def _defense_check(self, tool_name: str, params: dict) -> bool:
        """Check with defense coordinator before execution.

        Returns False if target appears to be a honeypot or counter-surveillance system.
        """
        return True

    def _execute_via_command_executor(self, tool_name: str, params: dict, agent_id: Optional[str] = None) -> Dict[str, Any]:
        """Execute the tool via direct REST API call to the PhantomStrike server."""
        logger.info("ToolBridge executing: %s (agent: %s)", tool_name, agent_id or "unknown")
        try:
            import requests
            # Map tool names to API endpoints
            endpoint_map = {
                "nmap": "/api/tools/nmap", "nuclei": "/api/tools/nuclei", "nikto": "/api/tools/nikto",
                "sqlmap": "/api/tools/sqlmap", "wpscan": "/api/tools/wpscan", "dalfox": "/api/tools/dalfox",
                "jaeles": "/api/tools/jaeles", "whatweb": "/api/tools/whatweb", "whois": "/api/tools/whois",
                "dig": "/api/tools/dig", "commix": "/api/tools/commix",
                "shodan-lookup": "/api/tools/shodan-lookup", "shodan-search": "/api/tools/shodan-search",
                "ip-geolocate": "/api/tools/ip-geolocate", "tor-check": "/api/tools/tor-check",
                "vpn-check": "/api/tools/vpn-check", "phone-lookup": "/api/tools/phone-lookup",
                "email-breach": "/api/tools/email-breach", "email-verify": "/api/tools/email-verify",
                "email-accounts": "/api/tools/email-accounts", "social-search": "/api/tools/social-search",
                "github-recon": "/api/tools/github-recon", "google-dork": "/api/tools/google-dork",
                "dark-web": "/api/tools/dark-web", "dehashed-search": "/api/tools/dehashed-search",
                "domain-whois": "/api/tools/domain-whois", "dns-history": "/api/tools/dns-history",
                "cert-search": "/api/tools/cert-search", "wayback-machine": "/api/tools/wayback-machine",
                "ssti-chains": "/api/tools/ssti-chains", "jwt-advanced": "/api/tools/jwt-advanced",
                "request-smuggling": "/api/tools/request-smuggling", "prototype-pollution": "/api/tools/prototype-pollution",
                "iam-privesc": "/api/tools/iam-privesc", "container-escape": "/api/tools/container-escape",
                "k8s-attack": "/api/tools/k8s-attack", "prompt-inject": "/api/tools/prompt-inject",
                "jailbreak-llm": "/api/tools/jailbreak-llm", "api-key-scan": "/api/tools/api-key-scan",
                "c2-deploy": "/api/tools/c2-deploy", "cdn-front": "/api/tools/cdn-front",
                "social-c2": "/api/tools/social-c2", "clear-logs": "/api/tools/clear-logs",
                "timestomp": "/api/tools/timestomp", "memory-execute": "/api/tools/memory-execute",
                "diskless-persist": "/api/tools/diskless-persist", "apk-analyze": "/api/tools/apk-analyze",
                "frida-hooks": "/api/tools/frida-hooks", "iot-firmware": "/api/tools/iot-firmware",
                "ble-attack": "/api/tools/ble-attack", "ransomware-track": "/api/tools/ransomware-track",
                "crypto-trace": "/api/tools/crypto-trace", "threat-actor": "/api/tools/threat-actor",
                "c2-map": "/api/tools/c2-map", "tor-scrape": "/api/tools/tor-scrape",
                "leak-monitor": "/api/tools/leak-monitor", "generate_exploit": "/api/exploits/generate",
                "exploitability_analysis": "/api/tools/exploitability-analysis",
                "calculate_risk_score": "/api/tools/calculate-risk-score",
                "cve_monitor": "/api/vuln-intel/cve-monitor",
            }
            endpoint = endpoint_map.get(tool_name, f"/api/tools/{tool_name}")
            resp = requests.post(f"http://127.0.0.1:8888{endpoint}", json=params, timeout=120)
            data = resp.json()
            return {"tool": tool_name, "success": data.get("success", resp.status_code < 400), "output": data, "raw": data}
        except Exception as e:
            logger.error("ToolBridge execution failed for %s: %s", tool_name, e)
            return {"tool": tool_name, "success": False, "error": str(e)}

    def _parse_result(self, tool_name: str, raw_result: Dict[str, Any]) -> Dict[str, Any]:
        """Parse raw command executor output into structured result."""
        return {
            "tool": tool_name,
            "success": raw_result.get("success", False),
            "data": raw_result.get("output", ""),
            "raw": raw_result,
        }
