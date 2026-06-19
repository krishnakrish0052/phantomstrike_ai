"""
server_core/orchestrator/task_decomposer.py

Breaks user natural-language prompts into structured mission phases
using keyword analysis and pattern matching. Returns an ordered list
of phases, each annotated with agent_type, tools_needed, parameters,
and success_criteria.

Works standalone (no LLM dependency) — falls back to pattern matching
when an LLM is unavailable.
"""

import logging
import re
import uuid
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


class TaskDecomposer:
    """Decompose hacking prompts into ordered mission phases.

    Handles prompts like:
      - "Hack this phone via IMEI X" → [imei_lookup, carrier_find, exploit_gen, execute, exfil]
      - "Find vulnerabilities on target.com" → [recon, port_scan, vuln_scan, report]
      - "Get admin access to server X" → [recon, exploit, privesc, persist, report]
    """

    # ---- Classification rules (keyword → phase list) ----
    RULES: List[Tuple[List[str], List[Dict[str, Any]]]] = [
        # ── Phone / mobile targeting ──
        (
            [
                r"\b(imei|phone|mobile|handset|sim|cell|sms|mms|imei)\b",
            ],
            [
                {
                    "id": "imei_lookup",
                    "agent_type": "recon",
                    "label": "IMEI Lookup & Device Identification",
                    "tools_needed": ["phone_tracer", "imei_parser", "gsm_lookup"],
                    "parameters": {"source": "prompt", "target_type": "imei"},
                    "success_criteria": "Valid device make/model and carrier identified",
                    "critical": True,
                },
                {
                    "id": "carrier_enumerate",
                    "agent_type": "recon",
                    "label": "Carrier & Network Enumeration",
                    "tools_needed": ["carrier_lookup", "hss_query", "ss7_scanner"],
                    "parameters": {"source": "previous_phase", "target_type": "carrier"},
                    "success_criteria": "MSC, HLR, and roaming status discovered",
                    "critical": True,
                },
                {
                    "id": "exploit_generate",
                    "agent_type": "exploit",
                    "label": "Exploit Generation (Mobile)",
                    "tools_needed": ["exploit_generator", "baseband_exploit", "sms_exploit", "wifi_exploit"],
                    "parameters": {"source": "previous_phase", "vuln_type": "mobile"},
                    "success_criteria": "At least one working exploit payload generated",
                    "critical": True,
                },
                {
                    "id": "exploit_deliver",
                    "agent_type": "exploit",
                    "label": "Exploit Delivery",
                    "tools_needed": ["sms_delivery", "silent_push", "wifi_deauth"],
                    "parameters": {"source": "previous_phase", "method": "ota"},
                    "success_criteria": "Payload delivered and callback received",
                    "critical": True,
                },
                {
                    "id": "post_exploit_execute",
                    "agent_type": "post_exploit",
                    "label": "Post-Exploitation & Data Collection",
                    "tools_needed": ["shell", "file_browser", "mic_camera"],
                    "parameters": {"source": "previous_phase"},
                    "success_criteria": "Shell access obtained or data exfiltrated",
                    "critical": False,
                },
                {
                    "id": "exfil_data",
                    "agent_type": "exfil",
                    "label": "Data Exfiltration",
                    "tools_needed": ["exfil_channel", "compression", "encryption"],
                    "parameters": {"source": "previous_phase", "target": "loot_server"},
                    "success_criteria": "Data transferred to exfil server",
                    "critical": False,
                },
                {
                    "id": "cleanup_tracks",
                    "agent_type": "cleanup",
                    "label": "Cleanup & Cover Tracks",
                    "tools_needed": ["log_wiper", "process_killer", "c2_remover"],
                    "parameters": {"source": "previous_phase"},
                    "success_criteria": "No forensic artifacts remain",
                    "critical": False,
                },
            ],
        ),
        # ── Web vulnerability scanning ──
        (
            [
                r"\b(vulnerabilit|vuln|scan|pentest|audit|assess)\b",
                r"\b(vuln_?scan|security.scan)\b",
            ],
            [
                {
                    "id": "recon_passive",
                    "agent_type": "recon",
                    "label": "Passive Reconnaissance",
                    "tools_needed": ["shodan", "whois", "dns_enum", "google_dork", "social_search"],
                    "parameters": {"source": "prompt", "target_type": "domain"},
                    "success_criteria": "Target IPs, subdomains, and technologies identified",
                    "critical": True,
                },
                {
                    "id": "port_scan",
                    "agent_type": "recon",
                    "label": "Active Port Scanning",
                    "tools_needed": ["nmap", "masscan", "rustscan"],
                    "parameters": {"source": "previous_phase", "target_type": "ip_range"},
                    "success_criteria": "All open ports and services enumerated",
                    "critical": True,
                },
                {
                    "id": "vuln_scan",
                    "agent_type": "vuln",
                    "label": "Vulnerability Scanning",
                    "tools_needed": ["nuclei", "nikto", "zap", "openvas"],
                    "parameters": {"source": "previous_phase", "target_type": "service"},
                    "success_criteria": "Vulnerabilities identified with CVSS scores",
                    "critical": True,
                },
                {
                    "id": "generate_report",
                    "agent_type": "recon",
                    "label": "Report Generation",
                    "tools_needed": ["report_builder", "markdown_renderer"],
                    "parameters": {"source": "previous_phase"},
                    "success_criteria": "Comprehensive vulnerability report produced",
                    "critical": False,
                },
            ],
        ),
        # ── Admin / root access on a server ──
        (
            [
                r"\b(admin|root|privilege|privesc|escalat|gain.access|get.access)\b",
            ],
            [
                {
                    "id": "recon_target",
                    "agent_type": "recon",
                    "label": "Target Reconnaissance",
                    "tools_needed": ["nmap", "shodan", "dns_enum", "whois"],
                    "parameters": {"source": "prompt", "target_type": "ip_or_hostname"},
                    "success_criteria": "Open ports, services, OS fingerprint obtained",
                    "critical": True,
                },
                {
                    "id": "vuln_identify",
                    "agent_type": "vuln",
                    "label": "Vulnerability Identification",
                    "tools_needed": ["nuclei", "searchsploit", "cve_lookup"],
                    "parameters": {"source": "previous_phase"},
                    "success_criteria": "Exploitable vulnerabilities found with CVSS >= 7",
                    "critical": True,
                },
                {
                    "id": "initial_exploit",
                    "agent_type": "exploit",
                    "label": "Initial Exploitation",
                    "tools_needed": ["exploit_generator", "metasploit", "sqlmap"],
                    "parameters": {"source": "previous_phase", "goal": "initial_access"},
                    "success_criteria": "Remote code execution or foothold established",
                    "critical": True,
                },
                {
                    "id": "privilege_escalation",
                    "agent_type": "post_exploit",
                    "label": "Privilege Escalation",
                    "tools_needed": ["linpeas", "winpeas", "kernel_exploit", "sudo_bypass"],
                    "parameters": {"source": "previous_phase", "goal": "root_or_admin"},
                    "success_criteria": "Root or Administrator access obtained",
                    "critical": True,
                },
                {
                    "id": "persist_access",
                    "agent_type": "post_exploit",
                    "label": "Persistence",
                    "tools_needed": ["cron_backdoor", "ssh_key", "service_binary"],
                    "parameters": {"source": "previous_phase", "goal": "persist"},
                    "success_criteria": "Backdoor installed and verified",
                    "critical": False,
                },
                {
                    "id": "generate_report",
                    "agent_type": "recon",
                    "label": "Mission Report",
                    "tools_needed": ["report_builder"],
                    "parameters": {"source": "previous_phase"},
                    "success_criteria": "Full access report with evidence",
                    "critical": False,
                },
            ],
        ),
        # ── Data exfiltration / extraction ──
        (
            [
                r"\b(exfil|extract|download|steal|dump|database|db_dump)\b",
            ],
            [
                {
                    "id": "recon_db",
                    "agent_type": "recon",
                    "label": "Database Reconnaissance",
                    "tools_needed": ["nmap", "sql_ping", "port_scan"],
                    "parameters": {"source": "prompt", "target_type": "database"},
                    "success_criteria": "DB type, version, and access vector identified",
                    "critical": True,
                },
                {
                    "id": "exploit_db",
                    "agent_type": "exploit",
                    "label": "Database Exploitation",
                    "tools_needed": ["sqlmap", "exploit_generator", "credential_brute"],
                    "parameters": {"source": "previous_phase", "vuln_type": "sqli"},
                    "success_criteria": "Database access obtained",
                    "critical": True,
                },
                {
                    "id": "dump_data",
                    "agent_type": "exfil",
                    "label": "Data Dump & Exfiltration",
                    "tools_needed": ["db_dumper", "compressor", "exfil_channel"],
                    "parameters": {"source": "previous_phase", "target": "loot"},
                    "success_criteria": "Data exfiltrated successfully",
                    "critical": True,
                },
                {
                    "id": "cleanup",
                    "agent_type": "cleanup",
                    "label": "Cleanup",
                    "tools_needed": ["log_wiper", "connection_killer"],
                    "parameters": {"source": "previous_phase"},
                    "success_criteria": "Access traces removed",
                    "critical": False,
                },
            ],
        ),
        # ── Generic / default ──
        (
            [r"."],
            [
                {
                    "id": "recon_generic",
                    "agent_type": "recon",
                    "label": "Generic Reconnaissance",
                    "tools_needed": ["nmap", "whois", "shodan", "dns_enum"],
                    "parameters": {"source": "prompt", "target_type": "auto"},
                    "success_criteria": "Target identified and profiled",
                    "critical": True,
                },
                {
                    "id": "vuln_generic",
                    "agent_type": "vuln",
                    "label": "Vulnerability Analysis",
                    "tools_needed": ["nuclei", "nikto", "cve_lookup"],
                    "parameters": {"source": "previous_phase"},
                    "success_criteria": "Vulnerabilities enumerated",
                    "critical": False,
                },
                {
                    "id": "report_generic",
                    "agent_type": "recon",
                    "label": "Report Generation",
                    "tools_needed": ["report_builder"],
                    "parameters": {"source": "previous_phase"},
                    "success_criteria": "Report produced",
                    "critical": False,
                },
            ],
        ),
    ]

    # ---- Target extractors ----
    TARGET_PATTERNS: List[Tuple[str, str]] = [
        (r"\b\d{14,16}\b", "imei"),
        (r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", "ip"),
        (r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b", "domain"),
        (r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b", "email"),
        (r"\b(?:https?://)(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b", "url"),
        (r"\b\d{10,15}\b", "phone"),
    ]

    def __init__(self, llm_client: Any = None):
        self._llm = llm_client

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def decompose(self, prompt: str) -> List[Dict[str, Any]]:
        """Break a natural-language prompt into ordered mission phases.

        Args:
            prompt: User's mission description.

        Returns:
            List of phase dicts, each containing:
                id, agent_type, label, tools_needed, parameters,
                success_criteria, critical
        """
        prompt_lower = prompt.lower().strip()

        # 1. Try LLM-based decomposition if available
        if self._llm is not None:
            try:
                llm_phases = self._llm_decompose(prompt)
                if llm_phases:
                    return llm_phases
            except Exception as exc:
                logger.warning("LLM decomposition failed, falling back to rules: %s", exc)

        # 2. Rule-based pattern matching
        return self._rule_decompose(prompt, prompt_lower)

    # ------------------------------------------------------------------
    # Rule-based decomposition
    # ------------------------------------------------------------------

    def _rule_decompose(self, prompt: str, prompt_lower: str) -> List[Dict[str, Any]]:
        """Match the prompt against classification rules."""
        extracted = self._extract_targets(prompt)

        for patterns, phases in self.RULES:
            for pat in patterns:
                if re.search(pat, prompt_lower):
                    phases = self._enrich_phases(phases, extracted)
                    logger.info(
                        "Decomposed '%s...' → %d phases (rule: %s)",
                        prompt[:60],
                        len(phases),
                        pat,
                    )
                    return phases

        # Should never reach here due to the catch-all rule, but safety:
        return self.RULES[-1][1]

    def _enrich_phases(
        self, phases: List[Dict[str, Any]], extracted: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Clone each phase, inject extracted targets, assign fresh IDs."""
        enriched = []
        for p in phases:
            ep = dict(p)
            ep["id"] = f"{p['id']}_{uuid.uuid4().hex[:8]}"
            ep.setdefault("parameters", {})
            ep["parameters"].setdefault("extracted_targets", extracted)
            enriched.append(ep)
        return enriched

    # ------------------------------------------------------------------
    # Target extraction
    # ------------------------------------------------------------------

    def _extract_targets(self, prompt: str) -> Dict[str, Any]:
        """Pull IMEIs, IPs, domains, emails, URLs, phone numbers from prompt."""
        found: Dict[str, Any] = {}
        for pattern, ttype in self.TARGET_PATTERNS:
            matches = re.findall(pattern, prompt, re.IGNORECASE)
            if matches:
                # Deduplicate while preserving order
                seen: set = set()
                unique = []
                for m in matches:
                    if m not in seen:
                        seen.add(m)
                        unique.append(m)
                key = "value" if len(unique) == 1 else "values"
                found[ttype] = {key: unique[0]} if len(unique) == 1 else {key: unique}
        return found

    # ------------------------------------------------------------------
    # LLM-assisted decomposition (optional)
    # ------------------------------------------------------------------

    def _llm_decompose(self, prompt: str) -> Optional[List[Dict[str, Any]]]:
        """Use an LLM to produce structured phases. Returns None on failure."""
        if self._llm is None:
            return None

        system_prompt = (
            "You are a hacking mission decomposer. Given a target description, "
            "output a JSON list of mission phases. Each phase must have: "
            "id, agent_type (one of: recon, vuln, exploit, post_exploit, exfil, cleanup), "
            "label, tools_needed (list), parameters (object), success_criteria (string), "
            "critical (boolean). Return ONLY valid JSON, no markdown fences."
        )

        try:
            response = self._llm.chat(system_prompt, prompt)
            # Strip possible markdown fences
            clean = response.strip().removeprefix("```json").removeprefix("```").removesuffix("```").strip()
            import json

            phases = json.loads(clean)
            if isinstance(phases, list) and len(phases) > 0:
                # Enrich with extracted targets
                extracted = self._extract_targets(prompt)
                return self._enrich_phases(phases, extracted)
        except Exception as exc:
            logger.debug("LLM decompose parse error: %s", exc)

        return None
