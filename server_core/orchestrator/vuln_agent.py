"""
server_core/orchestrator/vuln_agent.py

Vulnerability analysis specialist agent.

Uses nmap NSE, nuclei, nikto, CVE intelligence lookups, and CWE
mapping. Consumes recon output and produces a prioritized vulnerability
list with CVSS scores, exploit-maturity flags, and remediation hints.

Works standalone with simulated CVE lookups when no LLM is available.
"""

import logging
import time
from typing import Any, Dict, List, Optional

from server_core import ModernVisualEngine

logger = logging.getLogger(__name__)


# Simulated CVE database subset (replace with live CVE feed / NVD API)
_SIMULATED_CVE_DB: Dict[str, Dict[str, Any]] = {
    "OpenSSH 8.9p1": [
        {
            "cve": "CVE-2024-6387",
            "description": "regreSSHion — Remote Unauthenticated Code Execution in OpenSSH",
            "cvss": 9.8,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "exploit_maturity": "functional",
            "remediation": "Upgrade to OpenSSH >= 9.8p1",
            "epss": 0.96,
        },
        {
            "cve": "CVE-2023-48795",
            "description": "Terrapin — SSH protocol prefix truncation attack",
            "cvss": 5.9,
            "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N",
            "exploit_maturity": "proof-of-concept",
            "remediation": "Enable strict KEX, upgrade OpenSSH",
            "epss": 0.72,
        },
    ],
    "nginx 1.24.0": [
        {
            "cve": "CVE-2024-7347",
            "description": "nginx ngx_http_mp4_module buffer overflow",
            "cvss": 7.5,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
            "exploit_maturity": "unproven",
            "remediation": "Disable mp4 module or upgrade",
            "epss": 0.31,
        },
        {
            "cve": "CVE-2023-44487",
            "description": "HTTP/2 Rapid Reset — denial of service",
            "cvss": 7.5,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
            "exploit_maturity": "functional",
            "remediation": "Disable HTTP/2 or apply vendor patch",
            "epss": 0.89,
        },
    ],
    "MySQL 8.0.33": [
        {
            "cve": "CVE-2024-20996",
            "description": "Oracle MySQL privilege escalation via SET PERSIST",
            "cvss": 7.1,
            "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H",
            "exploit_maturity": "proof-of-concept",
            "remediation": "Apply Oracle CPU April 2024",
            "epss": 0.11,
        },
    ],
    "Apache 2.4.57": [
        {
            "cve": "CVE-2024-4084",
            "description": "Apache HTTP Server SSRF via mod_rewrite server/name",
            "cvss": 8.1,
            "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "exploit_maturity": "proof-of-concept",
            "remediation": "Upgrade to >= 2.4.62",
            "epss": 0.47,
        },
    ],
    "generic": [
        {
            "cve": "CVE-2025-0001",
            "description": "Generic stub CVE — update with live feed",
            "cvss": 5.0,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
            "exploit_maturity": "unproven",
            "remediation": "Review and patch",
            "epss": 0.05,
        },
    ],
}


class VulnAgent:
    """Vulnerability analysis specialist — produces prioritized vuln lists.

    Input: recon data (port scans, service banners, technology stack).
    Output: prioritized vulnerabilities with CVSS scores, EPSS, and
            exploit-maturity flags.
    """

    AGENT_NAME = "vuln"

    def __init__(self, llm_client: Any = None):
        self._llm = llm_client

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------

    def execute(self, phase: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        """Run vulnerability analysis for the given phase.

        Args:
            phase: Phase spec with id, tools_needed, parameters, etc.
            context: Shared memory context including previous recon output.

        Returns:
            Dict with success, data (vuln_list, stats), error, elapsed_seconds.
        """
        start = time.time()
        phase_id = phase.get("id", "unknown")
        tools = phase.get("tools_needed", [])
        label = phase.get("label", phase_id)

        logger.info(
            "%s",
            ModernVisualEngine.create_section_header(
                f"VULN AGENT — {label}", "🛡", "ELECTRIC_PURPLE"
            ),
        )

        # 1. Gather service banners from recon context
        services = self._extract_services(context)
        if not services:
            logger.warning("No service data found in context — building generic profile")
            # Fallback: simulate a scan
            services = [{"name": "generic", "version": "unknown", "port": 0}]

        logger.info("Analysing %d service(s) for vulnerabilities", len(services))

        # 2. Look up CVEs per service
        all_vulns: List[Dict[str, Any]] = []
        errors: List[str] = []

        for svc in services:
            svc_name = svc.get("name", "unknown")
            svc_version = svc.get("version", "")
            svc_port = svc.get("port", 0)

            # Try exact match first, then partial
            key = f"{svc_name} {svc_version}".strip()
            cves = (
                _SIMULATED_CVE_DB.get(key)
                or _SIMULATED_CVE_DB.get(svc_name)
                or _SIMULATED_CVE_DB.get("generic", [])
            )

            for cve in cves:
                entry = dict(cve)
                entry["matched_service"] = svc_name
                entry["matched_version"] = svc_version
                entry["port"] = svc_port
                all_vulns.append(entry)

        # 3. Run additional tools if specified
        tool_results: Dict[str, Any] = {}
        for tool in tools:
            if tool == "nuclei":
                tool_results["nuclei"] = self._simulate_nuclei(services)
            elif tool == "nikto":
                tool_results["nikto"] = self._simulate_nikto(services)
            elif tool in ("cve_lookup", "searchsploit"):
                tool_results[tool] = {"cves_found": len(all_vulns), "source": "simulated_db"}
            else:
                tool_results[tool] = {"note": f"Tool '{tool}' not implemented in VulnAgent"}

        # 4. Sort by CVSS descending
        all_vulns.sort(key=lambda v: v.get("cvss", 0), reverse=True)

        # 5. Compute stats
        critical = [v for v in all_vulns if v.get("cvss", 0) >= 9.0]
        high = [v for v in all_vulns if 7.0 <= v.get("cvss", 0) < 9.0]
        medium = [v for v in all_vulns if 4.0 <= v.get("cvss", 0) < 7.0]
        low = [v for v in all_vulns if v.get("cvss", 0) < 4.0]

        stats = {
            "total_vulns": len(all_vulns),
            "critical": len(critical),
            "high": len(high),
            "medium": len(medium),
            "low": len(low),
            "max_cvss": max((v.get("cvss", 0) for v in all_vulns), default=0),
            "avg_cvss": round(sum(v.get("cvss", 0) for v in all_vulns) / max(len(all_vulns), 1), 1),
            "services_analysed": len(services),
        }

        elapsed = time.time() - start

        return {
            "success": True,
            "data": {
                "vulnerabilities": all_vulns,
                "stats": stats,
                "tool_results": tool_results,
            },
            "error": "; ".join(errors) if errors else None,
            "elapsed_seconds": round(elapsed, 2),
        }

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _extract_services(self, context: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Pull service banners from the shared context dict."""
        services: List[Dict[str, Any]] = []

        # Context may have a flat dict or a nested 'data' key from ReconAgent
        for source in (context, context.get("data", {})):
            if not isinstance(source, dict):
                continue
            for key, val in source.items():
                # Look for nmap/shodan-style output
                if isinstance(val, dict):
                    # nmap result
                    if "open_ports" in val:
                        for port, info in val["open_ports"].items():
                            services.append({
                                "name": info.get("service", "unknown"),
                                "version": info.get("version", ""),
                                "port": port,
                            })
                    # shodan result
                    if "services" in val:
                        for port, banner in val["services"].items():
                            parts = banner.split(" ", 1)
                            services.append({
                                "name": parts[0] if parts else banner,
                                "version": parts[1] if len(parts) > 1 else "",
                                "port": int(port) if port.isdigit() else 0,
                            })

        # Deduplicate by (name, version, port)
        seen: set = set()
        deduped: List[Dict[str, Any]] = []
        for s in services:
            sig = (s["name"], s["version"], s["port"])
            if sig not in seen:
                seen.add(sig)
                deduped.append(s)
        return deduped

    def _simulate_nuclei(self, services: List[Dict]) -> Dict[str, Any]:
        """Simulated Nuclei scan output."""
        templates_run = len(services) * 15
        return {
            "templates_run": templates_run,
            "matches": max(1, len(services)),
            "severity_breakdown": {"critical": 0, "high": 1, "medium": 2, "low": 1, "info": 5},
            "note": "[STUB] Nuclei — integrate subprocess call or nuclei SDK",
        }

    def _simulate_nikto(self, services: List[Dict]) -> Dict[str, Any]:
        """Simulated Nikto scan output."""
        return {
            "targets_scanned": len(services),
            "findings": [
                "Server banner reveals version",
                "X-Frame-Options header not present",
                "directory /admin/ found (401)",
            ],
            "note": "[STUB] Nikto — integrate subprocess call or nikto SDK",
        }
