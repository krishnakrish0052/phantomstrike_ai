"""
tool_output_parser.py — Structured output parsing for common Kali tools.

Parses raw CLI output from nmap, nuclei, sqlmap, metasploit, hydra,
hashcat, and john-the-ripper into structured JSON dictionaries.

Designed to be used by the PhantomStrike AI pipeline for downstream
vulnerability correlation, reporting, and mission phase tracking.
"""

import json
import logging
import re
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class ToolOutputParser:
    """Parse raw tool output into structured JSON.

    Each ``parse_<tool>`` method accepts a raw string (the tool's stdout
    or collected PTY session output) and returns a dict with the key
    findings extracted.

    All methods are static — no shared state needed.  Instantiate or
    call directly as convenient.
    """

    # ── Nmap ──────────────────────────────────────────────────────────────────

    @staticmethod
    def parse_nmap(raw: str) -> Dict[str, Any]:
        """Parse nmap output into structured host/port/service data.

        Handles both normal nmap output and greppable (-oG) format.
        """
        result: Dict[str, Any] = {
            "tool": "nmap",
            "hosts": [],
            "open_ports_total": 0,
        }

        # Try greppable format first (most reliable).
        for line in raw.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            # Greppable format: Host: <ip> (...) Ports: <port>/open/...
            m = re.match(r"Host:\s+(\S+)\s+\(.*?\)\s+Ports:\s+(.*)", line)
            if m:
                host_ip = m.group(1)
                ports_str = m.group(2)
                host_entry = {"ip": host_ip, "ports": []}
                for port_part in ports_str.split(","):
                    port_part = port_part.strip()
                    parts = port_part.split("/")
                    if len(parts) >= 5:
                        host_entry["ports"].append(
                            {
                                "port": int(parts[0]) if parts[0].isdigit() else parts[0],
                                "state": parts[1],
                                "protocol": parts[2],
                                "owner": parts[3],
                                "service": parts[4],
                            }
                        )
                if not any(h["ip"] == host_ip for h in result["hosts"]):
                    result["hosts"].append(host_entry)

        # Fallback: parse standard nmap table format.
        if not result["hosts"]:
            host_ip = None
            for line in raw.splitlines():
                # Nmap scan report for ...
                hdr = re.match(r"Nmap scan report for (\S+)", line)
                if hdr:
                    host_ip = hdr.group(1)
                    if not any(h["ip"] == host_ip for h in result["hosts"]):
                        result["hosts"].append({"ip": host_ip, "ports": []})
                    continue
                # <port>/tcp open <service>
                port_line = re.match(
                    r"(\d+)/(tcp|udp)\s+(\S+)\s+(\S.*)", line
                )
                if port_line and host_ip:
                    host = next(
                        (h for h in result["hosts"] if h["ip"] == host_ip), None
                    )
                    if host is not None:
                        host["ports"].append(
                            {
                                "port": int(port_line.group(1)),
                                "state": port_line.group(3),
                                "protocol": port_line.group(2),
                                "service": port_line.group(4).strip(),
                            }
                        )

        # Count total open ports
        for host in result["hosts"]:
            result["open_ports_total"] += len(
                [p for p in host.get("ports", []) if p.get("state") == "open"]
            )

        return result

    # ── Nuclei ─────────────────────────────────────────────────────────────────

    @staticmethod
    def parse_nuclei(raw: str) -> Dict[str, Any]:
        """Parse nuclei JSON-lines output (``-jsonl`` flag)."""
        findings: List[Dict[str, Any]] = []
        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                findings.append(
                    {
                        "template": obj.get("template-id", obj.get("templateID", "")),
                        "name": obj.get("info", {}).get("name", ""),
                        "severity": obj.get("info", {}).get("severity", "unknown"),
                        "host": obj.get("host", obj.get("matched-at", "")),
                        "matched": obj.get("matched-at", ""),
                        "type": obj.get("type", ""),
                    }
                )
            except json.JSONDecodeError:
                # Some nuclei lines are non-JSON log messages — skip.
                continue

        return {
            "tool": "nuclei",
            "findings": findings,
            "total": len(findings),
            "by_severity": ToolOutputParser._count_by_key(findings, "severity"),
        }

    # ── SQLMap ─────────────────────────────────────────────────────────────────

    @staticmethod
    def parse_sqlmap(raw: str) -> Dict[str, Any]:
        """Parse sqlmap output for injection points and database info."""
        result: Dict[str, Any] = {
            "tool": "sqlmap",
            "vulnerable": False,
            "injection_points": [],
            "database_info": {},
            "tables_found": [],
        }

        # Detect vulnerability.
        if re.search(r"is (vulnerable|exploitable)", raw, re.IGNORECASE):
            result["vulnerable"] = True

        # Injection points.
        for m in re.finditer(
            r"Parameter:\s+(\S+)\s+\((GET|POST|Cookie|UA|Referer)\)",
            raw,
        ):
            result["injection_points"].append(
                {"parameter": m.group(1), "method": m.group(2)}
            )

        # Back-end DBMS.
        dbms = re.search(r"back-end DBMS:\s*(.+)", raw, re.IGNORECASE)
        if dbms:
            result["database_info"]["dbms"] = dbms.group(1).strip()

        # Database name.
        db_name = re.search(r"database:\s*['\"]?(\S+?)['\"]?\s*$", raw, re.MULTILINE | re.IGNORECASE)
        if db_name:
            result["database_info"]["name"] = db_name.group(1)

        # Cracked passwords (sqlmap --passwords).
        for m in re.finditer(
            r"\[\*\]\s+(\S+)\s+\[\d+\]\s+password:\s*(\S+)",
            raw,
        ):
            result.setdefault("credentials", []).append(
                {"username": m.group(1), "password": m.group(2)}
            )

        return result

    # ── Metasploit ─────────────────────────────────────────────────────────────

    @staticmethod
    def parse_msf(raw: str) -> Dict[str, Any]:
        """Parse msfconsole session output for sessions, exploits used, and loot.

        Designed for the output captured from PTYSession after issuing
        commands like ``sessions -l``, ``show options``, or ``loot``.
        """
        result: Dict[str, Any] = {
            "tool": "metasploit",
            "sessions": [],
            "exploits_used": [],
            "loot": [],
            "jobs": [],
        }

        # Parse ``sessions -l`` table.
        for m in re.finditer(
            r"^\s*(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S.*)",
            raw,
            re.MULTILINE,
        ):
            sid = m.group(1)
            if sid.isdigit():
                result["sessions"].append(
                    {
                        "id": int(sid),
                        "type": m.group(3).strip(),
                        "info": m.group(5).strip(),
                    }
                )

        # Parse ``loot`` table.
        for m in re.finditer(
            r"^\s*(\S+)\s+(\d{4}-\d{2}-\d{2}.*?)\s+(\S+)\s+(\S+)\s+(.+)",
            raw,
            re.MULTILINE,
        ):
            if m.group(2).count("-") >= 2:  # looks like a date
                result["loot"].append(
                    {
                        "host": m.group(1),
                        "type": m.group(4),
                        "path": m.group(5).strip(),
                    }
                )

        return result

    # ── Hydra ──────────────────────────────────────────────────────────────────

    @staticmethod
    def parse_hydra(raw: str) -> Dict[str, Any]:
        """Parse hydra brute-force output for successful credentials."""
        creds: List[Dict[str, str]] = []

        # Standard hydra success line:
        # [<port>][<service>] host: <host>   login: <user>   password: <pass>
        for m in re.finditer(
            r"\[(\d+)\]\[(\S+)\]\s+host:\s*(\S+)\s+login:\s*(\S+)\s+password:\s*(\S+)",
            raw,
        ):
            creds.append(
                {
                    "host": m.group(3),
                    "port": int(m.group(1)),
                    "service": m.group(2),
                    "username": m.group(4),
                    "password": m.group(5),
                }
            )

        valid_targets = re.findall(r"(\d+) valid password found", raw)
        total_valid = sum(int(c) for c in valid_targets)

        return {
            "tool": "hydra",
            "credentials": creds,
            "total_valid": total_valid or len(creds),
        }

    # ── Hashcat ────────────────────────────────────────────────────────────────

    @staticmethod
    def parse_hashcat(raw: str) -> Dict[str, Any]:
        """Parse hashcat output for cracked hashes.

        Handles both ``--show`` output and the potfile format
        (``hash:plaintext``).
        """
        cracked: List[Dict[str, str]] = []
        status = "exhausted"

        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue

            # hash:plaintext format
            if ":" in line and not line.startswith(("Session", "Status", "Hash", "Progress", "Approaching", "Started", "Stopped", "Candidates", "Recovered", "Time", "Speed", "Guess", "Hardware", "Dictionary", "Rules", "Hashes", "INFO", "WARN", "Watchdog", "ATTENTION")):
                parts = line.split(":", 1)
                if len(parts) == 2:
                    cracked.append({"hash": parts[0].strip(), "plaintext": parts[1].strip()})

            # Check overall status.
            if "Status" in line:
                if "Cracked" in line:
                    status = "cracked"
                elif "Exhausted" in line:
                    status = "exhausted"
                elif "Running" in line:
                    status = "running"

        return {
            "tool": "hashcat",
            "status": status,
            "cracked": cracked,
            "total_cracked": len(cracked),
        }

    # ── John the Ripper ────────────────────────────────────────────────────────

    @staticmethod
    def parse_john(raw: str) -> Dict[str, Any]:
        """Parse john-the-ripper output for cracked hashes.

        Handles ``john --show`` output (``user:pass::uid:gid:...`` on
        Unix-like formats).
        """
        cracked: List[Dict[str, str]] = []

        for line in raw.splitlines():
            line = line.strip()
            if not line or line.startswith(("Loaded", "No password", "Proceeding", "Using", "Press", "Warning", "Remaining")):
                continue

            # Standard john cracked line: user:password:...
            parts = line.split(":")
            if len(parts) >= 2 and parts[1]:
                cracked.append({"user": parts[0], "plaintext": parts[1]})

            # John pot file format may differ — also check for <hash>$<plaintext>
            if "$" in line and ":" not in line:
                cracked.append({"hash": line, "plaintext": ""})

        return {
            "tool": "john",
            "cracked": cracked,
            "total_cracked": len(cracked),
        }

    # ── Generic / utility ─────────────────────────────────────────────────────

    @staticmethod
    def auto_parse(tool: str, raw: str) -> Dict[str, Any]:
        """Auto-detect tool and route to the correct parser.

        Args:
            tool:  lowercase tool name (``"nmap"``, ``"nuclei"``, etc.).
            raw:   raw output string.

        Returns:
            Parsed dict, or ``{"tool": tool, "raw": raw[:500]}`` if no
            parser is registered for *tool*.
        """
        parsers = {
            "nmap": ToolOutputParser.parse_nmap,
            "nuclei": ToolOutputParser.parse_nuclei,
            "sqlmap": ToolOutputParser.parse_sqlmap,
            "sqlmap shell": ToolOutputParser.parse_sqlmap,
            "metasploit": ToolOutputParser.parse_msf,
            "msfconsole": ToolOutputParser.parse_msf,
            "msf": ToolOutputParser.parse_msf,
            "hydra": ToolOutputParser.parse_hydra,
            "hashcat": ToolOutputParser.parse_hashcat,
            "john": ToolOutputParser.parse_john,
            "john the ripper": ToolOutputParser.parse_john,
        }

        parser = parsers.get(tool.lower())
        if parser:
            try:
                return parser(raw)
            except Exception as exc:
                logger.warning(
                    "tool_output_parser: %s parser failed — %s", tool, exc
                )
                return {"tool": tool, "error": str(exc), "raw_preview": raw[:500]}

        return {"tool": tool, "raw_preview": raw[:500]}

    # ── Helpers ────────────────────────────────────────────────────────────────

    @staticmethod
    def _count_by_key(items: List[Dict[str, Any]], key: str) -> Dict[str, int]:
        """Count occurrences of each distinct value for *key* in *items*."""
        counts: Dict[str, int] = {}
        for item in items:
            val = str(item.get(key, "unknown")).lower()
            counts[val] = counts.get(val, 0) + 1
        return counts
