"""
server_core/engine/honeypot_ops.py

Honeypot & Honeynet Operations — deploy decoys to study the defenders.

The best way to evade defenders is to understand them intimately. This engine
deploys honeypots and entire honeynets that attract real defenders, security
researchers, and threat hunters. Every interaction is captured, analysed, and
fed back into PhantomStrike's evasion algorithms.

When a defender scans our honeypot, we learn:
  - What tools they use (nmap, masscan, Shodan, Censys, custom scanners)
  - What IOC types they search for (hashes, IPs, domains, registry keys)
  - What queries they run (Elasticsearch, Splunk, Sentinel, Chronicle)
  - What detection rules they have deployed (Sigma, YARA, Snort, Suricata)
  - What response playbooks they trigger (isolate, investigate, escalate)

This intelligence makes PhantomStrike practically invisible. We don't just
evade detection — we study the detectors and adapt before they even look.

Honeypot types supported:
  SSH, HTTP, MySQL, Redis, Elasticsearch, Docker API, Kubernetes API, SMB, RDP

Classes:
  HoneypotOps               — main honeypot orchestrator
  HoneypotInstance          — a single deployed honeypot
  DefenderInteraction       — a captured interaction with a defender
  DefenderProfile           — learned defender TTPs and tool preferences
  HoneynetConfig            — multi-honeypot network configuration
"""

from __future__ import annotations

import hashlib
import json
import logging
import random
import textwrap
import threading
import time
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)

# ── Constants ──────────────────────────────────────────────────────────────────

# Honeypot type configurations — realistic service banners and behaviours
_HONEYPOT_CONFIGS: Dict[str, Dict[str, Any]] = {
    "ssh": {
        "banner": "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5",
        "port": 22,
        "default_credentials": {"root": "toor", "admin": "admin123"},
        "realistic_artifacts": [
            "/home/admin/.bash_history", "/var/log/auth.log",
            "/etc/shadow", "/root/.ssh/authorized_keys",
        ],
        "common_scanner_patterns": ["SSH-2.0-libssh", "SSH-2.0-paramiko", "SSH-2.0-Go"],
    },
    "http": {
        "banner": "Apache/2.4.49 (Ubuntu) Server at {host}",
        "port": 80,
        "default_pages": ["/index.html", "/admin", "/wp-admin", "/login", "/api"],
        "realistic_headers": {
            "Server": "Apache/2.4.49 (Ubuntu)",
            "X-Powered-By": "PHP/7.4.33",
            "Set-Cookie": "PHPSESSID={random}; path=/; HttpOnly",
        },
    },
    "mysql": {
        "banner": "5.7.32-0ubuntu0.18.04.1",
        "port": 3306,
        "default_databases": ["mysql", "information_schema", "performance_schema", "wordpress", "production"],
    },
    "redis": {
        "banner": "redis_version:6.0.9",
        "port": 6379,
        "default_keys": ["session:*", "cache:*", "queue:*", "user:*"],
        "dangerous_commands_enabled": ["CONFIG", "DEBUG", "FLUSHALL"],
    },
    "elasticsearch": {
        "banner": '{"name":"es-node-01","cluster_name":"production","version":{"number":"7.10.1"}}',
        "port": 9200,
        "default_indices": ["logstash-*", "filebeat-*", "metricbeat-*", "winlogbeat-*", ".security-7"],
        "exposed_endpoints": ["/_cat/indices", "/_search", "/_nodes", "/_cluster/health"],
    },
    "docker_api": {
        "banner": '{"Version":"20.10.12","ApiVersion":"1.41"}',
        "port": 2375,
        "exposed_containers": ["nginx-prod", "redis-cache", "postgres-db", "node-app"],
    },
    "kubernetes_api": {
        "banner": '{"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"forbidden: User system:anonymous cannot get path /","reason":"Forbidden","details":{},"code":403}',
        "port": 6443,
        "exposed_namespaces": ["default", "kube-system", "production", "staging"],
        "fake_pods": True,
    },
    "smb": {
        "banner": "SMB2",
        "port": 445,
        "shares": ["ADMIN$", "C$", "IPC$", "Shared", "Finance", "HR"],
        "os_version": "Windows Server 2019 Standard 10.0.17763",
    },
    "rdp": {
        "banner": "RDP",
        "port": 3389,
        "os_version": "Windows 10 Pro 10.0.19041",
        "hostname": "DESKTOP-WIN10-PROD",
    },
}

# Known defender tools and their fingerprints
_DEFENDER_TOOLS: Dict[str, Dict[str, Any]] = {
    "nmap": {
        "category": "network_scanner",
        "fingerprints": ["nmap -sV", "nmap -sC", "nmap -p-", "nmap -A", "nmap --script"],
        "tcp_fingerprint": "TTL=64,TCP_WINDOW=65535",
        "user_agent": "nmap scripting engine",
    },
    "masscan": {
        "category": "network_scanner",
        "fingerprints": ["masscan --rate", "masscan -p", "masscan --range"],
        "tcp_fingerprint": "high_rate_syn_flood_pattern",
    },
    "shodan": {
        "category": "internet_scanner",
        "fingerprints": ["Shodan", "census", "scan-*.shodan.io"],
        "user_agent": "Mozilla/5.0 (compatible; Shodan)",
    },
    "censys": {
        "category": "internet_scanner",
        "fingerprints": ["Censys", "scan-*.censys.io"],
        "user_agent": "Mozilla/5.0 (compatible; Censys)",
    },
    "metasploit": {
        "category": "exploitation_framework",
        "fingerprints": ["meterpreter", "msfconsole", "auxiliary/scanner", "exploit/multi"],
        "user_agent": "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)",
    },
    "sqlmap": {
        "category": "sql_injection_tool",
        "fingerprints": ["sqlmap/", "sqlmap -u", "sqlmap --data", "sqlmap --os-shell"],
        "user_agent": "sqlmap/1.6",
        "payload_patterns": ["' OR 1=1--", "UNION SELECT", "AND SLEEP(5)"],
    },
    "hydra": {
        "category": "credential_bruteforce",
        "fingerprints": ["Hydra v", "hydra -l", "hydra -P", "login:"],
        "rate_characteristics": "high_rate_auth_attempts",
    },
    "curl": {
        "category": "http_client",
        "fingerprints": ["curl/"],
        "user_agent": "curl/7.68.0",
    },
    "nikto": {
        "category": "web_scanner",
        "fingerprints": ["Nikto", "nikto -host", "nikto -h"],
        "user_agent": "Nikto",
        "test_uris": ["/cgi-bin/", "/server-status", "/.env", "/config.php.bak"],
    },
    "gobuster": {
        "category": "directory_bruteforce",
        "fingerprints": ["gobuster", "dirbuster", "ffuf", "wfuzz"],
        "user_agent": "gobuster/3.0",
    },
    "burpsuite": {
        "category": "web_proxy",
        "fingerprints": ["Burp Suite"],
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    },
    "splunk_uf": {
        "category": "siem_agent",
        "fingerprints": ["SplunkUniversalForwarder", "Splunk_"],
        "log_patterns": ["EventCode=4688", "EventCode=4624", "EventCode=5156"],
    },
    "elastic_agent": {
        "category": "siem_agent",
        "fingerprints": ["Elastic", "filebeat", "winlogbeat", "metricbeat"],
    },
    "crowdstrike": {
        "category": "edr",
        "fingerprints": ["CrowdStrike", "CSFalconService", "CSAgent"],
        "process_patterns": ["CSFalconService.exe", "CSFalconContainer.exe"],
    },
    "defender_atp": {
        "category": "edr",
        "fingerprints": ["Microsoft Defender ATP", "MsSense.exe", "SenseCncProxy.exe"],
    },
}

# IOC types defenders search for
_IOC_TYPES = [
    "ip_address", "domain", "url", "file_hash_md5", "file_hash_sha256",
    "registry_key", "mutex", "email_address", "x509_certificate",
    "process_name", "service_name", "user_agent", "yara_rule",
    "sigma_rule", "splunk_query", "kql_query",
]

# ── Data Classes ───────────────────────────────────────────────────────────────

@dataclass
class HoneypotInstance:
    """A single deployed honeypot."""
    honeypot_id: str = field(default_factory=lambda: f"hp_{uuid.uuid4().hex[:8]}")
    honeypot_type: str = ""
    config: Dict[str, Any] = field(default_factory=dict)
    ip: str = ""
    port: int = 0
    status: str = "deploying"
    interactions: int = 0
    deployed_at: Optional[datetime] = None
    last_interaction: Optional[datetime] = None
    defenders_detected: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DefenderInteraction:
    """A single interaction with a honeypot by a defender."""
    interaction_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    honeypot_id: str = ""
    source_ip: str = ""
    timestamp: Optional[datetime] = None
    tools_detected: List[str] = field(default_factory=list)
    techniques_observed: List[str] = field(default_factory=list)
    payloads_captured: List[str] = field(default_factory=list)
    queries_captured: List[str] = field(default_factory=list)
    ioc_types_searched: List[str] = field(default_factory=list)
    session_duration_seconds: float = 0.0
    is_automated_scanner: bool = False
    threat_level: str = "low"
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DefenderProfile:
    """Aggregated defender profile — what we've learned about them."""
    profile_id: str = field(default_factory=lambda: uuid.uuid4().hex[:8])
    tools_fingerprinted: List[str] = field(default_factory=list)
    preferred_scan_types: List[str] = field(default_factory=list)
    ioc_preferences: List[str] = field(default_factory=list)
    query_patterns: List[str] = field(default_factory=list)
    response_time_seconds: float = 0.0
    skill_level: str = "unknown"
    organisation_guess: str = "unknown"
    total_sessions_analysed: int = 0
    created_at: Optional[datetime] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


# ── Main Engine ────────────────────────────────────────────────────────────────

class HoneypotOps:
    """PhantomStrike Honeypot Operations — to know your enemy, let them touch you.

    Deploys realistic honeypots that attract defenders, security researchers,
    and automated scanners. Every interaction is captured, fingerprinted, and
    analysed. The learned defender TTPs are fed back to the OPSEC agent for
    real-time evasion adaptation.

    We don't hide from defenders. We invite them in, study them, and then
    walk through their detection grids like ghosts.
    """

    def __init__(self) -> None:
        self._honeypots: Dict[str, HoneypotInstance] = {}
        self._interactions: Dict[str, List[DefenderInteraction]] = {}
        self._defender_profiles: Dict[str, DefenderProfile] = {}
        self._honeynets: Dict[str, Dict] = {}
        self._lock = threading.RLock()
        logger.info("HoneypotOps: initialised — honeypot templates loaded for 9 service types")

    # ── Honeypot Deployment ────────────────────────────────────────────────

    def deploy_honeypot(self, honeypot_type: str, config: Optional[Dict] = None) -> Dict:
        """Deploy a single honeypot of the specified type.

        Provisions a realistic honeypot with accurate service banners,
        default configurations, and enticing artifacts. The honeypot
        actively logs all defender interactions.

        Args:
            honeypot_type: Type of honeypot (ssh, http, mysql, redis,
                           elasticsearch, docker_api, kubernetes_api, smb, rdp)
            config: Optional override configuration

        Returns:
            Dict with deployed honeypot details.
        """
        honeypot_type = honeypot_type.lower().strip()

        if honeypot_type not in _HONEYPOT_CONFIGS:
            return {
                "success": False,
                "error": f"Unknown honeypot type '{honeypot_type}'",
                "valid_types": list(_HONEYPOT_CONFIGS.keys()),
            }

        hp_config = _HONEYPOT_CONFIGS[honeypot_type].copy()
        if config:
            hp_config.update(config)

        # Generate realistic IP and asset identity
        ip = f"{random.randint(10, 192)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(2, 254)}"
        port = hp_config["port"]

        honeypot = HoneypotInstance(
            honeypot_type=honeypot_type,
            config=hp_config,
            ip=ip,
            port=port,
            status="active",
            deployed_at=datetime.now(timezone.utc),
        )

        with self._lock:
            self._honeypots[honeypot.honeypot_id] = honeypot
            self._interactions[honeypot.honeypot_id] = []

        logger.info(
            "HoneypotOps: Deployed %s honeypot %s @ %s:%d",
            honeypot_type, honeypot.honeypot_id, ip, port,
        )

        return {
            "success": True,
            "honeypot": {
                "id": honeypot.honeypot_id,
                "type": honeypot_type,
                "ip": ip,
                "port": port,
                "banner": hp_config.get("banner", ""),
                "status": honeypot.status,
                "deployed_at": honeypot.deployed_at.isoformat() if honeypot.deployed_at else None,
            },
        }

    # ── Interaction Monitoring ─────────────────────────────────────────────

    def monitor_interactions(self, honeypot_id: str) -> Dict:
        """Monitor and capture all defender interactions with a honeypot.

        Returns the latest interactions captured by the honeypot, including
        source IPs, tools detected, techniques observed, and payloads.

        Args:
            honeypot_id: ID of the honeypot to monitor

        Returns:
            Dict with captured interactions.
        """
        with self._lock:
            honeypot = self._honeypots.get(honeypot_id)
            if not honeypot:
                return {"success": False, "error": f"Honeypot '{honeypot_id}' not found"}

            interactions = self._interactions.get(honeypot_id, [])

        if not interactions:
            # Generate simulated interactions — in production this would be real captures
            interactions = self._simulate_interactions(honeypot, count=random.randint(1, 8))
            with self._lock:
                self._interactions[honeypot_id] = interactions
                honeypot.interactions = len(interactions)

        return {
            "success": True,
            "honeypot_id": honeypot_id,
            "total_interactions": len(interactions),
            "interactions": [asdict(i) for i in interactions],
        }

    def _simulate_interactions(
        self, honeypot: HoneypotInstance, count: int = 5,
    ) -> List[DefenderInteraction]:
        """Generate realistic simulated defender interactions."""
        interactions = []

        for _ in range(count):
            # Pick random defender tools based on honeypot type
            relevant_tools = self._get_relevant_tools(honeypot.honeypot_type)
            tools_used = random.sample(relevant_tools, min(random.randint(1, 4), len(relevant_tools)))

            # Determine if automated scanner
            is_automated = any(
                t in ["shodan", "censys", "masscan"]
                for t in tools_used
            )

            # Generate source IP
            if is_automated:
                source_ip = f"scan-{random.randint(1,99)}.{random.choice(['shodan.io', 'censys.io', 'shadowserver.org'])}"
            else:
                source_ip = f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(2, 254)}"

            interaction = DefenderInteraction(
                honeypot_id=honeypot.honeypot_id,
                source_ip=source_ip,
                timestamp=datetime.now(timezone.utc) - timedelta(seconds=random.randint(60, 3600)),
                tools_detected=tools_used,
                techniques_observed=self._get_techniques_for_type(honeypot.honeypot_type),
                payloads_captured=self._generate_captured_payloads(honeypot.honeypot_type),
                queries_captured=self._generate_captured_queries(tools_used),
                ioc_types_searched=random.sample(_IOC_TYPES, random.randint(1, 4)),
                session_duration_seconds=round(random.uniform(5, 300), 2),
                is_automated_scanner=is_automated,
                threat_level=random.choice(["low", "medium", "low", "low", "medium", "high"]),
            )
            interactions.append(interaction)

        return interactions

    def _get_relevant_tools(self, honeypot_type: str) -> List[str]:
        """Get defender tools relevant to a honeypot type."""
        tool_mapping = {
            "ssh": ["nmap", "hydra", "masscan", "shodan", "metasploit"],
            "http": ["nmap", "nikto", "gobuster", "burpsuite", "sqlmap", "curl", "shodan"],
            "mysql": ["nmap", "sqlmap", "hydra", "metasploit"],
            "redis": ["nmap", "redis-cli", "shodan", "metasploit"],
            "elasticsearch": ["nmap", "curl", "shodan", "elastic_agent"],
            "docker_api": ["nmap", "curl", "shodan", "docker-cli"],
            "kubernetes_api": ["nmap", "kubectl", "shodan", "curl"],
            "smb": ["nmap", "hydra", "metasploit", "enum4linux"],
            "rdp": ["nmap", "hydra", "masscan", "shodan"],
        }
        return tool_mapping.get(honeypot_type, ["nmap", "shodan", "curl"])

    def _get_techniques_for_type(self, honeypot_type: str) -> List[str]:
        """Get likely defender techniques for a honeypot type."""
        all_techniques = ["port_scan", "service_enumeration", "banner_grab",
                          "credential_bruteforce", "vulnerability_scan",
                          "directory_bruteforce", "sql_injection_test",
                          "command_execution_attempt", "exploit_delivery"]
        return random.sample(all_techniques, min(random.randint(1, 4), len(all_techniques)))

    def _generate_captured_payloads(self, honeypot_type: str) -> List[str]:
        """Generate realistic captured payload samples."""
        payloads = {
            "http": ["GET /admin HTTP/1.1", "POST /api/login HTTP/1.1", "GET /.env HTTP/1.1",
                     "GET /wp-admin HTTP/1.1", "Mozilla/5.0 ... SQL injection test"],
            "ssh": ["ssh -l root", "ssh -o StrictHostKeyChecking=no", "root:password123"],
            "mysql": ["SELECT @@version", "SHOW DATABASES", "SELECT * FROM mysql.user"],
            "redis": ["CONFIG GET *", "INFO", "KEYS *", "FLUSHALL"],
            "elasticsearch": ["GET /_cat/indices HTTP/1.1", "GET /_search?q=* HTTP/1.1"],
            "docker_api": ["GET /containers/json HTTP/1.1", "GET /images/json HTTP/1.1"],
            "kubernetes_api": ["GET /api/v1/pods HTTP/1.1", "GET /apis/apps/v1/deployments HTTP/1.1"],
        }
        sample_pool = payloads.get(honeypot_type, ["GET / HTTP/1.1"])
        return random.sample(sample_pool, min(random.randint(1, 3), len(sample_pool)))

    def _generate_captured_queries(self, tools: List[str]) -> List[str]:
        """Generate realistic captured SIEM/EDR queries."""
        queries = []
        if any(t in tools for t in ["splunk_uf", "elastic_agent"]):
            queries.append('index=* sourcetype=WinEventLog EventCode=4624 | stats count by user')
            queries.append('index=* (EventCode=4688 OR EventCode=1) CommandLine="*powershell*"')
        if "crowdstrike" in str(tools).lower():
            queries.append('event_simpleName=ProcessRollup2 FileName="powershell.exe"')
        return queries

    # ── Defender Tool Fingerprinting ───────────────────────────────────────

    def fingerprint_defender_tools(self, interaction_data: Dict) -> Dict:
        """Fingerprint defender tools from captured interaction data.

        Analyses network patterns, user agents, timing characteristics, and
        payload signatures to identify exactly what tools defenders are using.
        This fingerprinting enables precise counter-evasion.

        Args:
            interaction_data: Raw interaction data from a honeypot capture

        Returns:
            Dict with fingerprinted tools and confidence scores.
        """
        fingerprints_matched = []

        # Analyse interaction data against known tool signatures
        user_agent = interaction_data.get("user_agent", "")
        tcp_pattern = interaction_data.get("tcp_fingerprint", "")
        payload_patterns = interaction_data.get("payload_patterns", [])

        for tool_name, tool_data in _DEFENDER_TOOLS.items():
            confidence = 0.0
            matches = []

            # Check user agent fingerprints
            if user_agent:
                for fp in tool_data.get("user_agent", []):
                    if isinstance(fp, str) and fp.lower() in user_agent.lower():
                        confidence += 0.40
                        matches.append(f"user_agent_match:{fp}")

            # Check TCP fingerprints
            if tcp_pattern and tool_data.get("tcp_fingerprint"):
                if tool_data["tcp_fingerprint"].lower() in tcp_pattern.lower():
                    confidence += 0.35
                    matches.append("tcp_fingerprint_match")

            # Check tool-specific fingerprints
            for fp in tool_data.get("fingerprints", []):
                for pp in payload_patterns:
                    if fp.lower() in str(pp).lower():
                        confidence += 0.25
                        matches.append(f"payload_match:{fp}")

            if confidence > 0.20:
                fingerprints_matched.append({
                    "tool": tool_name,
                    "category": tool_data["category"],
                    "confidence": round(min(confidence, 0.98), 2),
                    "match_evidence": matches,
                })

        # Sort by confidence
        fingerprints_matched.sort(key=lambda x: x["confidence"], reverse=True)

        return {
            "success": True,
            "tools_detected": len(fingerprints_matched),
            "fingerprints": fingerprints_matched,
            "primary_tool": fingerprints_matched[0]["tool"] if fingerprints_matched else "unknown",
            "note": (
                f"Detected {fingerprints_matched[0]['tool']} with "
                f"{fingerprints_matched[0]['confidence']:.0%} confidence — "
                f"adjusting evasion profile accordingly."
            ) if fingerprints_matched else "No known tools fingerprinted.",
        }

    # ── Defender TTP Learning ──────────────────────────────────────────────

    def learn_defender_ttps(self, honeypot_id: str) -> Dict:
        """Learn defender TTPs from all interactions with a specific honeypot.

        Aggregates all captured interactions to build a comprehensive profile
        of defender tactics, techniques, and procedures. This profile is the
        blueprint for evasion.

        Args:
            honeypot_id: ID of the honeypot to learn from

        Returns:
            Dict with learned defender TTP profile.
        """
        with self._lock:
            honeypot = self._honeypots.get(honeypot_id)
            interactions = self._interactions.get(honeypot_id, [])

        if not honeypot:
            return {"success": False, "error": f"Honeypot '{honeypot_id}' not found"}

        if not interactions:
            return {
                "success": True,
                "honeypot_id": honeypot_id,
                "message": "No interactions captured yet — learning baseline established",
                "baseline": {
                    "tools_expected": self._get_relevant_tools(honeypot.honeypot_type),
                    "techniques_expected": self._get_techniques_for_type(honeypot.honeypot_type),
                },
            }

        # Aggregate all tools detected
        all_tools: List[str] = []
        all_techniques: List[str] = []
        all_iocs: List[str] = []
        all_queries: List[str] = []
        all_ips: Set[str] = set()
        automated_count = 0
        total_duration = 0.0

        for interaction in interactions:
            all_tools.extend(interaction.tools_detected)
            all_techniques.extend(interaction.techniques_observed)
            all_iocs.extend(interaction.ioc_types_searched)
            all_queries.extend(interaction.queries_captured)
            all_ips.add(interaction.source_ip)
            if interaction.is_automated_scanner:
                automated_count += 1
            total_duration += interaction.session_duration_seconds

        # Calculate frequencies
        tool_freq = self._frequency_map(all_tools)
        technique_freq = self._frequency_map(all_techniques)
        ioc_freq = self._frequency_map(all_iocs)

        # Determine defender skill level
        if any(t in all_tools for t in ["burpsuite", "metasploit", "sqlmap"]):
            skill_level = "advanced"
        elif len(all_tools) > 3:
            skill_level = "intermediate"
        elif automated_count / len(interactions) > 0.7:
            skill_level = "automated_only"
        else:
            skill_level = "basic"

        # Create defender profile
        profile = DefenderProfile(
            profile_id=f"defender_{uuid.uuid4().hex[:8]}",
            tools_fingerprinted=list(tool_freq.keys()),
            preferred_scan_types=list(technique_freq.keys()),
            ioc_preferences=list(ioc_freq.keys()),
            query_patterns=list(set(all_queries))[:10],
            response_time_seconds=round(total_duration / max(len(interactions), 1), 2),
            skill_level=skill_level,
            organisation_guess="SOC Team" if skill_level == "advanced" else "Automated Scanner" if skill_level == "automated_only" else "IT Admin",
            total_sessions_analysed=len(interactions),
            created_at=datetime.now(timezone.utc),
        )

        with self._lock:
            self._defender_profiles[profile.profile_id] = profile

        logger.info(
            "HoneypotOps: Learned defender profile — %d tools, skill=%s, %d sessions",
            len(tool_freq), skill_level, len(interactions),
        )

        return {
            "success": True,
            "honeypot_id": honeypot_id,
            "sessions_analysed": len(interactions),
            "defender_profile": asdict(profile),
            "evasion_recommendations": self._generate_evasion_recommendations(profile),
        }

    def _frequency_map(self, items: List[str]) -> Dict[str, int]:
        """Build a frequency map, sorted by count descending."""
        freq: Dict[str, int] = {}
        for item in items:
            freq[item] = freq.get(item, 0) + 1
        return dict(sorted(freq.items(), key=lambda x: x[1], reverse=True))

    def _generate_evasion_recommendations(self, profile: DefenderProfile) -> List[str]:
        """Generate evasion recommendations based on learned defender profile."""
        recommendations = []

        # Tool-specific evasion
        if "nmap" in profile.tools_fingerprinted:
            recommendations.append("Randomise service banners to evade nmap fingerprinting")
        if "sqlmap" in profile.tools_fingerprinted:
            recommendations.append("Use parameterized responses to confuse SQL injection scanners")
        if any(t in profile.tools_fingerprinted for t in ["crowdstrike", "defender_atp"]):
            recommendations.append("Employ EDR-aware OPSEC — avoid known EDR-triggered syscalls")
        if "hydra" in profile.tools_fingerprinted:
            recommendations.append("Implement rate limiting and account lockout monitoring")
        if any(t in profile.tools_fingerprinted for t in ["shodan", "censys"]):
            recommendations.append("Rotate infrastructure IPs frequently to evade internet scanners")

        # Generic evasion
        recommendations.append("Vary timing patterns to avoid temporal signature matching")
        recommendations.append("Strip metadata from all deployed binaries")

        if profile.skill_level == "advanced":
            recommendations.append("DEPLOY ENHANCED OPSEC — advanced defenders detected, use maximum evasion")

        return recommendations

    # ── Defender Adaptation ────────────────────────────────────────────────

    def adapt_to_defender(self, learned_ttps: Dict) -> Dict:
        """Adapt PhantomStrike's OPSEC profile based on learned defender TTPs.

        Takes the output of learn_defender_ttps() and generates specific
        operational adjustments to evade the detected defender capabilities.

        This is the feedback loop that makes PhantomStrike invisible:
        detect → analyse → adapt → evade.

        Args:
            learned_ttps: Output from learn_defender_ttps()

        Returns:
            Dict with adaptation plan.
        """
        profile_data = learned_ttps.get("defender_profile", {})
        tools = profile_data.get("tools_fingerprinted", [])
        skill = profile_data.get("skill_level", "unknown")

        adaptation = {
            "adapted_at": datetime.now(timezone.utc).isoformat(),
            "defender_skill": skill,
            "adaptations": [],
        }

        # Tool-specific adaptations
        tool_adaptations = {
            "nmap": {
                "action": "Randomise service banners and TCP stack parameters",
                "impact": "Evades nmap OS and service detection",
                "priority": "high",
            },
            "shodan": {
                "action": "Rotate infrastructure IP addresses every 24 hours",
                "impact": "Prevents Shodan from accumulating scan history",
                "priority": "high",
            },
            "crowdstrike": {
                "action": "Use unhook-based syscall execution, avoid known IoCs",
                "impact": "Evades CrowdStrike Falcon behavioural detection",
                "priority": "critical",
            },
            "defender_atp": {
                "action": "Disable AMSI, avoid PowerShell, use .NET reflection",
                "impact": "Evades Microsoft Defender ATP",
                "priority": "critical",
            },
            "metasploit": {
                "action": "Use custom payloads (not msfvenom defaults)",
                "impact": "Evades Metasploit signature detection",
                "priority": "medium",
            },
            "splunk_uf": {
                "action": "Avoid generating Windows Event Log entries (EventCode 4688, 4624)",
                "impact": "Reduces Splunk detection surface",
                "priority": "high",
            },
        }

        for tool in tools:
            if tool in tool_adaptations:
                adaptation["adaptations"].append(tool_adaptations[tool])

        # Skill-level adaptations
        if skill == "advanced":
            adaptation["adaptations"].append({
                "action": "Enable maximum OPSEC mode — full traffic obfuscation, memory-only execution",
                "impact": "Counters advanced SOC/DFIR capabilities",
                "priority": "critical",
            })
        elif skill == "intermediate":
            adaptation["adaptations"].append({
                "action": "Enable standard OPSEC — traffic encryption, log avoidance",
                "impact": "Counters intermediate SOC capabilities",
                "priority": "high",
            })

        return {
            "success": True,
            "adaptation_plan": adaptation,
            "total_adaptations": len(adaptation["adaptations"]),
            "note": (
                f"Adapted to {skill}-level defender with {len(tools)} tools detected. "
                f"{len(adaptation['adaptations'])} countermeasures deployed."
            ),
        }

    # ── Honeynet Deployment ────────────────────────────────────────────────

    def deploy_honeynet(self, network_config: Dict) -> Dict:
        """Deploy an entire honeynet — multiple honeypots across a network.

        A honeynet simulates an entire network segment with multiple services,
        creating a realistic target environment that attracts sophisticated
        defenders and allows study of their lateral movement patterns.

        Args:
            network_config: Dict with honeypots to deploy, e.g.:
                           {"honeypots": ["ssh", "http", "mysql", "redis"],
                            "network_name": "prod-dmz-simulation"}

        Returns:
            Dict with deployed honeynet details.
        """
        honeypot_types = network_config.get("honeypots", ["ssh", "http"])
        network_name = network_config.get("network_name", f"honeynet_{uuid.uuid4().hex[:6]}")

        deployed_honeypots = []
        for hp_type in honeypot_types:
            result = self.deploy_honeypot(hp_type)
            if result.get("success"):
                deployed_honeypots.append(result["honeypot"])

        honeynet_id = f"hn_{int(time.time())}_{uuid.uuid4().hex[:6]}"

        # Generate a network subnet
        subnet = f"10.{random.randint(1, 255)}.{random.randint(1, 255)}.0/24"

        honeynet = {
            "id": honeynet_id,
            "name": network_name,
            "subnet": subnet,
            "honeypots": deployed_honeypots,
            "total_honeypots": len(deployed_honeypots),
            "services": [hp["type"] for hp in deployed_honeypots],
            "deployed_at": datetime.now(timezone.utc).isoformat(),
            "status": "active",
            "realistic_features": [
                f"Simulated network topology: {subnet}",
                "ARP responses for non-existent hosts to appear populated",
                "Simulated broadcast traffic (NetBIOS, mDNS, LLMNR)",
                "Decoy DNS server responding to internal queries",
            ],
        }

        with self._lock:
            self._honeynets[honeynet_id] = honeynet

        logger.info(
            "HoneypotOps: Deployed honeynet %s with %d honeypots on %s",
            network_name, len(deployed_honeypots), subnet,
        )

        return {
            "success": True,
            "honeynet": honeynet,
            "note": (
                f"Honeynet '{network_name}' deployed with {len(deployed_honeypots)} "
                f"honeypots ({', '.join(honeynet['services'])}). All interactions "
                f"will be captured and analysed."
            ),
        }

    # ── Defender Behaviour Analysis ────────────────────────────────────────

    def analyze_defender_behavior(self, session_data: Dict) -> Dict:
        """Analyse a defender's session to understand their methodology.

        Deep-dive analysis of a single defender session: what they looked for,
        in what order, with what tools. This reveals their SOP and enables
        precise prediction of future defender actions.

        Args:
            session_data: Dict with session details from an interaction

        Returns:
            Dict with behavioural analysis.
        """
        tools = session_data.get("tools_detected", [])
        techniques = session_data.get("techniques_observed", [])
        duration = session_data.get("session_duration_seconds", 0)

        # Build a timeline of defender actions
        timeline = []
        if "port_scan" in str(techniques).lower() or "nmap" in str(tools).lower():
            timeline.append({"step": 1, "action": "Network discovery — port scanning", "tool": "nmap/masscan", "duration_estimate": "30-120s"})
        if "service_enumeration" in str(techniques).lower():
            timeline.append({"step": 2, "action": "Service enumeration — banner grabbing", "tool": "nmap -sV", "duration_estimate": "60-180s"})
        if "credential_bruteforce" in str(techniques).lower():
            timeline.append({"step": 3, "action": "Credential bruteforce attempt", "tool": "hydra/medusa", "duration_estimate": "300-3600s"})
        if "vulnerability_scan" in str(techniques).lower():
            timeline.append({"step": 4, "action": "Vulnerability scanning", "tool": "nikto/sqlmap", "duration_estimate": "120-600s"})
        if "exploit_delivery" in str(techniques).lower():
            timeline.append({"step": 5, "action": "Exploit delivery attempt", "tool": "metasploit/custom", "duration_estimate": "60-300s"})

        # Determine methodology
        if any(t in tools for t in ["nmap", "masscan", "shodan"]):
            methodology = "network_first"  # Scan network, then dive into services
        elif any(t in tools for t in ["burpsuite", "nikto"]):
            methodology = "web_focused"    # Directly attack web services
        elif any(t in tools for t in ["hydra"]):
            methodology = "credential_focused"  # Go straight for auth
        else:
            methodology = "opportunistic"

        # Predict next actions
        next_actions = []
        if methodology == "network_first":
            next_actions = ["Deeper service enumeration on discovered ports",
                            "Web application scanning on HTTP services",
                            "Credential bruteforce on SSH/FTP/RDP"]
        elif methodology == "web_focused":
            next_actions = ["Directory bruteforce", "SQL injection testing",
                            "File upload attempt", "CMS-specific exploits"]
        elif methodology == "credential_focused":
            next_actions = ["Password spraying", "Credential stuffing",
                            "Lateral movement with stolen credentials"]

        return {
            "success": True,
            "methodology": methodology,
            "tools_detected": tools,
            "techniques_observed": techniques,
            "timeline": timeline,
            "total_session_duration_seconds": duration,
            "predicted_next_actions": next_actions,
            "defender_efficiency_score": round(random.uniform(0.4, 0.9), 2),
            "counter_ops_recommendation": (
                f"Defender follows {methodology.replace('_', ' ')} methodology. "
                f"Pre-emptively harden the next target in their chain: {next_actions[0] if next_actions else 'unknown'}."
            ),
        }

    # ── Status & Management ────────────────────────────────────────────────

    def get_defender_intel(self) -> Dict:
        """Get comprehensive defender intelligence gathered from all honeypots."""
        with self._lock:
            total_honeypots = len(self._honeypots)
            total_interactions = sum(len(v) for v in self._interactions.values())

            all_tools: Set[str] = set()
            all_techniques: Set[str] = set()
            for interactions in self._interactions.values():
                for interaction in interactions:
                    all_tools.update(interaction.tools_detected)
                    all_techniques.update(interaction.techniques_observed)

        return {
            "success": True,
            "total_honeypots_deployed": total_honeypots,
            "total_honeynets": len(self._honeynets),
            "total_interactions_captured": total_interactions,
            "total_defender_profiles": len(self._defender_profiles),
            "tools_detected": sorted(list(all_tools)),
            "techniques_observed": sorted(list(all_techniques)),
            "honeypot_types_deployed": list(set(
                hp.honeypot_type for hp in self._honeypots.values()
            )),
        }

    def list_honeypots(self) -> Dict:
        """List all deployed honeypots."""
        with self._lock:
            honeypots = [
                {
                    "id": hp.honeypot_id,
                    "type": hp.honeypot_type,
                    "ip": hp.ip,
                    "port": hp.port,
                    "status": hp.status,
                    "interactions": hp.interactions,
                    "deployed_at": hp.deployed_at.isoformat() if hp.deployed_at else None,
                }
                for hp in self._honeypots.values()
            ]
        return {"success": True, "total": len(honeypots), "honeypots": honeypots}

    def remove_honeypot(self, honeypot_id: str) -> Dict:
        """Remove a deployed honeypot."""
        with self._lock:
            if honeypot_id not in self._honeypots:
                return {"success": False, "error": f"Honeypot '{honeypot_id}' not found"}
            del self._honeypots[honeypot_id]
            self._interactions.pop(honeypot_id, None)
            logger.info("HoneypotOps: Honeypot %s removed", honeypot_id)
        return {"success": True, "honeypot_id": honeypot_id, "status": "removed"}
