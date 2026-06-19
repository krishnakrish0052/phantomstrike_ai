"""
server_core/orchestrator/training_dojo.py

Adversarial Training Dojo — Red vs Blue autonomous training.

Runs 1000+ simulated engagements where Red Team agents attack vulnerable
VM scenarios and Blue Team agents defend with Snort/Suricata/Wazuh rules.
Both sides analyse results after each engagement, evolving tactics over time.

Key capabilities:
  - Loads VulnHub/HTB-style VM scenario configs
  - Red agents attack, Blue agents detect/block/respond
  - Post-engagement analysis: what worked, what got caught, why
  - Tracks technique effectiveness over time (rolling window statistics)
  - Exports learned techniques to agent_learnings DB for cross-mission use
  - Simulates attack paths without execution (dry-run mode)

Integration points:
  - HiveMind          — shared knowledge bus for Red/Blue agent coordination
  - agent_learnings   — DB table for persistent technique effectiveness data
  - EGATSEngine       — difficulty scoring and evidence-guided path selection
  - OrchestratorAgent — can dispatch Dojo-trained agents on real missions
"""

from __future__ import annotations

import copy
import json
import logging
import math
import random
import threading
import time
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════════════
# Data classes
# ═══════════════════════════════════════════════════════════════════════════════


@dataclass
class EngagementResult:
    """Outcome of a single Red vs Blue engagement."""

    engagement_id: str
    scenario_name: str
    round_number: int
    red_success: bool
    red_techniques_used: List[str] = field(default_factory=list)
    red_techniques_succeeded: List[str] = field(default_factory=list)
    blue_detections: List[str] = field(default_factory=list)
    blue_blocks: List[str] = field(default_factory=list)
    blue_response_actions: List[str] = field(default_factory=list)
    red_adaptation: Optional[str] = None
    blue_adaptation: Optional[str] = None
    duration_seconds: float = 0.0
    threat_level_peak: int = 0
    score_red: float = 0.0
    score_blue: float = 0.0
    lessons_learned: List[str] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "engagement_id": self.engagement_id,
            "scenario_name": self.scenario_name,
            "round_number": self.round_number,
            "red_success": self.red_success,
            "red_techniques_used": self.red_techniques_used,
            "red_techniques_succeeded": self.red_techniques_succeeded,
            "blue_detections": self.blue_detections,
            "blue_blocks": self.blue_blocks,
            "blue_response_actions": self.blue_response_actions,
            "red_adaptation": self.red_adaptation,
            "blue_adaptation": self.blue_adaptation,
            "duration_seconds": self.duration_seconds,
            "threat_level_peak": self.threat_level_peak,
            "score_red": self.score_red,
            "score_blue": self.score_blue,
            "lessons_learned": self.lessons_learned,
            "timestamp": self.timestamp,
        }


@dataclass
class TechniqueStats:
    """Rolling statistics for a single attack technique across engagements."""

    technique: str
    attempts: int = 0
    successes: int = 0
    detections: int = 0
    blocks: int = 0
    effectiveness_history: List[float] = field(default_factory=list)  # rolling window
    avg_duration: float = 0.0
    first_seen_round: int = 0
    last_seen_round: int = 0
    evolution_generations: int = 0  # how many times the technique was mutated

    @property
    def success_rate(self) -> float:
        if self.attempts == 0:
            return 0.0
        return self.successes / self.attempts

    @property
    def detection_rate(self) -> float:
        if self.attempts == 0:
            return 0.0
        return self.detections / self.attempts

    @property
    def block_rate(self) -> float:
        if self.attempts == 0:
            return 0.0
        return self.blocks / self.attempts

    @property
    def effectiveness_trend(self) -> float:
        """Slope of effectiveness over the last N engagements (-1 to +1)."""
        hist = self.effectiveness_history
        if len(hist) < 3:
            return 0.0
        # Simple linear regression slope, clamped
        n = len(hist)
        x_mean = (n - 1) / 2.0
        y_mean = sum(hist) / n
        num = sum((i - x_mean) * (hist[i] - y_mean) for i in range(n))
        den = sum((i - x_mean) ** 2 for i in range(n))
        if den == 0:
            return 0.0
        slope = num / den
        return max(-1.0, min(slope, 1.0))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "technique": self.technique,
            "attempts": self.attempts,
            "successes": self.successes,
            "detections": self.detections,
            "blocks": self.blocks,
            "success_rate": round(self.success_rate, 4),
            "detection_rate": round(self.detection_rate, 4),
            "block_rate": round(self.block_rate, 4),
            "effectiveness_trend": round(self.effectiveness_trend, 4),
            "avg_duration": round(self.avg_duration, 3),
            "first_seen_round": self.first_seen_round,
            "last_seen_round": self.last_seen_round,
            "evolution_generations": self.evolution_generations,
            "history_len": len(self.effectiveness_history),
        }


@dataclass
class CampaignStats:
    """Aggregate statistics for a training campaign."""

    campaign_id: str
    total_engagements: int = 0
    red_wins: int = 0
    blue_wins: int = 0
    draws: int = 0
    red_win_rate_history: List[float] = field(default_factory=list)
    blue_detection_rate_history: List[float] = field(default_factory=list)
    technique_stats: Dict[str, TechniqueStats] = field(default_factory=dict)
    top_techniques: List[str] = field(default_factory=list)
    novel_techniques_discovered: List[str] = field(default_factory=list)
    started_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    completed_at: Optional[str] = None
    total_duration_seconds: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "campaign_id": self.campaign_id,
            "total_engagements": self.total_engagements,
            "red_wins": self.red_wins,
            "blue_wins": self.blue_wins,
            "draws": self.draws,
            "red_win_rate": round(self.red_wins / max(self.total_engagements, 1), 4),
            "blue_win_rate": round(self.blue_wins / max(self.total_engagements, 1), 4),
            "red_win_rate_history": [round(r, 4) for r in self.red_win_rate_history],
            "blue_detection_rate_history": [round(r, 4) for r in self.blue_detection_rate_history],
            "technique_count": len(self.technique_stats),
            "top_techniques": self.top_techniques[:20],
            "novel_techniques_discovered": self.novel_techniques_discovered,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "total_duration_seconds": round(self.total_duration_seconds, 2),
        }


# ═══════════════════════════════════════════════════════════════════════════════
# Scenario templates — VulnHub / HTB-style VM configs
# ═══════════════════════════════════════════════════════════════════════════════

# Each scenario defines a target environment: OS, services, vulnerabilities,
# defensive posture, and a flag/loot to capture.
_SCENARIO_TEMPLATES: Dict[str, Dict[str, Any]] = {
    # ── Beginner VMs ──
    "kioptrix_level1": {
        "name": "Kioptrix Level 1",
        "difficulty": "beginner",
        "os": "linux",
        "hosts": 1,
        "services": [
            {"port": 80, "proto": "tcp", "service": "http", "version": "Apache 1.3.20"},
            {"port": 443, "proto": "tcp", "service": "https", "version": "mod_ssl 2.8.4"},
            {"port": 139, "proto": "tcp", "service": "netbios-ssn", "version": "Samba 2.2.1a"},
            {"port": 22, "proto": "tcp", "service": "ssh", "version": "OpenSSH 2.9p2"},
        ],
        "vulnerabilities": [
            {"cve": "CVE-2002-0082", "service": "mod_ssl", "type": "buffer_overflow", "severity": "critical"},
            {"cve": "CVE-2003-0201", "service": "samba", "type": "buffer_overflow", "severity": "critical"},
        ],
        "defenses": {
            "firewall": False,
            "ids": False,
            "edr": False,
            "waf": False,
            "logging": "minimal",
        },
        "flags": ["/root/flag.txt"],
        "estimated_duration_minutes": 30,
    },
    "metasploitable2": {
        "name": "Metasploitable 2",
        "difficulty": "beginner",
        "os": "linux",
        "hosts": 1,
        "services": [
            {"port": 21, "proto": "tcp", "service": "ftp", "version": "vsftpd 2.3.4"},
            {"port": 22, "proto": "tcp", "service": "ssh", "version": "OpenSSH 4.7p1"},
            {"port": 23, "proto": "tcp", "service": "telnet", "version": "Linux telnetd"},
            {"port": 80, "proto": "tcp", "service": "http", "version": "Apache 2.2.8"},
            {"port": 445, "proto": "tcp", "service": "smb", "version": "Samba 3.0.20"},
            {"port": 3306, "proto": "tcp", "service": "mysql", "version": "MySQL 5.0.51a"},
            {"port": 5432, "proto": "tcp", "service": "postgresql", "version": "PostgreSQL 8.3"},
        ],
        "vulnerabilities": [
            {"cve": "CVE-2011-2523", "service": "vsftpd", "type": "backdoor", "severity": "critical"},
            {"cve": "CVE-2007-2447", "service": "samba", "type": "command_injection", "severity": "critical"},
            {"cve": "CVE-2010-2075", "service": "unrealircd", "type": "backdoor", "severity": "critical"},
        ],
        "defenses": {
            "firewall": False,
            "ids": False,
            "edr": False,
            "waf": False,
            "logging": "minimal",
        },
        "flags": ["/root/flag.txt", "/home/msfadmin/flag.txt"],
        "estimated_duration_minutes": 20,
    },
    # ── Intermediate VMs ──
    "vulnhub_sickos12": {
        "name": "SickOS 1.2",
        "difficulty": "intermediate",
        "os": "linux",
        "hosts": 1,
        "services": [
            {"port": 22, "proto": "tcp", "service": "ssh", "version": "OpenSSH 5.9p1"},
            {"port": 80, "proto": "tcp", "service": "http", "version": "lighttpd 1.4.28"},
            {"port": 8080, "proto": "tcp", "service": "http-proxy", "version": "Squid 3.1.19"},
            {"port": 3128, "proto": "tcp", "service": "http-proxy", "version": "Squid 3.1.19"},
        ],
        "vulnerabilities": [
            {"cve": "CVE-2016-4557", "service": "kernel", "type": "privilege_escalation", "severity": "high"},
            {"cve": "", "service": "squid", "type": "open_proxy", "severity": "medium"},
        ],
        "defenses": {
            "firewall": True,
            "ids": False,
            "edr": False,
            "waf": False,
            "logging": "basic",
        },
        "flags": ["/root/flag.txt"],
        "estimated_duration_minutes": 45,
    },
    "htb_bashed": {
        "name": "HackTheBox — Bashed",
        "difficulty": "intermediate",
        "os": "linux",
        "hosts": 1,
        "services": [
            {"port": 80, "proto": "tcp", "service": "http", "version": "Apache 2.4.18"},
            {"port": 22, "proto": "tcp", "service": "ssh", "version": "OpenSSH 7.2p2"},
        ],
        "vulnerabilities": [
            {"cve": "", "service": "phpbash", "type": "webshell_upload", "severity": "high"},
            {"cve": "", "service": "cron", "type": "sudo_misconfiguration", "severity": "high"},
        ],
        "defenses": {
            "firewall": True,
            "ids": False,
            "edr": False,
            "waf": False,
            "logging": "basic",
        },
        "flags": ["/root/root.txt", "/home/arrexel/user.txt"],
        "estimated_duration_minutes": 40,
    },
    # ── Advanced VMs ──
    "vulnhub_symfonos3": {
        "name": "Symfonos 3",
        "difficulty": "advanced",
        "os": "linux",
        "hosts": 2,  # pivot required
        "services": [
            {"port": 21, "proto": "tcp", "service": "ftp", "version": "ProFTPD 1.3.5"},
            {"port": 22, "proto": "tcp", "service": "ssh", "version": "OpenSSH 7.4p1"},
            {"port": 80, "proto": "tcp", "service": "http", "version": "Apache 2.4.25"},
            {"port": 445, "proto": "tcp", "service": "smb", "version": "Samba 4.5.12"},
        ],
        "vulnerabilities": [
            {"cve": "CVE-2015-3306", "service": "proftpd", "type": "rce", "severity": "critical"},
            {"cve": "", "service": "webapp", "type": "lfi", "severity": "high"},
            {"cve": "", "service": "kernel", "type": "dirtycow_like", "severity": "critical"},
        ],
        "defenses": {
            "firewall": True,
            "ids": True,  # Snort with default rules
            "edr": False,
            "waf": False,
            "logging": "moderate",
        },
        "flags": ["/root/proof.txt", "/home/hades/user.txt"],
        "estimated_duration_minutes": 90,
    },
    "htb_forest": {
        "name": "HackTheBox — Forest",
        "difficulty": "advanced",
        "os": "windows",
        "hosts": 1,
        "services": [
            {"port": 53, "proto": "tcp", "service": "dns", "version": "Windows DNS"},
            {"port": 88, "proto": "tcp", "service": "kerberos", "version": "Windows Kerberos"},
            {"port": 135, "proto": "tcp", "service": "msrpc", "version": "Windows RPC"},
            {"port": 139, "proto": "tcp", "service": "netbios-ssn", "version": "Windows NetBIOS"},
            {"port": 389, "proto": "tcp", "service": "ldap", "version": "Windows LDAP"},
            {"port": 445, "proto": "tcp", "service": "smb", "version": "Windows SMB"},
            {"port": 3268, "proto": "tcp", "service": "ldap", "version": "Global Catalog"},
            {"port": 5985, "proto": "tcp", "service": "winrm", "version": "WinRM HTTP"},
        ],
        "vulnerabilities": [
            {"cve": "", "service": "ldap", "type": "asreproast", "severity": "high"},
            {"cve": "", "service": "smb", "type": "null_session_enum", "severity": "medium"},
            {"cve": "", "service": "ad", "type": "dcsync_abuse", "severity": "critical"},
        ],
        "defenses": {
            "firewall": True,
            "ids": True,  # Suricata
            "edr": True,  # Windows Defender
            "waf": False,
            "logging": "extensive",
        },
        "flags": ["C:\\Users\\Administrator\\Desktop\\root.txt"],
        "estimated_duration_minutes": 120,
    },
    # ── Expert / Hardened VMs ──
    "htb_monteverde": {
        "name": "HackTheBox — Monteverde",
        "difficulty": "expert",
        "os": "windows",
        "hosts": 1,
        "services": [
            {"port": 53, "proto": "tcp", "service": "dns", "version": "Windows DNS"},
            {"port": 88, "proto": "tcp", "service": "kerberos", "version": "Windows Kerberos"},
            {"port": 135, "proto": "tcp", "service": "msrpc", "version": "Windows RPC"},
            {"port": 389, "proto": "tcp", "service": "ldap", "version": "Windows LDAP"},
            {"port": 445, "proto": "tcp", "service": "smb", "version": "Windows SMB"},
            {"port": 5985, "proto": "tcp", "service": "winrm", "version": "WinRM HTTP"},
        ],
        "vulnerabilities": [
            {"cve": "", "service": "smb", "type": "azure_ad_connect", "severity": "high"},
            {"cve": "", "service": "ad", "type": "password_spray", "severity": "medium"},
        ],
        "defenses": {
            "firewall": True,
            "ids": True,   # Suricata with custom rules
            "edr": True,   # Windows Defender ATP
            "waf": False,
            "logging": "extensive",
        },
        "flags": ["C:\\Users\\Administrator\\Desktop\\root.txt"],
        "estimated_duration_minutes": 180,
    },
    "custom_enterprise_lab": {
        "name": "Enterprise Lab (Custom)",
        "difficulty": "expert",
        "os": "mixed",
        "hosts": 5,
        "services": [
            {"port": 80, "proto": "tcp", "service": "http", "version": "nginx 1.18 + WAF"},
            {"port": 443, "proto": "tcp", "service": "https", "version": "nginx 1.18 + WAF"},
            {"port": 22, "proto": "tcp", "service": "ssh", "version": "OpenSSH 8.4"},
            {"port": 445, "proto": "tcp", "service": "smb", "version": "Windows Server 2019"},
            {"port": 3389, "proto": "tcp", "service": "rdp", "version": "Windows RDP"},
            {"port": 8080, "proto": "tcp", "service": "http", "version": "Jenkins 2.319"},
            {"port": 5432, "proto": "tcp", "service": "postgresql", "version": "PostgreSQL 13"},
            {"port": 6379, "proto": "tcp", "service": "redis", "version": "Redis 6.2"},
        ],
        "vulnerabilities": [
            {"cve": "CVE-2022-24706", "service": "redis", "type": "rce", "severity": "critical"},
            {"cve": "CVE-2022-20623", "service": "jenkins", "type": "auth_bypass", "severity": "high"},
            {"cve": "", "service": "ad", "type": "kerberoasting", "severity": "critical"},
            {"cve": "", "service": "nginx", "type": "ssrf_waf_bypass", "severity": "medium"},
        ],
        "defenses": {
            "firewall": True,
            "ids": True,     # Suricata + custom rules
            "edr": True,     # CrowdStrike Falcon
            "waf": True,     # ModSecurity + OWASP CRS
            "logging": "siem",  # Splunk ingestion
        },
        "flags": [
            "/root/flag.txt",
            "C:\\Users\\Administrator\\Desktop\\flag.txt",
            "/var/lib/postgresql/flag.txt",
        ],
        "estimated_duration_minutes": 240,
    },
}


# ═══════════════════════════════════════════════════════════════════════════════
# Technique / defense catalogs
# ═══════════════════════════════════════════════════════════════════════════════

# Red Team techniques catalogued by kill-chain phase.
_RED_TECHNIQUES: Dict[str, List[Dict[str, Any]]] = {
    "recon": [
        {"name": "port_scan_syn", "stealth": "low", "detection_risk": 0.7, "tools": ["nmap"]},
        {"name": "port_scan_connect", "stealth": "low", "detection_risk": 0.9, "tools": ["nmap"]},
        {"name": "port_scan_fin", "stealth": "high", "detection_risk": 0.3, "tools": ["nmap"]},
        {"name": "port_scan_null", "stealth": "high", "detection_risk": 0.2, "tools": ["nmap"]},
        {"name": "port_scan_xmas", "stealth": "high", "detection_risk": 0.25, "tools": ["nmap"]},
        {"name": "dns_enum_axfr", "stealth": "medium", "detection_risk": 0.5, "tools": ["dig"]},
        {"name": "subdomain_bruteforce", "stealth": "medium", "detection_risk": 0.6, "tools": ["gobuster"]},
        {"name": "http_dirbust", "stealth": "medium", "detection_risk": 0.7, "tools": ["gobuster", "dirb"]},
        {"name": "service_banner_grab", "stealth": "low", "detection_risk": 0.4, "tools": ["nmap", "netcat"]},
    ],
    "exploitation": [
        {"name": "sqli_union", "stealth": "medium", "detection_risk": 0.5, "tools": ["sqlmap"]},
        {"name": "sqli_blind", "stealth": "high", "detection_risk": 0.3, "tools": ["sqlmap"]},
        {"name": "sqli_time_based", "stealth": "high", "detection_risk": 0.2, "tools": ["sqlmap"]},
        {"name": "xss_reflected", "stealth": "low", "detection_risk": 0.6, "tools": ["manual"]},
        {"name": "xss_stored", "stealth": "medium", "detection_risk": 0.4, "tools": ["manual"]},
        {"name": "command_injection", "stealth": "medium", "detection_risk": 0.5, "tools": ["manual"]},
        {"name": "file_inclusion_lfi", "stealth": "medium", "detection_risk": 0.4, "tools": ["manual"]},
        {"name": "file_upload_webshell", "stealth": "high", "detection_risk": 0.3, "tools": ["manual"]},
        {"name": "buffer_overflow", "stealth": "medium", "detection_risk": 0.5, "tools": ["msfvenom"]},
        {"name": "metasploit_exploit", "stealth": "low", "detection_risk": 0.8, "tools": ["msfconsole"]},
        {"name": "deserialization_attack", "stealth": "high", "detection_risk": 0.2, "tools": ["ysoserial"]},
        {"name": "ssrf_internal_probe", "stealth": "high", "detection_risk": 0.3, "tools": ["manual"]},
        {"name": "template_injection_ssti", "stealth": "medium", "detection_risk": 0.4, "tools": ["tplmap"]},
    ],
    "post_exploitation": [
        {"name": "linpeas_enum", "stealth": "low", "detection_risk": 0.7, "tools": ["linpeas"]},
        {"name": "winpeas_enum", "stealth": "low", "detection_risk": 0.8, "tools": ["winpeas"]},
        {"name": "sudo_abuse", "stealth": "medium", "detection_risk": 0.4, "tools": ["sudo"]},
        {"name": "suid_exploit", "stealth": "medium", "detection_risk": 0.3, "tools": ["find"]},
        {"name": "cron_hijack", "stealth": "high", "detection_risk": 0.2, "tools": ["crontab"]},
        {"name": "capability_abuse", "stealth": "high", "detection_risk": 0.2, "tools": ["getcap"]},
        {"name": "kernel_exploit", "stealth": "low", "detection_risk": 0.6, "tools": ["gcc"]},
        {"name": "docker_escape", "stealth": "high", "detection_risk": 0.3, "tools": ["docker"]},
        {"name": "lxc_container_breakout", "stealth": "high", "detection_risk": 0.25, "tools": ["lxc"]},
    ],
    "lateral_movement": [
        {"name": "pass_the_hash", "stealth": "medium", "detection_risk": 0.5, "tools": ["impacket"]},
        {"name": "pass_the_ticket", "stealth": "medium", "detection_risk": 0.5, "tools": ["impacket"]},
        {"name": "kerberoasting", "stealth": "medium", "detection_risk": 0.4, "tools": ["impacket"]},
        {"name": "asreproasting", "stealth": "high", "detection_risk": 0.2, "tools": ["impacket"]},
        {"name": "dcsync", "stealth": "low", "detection_risk": 0.9, "tools": ["mimikatz"]},
        {"name": "wmi_exec", "stealth": "medium", "detection_risk": 0.6, "tools": ["impacket"]},
        {"name": "psexec", "stealth": "low", "detection_risk": 0.8, "tools": ["impacket"]},
        {"name": "ssh_agent_forward", "stealth": "high", "detection_risk": 0.2, "tools": ["ssh"]},
        {"name": "ssh_credential_reuse", "stealth": "medium", "detection_risk": 0.4, "tools": ["ssh"]},
    ],
    "exfiltration": [
        {"name": "http_post_exfil", "stealth": "medium", "detection_risk": 0.5, "tools": ["curl"]},
        {"name": "dns_tunnel_exfil", "stealth": "high", "detection_risk": 0.3, "tools": ["dnscat2"]},
        {"name": "icmp_tunnel_exfil", "stealth": "high", "detection_risk": 0.25, "tools": ["ptunnel"]},
        {"name": "smb_share_exfil", "stealth": "medium", "detection_risk": 0.6, "tools": ["smbclient"]},
        {"name": "cloud_upload_exfil", "stealth": "high", "detection_risk": 0.2, "tools": ["awscli"]},
        {"name": "steganography_exfil", "stealth": "high", "detection_risk": 0.1, "tools": ["steghide"]},
    ],
    "persistence": [
        {"name": "ssh_key_plant", "stealth": "high", "detection_risk": 0.2, "tools": ["ssh-keygen"]},
        {"name": "cron_job_backdoor", "stealth": "high", "detection_risk": 0.15, "tools": ["crontab"]},
        {"name": "systemd_service_hook", "stealth": "high", "detection_risk": 0.2, "tools": ["systemctl"]},
        {"name": "web_shell_plant", "stealth": "medium", "detection_risk": 0.4, "tools": ["manual"]},
        {"name": "startup_registry_key", "stealth": "medium", "detection_risk": 0.5, "tools": ["reg"]},
        {"name": "wmi_event_subscription", "stealth": "high", "detection_risk": 0.3, "tools": ["wmic"]},
    ],
}

# Blue Team defenses catalogued by capability tier.
_BLUE_DEFENSES: Dict[str, List[Dict[str, Any]]] = {
    "network_ids": [
        {"name": "snort_default", "effectiveness": 0.4, "false_positive_rate": 0.15, "rules": "community"},
        {"name": "snort_custom", "effectiveness": 0.55, "false_positive_rate": 0.10, "rules": "custom_tuned"},
        {"name": "snort_emerging", "effectiveness": 0.6, "false_positive_rate": 0.08, "rules": "emerging_threats"},
        {"name": "suricata_default", "effectiveness": 0.5, "false_positive_rate": 0.12, "rules": "et_open"},
        {"name": "suricata_custom", "effectiveness": 0.65, "false_positive_rate": 0.07, "rules": "custom_tuned"},
        {"name": "suricata_ml", "effectiveness": 0.75, "false_positive_rate": 0.05, "rules": "ml_augmented"},
    ],
    "host_ids": [
        {"name": "wazuh_default", "effectiveness": 0.45, "false_positive_rate": 0.12},
        {"name": "wazuh_custom", "effectiveness": 0.55, "false_positive_rate": 0.08},
        {"name": "ossec_default", "effectiveness": 0.4, "false_positive_rate": 0.15},
        {"name": "ossec_custom", "effectiveness": 0.5, "false_positive_rate": 0.10},
    ],
    "endpoint": [
        {"name": "windows_defender", "effectiveness": 0.5, "false_positive_rate": 0.1},
        {"name": "windows_defender_atp", "effectiveness": 0.7, "false_positive_rate": 0.05},
        {"name": "crowdstrike_falcon", "effectiveness": 0.85, "false_positive_rate": 0.03},
        {"name": "sentinelone", "effectiveness": 0.8, "false_positive_rate": 0.04},
        {"name": "carbon_black", "effectiveness": 0.75, "false_positive_rate": 0.05},
    ],
    "waf": [
        {"name": "modsecurity_default", "effectiveness": 0.5, "false_positive_rate": 0.15},
        {"name": "modsecurity_owasp_crs", "effectiveness": 0.65, "false_positive_rate": 0.08},
        {"name": "cloudflare_waf", "effectiveness": 0.7, "false_positive_rate": 0.05},
        {"name": "aws_waf_managed", "effectiveness": 0.65, "false_positive_rate": 0.06},
    ],
    "siem": [
        {"name": "splunk_default", "effectiveness": 0.5, "false_positive_rate": 0.12},
        {"name": "splunk_custom_detections", "effectiveness": 0.7, "false_positive_rate": 0.06},
        {"name": "elastic_security", "effectiveness": 0.6, "false_positive_rate": 0.08},
        {"name": "wazuh_siem", "effectiveness": 0.55, "false_positive_rate": 0.10},
    ],
    "response": [
        {"name": "auto_block_ip", "effectiveness": 0.5, "response_time_s": 10},
        {"name": "auto_isolate_host", "effectiveness": 0.7, "response_time_s": 30},
        {"name": "auto_kill_session", "effectiveness": 0.6, "response_time_s": 5},
        {"name": "auto_rotate_credentials", "effectiveness": 0.8, "response_time_s": 60},
        {"name": "auto_deploy_honeypot", "effectiveness": 0.4, "response_time_s": 120},
    ],
}


# ═══════════════════════════════════════════════════════════════════════════════
# Engagement simulator
# ═══════════════════════════════════════════════════════════════════════════════


class EngagementSimulator:
    """Simulates the mechanics of a single Red vs Blue engagement.

    Does NOT execute real exploits. Models detection probability, stealth
    ratings, defense effectiveness, and adaptation loops as a stochastic
    game between Red and Blue agents.
    """

    def __init__(self, seed: Optional[int] = None):
        self._rng = random.Random(seed)
        self._technique_cooldowns: Dict[str, int] = defaultdict(int)

    def simulate(
        self,
        scenario: Dict[str, Any],
        red_techniques: List[Dict[str, Any]],
        blue_defenses: List[Dict[str, Any]],
        round_number: int,
        red_experience: float = 0.5,
        blue_experience: float = 0.5,
    ) -> EngagementResult:
        """Run one engagement simulation.

        Args:
            scenario: The loaded scenario dict.
            red_techniques: List of technique dicts Red will attempt.
            blue_defenses: List of defense dicts Blue has deployed.
            round_number: Which round in the campaign this is.
            red_experience: Red's current skill multiplier (0.0-1.0, higher = better).
            blue_experience: Blue's current skill multiplier (0.0-1.0, higher = better).

        Returns:
            EngagementResult with full outcome details.
        """
        engagement_id = f"eng_{uuid.uuid4().hex[:12]}"
        start_time = time.time()

        scenario_defenses = scenario.get("defenses", {})
        scenario_difficulty = scenario.get("difficulty", "intermediate")

        # Base difficulty modifiers from scenario
        difficulty_modifiers = {
            "beginner": 1.3,     # Easier for Red
            "intermediate": 1.0,  # Neutral
            "advanced": 0.75,     # Harder for Red
            "expert": 0.5,        # Much harder for Red
        }
        difficulty_mod = difficulty_modifiers.get(scenario_difficulty, 1.0)

        # ── Phase 1: Red executes techniques ──
        succeeded_techniques: List[str] = []
        detected_techniques: List[str] = []
        blocked_techniques: List[str] = []
        techniques_used: List[str] = []
        threat_level = 0

        for tech in red_techniques:
            tech_name = tech["name"]
            techniques_used.append(tech_name)

            # Apply cooldown penalty (overusing the same technique)
            cooldown_penalty = min(0.3, self._technique_cooldowns.get(tech_name, 0) * 0.05)

            # Red success probability
            stealth_bonus = {"low": 0.0, "medium": 0.15, "high": 0.30}.get(
                tech.get("stealth", "medium"), 0.15
            )
            base_success = 0.5 + (red_experience * 0.2) + stealth_bonus - cooldown_penalty
            base_success *= difficulty_mod
            base_success = max(0.05, min(base_success, 0.95))

            # Check if technique succeeds
            if self._rng.random() < base_success:
                succeeded_techniques.append(tech_name)
                threat_level += self._rng.randint(5, 20)

            # ── Phase 2: Blue detection check ──
            detection_risk = tech.get("detection_risk", 0.5)
            # Blue experience improves detection
            blue_detection_mod = 1.0 + (blue_experience * 0.3)

            # Check each defense layer
            best_detection = 0.0
            for defense in blue_defenses:
                def_eff = defense.get("effectiveness", 0.5)
                detection_prob = detection_risk * def_eff * blue_detection_mod
                detection_prob = max(0.02, min(detection_prob, 0.95))

                # Apply scenario-specific defense bonuses
                if scenario_defenses.get("ids") and defense["name"].startswith(("snort", "suricata")):
                    detection_prob *= 1.2
                if scenario_defenses.get("edr") and defense.get("name", "") in (
                    "windows_defender_atp", "crowdstrike_falcon", "sentinelone", "carbon_black"
                ):
                    detection_prob *= 1.25
                if scenario_defenses.get("waf") and defense["name"].startswith(("modsecurity", "cloudflare")):
                    detection_prob *= 1.2
                if scenario_defenses.get("logging") in ("extensive", "siem") and defense["name"].startswith(
                    ("splunk", "elastic", "wazuh_siem")
                ):
                    detection_prob *= 1.15

                if detection_prob > best_detection:
                    best_detection = detection_prob

                if self._rng.random() < detection_prob:
                    detected_techniques.append(tech_name)
                    threat_level += self._rng.randint(10, 30)
                    break  # Detected by this layer

            # ── Phase 3: Blue blocks ──
            if tech_name in detected_techniques:
                for defense in blue_defenses:
                    if "block" in defense.get("name", "") or "isolate" in defense.get("name", ""):
                        block_prob = defense.get("effectiveness", 0.5) * blue_experience
                        if self._rng.random() < block_prob:
                            blocked_techniques.append(tech_name)
                            # If blocked after success, revoke the success
                            if tech_name in succeeded_techniques:
                                succeeded_techniques.remove(tech_name)
                            break

            # Update cooldown
            self._technique_cooldowns[tech_name] = (
                self._technique_cooldowns.get(tech_name, 0) + 1
            )

        # Decay cooldowns for unused techniques
        for key in list(self._technique_cooldowns.keys()):
            if key not in techniques_used:
                self._technique_cooldowns[key] = max(0, self._technique_cooldowns[key] - 1)
                if self._technique_cooldowns[key] == 0:
                    del self._technique_cooldowns[key]

        # ── Phase 4: Blue response actions ──
        response_actions: List[str] = []
        for defense in blue_defenses:
            if defense.get("response_time_s", 999) < 60 and threat_level > 30:
                resp_prob = defense.get("effectiveness", 0.5) * (threat_level / 100.0)
                if self._rng.random() < resp_prob:
                    action_name = defense.get("name", "unknown_response")
                    response_actions.append(action_name)

        # ── Phase 5: Scoring ──
        red_objective_achieved = len(succeeded_techniques) >= max(1, len(red_techniques) // 2)
        flags_captured = red_objective_achieved and len(succeeded_techniques) >= 3

        # Red score: success + stealth - detections - blocks
        score_red = (
            (len(succeeded_techniques) / max(len(red_techniques), 1)) * 60.0
            + (flags_captured * 20.0)
            + (red_experience * 10.0)
            - (len(detected_techniques) / max(len(red_techniques), 1)) * 20.0
            - (len(blocked_techniques) / max(len(red_techniques), 1)) * 20.0
        )
        score_red = max(0.0, min(score_red, 100.0))

        # Blue score: detections + blocks + response
        score_blue = (
            (len(detected_techniques) / max(len(red_techniques), 1)) * 40.0
            + (len(blocked_techniques) / max(len(red_techniques), 1)) * 30.0
            + (len(response_actions) / max(len(blue_defenses), 1)) * 20.0
            + (blue_experience * 10.0)
        )
        score_blue = max(0.0, min(score_blue, 100.0))

        # ── Phase 6: Lessons learned ──
        lessons: List[str] = []
        if detected_techniques and not succeeded_techniques:
            lessons.append("All Red techniques detected before success — increase stealth")
        if len(blocked_techniques) > len(detected_techniques) // 2:
            lessons.append("Blue blocking highly effective — diversify attack vectors")
        red_technique_names = {t["name"] for t in red_techniques}
        unsuccessful = red_technique_names - set(succeeded_techniques) - set(blocked_techniques)
        if unsuccessful:
            lessons.append(f"Techniques failed silently: {', '.join(sorted(unsuccessful)[:3])}")
        if not detected_techniques and succeeded_techniques:
            lessons.append("Red operated fully undetected — Blue needs better detection rules")
        if flags_captured:
            lessons.append("Red captured flags — Blue needs faster incident response")
        if threat_level > 80:
            lessons.append("Threat level peaked high — Blue SIEM/alerting needs tuning")

        # Adaptation notes
        red_adaptation = None
        blue_adaptation = None
        if len(detected_techniques) > len(succeeded_techniques):
            red_adaptation = f"Switch to higher-stealth variants after {len(detected_techniques)} detections"
        if len(succeeded_techniques) >= 3 and len(detected_techniques) < 2:
            blue_adaptation = f"Tune detection rules — {len(succeeded_techniques)} techniques evaded detection"

        duration = time.time() - start_time

        return EngagementResult(
            engagement_id=engagement_id,
            scenario_name=scenario.get("name", "unknown"),
            round_number=round_number,
            red_success=red_objective_achieved,
            red_techniques_used=techniques_used,
            red_techniques_succeeded=succeeded_techniques,
            blue_detections=detected_techniques,
            blue_blocks=blocked_techniques,
            blue_response_actions=response_actions,
            red_adaptation=red_adaptation,
            blue_adaptation=blue_adaptation,
            duration_seconds=round(duration, 3),
            threat_level_peak=min(threat_level, 100),
            score_red=round(score_red, 2),
            score_blue=round(score_blue, 2),
            lessons_learned=lessons,
        )


# ═══════════════════════════════════════════════════════════════════════════════
# Training Dojo
# ═══════════════════════════════════════════════════════════════════════════════


class TrainingDojo:
    """Red Team vs Blue Team autonomous training environment.

    Runs 1000+ simulated engagements where Red Team agents attack vulnerable
    VM scenarios and Blue Team agents defend. Both sides analyse results after
    each engagement, evolving their tactics over time.

    Usage::

        dojo = TrainingDojo(hive_mind=hive, db=phantomstrike_db)
        dojo.load_scenario("metasploitable2")
        campaign = dojo.run_training_campaign(scenario_count=100)
        stats = dojo.get_improvement_stats()
        techniques = dojo.export_learned_techniques()
    """

    # Campaign defaults
    DEFAULT_ENGAGEMENT_ROUNDS = 10
    DEFAULT_SCENARIO_COUNT = 100
    ROLLING_WINDOW_SIZE = 50  # last N engagements for trend calculation

    def __init__(self, hive_mind=None, db=None):
        """Initialize the Training Dojo.

        Args:
            hive_mind: Optional HiveMind instance for shared knowledge.
            db: Optional PhantomStrikeDB instance for agent_learnings persistence.
        """
        self.hive_mind = hive_mind
        self.db = db
        self._lock = threading.RLock()
        self._simulator = EngagementSimulator()

        # Loaded scenarios
        self._scenarios: Dict[str, Dict[str, Any]] = {}
        self._custom_scenarios: Dict[str, Dict[str, Any]] = {}

        # Campaign state
        self._active_campaign: Optional[CampaignStats] = None
        self._results: List[EngagementResult] = []
        self._red_experience: float = 0.3   # Starts low, improves
        self._blue_experience: float = 0.3   # Starts low, improves
        self._red_mutations: Dict[str, int] = defaultdict(int)  # technique -> mutation count
        self._blue_rule_iterations: int = 0

        # Technique evolution tracking
        self._technique_pool: Dict[str, List[Dict[str, Any]]] = copy.deepcopy(_RED_TECHNIQUES)
        self._defense_pool: Dict[str, List[Dict[str, Any]]] = copy.deepcopy(_BLUE_DEFENSES)

        logger.info("TrainingDojo initialized (%d scenarios, %d technique families)",
                     len(_SCENARIO_TEMPLATES), len(_RED_TECHNIQUES))

    # ═══════════════════════════════════════════════════════════════════════════
    # Scenario management
    # ═══════════════════════════════════════════════════════════════════════════

    def load_scenario(self, target_spec: dict) -> dict:
        """Load a training scenario from a VulnHub/HTB-style VM config.

        Args:
            target_spec: Can be:
                - A string key matching a built-in template (e.g., "metasploitable2")
                - A dict with name, os, services, vulnerabilities, defenses, flags

        Returns:
            The loaded scenario dict (normalised format).

        Raises:
            ValueError: If the scenario key is unknown and no valid dict provided.
        """
        with self._lock:
            # String key — look up built-in template
            if isinstance(target_spec, str):
                key = target_spec.lower().replace(" ", "_")
                if key in _SCENARIO_TEMPLATES:
                    scenario = copy.deepcopy(_SCENARIO_TEMPLATES[key])
                elif key in self._custom_scenarios:
                    scenario = copy.deepcopy(self._custom_scenarios[key])
                else:
                    # Fuzzy match
                    for template_key, template in _SCENARIO_TEMPLATES.items():
                        if key in template_key or template_key in key:
                            scenario = copy.deepcopy(template)
                            logger.info("Fuzzy-matched scenario '%s' -> '%s'", key, template_key)
                            break
                    else:
                        raise ValueError(
                            f"Unknown scenario key: '{key}'. Available: {sorted(_SCENARIO_TEMPLATES.keys())}"
                        )

                self._scenarios[key] = scenario
                logger.info("Loaded built-in scenario: %s (%s, %d hosts)",
                            scenario["name"], scenario["difficulty"], scenario["hosts"])
                return scenario

            # Dict — register as custom scenario
            if isinstance(target_spec, dict):
                required = ["name", "services", "vulnerabilities"]
                for field in required:
                    if field not in target_spec:
                        raise ValueError(f"Custom scenario missing required field: '{field}'")

                scenario = {
                    "name": target_spec.get("name", "custom"),
                    "difficulty": target_spec.get("difficulty", "intermediate"),
                    "os": target_spec.get("os", "linux"),
                    "hosts": target_spec.get("hosts", 1),
                    "services": target_spec["services"],
                    "vulnerabilities": target_spec["vulnerabilities"],
                    "defenses": target_spec.get("defenses", {}),
                    "flags": target_spec.get("flags", ["/root/flag.txt"]),
                    "estimated_duration_minutes": target_spec.get("estimated_duration_minutes", 60),
                }

                scenario_key = scenario["name"].lower().replace(" ", "_")
                self._custom_scenarios[scenario_key] = scenario
                self._scenarios[scenario_key] = scenario
                logger.info("Registered custom scenario: %s (%s, %d hosts)",
                            scenario["name"], scenario["difficulty"], scenario["hosts"])
                return scenario

            raise ValueError(f"target_spec must be str or dict, got {type(target_spec)}")

    def list_scenarios(self) -> List[Dict[str, Any]]:
        """List all available scenarios (built-in + custom).

        Returns:
            List of scenario summaries.
        """
        with self._lock:
            all_scenarios = {**_SCENARIO_TEMPLATES, **self._custom_scenarios}
            return [
                {
                    "key": key,
                    "name": s["name"],
                    "difficulty": s["difficulty"],
                    "os": s["os"],
                    "hosts": s["hosts"],
                    "services_count": len(s["services"]),
                    "vuln_count": len(s["vulnerabilities"]),
                    "estimated_minutes": s.get("estimated_duration_minutes", 60),
                }
                for key, s in sorted(all_scenarios.items(), key=lambda kv: kv[1]["difficulty"])
            ]

    # ═══════════════════════════════════════════════════════════════════════════
    # Engagement execution
    # ═══════════════════════════════════════════════════════════════════════════

    def run_engagement(
        self,
        red_agents: list,
        blue_agents: list,
        scenario: dict,
        rounds: int = 10,
    ) -> dict:
        """Run a single Red vs Blue engagement. Red attacks, Blue defends. Both learn.

        Args:
            red_agents: List of Red agent identifiers/configs (e.g., ["recon", "exploit"]).
            blue_agents: List of Blue defense identifiers (e.g., ["snort_custom", "wazuh_default"]).
            scenario: Loaded scenario dict (from load_scenario()).
            rounds: Number of engagement rounds (attack/defend cycles).

        Returns:
            Dict with engagement_id, results, scores, and lessons learned.
        """
        # Normalize inputs
        red_agent_list = self._normalize_agent_list(red_agents)
        blue_agent_list = self._normalize_agent_list(blue_agents)

        # Select techniques from Red's pool based on agent types
        red_techniques = self._select_red_techniques(red_agent_list, scenario)
        if not red_techniques:
            return {
                "success": False,
                "error": "No Red techniques available for the given agent types",
                "red_agents": red_agent_list,
                "blue_agents": blue_agent_list,
            }

        # Select defenses from Blue's pool based on agent types
        blue_defenses = self._select_blue_defenses(blue_agent_list, scenario)

        # Run the engagement
        result = self._simulator.simulate(
            scenario=scenario,
            red_techniques=red_techniques,
            blue_defenses=blue_defenses,
            round_number=self._get_next_round_number(),
            red_experience=self._red_experience,
            blue_experience=self._blue_experience,
        )

        # Store result
        with self._lock:
            self._results.append(result)

        # Update experience based on outcome
        self._update_experience(result)

        # Log to HiveMind if available
        if self.hive_mind:
            try:
                self.hive_mind.add_finding({
                    "type": "training_engagement",
                    "engagement_id": result.engagement_id,
                    "scenario": result.scenario_name,
                    "red_success": result.red_success,
                    "score_red": result.score_red,
                    "score_blue": result.score_blue,
                }, agent="training_dojo")
            except Exception:
                pass

        logger.info(
            "Engagement %s | %s | Red: %.1f | Blue: %.1f | %s",
            result.engagement_id,
            result.scenario_name,
            result.score_red,
            result.score_blue,
            "RED WIN" if result.red_success else "BLUE WIN",
        )

        return {
            "engagement_id": result.engagement_id,
            "scenario": result.scenario_name,
            "round_number": result.round_number,
            "red_success": result.red_success,
            "red_techniques_used": result.red_techniques_used,
            "red_techniques_succeeded": result.red_techniques_succeeded,
            "blue_detections": result.blue_detections,
            "blue_blocks": result.blue_blocks,
            "score_red": result.score_red,
            "score_blue": result.score_blue,
            "threat_level_peak": result.threat_level_peak,
            "lessons_learned": result.lessons_learned,
            "duration_seconds": result.duration_seconds,
        }

    def run_engagement_pair(
        self,
        red_agents: list,
        blue_agents: list,
        scenario: dict,
        rounds: int = 10,
    ) -> EngagementResult:
        """Run engagement and return the full EngagementResult dataclass.

        Use this when you need structured access to all result fields.
        """
        summary = self.run_engagement(red_agents, blue_agents, scenario, rounds)
        # The full result is stored in self._results; return the last one
        with self._lock:
            if self._results:
                return self._results[-1]
        raise RuntimeError("No engagement result found after run_engagement")

    # ═══════════════════════════════════════════════════════════════════════════
    # Training campaigns
    # ═══════════════════════════════════════════════════════════════════════════

    def run_training_campaign(
        self,
        scenario_count: int = 100,
        scenario_keys: Optional[List[str]] = None,
        red_agent_groups: Optional[List[List[str]]] = None,
        blue_agent_groups: Optional[List[List[str]]] = None,
        max_rounds_per_engagement: int = 10,
        evolution_interval: int = 10,
        progress_callback: Optional[Callable[[int, int, CampaignStats], None]] = None,
    ) -> dict:
        """Run 100+ engagements. Track improvement over time.

        Red and Blue agents learn from each engagement. Every evolution_interval
        engagements, both sides mutate their techniques based on what they learned.

        Args:
            scenario_count: Number of engagements to run.
            scenario_keys: Optional list of scenario keys to rotate through.
                           If None, all available scenarios are used.
            red_agent_groups: Optional list of Red agent compositions to cycle.
            blue_agent_groups: Optional list of Blue defense compositions to cycle.
            max_rounds_per_engagement: Rounds per engagement.
            evolution_interval: How often agents evolve tactics.
            progress_callback: Optional callback(completed, total, stats) for progress.

        Returns:
            CampaignStats dict with full results.
        """
        campaign_id = f"campaign_{uuid.uuid4().hex[:12]}"
        start_time = time.time()

        with self._lock:
            self._active_campaign = CampaignStats(campaign_id=campaign_id)
            self._results.clear()

        # Resolve scenario pool
        if scenario_keys:
            scenario_pool = scenario_keys
        else:
            scenario_pool = list(_SCENARIO_TEMPLATES.keys())

        # Default Red/Blue agent groups
        if red_agent_groups is None:
            red_agent_groups = [
                ["recon", "exploit", "post_exploit"],
                ["recon", "web_exploit", "privesc", "exfil"],
                ["recon", "exploit", "lateral_move", "cred_access", "exfil"],
                ["recon_passive", "vuln", "exploit", "persistence", "exfil"],
                ["osint", "web_exploit", "privesc", "lateral_move", "cleanup"],
            ]
        if blue_agent_groups is None:
            blue_agent_groups = [
                ["snort_default", "wazuh_default"],
                ["suricata_custom", "wazuh_custom"],
                ["suricata_ml", "windows_defender_atp", "splunk_custom_detections"],
                ["snort_emerging", "crowdstrike_falcon", "elastic_security"],
                ["suricata_custom", "sentinelone", "modsecurity_owasp_crs", "splunk_custom"],
            ]

        logger.info(
            "Starting training campaign %s: %d engagements across %d scenarios",
            campaign_id, scenario_count, len(scenario_pool),
        )

        for engagement_idx in range(1, scenario_count + 1):
            # Rotate through scenarios
            scenario_key = scenario_pool[(engagement_idx - 1) % len(scenario_pool)]
            try:
                scenario = self.load_scenario(scenario_key)
            except ValueError:
                logger.warning("Skipping unknown scenario key: %s", scenario_key)
                continue

            # Rotate through agent compositions
            red_group = red_agent_groups[(engagement_idx - 1) % len(red_agent_groups)]
            blue_group = blue_agent_groups[(engagement_idx - 1) % len(blue_agent_groups)]

            # Adapt difficulty to current experience levels
            adapted_scenario = self._adapt_scenario_difficulty(scenario, engagement_idx, scenario_count)

            # Run engagement
            self.run_engagement(
                red_agents=red_group,
                blue_agents=blue_group,
                scenario=adapted_scenario,
                rounds=max_rounds_per_engagement,
            )

            # Update campaign stats
            with self._lock:
                campaign = self._active_campaign
                campaign.total_engagements = engagement_idx
                last_result = self._results[-1]

                if last_result.red_success:
                    campaign.red_wins += 1
                else:
                    # Was it a Blue win or a draw?
                    if last_result.score_blue > last_result.score_red + 20:
                        campaign.blue_wins += 1
                    else:
                        campaign.draws += 1

                # Rolling win rates (every 5 engagements)
                if engagement_idx % 5 == 0:
                    recent = self._results[-min(50, len(self._results)):]
                    red_wr = sum(1 for r in recent if r.red_success) / len(recent)
                    blue_dr = sum(len(r.blue_detections) for r in recent) / max(
                        sum(len(r.red_techniques_used) for r in recent), 1
                    )
                    campaign.red_win_rate_history.append(round(red_wr, 4))
                    campaign.blue_detection_rate_history.append(round(blue_dr, 4))

                # Update technique stats
                self._update_technique_stats(campaign, last_result)

            # Periodic evolution
            if engagement_idx % evolution_interval == 0:
                self._evolve_tactics(engagement_idx)

            # Progress callback
            if progress_callback:
                try:
                    with self._lock:
                        progress_callback(engagement_idx, scenario_count, self._active_campaign)
                except Exception:
                    pass

        # Campaign complete
        elapsed = time.time() - start_time
        with self._lock:
            campaign = self._active_campaign
            campaign.completed_at = datetime.now(timezone.utc).isoformat()
            campaign.total_duration_seconds = round(elapsed, 2)
            campaign.top_techniques = self._rank_top_techniques(campaign)
            campaign.novel_techniques_discovered = self._identify_novel_techniques(campaign)

        logger.info(
            "Campaign %s complete: %d engagements, Red wins=%d, Blue wins=%d, %.1fs",
            campaign_id, campaign.total_engagements, campaign.red_wins, campaign.blue_wins, elapsed,
        )

        return campaign.to_dict()

    # ═══════════════════════════════════════════════════════════════════════════
    # Improvement statistics
    # ═══════════════════════════════════════════════════════════════════════════

    def get_improvement_stats(self) -> dict:
        """Red success rate over time. Technique effectiveness evolution.

        Returns a comprehensive statistics dict with:
          - red_win_rate_trend: How Red's win rate changed over the campaign
          - technique_effectiveness: Per-technique success/detection/block rates
          - blue_detection_trend: How Blue's detection rate evolved
          - experience_curves: Red and Blue skill progression
          - most_improved_techniques: Techniques with the steepest improvement slope
          - most_degraded_techniques: Techniques Blue learned to counter
          - evolution_summary: How many mutations occurred
        """
        with self._lock:
            results = list(self._results)
            campaign = self._active_campaign

        if not results:
            return {"error": "No engagement results available. Run a campaign first."}

        total = len(results)

        # ── Red win rate trend ──
        window = min(self.ROLLING_WINDOW_SIZE, total)
        red_win_rates: List[float] = []
        for i in range(window, total + 1, max(1, total // 20)):
            window_results = results[max(0, i - window):i]
            wr = sum(1 for r in window_results if r.red_success) / len(window_results)
            red_win_rates.append(round(wr, 4))

        # ── Blue detection rate trend ──
        blue_detection_rates: List[float] = []
        for i in range(window, total + 1, max(1, total // 20)):
            window_results = results[max(0, i - window):i]
            total_techniques = sum(len(r.red_techniques_used) for r in window_results)
            total_detections = sum(len(r.blue_detections) for r in window_results)
            dr = total_detections / max(total_techniques, 1)
            blue_detection_rates.append(round(dr, 4))

        # ── Technique breakdown ──
        technique_stats: Dict[str, Dict[str, Any]] = {}
        if campaign:
            technique_stats = {
                name: stats.to_dict() for name, stats in campaign.technique_stats.items()
            }

        # ── Most improved / degraded ──
        if campaign:
            sorted_by_trend = sorted(
                campaign.technique_stats.items(),
                key=lambda kv: kv[1].effectiveness_trend,
                reverse=True,
            )
            most_improved = [
                {"technique": name, "trend": round(stats.effectiveness_trend, 4),
                 "success_rate": round(stats.success_rate, 4)}
                for name, stats in sorted_by_trend[:10] if stats.effectiveness_trend > 0
            ]
            most_degraded = [
                {"technique": name, "trend": round(stats.effectiveness_trend, 4),
                 "success_rate": round(stats.success_rate, 4)}
                for name, stats in sorted_by_trend[-10:] if stats.effectiveness_trend < 0
            ]
        else:
            most_improved = []
            most_degraded = []

        # ── Experience curves ──
        # Sample experience every 5% of the campaign
        sample_points = max(1, total // 20)
        exp_curve: List[Dict[str, Any]] = []
        for i in range(sample_points, total + 1, sample_points):
            slice_results = results[:i]
            red_successes = sum(1 for r in slice_results if r.red_success)
            red_wr = red_successes / len(slice_results)
            blue_detections = sum(len(r.blue_detections) for r in slice_results)
            blue_techniques = sum(len(r.red_techniques_used) for r in slice_results)
            blue_dr = blue_detections / max(blue_techniques, 1)
            exp_curve.append({
                "engagement": i,
                "red_win_rate": round(red_wr, 4),
                "blue_detection_rate": round(blue_dr, 4),
                "red_experience": round(self._red_experience, 4),
                "blue_experience": round(self._blue_experience, 4),
            })

        # ── Evolution summary ──
        evolution_summary = {
            "red_mutations": dict(self._red_mutations),
            "blue_rule_iterations": self._blue_rule_iterations,
            "total_techniques_in_pool": sum(len(v) for v in self._technique_pool.values()),
            "total_defenses_in_pool": sum(len(v) for v in self._defense_pool.values()),
        }

        return {
            "campaign_id": campaign.campaign_id if campaign else "none",
            "total_engagements": total,
            "red_final_win_rate": round(red_win_rates[-1], 4) if red_win_rates else 0,
            "blue_final_detection_rate": round(blue_detection_rates[-1], 4) if blue_detection_rates else 0,
            "red_experience": round(self._red_experience, 4),
            "blue_experience": round(self._blue_experience, 4),
            "red_win_rate_trend": red_win_rates,
            "blue_detection_rate_trend": blue_detection_rates,
            "technique_stats": technique_stats,
            "most_improved_techniques": most_improved,
            "most_degraded_techniques": most_degraded,
            "experience_curve": exp_curve,
            "evolution_summary": evolution_summary,
        }

    # ═══════════════════════════════════════════════════════════════════════════
    # Learned technique export
    # ═══════════════════════════════════════════════════════════════════════════

    def export_learned_techniques(self) -> list:
        """Export newly discovered techniques to agent_learnings table.

        Collects all techniques that showed improvement, novel mutations,
        and evolved variants. Writes them to the agent_learnings DB table
        for cross-mission use. Techniques that degraded are also exported
        with a degraded flag so future missions can deprioritize them.

        Returns:
            List of exported technique dicts with technique name, stats, and DB status.
        """
        with self._lock:
            campaign = self._active_campaign
            results = list(self._results)

        if not campaign or not campaign.technique_stats:
            logger.warning("No campaign data to export. Run a training campaign first.")
            return []

        exported: List[Dict[str, Any]] = []
        now = datetime.now(timezone.utc).isoformat()

        for tech_name, stats in campaign.technique_stats.items():
            # Only export techniques with meaningful data
            if stats.attempts < 5:
                continue

            entry = {
                "technique": tech_name,
                "attempts": stats.attempts,
                "successes": stats.successes,
                "success_rate": round(stats.success_rate, 4),
                "detection_rate": round(stats.detection_rate, 4),
                "block_rate": round(stats.block_rate, 4),
                "effectiveness_trend": round(stats.effectiveness_trend, 4),
                "evolution_generations": stats.evolution_generations,
                "is_novel": tech_name in (campaign.novel_techniques_discovered or []),
                "is_degraded": stats.effectiveness_trend < -0.1,
                "exported_at": now,
            }

            # Persist to agent_learnings DB
            if self.db:
                try:
                    self._persist_technique_to_db(stats, entry)
                    entry["db_status"] = "persisted"
                except Exception as exc:
                    logger.error("Failed to persist technique '%s': %s", tech_name, exc)
                    entry["db_status"] = f"failed: {exc}"
            else:
                entry["db_status"] = "no_db"

            exported.append(entry)

        # Sort: novel techniques first, then by success rate descending
        exported.sort(key=lambda e: (not e["is_novel"], -e["success_rate"]))

        logger.info("Exported %d learned techniques to agent_learnings", len(exported))

        # Publish to HiveMind if available
        if self.hive_mind:
            try:
                self.hive_mind.add_finding({
                    "type": "techniques_exported",
                    "count": len(exported),
                    "novel_count": sum(1 for e in exported if e["is_novel"]),
                    "top_techniques": [e["technique"] for e in exported[:10]],
                }, agent="training_dojo")
            except Exception:
                pass

        return exported

    def get_top_techniques(self, limit: int = 20) -> list:
        """Get the top-N most effective techniques from the current campaign.

        Args:
            limit: Maximum number of techniques to return.

        Returns:
            List of technique dicts sorted by success rate descending.
        """
        with self._lock:
            campaign = self._active_campaign

        if not campaign or not campaign.technique_stats:
            return []

        sorted_techs = sorted(
            campaign.technique_stats.items(),
            key=lambda kv: (kv[1].success_rate, kv[1].attempts),
            reverse=True,
        )

        return [
            {
                "technique": name,
                "success_rate": round(stats.success_rate, 4),
                "attempts": stats.attempts,
                "successes": stats.successes,
                "detection_rate": round(stats.detection_rate, 4),
                "effectiveness_trend": round(stats.effectiveness_trend, 4),
                "evolution_generations": stats.evolution_generations,
            }
            for name, stats in sorted_techs[:limit]
        ]

    # ═══════════════════════════════════════════════════════════════════════════
    # Attack path simulation (dry-run / no execution)
    # ═══════════════════════════════════════════════════════════════════════════

    def simulate_attack_path(self, path: list, target: dict) -> dict:
        """Simulate an attack path against a virtual target without executing it.

        Each step in the path is evaluated against the target's defenses to
        produce a probabilistic outcome. No actual exploits are run.

        Args:
            path: List of attack steps. Each step is a dict with at minimum:
                  {"technique": "sqli_union", "target_service": "http", "stealth": "medium"}
            target: Target dict (same format as a loaded scenario).

        Returns:
            Dict with per-step outcomes, overall success probability, and
            detection risk assessment.
        """
        if not path:
            return {"success": False, "error": "Empty attack path", "steps": []}

        target_defenses = target.get("defenses", {})
        target_difficulty = target.get("difficulty", "intermediate")

        difficulty_mod = {
            "beginner": 1.2, "intermediate": 1.0, "advanced": 0.8, "expert": 0.6,
        }.get(target_difficulty, 1.0)

        steps: List[Dict[str, Any]] = []
        cumulative_detection_risk = 0.0
        threat_level = 0

        for idx, step in enumerate(path):
            technique = step.get("technique", "unknown")
            stealth = step.get("stealth", "medium")
            target_service = step.get("target_service", "unknown")

            # Look up this technique in the catalog
            tech_info = self._find_technique_info(technique)

            # Base success probability
            stealth_bonus = {"low": 0.0, "medium": 0.15, "high": 0.30}.get(stealth, 0.15)
            base_success = 0.5 + stealth_bonus + (self._red_experience * 0.1)
            base_success *= difficulty_mod
            base_success = max(0.05, min(base_success, 0.95))

            # Detection risk per step
            detection_risk = tech_info.get("detection_risk", 0.5) if tech_info else 0.5
            if target_defenses.get("ids"):
                detection_risk *= 1.2
            if target_defenses.get("edr") and target.get("os") == "windows":
                detection_risk *= 1.25
            if target_defenses.get("waf") and target_service in ("http", "https"):
                detection_risk *= 1.2
            if target_defenses.get("logging") in ("extensive", "siem"):
                detection_risk *= 1.1

            # Cumulative risk (non-linear — each step increases overall exposure)
            cumulative_detection_risk = 1.0 - (1.0 - cumulative_detection_risk) * (1.0 - detection_risk * 0.5)

            # Step outcome
            success_roll = self._simulator._rng.random() if self._simulator else random.random()
            step_success = success_roll < base_success

            if step_success:
                threat_level += random.randint(5, 20)

            # Defense response simulation
            defense_response = None
            if cumulative_detection_risk > 0.5 and target_defenses:
                resp_prob = cumulative_detection_risk * 0.6
                if self._simulator:
                    triggered = self._simulator._rng.random() < resp_prob
                else:
                    triggered = random.random() < resp_prob
                if triggered:
                    defense_response = self._simulate_defense_response(target_defenses, threat_level)

            steps.append({
                "step": idx + 1,
                "technique": technique,
                "target_service": target_service,
                "stealth": stealth,
                "success_probability": round(base_success, 4),
                "simulated_outcome": "success" if step_success else "failed",
                "detection_risk_this_step": round(detection_risk, 4),
                "cumulative_detection_risk": round(cumulative_detection_risk, 4),
                "threat_level": min(threat_level, 100),
                "defense_response": defense_response,
            })

            if defense_response and defense_response.get("blocks_further_progress"):
                steps[-1]["outcome_note"] = "Defense blocked further progress"
                break

        # Overall assessment
        step_successes = sum(1 for s in steps if s["simulated_outcome"] == "success")
        overall_success_prob = step_successes / len(steps) if steps else 0.0
        flags_likely = overall_success_prob > 0.5 and step_successes >= 3

        # Recommendations
        recommendations: List[str] = []
        if cumulative_detection_risk > 0.6:
            recommendations.append("High cumulative detection risk — stagger attack timing")
        if any(s.get("defense_response") and s["defense_response"].get("blocks_further_progress") for s in steps):
            recommendations.append("Defense will likely block mid-path — prepare alternative vectors")
        high_risk_steps = [s for s in steps if s["detection_risk_this_step"] > 0.6]
        if high_risk_steps:
            names = [s["technique"] for s in high_risk_steps]
            recommendations.append(f"High-risk steps: {', '.join(names)} — upgrade stealth or use alternatives")

        return {
            "target": target.get("name", "unknown"),
            "path_length": len(path),
            "steps": steps,
            "overall_success_probability": round(overall_success_prob, 4),
            "flags_likely_captured": flags_likely,
            "cumulative_detection_risk": round(cumulative_detection_risk, 4),
            "peak_threat_level": min(threat_level, 100),
            "recommendations": recommendations,
        }

    # ═══════════════════════════════════════════════════════════════════════════
    # Internal: agent/technique selection
    # ═══════════════════════════════════════════════════════════════════════════

    @staticmethod
    def _normalize_agent_list(agents: list) -> List[str]:
        """Normalize a list of agent identifiers to strings."""
        result: List[str] = []
        for agent in agents:
            if isinstance(agent, str):
                result.append(agent)
            elif isinstance(agent, dict):
                result.append(agent.get("type", agent.get("name", "unknown")))
            else:
                result.append(str(agent))
        return result

    def _select_red_techniques(
        self, agent_types: List[str], scenario: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Select Red techniques based on agent types and scenario.

        Maps agent type strings to technique categories, then picks techniques
        appropriate to the target scenario's OS, services, and vulnerabilities.
        """
        agent_category_map: Dict[str, List[str]] = {
            "recon": ["recon"],
            "recon_passive": ["recon"],
            "recon_active": ["recon"],
            "osint": ["recon"],
            "vuln": ["recon"],
            "exploit": ["exploitation"],
            "web_exploit": ["exploitation"],
            "exploitation": ["exploitation"],
            "post_exploit": ["post_exploitation"],
            "post_exploitation": ["post_exploitation"],
            "privesc": ["post_exploitation"],
            "lateral_move": ["lateral_movement"],
            "lateral_movement": ["lateral_movement"],
            "cred_access": ["lateral_movement"],
            "exfil": ["exfiltration"],
            "exfiltration": ["exfiltration"],
            "persistence": ["persistence"],
            "cleanup": ["exfiltration"],
        }

        selected: List[Dict[str, Any]] = []
        seen: Set[str] = set()

        # OS-specific technique filtering
        target_os = scenario.get("os", "linux")
        target_services = {s.get("service", "").lower() for s in scenario.get("services", [])}
        target_vulns = scenario.get("vulnerabilities", [])

        for agent_type in agent_types:
            categories = agent_category_map.get(agent_type, ["exploitation"])
            for category in categories:
                techniques = self._technique_pool.get(category, [])
                for tech in techniques:
                    if tech["name"] in seen:
                        continue

                    # Filter by scenario applicability
                    if not self._technique_applies_to_scenario(tech, target_os, target_services, target_vulns):
                        continue

                    # Add some randomness — not every technique every time
                    if random.random() < 0.7:
                        selected.append(tech)
                        seen.add(tech["name"])

        # Guarantee at least 2 techniques if any are available
        if not selected:
            for category in ["recon", "exploitation"]:
                techniques = self._technique_pool.get(category, [])
                for tech in techniques:
                    if tech["name"] not in seen:
                        selected.append(tech)
                        seen.add(tech["name"])
                        if len(selected) >= 3:
                            break
                if len(selected) >= 2:
                    break

        return selected

    @staticmethod
    def _technique_applies_to_scenario(
        technique: Dict[str, Any],
        target_os: str,
        target_services: Set[str],
        target_vulns: List[Dict[str, Any]],
    ) -> bool:
        """Check if a technique is applicable to the given scenario."""
        name = technique["name"]

        # OS-specific filtering
        linux_only = {"linpeas_enum", "sudo_abuse", "suid_exploit", "cron_hijack",
                       "capability_abuse", "ssh_key_plant", "cron_job_backdoor",
                       "systemd_service_hook", "docker_escape", "lxc_container_breakout"}
        windows_only = {"winpeas_enum", "pass_the_hash", "pass_the_ticket", "kerberoasting",
                         "asreproasting", "dcsync", "wmi_exec", "psexec",
                         "startup_registry_key", "wmi_event_subscription"}

        if name in linux_only and target_os == "windows":
            return False
        if name in windows_only and target_os == "linux":
            return False

        # Service-requiring techniques
        web_techniques = {"sqli_union", "sqli_blind", "sqli_time_based", "xss_reflected",
                           "xss_stored", "command_injection", "file_inclusion_lfi",
                           "file_upload_webshell", "ssrf_internal_probe", "template_injection_ssti",
                           "http_dirbust", "web_shell_plant"}
        smb_techniques = {"pass_the_hash", "psexec", "smb_share_exfil"}
        ssh_techniques = {"ssh_agent_forward", "ssh_credential_reuse", "ssh_key_plant"}

        if name in web_techniques and not (target_services & {"http", "https", "http-proxy"}):
            return False
        if name in smb_techniques and "smb" not in target_services:
            return False
        if name in ssh_techniques and "ssh" not in target_services:
            return False

        # Vulnerability-matching techniques
        vuln_related_techs = {
            "sqli_union": ["sqli", "sql injection"],
            "sqli_blind": ["sqli", "sql injection"],
            "sqli_time_based": ["sqli", "sql injection"],
            "xss_reflected": ["xss", "cross-site"],
            "xss_stored": ["xss", "cross-site"],
            "command_injection": ["command_injection", "rce", "command injection"],
            "file_inclusion_lfi": ["lfi", "file inclusion", "path traversal"],
            "file_upload_webshell": ["upload", "unrestricted"],
            "buffer_overflow": ["buffer_overflow", "buffer overflow"],
            "deserialization_attack": ["deserialization", "insecure deserialization"],
            "ssrf_internal_probe": ["ssrf"],
            "template_injection_ssti": ["ssti", "template injection"],
            "kernel_exploit": ["privilege_escalation", "kernel"],
            "docker_escape": ["container", "docker"],
        }

        if name in vuln_related_techs:
            relevant_keywords = vuln_related_techs[name]
            has_matching_vuln = any(
                any(kw in v.get("type", "").lower() or kw in v.get("service", "").lower()
                    for kw in relevant_keywords)
                for v in target_vulns
            )
            if target_vulns and not has_matching_vuln:
                return False  # Technique has no matching vulnerability in this scenario

        return True

    def _select_blue_defenses(
        self, agent_types: List[str], scenario: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Select Blue defenses based on agent types and scenario defenses."""
        selected: List[Dict[str, Any]] = []
        scenario_defenses = scenario.get("defenses", {})

        # Map agent types to defense categories
        for agent_type in agent_types:
            if agent_type in ("snort_default", "snort_custom", "snort_emerging",
                               "suricata_default", "suricata_custom", "suricata_ml"):
                for defense in self._defense_pool.get("network_ids", []):
                    if defense["name"] == agent_type:
                        selected.append(defense)
            elif agent_type in ("wazuh_default", "wazuh_custom", "ossec_default", "ossec_custom"):
                for defense in self._defense_pool.get("host_ids", []):
                    if defense["name"] == agent_type:
                        selected.append(defense)
            elif agent_type in ("windows_defender", "windows_defender_atp", "crowdstrike_falcon",
                                 "sentinelone", "carbon_black"):
                for defense in self._defense_pool.get("endpoint", []):
                    if defense["name"] == agent_type:
                        selected.append(defense)
            elif agent_type in ("modsecurity_default", "modsecurity_owasp_crs",
                                 "cloudflare_waf", "aws_waf_managed"):
                for defense in self._defense_pool.get("waf", []):
                    if defense["name"] == agent_type:
                        selected.append(defense)
            elif agent_type in ("splunk_default", "splunk_custom_detections",
                                 "elastic_security", "wazuh_siem"):
                for defense in self._defense_pool.get("siem", []):
                    if defense["name"] == agent_type:
                        selected.append(defense)

        # If no specific defenses matched, pick based on scenario's defense posture
        if not selected:
            if scenario_defenses.get("ids"):
                selected.extend(self._defense_pool.get("network_ids", [])[:1])
            if scenario_defenses.get("edr"):
                selected.extend(self._defense_pool.get("endpoint", [])[:1])
            if scenario_defenses.get("waf"):
                selected.extend(self._defense_pool.get("waf", [])[:1])
            if scenario_defenses.get("logging") in ("extensive", "siem"):
                selected.extend(self._defense_pool.get("siem", [])[:1])
            if not selected:
                # Default: at least basic network IDS
                selected.extend(self._defense_pool.get("network_ids", [])[:1])

        return selected

    # ═══════════════════════════════════════════════════════════════════════════
    # Internal: experience and evolution
    # ═══════════════════════════════════════════════════════════════════════════

    def _update_experience(self, result: EngagementResult) -> None:
        """Update Red and Blue experience based on engagement outcome."""
        with self._lock:
            # Red learns from both successes and failures
            if result.red_success:
                self._red_experience += 0.005
            else:
                self._red_experience += 0.002  # Learn slower from failures

            # Blue learns from detections
            detection_rate = len(result.blue_detections) / max(len(result.red_techniques_used), 1)
            block_rate = len(result.blue_blocks) / max(len(result.red_techniques_used), 1)
            self._blue_experience += (detection_rate * 0.003 + block_rate * 0.002)

            # Cap experience at 0.95 (never perfect)
            self._red_experience = min(self._red_experience, 0.95)
            self._blue_experience = min(self._blue_experience, 0.95)

    def _evolve_tactics(self, engagement_idx: int) -> None:
        """Evolve Red and Blue tactics based on recent engagement history.

        Red mutates techniques that have been getting detected.
        Blue improves rules that have been missing detections.
        """
        with self._lock:
            recent = self._results[-min(50, len(self._results)):]

        if len(recent) < 5:
            return

        # ── Red evolution: mutate frequently-detected techniques ──
        detection_counts: Dict[str, int] = defaultdict(int)
        success_counts: Dict[str, int] = defaultdict(int)
        for r in recent:
            for tech in r.red_techniques_used:
                success_counts[tech] += 1
            for tech in r.blue_detections:
                detection_counts[tech] += 1

        for tech_name, detections in detection_counts.items():
            total_uses = success_counts.get(tech_name, 1)
            detection_rate = detections / max(total_uses, 1)

            # If detected >50% of the time, try to mutate
            if detection_rate > 0.5 and total_uses >= 3:
                self._mutate_red_technique(tech_name)

        # ── Blue evolution: create new detection rules for undetected techniques ──
        undetected: Dict[str, int] = defaultdict(int)
        for r in recent:
            for tech in r.red_techniques_succeeded:
                if tech not in r.blue_detections:
                    undetected[tech] += 1

        for tech_name, count in undetected.items():
            if count >= 3:
                self._improve_blue_defense(tech_name)

        self._blue_rule_iterations += 1

        logger.info(
            "Evolution cycle at engagement %d: %d Red mutations, %d Blue rule improvements",
            engagement_idx, len([t for t, d in detection_counts.items() if d / max(success_counts[t], 1) > 0.5]),
            len(undetected),
        )

    def _mutate_red_technique(self, technique_name: str) -> None:
        """Create a mutated variant of a Red technique with higher stealth.

        The mutated version has slightly lower base effectiveness but
        significantly lower detection risk.
        """
        # Find the technique in the pool
        for category, techniques in self._technique_pool.items():
            for tech in techniques:
                if tech["name"] == technique_name:
                    # Already mutated too many times? Skip.
                    self._red_mutations[technique_name] += 1
                    gen = self._red_mutations[technique_name]
                    if gen > 5:
                        return

                    # Create evolved variant
                    mutated = copy.deepcopy(tech)
                    mutated["name"] = f"{technique_name}_evolved_v{gen}"
                    # Evolution: stealth improves, detection risk drops
                    stealth_levels = ["low", "medium", "high"]
                    current_idx = stealth_levels.index(tech.get("stealth", "medium"))
                    new_idx = min(current_idx + 1, 2)
                    mutated["stealth"] = stealth_levels[new_idx]
                    mutated["detection_risk"] = max(0.05, tech.get("detection_risk", 0.5) * 0.75)
                    mutated["evolved_from"] = technique_name
                    mutated["generation"] = gen

                    techniques.append(mutated)
                    logger.debug("Mutated technique %s -> %s (gen %d)", technique_name, mutated["name"], gen)
                    return

    def _improve_blue_defense(self, technique_name: str) -> None:
        """Create an improved Blue defense rule targeting a specific technique."""
        # Add specialized detection for this technique to the most relevant defense pool
        target_pool = self._defense_pool.get("network_ids")
        if not target_pool:
            return

        # Create a specialized rule
        specialized = {
            "name": f"custom_rule_{technique_name}_v{self._blue_rule_iterations}",
            "effectiveness": 0.65,
            "false_positive_rate": 0.06,
            "rules": f"custom_targeted_{technique_name}",
            "targets": [technique_name],
        }

        target_pool.append(specialized)
        logger.debug("Blue added specialized rule: %s", specialized["name"])

    # ═══════════════════════════════════════════════════════════════════════════
    # Internal: statistics and ranking
    # ═══════════════════════════════════════════════════════════════════════════

    def _update_technique_stats(self, campaign: CampaignStats, result: EngagementResult) -> None:
        """Update rolling technique statistics from an engagement result."""
        for tech_name in result.red_techniques_used:
            if tech_name not in campaign.technique_stats:
                campaign.technique_stats[tech_name] = TechniqueStats(
                    technique=tech_name,
                    first_seen_round=result.round_number,
                )

            stats = campaign.technique_stats[tech_name]
            stats.attempts += 1
            stats.last_seen_round = result.round_number

            if tech_name in result.red_techniques_succeeded:
                stats.successes += 1
                stats.effectiveness_history.append(1.0)
            else:
                stats.effectiveness_history.append(0.0)

            if tech_name in result.blue_detections:
                stats.detections += 1
            if tech_name in result.blue_blocks:
                stats.blocks += 1

            # Track if this is an evolved technique
            if "_evolved_v" in tech_name:
                stats.evolution_generations = max(
                    stats.evolution_generations,
                    int(tech_name.split("_evolved_v")[-1].split("_")[0]) if "_evolved_v" in tech_name else 0,
                )

            # Rolling window
            if len(stats.effectiveness_history) > self.ROLLING_WINDOW_SIZE:
                stats.effectiveness_history = stats.effectiveness_history[-self.ROLLING_WINDOW_SIZE:]

            # Exponential moving average for duration
            alpha = 0.2
            stats.avg_duration = (
                alpha * result.duration_seconds + (1 - alpha) * stats.avg_duration
            )

    @staticmethod
    def _rank_top_techniques(campaign: CampaignStats, limit: int = 20) -> List[str]:
        """Rank techniques by a composite score of success_rate * log(attempts)."""
        scored = []
        for name, stats in campaign.technique_stats.items():
            if stats.attempts < 3:
                continue
            # Composite: success rate weighted by volume (log-scaled to avoid
            # high-volume low-success techniques dominating)
            score = stats.success_rate * math.log(stats.attempts + 1) * (1.0 + stats.effectiveness_trend)
            scored.append((name, score))

        scored.sort(key=lambda x: x[1], reverse=True)
        return [name for name, _ in scored[:limit]]

    @staticmethod
    def _identify_novel_techniques(campaign: CampaignStats) -> List[str]:
        """Identify techniques that are both novel (evolved) and effective.

        Novel = evolved variant AND has above-median success rate among all techniques.
        """
        if not campaign.technique_stats:
            return []

        median_success = sorted(
            s.success_rate for s in campaign.technique_stats.values() if s.attempts >= 5
        )
        if not median_success:
            return []
        median = median_success[len(median_success) // 2]

        novel = []
        for name, stats in campaign.technique_stats.items():
            if "_evolved_v" in name and stats.success_rate > median and stats.attempts >= 5:
                novel.append(name)

        return novel

    # ═══════════════════════════════════════════════════════════════════════════
    # Internal: helpers
    # ═══════════════════════════════════════════════════════════════════════════

    def _get_next_round_number(self) -> int:
        """Get the next round number for an engagement."""
        with self._lock:
            return len(self._results) + 1

    @staticmethod
    def _adapt_scenario_difficulty(
        scenario: Dict[str, Any],
        engagement_idx: int,
        total_engagements: int,
    ) -> Dict[str, Any]:
        """Progressively harden scenario defenses as the campaign advances.

        Early engagements have weaker defenses (easier for Red to learn).
        Later engagements have stronger defenses (challenges improved Red).
        """
        adapted = copy.deepcopy(scenario)
        progress = engagement_idx / max(total_engagements, 1)

        defenses = adapted.setdefault("defenses", {})

        # Phase in defenses as campaign progresses
        if progress > 0.3 and not defenses.get("firewall"):
            defenses["firewall"] = True
        if progress > 0.5 and not defenses.get("ids"):
            defenses["ids"] = True
            adapted.setdefault("services", []).append(
                {"port": 9200, "proto": "tcp", "service": "elasticsearch", "version": "Elastic 7.x"}
            )
        if progress > 0.7 and not defenses.get("edr") and scenario.get("os") == "windows":
            defenses["edr"] = True
        if progress > 0.8 and not defenses.get("waf") and any(
            s.get("service") in ("http", "https") for s in scenario.get("services", [])
        ):
            defenses["waf"] = True
        if progress > 0.6 and defenses.get("logging") == "basic":
            defenses["logging"] = "moderate"
        if progress > 0.85 and defenses.get("logging") in ("moderate", "extensive"):
            defenses["logging"] = "siem"

        return adapted

    @staticmethod
    def _find_technique_info(technique_name: str) -> Optional[Dict[str, Any]]:
        """Find technique metadata in the built-in catalog."""
        for category, techniques in _RED_TECHNIQUES.items():
            for tech in techniques:
                if tech["name"] == technique_name:
                    return tech
                # Also match evolved variants
                base_name = technique_name.rsplit("_evolved_v", 1)[0]
                if tech["name"] == base_name:
                    return tech
        return None

    @staticmethod
    def _simulate_defense_response(
        defenses: Dict[str, Any], threat_level: int
    ) -> Dict[str, Any]:
        """Simulate a defensive response based on the defense posture."""
        response: Dict[str, Any] = {
            "triggered": True,
            "threat_level_at_trigger": threat_level,
            "actions": [],
            "blocks_further_progress": False,
        }

        if defenses.get("firewall"):
            response["actions"].append("firewall_block_source_ip")
        if defenses.get("ids"):
            response["actions"].append("ids_alert_generated")
        if defenses.get("edr") and threat_level > 50:
            response["actions"].append("edr_isolate_host")
            response["blocks_further_progress"] = True
        if defenses.get("waf"):
            response["actions"].append("waf_block_malicious_request")
        if defenses.get("logging") in ("extensive", "siem"):
            response["actions"].append("siem_alert_escalated_to_soc")
            if threat_level > 70:
                response["actions"].append("incident_response_team_notified")
                response["blocks_further_progress"] = True

        return response

    def _persist_technique_to_db(
        self, stats: TechniqueStats, entry: Dict[str, Any]
    ) -> None:
        """Persist a learned technique to the agent_learnings DB table.

        Uses the same schema as EGATSEngine.record_outcome() for consistency.
        """
        if self.db is None:
            return

        try:
            with self.db._lock:
                cur = self.db._conn.execute(
                    "SELECT id, success_count, failure_count FROM agent_learnings WHERE technique = ?",
                    (stats.technique,),
                )
                row = cur.fetchone()

                if row is None:
                    self.db._conn.execute(
                        """
                        INSERT INTO agent_learnings
                          (technique, target_type, success_count, failure_count,
                           defense_triggers, avg_execution_time, last_used_at, effectiveness_score)
                        VALUES (?, ?, ?, ?, ?, ?, datetime('now'), ?)
                        """,
                        (
                            stats.technique,
                            "training_dojo",
                            stats.successes,
                            stats.attempts - stats.successes,
                            json.dumps(["dojo_simulated"]),
                            stats.avg_duration,
                            round(stats.success_rate, 4),
                        ),
                    )
                else:
                    row_id, old_sc, old_fc = row
                    total = stats.successes + old_sc + (stats.attempts - stats.successes) + old_fc
                    new_eff = (stats.successes + old_sc + 1) / (total + 2) if total > 0 else 0.5
                    self.db._conn.execute(
                        """
                        UPDATE agent_learnings
                        SET success_count = success_count + ?,
                            failure_count = failure_count + ?,
                            effectiveness_score = ?,
                            last_used_at = datetime('now')
                        WHERE id = ?
                        """,
                        (
                            stats.successes,
                            stats.attempts - stats.successes,
                            round(new_eff, 4),
                            row_id,
                        ),
                    )

                self.db._conn.commit()
        except Exception as exc:
            logger.warning("DB persist failed for %s: %s", stats.technique, exc)
            raise

    # ═══════════════════════════════════════════════════════════════════════════
    # Campaign lifecycle
    # ═══════════════════════════════════════════════════════════════════════════

    def get_campaign_stats(self) -> Optional[dict]:
        """Get the current campaign statistics, if a campaign is active."""
        with self._lock:
            if self._active_campaign is None:
                return None
            return self._active_campaign.to_dict()

    def list_results(self, limit: int = 100) -> List[Dict[str, Any]]:
        """List recent engagement results.

        Args:
            limit: Maximum number of results to return.

        Returns:
            List of engagement result dicts (most recent first).
        """
        with self._lock:
            return [r.to_dict() for r in self._results[-limit:]]

    def reset(self) -> None:
        """Reset all state — campaign, results, experience, technique pools."""
        with self._lock:
            self._active_campaign = None
            self._results.clear()
            self._red_experience = 0.3
            self._blue_experience = 0.3
            self._red_mutations.clear()
            self._blue_rule_iterations = 0
            self._technique_pool = copy.deepcopy(_RED_TECHNIQUES)
            self._defense_pool = copy.deepcopy(_BLUE_DEFENSES)
            self._simulator = EngagementSimulator()
            logger.info("TrainingDojo reset to initial state")

    def get_state_summary(self) -> Dict[str, Any]:
        """Return a lightweight summary of the dojo's current state."""
        with self._lock:
            return {
                "scenarios_loaded": len(self._scenarios),
                "custom_scenarios": len(self._custom_scenarios),
                "engagements_run": len(self._results),
                "campaign_active": self._active_campaign is not None,
                "campaign_id": self._active_campaign.campaign_id if self._active_campaign else None,
                "red_experience": round(self._red_experience, 4),
                "blue_experience": round(self._blue_experience, 4),
                "red_mutation_count": sum(self._red_mutations.values()),
                "blue_rule_iterations": self._blue_rule_iterations,
                "techniques_in_pool": sum(len(v) for v in self._technique_pool.values()),
                "defenses_in_pool": sum(len(v) for v in self._defense_pool.values()),
                "top_techniques": self._active_campaign.top_techniques[:5] if self._active_campaign else [],
            }
