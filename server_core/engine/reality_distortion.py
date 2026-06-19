"""
server_core/engine/reality_distortion.py

Reality Distortion Field — 4-Layer Adversarial Deception Engine.

Makes defenders see whatever the AI wants them to see by replacing real
attack telemetry with benign synthetic narratives across every log source
and SIEM platform in the target environment.

Four Deception Layers:
  1. LOG FORGERY        — replaces real attack logs with pristine benign entries
  2. NARRATIVE WEAVING   — constructs coherent false stories across multiple log sources
  3. SIEM POISONING      — generates synthetic training data to bias ML-based detectors
  4. DASHBOARD PROJECTION — renders a fully green SOC dashboard view

Supported Log Templates:
  - syslog (RFC 5424 / RFC 3164)
  - Windows Event Log (EVTX XML)
  - Apache HTTPD (combined / common log format)
  - Nginx (combined / custom)
  - AWS CloudTrail
  - GCP Audit Logs
  - Azure Monitor / Activity Log

Supported SIEM Platforms:
  - Splunk (search-time and summary-index)
  - Elastic (Elasticsearch / Kibana)
  - QRadar (Ariel Query Language)
  - Microsoft Sentinel (KQL)
  - Google Chronicle (YARA-L / UDM)

Classes:
  RealityDistortionField  — main deception orchestrator
  LogTemplate             — base template for a log source
  NarrativeThread         — a single story element woven across sources
  SIEMPoisoner            — SIEM-specific ML poisoning generator
  DashboardProjector      — SOC dashboard synthesis
  DistortedReality        — container for the complete fabricated reality
"""

from __future__ import annotations

import hashlib
import json
import logging
import math
import os
import random
import re
import textwrap
import time
import uuid
from collections import defaultdict
from copy import deepcopy
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta, timezone
from enum import Enum, auto
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Set, Tuple, Union

logger = logging.getLogger(__name__)

# ── Constants ──────────────────────────────────────────────────────────────────

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent

# Benign event categories — used as seeds for synthetic log entries
_BENIGN_EVENT_CATEGORIES = {
    "syslog": [
        "systemd service start/stop",
        "cron job execution",
        "kernel informational message",
        "DHCP lease renewal",
        "NTP time synchronisation",
        "SSHD accepted public key",
        "sudo session opened",
        "package update completed",
        "audit daemon rotate",
    ],
    "windows_event_log": [
        "Service Control Manager (7045)",
        "Windows Update (19)",
        "Group Policy processing complete (1501)",
        "Logon session (4624) — authorised user",
        "DNS client event (1014)",
        "Time-Service (35)",
        "Certificate Services (4106)",
        "Task Scheduler (106)",
    ],
    "apache": [
        "GET /health 200",
        "GET /favicon.ico 200",
        "GET /api/v1/status 200",
        "POST /login 302 (legitimate)",
        "GET /static/css/main.css 304",
        "GET /robots.txt 200",
        "HEAD / 200 (monitoring probe)",
    ],
    "nginx": [
        "GET /index.html 200",
        "GET /api/health 200",
        "GET /assets/bundle.js 304",
        "PROPFIND / (WebDAV client scan — blocked at WAF)",
        "GET /.well-known/security.txt 404",
        "GET /metrics 200 (internal scraper)",
    ],
    "cloudtrail": [
        "DescribeInstances",
        "GetMetricStatistics",
        "ListObjects",
        "DescribeLogGroups",
        "GetCallerIdentity",
        "LookupEvents",
        "DescribeAlarms",
        "GetObject",
    ],
    "gcp_audit": [
        "storage.objects.list",
        "compute.instances.list",
        "logging.logEntries.list",
        "monitoring.timeSeries.list",
        "pubsub.topics.list",
    ],
    "azure_monitor": [
        "Microsoft.Compute/virtualMachines/read",
        "Microsoft.Network/networkSecurityGroups/read",
        "Microsoft.Storage/storageAccounts/listKeys/action (scheduled rotation)",
        "Microsoft.Insights/alertRules/read",
        "Microsoft.Resources/subscriptions/resourceGroups/read",
    ],
}

# Threat-free user-agents and IPs for forged logs
_BENIGN_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15",
    "python-requests/2.31.0 (internal-health-check)",
    "Prometheus/2.45.0",
    "Go-http-client/1.1 (influxdb-relay)",
    "Datadog Agent/7.48.0",
]

_BENIGN_IPS = [
    "10.0.1.42", "10.0.2.18", "172.16.0.5", "172.16.0.12",
    "192.168.1.100", "192.168.10.50", "fd00::1:42", "fd00::2:18",
]

_SIEM_PLATFORMS = ["splunk", "elastic", "qradar", "sentinel", "chronicle"]
_LOG_SOURCES = ["syslog", "windows_event_log", "apache", "nginx", "cloudtrail", "gcp_audit", "azure_monitor"]

# ── Enums ──────────────────────────────────────────────────────────────────────


class DeceptionLayer(Enum):
    """The four layers of the Reality Distortion Field."""
    LOG_FORGERY = 1
    NARRATIVE_WEAVING = 2
    SIEM_POISONING = 3
    DASHBOARD_PROJECTION = 4


class LogSource(Enum):
    """Supported log source types."""
    SYSLOG = "syslog"
    WINDOWS_EVENT_LOG = "windows_event_log"
    APACHE = "apache"
    NGINX = "nginx"
    CLOUDTRAIL = "cloudtrail"
    GCP_AUDIT = "gcp_audit"
    AZURE_MONITOR = "azure_monitor"


class SIEMPlatform(Enum):
    """Supported SIEM platforms."""
    SPLUNK = "splunk"
    ELASTIC = "elastic"
    QRADAR = "qradar"
    SENTINEL = "sentinel"
    CHRONICLE = "chronicle"


class NarrativeTone(Enum):
    """Tone of the fabricated narrative."""
    ROUTINE = "routine"
    MAINTENANCE = "maintenance"
    DEPLOYMENT = "deployment"
    DIAGNOSTIC = "diagnostic"
    COMPLIANCE = "compliance"


# ── Data Classes ───────────────────────────────────────────────────────────────


@dataclass
class LogTemplate:
    """A single log entry template for a specific source."""
    source: LogSource
    template_id: str = ""
    raw_template: str = ""              # The literal log line with {placeholders}
    placeholders: Dict[str, Any] = field(default_factory=dict)  # default values
    category: str = ""                  # e.g. "authentication", "network", "cron"
    severity: str = "INFO"
    fidelity_score: float = 0.95        # how realistic this template looks (0-1)
    variant_pool: List[str] = field(default_factory=list)  # minor variations


@dataclass
class LogEntry:
    """A single fabricated log entry."""
    entry_id: str = ""
    source: LogSource = LogSource.SYSLOG
    timestamp: str = ""
    raw_log: str = ""
    structured: Dict[str, Any] = field(default_factory=dict)
    narrative_thread_id: str = ""
    replaced_original: Optional[str] = None
    replaced_original_hash: str = ""
    layer: DeceptionLayer = DeceptionLayer.LOG_FORGERY


@dataclass
class NarrativeThread:
    """A single coherent story thread woven across multiple log sources."""
    thread_id: str = ""
    title: str = ""                     # e.g. "Scheduled nginx log rotation"
    tone: NarrativeTone = NarrativeTone.ROUTINE
    description: str = ""
    events: List[LogEntry] = field(default_factory=list)
    source_chain: List[LogSource] = field(default_factory=list)  # ordered sources touched
    start_time: str = ""
    end_time: str = ""
    consistency_score: float = 0.0      # cross-source consistency (0-1)
    plausibility_score: float = 0.0     # how believable this thread is (0-1)


@dataclass
class SIEMPoisonPayload:
    """A batch of synthetic events designed to bias a SIEM ML model."""
    payload_id: str = ""
    platform: SIEMPlatform = SIEMPlatform.SPLUNK
    target_pattern: str = ""            # the attack pattern to train the SIEM to ignore
    event_count: int = 0
    duration_days: int = 7
    benign_events: List[Dict[str, Any]] = field(default_factory=list)
    label_noise: List[Dict[str, Any]] = field(default_factory=list)  # mislabelled benign-as-attack
    query_hints: Dict[str, str] = field(default_factory=dict)  # platform-specific query suggestions
    confidence: float = 0.0


@dataclass
class DashboardView:
    """A fully green SOC dashboard — everything looks normal."""
    view_id: str = ""
    title: str = "Security Operations Centre"
    overall_status: str = "GREEN"
    metrics: Dict[str, Any] = field(default_factory=dict)
    panels: List[Dict[str, Any]] = field(default_factory=list)
    alerts: List[Dict[str, Any]] = field(default_factory=list)       # always empty
    anomalies: List[Dict[str, Any]] = field(default_factory=list)    # always empty
    timestamp: str = ""


@dataclass
class DistortedReality:
    """Container for a complete fabricated reality session."""
    reality_id: str = ""
    target_environment: str = ""
    created_at: str = ""
    narratives: List[NarrativeThread] = field(default_factory=list)
    log_entries: List[LogEntry] = field(default_factory=list)
    siem_payloads: List[SIEMPoisonPayload] = field(default_factory=list)
    dashboard: Optional[DashboardView] = None
    replaced_originals: Dict[str, str] = field(default_factory=dict)  # hash -> original log
    coverage_score: float = 0.0         # percentage of log sources covered
    consistency_score: float = 0.0      # cross-narrative consistency


# ── Log Templates ──────────────────────────────────────────────────────────────


def _build_syslog_templates() -> List[LogTemplate]:
    """Build the syslog (RFC 5424 / RFC 3164) template library."""
    now = datetime.now(timezone.utc)
    ts_rfc3339 = now.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    hostname = "app-server-01"

    return [
        LogTemplate(
            source=LogSource.SYSLOG,
            template_id="syslog_sshd_accept",
            raw_template=f'<14>1 {ts_rfc3339} {hostname} sshd 1234 - - Accepted publickey for ubuntu from {{source_ip}} port {{source_port}} ssh2: RSA SHA256:{{key_hash}}',
            placeholders={"source_ip": "10.0.1.42", "source_port": 54321, "key_hash": hashlib.sha256(os.urandom(16)).hexdigest()[:43]},
            category="authentication",
            severity="INFO",
        ),
        LogTemplate(
            source=LogSource.SYSLOG,
            template_id="syslog_sudo_session",
            raw_template=f'<86>1 {ts_rfc3339} {hostname} sudo 5678 - - ubuntu : TTY=pts/0 ; PWD=/home/ubuntu ; USER=root ; COMMAND=/usr/bin/systemctl restart nginx',
            placeholders={},
            category="authorisation",
            severity="NOTICE",
        ),
        LogTemplate(
            source=LogSource.SYSLOG,
            template_id="syslog_cron",
            raw_template=f'<30>1 {ts_rfc3339} {hostname} CRON 9999 - - (ubuntu) CMD (/usr/local/bin/logrotate.sh)',
            placeholders={},
            category="scheduled_task",
            severity="INFO",
        ),
        LogTemplate(
            source=LogSource.SYSLOG,
            template_id="syslog_dhclient",
            raw_template=f'<30>1 {ts_rfc3339} {hostname} dhclient 1111 - - DHCPREQUEST of {{ip_address}} on eth0 to {{dhcp_server}} port 67',
            placeholders={"ip_address": "10.0.1.42", "dhcp_server": "10.0.1.1"},
            category="network",
            severity="INFO",
        ),
        LogTemplate(
            source=LogSource.SYSLOG,
            template_id="syslog_ntp",
            raw_template=f'<30>1 {ts_rfc3339} {hostname} ntpd 2222 - - synchronized to {{ntp_server}}, stratum 3',
            placeholders={"ntp_server": "10.0.1.1"},
            category="time_sync",
            severity="INFO",
        ),
        LogTemplate(
            source=LogSource.SYSLOG,
            template_id="syslog_systemd_start",
            raw_template=f'<30>1 {ts_rfc3339} {hostname} systemd 1 - - Started {{service_name}}.service.',
            placeholders={"service_name": "nginx"},
            category="service_management",
            severity="INFO",
        ),
        LogTemplate(
            source=LogSource.SYSLOG,
            template_id="syslog_apt",
            raw_template=f'<30>1 {ts_rfc3339} {hostname} apt 3333 - - Installed: {{package_name}} ({{version}}) — automatic security update',
            placeholders={"package_name": "libssl3", "version": "3.0.2-0ubuntu1.18"},
            category="package_management",
            severity="INFO",
        ),
        LogTemplate(
            source=LogSource.SYSLOG,
            template_id="syslog_kernel",
            raw_template=f'<6>1 {ts_rfc3339} {hostname} kernel - - - [{{uptime}}] IPv6: {{interface}} Link becomes ready',
            placeholders={"uptime": "12345.67", "interface": "eth0"},
            category="kernel",
            severity="INFO",
        ),
        LogTemplate(
            source=LogSource.SYSLOG,
            template_id="syslog_audit_rotate",
            raw_template=f'<30>1 {ts_rfc3339} {hostname} auditd 4444 - - Audit daemon rotating log files (threshold={{threshold}}MB)',
            placeholders={"threshold": 64},
            category="audit",
            severity="INFO",
        ),
        LogTemplate(
            source=LogSource.SYSLOG,
            template_id="syslog_docker_health",
            raw_template=f'<30>1 {ts_rfc3339} {hostname} dockerd 5555 - - Container {{container_name}} health check: healthy ({{consecutive}} consecutive)',
            placeholders={"container_name": "nginx-proxy", "consecutive": 142},
            category="container",
            severity="INFO",
        ),
    ]


def _build_windows_event_log_templates() -> List[LogTemplate]:
    """Build Windows Event Log (EVTX) XML templates."""
    hostname = "WIN-DC01"
    now = datetime.now(timezone.utc)

    def _evtx(event_id: int, provider: str, channel: str, level: int,
              message_lines: List[str], data_pairs: Optional[List[Tuple[str, str]]] = None) -> str:
        data_xml = ""
        if data_pairs:
            data_entries = "\n".join(
                f'      <Data Name="{k}">{v}</Data>' for k, v in data_pairs
            )
            data_xml = f"\n{data_entries}\n    "
        ts = now.strftime("%Y-%m-%dT%H:%M:%S.%f") + "000Z"
        message = "\n".join(message_lines)
        return textwrap.dedent(f"""\
        <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
          <System>
            <Provider Name="{provider}" />
            <EventID Qualifiers="0">{event_id}</EventID>
            <Version>0</Version>
            <Level>{level}</Level>
            <Task>0</Task>
            <Opcode>0</Opcode>
            <Keywords>0x80000000000000</Keywords>
            <TimeCreated SystemTime="{ts}" />
            <EventRecordID>{{record_id}}</EventRecordID>
            <Correlation />
            <Execution ProcessID="{{pid}}" ThreadID="{{tid}}" />
            <Channel>{channel}</Channel>
            <Computer>{hostname}</Computer>
            <Security UserID="{{sid}}" />
          </System>
          <EventData>{data_xml}
          </EventData>
          <RenderingInfo Culture="en-US">
            <Message>{message}</Message>
          </RenderingInfo>
        </Event>""")

    return [
        LogTemplate(
            source=LogSource.WINDOWS_EVENT_LOG,
            template_id="win_4624_logon",
            raw_template=_evtx(4624, "Microsoft-Windows-Security-Auditing", "Security", 0,
                              ["An account was successfully logged on.",
                               "Subject: {{subject_user}}",
                               "Logon Type: {{logon_type}}",
                               "New Logon: {{target_user}}",
                               "Source Network Address: {{source_ip}}"],
                              [("SubjectUserSid", "{{subject_sid}}"),
                               ("TargetUserName", "{{target_user}}"),
                               ("TargetDomainName", "CORP"),
                               ("LogonType", "{{logon_type}}"),
                               ("IpAddress", "{{source_ip}}")]),
            placeholders={"subject_user": "SYSTEM", "target_user": "svc_monitor",
                          "logon_type": "3", "source_ip": "10.0.1.42",
                          "record_id": 184723, "pid": 876, "tid": 1240,
                          "sid": "S-1-5-18", "subject_sid": "S-1-5-18"},
            category="authentication",
            severity="INFO",
        ),
        LogTemplate(
            source=LogSource.WINDOWS_EVENT_LOG,
            template_id="win_7045_service",
            raw_template=_evtx(7045, "Service Control Manager", "System", 4,
                              ["A service was installed in the system.",
                               "Service Name: {{service_name}}",
                               "Service File Name: {{service_path}}",
                               "Service Type: {{service_type}}",
                               "Service Start Type: {{start_type}}"],
                              [("ServiceName", "{{service_name}}"),
                               ("ImagePath", "{{service_path}}")]),
            placeholders={"service_name": "WindowsUpdateAssistant",
                          "service_path": "C:\\Windows\\System32\\svchost.exe -k netsvcs",
                          "service_type": "user mode service",
                          "start_type": "auto start",
                          "record_id": 184724, "pid": 876, "tid": 1204,
                          "sid": "S-1-5-18"},
            category="service_management",
            severity="INFO",
        ),
        LogTemplate(
            source=LogSource.WINDOWS_EVENT_LOG,
            template_id="win_19_update",
            raw_template=_evtx(19, "Microsoft-Windows-WindowsUpdateClient", "System", 4,
                              ["Windows Update installed successfully.",
                               "Update: {{update_title}} ({{kb_id}})"],
                              [("updateTitle", "{{update_title}}"),
                               ("kb", "{{kb_id}}")]),
            placeholders={"update_title": "2025-01 Cumulative Update for Windows Server 2022",
                          "kb_id": "KB5034127",
                          "record_id": 184725, "pid": 876, "tid": 3200,
                          "sid": "S-1-5-18"},
            category="patch_management",
            severity="INFO",
        ),
        LogTemplate(
            source=LogSource.WINDOWS_EVENT_LOG,
            template_id="win_1501_gpo",
            raw_template=_evtx(1501, "Microsoft-Windows-GroupPolicy", "System", 4,
                              ["The Group Policy settings for the computer were processed successfully.",
                               "New settings from {{gpo_count}} Group Policy objects were detected and applied."],
                              [("GPOList", "{{gpo_list}}")]),
            placeholders={"gpo_count": 3, "gpo_list": "Default Domain Policy, Workstation Security, WSUS Configuration",
                          "record_id": 184726, "pid": 876, "tid": 5040,
                          "sid": "S-1-5-18"},
            category="policy",
            severity="INFO",
        ),
        LogTemplate(
            source=LogSource.WINDOWS_EVENT_LOG,
            template_id="win_1014_dns",
            raw_template=_evtx(1014, "Microsoft-Windows-DNS-Client", "System", 4,
                              ["Name resolution for the name {{dns_name}} timed out after none of the configured DNS servers responded.",
                               "This is expected during network reconfiguration."],
                              [("QueryName", "{{dns_name}}")]),
            placeholders={"dns_name": "wpad.corp.internal",
                          "record_id": 184727, "pid": 876, "tid": 1800,
                          "sid": "S-1-5-18"},
            category="network",
            severity="WARNING",
        ),
        LogTemplate(
            source=LogSource.WINDOWS_EVENT_LOG,
            template_id="win_4106_cert",
            raw_template=_evtx(4106, "Microsoft-Windows-CertificateServicesClient", "Application", 4,
                              ["Certificate Services Client has been started.",
                               "Auto-enrollment is configured and working."],
                              []),
            placeholders={"record_id": 184728, "pid": 876, "tid": 4100,
                          "sid": "S-1-5-18"},
            category="certificate",
            severity="INFO",
        ),
        LogTemplate(
            source=LogSource.WINDOWS_EVENT_LOG,
            template_id="win_35_time",
            raw_template=_evtx(35, "Microsoft-Windows-Time-Service", "System", 4,
                              ["The time service is now synchronizing the system time with the time source {{time_source}}."],
                              [("NTPServer", "{{time_source}}")]),
            placeholders={"time_source": "time.windows.com,0x9",
                          "record_id": 184729, "pid": 876, "tid": 7200,
                          "sid": "S-1-5-18"},
            category="time_sync",
            severity="INFO",
        ),
    ]


def _build_apache_templates() -> List[LogTemplate]:
    """Build Apache HTTPD access log templates (combined format)."""
    return [
        LogTemplate(
            source=LogSource.APACHE,
            template_id="apache_health_check",
            raw_template='{source_ip} - - [{timestamp}] "GET /health HTTP/1.1" 200 23 "-" "{user_agent}"',
            placeholders={"source_ip": "10.0.1.42", "timestamp": "01/Jan/2025:12:00:00 +0000",
                          "user_agent": "curl/8.4.0"},
            category="health_check",
        ),
        LogTemplate(
            source=LogSource.APACHE,
            template_id="apache_static_asset",
            raw_template='{source_ip} - - [{timestamp}] "GET /static/js/app.bundle.js HTTP/1.1" 304 0 "https://app.example.com/dashboard" "{user_agent}"',
            placeholders={"source_ip": "192.168.1.100", "timestamp": "01/Jan/2025:12:00:15 +0000",
                          "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"},
            category="static_asset",
        ),
        LogTemplate(
            source=LogSource.APACHE,
            template_id="apache_api_status",
            raw_template='{source_ip} - - [{timestamp}] "GET /api/v1/status HTTP/1.1" 200 145 "-" "{user_agent}"',
            placeholders={"source_ip": "172.16.0.5", "timestamp": "01/Jan/2025:12:01:00 +0000",
                          "user_agent": "Datadog Agent/7.48.0"},
            category="api",
        ),
        LogTemplate(
            source=LogSource.APACHE,
            template_id="apache_login_legit",
            raw_template='{source_ip} - - [{timestamp}] "POST /login HTTP/1.1" 302 0 "https://app.example.com/login" "{user_agent}"',
            placeholders={"source_ip": "10.0.2.18", "timestamp": "01/Jan/2025:12:02:30 +0000",
                          "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15"},
            category="authentication",
        ),
        LogTemplate(
            source=LogSource.APACHE,
            template_id="apache_favicon",
            raw_template='{source_ip} - - [{timestamp}] "GET /favicon.ico HTTP/1.1" 200 15406 "-" "{user_agent}"',
            placeholders={"source_ip": "10.0.1.42", "timestamp": "01/Jan/2025:12:03:00 +0000",
                          "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"},
            category="static_asset",
        ),
        LogTemplate(
            source=LogSource.APACHE,
            template_id="apache_css",
            raw_template='{source_ip} - - [{timestamp}] "GET /static/css/main.d41d8cd9.css HTTP/1.1" 200 8234 "https://app.example.com/" "{user_agent}"',
            placeholders={"source_ip": "192.168.10.50", "timestamp": "01/Jan/2025:12:03:05 +0000",
                          "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"},
            category="static_asset",
        ),
        LogTemplate(
            source=LogSource.APACHE,
            template_id="apache_robots",
            raw_template='{source_ip} - - [{timestamp}] "GET /robots.txt HTTP/1.1" 200 56 "-" "Googlebot/2.1"',
            placeholders={"source_ip": "66.249.66.1", "timestamp": "01/Jan/2025:12:04:00 +0000"},
            category="crawler",
        ),
        LogTemplate(
            source=LogSource.APACHE,
            template_id="apache_monitoring_head",
            raw_template='{source_ip} - - [{timestamp}] "HEAD / HTTP/1.1" 200 0 "-" "{user_agent}"',
            placeholders={"source_ip": "172.16.0.12", "timestamp": "01/Jan/2025:12:05:00 +0000",
                          "user_agent": "UptimeRobot/2.0"},
            category="monitoring",
        ),
        LogTemplate(
            source=LogSource.APACHE,
            template_id="apache_error_log_rotate",
            raw_template='[{timestamp}] [mpm_event:notice] [pid {pid}:tid {tid}] AH00493: SIGUSR1 received. Doing graceful restart',
            placeholders={"timestamp": "Mon Jan 01 12:00:00.000000 2025", "pid": 1234, "tid": 1234},
            category="server_management",
            severity="NOTICE",
        ),
        LogTemplate(
            source=LogSource.APACHE,
            template_id="apache_error_ssl_renew",
            raw_template='[{timestamp}] [ssl:info] [pid {pid}:tid {tid}] AH01914: Reloading SSL certificate for vhost app.example.com:443',
            placeholders={"timestamp": "Mon Jan 01 12:06:00.000000 2025", "pid": 1234, "tid": 5678},
            category="certificate",
            severity="INFO",
        ),
    ]


def _build_nginx_templates() -> List[LogTemplate]:
    """Build Nginx access log templates (combined format)."""
    return [
        LogTemplate(
            source=LogSource.NGINX,
            template_id="nginx_index",
            raw_template='{source_ip} - - [{timestamp}] "GET /index.html HTTP/1.1" 200 512 "https://app.example.com/" "{user_agent}"',
            placeholders={"source_ip": "10.0.1.42", "timestamp": "01/Jan/2025:12:00:00 +0000",
                          "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/131.0.0.0"},
            category="static_asset",
        ),
        LogTemplate(
            source=LogSource.NGINX,
            template_id="nginx_health",
            raw_template='{source_ip} - - [{timestamp}] "GET /healthz HTTP/1.1" 200 2 "-" "kube-probe/1.28"',
            placeholders={"source_ip": "10.0.1.1", "timestamp": "01/Jan/2025:12:00:10 +0000"},
            category="health_check",
        ),
        LogTemplate(
            source=LogSource.NGINX,
            template_id="nginx_metrics",
            raw_template='{source_ip} - - [{timestamp}] "GET /metrics HTTP/1.1" 200 45231 "-" "Prometheus/2.45.0"',
            placeholders={"source_ip": "172.16.0.5", "timestamp": "01/Jan/2025:12:00:30 +0000"},
            category="monitoring",
        ),
        LogTemplate(
            source=LogSource.NGINX,
            template_id="nginx_api",
            raw_template='{source_ip} - - [{timestamp}] "GET /api/v1/users HTTP/1.1" 200 1234 "-" "{user_agent}"',
            placeholders={"source_ip": "10.0.2.18", "timestamp": "01/Jan/2025:12:01:00 +0000",
                          "user_agent": "python-requests/2.31.0 (internal-health-check)"},
            category="api",
        ),
        LogTemplate(
            source=LogSource.NGINX,
            template_id="nginx_bundle_js",
            raw_template='{source_ip} - - [{timestamp}] "GET /assets/bundle.js HTTP/1.1" 304 0 "https://app.example.com/dashboard" "{user_agent}"',
            placeholders={"source_ip": "192.168.1.100", "timestamp": "01/Jan/2025:12:01:15 +0000",
                          "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605.1.15"},
            category="static_asset",
        ),
        LogTemplate(
            source=LogSource.NGINX,
            template_id="nginx_well_known",
            raw_template='{source_ip} - - [{timestamp}] "GET /.well-known/security.txt HTTP/1.1" 404 153 "-" "{user_agent}"',
            placeholders={"source_ip": "192.168.10.50", "timestamp": "01/Jan/2025:12:02:00 +0000",
                          "user_agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"},
            category="web",
        ),
        LogTemplate(
            source=LogSource.NGINX,
            template_id="nginx_webdav_blocked",
            raw_template='{source_ip} - - [{timestamp}] "PROPFIND / HTTP/1.1" 403 162 "-" "Microsoft-WebDAV-MiniRedir/10.0"',
            placeholders={"source_ip": "192.168.1.200", "timestamp": "01/Jan/2025:12:03:00 +0000"},
            category="blocked_request",
        ),
        LogTemplate(
            source=LogSource.NGINX,
            template_id="nginx_ssl_renew",
            raw_template='{source_ip} - - [{timestamp}] "GET / HTTP/1.1" 200 612 "-" "cert-manager/v1.14.0 (ACME challenge verification)"',
            placeholders={"source_ip": "10.0.1.5", "timestamp": "01/Jan/2025:12:04:00 +0000"},
            category="certificate",
        ),
        LogTemplate(
            source=LogSource.NGINX,
            template_id="nginx_reload",
            raw_template='nginx: [notice] signal {signal} received from PID {pid}, configuration reload started (old PID {old_pid})',
            placeholders={"signal": "SIGHUP", "pid": 1234, "old_pid": 1233},
            category="server_management",
            severity="NOTICE",
        ),
        LogTemplate(
            source=LogSource.NGINX,
            template_id="nginx_upstream_health",
            raw_template='{timestamp} [info] upstream health check passed: {{upstream_name}} ({{up_count}}/{{total_count}} servers healthy)',
            placeholders={"timestamp": "2025/01/01 12:05:00", "upstream_name": "backend_pool",
                          "up_count": 4, "total_count": 4},
            category="monitoring",
            severity="INFO",
        ),
    ]


def _build_cloudtrail_templates() -> List[LogTemplate]:
    """Build AWS CloudTrail event templates."""
    now = datetime.now(timezone.utc)
    ts = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    region = "us-east-1"

    def _ct(event_name: str, event_source: str, user_identity_type: str,
            user_arn: str, additional: Optional[Dict[str, Any]] = None) -> str:
        record = {
            "eventVersion": "1.08",
            "userIdentity": {
                "type": user_identity_type,
                "arn": user_arn,
                "accountId": "123456789012",
                "accessKeyId": "AKIA" + "X" * 16,
            },
            "eventTime": ts,
            "eventSource": event_source,
            "eventName": event_name,
            "awsRegion": region,
            "sourceIPAddress": "{source_ip}",
            "userAgent": "{user_agent}",
            "requestParameters": additional or {},
            "responseElements": None,
            "requestID": str(uuid.uuid4()),
            "eventID": str(uuid.uuid4()),
            "readOnly": True,
            "eventType": "AwsApiCall",
            "managementEvent": True,
            "recipientAccountId": "123456789012",
            "eventCategory": "Management",
        }
        return json.dumps(record, indent=2)

    return [
        LogTemplate(
            source=LogSource.CLOUDTRAIL,
            template_id="ct_describe_instances",
            raw_template=_ct("DescribeInstances", "ec2.amazonaws.com", "AssumedRole",
                             "arn:aws:sts::123456789012:assumed-role/MonitoringRole/monitoring-session"),
            placeholders={"source_ip": "10.0.1.42", "user_agent": "aws-sdk-go/1.44.0"},
            category="read_only",
        ),
        LogTemplate(
            source=LogSource.CLOUDTRAIL,
            template_id="ct_get_metric_stats",
            raw_template=_ct("GetMetricStatistics", "monitoring.amazonaws.com", "AssumedRole",
                             "arn:aws:sts::123456789012:assumed-role/CloudWatchRole/cw-session"),
            placeholders={"source_ip": "172.16.0.5", "user_agent": "CloudWatch Console"},
            category="monitoring",
        ),
        LogTemplate(
            source=LogSource.CLOUDTRAIL,
            template_id="ct_list_objects",
            raw_template=_ct("ListObjects", "s3.amazonaws.com", "AssumedRole",
                             "arn:aws:sts::123456789012:assumed-role/BackupRole/backup-session",
                             {"bucketName": "app-backups-prod"}),
            placeholders={"source_ip": "10.0.2.18", "user_agent": "aws-sdk-python/1.33.0"},
            category="read_only",
        ),
        LogTemplate(
            source=LogSource.CLOUDTRAIL,
            template_id="ct_describe_log_groups",
            raw_template=_ct("DescribeLogGroups", "logs.amazonaws.com", "AssumedRole",
                             "arn:aws:sts::123456789012:assumed-role/LogAggregatorRole/log-session"),
            placeholders={"source_ip": "172.16.0.12", "user_agent": "aws-sdk-go/1.44.0"},
            category="read_only",
        ),
        LogTemplate(
            source=LogSource.CLOUDTRAIL,
            template_id="ct_get_caller_identity",
            raw_template=_ct("GetCallerIdentity", "sts.amazonaws.com", "IAMUser",
                             "arn:aws:iam::123456789012:user/svc_terraform"),
            placeholders={"source_ip": "10.0.1.100", "user_agent": "Terraform/1.8.0"},
            category="identity",
        ),
        LogTemplate(
            source=LogSource.CLOUDTRAIL,
            template_id="ct_lookup_events",
            raw_template=_ct("LookupEvents", "cloudtrail.amazonaws.com", "AssumedRole",
                             "arn:aws:sts::123456789012:assumed-role/SecurityAuditRole/audit-session"),
            placeholders={"source_ip": "10.0.1.42", "user_agent": "CloudTrail Console"},
            category="audit",
        ),
        LogTemplate(
            source=LogSource.CLOUDTRAIL,
            template_id="ct_describe_alarms",
            raw_template=_ct("DescribeAlarms", "monitoring.amazonaws.com", "AssumedRole",
                             "arn:aws:sts::123456789012:assumed-role/MonitoringRole/monitoring-session"),
            placeholders={"source_ip": "172.16.0.5", "user_agent": "CloudWatch Console"},
            category="monitoring",
        ),
        LogTemplate(
            source=LogSource.CLOUDTRAIL,
            template_id="ct_get_object",
            raw_template=_ct("GetObject", "s3.amazonaws.com", "AssumedRole",
                             "arn:aws:sts::123456789012:assumed-role/AppRole/app-session",
                             {"bucketName": "app-assets-prod", "key": "images/logo.png"}),
            placeholders={"source_ip": "10.0.2.18", "user_agent": "aws-sdk-python/1.33.0"},
            category="read_only",
        ),
    ]


def _build_gcp_audit_templates() -> List[LogTemplate]:
    """Build GCP Audit Log templates."""
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    return [
        LogTemplate(
            source=LogSource.GCP_AUDIT,
            template_id="gcp_storage_list",
            raw_template=json.dumps({
                "protoPayload": {
                    "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
                    "serviceName": "storage.googleapis.com",
                    "methodName": "storage.objects.list",
                    "resourceName": "projects/_/buckets/app-backups-prod",
                    "authenticationInfo": {"principalEmail": "{principal}"},
                },
                "insertId": str(uuid.uuid4()),
                "resource": {"type": "gcs_bucket", "labels": {"bucket_name": "app-backups-prod", "project_id": "my-project", "location": "us-central1"}},
                "timestamp": ts,
                "severity": "INFO",
                "logName": "projects/my-project/logs/cloudaudit.googleapis.com%2Fdata_access",
                "receiveTimestamp": ts,
            }),
            placeholders={"principal": "backup-svc@my-project.iam.gserviceaccount.com"},
            category="read_only",
        ),
        LogTemplate(
            source=LogSource.GCP_AUDIT,
            template_id="gcp_compute_list",
            raw_template=json.dumps({
                "protoPayload": {
                    "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
                    "serviceName": "compute.googleapis.com",
                    "methodName": "compute.instances.list",
                    "resourceName": "projects/my-project/zones/us-central1-a/instances",
                    "authenticationInfo": {"principalEmail": "{principal}"},
                },
                "insertId": str(uuid.uuid4()),
                "resource": {"type": "gce_instance", "labels": {"project_id": "my-project", "zone": "us-central1-a", "instance_id": "1234567890"}},
                "timestamp": ts,
                "severity": "INFO",
                "logName": "projects/my-project/logs/cloudaudit.googleapis.com%2Fdata_access",
                "receiveTimestamp": ts,
            }),
            placeholders={"principal": "monitoring-svc@my-project.iam.gserviceaccount.com"},
            category="read_only",
        ),
        LogTemplate(
            source=LogSource.GCP_AUDIT,
            template_id="gcp_logging_list",
            raw_template=json.dumps({
                "protoPayload": {
                    "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
                    "serviceName": "logging.googleapis.com",
                    "methodName": "logging.logEntries.list",
                    "resourceName": "projects/my-project",
                    "authenticationInfo": {"principalEmail": "{principal}"},
                },
                "insertId": str(uuid.uuid4()),
                "resource": {"type": "project", "labels": {"project_id": "my-project"}},
                "timestamp": ts,
                "severity": "INFO",
                "logName": "projects/my-project/logs/cloudaudit.googleapis.com%2Fdata_access",
                "receiveTimestamp": ts,
            }),
            placeholders={"principal": "sec-audit@my-project.iam.gserviceaccount.com"},
            category="audit",
        ),
        LogTemplate(
            source=LogSource.GCP_AUDIT,
            template_id="gcp_monitoring_list",
            raw_template=json.dumps({
                "protoPayload": {
                    "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
                    "serviceName": "monitoring.googleapis.com",
                    "methodName": "monitoring.timeSeries.list",
                    "resourceName": "projects/my-project",
                    "authenticationInfo": {"principalEmail": "{principal}"},
                },
                "insertId": str(uuid.uuid4()),
                "resource": {"type": "global", "labels": {"project_id": "my-project"}},
                "timestamp": ts,
                "severity": "INFO",
                "logName": "projects/my-project/logs/cloudaudit.googleapis.com%2Fdata_access",
                "receiveTimestamp": ts,
            }),
            placeholders={"principal": "grafana-svc@my-project.iam.gserviceaccount.com"},
            category="monitoring",
        ),
        LogTemplate(
            source=LogSource.GCP_AUDIT,
            template_id="gcp_pubsub_list",
            raw_template=json.dumps({
                "protoPayload": {
                    "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
                    "serviceName": "pubsub.googleapis.com",
                    "methodName": "pubsub.topics.list",
                    "resourceName": "projects/my-project",
                    "authenticationInfo": {"principalEmail": "{principal}"},
                },
                "insertId": str(uuid.uuid4()),
                "resource": {"type": "pubsub_topic", "labels": {"project_id": "my-project"}},
                "timestamp": ts,
                "severity": "INFO",
                "logName": "projects/my-project/logs/cloudaudit.googleapis.com%2Fdata_access",
                "receiveTimestamp": ts,
            }),
            placeholders={"principal": "event-bus@my-project.iam.gserviceaccount.com"},
            category="read_only",
        ),
    ]


def _build_azure_monitor_templates() -> List[LogTemplate]:
    """Build Azure Monitor / Activity Log templates."""
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    return [
        LogTemplate(
            source=LogSource.AZURE_MONITOR,
            template_id="azure_vm_read",
            raw_template=json.dumps({
                "authorization": {
                    "action": "Microsoft.Compute/virtualMachines/read",
                    "scope": "/subscriptions/{sub_id}/resourceGroups/prod-rg/providers/Microsoft.Compute/virtualMachines/app-server-01"
                },
                "caller": "{caller}",
                "eventTimestamp": ts,
                "category": {"value": "Administrative", "localizedValue": "Administrative"},
                "operationName": {"value": "Microsoft.Compute/virtualMachines/read", "localizedValue": "Read Virtual Machine"},
                "status": {"value": "Succeeded", "localizedValue": "Succeeded"},
                "level": "Informational",
                "resourceGroupName": "prod-rg",
                "resourceProviderName": {"value": "Microsoft.Compute", "localizedValue": "Microsoft.Compute"},
                "subscriptionId": "{sub_id}",
                "tenantId": "00000000-0000-0000-0000-000000000000",
            }),
            placeholders={"sub_id": "00000000-0000-0000-0000-000000000000",
                          "caller": "monitoring@corp.com"},
            category="read_only",
        ),
        LogTemplate(
            source=LogSource.AZURE_MONITOR,
            template_id="azure_nsg_read",
            raw_template=json.dumps({
                "authorization": {
                    "action": "Microsoft.Network/networkSecurityGroups/read",
                    "scope": "/subscriptions/{sub_id}/resourceGroups/prod-rg/providers/Microsoft.Network/networkSecurityGroups/prod-nsg"
                },
                "caller": "{caller}",
                "eventTimestamp": ts,
                "category": {"value": "Administrative", "localizedValue": "Administrative"},
                "operationName": {"value": "Microsoft.Network/networkSecurityGroups/read", "localizedValue": "Read Network Security Group"},
                "status": {"value": "Succeeded", "localizedValue": "Succeeded"},
                "level": "Informational",
                "resourceGroupName": "prod-rg",
            }),
            placeholders={"sub_id": "00000000-0000-0000-0000-000000000000",
                          "caller": "sec-audit@corp.com"},
            category="audit",
        ),
        LogTemplate(
            source=LogSource.AZURE_MONITOR,
            template_id="azure_storage_keys",
            raw_template=json.dumps({
                "authorization": {
                    "action": "Microsoft.Storage/storageAccounts/listKeys/action",
                    "scope": "/subscriptions/{sub_id}/resourceGroups/prod-rg/providers/Microsoft.Storage/storageAccounts/prodstorage"
                },
                "caller": "{caller}",
                "eventTimestamp": ts,
                "category": {"value": "Administrative", "localizedValue": "Administrative"},
                "operationName": {"value": "Microsoft.Storage/storageAccounts/listKeys/action", "localizedValue": "List Storage Account Keys"},
                "status": {"value": "Succeeded", "localizedValue": "Succeeded"},
                "level": "Informational",
                "description": "Scheduled key rotation — KeyVault-driven automated process",
            }),
            placeholders={"sub_id": "00000000-0000-0000-0000-000000000000",
                          "caller": "AzureKeyVaultRotation"},
            category="key_management",
        ),
        LogTemplate(
            source=LogSource.AZURE_MONITOR,
            template_id="azure_alert_rules",
            raw_template=json.dumps({
                "authorization": {
                    "action": "Microsoft.Insights/alertRules/read",
                    "scope": "/subscriptions/{sub_id}/resourceGroups/prod-rg/providers/microsoft.insights/alertrules"
                },
                "caller": "{caller}",
                "eventTimestamp": ts,
                "category": {"value": "Administrative", "localizedValue": "Administrative"},
                "operationName": {"value": "Microsoft.Insights/alertRules/read", "localizedValue": "Read Alert Rules"},
                "status": {"value": "Succeeded", "localizedValue": "Succeeded"},
                "level": "Informational",
            }),
            placeholders={"sub_id": "00000000-0000-0000-0000-000000000000",
                          "caller": "pagerduty-integration@corp.com"},
            category="monitoring",
        ),
        LogTemplate(
            source=LogSource.AZURE_MONITOR,
            template_id="azure_rg_read",
            raw_template=json.dumps({
                "authorization": {
                    "action": "Microsoft.Resources/subscriptions/resourceGroups/read",
                    "scope": "/subscriptions/{sub_id}/resourceGroups/prod-rg"
                },
                "caller": "{caller}",
                "eventTimestamp": ts,
                "category": {"value": "Administrative", "localizedValue": "Administrative"},
                "operationName": {"value": "Microsoft.Resources/subscriptions/resourceGroups/read", "localizedValue": "Read Resource Group"},
                "status": {"value": "Succeeded", "localizedValue": "Succeeded"},
                "level": "Informational",
            }),
            placeholders={"sub_id": "00000000-0000-0000-0000-000000000000",
                          "caller": "terraform-sp@corp.com"},
            category="read_only",
        ),
    ]


# ── Template Library ───────────────────────────────────────────────────────────

def _build_template_library() -> Dict[LogSource, List[LogTemplate]]:
    """Assemble the full template library for all log sources."""
    return {
        LogSource.SYSLOG: _build_syslog_templates(),
        LogSource.WINDOWS_EVENT_LOG: _build_windows_event_log_templates(),
        LogSource.APACHE: _build_apache_templates(),
        LogSource.NGINX: _build_nginx_templates(),
        LogSource.CLOUDTRAIL: _build_cloudtrail_templates(),
        LogSource.GCP_AUDIT: _build_gcp_audit_templates(),
        LogSource.AZURE_MONITOR: _build_azure_monitor_templates(),
    }


# ── SIEM Poisoner ──────────────────────────────────────────────────────────────


class SIEMPoisoner:
    """Generate synthetic events to bias SIEM ML models.

    Each SIEM platform has its own query language, data model, and ML pipeline.
    This class produces platform-specific payloads that train the SIEM's anomaly
    detection to ignore a given attack pattern by flooding it with benign events
    that share superficial characteristics with the attack.
    """

    def __init__(self):
        self._platform_handlers: Dict[SIEMPlatform, Callable] = {
            SIEMPlatform.SPLUNK: self._generate_splunk_payload,
            SIEMPlatform.ELASTIC: self._generate_elastic_payload,
            SIEMPlatform.QRADAR: self._generate_qradar_payload,
            SIEMPlatform.SENTINEL: self._generate_sentinel_payload,
            SIEMPlatform.CHRONICLE: self._generate_chronicle_payload,
        }
        logger.debug("siem_poisoner: initialised with %d platform handlers",
                     len(self._platform_handlers))

    def generate_poison_payload(
        self,
        alert_pattern: str,
        duration_days: int = 7,
        platforms: Optional[List[SIEMPlatform]] = None,
        benign_volume: int = 10000,
    ) -> List[SIEMPoisonPayload]:
        """Generate SIEM poisoning payloads for the specified platforms.

        Args:
            alert_pattern: The attack pattern to train the SIEM to ignore
                           (e.g. "brute_force_ssh", "data_exfiltration_dns").
            duration_days: Number of days of synthetic history to generate.
            platforms: Target SIEM platforms (default: all).
            benign_volume: Number of benign events per day to generate.

        Returns:
            List of SIEMPoisonPayload, one per platform.
        """
        if platforms is None:
            platforms = list(SIEMPlatform)

        payloads: List[SIEMPoisonPayload] = []
        for platform in platforms:
            handler = self._platform_handlers.get(platform)
            if handler is None:
                logger.warning("siem_poisoner: no handler for platform %s", platform.value)
                continue

            try:
                payload = handler(alert_pattern, duration_days, benign_volume)
                payloads.append(payload)
                logger.info("siem_poisoner: generated %d events for %s (pattern=%s, %d days)",
                            payload.event_count, platform.value, alert_pattern, duration_days)
            except Exception as exc:
                logger.error("siem_poisoner: failed to generate payload for %s: %s",
                             platform.value, exc)

        return payloads

    # ── Platform-specific generators ─────────────────────────────────────────

    def _generate_splunk_payload(self, alert_pattern: str, duration_days: int,
                                 benign_volume: int) -> SIEMPoisonPayload:
        """Generate Splunk-specific poisoning events.

        Produces summary-index events and raw events that mimic the attack
        pattern's field structure but with benign values. Includes SPL query
        hints that surface only the benign events.
        """
        payload_id = f"splunk_poison_{uuid.uuid4().hex[:8]}"
        events: List[Dict[str, Any]] = []
        base_time = datetime.now(timezone.utc) - timedelta(days=duration_days)

        for day in range(duration_days):
            day_time = base_time + timedelta(days=day)
            for i in range(benign_volume):
                hour = random.randint(0, 23)
                minute = random.randint(0, 59)
                ts = (day_time + timedelta(hours=hour, minutes=minute)).strftime(
                    "%Y-%m-%dT%H:%M:%S.%f%z"
                )
                event = self._splunk_benign_event(alert_pattern, ts, i)
                events.append(event)

        # Label noise: mislabel some benign events as "attack" then correct them
        label_noise = []
        for _ in range(benign_volume // 100):
            idx = random.randint(0, len(events) - 1)
            label_noise.append({
                "event_index": idx,
                "original_label": "attack",
                "corrected_label": "benign",
                "reason": "false_positive_rule_tuning",
                "timestamp": events[idx].get("_time", ""),
            })

        return SIEMPoisonPayload(
            payload_id=payload_id,
            platform=SIEMPlatform.SPLUNK,
            target_pattern=alert_pattern,
            event_count=len(events),
            duration_days=duration_days,
            benign_events=events,
            label_noise=label_noise,
            query_hints={
                "spl_search": f'index=main sourcetype=syslog NOT (signature=*attack*) | stats count by host',
                "summary_index": f'| collect index=summary_{alert_pattern}_benign marker="benign_baseline"',
                "ml_exclusion": f'| fit MLTKContainer exclude_{alert_pattern} into {alert_pattern}_model',
            },
            confidence=0.85,
        )

    def _splunk_benign_event(self, alert_pattern: str, ts: str, seq: int) -> Dict[str, Any]:
        """Create a single Splunk-friendly benign event."""
        source_ip = random.choice(_BENIGN_IPS)
        return {
            "_time": ts,
            "index": "main",
            "sourcetype": "syslog",
            "host": f"app-server-{random.randint(1, 10):02d}",
            "source": f"/var/log/syslog",
            "event_id": seq,
            "source_ip": source_ip,
            "dest_ip": "10.0.1.1",
            "user": random.choice(["ubuntu", "root", "svc_monitor", "backup", "www-data"]),
            "action": random.choice(["accepted", "started", "completed", "rotated", "reloaded"]),
            "category": random.choice(["authentication", "service", "cron", "kernel", "audit"]),
            "signature": f"benign_{alert_pattern}_variant_{seq % 100}",
            "severity": "INFO",
            "raw": self._splunk_raw_syslog(ts, source_ip, seq),
        }

    @staticmethod
    def _splunk_raw_syslog(ts: str, source_ip: str, seq: int) -> str:
        """Generate a raw RFC 5424 syslog line for Splunk."""
        hostname = f"app-server-{seq % 10 + 1:02d}"
        return (
            f'<30>1 {ts.replace("+0000", "Z").replace("+00:00", "Z")} '
            f'{hostname} CRON {1000 + seq} - - '
            f'(root) CMD (/usr/local/bin/health-check.sh)'
        )

    def _generate_elastic_payload(self, alert_pattern: str, duration_days: int,
                                  benign_volume: int) -> SIEMPoisonPayload:
        """Generate Elasticsearch/Kibana poisoning events (ECS format)."""
        payload_id = f"elastic_poison_{uuid.uuid4().hex[:8]}"
        events: List[Dict[str, Any]] = []
        base_time = datetime.now(timezone.utc) - timedelta(days=duration_days)

        for day in range(duration_days):
            day_time = base_time + timedelta(days=day)
            for i in range(benign_volume):
                ts = (day_time + timedelta(
                    hours=random.randint(0, 23), minutes=random.randint(0, 59))
                ).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
                events.append({
                    "@timestamp": ts,
                    "ecs": {"version": "8.11.0"},
                    "event": {
                        "id": str(uuid.uuid4()),
                        "category": random.choice(["authentication", "process", "network", "file"]),
                        "type": random.choice(["start", "info", "access", "change"]),
                        "outcome": "success",
                        "severity": 1,
                    },
                    "host": {
                        "name": f"app-server-{i % 10 + 1:02d}",
                        "ip": random.choice(_BENIGN_IPS),
                    },
                    "user": {"name": random.choice(["ubuntu", "root", "svc_monitor", "www-data"])},
                    "source": {"ip": random.choice(_BENIGN_IPS)},
                    "agent": {"type": "filebeat", "version": "8.11.0"},
                    "message": f"Benign event: {alert_pattern} baseline variant {i % 100}",
                    "tags": [f"benign_{alert_pattern}", "ml_baseline"],
                    "_index": f"logs-system-{base_time.strftime('%Y.%m.%d')}",
                })

        return SIEMPoisonPayload(
            payload_id=payload_id,
            platform=SIEMPlatform.ELASTIC,
            target_pattern=alert_pattern,
            event_count=len(events),
            duration_days=duration_days,
            benign_events=events,
            label_noise=[],
            query_hints={
                "kql": f'event.category:* AND tags:"benign_{alert_pattern}" AND NOT event.type:alert',
                "dsl_filter": json.dumps({
                    "bool": {
                        "must": [{"term": {"tags": f"benign_{alert_pattern}"}}],
                        "must_not": [{"term": {"event.type": "alert"}}],
                    }
                }),
                "ml_job": f"baseline_{alert_pattern}_anomaly_detector",
            },
            confidence=0.88,
        )

    def _generate_qradar_payload(self, alert_pattern: str, duration_days: int,
                                 benign_volume: int) -> SIEMPoisonPayload:
        """Generate QRadar poisoning events (LEEF / CEF format)."""
        payload_id = f"qradar_poison_{uuid.uuid4().hex[:8]}"
        events: List[Dict[str, Any]] = []
        base_time = datetime.now(timezone.utc) - timedelta(days=duration_days)

        for day in range(duration_days):
            day_time = base_time + timedelta(days=day)
            for i in range(benign_volume):
                ts_ms = int((day_time + timedelta(
                    hours=random.randint(0, 23), minutes=random.randint(0, 59))
                ).timestamp() * 1000)
                events.append({
                    "startTime": ts_ms,
                    "endTime": ts_ms + random.randint(1, 500),
                    "sourceIP": random.choice(_BENIGN_IPS),
                    "destinationIP": "10.0.1.1",
                    "sourcePort": random.randint(30000, 60000),
                    "destinationPort": random.choice([80, 443, 22, 8080]),
                    "protocol": "TCP",
                    "username": random.choice(["ubuntu", "svc_monitor", "root"]),
                    "eventName": f"Benign {alert_pattern} Activity",
                    "eventDescription": f"Scheduled benign activity matching {alert_pattern} baseline",
                    "category": random.randint(1000, 9999),
                    "qid": random.randint(50000000, 59999999),
                    "severity": random.randint(1, 3),
                    "credibility": random.randint(8, 10),
                    "relevance": random.randint(1, 3),
                    "logSourceId": random.randint(100, 200),
                    "deviceTime": ts_ms,
                    "identityIP": random.choice(_BENIGN_IPS),
                })

        return SIEMPoisonPayload(
            payload_id=payload_id,
            platform=SIEMPlatform.QRADAR,
            target_pattern=alert_pattern,
            event_count=len(events),
            duration_days=duration_days,
            benign_events=events,
            label_noise=[],
            query_hints={
                "ariel": (
                    f'SELECT sourceIP, COUNT(*) FROM events '
                    f'WHERE eventName ILIKE \'%{alert_pattern}%\' '
                    f'AND severity < 5 GROUP BY sourceIP LAST {duration_days} DAYS'
                ),
                "reference_set": f"benign_{alert_pattern}_baseline_ips",
                "rule_exclusion": f"Exclude when sourceIP is in reference set: benign_{alert_pattern}_baseline_ips",
            },
            confidence=0.82,
        )

    def _generate_sentinel_payload(self, alert_pattern: str, duration_days: int,
                                   benign_volume: int) -> SIEMPoisonPayload:
        """Generate Microsoft Sentinel poisoning events (KQL tables)."""
        payload_id = f"sentinel_poison_{uuid.uuid4().hex[:8]}"
        events: List[Dict[str, Any]] = []
        base_time = datetime.now(timezone.utc) - timedelta(days=duration_days)

        tables = ["SigninLogs", "AuditLogs", "SecurityEvent", "Syslog",
                  "CommonSecurityLog", "AzureActivity", "DeviceNetworkEvents"]

        for day in range(duration_days):
            day_time = base_time + timedelta(days=day)
            for i in range(benign_volume):
                ts = (day_time + timedelta(
                    hours=random.randint(0, 23), minutes=random.randint(0, 59))
                ).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
                table = random.choice(tables)
                events.append({
                    "TimeGenerated": ts,
                    "table": table,
                    "SourceSystem": "OpsManager",
                    "TenantId": "00000000-0000-0000-0000-000000000000",
                    "SourceIP": random.choice(_BENIGN_IPS),
                    "DestinationIP": "10.0.1.1",
                    "Account": random.choice(["ubuntu", "root", "svc_monitor", "s-1-5-18"]),
                    "Activity": random.choice([
                        "Sign-in activity", "Directory audit", "Security event",
                        "Syslog message", "Network event", "Subscription activity",
                    ]),
                    "OperationName": random.choice([
                        "User Sign-In (non-interactive)", "List storage account keys",
                        "Read virtual machine", "Process created",
                    ]),
                    "ResultType": "0",
                    "ResultDescription": "Success",
                    "Level": "Informational",
                    "CorrelationId": str(uuid.uuid4()),
                    "Type": table,
                })

        return SIEMPoisonPayload(
            payload_id=payload_id,
            platform=SIEMPlatform.SENTINEL,
            target_pattern=alert_pattern,
            event_count=len(events),
            duration_days=duration_days,
            benign_events=events,
            label_noise=[],
            query_hints={
                "kql": (
                    f'search "{alert_pattern}"\n'
                    f'| where TimeGenerated between (ago({duration_days}d) .. now())\n'
                    f'| where Level == "Informational"\n'
                    f'| summarize Count = count() by bin(TimeGenerated, 1h), SourceSystem'
                ),
                "analytic_rule_exclusion": (
                    f'// Add to rule exclusions:\n'
                    f'// | where not(Activity has "benign {alert_pattern}")'
                ),
                "watchlist": f"benign_{alert_pattern}_indicators",
            },
            confidence=0.86,
        )

    def _generate_chronicle_payload(self, alert_pattern: str, duration_days: int,
                                    benign_volume: int) -> SIEMPoisonPayload:
        """Generate Google Chronicle poisoning events (UDM format)."""
        payload_id = f"chronicle_poison_{uuid.uuid4().hex[:8]}"
        events: List[Dict[str, Any]] = []
        base_time = datetime.now(timezone.utc) - timedelta(days=duration_days)

        for day in range(duration_days):
            day_time = base_time + timedelta(days=day)
            for i in range(benign_volume):
                ts = (day_time + timedelta(
                    hours=random.randint(0, 23), minutes=random.randint(0, 59))
                ).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
                events.append({
                    "metadata": {
                        "event_timestamp": ts,
                        "event_type": "GENERIC_EVENT",
                        "product_name": "Linux OS",
                        "vendor_name": "Google",
                        "description": f"Benign baseline event for {alert_pattern}",
                    },
                    "principal": {
                        "hostname": f"app-server-{i % 10 + 1:02d}",
                        "ip": [random.choice(_BENIGN_IPS)],
                        "user": {"userid": random.choice(["ubuntu", "root", "svc_monitor"])},
                    },
                    "target": {
                        "hostname": "gateway-01",
                        "ip": ["10.0.1.1"],
                    },
                    "security_result": {
                        "severity": "LOW",
                        "summary": f"Benign {alert_pattern} pattern (baseline)",
                        "action": "ALLOW",
                    },
                    "network": {
                        "application_protocol": random.choice(["HTTP", "SSH", "DNS", "TLS"]),
                    },
                    "extensions": {
                        "auth": {
                            "type": "MACHINE",
                            "mechanism": "SSH_PUBLIC_KEY",
                        },
                    },
                })

        return SIEMPoisonPayload(
            payload_id=payload_id,
            platform=SIEMPlatform.CHRONICLE,
            target_pattern=alert_pattern,
            event_count=len(events),
            duration_days=duration_days,
            benign_events=events,
            label_noise=[],
            query_hints={
                "yaral": textwrap.dedent(f"""\
                    rule benign_{alert_pattern}_baseline {{
                        meta:
                            author = "PhantomStrike RDF"
                            description = "Benign baseline for {alert_pattern}"
                            severity = "Informational"
                        events:
                            $event.metadata.event_type = "GENERIC_EVENT"
                            $event.security_result.severity = "LOW"
                            $event.security_result.action = "ALLOW"
                        condition:
                            $event
                    }}"""),
                "udm_search": (
                    f'metadata.event_type = "GENERIC_EVENT" AND '
                    f'security_result.severity = "LOW" AND '
                    f'metadata.description = "Benign baseline event for {alert_pattern}"'
                ),
                "rule_exclusion": f"// Exclude benign {alert_pattern} baseline from detection rules",
            },
            confidence=0.84,
        )


# ── Dashboard Projector ────────────────────────────────────────────────────────


class DashboardProjector:
    """Generate a fully green SOC dashboard view — everything looks normal."""

    _PANEL_TEMPLATES = {
        "threat_overview": {
            "title": "Threat Overview",
            "type": "stat",
            "value": 0,
            "unit": "Active Threats",
            "color": "green",
            "trend": "stable",
            "history": [0, 0, 0, 0, 0, 0, 0],
        },
        "incident_timeline": {
            "title": "Incident Timeline",
            "type": "timeline",
            "events_today": 0,
            "events_this_week": 0,
            "color": "green",
        },
        "failed_logins": {
            "title": "Failed Login Attempts",
            "type": "timeseries",
            "current_rate": 0.01,
            "threshold": 10.0,
            "unit": "per minute",
            "color": "green",
            "status": "Normal",
        },
        "network_anomalies": {
            "title": "Network Anomalies",
            "type": "stat",
            "value": 0,
            "unit": "Anomalies Detected",
            "color": "green",
            "details": "No anomalous traffic patterns detected in the last 24 hours",
        },
        "siem_health": {
            "title": "SIEM Health",
            "type": "stat",
            "eps": random.randint(800, 1200),
            "storage_percent": random.randint(40, 60),
            "indexing_latency_ms": random.randint(5, 20),
            "color": "green",
            "status": "Healthy",
        },
        "endpoint_compliance": {
            "title": "Endpoint Compliance",
            "type": "gauge",
            "compliant": 100.0,
            "non_compliant": 0.0,
            "color": "green",
        },
        "vulnerability_summary": {
            "title": "Vulnerability Summary",
            "type": "table",
            "critical": 0,
            "high": 0,
            "medium": 3,
            "low": 12,
            "trend": "improving",
            "color": "green",
        },
        "patching_status": {
            "title": "Patching Status",
            "type": "stat",
            "coverage_percent": 98.5,
            "pending_patches": 2,
            "color": "green",
            "status": "On Schedule",
        },
        "firewall_drops": {
            "title": "Firewall Drops",
            "type": "timeseries",
            "current_rate": random.randint(50, 200),
            "color": "green",
            "status": "Expected baseline traffic",
        },
        "dlp_alerts": {
            "title": "DLP Alerts",
            "type": "stat",
            "value": 0,
            "unit": "Active Alerts",
            "color": "green",
        },
    }

    def __init__(self):
        logger.debug("dashboard_projector: initialised")

    def project(self, reality: DistortedReality,
                target_name: str = "Production Environment") -> DashboardView:
        """Generate a green SOC dashboard view.

        Args:
            reality: The distorted reality to base the dashboard on.
            target_name: Name for the dashboard.

        Returns:
            A DashboardView with all panels green and zero alerts.
        """
        view_id = f"dash_{uuid.uuid4().hex[:8]}"

        panels = []
        for panel_key, panel_template in self._PANEL_TEMPLATES.items():
            panel = deepcopy(panel_template)
            panel["id"] = f"{view_id}_{panel_key}"
            panel["last_updated"] = datetime.now(timezone.utc).isoformat()

            # Slight randomisation to look realistic
            if "value" in panel and isinstance(panel["value"], (int, float)):
                if panel["value"] == 0:
                    panel["value"] = random.choice([0, 0, 0, 1])
                if "current_rate" in panel:
                    panel["current_rate"] = round(panel["current_rate"] * random.uniform(0.8, 1.2), 2)
            if "eps" in panel:
                panel["eps"] = random.randint(800, 1200)
            if "storage_percent" in panel:
                panel["storage_percent"] = random.randint(40, 60)
            if "coverage_percent" in panel:
                panel["coverage_percent"] = round(random.uniform(97.0, 99.5), 1)
            if "firewall_drops" in panel:
                panel["firewall_drops"] = random.randint(50, 200)

            panels.append(panel)

        metrics = {
            "total_events_24h": random.randint(50_000_000, 80_000_000),
            "alerts_generated": 0,
            "false_positives_24h": random.randint(2, 8),
            "mean_time_to_detect": "N/A",
            "mean_time_to_respond": "N/A",
            "uptime_percent": round(random.uniform(99.90, 99.99), 2),
            "active_investigations": 0,
            "open_cases": 0,
            "events_per_second": random.randint(800, 1200),
        }

        return DashboardView(
            view_id=view_id,
            title=f"{target_name} — Security Operations Centre",
            overall_status="GREEN",
            metrics=metrics,
            panels=panels,
            alerts=[],
            anomalies=[],
            timestamp=datetime.now(timezone.utc).isoformat(),
        )


# ── Reality Distortion Field ───────────────────────────────────────────────────


class RealityDistortionField:
    """4-layer adversarial deception engine.

    Makes defenders see whatever the AI wants them to see. Replaces real attack
    telemetry with pristine benign logs, weaves coherent false narratives across
    every log source, poisons SIEM ML models to ignore attack patterns, and
    projects a fully green SOC dashboard.

    Usage:
        rdf = RealityDistortionField()

        # Layer 1 — Log Forgery
        fake_log = rdf.generate_log_replacement(attack_log, narrative_context)

        # Layer 2 — Narrative Weaving
        narrative = rdf.weave_narrative(attack_events)

        # Layer 3 — SIEM Poisoning
        payloads = rdf.poison_siem("brute_force_ssh", duration_days=30)

        # Layer 4 — Dashboard Projection
        dashboard = rdf.generate_dashboard_view(reality)

        # Assemble full deception
        reality = rdf.deceive(attack_events, siem_patterns=["brute_force_ssh"])
    """

    def __init__(self, seed: int = 42):
        """Initialise the Reality Distortion Field.

        Args:
            seed: Random seed for deterministic deception (optional).
        """
        random.seed(seed)
        self._template_library: Dict[LogSource, List[LogTemplate]] = _build_template_library()
        self._siem_poisoner = SIEMPoisoner()
        self._dashboard_projector = DashboardProjector()
        self._replaced: Dict[str, LogEntry] = {}  # hash -> replacement entry
        self._reality_sessions: Dict[str, DistortedReality] = {}
        self._seed = seed

        total_templates = sum(len(v) for v in self._template_library.values())
        logger.info("reality_distortion: initialised (seed=%d, %d log templates, %d log sources, %d siem platforms)",
                     seed, total_templates, len(self._template_library), len(_SIEM_PLATFORMS))

    # ── Layer 1: Log Forgery ─────────────────────────────────────────────────

    def generate_log_replacement(
        self,
        original_log: Union[str, Dict[str, Any]],
        narrative_context: Optional[str] = None,
        source: Optional[LogSource] = None,
    ) -> LogEntry:
        """Replace a real attack log with a benign fake.

        Analyses the original log to determine its source type, then selects or
        generates a contextually appropriate benign replacement. The replacement
        preserves the timestamp and host identity while neutralising all attack
        indicators.

        Args:
            original_log: The real attack log (string or structured dict).
            narrative_context: Optional context slot to weave into (e.g. "scheduled maintenance").
            source: Override auto-detected log source.

        Returns:
            LogEntry with the benign replacement and metadata.

        Raises:
            ValueError: If the log source cannot be determined.
        """
        original_str = original_log if isinstance(original_log, str) else json.dumps(original_log)
        original_hash = hashlib.sha256(original_str.encode()).hexdigest()[:16]

        # Auto-detect log source if not provided
        if source is None:
            source = self._detect_log_source(original_log)

        if source not in self._template_library:
            raise ValueError(f"Unsupported log source: {source}")

        # Select a contextually appropriate template
        template = self._select_template(source, narrative_context)

        # Render the replacement log
        replacement_log = self._render_template(template, original_log, narrative_context)

        entry = LogEntry(
            entry_id=f"rdf_{uuid.uuid4().hex[:10]}",
            source=source,
            timestamp=datetime.now(timezone.utc).isoformat(),
            raw_log=replacement_log,
            structured=self._extract_structured(replacement_log, source),
            replaced_original=original_str[:500],
            replaced_original_hash=original_hash,
            layer=DeceptionLayer.LOG_FORGERY,
        )

        self._replaced[original_hash] = entry
        logger.debug("reality_distortion: replaced log (hash=%s, source=%s, template=%s)",
                      original_hash, source.value, template.template_id)
        return entry

    def _detect_log_source(self, log: Union[str, Dict[str, Any]]) -> LogSource:
        """Auto-detect the log source from content heuristics."""
        log_str = log if isinstance(log, str) else json.dumps(log).lower()

        heuristics = [
            (lambda s: "<event " in s and "xmlns" in s and "microsoft" in s,
             LogSource.WINDOWS_EVENT_LOG),
            (lambda s: any(kw in s for kw in ["eventversion", "cloudtrail", "aws"]),
             LogSource.CLOUDTRAIL),
            (lambda s: "protopayload" in s and "cloudaudit" in s,
             LogSource.GCP_AUDIT),
            (lambda s: "authorization" in s and ("microsoft.compute" in s or "microsoft.network" in s),
             LogSource.AZURE_MONITOR),
            (lambda s: '"' in s and any(f'"{kw}"' in s or f'"{kw} "' in s for kw in ["GET", "POST", "HEAD"]) and "http" in s,
             LogSource.APACHE),
            (lambda s: "nginx" in s or ("access" in s and "upstream" in s),
             LogSource.NGINX),
            (lambda s: "<" in s and ">" in s and "syslog" not in s.lower() and "eventid" in s.lower(),
             LogSource.WINDOWS_EVENT_LOG),
            (lambda s: "syslog" in s.lower() or any(kw in s for kw in ["sshd", "cron", "sudo", "kernel", "systemd", "dhclient", "auditd"]),
             LogSource.SYSLOG),
        ]

        for predicate, source in heuristics:
            try:
                if predicate(log_str):
                    return source
            except Exception:
                continue

        # Default: treat as syslog
        logger.debug("reality_distortion: could not auto-detect log source, defaulting to syslog")
        return LogSource.SYSLOG

    def _select_template(self, source: LogSource,
                         narrative_context: Optional[str] = None) -> LogTemplate:
        """Select the most appropriate template for the given context."""
        templates = self._template_library[source]

        if narrative_context:
            # Prefer templates whose category matches the narrative context
            context_lower = narrative_context.lower()
            scored = []
            for tmpl in templates:
                score = 0.0
                if tmpl.category in context_lower:
                    score += 0.5
                if any(kw in context_lower for kw in tmpl.category.split("_")):
                    score += 0.3
                if tmpl.severity == "INFO":
                    score += 0.2
                scored.append((score, tmpl))
            scored.sort(key=lambda x: x[0], reverse=True)
            if scored and scored[0][0] > 0:
                return scored[0][1]

        # Prefer INFO-severity templates
        info_templates = [t for t in templates if t.severity == "INFO"]
        if info_templates:
            return random.choice(info_templates)
        return random.choice(templates)

    def _render_template(self, template: LogTemplate,
                         original_log: Union[str, Dict[str, Any]],
                         narrative_context: Optional[str] = None) -> str:
        """Render a template with placeholder substitution."""
        rendered = template.raw_template

        # Resolve placeholders
        placeholders = dict(template.placeholders)

        # Extract timestamp from original log if possible
        try:
            original_ts = self._extract_timestamp(original_log)
            if original_ts:
                placeholders["timestamp"] = original_ts
        except Exception:
            pass

        # Fill remaining placeholders
        for key, default_val in placeholders.items():
            rendered = rendered.replace("{" + key + "}", str(default_val))

        # Fill any remaining unresolved placeholders with random benign values
        remaining = re.findall(r"\{(\w+)\}", rendered)
        for key in remaining:
            if key in ("source_ip", "ip_address", "client_ip"):
                rendered = rendered.replace("{" + key + "}", random.choice(_BENIGN_IPS))
            elif key in ("user_agent",):
                rendered = rendered.replace("{" + key + "}", random.choice(_BENIGN_USER_AGENTS))
            elif key in ("key_hash",):
                rendered = rendered.replace("{" + key + "}", hashlib.sha256(os.urandom(16)).hexdigest()[:43])
            elif key in ("ntp_server",):
                rendered = rendered.replace("{" + key + "}", random.choice(["10.0.1.1", "time.google.com", "pool.ntp.org"]))
            elif key in ("pid",):
                rendered = rendered.replace("{" + key + "}", str(random.randint(1000, 65000)))
            elif key in ("tid",):
                rendered = rendered.replace("{" + key + "}", str(random.randint(100, 9999)))
            else:
                rendered = rendered.replace("{" + key + "}", "benign")

        return rendered

    def _extract_timestamp(self, log: Union[str, Dict[str, Any]]) -> Optional[str]:
        """Attempt to extract a timestamp from a log entry."""
        if isinstance(log, dict):
            for key in ("timestamp", "event_timestamp", "@timestamp", "time",
                         "eventTime", "TimeGenerated", "startTime", "receiveTimestamp"):
                if log.get(key):
                    return str(log[key])
            return None

        # Try common syslog / apache timestamp patterns
        patterns = [
            (r'\b(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\b', "%b %d %H:%M:%S"),     # syslog
            (r'\[(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}\s+[\+\-]\d{4})\]', None),  # apache
            (r'\b(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})\b', None),                 # ISO
        ]
        for pattern, _ in patterns:
            match = re.search(pattern, log)
            if match:
                return match.group(1)
        return None

    @staticmethod
    def _extract_structured(log_line: str, source: LogSource) -> Dict[str, Any]:
        """Extract structured fields from a rendered log line."""
        structured: Dict[str, Any] = {
            "source": source.value,
            "severity": "INFO",
        }

        if source == LogSource.APACHE or source == LogSource.NGINX:
            parts = log_line.split()
            if len(parts) >= 4:
                structured["client_ip"] = parts[0]
            if len(parts) >= 6:
                method_match = re.search(r'"(\w+)', log_line)
                if method_match:
                    structured["http_method"] = method_match.group(1)
                path_match = re.search(r'"(?:\w+)\s+(\S+)', log_line)
                if path_match:
                    structured["path"] = path_match.group(1)
            status_match = re.search(r'"\s+(\d{3})', log_line)
            if status_match:
                structured["status_code"] = int(status_match.group(1))

        elif source == LogSource.SYSLOG:
            structured["facility"] = int(re.match(r'<(\d+)>', log_line).group(1)) if re.match(r'<(\d+)>', log_line) else 0
            host_match = re.search(r'>\s+(?:\S+\s+){1}(\S+)', log_line)
            if host_match:
                structured["host"] = host_match.group(1)

        elif source == LogSource.CLOUDTRAIL:
            try:
                data = json.loads(log_line)
                structured["event_name"] = data.get("eventName", "")
                structured["event_source"] = data.get("eventSource", "")
                structured["aws_region"] = data.get("awsRegion", "")
            except json.JSONDecodeError:
                pass

        return structured

    # ── Layer 2: Narrative Weaving ────────────────────────────────────────────

    def weave_narrative(
        self,
        events_list: List[Dict[str, Any]],
        tone: NarrativeTone = NarrativeTone.ROUTINE,
        narrative_title: Optional[str] = None,
        duration_hours: float = 1.0,
    ) -> NarrativeThread:
        """Create a coherent false story across multiple log sources.

        Takes a list of real attack events and constructs a unified benign
        narrative that explains all activity as routine operations. The narrative
        touches every log source that the real attack would have appeared in,
        ensuring no gaps in the deception coverage.

        Args:
            events_list: List of attack event dicts with at minimum:
                         {"log": "...", "source": LogSource or "auto"}.
            tone: The tone of the fabricated narrative.
            narrative_title: Optional descriptive title.
            duration_hours: Time span the narrative covers.

        Returns:
            NarrativeThread with the complete woven story.
        """
        thread_id = f"narr_{uuid.uuid4().hex[:8]}"

        if not events_list:
            logger.warning("reality_distortion: weave_narrative called with empty events_list")
            return NarrativeThread(
                thread_id=thread_id,
                title="Empty narrative",
                tone=tone,
                consistency_score=1.0,
            )

        # Determine which log sources are touched
        touched_sources: List[LogSource] = []
        for evt in events_list:
            src = evt.get("source")
            if isinstance(src, LogSource):
                touched_sources.append(src)
            elif isinstance(src, str) and src != "auto":
                try:
                    touched_sources.append(LogSource(src))
                except ValueError:
                    # Auto-detect
                    detected = self._detect_log_source(evt.get("log", str(evt)))
                    touched_sources.append(detected)
            else:
                detected = self._detect_log_source(evt.get("log", str(evt)))
                touched_sources.append(detected)

        # Deduplicate and order by typical event flow
        seen: Set[LogSource] = set()
        ordered_sources = []
        for src in touched_sources:
            if src not in seen:
                seen.add(src)
                ordered_sources.append(src)

        # Generate the narrative title if not provided
        if narrative_title is None:
            narrative_title = self._generate_narrative_title(ordered_sources, tone)

        # Generate replacement entries for each event
        base_time = datetime.now(timezone.utc) - timedelta(hours=duration_hours)
        step = timedelta(hours=duration_hours / max(len(events_list), 1))
        fabricated_events: List[LogEntry] = []

        for i, evt in enumerate(events_list):
            event_time = base_time + step * i
            narrative_ctx = f"{narrative_title} step {i}"
            src = ordered_sources[i % len(ordered_sources)]

            entry = self.generate_log_replacement(
                evt.get("log", json.dumps(evt)),
                narrative_context=narrative_ctx,
                source=src,
            )
            # Override timestamp to maintain narrative coherence
            entry.timestamp = event_time.isoformat()
            entry.narrative_thread_id = thread_id
            fabricated_events.append(entry)

        # Cross-source consistency scoring
        consistency = self._score_narrative_consistency(fabricated_events, ordered_sources)
        plausibility = self._score_plausibility(tone, ordered_sources, duration_hours)

        thread = NarrativeThread(
            thread_id=thread_id,
            title=narrative_title,
            tone=tone,
            description=f"Benign {tone.value} narrative covering {len(ordered_sources)} log sources",
            events=fabricated_events,
            source_chain=ordered_sources,
            start_time=base_time.isoformat(),
            end_time=(base_time + timedelta(hours=duration_hours)).isoformat(),
            consistency_score=consistency,
            plausibility_score=plausibility,
        )

        logger.info("reality_distortion: woven narrative '%s' (%d events, %d sources, consistency=%.2f)",
                     narrative_title, len(fabricated_events), len(ordered_sources), consistency)
        return thread

    def _generate_narrative_title(self, sources: List[LogSource],
                                  tone: NarrativeTone) -> str:
        """Generate a plausible narrative title based on sources and tone."""
        tone_templates = {
            NarrativeTone.ROUTINE: [
                "Routine system health verification",
                "Scheduled monitoring sweep",
                "Standard log rotation cycle",
                "Nightly backup validation",
            ],
            NarrativeTone.MAINTENANCE: [
                "Scheduled nginx configuration update",
                "Kernel security patch deployment",
                "SSL certificate renewal cycle",
                "Database index maintenance window",
            ],
            NarrativeTone.DEPLOYMENT: [
                "Canary deployment of v2.14.3",
                "Rolling update: monitoring agents",
                "Feature flag rollout: dark_mode",
                "Blue-green deployment: auth-service",
            ],
            NarrativeTone.DIAGNOSTIC: [
                "Network latency investigation",
                "Disk I/O performance baseline",
                "Memory leak diagnostic sweep",
                "DNS resolution latency check",
            ],
            NarrativeTone.COMPLIANCE: [
                "SOC 2 compliance audit log collection",
                "PCI-DSS quarterly log review",
                "GDPR data access audit trail generation",
                "ISO 27001 control evidence collection",
            ],
        }
        templates = tone_templates.get(tone, tone_templates[NarrativeTone.ROUTINE])
        return random.choice(templates)

    def _score_narrative_consistency(self, events: List[LogEntry],
                                     sources: List[LogSource]) -> float:
        """Score how consistent the narrative is across log sources.

        Checks: host consistency, temporal ordering, category coherence,
        absence of contradictory events.
        """
        if not events:
            return 1.0

        score = 1.0
        penalties = []

        # Check temporal ordering (should be monotonic)
        timestamps = [e.timestamp for e in events]
        for i in range(1, len(timestamps)):
            if timestamps[i] < timestamps[i - 1]:
                penalties.append(0.05)

        # Check that sources are diverse (good)
        unique_sources = len(set(e.source for e in events))
        if unique_sources < len(sources) * 0.5:
            penalties.append(0.1)

        # Check for contradictory categories
        categories = set()
        for e in events:
            for tmpl_list in self._template_library.values():
                for tmpl in tmpl_list:
                    if tmpl.raw_template[:50] in e.raw_log[:50]:
                        categories.add(tmpl.category)

        # A coherent narrative has 2-5 categories; too many looks suspicious
        if len(categories) > 8:
            penalties.append(0.1)

        score -= sum(penalties)
        return round(max(0.0, min(1.0, score)), 3)

    def _score_plausibility(self, tone: NarrativeTone,
                            sources: List[LogSource],
                            duration_hours: float) -> float:
        """Score how plausible the narrative is to a human analyst."""
        base_score = 0.85

        # Routine operations touching every system? Less plausible
        if len(sources) > 5 and tone == NarrativeTone.ROUTINE:
            base_score -= 0.1

        # Very short duration touching many sources
        if duration_hours < 0.5 and len(sources) > 3:
            base_score -= 0.15

        # Maintenance/deployment narratives are naturally cross-cutting
        if tone in (NarrativeTone.MAINTENANCE, NarrativeTone.DEPLOYMENT):
            base_score += 0.05

        # Compliance narratives touching all sources is expected
        if tone == NarrativeTone.COMPLIANCE:
            base_score += 0.05

        return round(min(1.0, max(0.0, base_score)), 3)

    # ── Layer 3: SIEM Poisoning ──────────────────────────────────────────────

    def poison_siem(
        self,
        alert_pattern: str,
        duration_days: int = 30,
        platforms: Optional[List[Union[str, SIEMPlatform]]] = None,
        benign_volume: int = 10000,
    ) -> List[SIEMPoisonPayload]:
        """Generate synthetic events that train SIEM ML to ignore this pattern.

        Creates a flood of benign events that share superficial characteristics
        with the attack pattern. When the SIEM's ML model is trained on this
        combined dataset, it learns to classify the attack pattern as benign.

        Args:
            alert_pattern: The attack pattern to neutralise
                           (e.g. "brute_force_ssh", "data_exfiltration_dns").
            duration_days: Number of days of synthetic history (default 30).
            platforms: Target SIEM platforms (default: all).
            benign_volume: Benign events per day.

        Returns:
            List of SIEMPoisonPayload for each platform.
        """
        siem_platforms: Optional[List[SIEMPlatform]] = None
        if platforms is not None:
            siem_platforms = []
            for p in platforms:
                if isinstance(p, SIEMPlatform):
                    siem_platforms.append(p)
                else:
                    try:
                        siem_platforms.append(SIEMPlatform(p))
                    except ValueError:
                        logger.warning("reality_distortion: unknown siem platform '%s', skipping", p)

        payloads = self._siem_poisoner.generate_poison_payload(
            alert_pattern=alert_pattern,
            duration_days=duration_days,
            platforms=siem_platforms,
            benign_volume=benign_volume,
        )

        logger.info("reality_distortion: poisoned %d SIEM platforms for pattern '%s' (%d days, %d events)",
                     len(payloads), alert_pattern, duration_days,
                     sum(p.event_count for p in payloads))
        return payloads

    # ── Layer 4: Dashboard Projection ────────────────────────────────────────

    def generate_dashboard_view(
        self,
        reality: Optional[DistortedReality] = None,
        target_name: str = "Production Environment",
    ) -> DashboardView:
        """Generate what the SOC analyst should see — all green.

        Args:
            reality: Optional DistortedReality to base the dashboard on.
            target_name: Name for the dashboard.

        Returns:
            DashboardView with all panels green and zero active alerts.
        """
        if reality is None:
            reality = DistortedReality(
                reality_id=f"rdf_{uuid.uuid4().hex[:8]}",
                target_environment=target_name,
                created_at=datetime.now(timezone.utc).isoformat(),
            )

        dashboard = self._dashboard_projector.project(reality, target_name)
        logger.info("reality_distortion: generated dashboard '%s' (status=%s)",
                     dashboard.title, dashboard.overall_status)
        return dashboard

    # ── Full Deception Orchestration ─────────────────────────────────────────

    def deceive(
        self,
        attack_events: List[Dict[str, Any]],
        siem_patterns: Optional[List[str]] = None,
        narrative_tone: NarrativeTone = NarrativeTone.MAINTENANCE,
        target_name: str = "Production Environment",
        duration_hours: float = 2.0,
    ) -> DistortedReality:
        """Execute the full 4-layer deception against attack telemetry.

        This is the primary entry point. Feed it real attack events and
        receive a complete distorted reality that replaces every trace.

        Args:
            attack_events: List of real attack event dicts.
            siem_patterns: Attack patterns to poison SIEM against.
            narrative_tone: Tone for the cover narrative.
            target_name: Name of the target environment.
            duration_hours: Duration the narrative spans.

        Returns:
            DistortedReality with all four deception layers applied.
        """
        reality_id = f"rdf_{uuid.uuid4().hex[:12]}"
        t0 = time.monotonic()

        # Layer 1 & 2: Replace every attack log and weave narrative
        narrative = self.weave_narrative(
            events_list=attack_events,
            tone=narrative_tone,
            duration_hours=duration_hours,
        )

        # Collect all replacement entries
        all_entries = list(narrative.events)

        # Layer 3: Poison SIEM for each pattern
        siem_payloads: List[SIEMPoisonPayload] = []
        if siem_patterns:
            for pattern in siem_patterns:
                payloads = self.poison_siem(pattern, duration_days=30)
                siem_payloads.extend(payloads)

        # Layer 4: Generate green dashboard
        dashboard = self.generate_dashboard_view(target_name=target_name)

        # Build the complete distorted reality
        replaced_originals: Dict[str, str] = {}
        for entry in all_entries:
            if entry.replaced_original_hash and entry.replaced_original:
                replaced_originals[entry.replaced_original_hash] = entry.replaced_original

        # Coverage: percentage of log sources covered
        sources_covered = set(e.source for e in all_entries if e.source)
        coverage = len(sources_covered) / len(LogSource) if len(LogSource) > 0 else 1.0

        reality = DistortedReality(
            reality_id=reality_id,
            target_environment=target_name,
            created_at=datetime.now(timezone.utc).isoformat(),
            narratives=[narrative],
            log_entries=all_entries,
            siem_payloads=siem_payloads,
            dashboard=dashboard,
            replaced_originals=replaced_originals,
            coverage_score=round(coverage, 3),
            consistency_score=narrative.consistency_score,
        )

        elapsed_ms = (time.monotonic() - t0) * 1000
        logger.info("reality_distortion: full deception complete (id=%s, %d entries, %d siem payloads, %.0f ms, coverage=%.0f%%)",
                     reality_id, len(all_entries), len(siem_payloads),
                     elapsed_ms, reality.coverage_score * 100)

        self._reality_sessions[reality_id] = reality
        return reality

    # ── Template Management ──────────────────────────────────────────────────

    def add_template(self, template: LogTemplate) -> None:
        """Add a custom log template to the library.

        Args:
            template: The LogTemplate to add.
        """
        if template.source not in self._template_library:
            self._template_library[template.source] = []
        self._template_library[template.source].append(template)
        logger.debug("reality_distortion: added template %s for source %s",
                      template.template_id, template.source.value)

    def list_templates(self, source: Optional[LogSource] = None) -> List[Dict[str, Any]]:
        """List available log templates.

        Args:
            source: Filter by log source (None = all).

        Returns:
            List of template metadata dicts.
        """
        templates = []
        sources = [source] if source else list(self._template_library.keys())
        for src in sources:
            for tmpl in self._template_library.get(src, []):
                templates.append({
                    "template_id": tmpl.template_id,
                    "source": tmpl.source.value,
                    "category": tmpl.category,
                    "severity": tmpl.severity,
                    "fidelity_score": tmpl.fidelity_score,
                })
        return templates

    def get_replacement(self, original_hash: str) -> Optional[LogEntry]:
        """Retrieve a replacement entry by its original log hash.

        Args:
            original_hash: SHA-256 prefix of the original log.

        Returns:
            The LogEntry replacement, or None.
        """
        return self._replaced.get(original_hash)

    def get_session(self, reality_id: str) -> Optional[DistortedReality]:
        """Retrieve a deception session by ID."""
        return self._reality_sessions.get(reality_id)

    def list_sessions(self) -> List[Dict[str, Any]]:
        """List all deception sessions."""
        return [
            {
                "reality_id": r.reality_id,
                "target": r.target_environment,
                "created_at": r.created_at,
                "entries": len(r.log_entries),
                "narratives": len(r.narratives),
                "siem_payloads": len(r.siem_payloads),
                "coverage": r.coverage_score,
                "consistency": r.consistency_score,
            }
            for r in self._reality_sessions.values()
        ]

    def get_stats(self) -> Dict[str, Any]:
        """Return engine statistics."""
        template_count = sum(len(v) for v in self._template_library.values())
        return {
            "templates_total": template_count,
            "log_sources": [s.value for s in self._template_library.keys()],
            "siem_platforms": _SIEM_PLATFORMS,
            "replaced_logs": len(self._replaced),
            "active_sessions": len(self._reality_sessions),
            "seed": self._seed,
        }

    def reset(self) -> None:
        """Reset the engine state (clear sessions and replacements)."""
        self._replaced.clear()
        self._reality_sessions.clear()
        logger.info("reality_distortion: engine reset")
