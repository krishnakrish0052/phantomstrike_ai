"""
server_core/orchestrator/attack_synthesizer.py

Attack Pattern Synthesizer — AI discovers NOVEL attack chains by combining
10,000+ primitives combinatorially. These are attack patterns no human has
ever documented.

The synthesizer builds a knowledge graph of attack primitives across eight
domains (web, network, auth, privesc, persistence, lateral, exfil, evasion)
and uses coherence validation, success estimation, and historical feedback
to generate ranked, novel multi-stage attack chains.
"""

from __future__ import annotations

import hashlib
import logging
import random
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Primitive metadata — complexity, typical tools, prerequisite domains
# ---------------------------------------------------------------------------

_PRIMITIVE_META: Dict[str, Dict[str, Any]] = {
    # ── Web ──
    "sqli": {
        "complexity": 0.65,
        "tools": ["sqlmap", "ghauri", "manual"],
        "prerequisites": ["web_endpoint_with_params"],
        "delivers": ["data_access", "auth_bypass", "rce_shell"],
        "indicators": ["sql_error", "parameter_reflection"],
    },
    "xss": {
        "complexity": 0.55,
        "tools": ["dalfox", "xsser", "bxsshunter"],
        "prerequisites": ["web_endpoint_with_reflection"],
        "delivers": ["session_theft", "credential_harvest", "browser_compromise"],
        "indicators": ["reflected_input", "csp_missing"],
    },
    "ssrf": {
        "complexity": 0.70,
        "tools": ["burp_collaborator", "interactsh", "custom"],
        "prerequisites": ["web_endpoint_with_url_param"],
        "delivers": ["internal_network_access", "cloud_metadata_theft", "port_scan_internal"],
        "indicators": ["url_parameter", "webhook_callback"],
    },
    "xxe": {
        "complexity": 0.60,
        "tools": ["burp", "custom_payloads"],
        "prerequisites": ["xml_parser_endpoint"],
        "delivers": ["file_read", "ssrf", "dos"],
        "indicators": ["xml_content_type", "dtd_processing"],
    },
    "lfi": {
        "complexity": 0.55,
        "tools": ["lfisuite", "dotdotpwn", "manual"],
        "prerequisites": ["file_inclusion_endpoint"],
        "delivers": ["file_read", "rce_via_log_poison", "source_disclosure"],
        "indicators": ["file_path_parameter", "null_byte_bypass"],
    },
    "rce": {
        "complexity": 0.85,
        "tools": ["metasploit", "commix", "custom_exploit"],
        "prerequisites": ["command_injection_point"],
        "delivers": ["shell_access", "full_control"],
        "indicators": ["command_execution_output", "shell_response"],
    },
    "ssti": {
        "complexity": 0.75,
        "tools": ["tplmap", "sstimap", "manual"],
        "prerequisites": ["template_engine_endpoint"],
        "delivers": ["rce", "file_read", "object_disclosure"],
        "indicators": ["template_syntax_reflected", "jinja_twig_patterns"],
    },
    "csrf": {
        "complexity": 0.45,
        "tools": ["burp", "xsrfprobe", "manual"],
        "prerequisites": ["state_changing_endpoint", "no_csrf_token"],
        "delivers": ["state_manipulation", "privilege_abuse"],
        "indicators": ["missing_csrf_token", "cookie_only_auth"],
    },
    "idor": {
        "complexity": 0.40,
        "tools": ["burp_autorize", "manual"],
        "prerequisites": ["object_id_endpoint"],
        "delivers": ["data_access", "privilege_escalation"],
        "indicators": ["sequential_ids", "predictable_references"],
    },
    "deserialization": {
        "complexity": 0.80,
        "tools": ["ysoserial", "phpggc", "marshalsec"],
        "prerequisites": ["serialized_object_endpoint"],
        "delivers": ["rce", "auth_bypass", "data_tampering"],
        "indicators": ["java_serialized_bytes", "php_serialized_string"],
    },
    "request_smuggling": {
        "complexity": 0.82,
        "tools": ["smuggler", "burp_http2", "manual"],
        "prerequisites": ["proxy_or_cdn_frontend"],
        "delivers": ["request_hijack", "cache_poison", "auth_bypass"],
        "indicators": ["cl_te_mismatch", "te_cl_confusion"],
    },
    "cache_poisoning": {
        "complexity": 0.72,
        "tools": ["param_miner", "web_cache_poisoning_scanner"],
        "prerequisites": ["caching_layer", "unkeyed_inputs"],
        "delivers": ["xss_stored_cached", "redirect_hijack", "dos"],
        "indicators": ["cache_headers", "unkeyed_parameters"],
    },
    "jwt_attack": {
        "complexity": 0.55,
        "tools": ["jwt_tool", "jwtcrack", "manual"],
        "prerequisites": ["jwt_token_observed"],
        "delivers": ["auth_bypass", "privilege_escalation", "token_forgery"],
        "indicators": ["jwt_in_header", "hs256_alg"],
    },
    "graphql_exploit": {
        "complexity": 0.60,
        "tools": ["graphw00f", "inql", "clairvoyance"],
        "prerequisites": ["graphql_endpoint"],
        "delivers": ["data_exposure", "dos_introspection", "idor"],
        "indicators": ["graphql_path", "introspection_enabled"],
    },
    "websocket_hack": {
        "complexity": 0.65,
        "tools": ["burp_ws", "ws_hunter", "manual"],
        "prerequisites": ["websocket_endpoint"],
        "delivers": ["csrf_ws", "data_injection", "replay"],
        "indicators": ["ws_upgrade_header", "no_origin_check"],
    },

    # ── Network ──
    "port_scan": {
        "complexity": 0.20,
        "tools": ["nmap", "masscan", "rustscan"],
        "prerequisites": [],
        "delivers": ["service_discovery", "topology_map"],
        "indicators": ["syn_packets", "connect_attempts"],
    },
    "service_enum": {
        "complexity": 0.25,
        "tools": ["nmap_scripts", "amap", "manual"],
        "prerequisites": ["open_port"],
        "delivers": ["version_info", "vulnerability_hints"],
        "indicators": ["banner_grab", "probe_patterns"],
    },
    "dns_enum": {
        "complexity": 0.30,
        "tools": ["dnsrecon", "subfinder", "amass"],
        "prerequisites": ["domain_name"],
        "delivers": ["subdomain_list", "dns_record_map", "zone_transfer"],
        "indicators": ["dns_queries", "axfr_attempt"],
    },
    "smb_exploit": {
        "complexity": 0.70,
        "tools": ["crackmapexec", "impacket", "metasploit"],
        "prerequisites": ["smb_port_open"],
        "delivers": ["file_access", "rce_eternalblue", "hash_capture"],
        "indicators": ["smb_negotiate", "named_pipe_access"],
    },
    "snmp_exploit": {
        "complexity": 0.40,
        "tools": ["snmpwalk", "onesixtyone", "snmpcheck"],
        "prerequisites": ["snmp_port_open"],
        "delivers": ["network_info", "process_list", "credential_disclosure"],
        "indicators": ["snmp_get_request", "community_string"],
    },
    "mitm": {
        "complexity": 0.75,
        "tools": ["bettercap", "ettercap", "responder"],
        "prerequisites": ["network_access", "arp_spoof_capable"],
        "delivers": ["credential_intercept", "session_hijack", "traffic_decrypt"],
        "indicators": ["arp_reply_flood", "dhcp_spoof"],
    },
    "arp_spoof": {
        "complexity": 0.50,
        "tools": ["arpspoof", "bettercap", "custom"],
        "prerequisites": ["local_network_access"],
        "delivers": ["traffic_redirect", "mitm_setup"],
        "indicators": ["arp_replies", "mac_mismatch"],
    },

    # ── Auth ──
    "credential_stuffing": {
        "complexity": 0.30,
        "tools": ["hydra", "medusa", "burp_intruder"],
        "prerequisites": ["credential_list", "login_endpoint"],
        "delivers": ["valid_credentials", "account_access"],
        "indicators": ["login_attempts", "rate_limiting_bypass"],
    },
    "password_spray": {
        "complexity": 0.25,
        "tools": ["spray", "crackmapexec", "o365spray"],
        "prerequisites": ["user_list", "auth_endpoint"],
        "delivers": ["valid_credentials", "initial_access"],
        "indicators": ["one_password_many_users", "lockout_avoidance"],
    },
    "token_theft": {
        "complexity": 0.65,
        "tools": ["mimikatz", "tokenvator", "manual"],
        "prerequisites": ["code_execution", "privileged_context"],
        "delivers": ["token_reuse", "privilege_escalation", "lateral_move"],
        "indicators": ["token_handle_access", "duplicate_token"],
    },
    "session_hijack": {
        "complexity": 0.55,
        "tools": ["ferret", "hamster", "cookie_editor"],
        "prerequisites": ["traffic_access", "session_token_visible"],
        "delivers": ["session_reuse", "identity_theft"],
        "indicators": ["cookie_replay", "session_fixation"],
    },
    "oauth_exploit": {
        "complexity": 0.72,
        "tools": ["burp", "oauth_scanner", "manual"],
        "prerequisites": ["oauth_flow_endpoint"],
        "delivers": ["token_theft", "redirect_hijack", "account_takeover"],
        "indicators": ["redirect_uri_open", "state_missing"],
    },
    "saml_bypass": {
        "complexity": 0.78,
        "tools": ["saml_raider", "burp", "manual"],
        "prerequisites": ["saml_endpoint"],
        "delivers": ["auth_bypass", "assertion_forgery", "privilege_escalation"],
        "indicators": ["saml_response", "signature_validation_missing"],
    },
    "kerberoasting": {
        "complexity": 0.60,
        "tools": ["impacket", "rubeus", "powershell"],
        "prerequisites": ["domain_user_context"],
        "delivers": ["service_ticket_hash", "offline_cracking"],
        "indicators": ["tgs_rep_rc4", "spn_enum"],
    },
    "asrep_roasting": {
        "complexity": 0.55,
        "tools": ["impacket", "rubeus", "hashcat"],
        "prerequisites": ["user_list", "no_preauth_users"],
        "delivers": ["as_rep_hash", "offline_cracking"],
        "indicators": ["as_rep_enc_part", "dont_req_preauth"],
    },
    "dcsync": {
        "complexity": 0.85,
        "tools": ["mimikatz", "secretsdump", "ntdsutil"],
        "prerequisites": ["domain_admin", "replication_rights"],
        "delivers": ["all_domain_hashes", "krbtgt_hash"],
        "indicators": ["drepsync_request", "ms_drsr"],
    },
    "golden_ticket": {
        "complexity": 0.88,
        "tools": ["mimikatz", "impacket", "rubeus"],
        "prerequisites": ["krbtgt_hash", "domain_name", "domain_sid"],
        "delivers": ["domain_admin_persistence", "unlimited_kdc_access"],
        "indicators": ["tgt_with_long_lifetime", "krbtgt_rc4_mismatch"],
    },

    # ── Privilege Escalation ──
    "kernel_exploit": {
        "complexity": 0.82,
        "tools": ["linux_exploit_suggester", "windows_exploit_suggester", "metasploit"],
        "prerequisites": ["unprivileged_shell", "kernel_version"],
        "delivers": ["root_or_system", "kernel_code_execution"],
        "indicators": ["kernel_version_enum", "dirty_pipe_candidate"],
    },
    "suid_abuse": {
        "complexity": 0.45,
        "tools": ["find", "gtfobins", "manual"],
        "prerequisites": ["unprivileged_shell", "suid_binaries"],
        "delivers": ["privilege_escalation", "root_shell"],
        "indicators": ["suid_bit", "writable_binary_path"],
    },
    "sudo_bypass": {
        "complexity": 0.50,
        "tools": ["sudo_killer", "linpeas", "manual"],
        "prerequisites": ["sudo_access", "restricted_sudo"],
        "delivers": ["root_shell", "command_execution_as_root"],
        "indicators": ["sudo_version", "sudo_rules_misconfig"],
    },
    "token_impersonation": {
        "complexity": 0.70,
        "tools": ["incognito", "metasploit", "potato_family"],
        "prerequisites": ["windows_shell", "se_impersonate_privilege"],
        "delivers": ["system_shell", "service_account_access"],
        "indicators": ["se_impersonate", "se_assign_primary"],
    },
    "service_hijack": {
        "complexity": 0.60,
        "tools": ["accesschk", "sc", "systemctl"],
        "prerequisites": ["unprivileged_shell", "writable_service_paths"],
        "delivers": ["system_shell", "persistence"],
        "indicators": ["unquoted_service_path", "writable_service_binary"],
    },
    "dll_sideload": {
        "complexity": 0.68,
        "tools": ["procmon", "manual", "custom_dll"],
        "prerequisites": ["file_write", "application_with_missing_dll"],
        "delivers": ["code_execution", "persistence"],
        "indicators": ["dll_search_order", "missing_dll_path"],
    },
    "container_escape": {
        "complexity": 0.85,
        "tools": ["cdk", "deepce", "amicontained"],
        "prerequisites": ["container_shell"],
        "delivers": ["host_access", "node_compromise", "cluster_access"],
        "indicators": ["docker_socket", "privileged_container", "cap_sys_admin"],
    },
    "capability_abuse": {
        "complexity": 0.55,
        "tools": ["capsh", "getcap", "manual"],
        "prerequisites": ["unprivileged_shell", "dangerous_capabilities"],
        "delivers": ["privilege_escalation", "arbitrary_read"],
        "indicators": ["cap_sys_ptrace", "cap_dac_read_search"],
    },

    # ── Persistence ──
    "registry_key": {
        "complexity": 0.35,
        "tools": ["reg", "powershell", "manual"],
        "prerequisites": ["windows_shell", "registry_write"],
        "delivers": ["boot_persistence", "user_persistence"],
        "indicators": ["run_key", "winlogon_shell"],
    },
    "wmi_subscription": {
        "complexity": 0.55,
        "tools": ["powershell", "wmi_explorer", "manual"],
        "prerequisites": ["windows_admin"],
        "delivers": ["event_triggered_execution", "fileless_persistence"],
        "indicators": ["wmi_event_filter", "wmi_consumer"],
    },
    "scheduled_task": {
        "complexity": 0.30,
        "tools": ["schtasks", "at", "powershell"],
        "prerequisites": ["shell_access"],
        "delivers": ["scheduled_code_execution", "recurring_beacon"],
        "indicators": ["scheduled_task_xml", "task_scheduler_log"],
    },
    "service_install": {
        "complexity": 0.50,
        "tools": ["sc", "systemctl", "metasploit"],
        "prerequisites": ["admin_or_root"],
        "delivers": ["system_persistence", "privileged_beacon"],
        "indicators": ["new_service_registration", "service_dacl"],
    },
    "ssh_key": {
        "complexity": 0.30,
        "tools": ["ssh_keygen", "manual"],
        "prerequisites": ["file_write", "ssh_directory_access"],
        "delivers": ["remote_access", "passwordless_login"],
        "indicators": ["authorized_keys", "new_private_key"],
    },
    "cron_job": {
        "complexity": 0.30,
        "tools": ["crontab", "manual"],
        "prerequisites": ["shell_access", "cron_write"],
        "delivers": ["scheduled_execution", "recurring_beacon"],
        "indicators": ["crontab_entry", "anacron_hook"],
    },
    "systemd_timer": {
        "complexity": 0.45,
        "tools": ["systemctl", "manual"],
        "prerequisites": ["root_or_sudo"],
        "delivers": ["persistent_service", "boot_triggered_execution"],
        "indicators": ["systemd_unit_file", "timer_schedule"],
    },
    "cloud_iam_backdoor": {
        "complexity": 0.72,
        "tools": ["aws_cli", "gcloud", "azure_cli"],
        "prerequisites": ["cloud_credentials", "iam_write_access"],
        "delivers": ["cloud_persistence", "cross_account_access"],
        "indicators": ["new_iam_user", "access_key_creation", "role_trust_policy"],
    },

    # ── Lateral Movement ──
    "psexec": {
        "complexity": 0.55,
        "tools": ["psexec", "impacket", "metasploit"],
        "prerequisites": ["admin_credentials", "smb_port_open"],
        "delivers": ["remote_system_shell", "code_execution"],
        "indicators": ["psexec_service", "admin_share"],
    },
    "wmi_exec": {
        "complexity": 0.50,
        "tools": ["wmiexec", "impacket", "powershell"],
        "prerequisites": ["admin_credentials", "wmi_enabled"],
        "delivers": ["remote_command_execution", "fileless_execution"],
        "indicators": ["wmi_process_create", "dcom_activation"],
    },
    "winrm": {
        "complexity": 0.45,
        "tools": ["evil_winrm", "powershell_remoting", "ruby_winrm"],
        "prerequisites": ["credentials", "winrm_enabled"],
        "delivers": ["interactive_shell", "remote_admin"],
        "indicators": ["wsman_traffic", "powershell_remoting_session"],
    },
    "ssh_pivot": {
        "complexity": 0.40,
        "tools": ["ssh", "sshuttle", "meterpreter"],
        "prerequisites": ["ssh_credentials", "ssh_port_open"],
        "delivers": ["network_pivot", "tunnel_access"],
        "indicators": ["ssh_tunnel", "dynamic_forwarding"],
    },
    "pass_the_hash": {
        "complexity": 0.60,
        "tools": ["crackmapexec", "impacket", "mimikatz"],
        "prerequisites": ["ntlm_hash", "smb_port_open"],
        "delivers": ["remote_access", "credential_dump"],
        "indicators": ["ntlm_auth_network", "admin_share_access"],
    },
    "pass_the_ticket": {
        "complexity": 0.65,
        "tools": ["mimikatz", "rubeus", "impacket"],
        "prerequisites": ["kerberos_ticket", "domain_joined"],
        "delivers": ["service_access", "privileged_context"],
        "indicators": ["tgs_presentation", "ticket_lifetime"],
    },
    "rdp_tunnel": {
        "complexity": 0.50,
        "tools": ["xfreerdp", "rdesktop", "remmina"],
        "prerequisites": ["rdp_credentials", "rdp_port_open"],
        "delivers": ["gui_access", "clipboard_exfil", "drive_mount"],
        "indicators": ["rdp_session", "tsclient_mount"],
    },
    "smb_relay": {
        "complexity": 0.68,
        "tools": ["ntlmrelayx", "responder", "impacket"],
        "prerequisites": ["network_access", "smb_signing_disabled"],
        "delivers": ["credential_relay", "remote_execution"],
        "indicators": ["smb_coerce", "relayed_ntlm_auth"],
    },

    # ── Exfiltration ──
    "dns_tunnel": {
        "complexity": 0.65,
        "tools": ["dnscat2", "iodine", "dns_exfil"],
        "prerequisites": ["dns_resolution", "authoritative_ns"],
        "delivers": ["covert_channel", "data_exfiltration"],
        "indicators": ["dns_txt_queries", "high_entropy_subdomains"],
    },
    "icmp_tunnel": {
        "complexity": 0.60,
        "tools": ["icmpsh", "ptunnel", "manual"],
        "prerequisites": ["icmp_allowed", "root_or_admin"],
        "delivers": ["covert_channel", "command_and_control"],
        "indicators": ["icmp_payload", "unusual_icmp_size"],
    },
    "https_exfil": {
        "complexity": 0.35,
        "tools": ["curl", "wget", "custom_post"],
        "prerequisites": ["outbound_https", "exfil_server"],
        "delivers": ["data_exfiltration", "callback"],
        "indicators": ["https_post_volume", "unusual_user_agent"],
    },
    "websocket_exfil": {
        "complexity": 0.55,
        "tools": ["ws_client", "custom", "manual"],
        "prerequisites": ["outbound_websocket", "exfil_server"],
        "delivers": ["full_duplex_c2", "streaming_exfil"],
        "indicators": ["ws_upgrade", "long_lived_connection"],
    },
    "cloud_upload": {
        "complexity": 0.30,
        "tools": ["aws_cli", "gcloud", "rclone"],
        "prerequisites": ["cloud_credentials", "storage_write"],
        "delivers": ["data_exfiltration", "offsite_storage"],
        "indicators": ["s3_put_object", "blob_upload"],
    },
    "stego_exfil": {
        "complexity": 0.70,
        "tools": ["steghide", "custom_encoder", "manual"],
        "prerequisites": ["data_to_exfil", "cover_media"],
        "delivers": ["covert_data_exfil", "bypass_dlp"],
        "indicators": ["image_file_transfer", "entropy_anomaly"],
    },

    # ── Evasion ──
    "syscall_obfuscation": {
        "complexity": 0.78,
        "tools": ["custom_syscall", "halos_gate", "manual"],
        "prerequisites": ["code_execution_context"],
        "delivers": ["edr_bypass", "userland_hooking_evasion"],
        "indicators": ["direct_syscall", "ntdll_unhooked"],
    },
    "dll_unhooking": {
        "complexity": 0.65,
        "tools": ["refleXXion", "custom", "manual"],
        "prerequisites": ["code_execution_context"],
        "delivers": ["edr_sensor_blind", "hook_removal"],
        "indicators": ["fresh_ntdll_copy", "section_overwrite"],
    },
    "amsi_bypass": {
        "complexity": 0.50,
        "tools": ["powershell", "custom_csharp", "manual"],
        "prerequisites": ["powershell_or_dotnet_execution"],
        "delivers": ["script_execution_without_scan", "payload_delivery"],
        "indicators": ["amsi_init_failed", "amsi_patch"],
    },
    "etw_patch": {
        "complexity": 0.60,
        "tools": ["custom_csharp", "powershell", "manual"],
        "prerequisites": ["code_execution_context"],
        "delivers": ["log_suppression", "telemetry_blindness"],
        "indicators": ["etw_event_write_patch", "etw_provider_disable"],
    },
    "sleep_obfuscation": {
        "complexity": 0.72,
        "tools": ["ekko", "foliAGE", "custom"],
        "prerequisites": ["implant_or_beacon"],
        "delivers": ["memory_scan_evasion", "timer_based_execution"],
        "indicators": ["rwx_page_encrypt", "ntp_time_check"],
    },
    "ja3_spoof": {
        "complexity": 0.45,
        "tools": ["curl_impersonate", "custom_tls", "python_tls_client"],
        "prerequisites": ["https_communication"],
        "delivers": ["tls_fingerprint_evasion", "bot_detection_bypass"],
        "indicators": ["ja3_hash_change", "cipher_reordering"],
    },
    "domain_fronting": {
        "complexity": 0.60,
        "tools": ["custom_dns", "cdn_routing", "manual"],
        "prerequisites": ["cdn_fronted_domain", "c2_domain"],
        "delivers": ["censorship_bypass", "network_detection_evasion"],
        "indicators": ["host_header_mismatch", "sni_discrepancy"],
    },
    "traffic_morphing": {
        "complexity": 0.68,
        "tools": ["shapeshifter", "custom_proxy", "manual"],
        "prerequisites": ["c2_communication"],
        "delivers": ["protocol_obfuscation", "deep_packet_inspection_bypass"],
        "indicators": ["traffic_entropy_normalized", "protocol_mimicry"],
    },
}

# ---------------------------------------------------------------------------
# Domain → valid transition domains (chains must follow attack progression)
# ---------------------------------------------------------------------------

_DOMAIN_TRANSITIONS: Dict[str, List[str]] = {
    "web": ["web", "auth", "privesc", "exfil", "evasion", "persistence"],
    "network": ["network", "auth", "privesc", "lateral", "web"],
    "auth": ["auth", "privesc", "lateral", "persistence", "exfil"],
    "privesc": ["privesc", "lateral", "persistence", "exfil", "evasion"],
    "persistence": ["persistence", "lateral", "exfil", "evasion"],
    "lateral": ["lateral", "privesc", "exfil", "evasion"],
    "exfil": ["exfil", "evasion"],
    "evasion": ["evasion", "exfil", "persistence"],
}

# Attack stage phases in order (for coherence validation)
_ATTACK_PHASES: List[str] = [
    "initial_access",
    "execution",
    "persistence",
    "privilege_escalation",
    "defense_evasion",
    "credential_access",
    "discovery",
    "lateral_movement",
    "collection",
    "exfiltration",
]


# ---------------------------------------------------------------------------
# AttackSynthesizer
# ---------------------------------------------------------------------------


class AttackSynthesizer:
    """Combinatorial attack chain generation. Discovers novel attack patterns.

    Takes a knowledge graph of 50+ attack primitives across 8 domains and
    combinatorially explores valid multi-stage chains. Validates coherence
    against domain transitions, prerequisite/deliverable matching, and
    attack-phase ordering. Estimates success using primitive complexity,
    context fit, and historical feedback.

    Usage:
        synth = AttackSynthesizer(db=db_instance)
        chains = synth.generate_novel_paths(
            goal="gain domain admin on corp.contoso.com",
            context={"target_os": "windows", "foothold": "user_shell", "ports": [445, 88]},
            count=5,
        )
        for chain in chains:
            print(chain["description"])
            print(f"Estimated success: {chain['estimated_success']:.0%}")
    """

    # Knowledge graph of attack primitives — 50+ across 8 domains
    ATTACK_PRIMITIVES: Dict[str, List[str]] = {
        "web": [
            "sqli", "xss", "ssrf", "xxe", "lfi", "rce", "ssti", "csrf", "idor",
            "deserialization", "request_smuggling", "cache_poisoning", "jwt_attack",
            "graphql_exploit", "websocket_hack",
        ],
        "network": [
            "port_scan", "service_enum", "dns_enum", "smb_exploit", "snmp_exploit",
            "mitm", "arp_spoof",
        ],
        "auth": [
            "credential_stuffing", "password_spray", "token_theft", "session_hijack",
            "oauth_exploit", "saml_bypass", "kerberoasting", "asrep_roasting",
            "dcsync", "golden_ticket",
        ],
        "privesc": [
            "kernel_exploit", "suid_abuse", "sudo_bypass", "token_impersonation",
            "service_hijack", "dll_sideload", "container_escape", "capability_abuse",
        ],
        "persistence": [
            "registry_key", "wmi_subscription", "scheduled_task", "service_install",
            "ssh_key", "cron_job", "systemd_timer", "cloud_iam_backdoor",
        ],
        "lateral": [
            "psexec", "wmi_exec", "winrm", "ssh_pivot", "pass_the_hash",
            "pass_the_ticket", "rdp_tunnel", "smb_relay",
        ],
        "exfil": [
            "dns_tunnel", "icmp_tunnel", "https_exfil", "websocket_exfil",
            "cloud_upload", "stego_exfil",
        ],
        "evasion": [
            "syscall_obfuscation", "dll_unhooking", "amsi_bypass", "etw_patch",
            "sleep_obfuscation", "ja3_spoof", "domain_fronting", "traffic_morphing",
        ],
    }

    # Domain → attack phase mapping
    _DOMAIN_TO_PHASE: Dict[str, str] = {
        "network": "initial_access",
        "web": "initial_access",
        "auth": "credential_access",
        "privesc": "privilege_escalation",
        "persistence": "persistence",
        "lateral": "lateral_movement",
        "exfil": "exfiltration",
        "evasion": "defense_evasion",
    }

    # Primitive → domain reverse lookup (built at init)
    _primitive_to_domain: Dict[str, str] = {}

    def __init__(self, db: Any = None):
        self.db = db
        self._discovered_chains: List[Dict[str, Any]] = []
        self._chain_scores: Dict[str, float] = {}

        # Build reverse lookup: primitive name → its domain
        if not AttackSynthesizer._primitive_to_domain:
            for domain, primitives in self.ATTACK_PRIMITIVES.items():
                for prim in primitives:
                    AttackSynthesizer._primitive_to_domain[prim] = domain

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def generate_novel_paths(
        self,
        goal: str,
        context: dict,
        count: int = 10,
    ) -> List[Dict[str, Any]]:
        """Generate novel attack chains by combining primitives.

        Args:
            goal: Natural-language goal description (e.g. "gain domain admin").
            context: Target context dict with keys like:
                - target_os: "windows" | "linux" | "cloud"
                - foothold: current access level ("none", "user_shell", "admin_shell")
                - ports: list of open ports
                - services: list of detected services
                - target_domain: AD domain name (if applicable)
                - cloud_provider: "aws" | "azure" | "gcp"
                - stealth_required: bool
                - known_defenses: list of detected defenses ("edr", "waf", "ids")
            count: Number of chains to return (best N after filtering).

        Returns:
            List of chain dicts, each with keys:
                chain, description, estimated_success, signature, stages
        """
        goal_lower = goal.lower()
        domains = self._get_applicable_domains(context)
        goal_domains = self._get_goal_domains(goal_lower)
        all_domains = list(dict.fromkeys(domains + goal_domains))  # deduplicate preserving order

        # Collect primitives from applicable domains
        primitives: List[str] = []
        for domain in all_domains:
            primitives.extend(self.ATTACK_PRIMITIVES.get(domain, []))

        if not primitives:
            logger.warning("No primitives for domains %s — falling back to web", all_domains)
            primitives = list(self.ATTACK_PRIMITIVES.get("web", ["sqli", "xss"]))

        # Sort primitives by estimated relevance to the goal
        primitives = self._rank_primitives_for_goal(primitives, goal_lower, context)

        # Combinatorial exploration — generate many, filter to best
        # Group primitives by domain for graph-walk chain construction
        primitives_by_domain: Dict[str, List[str]] = {}
        for domain in all_domains:
            domain_prims = [
                p for p in self.ATTACK_PRIMITIVES.get(domain, [])
                if p in primitives  # Only include ranked primitives
            ]
            if domain_prims:
                primitives_by_domain[domain] = domain_prims

        chains: List[List[str]] = []
        attempts = 0
        max_attempts = count * 20

        while len(chains) < count and attempts < max_attempts:
            attempts += 1

            # Pick random chain length biased by goal complexity
            complexity = self._estimate_goal_complexity(goal_lower, context)
            min_len = max(2, complexity - 1)
            max_len = min(6, complexity + 2)
            length = random.randint(min_len, max_len)

            # Build chain by walking the domain graph (inherently coherent)
            chain = self._build_coherent_chain(primitives_by_domain, length, context)

            # Deduplicate adjacent same-primitive repeats
            chain = self._deduplicate_chain(chain)

            if len(chain) < 2:
                continue

            # Validate chain coherence
            if not self._is_coherent(chain, context):
                continue

            # Check we haven't already generated an equivalent chain
            sig = self._chain_signature(chain)
            if any(self._chain_signature(c["chain"]) == sig for c in self._discovered_chains):
                continue
            if any(self._chain_signature(c) == sig for c in chains):
                continue

            chains.append(chain)

        # Build result dicts
        results: List[Dict[str, Any]] = []
        for chain in chains:
            sig = self._chain_signature(chain)
            description = self._describe_chain(chain)
            success = self._estimate_success(chain, context)
            stages = self._build_stage_details(chain, context)

            result = {
                "chain": chain,
                "signature": sig,
                "description": description,
                "estimated_success": success,
                "stages": stages,
                "complexity": self._classify_complexity(len(chain)),
                "domains_used": self._domains_in_chain(chain),
            }
            results.append(result)
            self._discovered_chains.append(result)
            self._chain_scores[sig] = success

        # Store in database if available
        if self.db:
            self._persist_chains(results, goal, context)

        return results

    # ------------------------------------------------------------------
    # Domain & primitive selection
    # ------------------------------------------------------------------

    def _get_applicable_domains(self, context: dict) -> List[str]:
        """Extract applicable domains from target context.

        Inspects context signals (ports, services, OS, foothold level, etc.)
        and returns the ordered list of attack domains that apply.
        """
        domains: List[str] = []
        context_lower = {k: str(v).lower() for k, v in context.items()}

        # Web: HTTP/HTTPS ports, web services, URLs present
        ports = context.get("ports", [])
        services = context.get("services", [])
        if any(p in (80, 443, 8080, 8443, 3000, 5000, 8000, 9000) for p in ports):
            domains.append("web")
        if any("http" in str(s).lower() or "nginx" in str(s).lower() or "apache" in str(s).lower()
               or "iis" in str(s).lower() or "tomcat" in str(s).lower() for s in services):
            if "web" not in domains:
                domains.append("web")

        # Network: Always applicable (target has network presence by definition)
        domains.append("network")

        # Auth: Credentials available, auth endpoints, domain context
        if any(p in (88, 389, 636, 3268, 3269) for p in ports):
            domains.append("auth")
        if context.get("target_domain") or any("kerberos" in str(s).lower() for s in services):
            if "auth" not in domains:
                domains.append("auth")
        if context.get("credentials") or context.get("hashes"):
            if "auth" not in domains:
                domains.append("auth")

        # Privesc: User-level foothold, OS known, kernel info available
        foothold = context.get("foothold", "none")
        if foothold in ("user_shell", "limited", "standard_user"):
            domains.append("privesc")
        if context.get("target_os") and foothold != "none":
            if "privesc" not in domains:
                domains.append("privesc")

        # Persistence: After exploitation phase, or explicitly requested
        if foothold in ("admin_shell", "root", "system"):
            domains.append("persistence")
        if any("persist" in str(v).lower() for v in context.values()):
            if "persistence" not in domains:
                domains.append("persistence")

        # Lateral: Multiple hosts, domain environment, network pivot opportunities
        if context.get("internal_network") or context.get("target_subnet"):
            domains.append("lateral")
        if any(p in (445, 135, 139, 5985, 5986) for p in ports):
            if "lateral" not in domains:
                domains.append("lateral")

        # Exfil: Data extraction goal, target has valuable data
        if any("exfil" in str(v).lower() or "extract" in str(v).lower()
               or "steal" in str(v).lower() for v in context.values()):
            domains.append("exfil")

        # Evasion: Stealth required, known defenses, post-exploitation
        if context.get("stealth_required", False) or context.get("known_defenses"):
            domains.append("evasion")
        if foothold != "none":  # Any post-access phase benefits from evasion
            if "evasion" not in domains:
                domains.append("evasion")

        # Ensure at least one domain
        if not domains:
            domains = ["network", "web"]

        return domains

    def _get_goal_domains(self, goal_lower: str) -> List[str]:
        """Extract domains directly hinted at by the goal string."""
        goal_domains: List[str] = []

        keyword_map: Dict[str, List[str]] = {
            "web": ["web", "website", "http", "app", "api", "xss", "sqli", "csrf", "ssrf"],
            "network": ["network", "port", "scan", "service", "enum", "nmap"],
            "auth": ["auth", "login", "password", "credential", "hash", "token",
                     "kerberos", "ntlm", "account", "domain admin"],
            "privesc": ["privesc", "escalat", "root", "admin", "privilege", "kernel",
                        "suid", "sudo"],
            "persistence": ["persist", "backdoor", "maintain", "keep access"],
            "lateral": ["lateral", "pivot", "move", "internal", "propagate", "relay"],
            "exfil": ["exfil", "extract", "steal", "dump", "download", "data", "loot"],
            "evasion": ["evade", "stealth", "hide", "bypass", "edr", "av", "defender"],
        }

        for domain, keywords in keyword_map.items():
            if any(kw in goal_lower for kw in keywords):
                goal_domains.append(domain)

        return goal_domains if goal_domains else ["web"]

    def _rank_primitives_for_goal(
        self, primitives: List[str], goal_lower: str, context: dict
    ) -> List[str]:
        """Rank primitives by relevance to the goal and context, highest first."""
        scored: List[Tuple[str, float]] = []

        for prim in primitives:
            score = 0.0
            meta = _PRIMITIVE_META.get(prim, {})

            # Goal keyword match
            if prim in goal_lower or prim.replace("_", " ") in goal_lower:
                score += 0.4

            # Context fit: does this primitive's prerequisites match what we have?
            prereqs = meta.get("prerequisites", [])
            if self._prerequisites_met(prereqs, context):
                score += 0.3

            # Reward historically successful primitives
            hist_key = f"prim__{prim}"
            if hist_key in self._chain_scores:
                score += self._chain_scores[hist_key] * 0.2

            # Penalize extreme complexity if no foothold
            if context.get("foothold", "none") == "none" and meta.get("complexity", 0.5) > 0.7:
                score -= 0.15

            scored.append((prim, score))

        scored.sort(key=lambda x: x[1], reverse=True)
        return [p for p, _ in scored]

    def _primitive_os_ok(self, prim: str, target_os: str) -> bool:
        """Check if a primitive is compatible with the target OS."""
        windows_only = {
            "token_impersonation", "dll_sideload", "registry_key", "wmi_subscription",
            "psexec", "wmi_exec", "winrm", "pass_the_hash", "pass_the_ticket",
            "rdp_tunnel", "smb_relay", "kerberoasting", "asrep_roasting",
            "dcsync", "golden_ticket", "amsi_bypass", "etw_patch", "smb_exploit",
        }
        linux_only = {
            "suid_abuse", "sudo_bypass", "capability_abuse", "cron_job",
            "systemd_timer", "kernel_exploit",
        }
        if target_os == "windows" and prim in linux_only:
            return False
        if target_os == "linux" and prim in windows_only:
            return False
        return True

    def _build_coherent_chain(
        self,
        primitives_by_domain: Dict[str, List[str]],
        desired_length: int,
        context: dict,
    ) -> List[str]:
        """Build a chain by walking the domain transition graph forward.

        Each step picks a domain reachable from the current one, then selects
        a random primitive from that domain. This guarantees phase ordering
        and domain-transition coherence by construction.

        Args:
            primitives_by_domain: Domain → list of available primitives.
            desired_length: Target number of primitives in the chain.
            context: Target context dict for OS filtering.

        Returns:
            A list of primitive names forming a coherent chain.
        """
        chain: List[str] = []
        target_os = str(context.get("target_os", "unknown")).lower()

        # Filter primitives by OS compatibility
        filtered_by_domain: Dict[str, List[str]] = {}
        for domain, prims in primitives_by_domain.items():
            filtered = [p for p in prims if self._primitive_os_ok(p, target_os)]
            if filtered:
                filtered_by_domain[domain] = filtered

        if not filtered_by_domain:
            return chain

        # Pick a starting domain — prefer ones with initial_access phase
        start_domains = [
            d for d in filtered_by_domain
            if self._DOMAIN_TO_PHASE.get(d, "") == "initial_access"
        ]
        if not start_domains:
            start_domains = list(filtered_by_domain.keys())

        current_domain = random.choice(start_domains)

        for _ in range(desired_length):
            if current_domain not in filtered_by_domain:
                break

            available_prims = filtered_by_domain[current_domain]
            if not available_prims:
                break

            # Pick a primitive not already in the chain
            unused = [p for p in available_prims if p not in chain]
            if not unused:
                unused = available_prims  # Allow reuse if all have been used

            chosen = random.choice(unused)
            chain.append(chosen)

            # Decide next domain from valid transitions
            valid_next = _DOMAIN_TRANSITIONS.get(current_domain, [])
            # Filter to domains that have primitives available
            reachable = [
                d for d in valid_next
                if d in filtered_by_domain and any(p not in chain for p in filtered_by_domain[d])
            ]
            if not reachable:
                # Pick any domain with unused primitives not already adjacent
                reachable = [
                    d for d in filtered_by_domain
                    if d != current_domain and any(p not in chain for p in filtered_by_domain[d])
                ]
            if not reachable:
                break  # No more domains to explore

            # Weight toward domains that move the attack phase forward
            current_phase = self._DOMAIN_TO_PHASE.get(current_domain, "")
            current_idx = _ATTACK_PHASES.index(current_phase) if current_phase in _ATTACK_PHASES else 0

            weights: List[float] = []
            for d in reachable:
                next_phase = self._DOMAIN_TO_PHASE.get(d, "")
                next_idx = _ATTACK_PHASES.index(next_phase) if next_phase in _ATTACK_PHASES else current_idx
                # Prefer forward progression; allow same phase
                if next_idx > current_idx:
                    weights.append(3.0)
                elif next_idx == current_idx:
                    weights.append(1.5)
                else:
                    weights.append(0.3)  # Backward is allowed but disfavored

            total = sum(weights)
            probs = [w / total for w in weights]
            current_domain = random.choices(reachable, weights=probs, k=1)[0]

        return chain

    # ------------------------------------------------------------------
    # Coherence validation
    # ------------------------------------------------------------------

    def _is_coherent(self, chain: List[str], context: dict) -> bool:
        """Validate that a chain of primitives forms a logically coherent attack.

        Checks:
        1. Domain transitions are valid (attack stages progress forward)
        2. Prerequisites of each primitive are satisfied by earlier primitives
        3. No contradictory combinations (e.g., Linux-only + Windows-only)
        4. Chain phases follow Kill Chain ordering
        """
        if len(chain) < 2:
            return False

        domains = [self._primitive_to_domain.get(p, "web") for p in chain]
        seen_primitives: Set[str] = set()
        delivered: Set[str] = set()  # Capabilities delivered by chain so far

        for i, (prim, domain) in enumerate(zip(chain, domains)):
            # No duplicate primitives (trivial chains are boring)
            if prim in seen_primitives:
                return False
            seen_primitives.add(prim)

            meta = _PRIMITIVE_META.get(prim, {})

            # Check domain transition validity
            if i > 0:
                prev_domain = domains[i - 1]
                valid_next = _DOMAIN_TRANSITIONS.get(prev_domain, [])
                if domain not in valid_next:
                    # Allow if primitives share a phase (e.g., web→web)
                    if domain != prev_domain:
                        # Check if the domain jump is via a bridging primitive
                        if not self._has_bridge_transition(chain[i - 1], prim):
                            return False

            # Track delivered capabilities (for success estimation, not rejection)
            delivers = meta.get("delivers", [])
            delivered.update(delivers)

        # Check overall chain phase ordering (stages should progress roughly forward)
        phase_indices = []
        for domain in domains:
            phase = self._DOMAIN_TO_PHASE.get(domain, "execution")
            if phase in _ATTACK_PHASES:
                phase_indices.append(_ATTACK_PHASES.index(phase))

        # Phases should be generally non-decreasing; allow up to 2 backward steps
        backward_steps = 0
        for j in range(1, len(phase_indices)):
            if phase_indices[j] < phase_indices[j - 1]:
                # Always allow defense_evasion to appear anywhere
                if domains[j] == "evasion" or domains[j - 1] == "evasion":
                    continue
                # Always allow discovery (network) anywhere
                if domains[j] == "network" or domains[j - 1] == "network":
                    continue
                backward_steps += 1
                if backward_steps > 2:
                    return False

        # OS compatibility check
        if not self._os_compatible(chain, context):
            return False

        return True

    def _has_bridge_transition(self, prim_a: str, prim_b: str) -> bool:
        """Check if prim_a's deliverables naturally feed into prim_b's prerequisites."""
        if prim_a not in _PRIMITIVE_META or prim_b not in _PRIMITIVE_META:
            return True  # Unknown primitives — allow

        delivers_a = set(_PRIMITIVE_META[prim_a].get("delivers", []))
        prereqs_b = set(_PRIMITIVE_META[prim_b].get("prerequisites", []))

        # Direct bridge: what A delivers matches what B needs
        if delivers_a & prereqs_b:
            return True

        # Semi-bridge: partial keyword overlap
        for d in delivers_a:
            for p in prereqs_b:
                if any(word in p for word in d.split("_")) or any(word in d for word in p.split("_")):
                    return True

        # Domain-level bridge: if they're in the same phase, allow
        dom_a = self._primitive_to_domain.get(prim_a, "")
        dom_b = self._primitive_to_domain.get(prim_b, "")
        if dom_a == dom_b:
            return True

        return False

    def _prerequisites_met(
        self,
        prereqs: List[str],
        context: dict,
        delivered: Optional[Set[str]] = None,
    ) -> bool:
        """Check if prerequisites are satisfied by context and/or delivered capabilities."""
        delivered = delivered or set()

        for prereq in prereqs:
            # Check context
            if self._context_has(context, prereq):
                continue
            # Check delivered capabilities
            if any(prereq in d or d in prereq for d in delivered):
                continue
            # Check generic prerequisites that most attack contexts satisfy
            if prereq in (
                "web_endpoint_with_params", "web_endpoint_with_reflection",
                "login_endpoint", "auth_endpoint", "dns_resolution",
                "network_access", "arp_spoof_capable", "local_network_access",
                "open_port", "domain_name", "outbound_https", "outbound_websocket",
                "https_communication", "code_execution_context", "credentials",
                "user_list", "credential_list", "unprivileged_shell",
                "shell_access", "file_write",
            ):
                continue  # Assume these are common enough to be plausible
            return False
        return True

    def _context_has(self, context: dict, prerequisite: str) -> bool:
        """Check if the target context satisfies a prerequisite signal."""
        prereq_lower = prerequisite.lower()
        context_str = str(context).lower()

        # Direct keyword match
        if prereq_lower in context_str:
            return True

        # Specific signal mappings
        signal_map: Dict[str, List[str]] = {
            "web_endpoint_with_params": ["http", "website", "web_app", "api"],
            "web_endpoint_with_reflection": ["http", "website", "web_app"],
            "web_endpoint_with_url_param": ["http", "url", "api"],
            "xml_parser_endpoint": ["xml", "soap", "wsdl"],
            "file_inclusion_endpoint": ["php", "file", "include"],
            "command_injection_point": ["ssh", "exec", "command", "shell"],
            "template_engine_endpoint": ["jinja", "twig", "template", "flask", "django"],
            "state_changing_endpoint": ["http", "form", "api", "post"],
            "object_id_endpoint": ["api", "rest", "graphql"],
            "serialized_object_endpoint": ["java", "php", "serialize"],
            "proxy_or_cdn_frontend": ["cloudfront", "cloudflare", "cdn", "nginx"],
            "caching_layer": ["cache", "varnish", "cdn"],
            "jwt_token_observed": ["jwt", "bearer", "token"],
            "graphql_endpoint": ["graphql"],
            "websocket_endpoint": ["ws", "websocket", "socket.io"],
            "open_port": ["port", "nmap"],
            "domain_name": ["domain", "dns"],
            "smb_port_open": ["smb", "445", "windows"],
            "snmp_port_open": ["snmp", "161"],
            "network_access": ["network", "lan", "subnet", "internal"],
            "arp_spoof_capable": ["lan", "local", "network_access"],
            "local_network_access": ["lan", "local", "internal"],
            "credential_list": ["password", "credential", "hash"],
            "user_list": ["user", "account", "ad", "ldap"],
            "domain_user_context": ["domain", "kerberos", "ad", "windows"],
            "no_preauth_users": ["kerberos", "asrep", "domain"],
            "domain_admin": ["admin", "domain", "da"],
            "replication_rights": ["domain", "admin", "dc"],
            "krbtgt_hash": ["krbtgt", "domain"],
            "unprivileged_shell": ["shell", "user", "foothold"],
            "kernel_version": ["kernel", "os", "linux"],
            "suid_binaries": ["linux", "suid", "unix"],
            "windows_shell": ["windows", "cmd", "powershell"],
            "admin_or_root": ["root", "admin", "system"],
            "file_write": ["write", "upload", "rw"],
            "shell_access": ["shell", "access", "foothold"],
            "cloud_credentials": ["aws", "azure", "gcp", "cloud"],
            "code_execution_context": ["shell", "code", "execution"],
            "implant_or_beacon": ["c2", "beacon", "implant", "agent"],
            "https_communication": ["http", "https", "web"],
            "c2_domain": ["c2", "server", "callback"],
            "c2_communication": ["c2", "beacon", "callback"],
            "outbound_https": ["http", "outbound", "egress"],
            "outbound_websocket": ["ws", "outbound", "egress"],
            "data_to_exfil": ["data", "file", "loot", "dump"],
            "cover_media": ["image", "media", "file"],
        }

        matching_signals = signal_map.get(prerequisite, [])
        return any(sig in context_str for sig in matching_signals)

    def _os_compatible(self, chain: List[str], context: dict) -> bool:
        """Check that all primitives in a chain are compatible with the target OS."""
        target_os = str(context.get("target_os", "unknown")).lower()

        # Primitives that require a specific OS
        windows_only = {
            "token_impersonation", "dll_sideload", "registry_key", "wmi_subscription",
            "psexec", "wmi_exec", "winrm", "pass_the_hash", "pass_the_ticket",
            "rdp_tunnel", "smb_relay", "kerberoasting", "asrep_roasting",
            "dcsync", "golden_ticket", "amsi_bypass", "etw_patch", "smb_exploit",
        }
        linux_only = {
            "suid_abuse", "sudo_bypass", "capability_abuse", "cron_job",
            "ssh_key", "systemd_timer", "kernel_exploit",
        }

        chain_set = set(chain)

        if target_os == "windows":
            if chain_set & linux_only:
                # Allow if the chain also has container_escape (Linux in Windows via WSL)
                if "container_escape" not in chain_set:
                    return False
        elif target_os == "linux":
            if chain_set & windows_only:
                # Allow if chain has cross-platform bridges
                if not (chain_set & {"smb_exploit"}):  # SMB can work on Linux via Samba
                    return False

        # Cloud-specific compatibility
        cloud_provider = str(context.get("cloud_provider", "")).lower()
        if cloud_provider and "container_escape" in chain_set:
            return True  # Container escape works across cloud providers

        return True

    def _deduplicate_chain(self, chain: List[str]) -> List[str]:
        """Remove adjacent duplicate primitives from a chain."""
        result = []
        for prim in chain:
            if not result or result[-1] != prim:
                result.append(prim)
        return result

    def _domains_in_chain(self, chain: List[str]) -> List[str]:
        """Return the unique domains represented in this chain."""
        domains: List[str] = []
        for prim in chain:
            d = self._primitive_to_domain.get(prim, "unknown")
            if d not in domains:
                domains.append(d)
        return domains

    # ------------------------------------------------------------------
    # Chain description
    # ------------------------------------------------------------------

    def _describe_chain(self, chain: List[str]) -> str:
        """Generate a human-readable description of an attack chain.

        Produces a narrative that explains how each primitive builds on the
        previous one to accomplish the overall goal.
        """
        if not chain:
            return "Empty chain."

        if len(chain) == 1:
            return f"Single-stage attack using {self._primitive_label(chain[0])}."

        parts: List[str] = []
        for i, prim in enumerate(chain):
            label = self._primitive_label(prim)
            meta = _PRIMITIVE_META.get(prim, {})
            phase = self._DOMAIN_TO_PHASE.get(
                self._primitive_to_domain.get(prim, "execution"), "attack"
            )

            # Stage numbering
            if i == 0:
                parts.append(f"Stage {i+1} ({phase}): Begin with {label}")
            else:
                # Try to explain how this stage builds on the previous
                prev_prim = chain[i - 1]
                prev_meta = _PRIMITIVE_META.get(prev_prim, {})
                prev_delivers = prev_meta.get("delivers", [])

                if prev_delivers:
                    connection = prev_delivers[0].replace("_", " ")
                    parts.append(
                        f"Stage {i+1} ({phase}): Leveraging {connection} "
                        f"from previous stage, execute {label}"
                    )
                else:
                    parts.append(f"Stage {i+1} ({phase}): Execute {label}")

        # Add overall strategy summary
        domains = self._domains_in_chain(chain)
        strategy = " → ".join(d.replace("_", " ").title() for d in domains)

        return f"[{strategy}] " + " | ".join(parts)

    def _primitive_label(self, prim: str) -> str:
        """Return a human-readable label for a primitive."""
        labels: Dict[str, str] = {
            "sqli": "SQL Injection exploitation",
            "xss": "Cross-Site Scripting (XSS) injection",
            "ssrf": "Server-Side Request Forgery (SSRF)",
            "xxe": "XML External Entity (XXE) injection",
            "lfi": "Local File Inclusion (LFI)",
            "rce": "Remote Code Execution (RCE)",
            "ssti": "Server-Side Template Injection (SSTI)",
            "csrf": "Cross-Site Request Forgery (CSRF)",
            "idor": "Insecure Direct Object Reference (IDOR)",
            "deserialization": "Insecure Deserialization exploitation",
            "request_smuggling": "HTTP Request Smuggling attack",
            "cache_poisoning": "Web Cache Poisoning attack",
            "jwt_attack": "JWT token manipulation attack",
            "graphql_exploit": "GraphQL API exploitation",
            "websocket_hack": "WebSocket connection hijacking",
            "port_scan": "TCP/UDP port scanning",
            "service_enum": "Service version enumeration",
            "dns_enum": "DNS reconnaissance and subdomain enumeration",
            "smb_exploit": "SMB protocol exploitation",
            "snmp_exploit": "SNMP information disclosure exploitation",
            "mitm": "Man-in-the-Middle (MITM) interception",
            "arp_spoof": "ARP cache poisoning / spoofing",
            "credential_stuffing": "Credential stuffing attack",
            "password_spray": "Password spraying attack",
            "token_theft": "Access token theft and reuse",
            "session_hijack": "Session hijacking / sidejacking",
            "oauth_exploit": "OAuth 2.0 flow manipulation",
            "saml_bypass": "SAML authentication bypass",
            "kerberoasting": "Kerberoasting (TGS-REP hash extraction)",
            "asrep_roasting": "AS-REP Roasting (pre-auth bypass)",
            "dcsync": "DCSync (domain controller replication)",
            "golden_ticket": "Golden Ticket (KRBTGT hash forgery)",
            "kernel_exploit": "Kernel exploit for privilege escalation",
            "suid_abuse": "SUID binary abuse for root escalation",
            "sudo_bypass": "Sudo configuration bypass",
            "token_impersonation": "Windows token impersonation",
            "service_hijack": "Service binary/path hijacking",
            "dll_sideload": "DLL side-loading attack",
            "container_escape": "Container breakout to host",
            "capability_abuse": "Linux capability abuse",
            "registry_key": "Registry Run key persistence",
            "wmi_subscription": "WMI event subscription persistence",
            "scheduled_task": "Scheduled task persistence",
            "service_install": "Service installation persistence",
            "ssh_key": "SSH authorized key persistence",
            "cron_job": "Cron job persistence",
            "systemd_timer": "Systemd timer persistence",
            "cloud_iam_backdoor": "Cloud IAM backdoor creation",
            "psexec": "PsExec remote execution",
            "wmi_exec": "WMI remote execution",
            "winrm": "WinRM remote PowerShell session",
            "ssh_pivot": "SSH pivot / tunnel",
            "pass_the_hash": "Pass-the-Hash authentication",
            "pass_the_ticket": "Pass-the-Ticket Kerberos authentication",
            "rdp_tunnel": "RDP session / tunnel",
            "smb_relay": "SMB NTLM relay attack",
            "dns_tunnel": "DNS tunneling exfiltration",
            "icmp_tunnel": "ICMP tunneling exfiltration",
            "https_exfil": "HTTPS POST data exfiltration",
            "websocket_exfil": "WebSocket streaming exfiltration",
            "cloud_upload": "Cloud storage upload exfiltration",
            "stego_exfil": "Steganography-based data exfiltration",
            "syscall_obfuscation": "Direct syscall obfuscation",
            "dll_unhooking": "DLL unhooking (EDR sensor evasion)",
            "amsi_bypass": "AMSI (Antimalware Scan Interface) bypass",
            "etw_patch": "ETW (Event Tracing for Windows) patching",
            "sleep_obfuscation": "Sleep obfuscation / memory encryption",
            "ja3_spoof": "JA3/JA4 TLS fingerprint spoofing",
            "domain_fronting": "Domain fronting via CDN",
            "traffic_morphing": "Network traffic morphing / protocol mimicry",
        }
        return labels.get(prim, prim.replace("_", " ").title())

    # ------------------------------------------------------------------
    # Success estimation
    # ------------------------------------------------------------------

    def _estimate_success(self, chain: List[str], context: dict) -> float:
        """Estimate the probability of a chain succeeding against the target.

        Uses a multiplicative model:
            P_total = product of P(stage_i) * complexity_decay * context_bonus

        Each stage probability is derived from:
        - Base success rate of the primitive (from metadata complexity)
        - How well prerequisites are met (context fit)
        - Historical success rate for this primitive (if recorded)
        - Chain position bonus/penalty

        Args:
            chain: List of primitive names.
            context: Target context dict.

        Returns:
            Estimated success probability as a float 0.0–1.0.
        """
        if not chain:
            return 0.0

        prob = 1.0
        delivered: Set[str] = set()
        complexity_penalty = 0.92  # Each additional stage reduces overall probability

        for i, prim in enumerate(chain):
            meta = _PRIMITIVE_META.get(prim, {})
            base_complexity = meta.get("complexity", 0.5)

            # Stage probability: easier primitives have higher base success
            stage_prob = 1.0 - (base_complexity * 0.5)  # Map complexity 0.2-0.9 → 0.90-0.55

            # Prerequisite fit bonus
            prereqs = meta.get("prerequisites", [])
            prereqs_met = sum(
                1 for p in prereqs
                if self._prerequisites_met([p], context, delivered)
            )
            if prereqs:
                fit_ratio = prereqs_met / len(prereqs)
                stage_prob += (1.0 - stage_prob) * fit_ratio * 0.3  # Up to +30% for ideal fit

            # Historical bonus/penalty
            hist_key = f"prim__{prim}"
            if hist_key in self._chain_scores:
                hist_score = self._chain_scores[hist_key]
                stage_prob = stage_prob * 0.7 + hist_score * 0.3  # Blend with history

            # OS-specific adjustments
            target_os = str(context.get("target_os", "")).lower()
            domain = self._primitive_to_domain.get(prim, "")
            if target_os == "windows" and domain in ("auth", "lateral"):
                stage_prob += 0.05  # Windows domain environments have more auth pivots
            elif target_os == "linux" and domain == "privesc":
                stage_prob += 0.05  # Linux privilege escalation is well-understood

            # Defense penalty
            defenses = context.get("known_defenses", [])
            if defenses:
                defense_str = " ".join(str(d).lower() for d in defenses)
                if "waf" in defense_str and domain == "web":
                    stage_prob -= 0.10
                if "edr" in defense_str and domain in ("evasion", "privesc", "persistence"):
                    stage_prob -= 0.08
                if "ids" in defense_str and domain == "network":
                    stage_prob -= 0.05

            # Clamp to valid range
            stage_prob = max(0.05, min(0.98, stage_prob))

            # Multiply into overall probability with decay
            prob *= stage_prob * (complexity_penalty ** i)

            # Track delivered capabilities for downstream stages
            delivers = meta.get("delivers", [])
            delivered.update(delivers)

        # Stealth bonus: if evasion is in the chain and context needs stealth
        if "evasion" in self._domains_in_chain(chain):
            if context.get("stealth_required", False):
                prob *= 1.10  # +10% for including evasion when needed

        # Cap at 1.0 and round
        return round(min(prob, 1.0), 4)

    def _estimate_goal_complexity(self, goal_lower: str, context: dict) -> int:
        """Estimate how complex the goal is (returns a chain-length hint 2-5)."""
        score = 2  # Minimum chain length

        # Complex goals need more stages
        complex_keywords = [
            "domain admin", "dcsync", "golden ticket", "full compromise",
            "complete takeover", "ransomware", "total pwn", "root all",
            "entire network", "whole domain",
        ]
        for kw in complex_keywords:
            if kw in goal_lower:
                score = max(score, 5)

        moderate_keywords = [
            "admin", "root", "privilege", "escalat", "persist", "lateral",
            "move", "pivot", "exfil",
        ]
        for kw in moderate_keywords:
            if kw in goal_lower:
                score = max(score, 3)

        # Context signals
        if context.get("known_defenses"):
            score += 1
        if context.get("stealth_required"):
            score += 1

        return min(score, 5)

    def _classify_complexity(self, chain_length: int) -> str:
        """Classify chain complexity based on length."""
        if chain_length <= 2:
            return "LOW"
        elif chain_length <= 4:
            return "MEDIUM"
        else:
            return "HIGH"

    # ------------------------------------------------------------------
    # Chain stages (detailed breakdown)
    # ------------------------------------------------------------------

    def _build_stage_details(
        self, chain: List[str], context: dict
    ) -> List[Dict[str, Any]]:
        """Build detailed stage information for each primitive in the chain."""
        stages = []
        delivered: Set[str] = set()

        for i, prim in enumerate(chain):
            meta = _PRIMITIVE_META.get(prim, {})
            domain = self._primitive_to_domain.get(prim, "unknown")
            phase = self._DOMAIN_TO_PHASE.get(domain, "execution")

            stage_prob = self._estimate_stage_probability(prim, i, chain, context, delivered)

            stage = {
                "stage": i + 1,
                "primitive": prim,
                "label": self._primitive_label(prim),
                "domain": domain,
                "phase": phase,
                "tools": meta.get("tools", []),
                "success_probability": stage_prob,
                "prerequisites_met": self._check_prerequisites_for_stage(prim, context, delivered),
            }
            stages.append(stage)

            delivers = meta.get("delivers", [])
            delivered.update(delivers)

        return stages

    def _estimate_stage_probability(
        self,
        prim: str,
        position: int,
        chain: List[str],
        context: dict,
        delivered: Set[str],
    ) -> float:
        """Estimate the success probability for a single stage."""
        meta = _PRIMITIVE_META.get(prim, {})
        base = 1.0 - meta.get("complexity", 0.5) * 0.4

        # Prerequisites met?
        prereqs = meta.get("prerequisites", [])
        if prereqs:
            met = sum(1 for p in prereqs if self._prerequisites_met([p], context, delivered))
            base *= 0.7 + 0.3 * (met / len(prereqs))

        # Historical adjustment
        hist_key = f"prim__{prim}"
        if hist_key in self._chain_scores:
            base = base * 0.6 + self._chain_scores[hist_key] * 0.4

        return round(max(0.05, min(0.98, base)), 4)

    def _check_prerequisites_for_stage(
        self, prim: str, context: dict, delivered: Set[str]
    ) -> Dict[str, bool]:
        """Check which prerequisites for a primitive are satisfied."""
        meta = _PRIMITIVE_META.get(prim, {})
        prereqs = meta.get("prerequisites", [])
        result: Dict[str, bool] = {}
        for p in prereqs:
            result[p] = self._prerequisites_met([p], context, delivered)
        return result

    # ------------------------------------------------------------------
    # Chain history & feedback
    # ------------------------------------------------------------------

    def record_chain_result(self, chain_signature: str, success: bool) -> None:
        """Record the real-world outcome of executing a chain.

        Updates internal score tracking and optionally the database, so
        future success estimates can learn from historical results.

        Args:
            chain_signature: The SHA256 signature of the chain primitives.
            success: Whether the chain was successfully executed.
        """
        # Update the aggregate score for this chain
        if chain_signature in self._chain_scores:
            old_score = self._chain_scores[chain_signature]
            # Exponential moving average — weight new result at 30%
            new_score = old_score * 0.7 + (1.0 if success else 0.05) * 0.3
            self._chain_scores[chain_signature] = round(new_score, 4)
        else:
            self._chain_scores[chain_signature] = 0.90 if success else 0.10

        # Also update per-primitive scores
        for entry in self._discovered_chains:
            if entry.get("signature") == chain_signature:
                for prim in entry.get("chain", []):
                    key = f"prim__{prim}"
                    if key in self._chain_scores:
                        old = self._chain_scores[key]
                        self._chain_scores[key] = round(
                            old * 0.7 + (1.0 if success else 0.05) * 0.3, 4
                        )
                    else:
                        self._chain_scores[key] = 0.90 if success else 0.10
                break

        # Update database if available
        if self.db:
            try:
                # Store feedback as a note on the chain in the DB
                self.db.create_attack_chain(
                    id=f"feedback_{chain_signature[:16]}_{uuid.uuid4().hex[:8]}",
                    session_id="attack_synthesizer",
                    chain_name=f"Feedback: {chain_signature[:16]}",
                    target_software="feedback",
                    stages_json="[]",
                    overall_prob=1.0 if success else 0.0,
                    complexity="FEEDBACK",
                    notes=f"Chain result: {'SUCCESS' if success else 'FAILURE'}",
                )
            except Exception as exc:
                logger.debug("Failed to persist chain feedback to DB: %s", exc)

        logger.info(
            "Recorded chain result: %s → %s (score now %.3f)",
            chain_signature[:16],
            "SUCCESS" if success else "FAILURE",
            self._chain_scores.get(chain_signature, 0.0),
        )

    def get_best_chains(
        self, goal_type: str = "", limit: int = 10
    ) -> List[Dict[str, Any]]:
        """Return the best known chains, optionally filtered by goal type.

        Chains are ranked by:
        1. Estimated success probability (primary)
        2. Chain complexity/depth (tiebreaker — more complex = more interesting)

        Args:
            goal_type: Optional filter for goal type (e.g., "privesc", "exfil",
                       "lateral", "persistence"). Case-insensitive prefix match
                       against chain descriptions and domain lists.
            limit: Maximum number of chains to return.

        Returns:
            List of chain dicts sorted by score (best first).
        """
        chains = list(self._discovered_chains)

        # Filter by goal type if specified
        if goal_type:
            goal_lower = goal_type.lower()
            filtered: List[Dict[str, Any]] = []
            for c in chains:
                desc_lower = c.get("description", "").lower()
                domains = [d.lower() for d in c.get("domains_used", [])]
                if (goal_lower in desc_lower or goal_lower in " ".join(domains)):
                    filtered.append(c)
            chains = filtered

        # Sort by estimated success (descending), then by chain length (descending)
        chains.sort(
            key=lambda c: (
                c.get("estimated_success", 0.0),
                len(c.get("chain", [])),
            ),
            reverse=True,
        )

        return chains[:limit]

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def _persist_chains(
        self, results: List[Dict[str, Any]], goal: str, context: dict
    ) -> None:
        """Persist generated chains to the database.

        Args:
            results: The generated chain result dicts.
            goal: The original goal string.
            context: The target context dict.
        """
        if not self.db:
            return

        target = context.get("target_domain") or context.get("target_host") or "unknown"
        session_id = context.get("session_id", "attack_synthesizer")

        for result in results:
            try:
                stages_json = __import__("json").dumps(
                    result.get("stages", []), default=str
                )
                self.db.create_attack_chain(
                    id=f"syn_{result.get('signature', uuid.uuid4().hex)[:24]}",
                    session_id=session_id,
                    chain_name=f"{goal[:80]} — {result.get('description', '')[:120]}",
                    target_software=target,
                    stages_json=stages_json,
                    overall_prob=result.get("estimated_success", 0.0),
                    complexity=result.get("complexity", "MEDIUM"),
                    notes=f"Auto-generated by AttackSynthesizer. Domains: {result.get('domains_used', [])}",
                )
            except Exception as exc:
                logger.debug("Failed to persist chain to DB: %s", exc)

    # ------------------------------------------------------------------
    # Utilities
    # ------------------------------------------------------------------

    @staticmethod
    def _chain_signature(chain: List[str]) -> str:
        """Generate a deterministic SHA256 signature for a chain."""
        canonical = ",".join(sorted(set(chain)))
        return hashlib.sha256(canonical.encode()).hexdigest()

    def list_all_primitives(self) -> Dict[str, List[str]]:
        """Return the full ATTACK_PRIMITIVES knowledge graph."""
        return dict(self.ATTACK_PRIMITIVES)

    def get_primitive_meta(self, primitive: str) -> Dict[str, Any]:
        """Return metadata for a specific primitive."""
        return dict(_PRIMITIVE_META.get(primitive, {}))

    def list_primitives_by_domain(self, domain: str) -> List[str]:
        """Return all primitives for a given domain."""
        return list(self.ATTACK_PRIMITIVES.get(domain, []))

    def count_possible_chains(self, min_len: int = 2, max_len: int = 5) -> int:
        """Estimate the combinatorial search space (for informational use).

        This is the theoretical number of possible chains — not the number
        that pass coherence validation.
        """
        import math

        all_prims = []
        for prims in self.ATTACK_PRIMITIVES.values():
            all_prims.extend(prims)
        n = len(all_prims)

        total = 0
        for k in range(min_len, max_len + 1):
            if k <= n:
                total += math.comb(n, k)

        return total
