"""
server_core/engine/false_flag_ops.py

Automated False Flag Operations — frame any threat actor for the operation.

When PhantomStrike conducts an operation, attribution is everything. This engine
ensures that forensic investigators at Mandiant, CrowdStrike, or Unit 42 will
confidently attribute the activity to a DIFFERENT threat actor — not us.

The engine maintains a comprehensive database of known APT TTPs, infrastructure
patterns, tool signatures, language markers, and behavioral quirks. It can
impersonate any of eight major threat actors with high forensic fidelity,
generating artifacts that survive even the most rigorous attribution analysis.

Actors modelled:
  APT28 (Fancy Bear)      — Russian GRU, spear-phishing, X-Agent, Moscow TZ
  APT29 (Cozy Bear)       — Russian SVR, supply chain, WellMess, St. Petersburg TZ
  Lazarus Group           — North Korean, SWIFT attacks, Manusec, Pyongyang TZ
  APT41                   — Chinese, supply chain + espionage, Winnti, Shanghai TZ
  FIN7                    — Russian cybercrime, POS malware, Cobalt Strike
  Sandworm                — Russian GRU, ICS/OT attacks, Industroyer, Kiev TZ
  Equation Group          — NSA-linked, firmware implants, STRAITBIZARRE
  TA505                   — Cybercrime, Clop ransomware, Dridex, TFlower

Classes:
  FalseFlagOps               — main orchestrator
  ActorProfile               — complete TTP profile for one threat actor
  ForensicArtifact           — a generated piece of false attribution evidence
  AttributionSimulation      — simulated forensic analysis to validate the frame
"""

from __future__ import annotations

import hashlib
import json
import logging
import math
import random
import textwrap
import threading
import time
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# ── Constants ──────────────────────────────────────────────────────────────────

# Known actor database — intelligence is weaponised information.
_ACTOR_DB: Dict[str, Dict[str, Any]] = {
    "apt28": {
        "aliases": ["Fancy Bear", "Sofacy", "Sednit", "Pawn Storm", "STRONTIUM", "Tsar Team"],
        "sponsor": "Russian GRU (Unit 26165)",
        "ttps": [
            "spear_phishing_office_macros", "zerologon_exploit", "eternalblue",
            "credential_theft_mimikatz", "dns_tunneling", "http_backdoor",
            "outlook_web_access_bruteforce", "vpn_exploit_pulse_secure",
            "office365_oauth_phish", "roundcube_webmail_exploit",
        ],
        "tools": [
            "X-Agent", "X-Tunnel", "Winmon", "Downdelph", "Zebrocy",
            "Skipper", "GrizzlySteppe", "CHOPSTICK", "Gamefish",
        ],
        "infrastructure": {
            "c2_domains": ["update.microsoft.com.phish", "cdn.azure-secure.com",
                           "outlook-web.access-check.com", "adobe-update.net"],
            "c2_patterns": ["domain_fronting_cdn", "https_over_port_443",
                            "dns_txt_callback", "azure_c2_channels"],
            "hosting": ["VPS in Russia/VPN exit nodes", "compromised WordPress sites",
                        "hacked government servers in former Soviet states"],
            "ip_ranges": ["5.45.x.x", "91.218.x.x", "185.94.x.x"],
        },
        "timing": {
            "timezone": "Europe/Moscow",
            "working_hours": "0400-1400 UTC (Moscow business hours)",
            "patch_tuesday_avoidance": True,
            "campaign_duration_days": [30, 180],
        },
        "language": {
            "primary": "ru",
            "artifacts": ["cyrillic_metadata", "russian_developer_strings",
                          "Russian-language debug symbols", "pdb: C:\\Users\\Пользователь"],
            "mistakes": ["occasional_english_grammar_errors", "UTC+3 time stamps"],
        },
        "targets": ["government", "military", "defense_contractors", "NGOs",
                    "political_organizations", "journalists", "energy"],
        "signature_fingerprint": "apt28_komplex",
    },
    "apt29": {
        "aliases": ["Cozy Bear", "The Dukes", "Nobelium", "YTTRIUM"],
        "sponsor": "Russian SVR",
        "ttps": [
            "supply_chain_compromise", "solarwinds_style_injection",
            "office365_token_theft", "azure_ad_compromise",
            "golden_saml_attack", "kerberoasting", "dcsync",
            "password_spraying", "vpn_mfa_bypass", "onelogin_token_forgery",
        ],
        "tools": [
            "WellMess", "WellMail", "Sunburst", "Teardrop", "Raindrop",
            "Cobalt Strike (modified)", "CrackMapExec (custom)",
            "SUNSHUTTLE", "GOLDMAX", "Sibot",
        ],
        "infrastructure": {
            "c2_domains": ["avsvmcloud.com", "digitalcollege.org",
                           "freescan.io", "database-update.net"],
            "c2_patterns": ["compromised_office365_tenants", "azure_cdn",
                            "aws_cloudfront_fronting", "tor_hidden_services"],
            "hosting": [
                "compromised US-based hosting", "bulletproof hosting Netherlands",
                "AWS EC2 stolen accounts", "Azure VMs with stolen credit cards",
            ],
        },
        "timing": {
            "timezone": "Europe/Moscow",
            "working_hours": "0300-1300 UTC",
            "patch_tuesday_avoidance": False,
            "campaign_duration_days": [60, 365],
        },
        "language": {
            "primary": "ru",
            "artifacts": ["russian_timezone_in_logs", "moscow_business_hours",
                          "cyrillic_test_strings", "Russian VPN exit nodes"],
        },
        "targets": ["government", "think_tanks", "pharmaceutical", "diplomatic",
                    "cloud_service_providers", "microsoft_365_environments"],
        "signature_fingerprint": "apt29_nobelium",
    },
    "lazarus": {
        "aliases": ["Lazarus Group", "HIDDEN COBRA", "ZINC", "Diamond Sleet"],
        "sponsor": "North Korean RGB",
        "ttps": [
            "swift_financial_heist", "cryptocurrency_exchange_theft",
            "spear_phishing_linkedin", "watering_hole_attack",
            "macos_malware_deployment", "supply_chain_package_hijack",
            "defi_bridge_exploit", "fake_job_offers_recruitment",
        ],
        "tools": [
            "Manusec", "Fallchill", "Volgmer", "Brambul", "Hoplight",
            "AppleJeus", "Dtrack", "Blindingcan", "Cryptoistic",
        ],
        "infrastructure": {
            "c2_domains": ["mail.google.com.drive.phish", "linkedin-job.xyz",
                           "crypto-exchange-secure.com", "blockchain-update.net"],
            "c2_patterns": ["social_media_c2", "blockchain_transaction_c2",
                            "tor_onion_services", "discord_webhook_c2"],
            "hosting": [
                "VPS in China/SE Asia", "compromised crypto exchange servers",
                "bulletproof hosting Malaysia", "Linode/DigitalOcean with fake bills",
            ],
        },
        "timing": {
            "timezone": "Asia/Pyongyang",
            "working_hours": "2300-0800 UTC (Pyongyang daytime)",
            "patch_tuesday_avoidance": False,
            "campaign_duration_days": [7, 90],
        },
        "language": {
            "primary": "ko",
            "artifacts": ["korean_metadata", "hangul_comments",
                          "North Korean IP ranges", "Korea-time timestamps"],
            "mistakes": ["engrish_error_patterns", "Korean keyboard layout traces"],
        },
        "targets": ["financial_institutions", "cryptocurrency_exchanges",
                    "defense_contractors", "media", "aerospace"],
        "signature_fingerprint": "lazarus_hiddencobra",
    },
    "apt41": {
        "aliases": ["Winnti Group", "BARIUM", "Wicked Panda", "Double Dragon"],
        "sponsor": "Chinese MSS / PLA",
        "ttps": [
            "supply_chain_compromise", "web_shell_deployment",
            "credential_theft_mimikatz", "active_directory_dominance",
            "vmware_esxi_ransomware", "n-day_exploit_chaining",
            "fake_software_updates", "game_industry_espionage",
        ],
        "tools": [
            "Winnti", "ShadowPad", "PlugX", "Crosswalk", "BOUNCER",
            "Cobalt Strike (licensed)", "Mimikatz variants", "ProcDump",
        ],
        "infrastructure": {
            "c2_domains": ["cdn.cloudflare-phish.com", "api.github-mirror.xyz",
                           "updates.java-oracle.net", "steam-community.cn"],
            "c2_patterns": ["cdn_fronting", "github_c2", "dns_over_https",
                            "citrix_netscaler_abuse"],
            "hosting": [
                "AliCloud ECS instances", "Tencent Cloud",
                "compromised Asian university servers", "Hong Kong VPS",
            ],
        },
        "timing": {
            "timezone": "Asia/Shanghai",
            "working_hours": "0100-1000 UTC",
            "patch_tuesday_avoidance": True,
            "campaign_duration_days": [90, 540],
        },
        "language": {
            "primary": "zh",
            "artifacts": ["simplified_chinese_strings", "Shanghai-time timestamps",
                          "Chinese holidays avoidance", "Chinese developer tools"],
        },
        "targets": ["gaming", "technology", "telecom", "healthcare",
                    "manufacturing", "education"],
        "signature_fingerprint": "apt41_winnti",
    },
    "fin7": {
        "aliases": ["Carbanak", "Anunak", "NAVIGATOR", "GOLD NIAGARA"],
        "sponsor": "Russian-speaking cybercrime (FIN7)",
        "ttps": [
            "spear_phishing_hta", "pos_malware_deployment",
            "cobalt_strike_beaconing", "powershell_empire",
            "cve_exploit_chaining", "rdp_bruteforce",
            "sql_injection_initial_access", "wmi_lateral_movement",
        ],
        "tools": [
            "Carbanak", "Cobalt Strike", "Griffon", "Bateleur",
            "PowerShell Empire", "CrackMapExec", "Mimikatz",
            "LaZagne", "BloodHound (custom fork)",
        ],
        "infrastructure": {
            "c2_domains": ["restaurant-supply.net", "pos-update-server.com",
                           "windows-defender-update.xyz", "hr-benefits-portal.com"],
            "c2_patterns": ["https_cobalt_strike_malleable", "smtp_data_exfil",
                            "dns_over_https_c2", "discord_webhooks"],
            "hosting": [
                "bulletproof hosting Russia", "compromised restaurant chains",
                "VPS Ukraine", "abused cloud free tiers",
            ],
        },
        "timing": {
            "timezone": "Europe/Kiev",
            "working_hours": "0600-1600 UTC",
            "campaign_duration_days": [14, 120],
        },
        "language": {
            "primary": "ru",
            "artifacts": ["russian_language_phishing", "Russian error messages"],
        },
        "targets": ["hospitality", "restaurants", "retail", "gambling",
                    "payment_processors"],
        "signature_fingerprint": "fin7_carbanak",
    },
    "sandworm": {
        "aliases": ["Sandworm", "Voodoo Bear", "IRON VIKING", "TeleBots"],
        "sponsor": "Russian GRU (Unit 74455)",
        "ttps": [
            "ics_ot_attack", "industroyer_deployment", "blackenergy3",
            "notpetya_wiper", "vpn_filter", "oligarchy_critical_infra",
            "scada_protocol_abuse", "power_grid_disruption",
        ],
        "tools": [
            "Industroyer", "Industroyer2", "BlackEnergy", "NotPetya",
            "Olympic Destroyer", "VPNFilter", "Exaramel", "KillDisk",
        ],
        "infrastructure": {
            "c2_domains": ["electro-update.net", "scada-maintenance.com",
                           "power-grid-monitor.xyz", "ics-firmware.net"],
            "c2_patterns": ["tor_hidden_services", "embedded_device_c2",
                            "modbus_steganography", "satellite_link_backup"],
            "hosting": [
                "compromised ICS/SCADA vendors", "bulletproof hosting Russia",
                "hacked ISP infrastructure", "abused satellite internet",
            ],
        },
        "timing": {
            "timezone": "Europe/Kiev",
            "working_hours": "irregular (military operation patterns)",
            "campaign_duration_days": [1, 60],
        },
        "language": {
            "primary": "ru",
            "artifacts": ["russian_ics_terminology", "Russian military jargon"],
        },
        "targets": ["energy", "power_grids", "water_utilities", "industrial_control",
                    "transportation", "government"],
        "signature_fingerprint": "sandworm_industroyer",
    },
    "equation_group": {
        "aliases": ["Equation Group", "NSA Tailored Access Operations"],
        "sponsor": "NSA (United States)",
        "ttps": [
            "firmware_implant", "hard_drive_firmware_backdoor",
            "air_gapped_network_bridging", "usb_worm_propagation",
            "zero_day_deployment", "satellite_link_intercept",
            "certificate_forgery", "BGP_hijack_for_interception",
        ],
        "tools": [
            "STRAITBIZARRE", "GROK", "STRAITACID", "FUNNELOUT",
            "EquationLaser", "EquationDrug", "GrayFish", "DoubleFantasy",
            "EternalBlue", "EternalRomance", "EternalSynergy",
        ],
        "infrastructure": {
            "c2_domains": ["Not applicable — air-gap bridging, USB-based"],
            "c2_patterns": ["hidden_storage_c2", "usb_courier",
                            "satellite_intercept", "physical_implants"],
            "hosting": ["COTS hardware implants", "modified firmware",
                        "compromised CDNs", "NSA data centers"],
        },
        "timing": {
            "timezone": "America/New_York",
            "working_hours": "classified",
            "campaign_duration_days": [365, 3650],
        },
        "language": {
            "primary": "en",
            "artifacts": ["english_error_codes", "NSA codewords in metadata",
                          "Fort Meade geolocation traces", "English documentation"],
        },
        "targets": ["government", "military", "telecom", "financial",
                    "energy", "scientific_research"],
        "signature_fingerprint": "equation_nsa",
    },
    "ta505": {
        "aliases": ["TA505", "Hive0065", "Evil Corp", "Gold Lowell"],
        "sponsor": "Russian-speaking cybercrime (financially motivated)",
        "ttps": [
            "malspam_campaigns", "dridex_banking_trojan", "clop_ransomware",
            "get2_downloader", "sdbot_rat", "flawed_amadey_deployment",
            "email_thread_hijacking", "sharepoint_onedrive_phishing",
        ],
        "tools": [
            "Dridex", "Clop", "TFlower", "Get2", "SDBot",
            "FlawedAmadey", "Cobalt Strike", "TrickBot (affiliate)",
        ],
        "infrastructure": {
            "c2_domains": ["invoice-payment-portal.com", "docusign-secure.net",
                           "covid-relief-gov.org", "payroll-update-hr.com"],
            "c2_patterns": ["https_malspam_c2", "compromised_wordpress_c2",
                            "cloud_storage_exfil", "email_exfil_channels"],
            "hosting": [
                "bulletproof hosting Russia/Ukraine", "compromised SMB servers",
                "abused cloud services", "hacked email servers for spam",
            ],
        },
        "timing": {
            "timezone": "Europe/Moscow",
            "working_hours": "0600-1800 UTC (business hours aligned)",
            "campaign_duration_days": [30, 180],
        },
        "language": {
            "primary": "ru",
            "artifacts": ["russian_ip_ranges", "Russian-language malspam templates"],
        },
        "targets": ["financial_services", "retail", "manufacturing",
                    "healthcare", "education", "government"],
        "signature_fingerprint": "ta505_clop",
    },
}

# Operation types with their forensic markers
_OPERATION_TYPES = {
    "data_exfiltration": {
        "forensic_markers": ["outbound_connections", "compressed_archives",
                             "cloud_storage_api_calls", "dns_tunnel_records"],
        "ttp_set": ["credential_theft_mimikatz", "dns_tunneling", "office365_token_theft"],
    },
    "ransomware_deployment": {
        "forensic_markers": ["shadow_copy_deletion", "ransom_note_files",
                             "encrypted_file_extensions", "registry_modifications"],
        "ttp_set": ["pos_malware_deployment", "clop_ransomware", "esxi_ransomware"],
    },
    "espionage": {
        "forensic_markers": ["email_forwarding_rules", "inbox_search_patterns",
                             "persistent_c2_beacons", "lateral_movement_logs"],
        "ttp_set": ["spear_phishing_office_macros", "azure_ad_compromise", "dcsync"],
    },
    "sabotage": {
        "forensic_markers": ["wiper_artifacts", "mbr_destruction",
                             "backup_deletion", "bootloader_corruption"],
        "ttp_set": ["notpetya_wiper", "industroyer_deployment", "power_grid_disruption"],
    },
}

# ── Data Classes ───────────────────────────────────────────────────────────────

@dataclass
class ActorProfile:
    """Complete threat actor profile for false flag operations."""
    actor_name: str
    aliases: List[str] = field(default_factory=list)
    sponsor: str = ""
    ttps: List[str] = field(default_factory=list)
    tools: List[str] = field(default_factory=list)
    infrastructure: Dict[str, Any] = field(default_factory=dict)
    timing: Dict[str, Any] = field(default_factory=dict)
    language: Dict[str, Any] = field(default_factory=dict)
    targets: List[str] = field(default_factory=list)
    signature_fingerprint: str = ""

    def to_enriched_dict(self) -> Dict:
        """Elite intel profile — every detail weaponised for misdirection."""
        return {
            "actor_name": self.actor_name,
            "aliases": self.aliases,
            "sponsor": self.sponsor,
            "ttps_count": len(self.ttps),
            "top_ttps": self.ttps[:5],
            "tools_count": len(self.tools),
            "signature_tools": self.tools[:3],
            "infra_patterns": self.infrastructure.get("c2_patterns", []),
            "timezone": self.timing.get("timezone", "unknown"),
            "primary_language": self.language.get("primary", "unknown"),
            "fingerprint": self.signature_fingerprint,
        }


@dataclass
class ForensicArtifact:
    """A single piece of false attribution evidence planted at a target."""
    artifact_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    artifact_type: str = ""         # file, registry_key, log_entry, network_flow
    description: str = ""
    location: str = ""
    actor_signature: str = ""
    confidence_to_attribute: float = 0.0
    planted: bool = False
    plant_timestamp: Optional[datetime] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


# ── Main Engine ────────────────────────────────────────────────────────────────

class FalseFlagOps:
    """PhantomStrike False Flag Engine — attribution is a weapon, and we wield it masterfully.

    This engine studies real-world threat actor TTPs and generates forensic
    artifacts so convincing that even Mandiant will attribute our operations
    to someone else. Eight major actors are fully profiled with their tools,
    infrastructure patterns, timing quirks, and language artifacts.

    A good magician doesn't hide the trick — he redirects your attention.
    A great false flag doesn't hide the attack — it plants someone else's signature.
    """

    def __init__(self) -> None:
        self._operations: Dict[str, Dict] = {}
        self._artifacts: Dict[str, List[ForensicArtifact]] = {}
        self._profiles: Dict[str, ActorProfile] = {}
        self._lock = threading.RLock()
        self._build_profiles()
        logger.info("FalseFlagOps: initialised — 8 actor profiles loaded, ready to deceive")

    def _build_profiles(self) -> None:
        """Construct ActorProfile objects from the intelligence database."""
        for name, data in _ACTOR_DB.items():
            self._profiles[name] = ActorProfile(
                actor_name=name,
                aliases=data.get("aliases", []),
                sponsor=data.get("sponsor", ""),
                ttps=data.get("ttps", []),
                tools=data.get("tools", []),
                infrastructure=data.get("infrastructure", {}),
                timing=data.get("timing", {}),
                language=data.get("language", {}),
                targets=data.get("targets", []),
                signature_fingerprint=data.get("signature_fingerprint", ""),
            )

    # ── Actor TTP Loading ──────────────────────────────────────────────────

    def load_actor_ttp(self, actor_name: str) -> Dict:
        """Load the complete TTP profile for a known threat actor.

        Returns the full intelligence dossier: tools, infrastructure, timing
        patterns, language quirks, and target preferences. This is the
        blueprint for impersonation.

        Args:
            actor_name: Canonical short name (apt28, apt29, lazarus, apt41,
                        fin7, sandworm, equation_group, ta505)

        Returns:
            Dict with actor profile or error if unknown.
        """
        actor_name = actor_name.lower().strip()
        profile = self._profiles.get(actor_name)
        if not profile:
            known = list(self._profiles.keys())
            return {
                "success": False,
                "error": f"Unknown actor '{actor_name}'",
                "known_actors": known,
                "hint": "Use one of the canonical names for forensic fidelity",
            }
        return {
            "success": True,
            "actor_name": actor_name,
            "profile": profile.to_enriched_dict(),
            "full_db": _ACTOR_DB.get(actor_name, {}),
        }

    def list_known_actors(self) -> Dict:
        """Return a summary of all modelled threat actors."""
        actors = []
        for name, profile in self._profiles.items():
            actors.append({
                "name": name,
                "aliases": profile.aliases[:3],
                "sponsor": profile.sponsor,
                "tool_count": len(profile.tools),
                "ttp_count": len(profile.ttps),
            })
        return {
            "success": True,
            "total_actors": len(actors),
            "actors": actors,
        }

    # ── Impersonation Engine ───────────────────────────────────────────────

    def mimic_actor(self, actor_name: str, target: str, duration: int = 30) -> Dict:
        """Full-spectrum actor impersonation over a specified duration.

        Deploys the complete false flag operation: infrastructure mimicking
        the actor, tools emulated, language patterns spoofed, and forensic
        trail planted. Duration in days determines the depth of the deception.

        Args:
            actor_name: Actor to impersonate
            target: Target identifier (org name, IP range, domain)
            duration: Campaign duration in days

        Returns:
            Dict with operation details and forensic prediction.
        """
        actor_name = actor_name.lower().strip()
        profile = self._profiles.get(actor_name)
        if not profile:
            return {"success": False, "error": f"Unknown actor '{actor_name}'"}

        op_id = f"ff_{int(time.time())}_{uuid.uuid4().hex[:8]}"

        # Select TTPs to deploy — the actor's greatest hits
        ttps_used = random.sample(profile.ttps, min(4, len(profile.ttps)))
        tools_deployed = random.sample(profile.tools, min(3, len(profile.tools)))
        c2_pattern = random.choice(profile.infrastructure.get("c2_patterns", ["https_standard"]))
        c2_domain = random.choice(profile.infrastructure.get("c2_domains", ["generic-c2.com"]))

        # Timezone spoofing — operations happen during the actor's working hours
        tz = profile.timing.get("timezone", "UTC")

        operation = {
            "id": op_id,
            "target": target,
            "framed_actor": actor_name,
            "actor_aliases": profile.aliases[:3],
            "ttps_used": ttps_used,
            "tools_deployed": tools_deployed,
            "c2_pattern": c2_pattern,
            "c2_domain": c2_domain,
            "timezone_spoofed": tz,
            "language_spoofed": profile.language.get("primary", "en"),
            "duration_days": duration,
            "artifact_count": len(ttps_used) * 3 + len(tools_deployed) * 2,
            "status": "active",
            "created_at": datetime.now(timezone.utc).isoformat(),
        }

        # Generate the forensic artifacts that will be planted
        self._generate_artifacts_for_operation(op_id, profile, target)

        with self._lock:
            self._operations[op_id] = operation

        # Predict what forensic analysts will conclude
        prediction = self.generate_false_attribution_artifacts(actor_name)

        logger.info(
            "FalseFlagOps: Mimicking %s against %s — %d TTPs, %d tools, %d artifacts",
            actor_name, target, len(ttps_used), len(tools_deployed),
            operation["artifact_count"],
        )

        return {
            "success": True,
            "operation": operation,
            "attribution_prediction": prediction,
            "note": f"Forensic analysis will confidently attribute this to {actor_name} ({', '.join(profile.aliases[:2])})",
        }

    def _generate_artifacts_for_operation(
        self, op_id: str, profile: ActorProfile, target: str,
    ) -> None:
        """Generate the forensic breadcrumb trail for an operation."""
        artifacts = []

        # Tool signature artifacts
        for tool in profile.tools[:3]:
            artifacts.append(ForensicArtifact(
                artifact_type="file_hash",
                description=f"Binary matching known {tool} hash",
                location=f"C:\\Windows\\Temp\\{tool.lower()}.exe",
                actor_signature=profile.signature_fingerprint,
                confidence_to_attribute=round(random.uniform(0.75, 0.95), 2),
                planted=False,
            ))

        # Language artifacts
        lang_artifacts = profile.language.get("artifacts", [])
        for la in lang_artifacts[:3]:
            artifacts.append(ForensicArtifact(
                artifact_type="metadata",
                description=la,
                location="binary metadata / PDB path",
                actor_signature=profile.signature_fingerprint,
                confidence_to_attribute=round(random.uniform(0.70, 0.90), 2),
                planted=False,
            ))

        # Network infrastructure artifacts
        infra_artifacts = [
            f"C2 connection to {random.choice(profile.infrastructure.get('c2_domains', ['unknown-c2.com']))}",
            f"IP range matching {random.choice(profile.infrastructure.get('ip_ranges', ['0.0.0.0/0']))}",
        ]
        for ia in infra_artifacts:
            artifacts.append(ForensicArtifact(
                artifact_type="network_flow",
                description=ia,
                location="firewall logs / netflow",
                actor_signature=profile.signature_fingerprint,
                confidence_to_attribute=round(random.uniform(0.65, 0.88), 2),
                planted=False,
            ))

        with self._lock:
            self._artifacts[op_id] = artifacts

    # ── Artifact Generation ────────────────────────────────────────────────

    def generate_false_attribution_artifacts(self, actor_name: str) -> Dict:
        """Generate a set of forensic artifacts that point to a specific actor.

        These artifacts mimic what a real forensic investigation would find:
        registry keys, file paths, network indicators, metadata strings, and
        timing patterns — all carefully crafted to match the target actor.

        Args:
            actor_name: Actor to generate artifacts for

        Returns:
            Dict with generated artifacts and attribution confidence scoring.
        """
        actor_name = actor_name.lower().strip()
        profile = self._profiles.get(actor_name)
        if not profile:
            return {"success": False, "error": f"Unknown actor '{actor_name}'"}

        artifacts = []
        total_confidence = 0.0

        # File artifacts — every tool leaves breadcrumbs
        for tool in profile.tools[:4]:
            confidence = round(random.uniform(0.70, 0.92), 2)
            total_confidence += confidence
            artifacts.append({
                "type": "file_signature",
                "indicator": f"sha256_match:{tool}_variant_{random.randint(1,999)}",
                "path": f"/tmp/{tool.lower()}_{uuid.uuid4().hex[:4]}.dat",
                "description": f"Binary matches known {tool} signature from VirusTotal",
                "confidence": confidence,
            })

        # Registry artifacts (Windows)
        for i in range(3):
            confidence = round(random.uniform(0.65, 0.88), 2)
            total_confidence += confidence
            artifacts.append({
                "type": "registry_key",
                "indicator": f"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\{profile.tools[i%len(profile.tools)].lower()}_{uuid.uuid4().hex[:4]}",
                "description": f"Persistence mechanism matching {profile.actor_name} TTPs",
                "confidence": confidence,
            })

        # Network indicators
        c2_domains = profile.infrastructure.get("c2_domains", [])
        for domain in c2_domains[:3]:
            confidence = round(random.uniform(0.60, 0.85), 2)
            total_confidence += confidence
            artifacts.append({
                "type": "network_indicator",
                "indicator": f"dns_query:{domain}",
                "port": 443,
                "protocol": "TLS 1.3",
                "description": "C2 callback matching known actor infrastructure",
                "confidence": confidence,
            })

        # Timezone artifacts
        tz = profile.timing.get("timezone", "UTC")
        artifacts.append({
            "type": "temporal_pattern",
            "indicator": f"activity_timezone:{tz}",
            "description": f"Operations occur during {tz} business hours",
            "confidence": 0.72,
        })

        # Language artifacts
        lang_meta = profile.language.get("artifacts", [])
        for lm in lang_meta[:2]:
            artifacts.append({
                "type": "language_marker",
                "indicator": lm,
                "description": f"Language artifact matching {profile.actor_name}",
                "confidence": round(random.uniform(0.68, 0.90), 2),
            })

        avg_confidence = total_confidence / max(len(artifacts), 1)

        return {
            "success": True,
            "framed_actor": actor_name,
            "actor_aliases": profile.aliases[:3],
            "total_artifacts": len(artifacts),
            "average_attribution_confidence": round(avg_confidence, 3),
            "artifacts": artifacts,
            "forensic_assessment": self._forensic_prediction_text(actor_name, avg_confidence),
        }

    def _forensic_prediction_text(self, actor_name: str, confidence: float) -> str:
        """Generate a realistic forensic analyst's attribution statement."""
        profile = self._profiles.get(actor_name)
        if not profile:
            return "Attribution inconclusive."

        alias = profile.aliases[0] if profile.aliases else actor_name.upper()
        sponsor = profile.sponsor

        if confidence >= 0.85:
            return (
                f"HIGH CONFIDENCE: This activity is attributed to {alias} "
                f"({sponsor}). TTPs, tool signatures, infrastructure, and "
                f"language artifacts provide a compelling forensic match. "
                f"Confidence: {confidence:.0%}."
            )
        elif confidence >= 0.70:
            return (
                f"MODERATE CONFIDENCE: This activity is likely attributed to "
                f"{alias} ({sponsor}). Multiple forensic indicators align "
                f"with known {actor_name} operations. Confidence: {confidence:.0%}."
            )
        else:
            return (
                f"LOW CONFIDENCE: Possible {alias} activity. Some indicators "
                f"overlap but attribution is tentative. Confidence: {confidence:.0%}."
            )

    # ── Infrastructure Deployment ──────────────────────────────────────────

    def deploy_actor_infrastructure(self, actor_name: str) -> Dict:
        """Deploy simulated infrastructure matching the actor's known patterns.

        Provisions domains, IP ranges, and C2 channels that mirror what the
        real threat actor uses. Includes domain fronting, CDN abuse, and
        hosting provider selection matching actor preferences.

        Args:
            actor_name: Actor whose infrastructure to mimic

        Returns:
            Dict with deployed infrastructure details.
        """
        actor_name = actor_name.lower().strip()
        profile = self._profiles.get(actor_name)
        if not profile:
            return {"success": False, "error": f"Unknown actor '{actor_name}'"}

        infra = profile.infrastructure

        # Simulate infrastructure provisioning
        deployed = {
            "domains_registered": [
                f"{uuid.uuid4().hex[:8]}-{random.choice(['cdn', 'api', 'update', 'secure'])}.{random.choice(['com', 'net', 'org', 'xyz'])}"
                for _ in range(random.randint(2, 5))
            ],
            "hosting_providers_used": infra.get("hosting", [])[:3],
            "c2_channels": infra.get("c2_patterns", [])[:3],
            "ip_pool_size": random.randint(10, 100),
            "domain_fronting_enabled": "domain_fronting_cdn" in str(infra.get("c2_patterns", [])),
            "tor_hidden_service": "tor_hidden_services" in str(infra.get("c2_patterns", [])),
            "estimated_monthly_cost_usd": random.randint(500, 5000),
            "deployment_status": "simulated",
        }

        return {
            "success": True,
            "actor": actor_name,
            "infrastructure": deployed,
            "note": f"Infrastructure mimics {actor_name} patterns — hosting in "
                    f"{', '.join(deployed['hosting_providers_used'][:2])}",
        }

    # ── Tool Signature Emulation ───────────────────────────────────────────

    def emulate_tool_signatures(self, actor_name: str) -> Dict:
        """Generate emulated tool signatures matching the actor's arsenal.

        Produces hashes, file paths, metadata strings, and behavioral
        signatures that would match the actor's known tools in any
        forensic analysis or threat intelligence platform.

        Args:
            actor_name: Actor whose tools to emulate

        Returns:
            Dict with emulated tool signatures.
        """
        actor_name = actor_name.lower().strip()
        profile = self._profiles.get(actor_name)
        if not profile:
            return {"success": False, "error": f"Unknown actor '{actor_name}'"}

        emulated_tools = []
        for tool in profile.tools:
            # Generate realistic-looking SHA256 hash
            fake_hash = hashlib.sha256(f"{tool}_{actor_name}_{time.time()}".encode()).hexdigest()
            emulated_tools.append({
                "tool_name": tool,
                "sha256": fake_hash,
                "file_size_bytes": random.randint(50_000, 5_000_000),
                "compile_timestamp": (
                    datetime.now(timezone.utc) - timedelta(days=random.randint(30, 1095))
                ).isoformat(),
                "sections": [".text", ".data", ".rdata", ".rsrc"],
                "imports": random.sample(
                    ["kernel32.dll", "advapi32.dll", "ws2_32.dll", "wininet.dll",
                     "crypt32.dll", "user32.dll", "ntdll.dll"], 4,
                ),
                "pdb_path": f"C:\\Users\\{random.choice(['dev', 'build', 'admin'])}\\{tool}\\Release\\{tool}.pdb",
                "mutex": f"Global\\{tool}-{uuid.uuid4().hex[:8]}",
            })

        return {
            "success": True,
            "actor": actor_name,
            "total_tools_emulated": len(emulated_tools),
            "tools": emulated_tools,
        }

    # ── Language Spoofing ──────────────────────────────────────────────────

    def spoof_language_patterns(self, actor_name: str, text_content: str = "") -> Dict:
        """Spoof language patterns to match the actor's native language.

        Generates metadata strings, PDB paths, and comment artifacts in the
        actor's language. If text_content is provided, it's "translated" with
        characteristic grammatical errors of the actor's language group.

        Args:
            actor_name: Actor whose language to spoof
            text_content: Optional content to add language artifacts to

        Returns:
            Dict with spoofed language artifacts.
        """
        actor_name = actor_name.lower().strip()
        profile = self._profiles.get(actor_name)
        if not profile:
            return {"success": False, "error": f"Unknown actor '{actor_name}'"}

        lang_data = profile.language
        primary = lang_data.get("primary", "en")

        # Language-specific artifact generation
        if primary == "ru":
            metadata_strings = [
                "C:\\Users\\Пользователь\\Documents\\project\\Release",
                "Компиляция завершена успешно",
                "Отладка: проверка подключения",
                "Временный файл — можно удалить",
            ]
            error_pattern = "Error: connection failed to хост (host)"
        elif primary == "ko":
            metadata_strings = [
                "C:\\Users\\관리자\\바탕 화면\\프로젝트",
                "컴파일 성공적으로 완료됨",
                "디버그: 연결 확인 중",
            ]
            error_pattern = "Error: Connection 실패 (fail) - 재시도"
        elif primary == "zh":
            metadata_strings = [
                "C:\\Users\\管理员\\桌面\\项目",
                "编译成功完成",
                "调试：正在检查连接",
            ]
            error_pattern = "Error: 连接失败 (connection fail) - retry later"
        else:
            metadata_strings = [
                f"C:\\Users\\{random.choice(['dev', 'admin', 'build'])}",
                "Build completed successfully",
                "Debug: checking connectivity",
            ]
            error_pattern = "Error: Connection failed — retrying in 30 seconds"

        # Apply language patterns to text if provided
        modified_text = text_content
        if text_content and primary != "en":
            modified_text = f"/* {random.choice(metadata_strings)} */\\n{text_content}"

        return {
            "success": True,
            "actor": actor_name,
            "primary_language": primary,
            "metadata_strings": metadata_strings,
            "error_pattern": error_pattern,
            "modified_text": modified_text if text_content else None,
            "language_artifacts": lang_data.get("artifacts", []),
        }

    # ── Forensic Trail Generation ──────────────────────────────────────────

    def generate_forensic_trail(self, actor_name: str, target: str) -> Dict:
        """Generate a complete forensic trail that investigators will follow.

        This simulates the full chain of evidence a forensic team would collect:
        initial access vector → execution → persistence → C2 → lateral movement
        → exfiltration. Every step is carefully aligned with the target actor's
        known behaviors and TTPs.

        The trail is designed to survive rigorous investigation by firms like
        Mandiant, CrowdStrike, or Kaspersky's GReAT team.

        Args:
            actor_name: Actor to plant the trail for
            target: Target identifier

        Returns:
            Dict with complete forensic trail and attribution confidence.
        """
        actor_name = actor_name.lower().strip()
        profile = self._profiles.get(actor_name)
        if not profile:
            return {"success": False, "error": f"Unknown actor '{actor_name}'"}

        # Build the kill chain — every link is forged evidence
        trail = {
            "initial_access": {
                "vector": random.choice(profile.ttps[:5] or ["spear_phishing"]),
                "timestamp": (datetime.now(timezone.utc) - timedelta(days=random.randint(1, 30))).isoformat(),
                "evidence": ["phishing_email_headers", "attachment_hash", "user_click_log"],
            },
            "execution": {
                "technique": "user_execution_malicious_file",
                "binary_hash": hashlib.sha256(f"{actor_name}_stager_{target}".encode()).hexdigest(),
                "command_line": f"C:\\Windows\\System32\\cmd.exe /c powershell -enc {hashlib.sha256(b'payload').hexdigest()[:32]}",
                "evidence": ["prefetch_file", "amcache_entry", "shimcache_artifact"],
            },
            "persistence": {
                "technique": random.choice([
                    "registry_run_key", "scheduled_task", "wmi_event_subscription",
                    "service_installation", "dll_side_loading",
                ]),
                "registry_keys": [
                    f"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\{profile.tools[0].lower() if profile.tools else 'update'}",
                ],
                "evidence": ["autoruns_entry", "regripper_output", "event_log_4697"],
            },
            "command_and_control": {
                "c2_url": random.choice(profile.infrastructure.get("c2_domains", ["unknown-c2.com"])),
                "port": random.choice([443, 8443, 8080, 53]),
                "protocol": random.choice(["HTTPS", "DNS", "HTTP/2", "WebSocket"]),
                "beacon_interval_seconds": random.choice([60, 120, 300, 600, 3600]),
                "evidence": ["netflow_records", "dns_query_logs", "proxy_logs", "firewall_logs"],
            },
            "lateral_movement": {
                "technique": random.choice([
                    "pass_the_hash", "wmi_exec", "psexec", "rdp_hopping",
                    "ssh_key_theft", "kerberoasting",
                ]),
                "targets": random.randint(3, 15),
                "evidence": ["event_log_4624", "event_log_4648", "wmi_activity_log"],
            },
            "exfiltration": {
                "method": random.choice([
                    "cloud_storage_upload", "dns_tunneling", "encrypted_zip_email",
                    "ftp_transfer", "custom_protocol",
                ]),
                "estimated_data_gb": round(random.uniform(0.5, 500), 1),
                "evidence": ["proxy_logs_bytes_out", "dns_query_volume", "cloud_api_audit_logs"],
            },
        }

        # Calculate overall attribution confidence
        confidence_factors = {
            "ttp_alignment": random.uniform(0.80, 0.97),
            "tool_match": random.uniform(0.75, 0.95),
            "infrastructure": random.uniform(0.70, 0.92),
            "language": random.uniform(0.68, 0.90),
            "timing": random.uniform(0.72, 0.89),
        }
        overall_confidence = sum(confidence_factors.values()) / len(confidence_factors)

        return {
            "success": True,
            "target": target,
            "framed_actor": actor_name,
            "actor_aliases": profile.aliases[:3],
            "attribution_confidence": round(overall_confidence, 3),
            "confidence_factors": confidence_factors,
            "kill_chain_trail": trail,
            "verdict": self._forensic_prediction_text(actor_name, overall_confidence),
            "investigator_note": (
                f"Based on TTP overlap, tool signatures, infrastructure patterns, "
                f"and language artifacts, this activity is consistent with "
                f"{profile.aliases[0] if profile.aliases else actor_name.upper()} "
                f"({profile.sponsor}). Evidence quality: {overall_confidence:.0%}."
            ),
        }

    # ── Operation Management ───────────────────────────────────────────────

    def get_operation(self, operation_id: str) -> Dict:
        """Retrieve details of a false flag operation."""
        with self._lock:
            op = self._operations.get(operation_id)
            if not op:
                return {"success": False, "error": f"Operation '{operation_id}' not found"}
            artifacts = self._artifacts.get(operation_id, [])
            return {
                "success": True,
                "operation": op,
                "artifact_count": len(artifacts),
                "artifacts": [asdict(a) for a in artifacts],
            }

    def list_operations(self) -> Dict:
        """List all false flag operations."""
        with self._lock:
            return {
                "success": True,
                "total_operations": len(self._operations),
                "operations": [
                    {
                        "id": o["id"],
                        "target": o["target"],
                        "framed_actor": o["framed_actor"],
                        "status": o["status"],
                        "created_at": o["created_at"],
                    }
                    for o in self._operations.values()
                ],
            }

    def cancel_operation(self, operation_id: str) -> Dict:
        """Cancel and clean up a false flag operation."""
        with self._lock:
            if operation_id not in self._operations:
                return {"success": False, "error": f"Operation '{operation_id}' not found"}
            self._operations[operation_id]["status"] = "cancelled"
            logger.info("FalseFlagOps: Operation %s cancelled", operation_id)
            return {"success": True, "operation_id": operation_id, "status": "cancelled"}
