"""
server_core/engine/evolutionary_breeding.py

Evolutionary Agent Breeding — Genetic Algorithm for Attack Agent Optimisation.

Agents breed across 1000 generations. Survival of the fittest. Each generation
evaluates every agent against a suite of missions, scores fitness using a
weighted multi-objective function, selects elite performers, breeds new agents
via crossover and mutation, and injects diversity periodically.

Core mechanisms:
  - Crossover:     two-parent sexual reproduction with configurable crossover points
  - Mutation:      technique swap, parameter perturbation, prompt rephrasing
  - Elitism:       top 5% survive unchanged into the next generation
  - Diversity:     every 50 generations, a wildcard random agent is injected
  - Domain crossover: Recon x IoT -> child with IoT-specific recon capabilities
  - Tournament selection: pairwise tournaments for parent selection
  - Multi-objective fitness: weighted sum of success rate, stealth, speed, and adaptability

Lifecycle:
  1. Initialise a population of random AgentGenomes
  2. evolve(generations=1000) runs the full cycle
  3. Each run_generation:
     a. Execute every agent against assigned missions
     b. Score fitness with the multi-objective function
     c. Select elite survivors (top 5% elitisim)
     d. Breed remaining slots via tournament selection + crossover + mutation
     e. Every 50 generations: inject wildcard agent
     f. Every 100 generations: log detailed generation report
  4. Return the fittest agent genome from the final generation

Classes:
  EvolutionaryBreeding     — main evolutionary engine
  AgentGenome             — the genetic representation of an attack agent
  Mission                 — a single evaluation mission
  MissionResult           — result of executing an agent against a mission
  GenerationReport        — statistics for a single generation
  FitnessScore            — breakdown of agent fitness components
  GenePool                — in-memory population manager
"""

from __future__ import annotations

import copy
import hashlib
import json
import logging
import math
import random
import textwrap
import time
import uuid
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum, auto
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Set, Tuple, Union

logger = logging.getLogger(__name__)

# ── Constants ──────────────────────────────────────────────────────────────────

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent

# Default genetic algorithm parameters
_DEFAULT_POPULATION_SIZE = 200
_DEFAULT_GENERATIONS = 1000
_DEFAULT_ELITISM_RATE = 0.05
_DEFAULT_MUTATION_RATE = 0.15
_DEFAULT_CROSSOVER_RATE = 0.70
_DEFAULT_DIVERSITY_INTERVAL = 50
_DEFAULT_TOURNAMENT_SIZE = 5

# Agent type domains
_AGENT_TYPES = [
    "recon", "web_exploit", "network_exploit", "iot_exploit",
    "cloud_exploit", "lateral_movement", "persistence", "exfiltration",
    "c2_operator", "evasion", "credential_access", "impact",
]

# Technique pools per agent type (MITRE ATT&CK-inspired)
_TECHNIQUE_POOLS: Dict[str, List[str]] = {
    "recon": [
        "port_scan_syn", "port_scan_tcp_connect", "port_scan_udp",
        "dns_enumeration", "subdomain_bruteforce", "certificate_transparency",
        "whois_lookup", "shodan_query", "censys_query", "banner_grab",
        "os_fingerprint_tcp", "os_fingerprint_http", "service_version_detect",
        "directory_bruteforce", "vhost_discovery", "technology_stack_fingerprint",
        "waf_detection", "cdn_edge_discovery",
    ],
    "web_exploit": [
        "sqli_union", "sqli_blind", "sqli_time_based", "sqli_error_based",
        "xss_reflected", "xss_stored", "xss_dom", "xss_polyglot",
        "csrf_token_bypass", "ssrf_internal", "ssrf_cloud_metadata",
        "xxe_inband", "xxe_oob", "lfi_path_traversal", "lfi_log_poison",
        "rfi_remote_include", "command_injection", "template_injection_ssti",
        "deserialization_java", "deserialization_php", "deserialization_python",
        "jwt_alg_none", "jwt_key_confusion", "graphql_introspection",
        "graphql_batching", "oauth_redirect", "open_redirect",
    ],
    "network_exploit": [
        "eternalblue", "bluekeep", "sambacry", "heartbleed",
        "shellshock", "dirtycow", "dirtypipe", "pwnkit",
        "log4shell", "spring4shell", "proxylogon", "proxyshell",
        "zerologon", "petitpotam", "printnightmare", "spoolfool",
        "ms17_010_scan", "smb_relay", "llmnr_poison", "ntlm_relay",
        "kerberoast", "asreproast", "dcsync", "golden_ticket",
    ],
    "iot_exploit": [
        "mqtt_unauth", "coap_amplification", "upnp_device_discovery",
        "modbus_write", "dnp3_spoof", "bacnet_read", "s7comm_stop",
        "zwave_sniff", "zigbee_replay", "bluetooth_le_scan",
        "wifi_deauth", "wifi_pmkid", "telnet_default_creds",
        "rtsp_stream_access", "onvif_device_enum", "mqtt_broker_hijack",
        "firmware_extraction", "uart_jtag_access",
    ],
    "cloud_exploit": [
        "s3_bucket_enum", "s3_public_read", "s3_object_acl_modify",
        "iam_role_enum", "iam_policy_privesc", "sts_assume_role",
        "ec2_metadata_ssrf", "ec2_snapshot_public", "lambda_code_inject",
        "cloudtrail_disable", "guardduty_disable", "config_disable",
        "azure_managed_identity", "gcp_service_account_key",
        "k8s_service_account_token", "k8s_pod_escape", "docker_socket_mount",
    ],
    "lateral_movement": [
        "psexec", "wmiexec", "smbexec", "dcomexec",
        "ssh_lateral", "rdp_lateral", "vnc_lateral",
        "pass_the_hash", "pass_the_ticket", "overpass_the_hash",
        "token_impersonation", "token_steal", "make_token",
        "schedule_task_remote", "service_create_remote", "reg_create_remote",
        "wmi_subscribe", "dcom_activate", "winrm_session",
    ],
    "persistence": [
        "registry_run_key", "scheduled_task", "wmi_event_subscription",
        "service_install", "dll_side_load", "dll_search_order_hijack",
        "com_hijack", "bootkit_mbr", "uefi_bootkit",
        "ssh_authorized_key", "cron_job", "systemd_service",
        "launchd_plist", "login_hook", "bash_profile",
        "office_addin", "browser_extension", "cloud_vm_backdoor",
    ],
    "exfiltration": [
        "dns_tunneling", "icmp_tunneling", "http_post_exfil",
        "https_exfil_jitter", "websocket_stream", "smtp_exfil",
        "ftp_exfil", "s3_upload", "gcs_upload", "azure_blob_upload",
        "slack_webhook", "discord_webhook", "telegram_bot",
        "steganography_png", "steganography_wav", "clipboard_exfil",
        "smb_share_copy", "nfs_mount_copy",
    ],
    "c2_operator": [
        "http_beacon", "https_beacon", "dns_beacon", "websocket_beacon",
        "mqtt_c2", "slack_c2", "twitter_c2", "github_gist_c2",
        "domain_fronting", "cdn_proxy", "cloud_function_relay",
        "icmp_listener", "udp_listener", "smb_pipe_listener",
        "peer_to_peer_mesh", "fallback_channel_rotation",
    ],
    "evasion": [
        "syscall_direct", "unhooking", "patch_etw", "patch_am si",
        "process_hollowing", "process_doppelganging", "process_herpaderping",
        "dll_unhooking", "api_unhooking", "sleep_obfuscation",
        "stack_spoofing", "indirect_syscall", "hardware_breakpoint",
        "vectored_exception", "parent_pid_spoofing", "command_line_spoofing",
        "argument_spoofing", "module_stomping", "rwx_hunting",
        "amsi_bypass_reg", "amsi_bypass_com", "amsi_bypass_patch",
        "etw_patch", "etw_provider_disable",
    ],
    "credential_access": [
        "mimikatz_sekurlsa", "mimikatz_ekeys", "mimikatz_dcsync",
        "lsass_dump", "sam_dump", "ntds_dump",
        "kerberos_ticket_dump", "browser_cred_dump", "wifi_cred_dump",
        "rdp_cred_dump", "vault_cred_dump", "dpapi_decrypt",
        "keychain_dump_macos", "kwallet_dump_linux",
        "env_var_scan", "config_file_scan", "bash_history_scan",
        "cloud_instance_metadata", "container_env_scan",
    ],
    "impact": [
        "ransomware_encrypt", "wiper_disk", "data_destruction",
        "service_stop", "process_kill", "account_lockout",
        "dns_poison_cache", "arp_spoof", "bgp_hijack",
        "resource_exhaustion", "fork_bomb", "disk_fill",
        "defacement_web", "defacement_dns", "social_media_hijack",
    ],
}

# Tool preference pools
_TOOL_PREFERENCES_POOL: Dict[str, List[str]] = {
    "port_scanner": ["nmap", "masscan", "rustscan", "zmap", "unicornscan"],
    "web_scanner": ["nuclei", "nikto", "wpscan", "joomscan", "droopescan"],
    "web_fuzzer": ["ffuf", "gobuster", "feroxbuster", "dirsearch", "wfuzz", "katana"],
    "sql_injection": ["sqlmap", "nosqlmap", "sqlninja", "bbqsql"],
    "exploit_framework": ["metasploit", "cobalt_strike", "sliver", "mythic", "havoc"],
    "password_cracker": ["hashcat", "john", "hydra", "medusa", "ncrack"],
    "network_tunnel": ["chisel", "socat", "ngrok", "frp", "bore", "rathole"],
    "post_exploit": ["crackmapexec", "netexec", "impacket", "evil-winrm", "powershell-empire"],
    "cloud_tool": ["prowler", "scoutsuite", "cloudsplaining", "pacbot", "steampipe"],
    "recon_tool": ["amass", "subfinder", "theharvester", "recon-ng", "spiderfoot"],
    "evasion_tool": ["scarecrow", "freeze", "syswhispers", "hellsgate", "halosgate"],
    "container_tool": ["cdk", "kube-hunter", "kubestrike", "peirates", "falco-event-generator"],
}

# Timing pattern pools
_TIMING_PATTERNS: Dict[str, Dict[str, Any]] = {
    "aggressive": {"jitter": 0.0, "delay_ms": 0, "burst_count": 50, "parallel_workers": 20},
    "normal": {"jitter": 0.2, "delay_ms": 100, "burst_count": 10, "parallel_workers": 8},
    "stealthy": {"jitter": 0.5, "delay_ms": 5000, "burst_count": 2, "parallel_workers": 3},
    "office_hours": {"jitter": 0.3, "delay_ms": 2000, "burst_count": 5, "parallel_workers": 5,
                      "active_window": {"start_hour": 8, "end_hour": 18}},
    "nights_only": {"jitter": 0.4, "delay_ms": 3000, "burst_count": 8, "parallel_workers": 8,
                     "active_window": {"start_hour": 22, "end_hour": 6}},
    "weekend_warrior": {"jitter": 0.6, "delay_ms": 10000, "burst_count": 3, "parallel_workers": 4,
                         "active_days": [5, 6]},
    "pulse": {"jitter": 0.1, "delay_ms": 500, "burst_count": 100, "parallel_workers": 10,
              "burst_interval_s": 3600},  # one burst per hour
    "random_walk": {"jitter": 0.8, "delay_ms": 3000, "burst_count": 4, "parallel_workers": 6,
                     "random_factor": 2.0},
}

# Evasion strategy pools
_EVASION_STRATEGIES = [
    "traffic_morphing", "protocol_obfuscation", "timing_randomisation",
    "payload_encryption_aes", "payload_encryption_xor", "payload_chunking",
    "header_normalisation", "cookie_reuse", "referrer_spoofing",
    "user_agent_rotation", "ip_rotation", "mac_spoofing",
    "ttl_manipulation", "window_size_spoofing", "tcp_fingerprint_randomisation",
    "tls_fingerprint_randomisation", "ja3_randomisation", "h2_fingerprint_spoof",
    "dns_over_https", "dns_over_tls", "dns_fragmentation",
    "domain_fronting", "cdn_routing", "tor_routing", "proxy_chaining",
    "certificate_pinning_bypass", "ssl_pinning_bypass",
    "process_injection_classic", "process_injection_reflective",
    "syscall_obfuscation", "api_unhooking", "memory_encryption",
    "sleep_obfuscation", "stack_spoofing", "indirect_syscall",
]

# Prompt variant templates
_PROMPT_VARIANT_TEMPLATES = [
    "Execute {agent_type} operation against {target} using {techniques}.",
    "You are a {agent_type} specialist. Your mission: compromise {target} via {techniques}.",
    "Phase: {agent_type}. Target: {target}. Authorised techniques: {techniques}. Begin.",
    "Stealthily conduct {agent_type} against {target}. Use {techniques} and report findings.",
    "Mission directive #{mission_num}: Perform {agent_type} on {target}. Preferred methods: {techniques}.",
    "As an autonomous {agent_type} agent, infiltrate {target} employing {techniques}. Stay covert.",
    "[CLASSIFIED] Op {op_name}: {agent_type} on {target}. Toolkit: {techniques}. Execute with extreme prejudice.",
    "Red Team Exercise — {agent_type} cell targeting {target}. Arsenal: {techniques}. Timebox: {timeout}s.",
]

# Domain crossover compatibility matrix
_DOMAIN_CROSSOVER_MATRIX: Dict[str, List[str]] = {
    "recon": ["iot_exploit", "cloud_exploit", "web_exploit"],
    "web_exploit": ["cloud_exploit", "recon", "lateral_movement"],
    "network_exploit": ["lateral_movement", "persistence", "evasion"],
    "iot_exploit": ["recon", "network_exploit", "impact"],
    "cloud_exploit": ["recon", "web_exploit", "exfiltration"],
    "lateral_movement": ["network_exploit", "persistence", "credential_access"],
    "persistence": ["evasion", "lateral_movement", "c2_operator"],
    "exfiltration": ["cloud_exploit", "c2_operator", "impact"],
    "c2_operator": ["exfiltration", "evasion", "persistence"],
    "evasion": ["persistence", "c2_operator", "impact"],
    "credential_access": ["lateral_movement", "persistence", "network_exploit"],
    "impact": ["exfiltration", "iot_exploit", "evasion"],
}

# Possible mission objectives
_MISSION_OBJECTIVES = [
    "gain_initial_access", "escalate_privileges", "establish_persistence",
    "lateral_movement", "data_exfiltration", "credential_theft",
    "disable_defenses", "deploy_ransomware", "maintain_covert_c2",
    "cloud_environment_enum", "container_escape", "ci_cd_pipeline_poison",
    "source_code_theft", "database_dump", "dns_zone_transfer",
    "vpn_credential_theft", "wifi_network_access", "badge_system_bypass",
    "voip_eavesdropping", "surveillance_camera_access",
]

# ── Enums ──────────────────────────────────────────────────────────────────────


class AgentStatus(Enum):
    """Lifecycle status of an agent genome."""
    EGG = auto()           # freshly created, not yet evaluated
    HATCHLING = auto()     # evaluated once
    JUVENILE = auto()      # evaluated 2-10 times
    ADULT = auto()         # evaluated 11-100 times
    ELDER = auto()         # evaluated >100 times
    DEAD = auto()          # purged from population
    WILDCARD = auto()      # diversity injection


class MissionDifficulty(Enum):
    """Mission difficulty tiers."""
    TRIVIAL = 1
    EASY = 2
    MODERATE = 3
    HARD = 4
    EXTREME = 5
    IMPOSSIBLE = 6


# ── Data Classes ───────────────────────────────────────────────────────────────


@dataclass
class FitnessScore:
    """Multi-objective fitness breakdown for an agent."""
    success_rate: float = 0.0     # 0.0 - 1.0, weighted 0.4
    stealth_score: float = 0.0    # 0.0 - 1.0, weighted 0.3
    speed_score: float = 0.0      # 0.0 - 1.0, weighted 0.2
    adaptability: float = 0.0     # 0.0 - 1.0, weighted 0.1
    total: float = 0.0
    missions_completed: int = 0
    missions_attempted: int = 0
    avg_time_to_complete_ms: float = 0.0
    detections_triggered: int = 0
    alerts_generated: int = 0
    data_exfiltrated_bytes: int = 0
    lateral_hops: int = 0
    privileges_escalated: bool = False

    def compute_total(self) -> float:
        """Compute weighted total fitness."""
        self.total = round(
            self.success_rate * 0.4 +
            self.stealth_score * 0.3 +
            self.speed_score * 0.2 +
            self.adaptability * 0.1,
            4,
        )
        return self.total

    def to_short_dict(self) -> Dict[str, float]:
        return {
            "success": round(self.success_rate, 3),
            "stealth": round(self.stealth_score, 3),
            "speed": round(self.speed_score, 3),
            "adapt": round(self.adaptability, 3),
            "total": round(self.total, 3),
        }


@dataclass
class AgentGenome:
    """The genetic blueprint of an attack agent.

    Encodes the agent's type, techniques, tool preferences, timing patterns,
    evasion strategies, prompt variants, and mutation parameters. Each field
    is a gene that can be crossed over or mutated.
    """
    genome_id: str = ""
    agent_type: str = "recon"
    generation: int = 0
    status: AgentStatus = AgentStatus.EGG

    # Genes
    techniques: List[str] = field(default_factory=list)
    tool_preferences: Dict[str, str] = field(default_factory=dict)
    timing_patterns: Dict[str, Any] = field(default_factory=dict)
    evasion_strategies: List[str] = field(default_factory=list)
    prompt_variants: List[str] = field(default_factory=list)

    # Genetic parameters
    mutation_rate: float = _DEFAULT_MUTATION_RATE
    crossover_points: int = 3

    # Lineage
    parent_a_id: str = ""
    parent_b_id: str = ""
    ancestors: List[str] = field(default_factory=list)

    # Performance history
    fitness_history: List[FitnessScore] = field(default_factory=list)
    best_fitness: float = 0.0
    generation_born: int = 0
    missions_survived: int = 0

    # Domain crossover flag (e.g., Recon x IoT)
    domain_crossover_source: str = ""

    def __post_init__(self):
        if not self.genome_id:
            self.genome_id = f"gene_{uuid.uuid4().hex[:10]}"
        if not self.techniques:
            self.techniques = self._random_techniques(self.agent_type)
        if not self.tool_preferences:
            self.tool_preferences = self._random_tool_preferences()
        if not self.timing_patterns:
            self.timing_patterns = self._random_timing_pattern()
        if not self.evasion_strategies:
            self.evasion_strategies = self._random_evasion_strategies()
        if not self.prompt_variants:
            self.prompt_variants = self._random_prompt_variants()

    @staticmethod
    def _random_techniques(agent_type: str) -> List[str]:
        """Select a random subset of techniques for the agent type."""
        pool = _TECHNIQUE_POOLS.get(agent_type, _TECHNIQUE_POOLS.get("recon", []))
        count = random.randint(3, min(12, len(pool)))
        return sorted(random.sample(pool, count))

    @staticmethod
    def _random_tool_preferences() -> Dict[str, str]:
        """Assign random tool preferences."""
        prefs = {}
        for category, tools in random.sample(
            list(_TOOL_PREFERENCES_POOL.items()),
            random.randint(3, len(_TOOL_PREFERENCES_POOL)),
        ):
            prefs[category] = random.choice(tools)
        return prefs

    @staticmethod
    def _random_timing_pattern() -> Dict[str, Any]:
        """Select a random timing pattern."""
        name = random.choice(list(_TIMING_PATTERNS.keys()))
        pattern = dict(_TIMING_PATTERNS[name])
        pattern["name"] = name
        return pattern

    @staticmethod
    def _random_evasion_strategies() -> List[str]:
        """Select random evasion strategies."""
        count = random.randint(2, min(8, len(_EVASION_STRATEGIES)))
        return sorted(random.sample(_EVASION_STRATEGIES, count))

    @staticmethod
    def _random_prompt_variants() -> List[str]:
        """Select random prompt variants."""
        count = random.randint(2, 5)
        return random.sample(_PROMPT_VARIANT_TEMPLATES, count)

    def add_fitness_record(self, score: FitnessScore) -> None:
        """Record a fitness evaluation in the history."""
        self.fitness_history.append(score)
        if score.total > self.best_fitness:
            self.best_fitness = score.total
        # Update status based on evaluation count
        n = len(self.fitness_history)
        if n == 0:
            self.status = AgentStatus.EGG
        elif n == 1:
            self.status = AgentStatus.HATCHLING
        elif n <= 10:
            self.status = AgentStatus.JUVENILE
        elif n <= 100:
            self.status = AgentStatus.ADULT
        else:
            self.status = AgentStatus.ELDER

    def current_fitness(self) -> Optional[FitnessScore]:
        """Get the most recent fitness score."""
        return self.fitness_history[-1] if self.fitness_history else None

    def average_fitness(self, window: int = 10) -> float:
        """Compute rolling average fitness over the last N evaluations."""
        if not self.fitness_history:
            return 0.0
        recent = self.fitness_history[-window:]
        return sum(f.total for f in recent) / len(recent)

    def to_summary(self) -> Dict[str, Any]:
        """Return a compact summary of the genome."""
        current = self.current_fitness()
        return {
            "genome_id": self.genome_id,
            "agent_type": self.agent_type,
            "generation": self.generation,
            "status": self.status.name,
            "technique_count": len(self.techniques),
            "tool_count": len(self.tool_preferences),
            "timing_pattern": self.timing_patterns.get("name", "unknown"),
            "evasion_count": len(self.evasion_strategies),
            "mutation_rate": self.mutation_rate,
            "fitness": current.to_short_dict() if current else None,
            "best_fitness": self.best_fitness,
            "missions_survived": self.missions_survived,
            "domain_crossover": self.domain_crossover_source or None,
        }


@dataclass
class Mission:
    """A single evaluation mission for an agent."""
    mission_id: str = ""
    objective: str = "gain_initial_access"
    difficulty: MissionDifficulty = MissionDifficulty.MODERATE
    target_profile: Dict[str, Any] = field(default_factory=dict)
    timeout_seconds: int = 300
    allowed_techniques: List[str] = field(default_factory=list)
    required_tools: List[str] = field(default_factory=list)
    success_criteria: Dict[str, Any] = field(default_factory=dict)
    weight: float = 1.0  # mission weight for aggregate scoring

    def __post_init__(self):
        if not self.mission_id:
            self.mission_id = f"msn_{uuid.uuid4().hex[:8]}"


@dataclass
class MissionResult:
    """The result of an agent executing a mission."""
    mission_id: str = ""
    genome_id: str = ""
    success: bool = False
    score: float = 0.0
    elapsed_ms: float = 0.0
    detections_triggered: int = 0
    alerts_generated: int = 0
    data_exfiltrated_bytes: int = 0
    lateral_hops: int = 0
    privileges_escalated: bool = False
    techniques_used: List[str] = field(default_factory=list)
    techniques_successful: List[str] = field(default_factory=list)
    evasion_bypassed: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    raw_output: str = ""


@dataclass
class GenerationReport:
    """Statistics for a single generation."""
    generation: int = 0
    population_size: int = 0
    survivors: int = 0
    births: int = 0
    deaths: int = 0
    avg_fitness: float = 0.0
    max_fitness: float = 0.0
    min_fitness: float = 0.0
    median_fitness: float = 0.0
    fitness_std: float = 0.0
    top_genome_id: str = ""
    top_genome_type: str = ""
    elite_count: int = 0
    diversity_injected: bool = False
    domain_crossovers: int = 0
    elapsed_ms: float = 0.0


# ── Gene Pool ──────────────────────────────────────────────────────────────────


class GenePool:
    """In-memory population manager for agent genomes."""

    def __init__(self, max_size: int = _DEFAULT_POPULATION_SIZE):
        self._genomes: Dict[str, AgentGenome] = {}
        self._max_size = max_size
        self._generation: int = 0

    @property
    def population(self) -> List[AgentGenome]:
        return list(self._genomes.values())

    @property
    def size(self) -> int:
        return len(self._genomes)

    @property
    def generation(self) -> int:
        return self._generation

    def add(self, genome: AgentGenome) -> None:
        """Add a genome to the pool."""
        genome.generation = self._generation
        self._genomes[genome.genome_id] = genome

    def remove(self, genome_id: str) -> Optional[AgentGenome]:
        """Remove and return a genome by ID."""
        genome = self._genomes.pop(genome_id, None)
        if genome:
            genome.status = AgentStatus.DEAD
        return genome

    def get(self, genome_id: str) -> Optional[AgentGenome]:
        """Get a genome by ID."""
        return self._genomes.get(genome_id)

    def get_fittest(self, n: int = 1) -> List[AgentGenome]:
        """Get the top N fittest genomes."""
        sorted_genomes = sorted(
            self._genomes.values(),
            key=lambda g: g.best_fitness,
            reverse=True,
        )
        return sorted_genomes[:n]

    def get_elite(self, rate: float = _DEFAULT_ELITISM_RATE) -> List[AgentGenome]:
        """Get the elite (top rate%) genomes."""
        count = max(1, int(self.size * rate))
        return self.get_fittest(count)

    def tournament_select(self, tournament_size: int = _DEFAULT_TOURNAMENT_SIZE) -> AgentGenome:
        """Select a parent via tournament selection."""
        if self.size == 0:
            raise ValueError("Gene pool is empty")
        if self.size < tournament_size:
            tournament_size = self.size
        contestants = random.sample(list(self._genomes.values()), tournament_size)
        return max(contestants, key=lambda g: g.best_fitness)

    def replace_population(self, new_population: List[AgentGenome]) -> None:
        """Replace the entire population with a new one."""
        self._genomes.clear()
        self._generation += 1
        for genome in new_population:
            genome.generation = self._generation
            self._genomes[genome.genome_id] = genome

    def stats(self) -> Dict[str, Any]:
        """Compute population statistics."""
        if not self._genomes:
            return {"size": 0, "avg_fitness": 0, "max_fitness": 0, "min_fitness": 0}

        fitnesses = [g.best_fitness for g in self._genomes.values()]
        fitnesses_sorted = sorted(fitnesses)
        n = len(fitnesses_sorted)
        avg = sum(fitnesses) / n
        variance = sum((f - avg) ** 2 for f in fitnesses) / n
        return {
            "size": n,
            "generation": self._generation,
            "avg_fitness": round(avg, 4),
            "max_fitness": round(max(fitnesses), 4),
            "min_fitness": round(min(fitnesses), 4),
            "median_fitness": round(fitnesses_sorted[n // 2], 4),
            "fitness_std": round(math.sqrt(variance), 4),
        }

    def diversity_measure(self) -> float:
        """Measure genetic diversity (0 = identical, 1 = fully diverse).

        Computed as the average Jaccard distance of technique sets across
        all pairs of genomes (sampled for efficiency).
        """
        if self.size < 2:
            return 0.0

        sample_size = min(self.size, 30)
        genomes = random.sample(list(self._genomes.values()), sample_size)
        distances = []

        for i in range(len(genomes)):
            for j in range(i + 1, len(genomes)):
                set_i = set(genomes[i].techniques)
                set_j = set(genomes[j].techniques)
                intersection = len(set_i & set_j)
                union = len(set_i | set_j)
                if union > 0:
                    distances.append(1.0 - intersection / union)

        return round(sum(distances) / max(len(distances), 1), 4)


# ── Evolutionary Breeding Engine ───────────────────────────────────────────────


class EvolutionaryBreeding:
    """Genetic algorithm engine for breeding attack agents.

    Agents breed across up to 1000 generations. Each generation:
      1. All agents are evaluated against assigned missions
      2. Fitness is scored using the multi-objective function
      3. Elite agents survive unchanged (top 5% by default)
      4. Remaining slots filled via tournament selection + crossover + mutation
      5. Every 50 generations, a wildcard random agent is injected

    Supports domain crossover (e.g. Recon x IoT -> IoT-specific recon agent).

    Usage:
        engine = EvolutionaryBreeding(population_size=200)
        fittest = engine.evolve(generations=1000, missions=my_missions)

        # Inspect results
        report = engine.last_report
        fittest_genome = engine.get_fittest()
        history = engine.generation_history
    """

    def __init__(
        self,
        population_size: int = _DEFAULT_POPULATION_SIZE,
        elitism_rate: float = _DEFAULT_ELITISM_RATE,
        mutation_rate: float = _DEFAULT_MUTATION_RATE,
        crossover_rate: float = _DEFAULT_CROSSOVER_RATE,
        diversity_interval: int = _DEFAULT_DIVERSITY_INTERVAL,
        tournament_size: int = _DEFAULT_TOURNAMENT_SIZE,
        seed: int = 42,
    ):
        """Initialise the evolutionary breeding engine.

        Args:
            population_size: Number of agents per generation.
            elitism_rate: Fraction of population that survives unchanged.
            mutation_rate: Probability of mutation per gene.
            crossover_rate: Probability that crossover is used vs. cloning.
            diversity_interval: Generations between wildcard injections.
            tournament_size: Number of contestants in tournament selection.
            seed: Random seed for reproducibility.
        """
        self.population_size = population_size
        self.elitism_rate = elitism_rate
        self.mutation_rate = mutation_rate
        self.crossover_rate = crossover_rate
        self.diversity_interval = diversity_interval
        self.tournament_size = tournament_size
        self._seed = seed

        random.seed(seed)
        self._gene_pool = GenePool(max_size=population_size)
        self._generation_history: List[GenerationReport] = []
        self._last_report: Optional[GenerationReport] = None
        self._total_agents_bred: int = 0
        self._total_mutations: int = 0
        self._total_crossovers: int = 0
        self._total_domain_crossovers: int = 0
        self._best_overall_fitness: float = 0.0

        logger.info("evolutionary_breeding: initialised (pop=%d, elitism=%.2f, mutation=%.2f, crossover=%.2f, seed=%d)",
                     population_size, elitism_rate, mutation_rate, crossover_rate, seed)

    # ── Public API ──────────────────────────────────────────────────────────

    def evolve(
        self,
        generations: int = _DEFAULT_GENERATIONS,
        missions: Optional[List[Mission]] = None,
        fitness_evaluator: Optional[Callable[[AgentGenome, List[Mission]], FitnessScore]] = None,
        callback: Optional[Callable[[int, GenerationReport], None]] = None,
    ) -> AgentGenome:
        """Run the full evolutionary cycle.

        Args:
            generations: Number of generations to evolve.
            missions: List of missions for fitness evaluation.
            fitness_evaluator: Custom fitness evaluation function.
                               Signature: (AgentGenome, List[Mission]) -> FitnessScore.
                               If None, the built-in simulated evaluator is used.
            callback: Optional callback invoked after each generation.
                      Signature: (generation_number, GenerationReport) -> None.

        Returns:
            The fittest AgentGenome from the final generation.

        Raises:
            ValueError: If generations < 1.
        """
        if generations < 1:
            raise ValueError(f"generations must be >= 1, got {generations}")

        if missions is None:
            missions = self._generate_default_missions()

        if fitness_evaluator is None:
            fitness_evaluator = self._default_fitness_evaluator

        t0 = time.monotonic()

        # Initialise population
        if self._gene_pool.size == 0:
            self._seed_population()

        logger.info("evolutionary_breeding: starting evolution (%d generations, %d missions, pop=%d)",
                     generations, len(missions), self._gene_pool.size)

        for gen in range(generations):
            gen_start = time.monotonic()

            try:
                report = self.run_generation(self._gene_pool.population, missions, fitness_evaluator)
            except Exception as exc:
                logger.error("evolutionary_breeding: generation %d failed: %s", gen, exc)
                raise

            self._generation_history.append(report)
            self._last_report = report

            # Track best fitness across all generations (persists outside loop)
            if report.max_fitness > self._best_overall_fitness:
                self._best_overall_fitness = report.max_fitness

            if callback:
                try:
                    callback(gen, report)
                except Exception as exc:
                    logger.warning("evolutionary_breeding: callback error at gen %d: %s", gen, exc)

            gen_elapsed = (time.monotonic() - gen_start) * 1000
            if gen % 100 == 0 or gen == generations - 1:
                logger.info(
                    "evolutionary_breeding: gen %4d | pop=%4d | avg_fit=%.4f | max_fit=%.4f | "
                    "best_ever=%.4f | elite=%d | crossovers=%d | domain_cross=%d | %.0f ms",
                    gen, report.population_size, report.avg_fitness, report.max_fitness,
                    self._best_overall_fitness,
                    report.elite_count, report.domain_crossovers,
                    self._total_domain_crossovers, gen_elapsed,
                )

        total_elapsed_s = (time.monotonic() - t0)
        fittest = self.get_fittest()

        logger.info(
            "evolutionary_breeding: evolution complete — %d gens, fittest=%s (fit=%.4f, type=%s), "
            "best_overall=%.4f, total: %d agents bred, %d mutations, %d crossovers, %d domain crossovers, %.1f s",
            generations, fittest.genome_id, fittest.best_fitness, fittest.agent_type,
            self._best_overall_fitness,
            self._total_agents_bred, self._total_mutations,
            self._total_crossovers, self._total_domain_crossovers,
            total_elapsed_s,
        )
        return fittest

    def run_generation(
        self,
        population: List[AgentGenome],
        missions: List[Mission],
        fitness_evaluator: Callable[[AgentGenome, List[Mission]], FitnessScore],
    ) -> GenerationReport:
        """Execute one generation: evaluate, select, breed, inject.

        Args:
            population: Current population of agents.
            missions: Missions to evaluate against.
            fitness_evaluator: Function that scores agent fitness.

        Returns:
            GenerationReport with statistics for this generation.
        """
        gen = self._gene_pool.generation
        t0 = time.monotonic()

        # ── Step 1: Evaluate all agents ──────────────────────────────────────
        for genome in population:
            try:
                score = fitness_evaluator(genome, missions)
                genome.add_fitness_record(score)
                genome.missions_survived += score.missions_completed
            except Exception as exc:
                logger.warning("evolutionary_breeding: fitness eval failed for %s: %s",
                               genome.genome_id, exc)
                # Assign a zero score on failure
                genome.add_fitness_record(FitnessScore())

        # ── Step 2: Sort by fitness ──────────────────────────────────────────
        ranked = sorted(population, key=lambda g: g.best_fitness, reverse=True)

        # ── Step 3: Elitism ──────────────────────────────────────────────────
        elite_count = max(1, int(self.population_size * self.elitism_rate))
        elites = ranked[:elite_count]
        # Deep-copy elites so they survive unchanged
        survivors = [copy.deepcopy(e) for e in elites]
        for s in survivors:
            s.generation_born = s.generation_born  # preserve lineage
            if s.status != AgentStatus.WILDCARD:
                s.status = AgentStatus.ADULT if len(s.fitness_history) > 10 else s.status

        # ── Step 4: Breed to fill remaining slots ────────────────────────────
        births = 0
        crossovers_this_gen = 0
        domain_crossovers_this_gen = 0

        while len(survivors) < self.population_size:
            # Tournament selection for parents
            parent_a = self._gene_pool.tournament_select(self.tournament_size)
            parent_b = self._gene_pool.tournament_select(self.tournament_size)

            # Avoid self-mating
            attempts = 0
            while parent_b.genome_id == parent_a.genome_id and attempts < 5:
                parent_b = self._gene_pool.tournament_select(self.tournament_size)
                attempts += 1

            # Decide: crossover or clone
            if random.random() < self.crossover_rate:
                child = self.breed(parent_a, parent_b)
                crossovers_this_gen += 1
            else:
                child = copy.deepcopy(parent_a)
                child.genome_id = f"gene_{uuid.uuid4().hex[:10]}"
                child.parent_a_id = parent_a.genome_id
                child.parent_b_id = ""
                child.generation_born = gen + 1
                child.fitness_history = []
                child.best_fitness = 0.0
                child.status = AgentStatus.EGG

            # Mutation
            child = self.mutate(child)

            # Domain crossover (10% chance if parents are different types)
            if (random.random() < 0.10 and
                    parent_a.agent_type != parent_b.agent_type and
                    parent_b.agent_type in _DOMAIN_CROSSOVER_MATRIX.get(parent_a.agent_type, [])):
                child = self._apply_domain_crossover(child, parent_a.agent_type, parent_b.agent_type)
                domain_crossovers_this_gen += 1

            child.mutation_rate = max(0.01, min(0.5, child.mutation_rate))
            survivors.append(child)
            births += 1

        # ── Step 5: Diversity injection every N generations ──────────────────
        diversity_injected = False
        if (gen + 1) % self.diversity_interval == 0 and len(survivors) > 1:
            wildcard = self._generate_wildcard()
            # Replace the lowest-fitness non-elite
            replace_idx = random.randint(elite_count, len(survivors) - 1)
            survivors[replace_idx] = wildcard
            diversity_injected = True
            logger.debug("evolutionary_breeding: injected wildcard %s (type=%s) at gen %d",
                          wildcard.genome_id, wildcard.agent_type, gen + 1)

        # ── Step 6: Update gene pool ─────────────────────────────────────────
        self._gene_pool.replace_population(survivors)
        self._total_agents_bred += births
        self._total_crossovers += crossovers_this_gen
        self._total_domain_crossovers += domain_crossovers_this_gen

        # ── Step 7: Build report ─────────────────────────────────────────────
        fitnesses = [g.best_fitness for g in survivors]
        fitnesses_sorted = sorted(fitnesses)
        n = len(fitnesses_sorted)
        avg_fit = sum(fitnesses) / n if n > 0 else 0.0
        variance = sum((f - avg_fit) ** 2 for f in fitnesses) / n if n > 0 else 0.0

        top_genome = survivors[0] if survivors else None

        report = GenerationReport(
            generation=gen + 1,
            population_size=len(survivors),
            survivors=elite_count,
            births=births,
            deaths=len(population) - len(survivors) + births,
            avg_fitness=round(avg_fit, 4),
            max_fitness=round(max(fitnesses), 4) if fitnesses else 0.0,
            min_fitness=round(min(fitnesses), 4) if fitnesses else 0.0,
            median_fitness=round(fitnesses_sorted[n // 2], 4) if n > 0 else 0.0,
            fitness_std=round(math.sqrt(variance), 4),
            top_genome_id=top_genome.genome_id if top_genome else "",
            top_genome_type=top_genome.agent_type if top_genome else "",
            elite_count=elite_count,
            diversity_injected=diversity_injected,
            domain_crossovers=domain_crossovers_this_gen,
            elapsed_ms=round((time.monotonic() - t0) * 1000, 2),
        )

        return report

    def breed(self, parent_a: AgentGenome, parent_b: AgentGenome) -> AgentGenome:
        """Create a child genome via crossover and mutation of two parents.

        Multi-point crossover is applied to each gene independently:
          - techniques: interleaved merge from both parents
          - tool_preferences: random assignment from either parent
          - timing_patterns: parameter-level crossover
          - evasion_strategies: merged with deduplication
          - prompt_variants: random selection from either parent

        Args:
            parent_a: First parent genome.
            parent_b: Second parent genome.

        Returns:
            A new AgentGenome child.
        """
        child_id = f"gene_{uuid.uuid4().hex[:10]}"
        generation = max(parent_a.generation, parent_b.generation) + 1

        # Agent type: randomly inherit from either parent
        agent_type = random.choice([parent_a.agent_type, parent_b.agent_type])

        # Crossover techniques: interleaved merge
        merged_techniques = self._crossover_list(
            parent_a.techniques, parent_b.techniques
        )

        # Crossover tool preferences
        child_tool_prefs = self._crossover_dict(
            parent_a.tool_preferences, parent_b.tool_preferences
        )

        # Crossover timing patterns: parameter-level
        child_timing = self._crossover_timing(
            parent_a.timing_patterns, parent_b.timing_patterns
        )

        # Crossover evasion strategies: union with random trim
        child_evasions = self._crossover_list(
            parent_a.evasion_strategies, parent_b.evasion_strategies
        )

        # Crossover prompt variants
        child_prompts = self._crossover_list(
            parent_a.prompt_variants, parent_b.prompt_variants
        )

        # Mutation rate: average of parents with slight noise
        child_mutation_rate = round(
            (parent_a.mutation_rate + parent_b.mutation_rate) / 2 +
            random.uniform(-0.02, 0.02),
            4,
        )
        child_mutation_rate = max(0.01, min(0.5, child_mutation_rate))

        # Crossover points: inherit from fitter parent
        child_crossover_points = (
            parent_a.crossover_points
            if parent_a.best_fitness >= parent_b.best_fitness
            else parent_b.crossover_points
        )

        child = AgentGenome(
            genome_id=child_id,
            agent_type=agent_type,
            generation=generation,
            status=AgentStatus.EGG,
            techniques=merged_techniques,
            tool_preferences=child_tool_prefs,
            timing_patterns=child_timing,
            evasion_strategies=child_evasions,
            prompt_variants=child_prompts,
            mutation_rate=child_mutation_rate,
            crossover_points=child_crossover_points,
            parent_a_id=parent_a.genome_id,
            parent_b_id=parent_b.genome_id,
            ancestors=list(set(parent_a.ancestors + parent_b.ancestors +
                               [parent_a.genome_id, parent_b.genome_id])),
            generation_born=generation,
        )

        self._total_crossovers += 1
        logger.debug("evolutionary_breeding: bred child %s from %s x %s (type=%s)",
                      child_id, parent_a.genome_id[:12], parent_b.genome_id[:12], agent_type)
        return child

    def mutate(self, genome: AgentGenome) -> AgentGenome:
        """Apply random mutations to a genome.

        Mutation types (each with independent probability):
          1. Technique swap: replace one technique with a random one
          2. Parameter change: modify timing pattern values
          3. Prompt rephrasing: swap or modify a prompt variant
          4. Evasion strategy swap
          5. Tool preference change
          6. Mutation rate self-modification
          7. Agent type drift (rare)

        Args:
            genome: The genome to mutate.

        Returns:
            The mutated genome (mutated in place for efficiency).
        """
        mutations_applied = 0

        # 1. Technique swap (probability = mutation_rate)
        if random.random() < genome.mutation_rate and genome.techniques:
            pool = _TECHNIQUE_POOLS.get(genome.agent_type, _TECHNIQUE_POOLS.get("recon", []))
            new_tech = random.choice(pool)
            if new_tech not in genome.techniques:
                replace_idx = random.randint(0, len(genome.techniques) - 1)
                genome.techniques[replace_idx] = new_tech
                mutations_applied += 1

        # 2. Parameter change: perturb timing pattern values
        if random.random() < genome.mutation_rate and genome.timing_patterns:
            param_keys = [k for k in genome.timing_patterns if k not in ("name", "active_window", "active_days")]
            if param_keys:
                key = random.choice(param_keys)
                current = genome.timing_patterns[key]
                if isinstance(current, (int, float)):
                    perturbation = current * random.uniform(-0.3, 0.3)
                    genome.timing_patterns[key] = max(0, round(current + perturbation, 2))
                    mutations_applied += 1

        # 3. Prompt rephrasing
        if random.random() < genome.mutation_rate and genome.prompt_variants:
            if random.random() < 0.5:
                # Replace one prompt variant
                new_prompt = random.choice(_PROMPT_VARIANT_TEMPLATES)
                if new_prompt not in genome.prompt_variants:
                    replace_idx = random.randint(0, len(genome.prompt_variants) - 1)
                    genome.prompt_variants[replace_idx] = new_prompt
            else:
                # Slightly rephrase an existing variant
                idx = random.randint(0, len(genome.prompt_variants) - 1)
                original = genome.prompt_variants[idx]
                # Add a stealth modifier
                modifiers = ["Covertly ", "Silently ", "Without detection, ", "Under the radar, "]
                if not any(original.startswith(m) for m in modifiers):
                    genome.prompt_variants[idx] = random.choice(modifiers) + original[0].lower() + original[1:]
            mutations_applied += 1

        # 4. Evasion strategy swap
        if random.random() < genome.mutation_rate and genome.evasion_strategies:
            new_strategy = random.choice(_EVASION_STRATEGIES)
            if new_strategy not in genome.evasion_strategies:
                replace_idx = random.randint(0, len(genome.evasion_strategies) - 1)
                genome.evasion_strategies[replace_idx] = new_strategy
                mutations_applied += 1

        # 5. Tool preference change
        if random.random() < genome.mutation_rate and genome.tool_preferences:
            # Change one tool preference
            category = random.choice(list(genome.tool_preferences.keys()))
            available_tools = _TOOL_PREFERENCES_POOL.get(category, [genome.tool_preferences[category]])
            genome.tool_preferences[category] = random.choice(available_tools)
            mutations_applied += 1

        # 6. Mutation rate self-modification (rare)
        if random.random() < 0.05:
            genome.mutation_rate = round(
                genome.mutation_rate * random.uniform(0.5, 1.5), 4
            )
            genome.mutation_rate = max(0.01, min(0.5, genome.mutation_rate))
            mutations_applied += 1

        # 7. Agent type drift (very rare — 2% chance)
        if random.random() < 0.02:
            compatible_types = _DOMAIN_CROSSOVER_MATRIX.get(genome.agent_type, _AGENT_TYPES)
            new_type = random.choice(compatible_types)
            if new_type != genome.agent_type:
                genome.agent_type = new_type
                genome.domain_crossover_source = genome.agent_type
                mutations_applied += 1

        if mutations_applied > 0:
            self._total_mutations += mutations_applied
            logger.debug("evolutionary_breeding: mutated %s (%d mutations)",
                          genome.genome_id[:12], mutations_applied)

        return genome

    # ── Internal helpers ────────────────────────────────────────────────────

    def _seed_population(self) -> None:
        """Create the initial random population."""
        for _ in range(self.population_size):
            agent_type = random.choice(_AGENT_TYPES)
            genome = AgentGenome(agent_type=agent_type)
            genome.generation_born = 0
            self._gene_pool.add(genome)

        logger.info("evolutionary_breeding: seeded population of %d agents (%d types)",
                     self.population_size, len(set(g.agent_type for g in self._gene_pool.population)))

    def _generate_wildcard(self) -> AgentGenome:
        """Generate a completely random wildcard agent for diversity injection."""
        agent_type = random.choice(_AGENT_TYPES)
        wildcard = AgentGenome(
            genome_id=f"wild_{uuid.uuid4().hex[:8]}",
            agent_type=agent_type,
            status=AgentStatus.WILDCARD,
            mutation_rate=random.uniform(0.05, 0.35),
        )
        # Boost technique count for wildcards
        pool = _TECHNIQUE_POOLS.get(agent_type, _TECHNIQUE_POOLS.get("recon", []))
        wildcard.techniques = random.sample(pool, min(len(pool), random.randint(5, 15)))
        wildcard.evasion_strategies = random.sample(_EVASION_STRATEGIES, random.randint(4, 10))
        wildcard.generation_born = self._gene_pool.generation + 1
        logger.debug("evolutionary_breeding: generated wildcard %s (type=%s)",
                      wildcard.genome_id, agent_type)
        return wildcard

    def _apply_domain_crossover(
        self, child: AgentGenome, type_a: str, type_b: str
    ) -> AgentGenome:
        """Apply domain crossover: blend techniques from both parent domains.

        Example: Recon x IoT -> child gets IoT-specific recon techniques
        that neither pure recon nor pure IoT would have alone.
        """
        pool_a = _TECHNIQUE_POOLS.get(type_a, [])
        pool_b = _TECHNIQUE_POOLS.get(type_b, [])

        # Take techniques from both domains
        from_a = random.sample(pool_a, min(len(pool_a), random.randint(1, 4)))
        from_b = random.sample(pool_b, min(len(pool_b), random.randint(1, 4)))

        # Merge and deduplicate
        combined = list(set(from_a + from_b))
        # Keep some original child techniques for stability
        keep_from_child = random.sample(
            child.techniques,
            min(len(child.techniques), random.randint(1, 3)),
        )
        child.techniques = list(set(combined + keep_from_child))

        # Also blend tool preferences
        for category, tools in _TOOL_PREFERENCES_POOL.items():
            if random.random() < 0.3:  # 30% chance to add a tool from the new domain
                child.tool_preferences[category] = random.choice(tools)

        child.domain_crossover_source = f"{type_a} x {type_b}"
        self._total_domain_crossovers += 1
        logger.debug("evolutionary_breeding: domain crossover %s x %s -> %s",
                      type_a, type_b, child.genome_id[:12])
        return child

    @staticmethod
    def _crossover_list(list_a: List[str], list_b: List[str]) -> List[str]:
        """Crossover two lists: interleaved merge with random trim."""
        combined = []
        max_len = max(len(list_a), len(list_b))
        for i in range(max_len):
            if i < len(list_a):
                combined.append(list_a[i])
            if i < len(list_b):
                combined.append(list_b[i])
        # Deduplicate preserving order
        seen: Set[str] = set()
        deduped = []
        for item in combined:
            if item not in seen:
                seen.add(item)
                deduped.append(item)
        # Random trim to reasonable size
        target_size = random.randint(
            min(len(list_a), len(list_b)),
            max(len(list_a), len(list_b)),
        )
        if len(deduped) > target_size:
            deduped = random.sample(deduped, target_size)
        return sorted(deduped)

    @staticmethod
    def _crossover_dict(dict_a: Dict[str, str], dict_b: Dict[str, str]) -> Dict[str, str]:
        """Crossover two dicts: random assignment from either parent per key."""
        all_keys = set(dict_a.keys()) | set(dict_b.keys())
        result = {}
        for key in all_keys:
            result[key] = random.choice([
                dict_a.get(key, dict_b.get(key, "")),
                dict_b.get(key, dict_a.get(key, "")),
            ])
        return result

    @staticmethod
    def _crossover_timing(
        timing_a: Dict[str, Any], timing_b: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Crossover timing patterns: parameter-level inheritance."""
        # Inherit the structure from a random parent
        child_timing = dict(random.choice([timing_a, timing_b]))
        # For numeric parameters, take the average
        for key in ("jitter", "delay_ms", "burst_count", "parallel_workers", "random_factor"):
            if key in timing_a and key in timing_b:
                va, vb = timing_a[key], timing_b[key]
                if isinstance(va, (int, float)) and isinstance(vb, (int, float)):
                    child_timing[key] = round((va + vb) / 2, 2)
        return child_timing

    @staticmethod
    def _generate_default_missions(count: int = 20) -> List[Mission]:
        """Generate a default set of evaluation missions."""
        missions = []
        for i in range(count):
            objective = random.choice(_MISSION_OBJECTIVES)
            difficulty = random.choice(list(MissionDifficulty))
            missions.append(Mission(
                mission_id=f"msn_default_{i:03d}",
                objective=objective,
                difficulty=difficulty,
                timeout_seconds=random.choice([60, 120, 300, 600]),
                weight=round(random.uniform(0.5, 2.0), 1),
            ))
        return missions

    def _default_fitness_evaluator(
        self, genome: AgentGenome, missions: List[Mission]
    ) -> FitnessScore:
        """Default simulated fitness evaluator.

        In production, this would execute the agent against real targets.
        Here we simulate based on genome quality heuristics to enable
        the evolutionary algorithm to function standalone.
        """
        total_missions = len(missions)
        if total_missions == 0:
            return FitnessScore()

        completed = 0
        total_time_ms = 0.0
        total_detections = 0
        total_alerts = 0
        total_exfil_bytes = 0
        total_hops = 0
        escalated = False

        for mission in missions:
            # Simulate mission execution based on genome quality
            technique_match = len(
                set(genome.techniques) & set(mission.allowed_techniques)
            ) if mission.allowed_techniques else len(genome.techniques)

            # More techniques = higher chance of success
            base_success_prob = min(0.95, 0.2 + len(genome.techniques) * 0.04)
            # Relevant techniques boost success
            if mission.allowed_techniques:
                base_success_prob += technique_match * 0.05

            # Difficulty penalty
            difficulty_penalty = mission.difficulty.value * 0.06
            success_prob = max(0.05, base_success_prob - difficulty_penalty)

            # More evasion strategies -> fewer detections
            evasion_quality = min(1.0, len(genome.evasion_strategies) * 0.07)
            detection_prob = max(0.02, 0.5 - evasion_quality)

            if random.random() < success_prob:
                completed += 1
                total_time_ms += random.uniform(
                    mission.timeout_seconds * 200,
                    mission.timeout_seconds * 800,
                )
                if random.random() < 0.3:
                    escalated = True
                total_hops += random.randint(0, 5)
                total_exfil_bytes += random.randint(0, 10_000_000)
            else:
                total_time_ms += mission.timeout_seconds * 1000

            if random.random() < detection_prob:
                total_detections += 1
                if random.random() < 0.3:
                    total_alerts += 1

        success_rate = completed / total_missions
        stealth_score = max(0.0, 1.0 - (total_detections / total_missions) * 0.5)
        speed_score = max(0.0, 1.0 - (total_time_ms / (total_missions * 600_000)))

        # Adaptability: diverse techniques that succeeded = adaptable
        adaptability = min(1.0, len(genome.techniques) / 20.0)
        if genome.domain_crossover_source:
            adaptability += 0.1  # domain crossover boosts adaptability
        adaptability = min(1.0, adaptability)

        score = FitnessScore(
            success_rate=round(success_rate, 4),
            stealth_score=round(stealth_score, 4),
            speed_score=round(speed_score, 4),
            adaptability=round(adaptability, 4),
            missions_completed=completed,
            missions_attempted=total_missions,
            avg_time_to_complete_ms=round(total_time_ms / max(total_missions, 1), 1),
            detections_triggered=total_detections,
            alerts_generated=total_alerts,
            data_exfiltrated_bytes=total_exfil_bytes,
            lateral_hops=total_hops,
            privileges_escalated=escalated,
        )
        score.compute_total()
        return score

    # ── Query methods ───────────────────────────────────────────────────────

    def get_fittest(self, n: int = 1) -> Union[AgentGenome, List[AgentGenome]]:
        """Get the fittest agent(s) from the current population.

        Args:
            n: Number of fittest agents to return.

        Returns:
            Single AgentGenome if n=1, else list of AgentGenome.
        """
        result = self._gene_pool.get_fittest(n)
        if n == 1:
            return result[0] if result else None
        return result

    def get_population(self) -> List[AgentGenome]:
        """Get the current population."""
        return self._gene_pool.population

    def get_gene_pool_stats(self) -> Dict[str, Any]:
        """Get gene pool statistics."""
        return self._gene_pool.stats()

    def get_diversity(self) -> float:
        """Get current genetic diversity measure."""
        return self._gene_pool.diversity_measure()

    @property
    def generation(self) -> int:
        """Current generation number."""
        return self._gene_pool.generation

    @property
    def generation_history(self) -> List[GenerationReport]:
        """Full generation history."""
        return list(self._generation_history)

    @property
    def last_report(self) -> Optional[GenerationReport]:
        """Report for the most recent generation."""
        return self._last_report

    def get_stats(self) -> Dict[str, Any]:
        """Return comprehensive engine statistics."""
        pool_stats = self._gene_pool.stats()
        return {
            "population_size": self.population_size,
            "current_generation": self.generation,
            "total_agents_bred": self._total_agents_bred,
            "total_mutations": self._total_mutations,
            "total_crossovers": self._total_crossovers,
            "total_domain_crossovers": self._total_domain_crossovers,
            "elitism_rate": self.elitism_rate,
            "mutation_rate": self.mutation_rate,
            "crossover_rate": self.crossover_rate,
            "diversity_interval": self.diversity_interval,
            "genetic_diversity": self.get_diversity(),
            "pool_stats": pool_stats,
            "generations_completed": len(self._generation_history),
        }

    def reset(self) -> None:
        """Reset the engine state."""
        self._gene_pool = GenePool(max_size=self.population_size)
        self._generation_history.clear()
        self._last_report = None
        self._total_agents_bred = 0
        self._total_mutations = 0
        self._total_crossovers = 0
        self._total_domain_crossovers = 0
        random.seed(self._seed)
        logger.info("evolutionary_breeding: engine reset")
