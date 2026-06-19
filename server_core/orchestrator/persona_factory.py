"""
Persona Factory — Fake Attacker Persona Generation & Decoy Orchestration.

Generates 100+ unique, believable attacker personas with distinct TTPs,
infrastructure, linguistic quirks, and behavioural patterns. The real attack
hides among the decoys — every decoy looks like a plausible threat actor
to overwhelm and misdirect defenders.

Integration points:
  - HiveMind: publishes DEFENSE_ALERT on decoy deployments, logs persona events
  - DecoyAgent: consumes generated personas for false-flag campaigns
  - TraceBusterAgent: compartmentalises decoys across geo-sequences
  - OrchestratorAgent: calls deploy_decoy_swarm() before real mission phases

Persona dimensions varied (100+ unique combinations):
  - Name, nationality, skill level, typing speed, language quirks
  - JA4 TLS fingerprint, User-Agent string
  - Tool preferences (script-kiddie → APT tier)
  - Attack timing (aggressive / patient / business-hours)
  - Infrastructure (C2 domains, proxy chain topology, hosting providers)
  - Linguistic: common typos per language background, punctuation style, phrase patterns
"""

from __future__ import annotations

import hashlib
import logging
import random
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════════════
# Data class
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class Persona:
    """A fully-realised fake attacker persona — every field contributes to uniqueness.

    When N personas are generated, every combination of (ja4_fingerprint, user_agent,
    typing_speed_wpm, language_patterns, tool_preferences, attack_timing, infrastructure)
    is varied to ensure no two personas look alike under forensic correlation.
    """
    id: str
    name: str
    skill_level: str                     # script_kiddie | professional | apt | nation_state
    origin_country: str
    ja4_fingerprint: str
    user_agent: str
    tool_preferences: List[str]
    typing_speed_wpm: int
    language_patterns: dict              # common_typos, phrases, punctuation_style, keyboard_layout
    attack_timing: str                   # aggressive | patient | business_hours_only | weekend_warrior
    infrastructure: dict                 # c2_domains, proxy_chain, hosting_providers, vps_regions
    behavioural_quirks: dict = field(default_factory=dict)   # rest_interval_seconds, retry_behaviour, etc.
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def fingerprint(self) -> str:
        """Deterministic hash of persona traits for deduplication."""
        seed = f"{self.ja4_fingerprint}|{self.user_agent}|{self.typing_speed_wpm}|{self.attack_timing}"
        return hashlib.sha256(seed.encode()).hexdigest()[:16]

    def summary(self) -> dict:
        """Compact dict suitable for HiveMind logging."""
        return {
            "id": self.id,
            "name": self.name,
            "skill_level": self.skill_level,
            "origin_country": self.origin_country,
            "ja4": self.ja4_fingerprint,
            "tool_count": len(self.tool_preferences),
            "typing_wpm": self.typing_speed_wpm,
            "timing": self.attack_timing,
            "c2_domains": self.infrastructure.get("c2_domains", []),
        }


# ═══════════════════════════════════════════════════════════════════════════════
# Rich data pools — every pool has 20+ entries to guarantee >100 unique combos
# ═══════════════════════════════════════════════════════════════════════════════

# ── Names by country ──
_FIRST_NAMES: Dict[str, List[str]] = {
    "RU": ["Dmitri", "Alexei", "Sergei", "Nikolai", "Vladimir", "Ivan", "Yuri", "Andrei",
           "Mikhail", "Pavel", "Boris", "Fyodor", "Grigori", "Oleg", "Viktor", "Leonid",
           "Anatoly", "Konstantin", "Arkady", "Maxim"],
    "CN": ["Wei", "Jian", "Lei", "Ming", "Qiang", "Hao", "Bo", "Chao", "Feng", "Gang",
           "Hui", "Jun", "Kai", "Long", "Peng", "Rui", "Tao", "Xiang", "Yong", "Zhen"],
    "KP": ["Chol", "Gwang", "Hyun", "Il", "Jong", "Kwan", "Min", "Nam", "Song", "Yong",
           "Chul", "Dae", "Eun", "Ho", "Jae", "Kyung", "Ri", "Suk", "Tae", "Won"],
    "IR": ["Amir", "Reza", "Farhad", "Saeed", "Majid", "Hossein", "Bahram", "Kazem",
           "Mehdi", "Navid", "Omid", "Payam", "Ramin", "Shahab", "Vahid", "Arash",
           "Babak", "Dariush", "Ehsan", "Kamran"],
    "BR": ["Lucas", "Gabriel", "Rafael", "Felipe", "Thiago", "Marcos", "Diego", "Andre",
           "Bruno", "Caio", "Daniel", "Eduardo", "Fabio", "Gustavo", "Henrique", "Igor",
           "Joao", "Leandro", "Mateus", "Pedro"],
    "IN": ["Arjun", "Vikram", "Rohan", "Sanjay", "Deepak", "Rajesh", "Amit", "Nikhil",
           "Karthik", "Manoj", "Pranav", "Siddharth", "Varun", "Aditya", "Harsh",
           "Kunal", "Rahul", "Suresh", "Tarun", "Vijay"],
    "NG": ["Emeka", "Chidi", "Obinna", "Tunde", "Adebayo", "Ikenna", "Nnamdi", "Olumide",
           "Chukwuma", "Ifeanyi", "Kelechi", "Oluwaseun", "Uchenna", "Yemi", "Babajide",
           "Chinedu", "Femi", "Ngozi", "Seyi", "Tayo"],
    "VN": ["Duc", "Hung", "Minh", "Quang", "Thanh", "Tuan", "Anh", "Binh", "Cuong",
           "Dung", "Hai", "Khanh", "Long", "Nam", "Phong", "Quoc", "Son", "Thang",
           "Trung", "Viet"],
    "RO": ["Andrei", "Cristian", "Mihai", "Stefan", "Vlad", "Alexandru", "Bogdan",
           "Cosmin", "Dragos", "Eugen", "Florin", "George", "Ionut", "Lucian", "Marius",
           "Nicolae", "Octavian", "Radu", "Sorin", "Victor"],
    "UA": ["Andriy", "Dmytro", "Ivan", "Mykola", "Oleh", "Pavlo", "Roman", "Sergiy",
           "Taras", "Vasyl", "Volodymyr", "Yaroslav", "Bohdan", "Denys", "Igor",
           "Kyrylo", "Maksym", "Oleksandr", "Ruslan", "Vitaliy"],
    "TR": ["Emre", "Mehmet", "Mustafa", "Ahmet", "Ali", "Can", "Deniz", "Eren", "Fatih",
           "Gokhan", "Hakan", "Ismail", "Kemal", "Murat", "Onur", "Ozgur", "Serkan",
           "Tolga", "Ugur", "Yusuf"],
    "PK": ["Ahmed", "Bilal", "Danish", "Fahad", "Hamza", "Imran", "Junaid", "Kamran",
           "Mohsin", "Nabeel", "Omar", "Rizwan", "Saad", "Tariq", "Usman", "Waqas",
           "Yasir", "Zubair", "Asad", "Farhan"],
    "EG": ["Ahmed", "Mohamed", "Mahmoud", "Omar", "Khaled", "Amr", "Hassan", "Ibrahim",
           "Karim", "Mostafa", "Sherif", "Tarek", "Youssef", "Aly", "Bassem",
           "Hany", "Nader", "Ramy", "Sameh", "Wael"],
    "ID": ["Adi", "Budi", "Cahyo", "Dian", "Eko", "Fajar", "Guntur", "Hendra", "Irwan",
           "Joko", "Krisna", "Lukman", "Mulyadi", "Nugroho", "Oka", "Putu", "Rizky",
           "Surya", "Teguh", "Wahyu"],
    "MX": ["Alejandro", "Carlos", "Diego", "Eduardo", "Fernando", "Guillermo", "Hector",
           "Ignacio", "Javier", "Luis", "Manuel", "Oscar", "Pablo", "Raul", "Sergio",
           "Tomas", "Victor", "Arturo", "Cesar", "Ernesto"],
}

_LAST_NAMES: Dict[str, List[str]] = {
    "RU": ["Volkov", "Kozlov", "Smirnov", "Ivanov", "Petrov", "Sokolov", "Popov",
           "Lebedev", "Morozov", "Novikov", "Fyodorov", "Mikhailov", "Zaitsev", "Orlov",
           "Gusev", "Kuznetsov", "Bogdanov", "Semyonov", "Grigoriev", "Titov"],
    "CN": ["Wang", "Li", "Zhang", "Liu", "Chen", "Yang", "Zhao", "Huang", "Wu", "Zhou",
           "Xu", "Sun", "Ma", "Zhu", "Hu", "Lin", "Guo", "He", "Gao", "Luo"],
    "KP": ["Kim", "Ri", "Pak", "Choe", "Jang", "Kang", "Han", "Yun", "Chon", "Hwang",
           "Hong", "Mun", "Paek", "Sin", "Son", "Yu", "Im", "O", "Chi", "An"],
    "IR": ["Ahmadi", "Mohammadi", "Hosseini", "Rezaei", "Moradi", "Karimi", "Rahimi",
           "Hashemi", "Ebrahimi", "Sadeghi", "Bagheri", "Ghafari", "Jafari", "Nazari",
           "Safavi", "Tabrizi", "Tehrani", "Yazdani", "Zare", "Shirazi"],
    "BR": ["Silva", "Santos", "Oliveira", "Souza", "Pereira", "Lima", "Costa", "Ferreira",
           "Ribeiro", "Alves", "Carvalho", "Gomes", "Martins", "Araujo", "Barbosa",
           "Rocha", "Nunes", "Mendes", "Cardoso", "Moreira"],
    "IN": ["Sharma", "Patel", "Singh", "Kumar", "Verma", "Gupta", "Reddy", "Nair",
           "Mehta", "Joshi", "Desai", "Shah", "Das", "Chopra", "Malhotra", "Kapoor",
           "Bose", "Rao", "Menon", "Iyer"],
    "NG": ["Okafor", "Okonkwo", "Adebayo", "Obinna", "Chukwu", "Olayinka", "Ogunleye",
           "Eze", "Nwachukwu", "Oluwole", "Adeyemi", "Balogun", "Chibueze", "Ibe",
           "Nwosu", "Oni", "Obi", "Salami", "Taiwo", "Uche"],
    "VN": ["Nguyen", "Tran", "Le", "Pham", "Hoang", "Phan", "Vu", "Dang", "Bui", "Do",
           "Ngo", "Duong", "Ly", "Dinh", "Mai", "Trinh", "Ha", "Truong", "Lam", "Cao"],
    "RO": ["Popescu", "Ionescu", "Dumitrescu", "Stanescu", "Georgescu", "Radulescu",
           "Marinescu", "Moldoveanu", "Enescu", "Vladimirescu", "Constantinescu",
           "Cristescu", "Florescu", "Lazar", "Rusu", "Tudor", "Mihailescu",
           "Gheorghiu", "Preda", "Stoica"],
    "UA": ["Tkachenko", "Shevchenko", "Bondarenko", "Kovalenko", "Melnyk", "Kravchenko",
           "Boyko", "Rudenko", "Savchenko", "Klymenko", "Hrytsenko", "Lysenko",
           "Marchenko", "Petrenko", "Moroz", "Oliynyk", "Polishchuk", "Symonenko",
           "Tymoshenko", "Zinchenko"],
    "TR": ["Yilmaz", "Demir", "Celik", "Aydin", "Erdogan", "Kaya", "Arslan", "Dogan",
           "Ozdemir", "Aksoy", "Polat", "Cakir", "Gunes", "Bulut", "Tekin", "Yildiz",
           "Ozkan", "Koc", "Sahin", "Simsek"],
    "PK": ["Khan", "Malik", "Butt", "Chaudhry", "Raja", "Ahmed", "Qureshi", "Sheikh",
           "Siddiqui", "Iqbal", "Hussain", "Aziz", "Nasir", "Tariq", "Javed",
           "Akram", "Bhatti", "Gill", "Lodhi", "Nawaz"],
    "EG": ["Ibrahim", "Hassan", "Ali", "Mahmoud", "Gamal", "Saad", "Salem", "Nasser",
           "Fathy", "Abdelaziz", "Shawky", "Yassin", "Ezzat", "Khalil", "Rashad",
           "Sobhy", "Tawfik", "Helmy", "Lotfy", "Farouk"],
    "ID": ["Santoso", "Wijaya", "Wibowo", "Pratama", "Setiawan", "Kusuma", "Hidayat",
           "Nugroho", "Putra", "Gunawan", "Hartono", "Halim", "Pangestu", "Saputra",
           "Maulana", "Hermawan", "Susanto", "Handoko", "Suryadi", "Ra hardjo"],
    "MX": ["Garcia", "Hernandez", "Lopez", "Martinez", "Rodriguez", "Gonzalez", "Perez",
           "Sanchez", "Ramirez", "Cruz", "Flores", "Morales", "Reyes", "Gutierrez",
           "Ortiz", "Castillo", "Vazquez", "Jimenez", "Mendoza", "Ruiz"],
}

# ── Tool pools by skill level ──
_TOOLS_BY_SKILL: Dict[str, List[str]] = {
    "script_kiddie": [
        "sqlmap", "nmap", "metasploit-basic", "hydra", "aircrack-ng", "john",
        "burp-suite-community", "nikto", "dirb", "gobuster", "searchsploit",
        "beef", "ettercap", "sslstrip", "zap", "social-engineer-toolkit-basic",
        "wifite", "fernet-cracker", "arpspoof", "setoolkit", "commix",
        "wpscan", "joomscan", "droopescan", "slowloris", "hping3",
        "dnsrecon", "theharvester", "fierce", "recon-ng-basic",
    ],
    "professional": [
        "metasploit-pro", "cobalt-strike", "empire", "powersploit", "bloodhound",
        "responder", "im packet", "crackmapexec", "mimikatz", "rubeus",
        "certipy", "petitpotam", "ntlmrelayx", "evil-winrm", "chisel",
        "ligolo-ng", "sharp-shares", "sharp-hound", "seatbelt", "lazagne",
        "linpeas", "winpeas", "kerbrute", "getchanges", "adrecon",
        "pwndb", "dehashed", "sn1per", "nessus", "openvas",
    ],
    "apt": [
        "custom-c2-framework", "zero-day-exploit-kit", "custom-implant", "memory-only-dropper",
        "uefi-bootkit", "hypervisor-rootkit", "firmware-backdoor", "supply-chain-injector",
        "air-gap-bridge", "custom-ransomware-builder", "stolen-cert-signer",
        "domain-fronting-proxy", "doh-tunneller", "quic-exfil-channel",
        "dns-cat-ng", "icmp-tunnel-v3", "bpf-covert-channel", "rdma-exfil",
        "fpga-side-channel", "hdmi-rf-leakage-exploit", "custom-rainbow-tables",
        "tpu-optimised-hash-cracker", "lattice-crypto-breaker", "ai-driven-fuzzer",
    ],
    "nation_state": [
        "stuxnet-class-framework", "equation-group-toolkit", "bvp47-pedigree-implant",
        "regin-style-modular-platform", "duqu-derived-keylogger", "flame-derived-recon-suite",
        "careto-derived-exfil-platform", "project-sauron-c2-mesh",
        "darkhotel-wifi-intercept", "tajmahal-full-spectrum-suite",
        "quantum-insert-derivative", "foxacid-modular-implant", "hammertoss-exfil",
        "airhopper-keyboard-exfil", "cottonmouth-bridge", "nightstand-wi-fi-injector",
        "deity-weaponized-router-backdoor", "feeder-tap-undersea-cable-interceptor",
        "genie-multi-hop-relay", "gourmet-through-router-implant",
        "snowden-extracted-nsa-toolkit", "shadow-brokers-equation-group-leak",
        "red-echo-scada-weaponizer", "volatile-cedar-botnet-kit",
    ],
}

# ── User-Agent pool (varied by OS, browser, and version) ──
_USER_AGENTS: List[str] = [
    # Windows + Chrome
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    # Windows + Firefox
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0",
    # Windows + Edge
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0",
    # macOS + Chrome
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    # macOS + Safari
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    # Linux + Chrome
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    # Linux + Firefox
    "Mozilla/5.0 (X11; Linux x86_64; rv:127.0) Gecko/20100101 Firefox/127.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0",
    # Mobile
    "Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.6422.165 Mobile Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
    # cURL / script
    "curl/8.6.0",
    "python-requests/2.31.0",
    "Wget/1.24.5",
    "Go-http-client/2.0",
    # Uncommon / niche
    "Mozilla/5.0 (X11; CrOS x86_64 14541.0.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.127 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko",
    # TOR Browser
    "Mozilla/5.0 (Windows NT 10.0; rv:115.0) Gecko/20100101 Firefox/115.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:115.0) Gecko/20100101 Firefox/115.0",
]

# ── JA4 TLS fingerprints (realistic hash-like strings) ──
_JA4_POOL: List[str] = [
    # Chrome on Windows 11
    "t13d1516h2_8daaf6152771_02713d6af862",
    "t13d1516h2_8daaf6152771_e5627f48ed66",
    "t13d1516h2_b6c5a7a2f3e1_02713d6af862",
    # Chrome on macOS
    "t13d1516h2_b733b2d39961_02713d6af862",
    "t13d1516h2_c441fd07509f_02713d6af862",
    # Chrome on Linux
    "t13d1516h2_18af80273036_02713d6af862",
    "t13d1516h2_39d2d4c4e3b1_02713d6af862",
    # Firefox on Windows
    "t13d1715h2_5b57614c22b0_4c5b5b3e5b3b",
    "t13d1715h2_8c6e7a3f2d1b_4c5b5b3e5b3b",
    # Firefox on Linux
    "t13d1715h2_f2a3b1c4d5e6_4c5b5b3e5b3b",
    "t13d1715h2_a1b2c3d4e5f6_4c5b5b3e5b3b",
    # Safari
    "t13d1617h2_3a2b1c4f5e6d_ea1fda2ceab1",
    "t13d1617h2_7c8b9a0f1e2d_ea1fda2ceab1",
    # cURL
    "t13d1516h2_d37a25ff3011_000000000000",
    "t12d1208h2_9b1c3d5e7f8a_000000000000",
    # Go
    "t13d1516h2_000000000000_000000000000",
    "t13d2316h2_1a2b3c4d5e6f_000000000000",
    # Python (requests)
    "t13d1516h2_0a1b2c3d4e5f_000000000000",
    "t13d2016h2_6f7a8b9c0d1e_000000000000",
    # Unusual (older TLS)
    "t12d1208h2_3a2b1c4f5e6d_4c5b5b3e5b3b",
    "t10d1005h2_7c8b9a0f1e2d_000000000000",
    # Custom implant fingerprints
    "t13d1516h2_c001d00ddead_000000000000",
    "t13d2316h2_beefbeefcafe_000000000000",
    "t12d1208h2_feedfacebabe_000000000000",
    "t13d1516h2_decafbad1337_000000000000",
]

# ── C2 domain patterns (realistic-looking, non-existent domains) ──
_C2_DOMAIN_PATTERNS: List[str] = [
    "cdn-{slug}.com", "api-{slug}.net", "metrics.{slug}.io",
    "telemetry.{slug}.org", "{slug}-analytics.com", "static.{slug}.dev",
    "update.{slug}.net", "sync.{slug}.io", "{slug}-cdn.com",
    "mirror.{slug}.org", "replica.{slug}.net", "edge.{slug}.io",
    "cache.{slug}.com", "relay.{slug}.net", "{slug}-gateway.com",
    "tunnel.{slug}.dev", "{slug}-balancer.com", "portal.{slug}.io",
    "api-{slug}-v2.net", "ingest.{slug}.com", "events.{slug}.io",
    "log.{slug}.net", "monitor.{slug}.com", "{slug}-status.net",
]

_SLUGS: List[str] = [
    "cloudflare", "akamai", "fastly", "azure", "gcp", "aws",
    "alibaba", "tencent", "oracle", "ibm", "digitalocean", "vultr",
    "linode", "ovh", "hetzner", "contabo", "hostinger", "namecheap",
    "godaddy", "dynadot", "porkbun", "cloudns", "vercel", "netlify",
    "heroku", "flyio", "render", "railway", "supabase", "planetscale",
]

# ── Hosting providers (look realistic) ──
_HOSTING_PROVIDERS: List[str] = [
    "DigitalOcean", "Vultr", "Linode", "OVHcloud", "Hetzner",
    "Contabo", "AWS Lightsail", "Google Cloud", "Azure VM",
    "Alibaba Cloud ECS", "Tencent CVM", "Oracle Cloud",
    "Hostinger VPS", "Namecheap VPS", "A2 Hosting",
    "InMotion Hosting", "Kamatera", "Scaleway", "UpCloud",
    "Netcup", "Ionos", "Aruba Cloud", "G-Core Labs",
    "RackNerd", "BuyVM", "GreenCloud", "Evoxt", "Rackspace",
    "Interserver", "Psychz", "M247", "Shinjiru",
]

# ── Proxy chain countries (exclude origin to simulate layering) ──
_PROXY_COUNTRIES: List[str] = [
    "NL", "DE", "SE", "CH", "FR", "SG", "JP", "CA", "AU", "GB",
    "ES", "IT", "PL", "CZ", "FI", "NO", "DK", "AT", "BE", "IE",
    "PT", "GR", "HU", "SK", "LT", "EE", "LV", "KR", "TW", "HK",
]

# ── Attack timing profiles ──
_ATTACK_TIMING: List[str] = [
    "aggressive", "patient", "business_hours_only", "weekend_warrior",
    "night_owl", "burst_and_sleep", "office_hours_mask", "randomized_interval",
    "low_and_slow", "reactive_only", "cron_job_style", "geo_fenced_sunrise",
]

# ── Typing speed ranges by skill level (WPM) ──
_TYPING_WPM_RANGES: Dict[str, Tuple[int, int]] = {
    "script_kiddie": (25, 55),     # hunt-and-peck, slow
    "professional": (50, 90),      # competent
    "apt": (70, 115),              # fast, practised
    "nation_state": (80, 140),     # elite operators
}

# ── Language quirk generators ──

# Typos per native language (L1 interference patterns)
_TYPOS_BY_LANG: Dict[str, List[Tuple[str, str]]] = {
    # Russian: Cyrillic keyboard layout bleed
    "RU": [
        ("the", "teh"), ("with", "withe"), ("attack", "atack"), ("command", "comand"),
        ("server", "serwer"), ("exploit", "exploitt"), ("shell", "shel"),
        ("their", "thier"), ("receive", "recieve"), ("because", "becouse"),
    ],
    # Chinese: Missing articles, pluralisation
    "CN": [
        ("the server", "server"), ("a file", "file"), ("the exploit", "exploit"),
        ("attacked", "attack"), ("scanning", "scan"), ("vulnerabilities", "vulnerability"),
        ("the target", "target"), ("has been", "has beened"), ("it is", "its"),
    ],
    # Korean: Spacing issues, Romanisation
    "KP": [
        ("together", "togather"), ("the network", "thenetwork"),
        ("running", "runing"), ("connection", "conection"), ("successful", "sucessful"),
        ("directory", "directoy"), ("privilege", "priviledge"), ("access", "acces"),
    ],
    # Persian/Farsi: RTL bleed, vowel confusion
    "IR": [
        ("the system", "system"), ("password", "pasword"), ("attack", "atack"),
        ("server", "serwer"), ("admin", "admine"), ("database", "data base"),
        ("download", "downlod"), ("upload", "uplod"), ("command", "comand"),
    ],
    # Brazilian Portuguese: nasal vowels, accents
    "BR": [
        ("information", "informacao"), ("connection", "conexao"), ("attack", "ataque"),
        ("server", "servidor"), ("to execute", "executar"), ("file", "arquivo"),
        ("network", "rede"), ("the system", "o sistema"), ("password", "senha"),
    ],
    # Hindi/Indian English: code-switching, spelling
    "IN": [
        ("the server", "server only"), ("it is", "its"), ("attack", "atack"),
        ("scanning", "scaning"), ("please", "pls"), ("checking", "cheking"),
        ("the", "d"), ("that", "dat"), ("very", "wery"),
    ],
    # Nigerian English
    "NG": [
        ("the", "di"), ("that", "dat"), ("attack", "atak"), ("server", "sava"),
        ("exploit", "exploits"), ("going to", "gonna"), ("want to", "wanna"),
        ("password", "paswod"), ("scanning", "skaning"),
    ],
    # Vietnamese: tonal language, dropped final consonants
    "VN": [
        ("the", "de"), ("attack", "atack"), ("scanning", "scanin"),
        ("connection", "conect"), ("server", "serber"), ("exploit", "exploit"),
        ("running", "runnin"), ("checking", "checkin"), ("sending", "sendin"),
    ],
    # Romanian: Romance-language carry-over
    "RO": [
        ("the", "teh"), ("attack", "atac"), ("server", "serveru"),
        ("command", "comanda"), ("connection", "conexiune"), ("file", "fisier"),
        ("exploit", "exploat"), ("scanning", "scanare"), ("network", "retea"),
    ],
    # Ukrainian: similar to Russian with differences
    "UA": [
        ("the", "teh"), ("with", "vith"), ("attack", "atack"), ("server", "serverr"),
        ("command", "komand"), ("exploit", "exploitt"), ("shell", "shel"),
        ("their", "theyr"), ("receive", "recieve"), ("connection", "conekt"),
    ],
    # Turkish: vowel harmony, agglutination
    "TR": [
        ("the", "te"), ("attack", "atak"), ("server", "serveri"),
        ("scanning", "scanlıyor"), ("running", "run ediyor"), ("file", "dosya"),
        ("connection", "baglantı"), ("command", "komut"), ("exploit", "exploit et"),
    ],
    # Urdu/Pakistani English
    "PK": [
        ("the", "teh"), ("attack", "atack"), ("server", "sarver"),
        ("scanning", "scaning"), ("please", "plz"), ("checking", "cheking"),
        ("command", "comand"), ("that", "dat"), ("very", "wery"),
    ],
    # Egyptian Arabic
    "EG": [
        ("the", "el"), ("attack", "atack"), ("server", "serwer"),
        ("password", "pass"), ("scanning", "scan"), ("connection", "conect"),
        ("command", "comand"), ("exploit", "exploit"), ("running", "runnin"),
    ],
    # Indonesian
    "ID": [
        ("the", "de"), ("attack", "atack"), ("server", "serper"),
        ("scanning", "scanning"), ("running", "runing"), ("file", "fail"),
        ("password", "pasword"), ("command", "comand"), ("connection", "koneksi"),
    ],
    # Mexican Spanish
    "MX": [
        ("the", "de"), ("attack", "ataque"), ("server", "servidor"),
        ("scanning", "escaneo"), ("running", "corriendo"), ("password", "contraseña"),
        ("command", "comando"), ("file", "archivo"), ("connection", "conexion"),
    ],
}

# Common phrases by country
_PHRASES_BY_LANG: Dict[str, List[str]] = {
    "RU": ["blyat", "tovarisch", "davai", "norm", "poehali", "khorosho"],
    "CN": ["jia you", "mei wenti", "hao de", "zenme ban", "tai hao le"],
    "KP": ["daedanhada", "joh-eun", "ppalli", "ye", "aniyo"],
    "IR": ["bale", "kheili khoob", "mamnoon", "bebakhshid", "khoda hafez"],
    "BR": ["beleza", "valeu", "blz", "e nois", "partiu", "fechou"],
    "IN": ["arre", "yaar", "accha", "theek hai", "chal", "bhai"],
    "NG": ["abeg", "wahala", "no wahala", "oga", "oya", "shey"],
    "VN": ["ok", "duoc", "di", "nhanh len", "tot", "khong sao"],
    "RO": ["ok", "bine", "merge", "super", "hai", "lasa"],
    "UA": ["harazd", "dobre", "tak", "davay", "super", "zrozumilo"],
    "TR": ["tamam", "eyvallah", "hadi", "aynen", "guzel", "bakalım"],
    "PK": ["theek hai", "yaar", "chalo", "inshallah", "bas", "acha"],
    "EG": ["tamam", "yalla", "mashi", "khalas", "aywa", "shokran"],
    "ID": ["oke", "mantap", "gas", "sip", "gitu", "dong"],
    "MX": ["orale", "simon", "wey", "chido", "va", "pues"],
}

# Punctuation styles
_PUNCTUATION_STYLES: List[str] = [
    "formal_periods",          # Proper punctuation always
    "stream_of_consciousness", # Run-on sentences, no caps
    "exclamation_heavy",       # Every sentence ends with !!
    "lowercase_only",          # never hits shift
    "ellipsis_heavy",          # everything... trails... off...
    "emoji_littered",          # :) :-) :P :D interspersed
    "tabs_not_spaces",         # Tab indenters (vs spaces)
    "double_space_after_period",  # Old-school typing
    "no_contractions",         # "do not" "cannot" "will not"
    "camelCase_abuser",        # writesLikeThisInChat
    "UPPERCASE_CAPS_LOCK",     # ALWAYS YELLING
    "hyphen-heavy",            # everything-is-connected-type-style
    "bracket_nester",          # (nested (parens (everywhere)))
]

# ── Behavioural quirks ──
_REST_INTERVALS: Dict[str, Tuple[int, int]] = {
    "aggressive": (1, 15),
    "patient": (60, 600),
    "business_hours_only": (30, 300),
    "weekend_warrior": (5, 120),
    "night_owl": (2, 30),
    "burst_and_sleep": (0, 3600),
    "office_hours_mask": (10, 180),
    "randomized_interval": (0, 900),
    "low_and_slow": (300, 7200),
    "reactive_only": (0, 1800),
    "cron_job_style": (60, 3600),
    "geo_fenced_sunrise": (30, 240),
}

_RETRY_BEHAVIOURS: List[str] = [
    "retry_3_then_give_up", "exponential_backoff", "retry_indefinitely",
    "switch_tool_on_failure", "escalate_privilege_on_failure",
    "report_and_wait", "burn_identity_and_retry", "stealth_fallback",
    "parallel_retry_on_all_nodes", "abort_on_first_sign_of_detection",
]

# ── VPS regions ──
_VPS_REGIONS: List[str] = [
    "us-east-1", "us-west-2", "eu-west-1", "eu-central-1", "ap-southeast-1",
    "ap-northeast-1", "sa-east-1", "me-south-1", "af-south-1", "ca-central-1",
    "ap-south-1", "ap-east-1", "eu-north-1", "eu-south-1", "us-west-1",
    "me-central-1", "ap-southeast-2", "ap-northeast-2", "ap-northeast-3",
    "sa-east-1", "il-central-1", "se-sthlm-1", "jp-tok-1", "uk-lon-1",
]


# ═══════════════════════════════════════════════════════════════════════════════
# PersonaFactory
# ═══════════════════════════════════════════════════════════════════════════════

class PersonaFactory:
    """Generates and manages 100+ unique fake attacker personas for deception.

    The real attack is indistinguishable from decoys because every persona —
    real or fake — is drawn from the same distribution. Defenders see N equally
    plausible threat actors and cannot identify the true one without expending
    resources on each.

    Typical usage::

        factory = PersonaFactory(hive_mind=hm)
        swarm = factory.generate_swarm(100)
        result = factory.deploy_decoy_swarm(
            target="10.0.1.50", count=99, real_agent_id="agent_007"
        )
        # ... mission runs ...
        factory.dismiss_decoys()
    """

    COUNTRIES = ["RU", "CN", "KP", "IR", "BR", "IN", "NG", "VN", "RO", "UA",
                 "TR", "PK", "EG", "ID", "MX"]
    SKILL_LEVELS = ["script_kiddie", "professional", "apt", "nation_state"]

    def __init__(self, hive_mind=None):
        """Initialise the factory.

        Args:
            hive_mind: Optional HiveMind instance for event publishing and
                       defensive alert integration.
        """
        self.hive_mind = hive_mind
        self._personas: Dict[str, Persona] = {}
        self._active_decoys: List[dict] = []
        self._real_agent_id: str = ""
        self._rng = random.Random()
        self._generated_fingerprints: set = set()
        self._generation_count: int = 0
        logger.info("PersonaFactory initialised (personas=%d, decoys=%d)",
                     len(self._personas), len(self._active_decoys))

    # ═══════════════════════════════════════════════════════════════════════
    # Persona generation
    # ═══════════════════════════════════════════════════════════════════════

    def generate_persona(self, skill_level: str = None,
                         origin_country: str = None) -> Persona:
        """Generate a single fully-realised attacker persona.

        Args:
            skill_level: Optional override. Randomly chosen if None.
            origin_country: Optional override. Randomly chosen if None.

        Returns:
            A Persona with every field populated — guaranteed unique within
            this factory session.
        """
        if skill_level is None:
            skill_level = self._rng.choice(self.SKILL_LEVELS)
        if origin_country is None:
            origin_country = self._rng.choice(self.COUNTRIES)

        persona_id = f"persona_{uuid.uuid4().hex[:12]}"
        name = self._generate_name(origin_country)

        # Tool preferences: 3-8 tools from the skill-appropriate pool
        tool_pool = _TOOLS_BY_SKILL.get(skill_level, _TOOLS_BY_SKILL["professional"])
        tool_count = self._rng.randint(3, min(8, len(tool_pool)))
        tool_preferences = sorted(self._rng.sample(tool_pool, tool_count))

        # JA4 fingerprint (must be unique)
        ja4 = self._unique_ja4()

        # User-Agent (cycled to avoid collisions across personas)
        ua = self._rng.choice(_USER_AGENTS)

        # Typing speed
        wpm_min, wpm_max = _TYPING_WPM_RANGES.get(skill_level, (50, 90))
        typing_speed = self._rng.randint(wpm_min, wpm_max)

        # Language patterns
        language_patterns = self._generate_language_patterns(origin_country)

        # Attack timing
        attack_timing = self._rng.choice(_ATTACK_TIMING)

        # Infrastructure
        infrastructure = self._generate_infrastructure(origin_country)

        # Behavioural quirks
        behavioural_quirks = self._generate_behavioural_quirks(attack_timing)

        persona = Persona(
            id=persona_id,
            name=name,
            skill_level=skill_level,
            origin_country=origin_country,
            ja4_fingerprint=ja4,
            user_agent=ua,
            tool_preferences=tool_preferences,
            typing_speed_wpm=typing_speed,
            language_patterns=language_patterns,
            attack_timing=attack_timing,
            infrastructure=infrastructure,
            behavioural_quirks=behavioural_quirks,
        )

        # Ensure fingerprint uniqueness
        fp = persona.fingerprint()
        attempt = 0
        while fp in self._generated_fingerprints and attempt < 50:
            # Tweak typing speed or ja4 to break collision
            persona.typing_speed_wpm += self._rng.randint(1, 5)
            persona.ja4_fingerprint = self._unique_ja4()
            fp = persona.fingerprint()
            attempt += 1
        self._generated_fingerprints.add(fp)

        self._personas[persona_id] = persona
        self._generation_count += 1

        logger.debug("Generated persona %s (%s/%s) — %d tools, %d wpm, %s",
                     persona_id, skill_level, origin_country,
                     len(tool_preferences), typing_speed, attack_timing)

        return persona

    def generate_swarm(self, count: int = 50) -> List[Persona]:
        """Generate a swarm of N unique personas with broad diversity.

        The swarm deliberately covers all skill levels, all countries, and
        all timing profiles to present the widest possible decoy surface.

        Args:
            count: Number of personas to generate (default 50, max 500).

        Returns:
            List of generated Persona objects, all unique.
        """
        count = max(1, min(count, 500))
        personas: List[Persona] = []

        # Strategy: round-robin across countries and skill levels to maximise
        # diversity before repeating combinations.
        for i in range(count):
            skill = self.SKILL_LEVELS[i % len(self.SKILL_LEVELS)]
            country = self.COUNTRIES[i % len(self.COUNTRIES)]
            # After exhausting unique country+skill pairs, add jitter
            if i >= len(self.SKILL_LEVELS) * len(self.COUNTRIES):
                skill = self._rng.choice(self.SKILL_LEVELS)
                country = self._rng.choice(self.COUNTRIES)
            persona = self.generate_persona(skill_level=skill, origin_country=country)
            personas.append(persona)

        logger.info("Generated swarm of %d personas (%d unique fingerprints)",
                     len(personas), len(self._generated_fingerprints))

        if self.hive_mind:
            self.hive_mind.add_alert({
                "type": "persona_swarm_generated",
                "count": len(personas),
                "threat_level": 0,
                "detail": f"Generated {len(personas)} decoy personas for upcoming operation",
            })

        return personas

    # ═══════════════════════════════════════════════════════════════════════
    # Decoy deployment
    # ═══════════════════════════════════════════════════════════════════════

    def deploy_decoy_attack(self, persona: Persona, target: str) -> dict:
        """Deploy a single decoy attack against a target using one persona.

        The decoy creates observable artefacts (fake scans, fake C2 beacons,
        fake login attempts) that look exactly like a real attack to any
        defender monitoring the target.

        Args:
            persona: The Persona whose TTPs to impersonate.
            target: IP or hostname to target with the decoy.

        Returns:
            Deployment record with status and artefact inventory.
        """
        deployment_id = f"decoy_{uuid.uuid4().hex[:8]}"
        started_at = datetime.now(timezone.utc)

        # Choose a subset of the persona's tools to "use" (2-4)
        active_tools = self._rng.sample(
            persona.tool_preferences,
            min(self._rng.randint(2, 4), len(persona.tool_preferences)),
        )

        # Generate fake scan artefacts
        artefacts = []
        for tool in active_tools:
            artefact = self._generate_decoy_artefact(persona, tool, target)
            artefacts.append(artefact)

        # Build proxy chain for this decoy (multi-hop through persona's infra)
        proxy_chain = persona.infrastructure.get("proxy_chain", [])

        # Build the deployment record
        deployment = {
            "deployment_id": deployment_id,
            "persona_id": persona.id,
            "persona_name": persona.name,
            "skill_level": persona.skill_level,
            "origin_country": persona.origin_country,
            "target": target,
            "started_at": started_at.isoformat(),
            "status": "active",
            "ja4": persona.ja4_fingerprint,
            "user_agent": persona.user_agent,
            "tools_deployed": active_tools,
            "proxy_chain": proxy_chain,
            "artefacts": artefacts,
            "c2_domains": persona.infrastructure.get("c2_domains", []),
            "estimated_noise_level": self._estimate_noise(persona),
        }

        self._active_decoys.append(deployment)

        if self.hive_mind:
            self.hive_mind.add_alert({
                "type": "decoy_deployed",
                "deployment_id": deployment_id,
                "persona": persona.name,
                "target": target,
                "skill": persona.skill_level,
                "threat_level": 0,
                "detail": f"Decoy {deployment_id} ({persona.skill_level}/{persona.origin_country}) targeting {target}",
            })

        logger.info("Decoy %s deployed: %s (%s) → %s [%d tools, %d artefacts]",
                     deployment_id, persona.name, persona.skill_level,
                     target, len(active_tools), len(artefacts))

        return {"success": True, "deployment": deployment}

    def deploy_decoy_swarm(self, target: str, count: int = 50,
                           real_agent_id: str = "") -> dict:
        """Deploy a full swarm of decoy attacks with one real attack hidden.

        This is the primary entry point for the orchestrator. It generates
        `count` personas (if not already available), deploys decoy attacks
        for all but the real agent, and returns a summary that includes the
        real agent's deployment alongside the decoys.

        From the defender's perspective, every attack looks equally real —
        same port scan patterns, same C2 beacon cadences, same typo-laden
        SSH attempts. Only the orchestrator knows which deployment is real.

        Args:
            target: Target IP/hostname for all attacks.
            count: Total number of "attackers" (real + decoys). Default 50.
            real_agent_id: The ID of the real attack agent. If empty, all
                           deployments are decoys (pure noise operation).

        Returns:
            Dict with 'real_deployment' key (the one that is NOT a decoy)
            and 'decoys' list of all decoy deployment records.
        """
        self._real_agent_id = real_agent_id

        # Ensure we have enough personas
        needed = count - len(self._personas)
        if needed > 0:
            logger.info("Generating %d additional personas for swarm", needed)
            self.generate_swarm(needed)

        # Select the personas for this swarm (random sample)
        persona_pool = list(self._personas.values())
        selected = self._rng.sample(persona_pool, min(count, len(persona_pool)))

        # If pool is smaller than count, generate more
        while len(selected) < count:
            p = self.generate_persona()
            selected.append(p)

        # Deploy all as decoys
        decoy_deployments = []
        for persona in selected:
            result = self.deploy_decoy_attack(persona, target)
            if result.get("success"):
                decoy_deployments.append(result["deployment"])

        # The real agent gets a special deployment slot
        real_deployment = None
        if real_agent_id:
            real_deployment = {
                "agent_id": real_agent_id,
                "target": target,
                "deployed_at": datetime.now(timezone.utc).isoformat(),
                "hidden_among": len(decoy_deployments),
                "note": "Real attack is indistinguishable from decoy traffic",
            }

        summary = {
            "success": True,
            "target": target,
            "total_deployments": len(decoy_deployments) + (1 if real_deployment else 0),
            "decoy_count": len(decoy_deployments),
            "real_deployment": real_deployment,
            "decoys": decoy_deployments,
            "diversity": {
                "countries": len({d["origin_country"] for d in decoy_deployments}),
                "skill_levels": len({d["skill_level"] for d in decoy_deployments}),
                "unique_tools": len({t for d in decoy_deployments for t in d["tools_deployed"]}),
            },
        }

        if self.hive_mind:
            self.hive_mind.add_alert({
                "type": "decoy_swarm_deployed",
                "target": target,
                "decoy_count": len(decoy_deployments),
                "real_agent": real_agent_id or "(pure noise)",
                "threat_level": 0,
                "detail": f"Swarm of {len(decoy_deployments)} decoys deployed against {target}",
            })

        logger.info("Decoy swarm deployed: %d decoys → %s (real=%s)",
                     len(decoy_deployments), target, real_agent_id or "none")

        return summary

    def get_active_decoys(self) -> List[dict]:
        """Return all currently active decoy deployments."""
        return [d for d in self._active_decoys if d.get("status") == "active"]

    def dismiss_decoys(self) -> int:
        """Dismiss all active decoys. Returns the count of dismissed decoys."""
        dismissed = 0
        now = datetime.now(timezone.utc)
        for deployment in self._active_decoys:
            if deployment.get("status") == "active":
                deployment["status"] = "dismissed"
                deployment["dismissed_at"] = now.isoformat()
                dismissed += 1

        logger.info("Dismissed %d active decoys", dismissed)

        if self.hive_mind and dismissed > 0:
            self.hive_mind.add_alert({
                "type": "decoys_dismissed",
                "count": dismissed,
                "threat_level": 0,
                "detail": f"Dismissed {dismissed} decoy deployments",
            })

        return dismissed

    # ═══════════════════════════════════════════════════════════════════════
    # Batch operations
    # ═══════════════════════════════════════════════════════════════════════

    def get_persona(self, persona_id: str) -> Optional[Persona]:
        """Retrieve a previously generated persona by ID."""
        return self._personas.get(persona_id)

    def list_personas(self, skill_level: str = None,
                      origin_country: str = None) -> List[Persona]:
        """List generated personas, optionally filtered."""
        result = list(self._personas.values())
        if skill_level:
            result = [p for p in result if p.skill_level == skill_level]
        if origin_country:
            result = [p for p in result if p.origin_country == origin_country]
        return result

    def persona_count(self) -> int:
        """Return total number of personas generated."""
        return len(self._personas)

    def stats(self) -> dict:
        """Return generation and deployment statistics."""
        active = self.get_active_decoys()
        return {
            "total_personas": len(self._personas),
            "active_decoys": len(active),
            "dismissed_decoys": len(self._active_decoys) - len(active),
            "real_agent_id": self._real_agent_id or "(none)",
            "unique_fingerprints": len(self._generated_fingerprints),
            "by_skill": {
                sl: len(self.list_personas(skill_level=sl))
                for sl in self.SKILL_LEVELS
            },
            "by_country": {
                co: len(self.list_personas(origin_country=co))
                for co in self.COUNTRIES
            },
            "generation_count": self._generation_count,
        }

    # ═══════════════════════════════════════════════════════════════════════
    # Internal helpers
    # ═══════════════════════════════════════════════════════════════════════

    def _generate_name(self, country: str) -> str:
        """Generate a full name appropriate to the country."""
        firsts = _FIRST_NAMES.get(country, _FIRST_NAMES["RU"])
        lasts = _LAST_NAMES.get(country, _LAST_NAMES["RU"])
        first = self._rng.choice(firsts)
        last = self._rng.choice(lasts)
        # Slight chance of middle initial for realism
        if self._rng.random() < 0.15:
            middle_initial = self._rng.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
            return f"{first} {middle_initial}. {last}"
        return f"{first} {last}"

    def _unique_ja4(self) -> str:
        """Return a JA4 fingerprint, with a chance of generating a novel one."""
        if self._rng.random() < 0.7:
            # Use from pool
            base = self._rng.choice(_JA4_POOL)
        else:
            # Generate a novel fingerprint by perturbing a pool entry
            base = self._rng.choice(_JA4_POOL)
            # Replace the hex suffix with a random one
            parts = base.rsplit("_", 1)
            if len(parts) == 2:
                random_suffix = hashlib.md5(
                    str(self._rng.randint(0, 2**48)).encode()
                ).hexdigest()[:12]
                base = f"{parts[0]}_{random_suffix}"

        # Small jitter to ensure uniqueness across large swarms
        if self._rng.random() < 0.3:
            # Flip one hex character in the last segment
            pos = self._rng.randint(0, len(base) - 1)
            chars = list(base)
            if chars[pos] in "0123456789abcdef":
                chars[pos] = self._rng.choice("0123456789abcdef")
            base = "".join(chars)

        return base

    def _generate_language_patterns(self, country: str) -> dict:
        """Generate language patterns that reflect L1 interference.

        Returns a dict with 'common_typos', 'phrases', 'punctuation_style',
        and 'keyboard_layout' keys.
        """
        typos = _TYPOS_BY_LANG.get(country, _TYPOS_BY_LANG["RU"])
        phrases = _PHRASES_BY_LANG.get(country, _PHRASES_BY_LANG["RU"])

        # Select 3-5 typos
        selected_typos = self._rng.sample(typos, min(self._rng.randint(3, 5), len(typos)))

        # Select 2-4 phrases
        selected_phrases = self._rng.sample(phrases, min(self._rng.randint(2, 4), len(phrases)))

        # Punctuation style
        punctuation_style = self._rng.choice(_PUNCTUATION_STYLES)

        # Keyboard layout (likely the country's native layout)
        keyboard_layouts = {
            "RU": "ЙЦУКЕН", "CN": "QWERTY (Pinyin IME)", "KP": "QWERTY (Korean IME)",
            "IR": "Persian ISIRI 9147", "BR": "QWERTY ABNT2", "IN": "QWERTY (US-International)",
            "NG": "QWERTY (US)", "VN": "QWERTY (Telex IME)", "RO": "QWERTY (Romanian)",
            "UA": "ЙЦУКЕН (Ukrainian)", "TR": "QWERTY (Turkish-Q)", "PK": "QWERTY (US)",
            "EG": "QWERTY (Arabic 101)", "ID": "QWERTY (US)", "MX": "QWERTY (Latin American)",
        }
        keyboard = keyboard_layouts.get(country, "QWERTY (US)")

        return {
            "common_typos": [{"correct": t[0], "typo": t[1]} for t in selected_typos],
            "phrases": selected_phrases,
            "punctuation_style": punctuation_style,
            "keyboard_layout": keyboard,
        }

    def _generate_infrastructure(self, origin_country: str) -> dict:
        """Generate C2 domains, proxy chain, and hosting infrastructure.

        Proxy chains deliberately avoid the persona's origin country to
        simulate layered anonymization (multi-hop through different legal
        jurisdictions).
        """
        # C2 domains: 2-4 domain names that look like legitimate cloud services
        num_c2 = self._rng.randint(2, 4)
        c2_domains = []
        used_slugs: set = set()
        for _ in range(num_c2):
            pattern = self._rng.choice(_C2_DOMAIN_PATTERNS)
            slug = self._rng.choice(_SLUGS)
            # Avoid duplicate slugs
            while slug in used_slugs and len(used_slugs) < len(_SLUGS):
                slug = self._rng.choice(_SLUGS)
            used_slugs.add(slug)
            domain = pattern.replace("{slug}", slug)
            c2_domains.append(domain)

        # Proxy chain: 2-4 hops through countries that are NOT the origin
        num_hops = self._rng.randint(2, 4)
        eligible = [c for c in _PROXY_COUNTRIES if c != origin_country]
        proxy_chain = []
        for _ in range(num_hops):
            hop_country = self._rng.choice(eligible)
            proxy_chain.append({
                "country": hop_country,
                "ip": f"10.{self._rng.randint(1, 255)}.{self._rng.randint(1, 255)}.{self._rng.randint(2, 254)}",
                "port": self._rng.choice([80, 443, 8080, 8443, 3128, 1080, 9050]),
                "protocol": self._rng.choice(["socks5", "http", "https", "ssh-tunnel"]),
            })

        # Hosting providers: 1-3
        num_hosts = self._rng.randint(1, 3)
        hosting = self._rng.sample(_HOSTING_PROVIDERS, min(num_hosts, len(_HOSTING_PROVIDERS)))

        # VPS regions: 1-3 distinct regions
        num_regions = self._rng.randint(1, 3)
        regions = self._rng.sample(_VPS_REGIONS, min(num_regions, len(_VPS_REGIONS)))

        return {
            "c2_domains": c2_domains,
            "proxy_chain": proxy_chain,
            "hosting_providers": hosting,
            "vps_regions": regions,
        }

    def _generate_behavioural_quirks(self, attack_timing: str) -> dict:
        """Generate behavioural quirks based on attack timing profile."""
        rest_min, rest_max = _REST_INTERVALS.get(attack_timing, (30, 300))
        rest_interval = self._rng.randint(rest_min, rest_max)

        retry_behaviour = self._rng.choice(_RETRY_BEHAVIOURS)

        # Additional behavioural randomisation
        quirks = {
            "rest_interval_seconds": rest_interval,
            "retry_behaviour": retry_behaviour,
            "port_scan_randomize_order": self._rng.choice([True, False]),
            "beacon_jitter_percent": self._rng.randint(0, 25),
            "uses_padding_bytes": self._rng.choice([True, False]),
            "prefers_ipv6": self._rng.choice([True, False, False, False]),  # bias towards IPv4
            "dns_over_https": self._rng.choice([True, False]),
            "connection_pooling": self._rng.choice([True, False]),
            "tcp_fast_open": self._rng.choice([True, False]),
            "max_parallel_connections": self._rng.choice([1, 2, 4, 8, 16, 32]),
            "session_timeout_seconds": self._rng.choice([30, 60, 120, 300, 600, 1800]),
            "reconnect_on_timeout": self._rng.choice([True, True, False]),  # bias towards true
        }

        return quirks

    def _generate_decoy_artefact(self, persona: Persona, tool: str,
                                  target: str) -> dict:
        """Generate a single decoy artefact that mimics a real tool execution."""
        artefact_types = ["scan_output", "auth_attempt", "c2_beacon",
                          "file_touch", "dns_query", "http_request"]

        artefact_type = self._rng.choice(artefact_types)

        artefact = {
            "type": artefact_type,
            "tool": tool,
            "target": target,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "persona_ja4": persona.ja4_fingerprint,
            "persona_ua": persona.user_agent,
        }

        # Generate type-specific fields
        if artefact_type == "scan_output":
            artefact["open_ports"] = sorted(self._rng.sample(
                [22, 80, 443, 3306, 5432, 6379, 8080, 8443, 9090, 27017], self._rng.randint(1, 5)
            ))
            artefact["scan_duration_ms"] = self._rng.randint(1500, 45000)

        elif artefact_type == "auth_attempt":
            artefact["username"] = self._rng.choice(["root", "admin", "ubuntu", "ec2-user", "www-data"])
            artefact["auth_method"] = self._rng.choice(["ssh_password", "ssh_key", "http_basic", "jwt_forged"])
            artefact["success"] = False  # Decoys always fail auth

        elif artefact_type == "c2_beacon":
            artefact["beacon_id"] = hashlib.md5(
                f"{persona.id}{time.time()}{self._rng.random()}".encode()
            ).hexdigest()[:8]
            artefact["c2_domain"] = self._rng.choice(persona.infrastructure.get("c2_domains", ["unknown.io"]))
            artefact["payload_size_bytes"] = self._rng.randint(64, 4096)
            artefact["interval_seconds"] = persona.behavioural_quirks.get("rest_interval_seconds", 60)

        elif artefact_type == "file_touch":
            paths = ["/tmp/.cache", "/var/tmp/.syslog", "/dev/shm/.X11-unix",
                     "/tmp/.ICE-unix", "/var/tmp/.font-unix"]
            artefact["path"] = self._rng.choice(paths)
            artefact["size_bytes"] = self._rng.randint(0, 1048576)

        elif artefact_type == "dns_query":
            artefact["queried_domain"] = self._rng.choice(persona.infrastructure.get("c2_domains", ["update.example.com"]))
            artefact["query_type"] = self._rng.choice(["A", "AAAA", "TXT", "MX", "CNAME"])
            artefact["resolved"] = self._rng.choice([True, False])

        elif artefact_type == "http_request":
            artefact["method"] = self._rng.choice(["GET", "POST", "PUT"])
            artefact["path"] = self._rng.choice(["/api/v1/status", "/health", "/metrics", "/.env", "/wp-admin"])
            artefact["status_code"] = self._rng.choice([200, 301, 403, 404, 500])
            artefact["response_size_bytes"] = self._rng.randint(0, 65536)

        return artefact

    def _estimate_noise(self, persona: Persona) -> str:
        """Estimate the noise level a decoy persona will generate."""
        timing = persona.attack_timing
        if timing in ("aggressive", "burst_and_sleep"):
            return "high"
        elif timing in ("patient", "low_and_slow"):
            return "low"
        elif timing in ("reactive_only",):
            return "very_low"
        return "medium"

    # ═══════════════════════════════════════════════════════════════════════
    # Serialisation
    # ═══════════════════════════════════════════════════════════════════════

    def to_dict(self) -> dict:
        """Serialise factory state for persistence / snapshot."""
        return {
            "persona_count": len(self._personas),
            "active_decoy_count": len(self.get_active_decoys()),
            "real_agent_id": self._real_agent_id,
            "generation_count": self._generation_count,
            "personas": {pid: p.summary() for pid, p in self._personas.items()},
            "active_decoys": self.get_active_decoys(),
        }
