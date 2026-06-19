# PhantomStrike v2.0 — Architecture Documentation

## Overview

PhantomStrike is an AI-powered offensive security platform that wraps 153+ real security tools behind a unified API and exposes them to AI assistants via MCP (Model Context Protocol). The platform provides Web UI, REST API, and MCP interfaces for autonomous penetration testing, exploit generation, OSINT, stealth operations, and post-exploitation.

**Version**: 2.0.0  
**License**: AGPLv3 (base) + MIT (ported components)  
**Technology**: Python 3.12+ / Flask / React 19 / FastMCP / Docker (Kali Linux)  
**Routes**: 376 API endpoints  
**Database**: SQLite (WAL mode, thread-safe)

---

## Architecture Layers

```
┌─────────────────────────────────────────────────────────────────────┐
│                        ACCESS LAYER                                  │
│  Web UI (React 19)  │  MCP (FastMCP)  │  REST API (Flask)  │  CLI  │
├─────────────────────────────────────────────────────────────────────┤
│                        API LAYER (server_api/)                      │
│  55+ blueprint directories, 376 routes                              │
├─────────────────────────────────────────────────────────────────────┤
│                     CORE ENGINE LAYER (server_core/)                 │
│  Exploits (10 classes) │ Evasion │ OSINT │ Intelligence │ Workflows │
├─────────────────────────────────────────────────────────────────────┤
│                        DATA LAYER                                    │
│  SQLite via PhantomStrikeDB (WAL, thread-safe, 14 tables)           │
├─────────────────────────────────────────────────────────────────────┤
│                   INFRASTRUCTURE LAYER                               │
│  Docker (Kali Linux) │ Plugin System │ Auth (Bearer token)          │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Directory Structure

```
phantomstrike/
├── phantomstrike_server.py          Flask server entry (269 lines)
├── phantomstrike_mcp.py             MCP client entry (48 lines)
├── phantomstrike.sh                 Shell entrypoint + installer
├── config.py                        Global configuration
├── tool_registry.py                 153 tool definitions (2082 lines)
│
├── server_core/                     Core business logic (~80 files)
│   ├── db.py                        PhantomStrikeDB — 14 tables
│   ├── singletons.py                Thread-safe lazy singletons
│   ├── ai_exploit_generator.py      Exploit generation dispatch (1788 lines)
│   ├── vulnerability_correlator.py  Attack chain engine w/ MITRE ATT&CK
│   ├── llm_client.py                Provider-agnostic LLM (Ollama/OpenAI/Anthropic)
│   ├── llm_agent.py                 AI session analysis + planning
│   ├── exploits/                    10 modular exploit classes
│   │   ├── base_exploit.py          ExploitPayload base (evasion, scoring)
│   │   ├── sqli_exploit.py          SQLi (UNION, boolean, time, error)
│   │   ├── xss_exploit.py           XSS (reflected, stored, DOM, WAF bypass)
│   │   ├── rce_exploit.py           RCE (command injection, SSTI)
│   │   ├── xxe_exploit.py           XXE (in-band, OOB, parameter entity)
│   │   ├── file_read_exploit.py     LFI/RFI/path traversal
│   │   ├── deserialization_exploit.py  Pickle/Java/.NET/PHP
│   │   ├── auth_bypass_exploit.py   SQL bypass, JWT, header manipulation
│   │   ├── buffer_overflow_exploit.py  x86/x64 ROP chains
│   │   └── generic_exploit.py       Fallback template matching
│   ├── evasion/                     Stealth engine
│   │   ├── payload_encryptor.py     AES-256/XOR/RC4 chains + polyglot
│   │   └── traffic_obfuscator.py    JA3/JA4 spoofing, domain fronting, CDN morphing
│   ├── osint/                       OSINT intelligence engine
│   │   ├── ip_intel.py              Shodan, Censys, AbuseIPDB, geolocation
│   │   ├── phone_tracer.py          Carrier, line type, validation
│   │   ├── email_tracer.py          HIBP, Dehashed, MX check, Gravatar
│   │   ├── social_profiler.py       30+ platform account discovery
│   │   └── dark_web_monitor.py      .onion scraping, ransomware tracking
│   ├── intelligence/                Decision engine
│   │   ├── cve_intelligence_manager.py  Exploitability analysis, risk scoring
│   │   ├── intelligent_decision_engine.py  Tool selection, parameter optimization
│   │   └── tool_catalog.py          Tool effectiveness scoring
│   └── workflows/                   Automated workflows
│       ├── bugbounty/               Bug bounty assessment management
│       └── ctf/                     CTF challenge automation
│
├── server_api/                      API layer (55+ blueprint dirs, 376 routes)
│   ├── __init__.py                  Blueprint registration hub
│   ├── net_scan/                    nmap, masscan, rustscan, arp-scan
│   ├── recon/                       amass, subfinder, theharvester, etc.
│   ├── web_scan/                    nuclei, sqlmap, nikto, wpscan, etc.
│   ├── web_fuzz/                    gobuster, ffuf, feroxbuster, etc.
│   ├── exploit_framework/           metasploit, msfvenom, pwntools, etc.
│   ├── password_cracking/           hashcat, john, hydra, medusa, etc.
│   ├── binary_analysis/             gdb, radare2, ghidra, binwalk, etc.
│   ├── cloud_audit/                 prowler, trivy, scout-suite
│   ├── osint/                       ★ shodan, phone, email, social, dark web
│   ├── evasion/                     ★ payload obfuscation, traffic morphing
│   ├── advanced_web/                ★ request smuggling, JWT, SSTI, prototype pollution
│   ├── cloud_attack/                ★ IAM privesc, container escape, K8s attacks
│   ├── ai_attack/                   ★ prompt injection, jailbreaking, API key scan
│   ├── mobile_iot/                  ★ APK analysis, Frida hooks, BLE attacks
│   ├── stealth_c2/                  ★ C2 deployment, CDN fronting, social C2
│   ├── anti_forensics/              ★ log clearing, timestomp, memory execution
│   ├── dark_web/                    ★ .onion scraping, ransomware tracking
│   ├── exploitation/                ★ live exploit execution + generation
│   └── vuln_intel/                  ★ attack chain builder + CVE intelligence
│
├── mcp_tools/                       MCP tool wrappers (mirrors server_api/)
├── skills/                          Workflow documentation (10 skills)
├── plugins/                         Drop-in plugin system (4 plugins)
├── ui/                              React 19 + Vite 8 + TypeScript frontend
│   └── src/
│       ├── api/                     Typed REST client
│       ├── components/              Shared React components
│       ├── pages/                   18 pages + 5 new merged pages
│       └── themes/                  10 CSS themes
├── tests/                           pytest test suite
├── Dockerfile                       Kali Linux base image
├── docker-compose.yml               Multi-service orchestration
└── docker-entrypoint.sh             Container startup
```

---

## Core Capabilities Matrix

| Domain | Capabilities | Tool Count |
|--------|-------------|------------|
| **Network Recon** | nmap, masscan, rustscan, arp-scan, autorecon | 7 |
| **Subdomain/DNS** | amass, subfinder, dnsenum, fierce, massdns | 8 |
| **Web Discovery** | gobuster, ffuf, feroxbuster, katana, hakrawler | 7 |
| **Web Vuln Scanning** | nuclei, sqlmap, nikto, wpscan, dalfox, xsser, jaeles | 12 |
| **Exploitation** | metasploit, msfvenom, exploit-db, pwntools, commix | 6 |
| **Password Cracking** | hashcat, john, hydra, medusa, patator, hashid | 8 |
| **WiFi Pentesting** | aircrack-ng suite, wifite2, bettercap, hcxtools | 12 |
| **Binary/RE** | gdb, radare2, ghidra, binwalk, ropgadget, angr | 12 |
| **Cloud Security** | prowler, trivy, scout-suite, kube-hunter, checkov | 12 |
| **OSINT** | Shodan, phone tracer, email breach, social profiler, dark web | 21 |
| **Exploit Generation** | SQLi, XSS, RCE, XXE, LFI, Deserialization, AuthBypass, BOF | 8 |
| **Evasion** | Payload encryption, polyglot, JA3 spoofing, domain fronting | 7 |
| **Advanced Web** | Request smuggling, JWT attacks, SSTI chains, prototype pollution | 4 |
| **Cloud Attack** | IAM privesc (AWS/GCP/Azure), container escape, K8s RBAC | 3 |
| **AI Attacks** | Prompt injection, jailbreaking, API key scan, prompt leak | 4 |
| **Mobile/IoT** | APK analysis, Frida hooks, firmware analysis, BLE attacks | 4 |
| **C2 Infrastructure** | DNS/ICMP/WebSocket/Social C2, CDN fronting | 3 |
| **Anti-Forensics** | Log clearing, timestomp, memory exec, diskless persistence | 4 |
| **Attack Chains** | MITRE ATT&CK mapping, Monte Carlo simulation | 1 |
| **CVE Intelligence** | Exploitability analysis, risk scoring, zero-day research | 1 |

---

## Database Schema (14 tables)

| Table | Purpose |
|-------|---------|
| `llm_sessions` | AI analysis session tracking |
| `llm_vulnerabilities` | Parsed vulnerabilities from AI analysis |
| `chat_sessions` | Chat conversation threads |
| `chat_messages` | Individual chat messages |
| `credentials` | Discovered credentials/hashes/tokens |
| `loot` | Non-credential artifacts |
| `exploit_generations` | Generated exploit code history |
| `attack_chains` | Persisted multi-stage attack chains |
| `browser_agent_sessions` | Browser agent inspection results |
| `http_proxy_history` | HTTP request/response history |
| `cve_intel_cache` | Cached CVE intelligence data |
| `exploit_evidence` | Exploit verification artifacts |
| `http_testing_rules` | HTTP framework match/replace rules |
| `bugbounty_assessments` | Bug bounty assessment results |

---

## API Endpoints by Category

### Core System
- `GET /health` — Health check, tool availability, telemetry
- `GET /api/telemetry` — System performance metrics
- `POST /api/cache/clear` — Clear command cache

### Exploit Generation (★ new in v2.0)
- `POST /api/exploits/generate` — Generate exploit code (8 types)
- `POST /api/ai/generate_exploit_from_cve` — CVE-based generation
- `POST /api/exploitation/execute` — Live exploit execution
- `POST /api/exploitation/verify` — Verify exploit success
- `POST /api/exploitation/rollback` — Clean up after exploit

### OSINT (★ 17 new endpoints)
- `POST /api/tools/shodan-lookup` — Shodan IP intelligence
- `POST /api/tools/shodan-search` — Shodan host search
- `POST /api/tools/ip-geolocate` — Multi-source IP geolocation
- `POST /api/tools/tor-check` — Tor exit node detection
- `POST /api/tools/vpn-check` — VPN/proxy detection
- `POST /api/tools/phone-lookup` — Phone carrier/location
- `POST /api/tools/email-breach` — HIBP breach lookup
- `POST /api/tools/email-verify` — MX validation
- `POST /api/tools/email-accounts` — Social accounts via email
- `POST /api/tools/dehashed-search` — Breach database search
- `POST /api/tools/social-search` — 30+ platform username search
- `POST /api/tools/github-recon` — Deep GitHub profiling
- `POST /api/tools/google-dork` — Dork query builder
- `POST /api/tools/dark-web` — .onion scraping
- `POST /api/tools/crypto-trace` — BTC/ETH tracing
- `POST /api/tools/threat-actor` — Threat actor profiling
- `POST /api/tools/c2-map` — C2 infrastructure mapping

### Evasion (★ 7 new endpoints)
- `POST /api/tools/obfuscate-payload` — Chained encryption
- `POST /api/tools/polyglot-payload` — File embedding
- `POST /api/tools/stealth-score` — Entropy analysis
- `POST /api/tools/traffic-morph` — Browser impersonation
- `POST /api/tools/domain-front` — CDN domain fronting
- `POST /api/tools/stealth-profile` — Complete stealth config
- `POST /api/tools/ja3-randomize` — TLS fingerprint randomization

### Attack Chains
- `POST /api/vuln-intel/build-chain` — Build MITRE-mapped chain
- `POST /api/vuln-intel/simulate-chain` — Monte Carlo simulation

### Advanced Web, Cloud, AI, Mobile, C2, Anti-Forensics, Dark Web
(★ 25 additional endpoints — see capability matrix above)
