# PhantomStrike v3.2 — 35-Agent Swarm Architecture

**Built: June 19, 2026**

> Universal Autonomous Hacking Platform. Any target. Any domain. Any defense.
> One prompt → total compromise. Zero human intervention required.

---

## 1. System Overview

PhantomStrike v3.2 is an **autonomous AI agent swarm** that attacks, defends,
specializes, and dominates across all 12 attack domains. The system runs as a
Flask REST API with a FastMCP bridge that exposes 200+ tools to AI models.

```
┌─────────────────────────────────────────────────────────────┐
│                    PHANTOMSTRIKE v3.2                       │
│              Universal Autonomous Hacking Platform           │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌─────────────┐  ┌─────────────┐  ┌───────────────────┐  │
│  │  Flask API  │  │  FastMCP    │  │  Dashboard (React) │  │
│  │  (397 routes)│  │  Bridge     │  │                   │  │
│  └──────┬──────┘  └──────┬──────┘  └─────────┬─────────┘  │
│         │                │                    │             │
│         └────────────────┼────────────────────┘             │
│                          │                                  │
│               ┌──────────▼──────────┐                      │
│               │   ORCHESTRATOR      │                      │
│               │  (orchestrator_agent)│                      │
│               │  decompose → dispatch│                      │
│               │  → monitor → adapt   │                      │
│               └──────────┬──────────┘                      │
│                          │                                  │
│     ┌────────────────────┼────────────────────┐            │
│     │                    │                    │            │
│  ┌──▼──────┐      ┌──────▼──────┐      ┌─────▼──────┐    │
│  │  HIVE   │◄────►│   TOOL      │◄────►│   AGENT    │    │
│  │  MIND   │      │   BRIDGE    │      │   FLEET    │    │
│  │(shared  │      │ (200+ tools)│      │ (35 agents)│    │
│  │  KB)    │      │             │      │            │    │
│  └─────────┘      └─────────────┘      └────────────┘    │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │              KALI LINUX (native, no Docker)          │   │
│  └─────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

### Core Stack

| Layer | Technology | Purpose |
|-------|-----------|---------|
| API Server | Flask (Python 3.13+) | REST API with 397 routes, bearer auth |
| MCP Bridge | FastMCP | Exposes agent tools to AI models (Claude, GPT, etc.) |
| Orchestrator | ReAct loop + EGATS | Mission lifecycle: decompose → dispatch → monitor → adapt |
| Agent Swarm | 35 specialized agents | Autonomous attack/defense/specialist/domain operations |
| Hive Mind | Shared knowledge base | Thread-safe, typed collections, DB persistence, event bus |
| Tool Bridge | REST API wrappers | 200+ real security tools with defense pre-check pipeline |
| Database | SQLite (29 tables) | Missions, agents, exploits, credentials, loot, defense |
| Deployment | phantomstrike.sh | One-command install, start, stop, update, health check |
| Dashboard | React SPA | Real-time mission monitoring, findings, loot, settings |

---

## 2. The 35-Agent Fleet

Agents are organized into 5 categories. Every agent inherits from
`server_core/orchestrator/agent_base.py` and runs a ReAct (Reasoning + Acting)
loop. Agents NEVER talk directly — all communication flows through the Hive Mind.

### Category 1: Core Agents (6) — The Kill Chain

```
 RECON ──► VULN ──► EXPLOIT ──► POST-EXPLOIT ──► EXFIL ──► CLEANUP
   │         │          │             │             │          │
   └─────────┴──────────┴─────────────┴─────────────┴──────────┘
                              │
                          HIVE MIND
```

| # | Agent | File | Key Capability |
|---|-------|------|----------------|
| 1 | Recon | `recon_agent.py` | OSINT, 50+ sources, passive recon, Shodan, crt.sh |
| 2 | Vuln | `vuln_agent.py` | CVE matching, CVSS scoring, vulnerability chaining |
| 3 | Exploit | `exploit_agent.py` | 8 exploit types, WAF/IDS evasion, payload generation |
| 4 | Post-Exploit | `post_exploit_agent.py` | Linux/Windows enumeration, situational awareness |
| 5 | Exfil | `exfil_agent.py` | Multi-channel data extraction, DNS/HTTP/ICMP tunneling |
| 6 | Cleanup | `cleanup_agent.py` | Anti-forensics, selective log wiping, timestamp manipulation |

### Category 2: Attack Agents (6) — Post-Exploitation

```
/server_core/orchestrator/attack_agents/

 PRIVESC ──► CRED-ACCESS ──► PERSISTENCE
    │             │               │
 LATERAL-MOVE ◄──┘               │
    │                             │
 CLOUD ◄─────────────────────────┘
    │
 WEBAPP
```

| # | Agent | File | Key Capability |
|---|-------|------|----------------|
| 7 | PrivEsc | `attack_agents/privesc_agent.py` | 200+ techniques, kernel exploit matching, SUID/SGID |
| 8 | Cred Access | `attack_agents/cred_access_agent.py` | mimikatz, DPAPI, cloud credential extraction, token theft |
| 9 | Persistence | `attack_agents/persistence_agent.py` | 50+ mechanisms, cron, systemd, WMI, registry, hidden users |
| 10 | Cloud | `attack_agents/cloud_agent.py` | AWS/GCP/Azure IAM, K8s, serverless, metadata attacks |
| 11 | Lateral Move | `attack_agents/lateral_move_agent.py` | AD domination, PtH/PtT/Kerberoasting, PSRemoting, WMI |
| 12 | WebApp | `attack_agents/webapp_agent.py` | Modern web, APIs, GraphQL, JWT, SSRF, SSTI, deserialization |

### Category 3: Defense Agents (6) — Self-Protection

```
/server_core/orchestrator/defense_agents/

 OPSEC ──► pre-execution audit + veto ──► all other agents
    │
 COUNTER-SURVEILLANCE ──► threat detection ──► alerts
    │
 TRACE-BUSTER ──► identity rotation, geo-hopping
    │
 DECOY ──► false flags, rabbit holes
    │
 REVERSE-TRACE ──► attacker attribution
    │
 EMERGENCY ──► kill switch, go dark, wipe evidence
```

| # | Agent | File | Key Capability |
|---|-------|------|----------------|
| 13 | Emergency | `defense_agents/emergency_agent.py` | Kill switch, evidence wipe, go dark, dead man's switch |
| 14 | OPSEC | `defense_agents/opsec_agent.py` | Pre-execution audit, risk scoring (0-100), veto power |
| 15 | Decoy | `defense_agents/decoy_agent.py` | False flags, misdirection, decoy targets, rabbit holes |
| 16 | CounterSurv | `defense_agents/counter_surveillance.py` | 15+ threat feeds, tracing detection, responder shutdown |
| 17 | ReverseTrace | `defense_agents/reverse_trace.py` | Attacker attribution, evidence collection, honeypot deploy |
| 18 | TraceBuster | `defense_agents/trace_buster.py` | Identity rotation, compartmentalization, geo-hopping, proxy chains |

### Category 4: Specialist Agents (5) — Advanced Capabilities

```
/server_core/orchestrator/specialist_agents/

 REVERSE-ENGINEERING ──► binary analysis, vulnerability patterns
 AUTO-FIXER ──► Plan → Present → Approve → Fix → Verify (gated)
 BUG-BOUNTY ──► scope → hunt → duplicate check → report → submit
 SOCIAL-ENGINEERING ──► profiling, phishing, pretext (authorized only)
 SUPPLY-CHAIN ──► dependency scan, confusion check, CI/CD audit
```

| # | Agent | File | Key Capability |
|---|-------|------|----------------|
| 19 | Supply Chain | `specialist_agents/supply_chain_agent.py` | Dependency scan, confusion check, CI/CD audit |
| 20 | Social Engineering | `specialist_agents/social_eng_agent.py` | Profiling, phishing, pretext, deepfake voice (authorized only) |
| 21 | Bug Bounty | `specialist_agents/bug_bounty_agent.py` | Scope → hunt → duplicate check → professional reports → submit |
| 22 | Auto Fixer | `specialist_agents/auto_fixer_agent.py` | Plan → Present → Approve → Fix → Verify (human-gated) |
| 23 | Reverse Engineering | `specialist_agents/reverse_engineering_agent.py` | Binary analysis, Ghidra/radare2, vulnerability pattern extraction |

### Category 5: Domain Agents (12) — Universal Attack Surface ★ NEW in v3.2

```
/server_core/orchestrator/domain_agents/

  IoT ────► Embedded, firmware, BLE, Zigbee, MQTT
  SCADA ──► ICS/OT, Modbus, PLC, DNP3, safety systems
  AUTOMOTIVE ──► CAN bus, OBD-II, ECU, key fob relay
  SATELLITE ──► SDR, ground station, GPS spoof, telemetry
  BLOCKCHAIN ──► Smart contracts, MEV, DeFi, flash loans
  AI-EXPLOIT ──► Prompt injection, model extraction, adversarial
  MOBILE ──► APK/IPA, Frida, SSL pinning, biometric bypass
  TELECOM ──► SS7, Diameter, 5G core, IMSI catcher, SIP/VoIP
  PHYSICAL ──► RFID, lockpick, badge clone, drone delivery
  DARKWEB ──► Tor/I2P, market crawl, credential acquisition
  DRONE ──► MAVLink, GPS spoof, FPV intercept, swarm takeover
  NUCLEAR-OPSEC ──► Traffic entropy matching, mathematical stealth
```

| # | Agent | File | Key Capability |
|---|-------|------|----------------|
| 24 | IoT | `domain_agents/iot_agent.py` | MQTT/BLE/Zigbee, firmware extraction (UART/SPI/JTAG), binwalk |
| 25 | SCADA | `domain_agents/scada_agent.py` | Modbus/s7comm/DNP3, PLC takeover, safety system bypass |
| 26 | Automotive | `domain_agents/automotive_agent.py` | CAN bus injection, OBD-II, key fob relay, ECU reflashing |
| 27 | Satellite | `domain_agents/satellite_agent.py` | SDR, ground station discovery, GPS spoofing, telecommand |
| 28 | Blockchain | `domain_agents/blockchain_agent.py` | Smart contract fuzzing, MEV extraction, flash loan synthesis |
| 29 | AI Exploit | `domain_agents/ai_exploit_agent.py` | Prompt injection, model extraction, adversarial examples, jailbreak |
| 30 | Mobile | `domain_agents/mobile_agent.py` | APK/IPA analysis, Frida/Objection, SSL pinning bypass |
| 31 | Telecom | `domain_agents/telecom_agent.py` | SS7/Diameter attacks, 5G core scanning, IMSI catcher evasion |
| 32 | Physical | `domain_agents/physical_agent.py` | RFID/NFC cloning, lockpicking, badge cloning, drone drop delivery |
| 33 | DarkWeb | `domain_agents/darkweb_agent.py` | Automated Tor crawling, credential markets, zero-day acquisition |
| 34 | Drone | `domain_agents/drone_agent.py` | MAVLink injection, GPS spoofing, FPV interception, swarm takeover |
| 35 | Nuclear OpSec | `domain_agents/nuclear_opsec_agent.py` | Entropy matching (KS test p>0.95), temporal correlation breaking |

---

## 3. Hive Mind — Shared Knowledge Base

The Hive Mind is the central nervous system. All 35 agents read from and write to
it. No agent-to-agent direct communication exists.

```
               ┌─────────────────────────┐
               │       HIVE MIND          │
               │  ┌───────────────────┐   │
               │  │  Typed Collections │   │
               │  │  - hosts           │   │
RECON ────────►│  │  - vulns           │◄──── VULN
               │  │  - exploits        │   │
EXPLOIT ──────►│  │  - sessions        │◄──── POST-EXPLOIT
               │  │  - credentials     │   │
PRIVESC ──────►│  │  - findings        │◄──── SPECIALISTS
               │  │  - defense_events  │   │
DEFENSE ──────►│  │  - domain_signals  │◄──── DOMAIN AGENTS
               │  │  - mission_phases  │   │
               │  └───────────────────┘   │
               │                           │
               │  Thread-safe              │
               │  DB-persisted (SQLite)    │
               │  Event bus (pub/sub)      │
               │  Context queries per agent│
               │  Snapshot & rollback      │
               └─────────────────────────┘
```

### Key Features

- **Thread-safe**: All operations use `threading.Lock` — safe for 35 concurrent agents
- **Typed collections**: hosts, vulns, exploits, sessions, credentials, findings, defense_events, domain_signals
- **Context queries**: Each agent queries only what it needs (e.g., VulnAgent sees new hosts → auto-runs nuclei)
- **DB persistence**: All knowledge survives server restarts
- **Event bus**: Agents subscribe to collection changes (pub/sub pattern)
- **Snapshots**: Full state snapshots for mission restart/resume

### Communication Flow Example

```
User: "Hack example.com completely"

1. Orchestrator decomposes prompt into mission phases
2. ReconAgent starts → discovers:
   - 3 open ports (80, 443, 22)
   - nginx 1.18.0
   - WordPress 6.2
   - → HiveMind.add_host("example.com", {ports: [80,443,22], ...})
   
3. VulnAgent sees new host → runs nuclei → discovers:
   - CVE-2023-XXXX (WordPress plugin, CVSS 9.8)
   - → HiveMind.add_vuln("example.com", {cve: "CVE-2023-XXXX", cvss: 9.8})
   
4. ExploitAgent sees new vuln → generates exploit payload:
   - WAF detection: none
   - → HiveMind.add_exploit("example.com", {payload: "...", type: "rce"})
   
5. OPSECAgent reviews exploit:
   - Risk score: 25 (low)
   - → APPROVED (with suggestion: --random-agent --delay=2)
   
6. TraceBusterAgent rotates ExploitAgent's identity:
   - New IP: 45.33.xxx.xxx
   - New User-Agent
   
7. ExploitAgent executes → gets shell:
   - → HiveMind.add_session("example.com", {type: "reverse_shell", uid: "www-data"})
   
8. PostExploitAgent sees new session:
   - Enumeration: Linux 5.10, 2 users, MySQL running as root
   
9. PrivEscAgent sees enumeration data:
   - MySQL UDF privilege escalation → root
   - → HiveMind.add_credential("example.com", {user: "root", method: "mysql_udf"})
   
10. ExfilAgent extracts /var/www/html/wp-config.php → DB credentials
11. CleanupAgent wipes bash history, auth.log entries, MySQL query logs
12. Mission complete → report generated with all findings
```

---

## 4. Tool Bridge — 200+ Tool Integrations

The Tool Bridge maps agent capabilities to real security tools. Every tool call
passes through the defense pre-check pipeline.

```
                        ┌─────────────────────┐
                        │    TOOL BRIDGE       │
                        │  ┌───────────────┐   │
AGENT ──► request ─────►│  │ Defense Check │   │──► denied ──► OPSEC Agent
                        │  │  - risk score  │   │
                        │  │  - scope check │   │
                        │  │  - OPSEC audit │   │
                        │  └───────┬───────┘   │
                        │          │ approved   │
                        │  ┌───────▼───────┐   │
                        │  │ Tool Router   │   │
                        │  │  - nmap       │   │
                        │  │  - nuclei     │   │
                        │  │  - sqlmap     │   │
                        │  │  - metasploit │   │
                        │  │  - ...200+    │   │
                        │  └───────┬───────┘   │
                        │          │            │
                        │  ┌───────▼───────┐   │
                        │  │ Result Cache  │   │
                        │  └───────────────┘   │
                        └─────────────────────┘
```

### Tool Categories

| Category | Count | Examples |
|----------|-------|----------|
| Reconnaissance | 25 | nmap, masscan, amass, subfinder, assetfinder, shodan |
| Web Exploitation | 30 | sqlmap, nuclei, ffuf, dirb, wpscan, burp-rest-api |
| Exploitation | 20 | metasploit, searchsploit, pwntools, ropper |
| Post-Exploitation | 25 | mimikatz, bloodhound, impacket, crackmapexec, evil-winrm |
| IoT/Embedded | 15 | binwalk, firmwalker, FACT, flashrom, openocd, gatttool |
| SCADA/ICS | 12 | modbus-cli, s7comm, plcscan, isf, opcua-client |
| Automotive | 10 | can-utils, caringcaribou, savvycan, icsim |
| Satellite/RF | 15 | gnuradio, hackrf, rtl-sdr, gqrx, satdump, gr-gsm |
| Blockchain | 12 | foundry, slither, mythril, echidna, web3.py, hardhat |
| Mobile | 10 | frida, objection, jadx, apktool, mobsf, mitmproxy |
| Telecom | 8 | srsRAN, Open5GS, YateBTS, sigPloit, SIMtrace |
| Physical | 12 | proxmark3, flipper-utils, ducky-flasher, esp32-marauder |

---

## 5. Phantom Proxy — Identity Obfuscation

The Phantom Proxy layer ensures all agent traffic is anonymized and rotated.

```
┌──────────────────────────────────────────────────────┐
│                  PHANTOM PROXY                        │
│                                                      │
│  Agent ──► Tor (entry) ──► VPN Chain ──► Proxy Pool  │
│              │                │              │        │
│              │          ┌─────▼──────┐  ┌────▼─────┐ │
│              │          │  VPN #1    │  │ HTTP/    │ │
│              │          │  (US East) │  │ SOCKS5   │ │
│              │          └─────┬──────┘  │ Pool     │ │
│              │                │         │ (100+)   │ │
│              │          ┌─────▼──────┐  └────┬─────┘ │
│              │          │  VPN #2    │       │       │
│              │          │  (EU West) │       │       │
│              │          └─────┬──────┘       │       │
│              │                │              │       │
│              └────────────────┴──────────────┘       │
│                              │                       │
│                     TARGET ◄─┘                       │
│                                                      │
│  IP Rotation: Every 30s or per-request (configurable) │
│  Identity Compartmentalization: Each agent gets       │
│    its own proxy chain                                │
└──────────────────────────────────────────────────────┘
```

---

## 6. MCP Tool Exposure for AI Agents

FastMCP bridges PhantomStrike to external AI agents (Claude Desktop, 5ire, etc.).

```
┌─────────────┐     FastMCP/JSON-RPC     ┌──────────────────┐
│  AI AGENT   │◄────────────────────────►│  PHANTOMSTRIKE    │
│  (Claude,   │                          │  MCP SERVER       │
│   GPT,      │  Tools exposed:          │                   │
│   Gemini)   │  - recon(target)         │  ┌─────────────┐  │
│             │  - exploit(target, cve)  │  │ 397 API     │  │
│             │  - privesc(session_id)   │  │ endpoints   │  │
│             │  - exfil(session,path)   │  │             │  │
│             │  - opsec_check(action)   │  │ 35 agent    │  │
│             │  - go_dark()             │  │ wrappers    │  │
│             │  - ...35+ tools          │  │             │  │
│             │                          │  └─────────────┘  │
└─────────────┘                          └──────────────────┘
```

### Configuration

```json
{
  "mcpServers": {
    "phantomstrike": {
      "command": "./phantomstrike.sh",
      "args": ["--mcp"],
      "env": {
        "PHANTOMSTRIKE_API_TOKEN": "your-token",
        "PHANTOMSTRIKE_PORT": "8888"
      }
    }
  }
}
```

---

## 7. Data Flow — Mission Lifecycle

```
USER PROMPT
    │
    ▼
┌─────────────────────────────────────────────┐
│  TASK DECOMPOSER                            │
│  "Hack example.com completely"              │
│  ┌─────────────────────────────────────┐    │
│  │ Phase 1: Reconnaissance             │    │
│  │ Phase 2: Vulnerability Assessment   │    │
│  │ Phase 3: Exploitation               │    │
│  │ Phase 4: Post-Exploitation          │    │
│  │ Phase 5: Privilege Escalation       │    │
│  │ Phase 6: Lateral Movement           │    │
│  │ Phase 7: Data Exfiltration          │    │
│  │ Phase 8: Persistence                │    │
│  │ Phase 9: Cleanup & Cover Tracks     │    │
│  └─────────────────────────────────────┘    │
└──────────────────┬──────────────────────────┘
                   │
                   ▼
┌─────────────────────────────────────────────┐
│  ORCHESTRATOR AGENT                        │
│  ┌─────────────────────────────────────┐   │
│  │ For each phase:                     │   │
│  │   1. Select agents (list)           │   │
│  │   2. Dispatch (parallel/serial)     │   │
│  │   3. Monitor Hive Mind for results  │   │
│  │   4. Evaluate: continue / replan    │   │
│  │   5. Adapt if obstacles detected    │   │
│  └─────────────────────────────────────┘   │
└──────────────────┬──────────────────────────┘
                   │
      ┌────────────┼────────────┐
      ▼            ▼            ▼
┌──────────┐ ┌──────────┐ ┌──────────┐
│  AGENT 1 │ │  AGENT 2 │ │  AGENT N │  ... (up to 35)
│ ReAct    │ │ ReAct    │ │ ReAct    │
│ loop     │ │ loop     │ │ loop     │
└────┬─────┘ └────┬─────┘ └────┬─────┘
     │            │            │
     └────────────┼────────────┘
                  │
                  ▼
         ┌───────────────┐
         │   HIVE MIND   │
         │ (shared state)│
         └───────┬───────┘
                 │
                 ▼
         ┌───────────────┐
         │  TOOL BRIDGE  │
         │  + Defense    │
         │    Pipeline   │
         └───────┬───────┘
                 │
                 ▼
         ┌───────────────┐
         │  REAL TOOLS   │
         │  nmap, nuclei,│
         │  metasploit,  │
         │  frida, etc.  │
         └───────┬───────┘
                 │
                 ▼
         ┌───────────────┐
         │   FINDINGS    │
         │  → Mission    │
         │    Report     │
         └───────────────┘
```

### ReAct Loop (per agent)

```python
class AgentBase:
    def run(self, mission_context: dict) -> AgentResult:
        """
        ReAct loop for every agent:
          1. THINK: Analyze Hive Mind context for my agent type
          2. DECIDE: Choose next action (recon, exploit, wait, escalate)
          3. ACT: Execute via Tool Bridge (with defense pipeline)
          4. OBSERVE: Parse results, extract findings
          5. SHARE: Push findings to Hive Mind
          6. LOOP: Goto 1 until phase complete or abort signal
        """
```

---

## 8. Database Schema (29 Tables)

| Category | Tables |
|----------|--------|
| **Core** | `llm_sessions`, `llm_vulnerabilities`, `chat_sessions`, `chat_messages`, `credentials`, `loot` |
| **Exploits** | `exploit_generations`, `attack_chains`, `exploit_evidence` |
| **Web** | `browser_agent_sessions`, `http_proxy_history`, `http_testing_rules` |
| **Intel** | `cve_intel_cache`, `bugbounty_assessments` |
| **Defense** | `proxy_sessions`, `defense_events` |
| **Missions** | `missions`, `mission_phases`, `mission_findings` |
| **Agents** | `agent_actions`, `agent_learnings`, `agent_personas` |
| **Specialist** | `fix_plans`, `bug_bounty_reports`, `supply_chain_findings`, `reverse_engineering_sessions`, `social_engineering_campaigns` |
| **Kali** | `kali_sessions`, `cracked_hashes` |

---

## 9. Deployment

PhantomStrike v3.2 runs **natively on Kali Linux** — no Docker, no containers.
All tools are real Kali packages installed directly on the host.

### Quick Start

```bash
# Full installation (first time)
./phantomstrike.sh install

# Update codebase + deps
./phantomstrike.sh update

# Install/update external tools only
./phantomstrike.sh tools

# Start the server
./phantomstrike.sh start

# Health check
./phantomstrike.sh health

# Stop the server
./phantomstrike.sh stop

# Start server + MCP bridge
./phantomstrike.sh start
./phantomstrike.sh --mcp --server-url http://localhost:8888
```

### Commands Reference

| Command | Description |
|---------|-------------|
| `install` | Full setup: virtual env, Python deps, external tools, config bootstrap |
| `start` | Start the PhantomStrike API server on port 8888 |
| `stop` | Gracefully terminate the running server |
| `update` | git pull + reinstall Python deps if requirements changed |
| `tools` | Install/update external security tools via `scripts/install_tools.sh` |
| `health` | Verify all components: server, MCP, agents, Hive Mind, tool bridge |

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PHANTOMSTRIKE_HOST` | `127.0.0.1` | Server bind address |
| `PHANTOMSTRIKE_PORT` | `8888` | API server port |
| `PHANTOMSTRIKE_API_TOKEN` | (none) | Bearer auth token |
| `PHANTOMSTRIKE_LLM_MODEL` | (none) | Ollama model for local AI |
| `PHANTOMSTRIKE_DATA_DIR` | `.phantomstrike_data` | Database and config location |
| `COMMAND_TIMEOUT` | (config) | Command execution timeout |

---

## 10. Verified Capabilities

- **AutoFixer**: Plan created → pending_approval → operator approves → fix executed ✓
- **OPSEC Audit**: sqlmap risk=85 → VETOED → suggests --random-agent --delay=2 ✓
- **BugBounty**: Hunt target → 2 findings → check duplicates → generate report ✓
- **Emergency**: go_dark → terminate all + wipe evidence + rotate identities ✓
- **Hive Mind**: Thread-safe, context queries per agent type, DB persistence ✓
- **Tool Bridge**: 200+ real tool endpoints mapped, defense pre-check pipeline ✓
- **Server**: 397 routes, all healthy ✓
- **35 Agents**: All agent files present with ReAct loop and Hive Mind integration ✓
- **Cross-Domain**: AI identifies target domain from fingerprint, dispatches correct agents ✓

---

## 11. Agent File Mapping Reference

```
server_core/orchestrator/
├── agent_base.py                    # Base class (ReAct loop, ToolExecutor, PatternMatcher)
├── hive_mind.py                     # Shared KB (thread-safe, typed, DB-persisted)
├── tool_bridge.py                   # 200+ tool wrappers with defense pipeline
├── orchestrator_agent.py            # Mission lifecycle manager
├── task_decomposer.py               # Prompt → structured mission phases
├── agent_memory.py                  # Append-only shared memory
├── mission_tracker.py               # Progress tracking + report generation
├── recon_agent.py                   # Agent 1
├── vuln_agent.py                    # Agent 2
├── exploit_agent.py                 # Agent 3
├── post_exploit_agent.py            # Agent 4
├── exfil_agent.py                   # Agent 5
├── cleanup_agent.py                 # Agent 6
├── attack_agents/                   # Agents 7-12
│   ├── privesc_agent.py
│   ├── cred_access_agent.py
│   ├── persistence_agent.py
│   ├── cloud_agent.py
│   ├── lateral_move_agent.py
│   └── webapp_agent.py
├── defense_agents/                  # Agents 13-18
│   ├── emergency_agent.py
│   ├── opsec_agent.py
│   ├── decoy_agent.py
│   ├── counter_surveillance.py
│   ├── reverse_trace.py
│   └── trace_buster.py
├── specialist_agents/               # Agents 19-23
│   ├── supply_chain_agent.py
│   ├── social_eng_agent.py
│   ├── bug_bounty_agent.py
│   ├── auto_fixer_agent.py
│   └── reverse_engineering_agent.py
└── domain_agents/                   # Agents 24-35 ★
    ├── iot_agent.py
    ├── scada_agent.py
    ├── automotive_agent.py
    ├── satellite_agent.py
    ├── blockchain_agent.py
    ├── ai_exploit_agent.py
    ├── mobile_agent.py
    ├── telecom_agent.py
    ├── physical_agent.py
    ├── darkweb_agent.py
    ├── drone_agent.py
    └── nuclear_opsec_agent.py
```

---

## 12. Ethics & Safety Gates

- **Autonomous ransomware** requires explicit operator opt-in with secondary confirmation
- **Social engineering** operates only against authorized penetration test targets
- **Dark web operations** use Monero + Tor for operator protection
- **All actions** logged with immutable audit trail
- **OPSEC agent** reviews every action before execution (risk score 0-100, can veto)
- **Emergency agent** can terminate all operations in milliseconds
- **Legal compliance** module checks target jurisdiction before mission start
- **Scope enforcement**: Bug Bounty agent respects program scope boundaries

---

*PhantomStrike v3.2 — One prompt. Total compromise. Zero human intervention.*
