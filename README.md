# PhantomStrike v3.2 GODMODE

### AI-Powered Autonomous Offensive Security Platform

**35 specialized AI agents. 15 attack domains. 12 GODMODE capabilities. 200+ real security tools. Fully autonomous.**

---

[![Python](https://img.shields.io/badge/Python-3.12%2B-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-AGPLv3-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Kali%20Linux%20Native-red.svg)]()
[![MCP](https://img.shields.io/badge/MCP-Compatible-purple.svg)]()
[![Version](https://img.shields.io/badge/Version-3.2.0-orange.svg)]()
[![Agents](https://img.shields.io/badge/AI%20Agents-35-brightgreen.svg)]()
[![Routes](https://img.shields.io/badge/API%20Routes-397%2B-blue.svg)]()
[![Tools](https://img.shields.io/badge/Security%20Tools-200%2B-darkred.svg)]()

---

## What is PhantomStrike?

PhantomStrike is an AI-powered autonomous offensive security platform. It deploys a swarm of 35 specialized AI agents that think, act, and adapt like elite human hackers — orchestrating real Kali Linux security tools through an undetectable proxy layer with military-grade self-defense.

**One prompt. Autonomous hacking. Undetectable. Self-protecting.**

---

## Quick Start

```bash
git clone https://github.com/krishnakrish0052/phantomstrike_ai.git
cd phantomstrike_ai

# Install & start (native Kali Linux — no Docker required)
./phantomstrike.sh install     # Auto-detect & install 200+ tools
./phantomstrike.sh start       # Start server + MCP on localhost:8888
./phantomstrike.sh health      # Verify everything is running

# Open http://localhost:8888 in your browser
```

**Requirements**: Kali Linux (or any Debian-based distro with security tools). Python 3.12+. 4GB+ RAM.

---

## AI Agent Integration (MCP)

Connect any MCP-compatible AI client (Claude Desktop, Cursor, VS Code Copilot, OpenCode):

```json
{
  "mcpServers": {
    "phantomstrike": {
      "command": "phantomstrike-env/bin/python3",
      "args": ["phantomstrike_mcp.py", "--server", "http://127.0.0.1:8888", "--profile", "full"],
      "cwd": "/path/to/phantomstrike_ai"
    }
  }
}
```

Your AI assistant gains access to 150+ security tools as callable functions.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                   35 AI AGENT SWARM                          │
│  ┌──────────┐  ┌──────────┐  ┌───────────┐  ┌───────────┐ │
│  │  Attack  │  │ Defense  │  │Specialist │  │  Domain   │ │
│  │  Agents  │  │  Agents  │  │  Agents   │  │  Agents   │ │
│  │  (12)    │  │  (6)     │  │  (5)      │  │  (12)     │ │
│  └────┬─────┘  └────┬─────┘  └─────┬─────┘  └─────┬─────┘ │
│       └──────────────┼──────────────┼──────────────┘       │
│                 ┌────▼────┐                                 │
│                 │HIVE MIND│  ← Shared Knowledge Base        │
│                 │  v3     │  ← Event Bus (11 types)         │
│                 └────┬────┘  ← Snapshots + ContextSelector  │
│                      │                                      │
│    ┌─────────────────┼─────────────────┐                   │
│ ┌──▼──┐  ┌────────▼────────┐  ┌───────▼──────┐            │
│ │TOOL │  │  PHANTOM PROXY  │  │   DEFENSE    │            │
│ │BRIDGE│ │ IP Rotation     │  │   SHIELD     │            │
│ │200+  │ │ JA4 Spoofing    │  │ Honeypot Det │            │
│ │Tools │ │ Protocol Camo   │  │ CounterSurv  │            │
│ └─────┘  └─────────────────┘  └──────────────┘            │
└─────────────────────────────────────────────────────────────┘
```

---

## GODMODE Capabilities (12 Modules — 20,371 Lines)

| # | Capability | Purpose |
|---|-----------|---------|
| 1 | **Universal Goal Engine** | Pursues any objective relentlessly across ALL 35 agents. Parallel path execution. Never stops until achieved. |
| 2 | **EGATS Engine** | Evidence-Guided Attack Tree Search. UCB node selection. Difficulty scoring with evidence-based pruning. |
| 3 | **Attack Synthesizer** | AI discovers novel attack chains from 70 primitives across 8 domains. 13M+ theoretical combinations. |
| 4 | **Persona Factory** | 100+ fake attacker personas. Real attack hides among decoys with unique TTPs per persona. |
| 5 | **Protocol Morpher** | 8 transport protocols. Seamless mid-attack switching without session loss. |
| 6 | **GAN Traffic Mimicry** | C2 traffic statistically identical to target baseline (KS test p > 0.95). |
| 7 | **Infrastructure Fabric** | Self-healing C2 across 7 cloud providers. 60s redeploy. DNS fast-flux. |
| 8 | **Training Dojo** | 1000+ Red vs Blue autonomous engagements. Agents evolve techniques continuously. |
| 9 | **Polymorphic Malware** | Self-rewriting code via LLM. 1000 generations → 0% AV detection rate. |
| 10 | **Zero Day Hunter** | AI fuzzing → crash analysis → exploit generation → value assessment. |
| 11 | **Deepfake Social** | Voice clone (3s audio) + real-time face swap + emotion mirroring. Authorized testing only. |
| 12 | **Psychological Profiler** | OCEAN + Dark Triad + cognitive biases. Personalized attack vectors per person. |

---

## 35 AI Agents

### Attack Agents
Recon, Vulnerability, Exploit, Post-Exploit, Privilege Escalation, Lateral Movement, Persistence, Credential Access, Exfiltration, Cleanup, Web Application, Cloud Attack

### Defense Agents
TraceBuster (identity protection), Decoy (misdirection), OPSEC (pre-execution audit), CounterSurveillance (threat detection), Emergency Response (kill switch), Reverse Trace (attacker attribution)

### Specialist Agents
Reverse Engineering, Auto Fixer (plan→approve→fix→verify), Bug Bounty, Social Engineering, Supply Chain

### Domain Agents (New in v3.2)
IoT, SCADA/ICS, Automotive, Satellite/Aerospace, Blockchain/DeFi, AI/ML Exploitation, Mobile (iOS/Android), Telecom (SS7/5G), Physical Access, Dark Web Operations, Drone/UAV, Nuclear-Grade OpSec

---

## 15 Attack Domains

| Domain | Target Types |
|--------|-------------|
| **Web** | Modern SPAs, APIs, GraphQL, WebSockets, JWT, OAuth |
| **Cloud** | AWS, GCP, Azure, Kubernetes, serverless, CI/CD |
| **SCADA/ICS** | PLCs, HMIs, RTUs, Modbus, DNP3, IEC 61850 |
| **Automotive** | CAN bus, OBD-II, key fobs, ECUs, Tesla API |
| **Satellite** | Ground stations, SDR downlink, GPS spoof, ADS-B |
| **Blockchain** | Smart contracts, DeFi, flash loans, MEV, bridges |
| **AI/ML** | Prompt injection, model extraction, adversarial examples |
| **Mobile** | APK/IPA analysis, Frida hooks, SSL pinning bypass |
| **Telecom** | SS7, Diameter, 5G core, IMSI catcher, SIP/VoIP |
| **Physical** | RFID cloning, lockpick, drone delivery, thermal camera |
| **Dark Web** | Tor scraping, market monitoring, crypto tracing |
| **Drone** | GPS spoof, MAVLink inject, FPV intercept |
| **IoT** | MQTT/BLE/Zigbee, firmware extraction, 10K+ default creds |
| **IT Network** | Active Directory, SMB, RDP, SSH, Kerberos |
| **Application** | SQLi, XSS, RCE, XXE, LFI, SSTI, SSRF, CSRF |

---

## Tool Arsenal (200+)

| Category | Tools |
|----------|-------|
| **Network** | nmap, masscan, rustscan, autorecon, arp-scan |
| **Web Discovery** | gobuster, ffuf, feroxbuster, katana, hakrawler |
| **Web Vuln** | nuclei (4000+ templates), sqlmap, nikto, wpscan, dalfox, xsser |
| **Exploitation** | metasploit, msfvenom, exploit-db, pwntools, commix |
| **Password** | hashcat, john, hydra, medusa, hashid |
| **Binary/RE** | gdb, radare2, ghidra, binwalk, angr, ropgadget |
| **Cloud** | prowler, trivy, scout-suite, kube-hunter, checkov |
| **OSINT** | Shodan, Censys, theHarvester, sherlock, spiderfoot, phone/email tracing, social profiling, dark web monitor |
| **WiFi** | aircrack-ng suite, wifite2, bettercap, hcxtools |
| **Forensics** | volatility, foremost, steghide, exiftool, hashpump |
| **C2** | DNS/ICMP/WebSocket/Social C2, CDN domain fronting |
| **Evasion** | Payload encryption, JA4 spoofing, traffic morphing, polyglot embedding |

---

## Features

- **35 autonomous AI agents** that think, adapt, and coordinate like elite human hackers
- **Universal Goal Engine** — one prompt, autonomous execution, never stops until achieved
- **Hive Mind v3** — shared knowledge base with event bus, reactive agent triggering, selective context
- **12 GODMODE capabilities** — from EGATS attack tree search to GAN traffic mimicry
- **200+ real Kali Linux tools** — auto-installed and orchestrated by AI agents
- **Phantom Proxy** — undetectable operations via rotating IPs, JA4 spoofing, protocol camouflage
- **Defense Shield** — real-time honeypot detection, counter-surveillance, emergency termination
- **397+ REST API routes** — complete programmatic access
- **29 database tables** — persistent mission tracking, agent learning, findings storage
- **Full React UI** — Proxy Control, Defense Monitor, Mission Console, Exploit Generator, HTTP Framework, Browser Agent, Attack Chains, Bug Bounty
- **MCP protocol** — plug into Claude Desktop, Cursor, VS Code Copilot, any MCP client
- **Native Kali deployment** — one shell script, auto-installs missing tools, no Docker required

---

## ⚠️ Important Legal Notice — READ CAREFULLY

PhantomStrike is an **open-source security research and educational tool**. It is designed and provided exclusively for:

| ✅ Permitted Use | ❌ Strictly Prohibited |
|---|---|
| Authorized penetration testing with **written permission** | Unauthorized access to ANY system you don't own |
| Security research on **your own** applications, servers, and infrastructure | Hacking, exploiting, or compromising third-party property |
| Bug bounty programs **within scope and program rules** | Any activity violating local, state, federal, or international law |
| CTF competitions and educational environments | Unauthorized data access, theft, or exfiltration |
| Red team exercises with **organizational approval** | Malware deployment against unauthorized targets |
| Finding and fixing vulnerabilities in **your own** code | Any malicious, harmful, or destructive activity |

### User Responsibility

**This software is completely unrestricted in its technical capabilities. The responsibility for its use rests ENTIRELY with the user.**

- The authors, contributors, and maintainers of PhantomStrike are **NOT responsible** for any misuse, damage, or legal consequences resulting from the use of this software
- By using PhantomStrike, you acknowledge that you are solely responsible for ensuring your use complies with all applicable laws and regulations
- This tool does not promote, encourage, or condone unauthorized hacking
- The AI agents within PhantomStrike will execute the instructions given to them — it is **your responsibility** to ensure those instructions are legal and ethical

### AI-Specific Warning

PhantomStrike contains autonomous AI agents capable of independently discovering vulnerabilities, generating exploits, and executing attack chains. These agents:

- **Do not** have built-in ethical constraints beyond scope configuration
- **Will execute** any technically feasible operation you instruct them to perform
- **Cannot** distinguish between authorized and unauthorized targets
- **Must be** supervised and controlled by a responsible operator

**Think of PhantomStrike as a powerful tool — like a lockpick set or a security scanner. The tool itself is neutral. How you use it defines whether it's ethical or criminal.**

---

## Source Credits & Attribution

PhantomStrike is built upon and inspired by several open-source projects:

| Project | Contribution | License |
|---------|-------------|---------|
| **[NyxStrike](https://github.com/CommonHuman-Lab/nyxstrike)** | Core architecture, Flask API, MCP integration, tool registry, React UI, database schema, plugin system, LLM client | AGPLv3 |
| **[HexStrike AI](https://github.com/0x4m4/hexstrike-ai)** | Exploit generation engine, browser agent, HTTP testing framework, vulnerability correlator, CVE intelligence, bug bounty workflows | MIT |

We are deeply grateful to the open-source security community. PhantomStrike extends these foundations with:

- **35 AI agents** (up from 6 stub agents)
- **12 GODMODE capabilities** (Universal Goal Engine, EGATS, Attack Synthesizer, Persona Factory, Protocol Morpher, GAN Traffic Mimicry, Infrastructure Fabric, Training Dojo, Polymorphic Malware, Zero Day Hunter, Deepfake Social, Psychological Profiler)
- **12 new attack domains** (SCADA, Automotive, Satellite, Blockchain, AI/ML, Mobile, Telecom, Physical, Dark Web, Drone, IoT, Nuclear OpSec)
- **Hive Mind v3** event bus with reactive agent triggering
- **Undetectable layer** via Phantom Proxy with IP rotation and protocol camouflage
- **Self-defense engine** with honeypot detection and counter-surveillance

---

## Open Source

PhantomStrike is **100% open-source** under the [AGPLv3 License](LICENSE).

- ✅ Free to use, modify, and distribute
- ✅ Anyone can contribute via pull requests
- ✅ Anyone can fork and build upon this work
- ✅ Commercial use permitted under AGPLv3 terms
- ✅ Source code must remain open if distributed as a service

**We believe security tools should be open. Transparency builds trust. Community improves quality.**

---

## Quick Commands

```bash
./phantomstrike.sh install    # Auto-detect Kali, install 200+ tools
./phantomstrike.sh start      # Start Flask server + MCP
./phantomstrike.sh stop       # Graceful shutdown
./phantomstrike.sh update     # Git pull + reinstall dependencies
./phantomstrike.sh tools      # List all tools with install status
./phantomstrike.sh health     # Server health + tool availability
```

---

## Contributing

Contributions are welcome. Open a PR or issue on GitHub.

1. Fork the repository
2. Create a feature branch
3. Submit a pull request

Please keep PRs focused and under 300 lines where possible.

---

## License

PhantomStrike is licensed under the [GNU Affero General Public License v3.0](LICENSE).

Portions of this codebase incorporate MIT-licensed code from [HexStrike AI](https://github.com/0x4m4/hexstrike-ai).

---

## ⭐ Support

If PhantomStrike is useful to you:

- Star the repository on GitHub
- Share it with the security community
- Contribute improvements, fixes, or new capabilities

**Built for the security community. By the security community.**
