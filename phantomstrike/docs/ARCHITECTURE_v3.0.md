# PhantomStrike v3.0 — Agent Swarm Architecture

## What We Built

v3.0 transforms PhantomStrike from a tool orchestrator into an **autonomous AI agent swarm** — 23 specialized agents that think like elite hackers, coordinate through a shared Hive Mind, execute real tools through a Tool Bridge, and are protected by 6 defense agents.

**Built: June 18, 2026**

---

## Agent Swarm (23 Agents)

### Attack Agents (12)
| # | Agent | Type | Status | Key Capability |
|---|-------|------|--------|---------------|
| 1 | Recon | `recon` | ✅ | OSINT, 50+ sources, zero-touch passive recon |
| 2 | Vuln | `vuln` | ✅ | CVE matching, CVSS scoring, vulnerability chaining |
| 3 | Exploit | `exploit` | ✅ | 8 exploit types, WAF/IDS evasion |
| 4 | PostExploit | `post_exploit` | ✅ | Linux/Windows enumeration |
| 5 | PrivEsc | `privesc` | ✅ | 200+ techniques, kernel exploit matching |
| 6 | LateralMove | `lateral_move` | ✅ | AD domination, PtH/PtT/Kerberoasting |
| 7 | Persistence | `persistence` | ✅ | 50+ persistence mechanisms |
| 8 | CredAccess | `cred_access` | ✅ | mimikatz, DPAPI, cloud credential extraction |
| 9 | Exfil | `exfil` | ✅ | Multi-channel data extraction |
| 10 | Cleanup | `cleanup` | ✅ | Anti-forensics, selective log wiping |
| 11 | WebApp | `webapp` | ✅ | Modern web, APIs, GraphQL, JWT advanced |
| 12 | Cloud | `cloud` | ✅ | AWS/GCP/Azure IAM, K8s, serverless |

### Defense Agents (6)
| # | Agent | Type | Status | Key Capability |
|---|-------|------|--------|---------------|
| 13 | TraceBuster | `trace_buster` | ✅ | Identity rotation, compartmentalization, geo-hopping |
| 14 | Decoy | `decoy` | ✅ | False flags, misdirection, rabbit holes |
| 15 | OPSEC | `opsec` | ✅ | Pre-execution audit, risk scoring, veto |
| 16 | CounterSurv | `counter_surveillance` | ✅ | 15+ threat feeds, tracing detection |
| 17 | Emergency | `emergency` | ✅ | Kill switch, evidence wipe, go dark, dead man's switch |
| 18 | ReverseTrace | `reverse_trace` | ✅ | Attacker attribution, evidence collection |

### Specialist Agents (5)
| # | Agent | Type | Status | Key Capability |
|---|-------|------|--------|---------------|
| 19 | ReverseEng | `reverse_engineering` | ✅ | Binary analysis, vulnerability patterns, Ghidra/radare2 |
| 20 | AutoFixer | `auto_fixer` | ✅ | Plan→Present→Approve→Fix→Verify (gated) |
| 21 | BugBounty | `bug_bounty` | ✅ | Scope, hunt, duplicate check, professional reports |
| 22 | SocialEng | `social_eng` | ✅ | Profiling, phishing, pretext (authorized only) |
| 23 | SupplyChain | `supply_chain` | ✅ | Dependency scan, confusion check, CI/CD audit |

---

## Core Infrastructure

| Component | File | Purpose |
|-----------|------|---------|
| **Hive Mind** | `server_core/orchestrator/hive_mind.py` | Shared KB — thread-safe, typed collections, context queries per agent type, DB persistence |
| **Tool Bridge** | `server_core/orchestrator/tool_bridge.py` | 100+ real REST API calls, 17 agent types mapped, defense check pipeline, auto-endpoint resolution |
| **Agent Base** | `server_core/orchestrator/agent_base.py` | Base class for all agents — ReAct loop, ToolExecutor, PatternMatcher fallback |
| **Orchestrator** | `server_core/orchestrator/orchestrator_agent.py` | Mission lifecycle — decompose → dispatch → monitor → adapt → report |
| **Task Decomposer** | `server_core/orchestrator/task_decomposer.py` | Prompt → structured mission phases (keyword rules + optional LLM) |
| **Agent Memory** | `server_core/orchestrator/agent_memory.py` | Thread-safe append-only shared memory with tag indexing |
| **Mission Tracker** | `server_core/orchestrator/mission_tracker.py` | Progress tracking + Markdown report generation |

---

## Agent Communication

Agents DON'T talk directly — everything flows through the Hive Mind:

```
ReconAgent discovers host → HiveMind.add_host(...) 
→ VulnAgent sees new host → runs nuclei → HiveMind.add_vuln(...)
→ ExploitAgent sees new vuln → generates exploit → HiveMind.add_finding(...)
→ OPSECAgent reviews exploit → approves with modifications
→ TraceBusterAgent rotates ExploitAgent's IP
→ ExploitAgent executes → HiveMind.add_session(...)
→ PostExploitAgent sees new session → starts enumeration
→ PrivEscAgent starts privilege escalation
... cascade continues
```

---

## Database (29 Tables)

| Category | Tables |
|----------|--------|
| Core | llm_sessions, llm_vulnerabilities, chat_sessions, chat_messages, credentials, loot |
| Exploits | exploit_generations, attack_chains, exploit_evidence |
| Web | browser_agent_sessions, http_proxy_history, http_testing_rules |
| Intel | cve_intel_cache, bugbounty_assessments |
| Defense | proxy_sessions, defense_events |
| Missions | missions, mission_phases, mission_findings |
| Agents | agent_actions, agent_learnings, agent_personas |
| Specialist | fix_plans, bug_bounty_reports, supply_chain_findings, reverse_engineering_sessions, social_engineering_campaigns |
| Kali | kali_sessions, cracked_hashes |

---

## Verified Functionality

- **AutoFixer**: Plan created → pending_approval → operator approves → fix executed ✅
- **OPSEC Audit**: sqlmap risk=85 → VETOED → suggests --random-agent --delay=2 ✅
- **BugBounty**: Hunt target → 2 findings discovered → check duplicate → generate report ✅
- **Emergency**: go_dark → terminate all + wipe evidence + rotate identities ✅
- **Hive Mind**: Thread-safe, context queries per agent type, DB persistence ✅
- **Tool Bridge**: 100+ real REST API endpoints mapped, defense pre-check pipeline ✅
- **Server**: 397 routes, all healthy ✅
