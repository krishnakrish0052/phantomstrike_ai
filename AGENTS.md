# AGENTS.md

## Guidance for agentic coding assistants working in this repository

## Quick orientation

- Project: PhantomStrike v3.3 (Python 3.13+)
- Architecture: 35-agent AI swarm on native Kali Linux (no Docker)
- Stack: Flask REST API + FastMCP bridge + ReAct-based autonomous loop + Hive Mind v3 event bus
- Primary entrypoints: `phantomstrike_server.py`, `phantomstrike_mcp.py`
- Config helpers: `config.py`, `core/config_core.py`
- Tools registry: `tool_registry.py`
- Deployment: `./phantomstrike.sh install` (one-command setup)
- Tests: pytest suite under `tests/` (latest local verification: 528 passing)

## The 35-Agent Swarm — Fleet Overview

PhantomStrike v3.3 deploys 35 specialized AI agents organized into 5 categories.
Every runtime agent is BaseAgent-backed through
`server_core/orchestrator/agent_registry.py`; native agents inherit
`server_core/orchestrator/agent_base.py` directly and legacy agents are wrapped
by `BaseAgentRuntimeAdapter`. Agents communicate exclusively through the Hive
Mind shared knowledge base.

### Category 1: Core Agents (6)
The kill-chain foundation — these agents are in `server_core/orchestrator/` directly.

| # | Agent | File | Role |
|---|-------|------|------|
| 1 | Recon Agent | `recon_agent.py` | OSINT, 50+ sources, zero-touch passive recon |
| 2 | Vuln Agent | `vuln_agent.py` | CVE matching, CVSS scoring, vulnerability chaining |
| 3 | Exploit Agent | `exploit_agent.py` | 8 exploit types, WAF/IDS evasion |
| 4 | Post-Exploit Agent | `post_exploit_agent.py` | Linux/Windows enumeration |
| 5 | Exfil Agent | `exfil_agent.py` | Multi-channel data extraction |
| 6 | Cleanup Agent | `cleanup_agent.py` | Anti-forensics, selective log wiping |

### Category 2: Attack Agents (6)
Post-exploitation and lateral spread — `server_core/orchestrator/attack_agents/`.

| # | Agent | File | Role |
|---|-------|------|------|
| 7 | PrivEsc Agent | `attack_agents/privesc_agent.py` | 200+ techniques, kernel exploit matching |
| 8 | Credential Access | `attack_agents/cred_access_agent.py` | mimikatz, DPAPI, cloud credential extraction |
| 9 | Persistence Agent | `attack_agents/persistence_agent.py` | 50+ persistence mechanisms |
| 10 | Cloud Agent | `attack_agents/cloud_agent.py` | AWS/GCP/Azure IAM, K8s, serverless |
| 11 | Lateral Move Agent | `attack_agents/lateral_move_agent.py` | AD domination, PtH/PtT/Kerberoasting |
| 12 | WebApp Agent | `attack_agents/webapp_agent.py` | Modern web, APIs, GraphQL, JWT advanced |

### Category 3: Defense Agents (6)
Self-protection and operational security — `server_core/orchestrator/defense_agents/`.

| # | Agent | File | Role |
|---|-------|------|------|
| 13 | Emergency Agent | `defense_agents/emergency_agent.py` | Kill switch, evidence wipe, go dark, dead man's switch |
| 14 | OPSEC Agent | `defense_agents/opsec_agent.py` | Pre-execution audit, risk scoring, veto |
| 15 | Decoy Agent | `defense_agents/decoy_agent.py` | False flags, misdirection, rabbit holes |
| 16 | CounterSurveillance | `defense_agents/counter_surveillance.py` | 15+ threat feeds, tracing detection |
| 17 | ReverseTrace Agent | `defense_agents/reverse_trace.py` | Attacker attribution, evidence collection |
| 18 | TraceBuster Agent | `defense_agents/trace_buster.py` | Identity rotation, compartmentalization, geo-hopping |

### Category 4: Specialist Agents (5)
Advanced capabilities — `server_core/orchestrator/specialist_agents/`.

| # | Agent | File | Role |
|---|-------|------|------|
| 19 | Supply Chain | `specialist_agents/supply_chain_agent.py` | Dependency scan, confusion check, CI/CD audit |
| 20 | Social Engineering | `specialist_agents/social_eng_agent.py` | Profiling, phishing, pretext (authorized only) |
| 21 | Bug Bounty | `specialist_agents/bug_bounty_agent.py` | Scope, hunt, duplicate check, professional reports |
| 22 | Auto Fixer | `specialist_agents/auto_fixer_agent.py` | Plan→Present→Approve→Fix→Verify (gated) |
| 23 | Reverse Engineering | `specialist_agents/reverse_engineering_agent.py` | Binary analysis, vulnerability patterns, Ghidra/radare2 |

### Category 5: Domain Agents (12) ★ Added in v3.2, carried forward in v3.3
Universal attack surface coverage — `server_core/orchestrator/domain_agents/`.

| # | Agent | File | Role |
|---|-------|------|------|
| 24 | IoT Agent | `domain_agents/iot_agent.py` | MQTT/BLE/Zigbee, firmware extraction & analysis |
| 25 | SCADA Agent | `domain_agents/scada_agent.py` | Modbus/s7comm/DNP3, PLC takeover, ICS exploitation |
| 26 | Automotive Agent | `domain_agents/automotive_agent.py` | CAN bus, OBD-II, key fob relay, ECU reflashing |
| 27 | Satellite Agent | `domain_agents/satellite_agent.py` | SDR, ground station, GPS spoofing, telecommand injection |
| 28 | Blockchain Agent | `domain_agents/blockchain_agent.py` | Smart contract analysis, MEV, flash loans, DeFi exploits |
| 29 | AI Exploit Agent | `domain_agents/ai_exploit_agent.py` | Prompt injection, model extraction, adversarial examples |
| 30 | Mobile Agent | `domain_agents/mobile_agent.py` | APK/IPA analysis, Frida, SSL pinning bypass |
| 31 | Telecom Agent | `domain_agents/telecom_agent.py` | SS7/Diameter, 5G core, IMSI catcher, SIP/VoIP |
| 32 | Physical Agent | `domain_agents/physical_agent.py` | RFID cloning, lockpicking, badge cloning, drone delivery |
| 33 | DarkWeb Agent | `domain_agents/darkweb_agent.py` | Tor/I2P automation, market crawling, credential acquisition |
| 34 | Drone Agent | `domain_agents/drone_agent.py` | MAVLink injection, GPS spoofing, FPV interception |
| 35 | Nuclear OpSec Agent | `domain_agents/nuclear_opsec_agent.py` | Traffic entropy matching, mathematical stealth proofs |

All 35 agents communicate through the **Hive Mind** (`server_core/orchestrator/hive_mind.py`) —
a thread-safe shared knowledge base with typed collections, context queries per agent type,
and DB persistence. Agents never talk directly to each other.

## Deployment

PhantomStrike v3.3 runs natively on Kali Linux — **no Docker required**.
All tools install directly on the host via `scripts/install_tools.sh`.

### phantomstrike.sh Commands

```
./phantomstrike.sh install       # Full setup: venv + Python deps + external tools
./phantomstrike.sh start         # Start the PhantomStrike API server
./phantomstrike.sh stop          # Gracefully stop the server
./phantomstrike.sh update        # git pull + reinstall deps if needed
./phantomstrike.sh tools         # Install/update external security tools only
./phantomstrike.sh health        # Verify all components are operational
```

Legacy flags still supported: `-a` (install+start), `-s` (update repo), `-t` (install tools),
`--server`, `--mcp`, `--server --mcp` (both).

### Environment setup

```bash
python3 -m venv phantomstrike-env
source phantomstrike-env/bin/activate
python3 -m pip install -r requirements.txt
```

### Run the server

```bash
python3 phantomstrike_server.py
```

### Run the MCP client

```bash
phantomstrike-env/bin/python3 phantomstrike_mcp.py --server http://localhost:8888
```

## Directory Structure

```
nyxstrike/
├── phantomstrike.sh              # Main entrypoint (install/start/stop/update/tools/health)
├── phantomstrike_server.py       # Flask REST API server (397 routes)
├── phantomstrike_mcp.py          # FastMCP bridge (exposes tools to AI agents)
├── config.py                     # Global configuration
├── tool_registry.py              # 200+ tool registration & health checks
├── core/                         # Core infrastructure
│   └── config_core.py            # Configuration helper
├── server_core/                  # Backend services
│   ├── db.py                     # SQLite database (29+ tables)
│   ├── orchestrator/
│   │   ├── orchestrator_agent.py # Mission lifecycle: decompose → dispatch → adapt → report
│   │   ├── agent_base.py         # Base class for all 35 agents (ReAct loop)
│   │   ├── hive_mind.py          # Shared knowledge base (thread-safe, DB-backed)
│   │   ├── tool_bridge.py        # 100+ REST endpoints, defense pre-check pipeline
│   │   ├── task_decomposer.py    # Prompt → structured mission phases
│   │   ├── agent_memory.py       # Thread-safe append-only shared memory
│   │   ├── mission_tracker.py    # Progress tracking + Markdown report generation
│   │   ├── recon_agent.py        # Core agent (OSINT)
│   │   ├── vuln_agent.py         # Core agent (vulnerability)
│   │   ├── exploit_agent.py      # Core agent (exploitation)
│   │   ├── post_exploit_agent.py # Core agent (enumeration)
│   │   ├── exfil_agent.py        # Core agent (data extraction)
│   │   ├── cleanup_agent.py      # Core agent (anti-forensics)
│   │   ├── attack_agents/        # 6 post-exploitation agents
│   │   │   ├── privesc_agent.py
│   │   │   ├── cred_access_agent.py
│   │   │   ├── persistence_agent.py
│   │   │   ├── cloud_agent.py
│   │   │   ├── lateral_move_agent.py
│   │   │   └── webapp_agent.py
│   │   ├── defense_agents/       # 6 self-defense agents
│   │   │   ├── emergency_agent.py
│   │   │   ├── opsec_agent.py
│   │   │   ├── decoy_agent.py
│   │   │   ├── counter_surveillance.py
│   │   │   ├── reverse_trace.py
│   │   │   └── trace_buster.py
│   │   ├── specialist_agents/    # 5 advanced-capability agents
│   │   │   ├── supply_chain_agent.py
│   │   │   ├── social_eng_agent.py
│   │   │   ├── bug_bounty_agent.py
│   │   │   ├── auto_fixer_agent.py
│   │   │   └── reverse_engineering_agent.py
│   │   └── domain_agents/        # 12 universal-domain agents (added in v3.2)
│   │       ├── iot_agent.py
│   │       ├── scada_agent.py
│   │       ├── automotive_agent.py
│   │       ├── satellite_agent.py
│   │       ├── blockchain_agent.py
│   │       ├── ai_exploit_agent.py
│   │       ├── mobile_agent.py
│   │       ├── telecom_agent.py
│   │       ├── physical_agent.py
│   │       ├── darkweb_agent.py
│   │       ├── drone_agent.py
│   │       └── nuclear_opsec_agent.py
│   ├── intelligence/             # Intelligent Decision Engine
│   │   └── tool_catalog.py       # Catalog-driven tool selection
│   └── ...                       # Additional server modules
├── mcp_tools/                    # MCP tool wrappers
│   └── gateway.py                # Gateway tools registered via mcp.tool()
├── scripts/
│   └── install_tools.sh          # External security tool installer
├── dashboard/                    # React web dashboard
├── docs/                         # Documentation
│   ├── ARCHITECTURE_v3.0.md      # v3.0 architecture reference
│   ├── ARCHITECTURE.md           # v3.3 comprehensive architecture
│   ├── ARCHITECTURE_v3.3.md      # v3.3 architecture delta
│   └── intelligence_tool_catalog.md
├── tests/                        # pytest test suite
├── dependencies/                 # Python requirements (tiered)
│   ├── requirements.txt          # Core dependencies
│   ├── requirements-extra.txt    # Optional packages
│   └── requirements-big.txt      # Heavy optional packages
└── Modelfiles/                   # Ollama model definitions
```

## Build, lint, test commands

### Tests

This repo uses pytest. Keep new tests focused on the changed surface area.

Run all tests:

```bash
pytest
```

Run a single test file:

```bash
pytest tests/path/to/test_file.py
```

Run a single test function:

```bash
pytest tests/path/to/test_file.py::test_function_name
```

Run a single test class method:

```bash
pytest tests/path/to/test_file.py::TestClassName::test_method_name
```

### Lint/format

No explicit lint/format configuration was found (no `pyproject.toml`, `setup.cfg`,
or `tox.ini`). Do not introduce auto-format-only changes unless requested.

If you add a linter, follow existing conventions and keep diffs scoped.

## Code style guidelines

### General conventions

- Follow existing patterns and keep changes minimal.
- Avoid large formatting-only diffs.
- Keep PRs small and focused (see `.github/CONTRIBUTING.md`).

### Indentation and whitespace

- `.editorconfig` specifies: spaces, 2-space indent, LF, final newline.
- Respect existing files even if they deviate (avoid reformatting).

### Imports

- Prefer standard ordering: stdlib, third-party, local modules.
- Use explicit imports for project modules (e.g., `from core import ...`).
- Keep import lists stable; do not reorder for style only.

### Typing

- Use type hints on public functions and significant internal APIs.
- Prefer `Dict[str, Any]`, `Optional[T]`, and dataclasses where already used.
- Keep typing consistent with existing style in the file you edit.

### Naming

- Modules/files: `snake_case.py`.
- Classes: `PascalCase`.
- Functions/variables: `snake_case`.
- Constants: `UPPER_SNAKE_CASE`.
- Use descriptive names for tools and endpoints (see `mcp_tools/*`).

### Logging and errors

- Prefer the `logging` module; reuse existing loggers in each module.
- Follow existing patterns for structured error returns, e.g.
  `{"error": "message", "success": False}`.
- When integrating tool execution, surface recovery or escalation info if present.

### API and tool patterns

- Gateway tools are registered via `mcp.tool()` decorators (see `mcp_tools/gateway.py`).
- When calling tools, validate required params and fill defaults like existing logic.
- When adding tools, keep signature docstrings short and consistent.

### Configuration

- Read config values via `core.config_core.get(key, default)`.
- Avoid hard-coding wordlist paths; use `config_core.get_word_list_path(...)`.

### External tools

- Many security tools are external and not installed via pip.
- If you add new tool integrations, document required binaries and parameters.

## Contribution guidelines (from repo docs)

- Keep PRs focused; avoid unrelated formatting changes.
- Prefer PRs under 300 changed lines; avoid exceeding 500 lines.
- Use clear commit messages: `type: short description`.
- Branch naming: `feature/...`, `fix/...`, `docs/...`, `refactor/...`.
- AI assistance is allowed but must be reviewed and tested.

## Repo-specific notes

- **Kali Linux native**: The platform runs directly on Kali — no Docker, no containerization.
  All tools are installed natively via `scripts/install_tools.sh`.
- Server binds to `127.0.0.1` by default; override via `PHANTOMSTRIKE_HOST`.
- API token: set `PHANTOMSTRIKE_API_TOKEN` to enable bearer auth.
- Default API port: `PHANTOMSTRIKE_PORT` (default 8888).
- Command timeouts: `COMMAND_TIMEOUT` in config.
- All 35 agents communicate through the Hive Mind — never directly.
  Use `server_core/orchestrator/hive_mind.py` to add knowledge, query context.
- Agent base class at `server_core/orchestrator/agent_base.py` provides the ReAct
  loop, ToolExecutor, and PatternMatcher fallback for every agent.
- When adding a new agent, place it in the correct category directory
  (`attack_agents/`, `defense_agents/`, `specialist_agents/`, `domain_agents/`)
  or directly in `orchestrator/` for core agents.

## Intelligence planner

- The Intelligent Decision Engine is catalog-driven.
- Add or tune tool behavior in `server_core/intelligence/tool_catalog.py`.
- Use `docs/intelligence_tool_catalog.md` for the add-tool workflow.
- Run planner tests when modifying catalog/scoring:

```bash
pytest tests/test_intelligence_precision_planner.py
```

## When in doubt

- Mirror the style of the file you are editing.
- Keep diffs minimal and avoid global refactors.
- Prefer adding tests when adding new logic, even if the suite is small.
