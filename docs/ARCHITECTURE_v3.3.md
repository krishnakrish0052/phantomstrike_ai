# PhantomStrike v3.3 — Architecture Delta

This document records the v3.3 architecture changes on top of the v3.2
35-agent swarm. The canonical living architecture remains `docs/ARCHITECTURE.md`.

## Version

| Surface | Value |
|---------|-------|
| Runtime config | `3.3.0` |
| README badge | `3.3.0` |
| Health banner | `PhantomStrike v3.3` |
| Engine package | `server_core/engine/` v3.3 |

## Agent Runtime

v3.3 standardizes agent construction through
`server_core/orchestrator/agent_registry.py`.

| Metric | Current State |
|--------|---------------|
| Agent specs | 35 |
| Runtime agents | 35 |
| BaseAgent-backed | 35 |
| Native BaseAgent implementations | 6 |
| Wrapped legacy implementations | 29 |

Legacy agents are not deleted or rewritten. They are wrapped by
`BaseAgentRuntimeAdapter`, which provides the shared lifecycle, status, and
capability contract expected by the orchestrator.

## MCP Bridge

The FastMCP bridge is profile-driven:

| Profile | Exposed Tools | Purpose |
|---------|---------------|---------|
| `compact` | 2 | Gateway-only classification and execution |
| `default` | 129 | Common security workflow surface |
| `full` | 230 | Complete registered MCP surface |

v3.3 also fixes profile dependency ordering so dependency profiles are loaded
before dependent profiles in a deterministic order.

## Exploitation MCP Wiring

`mcp_tools/exploitation/__init__.py` now follows the same registration model as
the rest of `mcp_tools`:

- `register_exploitation_tools(mcp, api_client, logger=None)`
- `register_tools(...)` remains as a backward-compatible wrapper
- HTTP calls route through injected `ApiClient.safe_post` and `safe_get`
- synchronous client calls run through `asyncio.get_running_loop().run_in_executor`
- endpoints are normalized without leading slashes

## REST Tool Registry

| Metric | Current State |
|--------|---------------|
| Static registry entries | 158 |
| Duplicate endpoint mappings | 0 |
| Health-check tool records | 157 |
| Verified available in local smoke test | 153 / 157 |
| Essential tools | All available |

Registry fixes include unique Impacket alias endpoints, a real
`/api/tools/hashcat-utils` endpoint, and `vol` mapped to Volatility3.

## Deployment

`phantomstrike.sh start` launches the API server as a detached session when
`setsid` is available, then waits for `/ping`. `health` reports v3.3 runtime
status and respects bearer auth during its initial probe.

Latest verification:

```bash
phantomstrike-env/bin/python -m pytest -q
# 528 passed

./phantomstrike.sh start && ./phantomstrike.sh health && ./phantomstrike.sh stop
# healthy, version 3.3.0, clean shutdown
```
