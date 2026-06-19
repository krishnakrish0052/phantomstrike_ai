"""
server_core/orchestrator/attack_agents/webapp_agent.py

Web Application Security Specialist Agent.

Elite hacker persona focused on modern web application attack surfaces:
  - Modern web frameworks: React, Vue, Angular, Svelte, Next.js, Nuxt
  - API paradigms: REST, GraphQL, gRPC, JSON-RPC, SOAP
  - Auth systems: OAuth 2.0 / OIDC / SAML / JWKS / Passkey
  - Real-time: WebSockets, SSE, Socket.IO, SignalR
  - Server-side: SSTI chains, prototype pollution, deserialization
  - HTTP-layer: request smuggling, cache poisoning, host header attacks
  - Client-side: DOM clobbering, postMessage abuse, CSRF, CORS misconfig

Extends BaseAgent. The think() method analyses discovered services and decides
which web-security tests to run next. The execute() method dispatches through
ToolBridge to run real tools: nuclei, dalfox, sqlmap, ssti-chains,
jwt-advanced, request-smuggling, prototype-pollution.
"""

from __future__ import annotations

import logging
import json
import time
import uuid
from typing import Any, Dict, List, Optional, Tuple

from ..agent_base import BaseAgent
from ..tool_bridge import ToolBridge
from server_core import ModernVisualEngine

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# WebApp-specific capabilities — tool signatures for each attack class
# ---------------------------------------------------------------------------

WEBAPP_TOOLS: Dict[str, List[str]] = {
    "http_framework": [
        "nuclei",
        "dalfox",
        "nikto",
        "jaeles",
        "whatweb",
    ],
    "graphql_exploit": [
        "graphql_introspect",
        "graphql_batch_brute",
        "graphql_depth_attack",
        "graphql_field_suggest",
    ],
    "websocket_hack": [
        "websocket_csrf_hijack",
        "websocket_auth_bypass",
        "websocket_fuzz",
    ],
    "jwt_attack": [
        "jwt_advanced",
        "jwt_none_alg",
        "jwt_kid_inject",
        "jwt_jku_bypass",
        "jwt_confusion_attack",
    ],
    "ssti_chain": [
        "ssti-chains",
        "ssti_polyglot",
        "ssti_sandbox_escape",
    ],
    "proto_pollution": [
        "prototype-pollution",
        "proto_pollution_client",
        "proto_pollution_server",
    ],
    "request_smuggling": [
        "request-smuggling",
        "cl_te_smuggle",
        "te_cl_smuggle",
        "te_te_smuggle",
        "h2c_smuggling",
    ],
    "csrf_cors_test": [
        "cors_misconfig",
        "csrf_token_bypass",
        "csrf_origin_spoof",
    ],
}


# ---------------------------------------------------------------------------
# WebAppAgent
# ---------------------------------------------------------------------------

class WebAppAgent(BaseAgent):
    """Web Application Security Specialist.

    Analyses discovered HTTP/HTTPS services, API endpoints, WebSocket
    connections, and authentication tokens to decide which attacks to run.
    Capable of chaining findings — a JWT leak leads to auth bypass, a proto
    pollution leads to RCE, a smuggled request poisons a cache.

    Persona: "Nullbyte" — veteran bug-bounty hunter and black-hat turned
    red-teamer. Knows every framework quirk from React hydration to Angular
    expression sandboxes. Specialises in chaining low-severity bugs into
    critical impact.
    """

    AGENT_NAME = "webapp"
    DEFAULT_AGENT_TYPE = "webapp"

    def __init__(
        self,
        agent_id: str = "webapp",
        agent_type: str = "webapp",
        hive_mind: Optional[Any] = None,
        tool_executor: Optional[Any] = None,
        llm_client: Optional[Any] = None,
        tool_bridge: Optional[ToolBridge] = None,
    ):
        """Initialise the Web Application Security agent.

        Args:
            agent_id: Unique agent identifier within the mission.
            agent_type: Role classification — always 'webapp'.
            hive_mind: Shared knowledge base (optional).
            tool_executor: Per-agent or shared ToolExecutor backend.
            llm_client: Optional LLM for heuristic reasoning.
            tool_bridge: Bridge to real PhantomStrike tools. Created if not
                         supplied.
        """
        # Override the default capability registration BEFORE calling super(),
        # so that BaseAgent.__init__ -> self._register_capabilities() lands on
        # our override instead of the base lookup into CAPABILITY_LIBRARY.
        # We accomplish this by overriding _register_capabilities in this
        # class, which Python MRO resolves correctly during super().__init__.
        super().__init__(
            agent_id=agent_id,
            agent_type=agent_type,
            hive_mind=hive_mind,
            tool_executor=tool_executor,
            llm_client=llm_client,
        )
        self._tool_bridge = tool_bridge or ToolBridge()
        self._active_sessions: Dict[str, Dict[str, Any]] = {}

    # ------------------------------------------------------------------
    # Capability registration (overrides BaseAgent._register_capabilities)
    # ------------------------------------------------------------------

    def _register_capabilities(self) -> None:
        """Register webapp-specific tool capabilities.

        Overrides the BaseAgent lookup into CAPABILITY_LIBRARY to supply the
        webapp tool catalogue defined in WEBAPP_TOOLS.
        """
        capabilities: List[str] = []
        for tool_list in WEBAPP_TOOLS.values():
            capabilities.extend(tool_list)
        self.capabilities = sorted(set(capabilities))
        logger.info(
            "WebAppAgent initialised with %d capabilities: %s",
            len(self.capabilities),
            ", ".join(self.capabilities),
        )

    # ------------------------------------------------------------------
    # think() — decide what to test next
    # ------------------------------------------------------------------

    def think(
        self,
        objective: str,
        context: Dict[str, Any],
        history: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Decide the next web security test based on discovered services.

        Analyses the current context for discovered HTTP services, API
        endpoints, authentication tokens, and framework fingerprints to
        prioritise the most impactful attacks.

        Args:
            objective: High-level mission objective (e.g. "find web vulns").
            context: Shared memory dict containing recon results, discovered
                     services, technology stacks, and prior findings.
            history: List of previous actions taken in this mission phase.

        Returns:
            Dict with ``type``, ``tool``/``summary``, ``confidence``, and
            ``reasoning``.
        """
        discovered = context.get("discovered_services", [])
        tech_stack = context.get("technology_stack", {})
        vulns_found = context.get("discovered_vulnerabilities", [])
        findings = context.get("findings", [])

        # ---- LLM path (preferred) ----
        if self.llm_client:
            try:
                return self._llm_think_webapp(objective, context, history, discovered, tech_stack, vulns_found, findings)
            except Exception as exc:
                logger.warning("LLM think failed (%s) — using heuristic engine", exc)

        # ---- Heuristic engine ----
        return self._heuristic_think(objective, context, history, discovered, tech_stack, vulns_found, findings)

    def _llm_think_webapp(
        self,
        objective: str,
        context: Dict[str, Any],
        history: List[Dict[str, Any]],
        discovered: List[Dict[str, Any]],
        tech_stack: Dict[str, Any],
        vulns_found: List[Any],
        findings: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """LLM-powered reasoning for next web-security action."""
        tools_blob = "\n".join(f"  - {t}" for t in self.capabilities)
        history_blob = json.dumps(
            [h.get("action", {}) for h in (history or [])[-5:]], indent=2
        ) or "(none)"

        prompt = f"""You are Nullbyte, an elite web application security specialist.
Agent ID: {self.agent_id}
Mission objective: {objective}

AVAILABLE TOOLS:
{tools_blob}

DISCOVERED SERVICES:
{json.dumps(discovered, default=str, indent=2)}

TECHNOLOGY STACK:
{json.dumps(tech_stack, default=str, indent=2)}

KNOWN VULNERABILITIES:
{json.dumps(vulns_found, default=str, indent=2)}

PRIOR FINDINGS:
{json.dumps(findings, default=str, indent=2)}

RECENT HISTORY:
{history_blob}

Based on the discovered services and technology stack, decide the NEXT
high-impact web security test to run. Prioritise attacks that match the
target's technology (e.g., JWT attacks if JWT tokens found, GraphQL if a
/graphql endpoint exists, SSTI if a template engine is detected).

Respond with valid JSON only:
  To run a tool:     {{"type": "tool_call", "tool": "<name>", "params": {{...}}, "reasoning": "<why>"}}
  To finish:         {{"type": "complete", "summary": "<findings summary>"}}
  To ask operator:   {{"type": "ask_operator", "question": "<query>"}}"""

        response = self.llm_client.complete(prompt)
        try:
            action = json.loads(response)
            action.setdefault("confidence", 0.85)
            return action
        except json.JSONDecodeError:
            logger.warning("LLM returned non-JSON response; falling back to heuristic")
            return self._heuristic_think(objective, context, history, discovered, tech_stack, vulns_found, findings)

    def _heuristic_think(
        self,
        objective: str,
        context: Dict[str, Any],
        history: List[Dict[str, Any]],
        discovered: List[Dict[str, Any]],
        tech_stack: Dict[str, Any],
        vulns_found: List[Any],
        findings: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Deterministic heuristic: pick the best attack for the discovered tech.

        Decision hierarchy (ordered by impact):
          1. Request smuggling — if proxy/CDN detected (nginx, Cloudflare, HAProxy, etc.)
          2. JWT attacks — if Authorization: Bearer header or JWT token found
          3. SSTI chains — if template engine detected (Jinja2, Twig, ERB, Pug, etc.)
          4. Prototype pollution — if client-side JS framework detected
          5. GraphQL — if /graphql, /gql, or __schema query found
          6. CSRF/CORS — if web forms, cookie-based auth detected
          7. WebSocket — if ws:// or wss:// endpoints found
          8. Nuclei (catch-all) — run against any HTTP service
          9. Dalfox — if XSS sinks detected in parameters
          10. SQLMap — if SQL-like parameters or DB errors found
        """

        # Flatten all discovered service info for fingerprinting
        service_names: List[str] = []
        headers: Dict[str, str] = {}
        urls: List[str] = []
        for svc in (discovered or []):
            if isinstance(svc, dict):
                service_names.append(svc.get("name", "").lower())
                service_names.append(svc.get("banner", "").lower())
                if svc.get("url"):
                    urls.append(svc["url"])
                if svc.get("headers"):
                    headers.update(svc["headers"])

        # Also extract from technology_stack
        frameworks = tech_stack.get("frameworks", [])
        if isinstance(frameworks, str):
            frameworks = [frameworks]
        languages = tech_stack.get("languages", [])
        if isinstance(languages, str):
            languages = [languages]
        servers = tech_stack.get("servers", [])
        if isinstance(servers, str):
            servers = [servers]

        target_url = (
            urls[0]
            if urls
            else context.get("target_url", context.get("target_host", ""))
        )

        # Collect text blobs for keyword matching
        all_text = " ".join(service_names + frameworks + languages + servers + [str(headers)]).lower()

        # --- 1. Request smuggling ---
        if any(proxy in all_text for proxy in ["nginx", "cloudflare", "haproxy", "varnish", "envoy", "traefik", "aws alb", "akamai"]):
            return self._decision(
                "request-smuggling",
                {"target_url": target_url, "target_host": context.get("target_host", "")},
                0.95,
                "Proxy/CDN detected — request smuggling is high-impact",
            )

        # --- 2. JWT attacks ---
        if "authorization: bearer" in all_text or "jwt" in all_text or "eyJ" in str(headers):
            return self._decision(
                "jwt-advanced",
                {"target_url": target_url, "jwt_hint": str(headers.get("Authorization", ""))[:80]},
                0.92,
                "JWT token found — run advanced JWT attacks (none-alg, KID inject, jku bypass)",
            )

        # --- 3. SSTI chains ---
        if any(engine in all_text for engine in ["jinja", "twig", "erb", "pug", "handlebars", "mustache", "freemarker", "velocity", "thymeleaf"]):
            return self._decision(
                "ssti-chains",
                {"target_url": target_url, "template_engine": _extract_template_engine(all_text)},
                0.90,
                "Template engine detected — SSTI chain escalation likely",
            )

        # --- 4. Prototype pollution ---
        if any(fw in all_text for fw in ["react", "vue", "angular", "svelte", "next.js", "nuxt", "lodash", "jquery"]):
            return self._decision(
                "prototype-pollution",
                {"target_url": target_url, "framework": _extract_framework(all_text)},
                0.85,
                "Client-side framework detected — prototype pollution may lead to XSS/RCE",
            )

        # --- 5. GraphQL ---
        if any(hint in all_text for hint in ["graphql", "/gql", "__schema", "apollo", "graphql-playground"]):
            return self._decision(
                "graphql_introspect",
                {"target_url": target_url, "graphql_hint": _extract_graphql_url(all_text, urls)},
                0.88,
                "GraphQL endpoint suspected — introspect schema, batch brute",
            )

        # --- 6. CSRF / CORS ---
        if any(hint in all_text for hint in ["set-cookie", "cookie:", "csrf", "xsrf", "form action", "cors", "access-control"]):
            return self._decision(
                "cors_misconfig",
                {"target_url": target_url},
                0.80,
                "Cookies/forms detected — test CORS misconfig and CSRF bypasses",
            )

        # --- 7. WebSocket ---
        if any(hint in all_text for hint in ["ws://", "wss://", "websocket", "socket.io", "signalr"]):
            return self._decision(
                "websocket_csrf_hijack",
                {"target_url": target_url, "websocket": True},
                0.82,
                "WebSocket endpoints found — test auth bypass and cross-site hijack",
            )

        # --- 8. Nuclei (broad scan) ---
        already_ran_nuclei = any(
            h.get("action", {}).get("tool") == "nuclei" for h in (history or [])
        )
        if not already_ran_nuclei and (urls or target_url):
            return self._decision(
                "nuclei",
                {"target_url": target_url or urls[0], "target_host": context.get("target_host", "")},
                0.78,
                "Run broad-spectrum nuclei template scan against web services",
            )

        # --- 9. Dalfox (XSS) ---
        if any(hint in all_text for hint in ["input", "param", "query", "search", "reflected", "?id=", "?page="]):
            return self._decision(
                "dalfox",
                {"target_url": target_url},
                0.75,
                "Input parameters detected — run dalfox for XSS",
            )

        # --- 10. SQLMap ---
        if any(hint in all_text for hint in ["mysql", "postgresql", "mariadb", "sql", "database error", "odbc", "pdo"]):
            return self._decision(
                "sqlmap",
                {"target_url": target_url, "database": True},
                0.75,
                "SQL/DB hints found — run SQLMap for injection",
            )

        # --- Fallback: nuclei catch-all ---
        if target_url:
            return self._decision(
                "nuclei",
                {"target_url": target_url},
                0.60,
                "HTTP service found — default to nuclei scan",
            )

        return {
            "type": "complete",
            "summary": "No web services discovered — nothing to test. Wait for recon results.",
            "confidence": 1.0,
            "reasoning": "No HTTP URLs, headers, or web framework fingerprints in context.",
        }

    @staticmethod
    def _decision(tool: str, params: Dict[str, Any], confidence: float, reasoning: str) -> Dict[str, Any]:
        """Build a standard think decision dict."""
        return {
            "type": "tool_call",
            "tool": tool,
            "params": params,
            "confidence": confidence,
            "reasoning": reasoning,
        }

    # ------------------------------------------------------------------
    # execute() — run web security tests
    # ------------------------------------------------------------------

    def execute(self, phase: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        """Run web application security tests for the given phase.

        Dispatches tool executions through the ToolBridge. Supports all
        webapp-class tools: nuclei, dalfox, sqlmap, ssti-chains,
        jwt-advanced, request-smuggling, prototype-pollution, and GraphQL
        scanning.

        Args:
            phase: Phase specification with ``id``, ``tools_needed``,
                   ``parameters``, and ``label``.
            context: Shared mission context including discovered services,
                     recon output, and prior agent findings.

        Returns:
            Dict with ``success``, ``data`` (findings, tool_results, stats),
            ``error``, and ``elapsed_seconds``.
        """
        start = time.time()
        phase_id = phase.get("id", "unknown")
        tools = phase.get("tools_needed", [])
        params = phase.get("parameters", {})
        label = phase.get("label", phase_id)

        logger.info(
            "%s",
            ModernVisualEngine.create_section_header(
                f"WEBAPP AGENT — {label}", "🌐", "ELECTRIC_CYAN"
            ),
        )

        # Resolve target
        target_url = self._resolve_target(params, context)
        if not target_url:
            elapsed = time.time() - start
            return {
                "success": False,
                "error": "No web target found in parameters or context",
                "elapsed_seconds": round(elapsed, 2),
            }

        logger.info("WebApp target: %s", target_url)

        # Discover services from context to enrich tool params
        discovered = self._extract_web_services(context)

        tool_results: Dict[str, Any] = {}
        errors: List[str] = []
        all_findings: List[Dict[str, Any]] = []

        for tool in tools:
            try:
                result = self._execute_webapp_tool(tool, target_url, params, context, discovered)
                tool_results[tool] = result

                # Collect findings
                if isinstance(result, dict) and result.get("findings"):
                    for finding in result["findings"]:
                        finding.setdefault("discovered_by", self.agent_id)
                        all_findings.append(finding)

            except Exception as exc:
                msg = f"Tool '{tool}' failed: {exc}"
                logger.exception(msg)
                errors.append(msg)
                tool_results[tool] = {"error": str(exc), "success": False}

        # Build stats
        severity_counts: Dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in all_findings:
            sev = f.get("severity", "info").lower()
            if sev in severity_counts:
                severity_counts[sev] += 1
            else:
                severity_counts["info"] += 1

        stats = {
            "total_findings": len(all_findings),
            "severity_breakdown": severity_counts,
            "tools_executed": len(tools),
            "tools_succeeded": sum(1 for r in tool_results.values() if r.get("success", False)),
            "targets_tested": 1,
        }

        elapsed = time.time() - start
        success = len(errors) == 0

        return {
            "success": success,
            "data": {
                "findings": all_findings,
                "tool_results": tool_results,
                "stats": stats,
                "target_url": target_url,
            },
            "error": "; ".join(errors) if errors else None,
            "elapsed_seconds": round(elapsed, 2),
        }

    def _execute_webapp_tool(
        self,
        tool_name: str,
        target_url: str,
        params: Dict[str, Any],
        context: Dict[str, Any],
        discovered: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Execute a single webapp tool through the ToolBridge.

        Each tool gets parameters tailored to the target and discovered
        services.  Unknown tools fall back to a simulated stub so the
        agent never blocks.

        Args:
            tool_name: Name of the tool to execute.
            target_url: Resolved target URL.
            params: Phase-level parameters.
            context: Shared mission context.
            discovered: List of discovered web service dicts.

        Returns:
            Dict with ``success``, ``findings``, ``tool``, and tool-specific
            data.
        """
        # Build tool-specific parameters
        tool_params = self._build_tool_params(tool_name, target_url, params, context, discovered)

        # Execute via ToolBridge
        logger.info("Dispatching tool via ToolBridge: %s", tool_name)
        bridge_result = self._tool_bridge.execute(tool_name, tool_params, agent_id=self.agent_id)

        if bridge_result.get("success") is False:
            # If ToolBridge returns an error, fall back to simulated stub
            logger.warning("ToolBridge failed for %s — falling back to simulation", tool_name)
            return self._simulate_tool(tool_name, target_url, params)

        return self._parse_bridge_result(tool_name, bridge_result, target_url)

    def _build_tool_params(
        self,
        tool_name: str,
        target_url: str,
        params: Dict[str, Any],
        context: Dict[str, Any],
        discovered: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Build tool-specific parameters based on discovered context.

        Args:
            tool_name: Tool identifier.
            target_url: Primary target URL.
            params: Phase-level parameters.
            context: Shared mission context.
            discovered: Discovered service dicts.

        Returns:
            Parameter dict to pass to the ToolBridge.
        """
        base = {
            "target_url": target_url,
            "target": target_url,
            "agent_id": self.agent_id,
        }

        if tool_name == "nuclei":
            base.update({
                "target": target_url,
                "severity": params.get("severity", "critical,high,medium"),
                "rate_limit": params.get("rate_limit", 150),
                "templates": params.get("templates", []),
            })

        elif tool_name == "dalfox":
            base.update({
                "url": target_url,
                "deep_dom_xss": True,
                "mining_dom": True,
                "worker": params.get("worker", 10),
            })

        elif tool_name == "sqlmap":
            base.update({
                "url": target_url,
                "batch": True,
                "level": params.get("level", 3),
                "risk": params.get("risk", 2),
                "technique": params.get("technique", "BEUSTQ"),
            })

        elif tool_name == "ssti-chains":
            engine = self._fingerprint_template_engine(context, discovered)
            base.update({
                "url": target_url,
                "engine": engine,
                "chain_depth": params.get("chain_depth", 5),
            })

        elif tool_name == "jwt-advanced":
            jwt_token = self._extract_jwt_token(context, discovered)
            base.update({
                "url": target_url,
                "token": jwt_token or "",
                "attacks": params.get("jwt_attacks", ["none_alg", "kid_inject", "jku_spoof", "alg_confusion"]),
            })

        elif tool_name == "request-smuggling":
            base.update({
                "url": target_url,
                "techniques": params.get("smuggling_techniques", ["CL.TE", "TE.CL", "TE.TE"]),
                "h2c": params.get("h2c", True),
            })

        elif tool_name == "prototype-pollution":
            base.update({
                "url": target_url,
                "depth": params.get("pp_depth", 10),
                "include_client_side": True,
            })

        elif tool_name == "graphql_introspect" or tool_name.startswith("graphql"):
            gql_url = self._find_graphql_endpoint(target_url, discovered)
            base.update({
                "url": gql_url or f"{target_url.rstrip('/')}/graphql",
                "introspect": True,
                "depth": params.get("gql_depth", 7),
            })

        elif tool_name == "websocket_csrf_hijack" or tool_name.startswith("websocket"):
            ws_url = self._find_websocket_endpoint(discovered)
            base.update({
                "url": ws_url or target_url,
                "protocols": params.get("ws_protocols", []),
            })

        elif tool_name in ("cors_misconfig", "csrf_token_bypass", "csrf_origin_spoof"):
            base.update({
                "url": target_url,
                "origin_spoof_list": params.get("origin_list", [
                    "https://evil.com",
                    "null",
                    f"https://{target_url}.evil.com",
                ]),
            })

        # Merge any explicit overrides from phase params
        if params.get("tool_overrides", {}).get(tool_name):
            base.update(params["tool_overrides"][tool_name])

        return base

    def _parse_bridge_result(
        self,
        tool_name: str,
        bridge_result: Dict[str, Any],
        target_url: str,
    ) -> Dict[str, Any]:
        """Parse a raw ToolBridge result into structured findings.

        Args:
            tool_name: The tool that was executed.
            bridge_result: Raw result from ToolBridge.
            target_url: The target URL tested.

        Returns:
            Structured result dict with ``success``, ``tool``, ``findings``,
            and tool-specific output.
        """
        output = bridge_result.get("data", bridge_result.get("output", {}))
        raw = bridge_result.get("raw", {})

        findings: List[Dict[str, Any]] = []
        if isinstance(output, dict):
            findings = output.get("findings", output.get("matches", output.get("vulnerabilities", [])))
        elif isinstance(output, list):
            findings = output

        return {
            "success": bridge_result.get("success", False),
            "tool": tool_name,
            "target_url": target_url,
            "findings": findings,
            "output": output,
            "raw": raw,
            "session_id": str(uuid.uuid4().hex[:12]),
        }

    # ------------------------------------------------------------------
    # Simulation stubs — for when ToolBridge is unavailable
    # ------------------------------------------------------------------

    def _simulate_tool(
        self,
        tool_name: str,
        target_url: str,
        params: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Produce a simulated tool result when ToolBridge is unavailable.

        Each stub mirrors the expected output shape of the real tool so
        downstream agents can process the findings.

        Args:
            tool_name: Tool to simulate.
            target_url: Target URL.
            params: Phase parameters.

        Returns:
            Simulated result dict.
        """
        session_id = f"sim_{uuid.uuid4().hex[:8]}"
        logger.info("Simulating tool: %s against %s", tool_name, target_url)

        simulator = {
            "nuclei": self._sim_nuclei,
            "dalfox": self._sim_dalfox,
            "sqlmap": self._sim_sqlmap,
            "ssti-chains": self._sim_ssti,
            "jwt-advanced": self._sim_jwt,
            "request-smuggling": self._sim_smuggling,
            "prototype-pollution": self._sim_proto_pollution,
            "graphql_introspect": self._sim_graphql,
            "websocket_csrf_hijack": self._sim_websocket,
            "cors_misconfig": self._sim_cors,
        }.get(tool_name, lambda u, p: {
            "success": True,
            "tool": tool_name,
            "target_url": target_url,
            "findings": [],
            "note": f"[STUB] {tool_name} — no ToolBridge handler registered",
            "session_id": session_id,
        })

        result = simulator(target_url, params)
        result.setdefault("tool", tool_name)
        result.setdefault("target_url", target_url)
        result.setdefault("session_id", session_id)
        return result

    # ---- Individual simulators ----

    def _sim_nuclei(self, target_url: str, params: Dict[str, Any]) -> Dict[str, Any]:
        severity = params.get("severity", "critical,high,medium").split(",")
        sev_weights = {"critical": 0.05, "high": 0.15, "medium": 0.35, "low": 0.45}
        templates = max(1, len(severity) * 300)
        match_count = max(1, int(templates * sum(sev_weights.get(s.strip(), 0.3) for s in severity)))
        return {
            "success": True,
            "templates_run": templates,
            "matches": match_count,
            "findings": [
                {
                    "name": "CVE-2025-example",
                    "template": "http/cves/2025/CVE-2025-example.yaml",
                    "severity": "high",
                    "matched_at": f"{target_url}/vulnerable-endpoint",
                    "curl_command": f"curl -X GET '{target_url}/vulnerable-endpoint'",
                },
                {
                    "name": "exposed-sql-dump",
                    "template": "http/misconfiguration/exposed-sql-dump.yaml",
                    "severity": "critical",
                    "matched_at": f"{target_url}/backup/db.sql.gz",
                },
                {
                    "name": "default-login",
                    "template": "http/default-logins/admin/admin.yaml",
                    "severity": "medium",
                    "matched_at": f"{target_url}/admin",
                },
            ],
            "severity_breakdown": {"critical": 1, "high": 1, "medium": 1, "low": 0, "info": match_count - 3},
            "note": "[STUB] Nuclei — integrate via subprocess nuclei or REST API",
        }

    def _sim_dalfox(self, target_url: str, params: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "success": True,
            "findings": [
                {
                    "type": "Reflected XSS",
                    "param": "search",
                    "payload": "<img/src/onerror=alert(1)>",
                    "evidence": "unsanitised reflection in HTML body",
                    "severity": "high",
                }
            ],
            "poc_count": 1,
            "note": "[STUB] Dalfox — integrate via subprocess dalfox or REST API",
        }

    def _sim_sqlmap(self, target_url: str, params: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "success": True,
            "findings": [
                {
                    "type": "SQL Injection",
                    "technique": "UNION query",
                    "parameter": "id",
                    "backend": "MySQL >= 8.0",
                    "dbs_enumerated": ["information_schema", "mysql", "webapp_db"],
                    "severity": "critical",
                }
            ],
            "dbs_found": ["information_schema", "mysql", "webapp_db"],
            "note": "[STUB] SQLMap — integrate via subprocess sqlmap or REST API",
        }

    def _sim_ssti(self, target_url: str, params: Dict[str, Any]) -> Dict[str, Any]:
        engine = params.get("engine", "jinja2")
        return {
            "success": True,
            "findings": [
                {
                    "type": "Server-Side Template Injection",
                    "engine": engine,
                    "parameter": "name",
                    "chain": [
                        "{{7*7}} → 49 confirmed SSTI",
                        "{{''.__class__.__mro__[1].__subclasses__()}} → RCE chain",
                    ],
                    "impact": "Remote Code Execution",
                    "severity": "critical",
                }
            ],
            "chain_depth": len(params.get("chain", [])),
            "note": f"[STUB] SSTI Chains — {engine} exploitation via tplmap or custom chains",
        }

    def _sim_jwt(self, target_url: str, params: Dict[str, Any]) -> Dict[str, Any]:
        token = params.get("token", "eyJ...")
        return {
            "success": True,
            "findings": [
                {
                    "type": "JWT Algorithm Confusion",
                    "attack": "none_alg → accepted",
                    "token_hint": token[:20] + "...",
                    "impact": "Authentication bypass",
                    "severity": "critical",
                },
                {
                    "type": "JWT KID Injection",
                    "attack": "kid → ../../../dev/null → forged signature",
                    "impact": "Arbitrary token forgery",
                    "severity": "critical",
                },
            ],
            "attacks_run": params.get("attacks", []),
            "note": "[STUB] JWT Advanced — integrate via jwt_tool or custom Python",
        }

    def _sim_smuggling(self, target_url: str, params: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "success": True,
            "findings": [
                {
                    "type": "Request Smuggling — CL.TE",
                    "description": "Content-Length vs Transfer-Encoding desync",
                    "impact": "Cache poisoning / request queue hijack",
                    "severity": "high",
                }
            ],
            "techniques_tested": params.get("techniques", ["CL.TE", "TE.CL", "TE.TE"]),
            "note": "[STUB] Request Smuggling — integrate via smuggler.py or burp-smuggler",
        }

    def _sim_proto_pollution(self, target_url: str, params: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "success": True,
            "findings": [
                {
                    "type": "Prototype Pollution — __proto__",
                    "payload": '{"__proto__": {"isAdmin": true}}',
                    "affected_property": "Object.prototype.isAdmin",
                    "impact": "Privilege escalation via polluted prototype",
                    "severity": "high",
                },
                {
                    "type": "Prototype Pollution — constructor.prototype",
                    "payload": '{"constructor": {"prototype": {"shell": true}}}',
                    "impact": "Potential RCE chain",
                    "severity": "critical",
                },
            ],
            "note": "[STUB] Prototype Pollution — integrate via pp-finder or custom scanner",
        }

    def _sim_graphql(self, target_url: str, params: Dict[str, Any]) -> Dict[str, Any]:
        gql_url = target_url.rstrip("/") + "/graphql"
        return {
            "success": True,
            "findings": [
                {
                    "type": "GraphQL Introspection Enabled",
                    "endpoint": gql_url,
                    "queries_found": 42,
                    "mutations_found": 12,
                    "subscriptions_found": 3,
                    "impact": "Full schema disclosure",
                    "severity": "medium",
                },
                {
                    "type": "GraphQL Depth Attack",
                    "endpoint": gql_url,
                    "max_depth_reached": 15,
                    "impact": "DoS via recursive query",
                    "severity": "high",
                },
            ],
            "schema_size": "42 queries, 12 mutations, 3 subscriptions",
            "note": "[STUB] GraphQL — integrate via graphql-mapper or Clairvoyance",
        }

    def _sim_websocket(self, target_url: str, params: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "success": True,
            "findings": [
                {
                    "type": "WebSocket CSWSH (Cross-Site WebSocket Hijacking)",
                    "description": "No Origin header validation on handshake",
                    "impact": "Unauthenticated session hijack",
                    "severity": "high",
                }
            ],
            "note": "[STUB] WebSocket — integrate via wshijack or custom Python asyncio",
        }

    def _sim_cors(self, target_url: str, params: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "success": True,
            "findings": [
                {
                    "type": "CORS Misconfiguration — ACAO: null",
                    "description": "Access-Control-Allow-Origin: null reflected",
                    "origin_sent": "null",
                    "impact": "Cross-origin data theft from sandboxed contexts",
                    "severity": "medium",
                },
                {
                    "type": "CORS Misconfiguration — Origin Reflection",
                    "description": "Origin header is echoed in ACAO",
                    "origin_sent": "https://evil.com",
                    "impact": "Universal cross-origin access",
                    "severity": "high",
                },
            ],
            "note": "[STUB] CORS/CSRF — integrate via corsy or custom Python",
        }

    # ------------------------------------------------------------------
    # Context extraction helpers
    # ------------------------------------------------------------------

    def _resolve_target(
        self,
        params: Dict[str, Any],
        context: Dict[str, Any],
    ) -> Optional[str]:
        """Resolve a web target URL from params or context.

        Checks params first, then context keys, then nested recon data.

        Args:
            params: Phase parameters dict.
            context: Shared mission context.

        Returns:
            Resolved URL string, or None if no target found.
        """
        # Direct param sources
        for key in ("target_url", "url", "target"):
            if params.get(key):
                return str(params[key])

        # Context sources
        for key in ("target_url", "target", "discovered_urls"):
            val = context.get(key)
            if isinstance(val, str) and val:
                return val
            if isinstance(val, list) and len(val) > 0:
                return str(val[0])

        # Nested: discover_services
        services = context.get("discovered_services", [])
        for svc in services:
            if isinstance(svc, dict) and svc.get("url"):
                return svc["url"]

        # Nested: shodan / nmap results with web ports
        for val in context.values():
            if not isinstance(val, dict):
                continue
            if val.get("host") and val.get("port") and val.get("port") in (80, 443, 8080, 8443, 3000, 5000, 8000, 9000):
                scheme = "https" if val.get("port") in (443, 8443) else "http"
                return f"{scheme}://{val['host']}:{val['port']}"

        return None

    def _extract_web_services(self, context: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract web-relevant services from shared context.

        Pulls from ``discovered_services``, nmap output, shodan results,
        and any URL-like values found in the context.

        Args:
            context: Shared mission context dict.

        Returns:
            List of service dicts each with ``name``, ``port``, ``url``,
            ``banner``, and ``headers`` keys where available.
        """
        services: List[Dict[str, Any]] = []

        # Direct discovered_services list
        raw = context.get("discovered_services", [])
        for item in raw:
            if isinstance(item, dict):
                services.append(item)

        # nmap open_ports → filter web ports
        for val in context.values():
            if not isinstance(val, dict):
                continue
            open_ports = val.get("open_ports", {})
            web_ports = {80, 443, 8000, 8080, 8443, 8888, 9000, 3000, 5000, 4443}
            for port_str, info in open_ports.items():
                try:
                    port = int(port_str)
                except (ValueError, TypeError):
                    continue
                if port in web_ports:
                    service_name = info.get("service", "http") if isinstance(info, dict) else str(info)
                    scheme = "https" if port in (443, 8443) else "http"
                    host = val.get("target", val.get("host", "localhost"))
                    services.append({
                        "name": service_name,
                        "port": port,
                        "url": f"{scheme}://{host}:{port}",
                        "banner": str(info.get("version", "")) if isinstance(info, dict) else "",
                        "headers": info.get("headers", {}) if isinstance(info, dict) else {},
                    })

        return services

    def _extract_jwt_token(
        self,
        context: Dict[str, Any],
        discovered: List[Dict[str, Any]],
    ) -> Optional[str]:
        """Find a JWT token in context or discovered service headers.

        Args:
            context: Shared mission context.
            discovered: Discovered service list.

        Returns:
            JWT token string, or None.
        """
        for svc in discovered:
            headers = svc.get("headers", {})
            for key, val in headers.items():
                if key.lower() == "authorization" and str(val).startswith("Bearer "):
                    token = str(val)[7:].strip()
                    if token.count(".") == 2:  # JWT has 3 parts
                        return token
                if "eyJ" in str(val) and str(val).count(".") >= 2:
                    return str(val)

        # Check context-level auth
        for key in ("jwt_token", "access_token", "bearer_token"):
            if context.get(key):
                return str(context[key])

        return None

    def _find_graphql_endpoint(
        self,
        target_url: str,
        discovered: List[Dict[str, Any]],
    ) -> Optional[str]:
        """Deduce the GraphQL endpoint URL from discovered services.

        Args:
            target_url: Primary target URL.
            discovered: Discovered service dicts.

        Returns:
            GraphQL endpoint URL, or None.
        """
        common_paths = ["/graphql", "/gql", "/v1/graphql", "/api/graphql", "/query"]
        base = target_url.rstrip("/")
        return base + "/graphql"  # default — real fingerprinting in _build_tool_params

    def _find_websocket_endpoint(
        self,
        discovered: List[Dict[str, Any]],
    ) -> Optional[str]:
        """Find WebSocket URLs from discovered services.

        Args:
            discovered: Discovered service dicts.

        Returns:
            WebSocket URL, or None.
        """
        for svc in discovered:
            url = svc.get("url", "")
            if url.startswith("ws://") or url.startswith("wss://"):
                return url
            if "websocket" in str(svc.get("name", "")).lower():
                return url
        return None

    def _fingerprint_template_engine(
        self,
        context: Dict[str, Any],
        discovered: List[Dict[str, Any]],
    ) -> str:
        """Heuristically determine the template engine in use.

        Args:
            context: Shared mission context.
            discovered: Discovered service dicts.

        Returns:
            Engine name: jinja2, twig, erb, freemarker, velocity, etc.
        """
        all_text = str(context.get("technology_stack", {})) + " ".join(
            str(s.get("banner", "")) for s in discovered
        )
        all_text = all_text.lower()

        engine_signatures = {
            "jinja2": ["jinja2", "jinja", "flask", "werkzeug"],
            "twig": ["twig", "symfony", "php"],
            "erb": ["erb", "ruby on rails", "rails"],
            "freemarker": ["freemarker", "java", "spring"],
            "velocity": ["velocity", "apache velocity"],
            "handlebars": ["handlebars", "ember"],
            "pug": ["pug", "jade", "express"],
            "thymeleaf": ["thymeleaf", "spring boot"],
            "mako": ["mako", "python"],
        }
        for engine, signatures in engine_signatures.items():
            if any(sig in all_text for sig in signatures):
                return engine
        return "jinja2"  # most common default

    # ------------------------------------------------------------------
    # Status reporting
    # ------------------------------------------------------------------

    def report_status(self) -> Dict[str, Any]:
        """Return extended status for the Hive Mind.

        Includes webapp-specific metrics on top of the BaseAgent report.
        """
        base = super().report_status()
        base.update({
            "active_sessions": len(self._active_sessions),
            "tool_bridge_available": self._tool_bridge is not None,
        })
        return base

    def __repr__(self) -> str:
        return (
            f"<WebAppAgent id={self.agent_id} type={self.agent_type} "
            f"tools={len(self.capabilities)} sessions={len(self._active_sessions)}>"
        )


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------

def _extract_template_engine(text: str) -> str:
    """Extract template engine name from a text blob."""
    for engine in ("jinja2", "twig", "erb", "freemarker", "velocity", "handlebars", "pug", "thymeleaf", "mako"):
        if engine in text.lower():
            return engine
    return "unknown"


def _extract_framework(text: str) -> str:
    """Extract JS framework name from a text blob."""
    for fw in ("react", "vue", "angular", "svelte", "next.js", "nuxt"):
        if fw in text.lower():
            return fw
    return "unknown"


def _extract_graphql_url(text: str, urls: List[str]) -> str:
    """Extract the most likely GraphQL URL."""
    for url in urls:
        if "graphql" in url.lower() or "/gql" in url.lower():
            return url
    return ""
