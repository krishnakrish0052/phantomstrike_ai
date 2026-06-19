from server_core.llm_client import LLMClient, OllamaBackend


def test_llm_client_initializes_backend_without_warmup_flag(monkeypatch):
    monkeypatch.delenv("PHANTOMSTRIKE_LLM_WARMUP", raising=False)
    monkeypatch.setenv("PHANTOMSTRIKE_LLM_PROVIDER", "ollama")
    monkeypatch.setenv("PHANTOMSTRIKE_LLM_MODEL", "phantomstrike-ai")
    monkeypatch.setenv("PHANTOMSTRIKE_LLM_URL", "http://localhost:11434")
    monkeypatch.setenv("PHANTOMSTRIKE_LLM_TIMEOUT", "1")

    client = LLMClient()

    assert client.provider == "ollama"
    assert client.model == "phantomstrike-ai"
    assert isinstance(client._backend, OllamaBackend)


def test_orchestrator_singleton_factory_imports_real_orchestrator():
    from server_core.singletons import _get_orchestrator_agent
    from server_core.orchestrator.agent_base import BaseAgent
    from server_core.orchestrator import OrchestratorAgent

    agent = _get_orchestrator_agent()

    assert isinstance(agent, OrchestratorAgent)
    assert len(agent.agents) == 35
    assert {"recon", "privesc", "cloud", "nuclear_opsec"}.issubset(agent.agents)
    assert all(isinstance(registered, BaseAgent) for registered in agent.agents.values())


def test_agent_registry_builds_baseagent_backed_fleet():
    from server_core.orchestrator.agent_base import BaseAgent
    from server_core.orchestrator.agent_registry import AGENT_SPECS, BaseAgentRuntimeAdapter, build_agent_registry

    agents = build_agent_registry()

    assert len(AGENT_SPECS) == 35
    assert len(agents) == 35
    assert all(isinstance(agent, BaseAgent) for agent in agents.values())
    assert any(isinstance(agent, BaseAgentRuntimeAdapter) for agent in agents.values())
    assert all(agent.report_status()["agent_type"] for agent in agents.values())
    assert all(agent.get_tools() for agent in agents.values())
