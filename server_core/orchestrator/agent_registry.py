"""
Central construction registry for the PhantomStrike orchestrator fleet.

The historical agent modules use two implementation styles: newer agents
inherit BaseAgent directly, while older agents expose the same execute()
contract without sharing the BaseAgent state model. This registry is the
single place that normalizes those implementations into BaseAgent-backed
runtime objects before the orchestrator dispatches work.
"""

from __future__ import annotations

from dataclasses import dataclass
import logging
from typing import Any, Callable, Dict, List

from server_core.orchestrator.agent_base import BaseAgent
from server_core.orchestrator.cleanup_agent import CleanupAgent
from server_core.orchestrator.exfil_agent import ExfilAgent
from server_core.orchestrator.exploit_agent import ExploitAgent
from server_core.orchestrator.post_exploit_agent import PostExploitAgent
from server_core.orchestrator.recon_agent import ReconAgent
from server_core.orchestrator.vuln_agent import VulnAgent

from server_core.orchestrator.attack_agents.privesc_agent import PrivescAgent
from server_core.orchestrator.attack_agents.cred_access_agent import CredAccessAgent
from server_core.orchestrator.attack_agents.persistence_agent import PersistenceAgent
from server_core.orchestrator.attack_agents.cloud_agent import CloudAgent
from server_core.orchestrator.attack_agents.lateral_move_agent import LateralMoveAgent
from server_core.orchestrator.attack_agents.webapp_agent import WebAppAgent

from server_core.orchestrator.defense_agents.emergency_agent import EmergencyAgent
from server_core.orchestrator.defense_agents.opsec_agent import OPSECAgent
from server_core.orchestrator.defense_agents.decoy_agent import DecoyAgent
from server_core.orchestrator.defense_agents.counter_surveillance import CounterSurveillanceAgent
from server_core.orchestrator.defense_agents.reverse_trace import ReverseTraceAgent
from server_core.orchestrator.defense_agents.trace_buster import TraceBusterAgent

from server_core.orchestrator.specialist_agents.supply_chain_agent import SupplyChainAgent
from server_core.orchestrator.specialist_agents.social_eng_agent import SocialEngineeringAgent
from server_core.orchestrator.specialist_agents.bug_bounty_agent import BugBountyAgent
from server_core.orchestrator.specialist_agents.auto_fixer_agent import AutoFixerAgent
from server_core.orchestrator.specialist_agents.reverse_engineering_agent import ReverseEngineeringAgent

from server_core.orchestrator.domain_agents.iot_agent import IoTAgent
from server_core.orchestrator.domain_agents.scada_agent import SCADAAgent
from server_core.orchestrator.domain_agents.automotive_agent import AutomotiveAgent
from server_core.orchestrator.domain_agents.satellite_agent import SatelliteAgent
from server_core.orchestrator.domain_agents.blockchain_agent import BlockchainAgent
from server_core.orchestrator.domain_agents.ai_exploit_agent import AIExploitAgent
from server_core.orchestrator.domain_agents.mobile_agent import MobileAgent
from server_core.orchestrator.domain_agents.telecom_agent import TelecomAgent
from server_core.orchestrator.domain_agents.physical_agent import PhysicalAgent
from server_core.orchestrator.domain_agents.darkweb_agent import DarkWebAgent
from server_core.orchestrator.domain_agents.drone_agent import DroneAgent
from server_core.orchestrator.domain_agents.nuclear_opsec_agent import NuclearOpsecAgent

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class AgentSpec:
    """Declarative entry for one orchestrator fleet member."""

    name: str
    factory: Callable[[], Any]


class BaseAgentRuntimeAdapter(BaseAgent):
    """BaseAgent facade for legacy agents that already implement execute().

    The adapter keeps the legacy implementation untouched while adding the
    BaseAgent lifecycle, status, capabilities, and common helper methods that
    newer agents already have.
    """

    def __init__(self, name: str, wrapped_agent: Any):
        self._wrapped_agent = wrapped_agent
        agent_type = _agent_type_for(name, wrapped_agent)
        super().__init__(
            agent_id=name,
            agent_type=agent_type,
            hive_mind=getattr(wrapped_agent, "hive_mind", None),
            tool_executor=_tool_executor_for(wrapped_agent),
            llm_client=getattr(wrapped_agent, "_llm", None) or getattr(wrapped_agent, "llm_client", None),
        )
        self.capabilities = _merge_capabilities(self.capabilities, wrapped_agent)

    @property
    def wrapped_agent(self) -> Any:
        return self._wrapped_agent

    def execute(self, phase: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        """Dispatch to the wrapped legacy agent while tracking BaseAgent state."""

        self.mark_started()
        result = self._wrapped_agent.execute(phase, context)
        if isinstance(result, dict) and result.get("success") is False:
            self._error_count += 1
            self._consecutive_errors += 1
        else:
            self._consecutive_errors = 0
        return result

    def think(self, objective: str, context: Dict[str, Any], history: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Prefer the wrapped agent's custom reasoning when it has one."""

        wrapped_think = getattr(self._wrapped_agent, "think", None)
        if callable(wrapped_think):
            return wrapped_think(objective, context, history)
        return super().think(objective, context, history)

    def report_status(self) -> Dict[str, Any]:
        status = super().report_status()
        status["wrapped_agent_class"] = self._wrapped_agent.__class__.__name__
        return status

    def __getattr__(self, name: str) -> Any:
        return getattr(self._wrapped_agent, name)


AGENT_SPECS: tuple[AgentSpec, ...] = (
    # Core mission phases
    AgentSpec("recon", ReconAgent),
    AgentSpec("vuln", VulnAgent),
    AgentSpec("exploit", ExploitAgent),
    AgentSpec("post_exploit", PostExploitAgent),
    AgentSpec("exfil", ExfilAgent),
    AgentSpec("cleanup", CleanupAgent),
    # Attack agents
    AgentSpec("privesc", lambda: PrivescAgent(agent_id="privesc")),
    AgentSpec("cred_access", lambda: CredAccessAgent(agent_id="cred_access")),
    AgentSpec("persistence", lambda: PersistenceAgent(agent_id="persistence")),
    AgentSpec("cloud", lambda: CloudAgent(agent_id="cloud")),
    AgentSpec("lateral_move", lambda: LateralMoveAgent(agent_id="lateral_move")),
    AgentSpec("webapp", lambda: WebAppAgent(agent_id="webapp")),
    # Defense agents
    AgentSpec("emergency", EmergencyAgent),
    AgentSpec("opsec", OPSECAgent),
    AgentSpec("decoy", DecoyAgent),
    AgentSpec("counter_surveillance", CounterSurveillanceAgent),
    AgentSpec("reverse_trace", ReverseTraceAgent),
    AgentSpec("trace_buster", TraceBusterAgent),
    # Specialist agents
    AgentSpec("supply_chain", SupplyChainAgent),
    AgentSpec("social_eng", SocialEngineeringAgent),
    AgentSpec("bug_bounty", BugBountyAgent),
    AgentSpec("auto_fixer", AutoFixerAgent),
    AgentSpec("reverse_engineering", ReverseEngineeringAgent),
    # Domain agents
    AgentSpec("iot", IoTAgent),
    AgentSpec("scada", SCADAAgent),
    AgentSpec("automotive", AutomotiveAgent),
    AgentSpec("satellite", SatelliteAgent),
    AgentSpec("blockchain", BlockchainAgent),
    AgentSpec("ai_exploit", AIExploitAgent),
    AgentSpec("mobile", MobileAgent),
    AgentSpec("telecom", TelecomAgent),
    AgentSpec("physical", PhysicalAgent),
    AgentSpec("darkweb", DarkWebAgent),
    AgentSpec("drone", DroneAgent),
    AgentSpec("nuclear_opsec", NuclearOpsecAgent),
)


def build_agent_registry() -> Dict[str, BaseAgent]:
    """Instantiate the full 35-agent fleet as BaseAgent-backed objects."""

    agents: Dict[str, BaseAgent] = {}
    for spec in AGENT_SPECS:
        raw_agent = spec.factory()
        agents[spec.name] = ensure_base_agent(spec.name, raw_agent)
    return agents


def ensure_base_agent(name: str, agent: Any) -> BaseAgent:
    """Return a BaseAgent instance, wrapping legacy agents when needed."""

    if isinstance(agent, BaseAgent):
        return agent
    logger.debug("Wrapping legacy agent %s (%s) with BaseAgentRuntimeAdapter", name, agent.__class__.__name__)
    return BaseAgentRuntimeAdapter(name, agent)


def _agent_type_for(name: str, agent: Any) -> str:
    return str(getattr(agent, "agent_type", getattr(agent, "AGENT_NAME", name)))


def _tool_executor_for(agent: Any) -> Any:
    return getattr(agent, "tool_bridge", None) or getattr(agent, "_tool_bridge", None)


def _merge_capabilities(base_capabilities: List[str], agent: Any) -> List[str]:
    capabilities = set(base_capabilities)
    for attr in ("TOOL_HANDLERS", "_tool_handlers"):
        handlers = getattr(agent, attr, None)
        if isinstance(handlers, dict):
            capabilities.update(str(name) for name in handlers.keys())
    return sorted(capabilities)
