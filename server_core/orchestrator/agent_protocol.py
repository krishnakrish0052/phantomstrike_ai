"""
Runtime contract for orchestrator-dispatched agents.

The orchestrator does not require every agent to share the same inheritance
tree. It requires a small dispatch interface: execute a mission phase with the
current shared context and return a result dictionary.
"""

from __future__ import annotations

import inspect
from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Protocol, TypeGuard, runtime_checkable


@runtime_checkable
class AgentProtocol(Protocol):
    """Minimal interface required by OrchestratorAgent."""

    def execute(self, phase: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        """Execute one mission phase and return a structured result."""
        ...


@dataclass(frozen=True)
class AgentContractIssue:
    """Describes why a registered agent does not satisfy AgentProtocol."""

    name: str
    reason: str


def is_agent_protocol(candidate: Any) -> TypeGuard[AgentProtocol]:
    """Return True when candidate exposes the orchestrator dispatch method."""

    return isinstance(candidate, AgentProtocol) and _execute_accepts_phase_context(candidate.execute)


def validate_agent_registry(agents: Mapping[str, Any]) -> List[AgentContractIssue]:
    """Validate an agent registry without executing any agent code."""

    issues: List[AgentContractIssue] = []
    for name, agent in agents.items():
        execute = getattr(agent, "execute", None)
        if not callable(execute):
            issues.append(AgentContractIssue(name, "missing callable execute(phase, context)"))
            continue
        if not _execute_accepts_phase_context(execute):
            issues.append(AgentContractIssue(name, "execute cannot be called with phase and context"))
    return issues


def _execute_accepts_phase_context(execute: Any) -> bool:
    try:
        signature = inspect.signature(execute)
        signature.bind({}, {})
        return True
    except (TypeError, ValueError):
        return False
