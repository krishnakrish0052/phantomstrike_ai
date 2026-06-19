from .orchestrator_agent import OrchestratorAgent
from .task_decomposer import TaskDecomposer
from .agent_memory import AgentMemory
from .mission_tracker import MissionTracker
from .universal_goal_engine import UniversalGoalEngine, EGATSEngine
from .attack_synthesizer import AttackSynthesizer
from .polymorphic_malware import PolymorphicMalwareForge, create_forge

# ── Core phase agents ──
from .recon_agent import ReconAgent
from .vuln_agent import VulnAgent
from .exploit_agent import ExploitAgent
from .post_exploit_agent import PostExploitAgent
from .exfil_agent import ExfilAgent
from .cleanup_agent import CleanupAgent

# ── Attack agents ──
from .attack_agents.privesc_agent import PrivescAgent
from .attack_agents.cred_access_agent import CredAccessAgent
from .attack_agents.persistence_agent import PersistenceAgent
from .attack_agents.cloud_agent import CloudAgent
from .attack_agents.lateral_move_agent import LateralMoveAgent
from .attack_agents.webapp_agent import WebAppAgent

# ── Defense agents ──
from .defense_agents.emergency_agent import EmergencyAgent
from .defense_agents.opsec_agent import OPSECAgent
from .defense_agents.decoy_agent import DecoyAgent
from .defense_agents.counter_surveillance import CounterSurveillanceAgent
from .defense_agents.reverse_trace import ReverseTraceAgent
from .defense_agents.trace_buster import TraceBusterAgent

# ── Specialist agents ──
from .specialist_agents.supply_chain_agent import SupplyChainAgent
from .specialist_agents.social_eng_agent import SocialEngineeringAgent
from .specialist_agents.bug_bounty_agent import BugBountyAgent
from .specialist_agents.auto_fixer_agent import AutoFixerAgent
from .specialist_agents.reverse_engineering_agent import ReverseEngineeringAgent

# ── Domain agents (v3.2+) ──
from .domain_agents.iot_agent import IoTAgent
from .domain_agents.scada_agent import SCADAAgent
from .domain_agents.automotive_agent import AutomotiveAgent
from .domain_agents.satellite_agent import SatelliteAgent
from .domain_agents.blockchain_agent import BlockchainAgent
from .domain_agents.ai_exploit_agent import AIExploitAgent
from .domain_agents.mobile_agent import MobileAgent
from .domain_agents.telecom_agent import TelecomAgent
from .domain_agents.physical_agent import PhysicalAgent
from .domain_agents.darkweb_agent import DarkWebAgent
from .domain_agents.drone_agent import DroneAgent
from .domain_agents.nuclear_opsec_agent import NuclearOpsecAgent

from .zero_day_hunter import ZeroDayHunter, create_zero_day_hunter

__all__ = [
    "OrchestratorAgent",
    "TaskDecomposer",
    "AgentMemory",
    "MissionTracker",
    "UniversalGoalEngine",
    "EGATSEngine",
    "AttackSynthesizer",
    "PolymorphicMalwareForge",
    "create_forge",
    # Core
    "ReconAgent",
    "VulnAgent",
    "ExploitAgent",
    "PostExploitAgent",
    "ExfilAgent",
    "CleanupAgent",
    # Attack
    "PrivescAgent",
    "CredAccessAgent",
    "PersistenceAgent",
    "CloudAgent",
    "LateralMoveAgent",
    "WebAppAgent",
    # Defense
    "EmergencyAgent",
    "OPSECAgent",
    "DecoyAgent",
    "CounterSurveillanceAgent",
    "ReverseTraceAgent",
    "TraceBusterAgent",
    # Specialist
    "SupplyChainAgent",
    "SocialEngineeringAgent",
    "BugBountyAgent",
    "AutoFixerAgent",
    "ReverseEngineeringAgent",
    # Domain (v3.2+)
    "IoTAgent",
    "SCADAAgent",
    "AutomotiveAgent",
    "SatelliteAgent",
    "BlockchainAgent",
    "AIExploitAgent",
    "MobileAgent",
    "TelecomAgent",
    "PhysicalAgent",
    "DarkWebAgent",
    "DroneAgent",
    "NuclearOpsecAgent",
    # Zero-Day Hunter
    "ZeroDayHunter",
    "create_zero_day_hunter",
]
