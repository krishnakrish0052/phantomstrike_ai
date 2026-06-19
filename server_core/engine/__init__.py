"""
PhantomStrike v3.3 Engine — 7 Pillars + 15 Capabilities.
"""
import logging
logger = logging.getLogger(__name__)

# 7 Pillars
from .swce import SelfWritingCodeEngine
from .digital_twin import DigitalTwinEngine
from .reality_distortion import RealityDistortionField
from .evolutionary_breeding import EvolutionaryBreeding
from .temporal_weaver import TemporalWeaver
from .zero_day_factory import UniversalZeroDayFactory
from .distributed_consciousness import DistributedConsciousnessMesh

# 15 New Capabilities (v3.3)
from .quantum_attack_search import QuantumAttackSearch
from .predictive_precognition import PredictivePrecognition
from .memetic_attack import MemeticAttack
from .cross_reality_bridge import CrossRealityBridge
from .legal_grayzone import LegalGrayZone
from .biological_attack import BiologicalAttack
from .infrastructure_genesis import InfrastructureGenesis
from .defender_psychology import DefenderPsychology
from .recursive_self_improve import RecursiveSelfImprove
from .universal_protocol_decoder import UniversalProtocolDecoder
from .false_flag_ops import FalseFlagOps
from .economic_attack import EconomicAttack
from .swarm_intelligence import SwarmIntelligence
from .honeypot_ops import HoneypotOps
from .insider_threat import InsiderThreat

__all__ = [
    "SelfWritingCodeEngine", "DigitalTwinEngine", "RealityDistortionField",
    "EvolutionaryBreeding", "TemporalWeaver", "UniversalZeroDayFactory",
    "DistributedConsciousnessMesh",
    "QuantumAttackSearch", "PredictivePrecognition", "MemeticAttack",
    "CrossRealityBridge", "LegalGrayZone", "BiologicalAttack",
    "InfrastructureGenesis", "DefenderPsychology", "RecursiveSelfImprove",
    "UniversalProtocolDecoder", "FalseFlagOps", "EconomicAttack",
    "SwarmIntelligence", "HoneypotOps", "InsiderThreat",
]
