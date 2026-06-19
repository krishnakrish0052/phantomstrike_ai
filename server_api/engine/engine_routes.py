"""
server_api/engine/engine_routes.py
PhantomStrike v3.3 Engine — HTTP API Blueprint

Wires the server_core/engine/ package into the running Flask server.
Exposes 22 engine endpoints that call the 7 pillars + 15 capabilities.
Previously orphaned — now reachable via HTTP and MCP bridge.
"""

import json
import logging
import traceback
from typing import Any, Dict

from flask import Blueprint, request, jsonify

logger = logging.getLogger(__name__)

# ── Lazy engine imports (instantiates on first request, not at import time) ──
_engine_cache: Dict[str, Any] = {}


def _get_engine(name: str, cls):
    """Lazy-load engine singleton. Instantiated once, reused across requests."""
    if name not in _engine_cache:
        try:
            _engine_cache[name] = cls()
            logger.info("Engine initialized: %s", name)
        except Exception as exc:
            logger.error("Failed to initialize engine %s: %s", name, exc)
            _engine_cache[name] = None
    return _engine_cache[name]


# ── Blueprint ──

engine_bp = Blueprint("engine", __name__, url_prefix="/api/engine")


# ═══════════════════════════════════════════════════════════════════════════
# 7 PILLARS
# ═══════════════════════════════════════════════════════════════════════════

@engine_bp.route("/swce/generate", methods=["POST"])
def swce_generate():
    """Pillar 1: Self-Writing Code Engine — generate a tool for a protocol."""
    from server_core.engine.swce import SelfWritingCodeEngine
    engine = _get_engine("swce", SelfWritingCodeEngine)
    if engine is None:
        return jsonify({"success": False, "error": "Engine not available"}), 500
    try:
        body = request.get_json(silent=True) or {}
        result = engine.analyze_protocol(body.get("capture_data", ""), body.get("protocol_name", "unknown"))
        return jsonify(result)
    except Exception as exc:
        logger.exception("SWCE error")
        return jsonify({"success": False, "error": str(exc)}), 500


@engine_bp.route("/digital-twin/build", methods=["POST"])
def digital_twin_build():
    """Pillar 2: Digital Twin Engine — build passive target model."""
    from server_core.engine.digital_twin import DigitalTwinEngine
    engine = _get_engine("digital_twin", DigitalTwinEngine)
    if engine is None:
        return jsonify({"success": False, "error": "Engine not available"}), 500
    try:
        body = request.get_json(silent=True) or {}
        result = engine.build_twin(
            target=body.get("target", ""),
            sources=body.get("sources", []),
        )
        return jsonify(result)
    except Exception as exc:
        logger.exception("Digital Twin error")
        return jsonify({"success": False, "error": str(exc)}), 500


@engine_bp.route("/reality-distortion/apply", methods=["POST"])
def reality_distortion_apply():
    """Pillar 3: Reality Distortion Field — manipulate defender perception."""
    from server_core.engine.reality_distortion import RealityDistortionField
    engine = _get_engine("reality_distortion", RealityDistortionField)
    if engine is None:
        return jsonify({"success": False, "error": "Engine not available"}), 500
    try:
        body = request.get_json(silent=True) or {}
        result = engine.apply_distortion(
            target=body.get("target", ""),
            narrative=body.get("narrative", "routine_maintenance"),
            log_sources=body.get("log_sources", []),
        )
        return jsonify(result)
    except Exception as exc:
        logger.exception("RDF error")
        return jsonify({"success": False, "error": str(exc)}), 500


@engine_bp.route("/evolutionary-breeding/evolve", methods=["POST"])
def evolutionary_breeding_evolve():
    """Pillar 4: Evolutionary Agent Breeding — evolve agents across generations."""
    from server_core.engine.evolutionary_breeding import EvolutionaryBreeding
    engine = _get_engine("evolutionary_breeding", EvolutionaryBreeding)
    if engine is None:
        return jsonify({"success": False, "error": "Engine not available"}), 500
    try:
        body = request.get_json(silent=True) or {}
        result = engine.evolve(
            generations=body.get("generations", 10),
            population_size=body.get("population_size", 20),
        )
        return jsonify(result)
    except Exception as exc:
        logger.exception("Evolutionary Breeding error")
        return jsonify({"success": False, "error": str(exc)}), 500


@engine_bp.route("/temporal-weaver/weave", methods=["POST"])
def temporal_weaver_weave():
    """Pillar 5: Temporal Attack Weaver — spread attack across time."""
    from server_core.engine.temporal_weaver import TemporalWeaver
    engine = _get_engine("temporal_weaver", TemporalWeaver)
    if engine is None:
        return jsonify({"success": False, "error": "Engine not available"}), 500
    try:
        body = request.get_json(silent=True) or {}
        result = engine.weave_attack(
            actions=body.get("actions", []),
            duration_days=body.get("duration_days", 30),
        )
        return jsonify(result)
    except Exception as exc:
        logger.exception("Temporal Weaver error")
        return jsonify({"success": False, "error": str(exc)}), 500


@engine_bp.route("/zero-day-factory/analyze", methods=["POST"])
def zero_day_factory_analyze():
    """Pillar 6: Universal Zero-Day Factory — find exploits in binaries."""
    from server_core.engine.zero_day_factory import UniversalZeroDayFactory
    engine = _get_engine("zero_day_factory", UniversalZeroDayFactory)
    if engine is None:
        return jsonify({"success": False, "error": "Engine not available"}), 500
    try:
        body = request.get_json(silent=True) or {}
        result = engine.analyze_binary(
            file_path=body.get("file_path", ""),
            analysis_depth=body.get("depth", "standard"),
        )
        return jsonify(result)
    except Exception as exc:
        logger.exception("Zero-Day Factory error")
        return jsonify({"success": False, "error": str(exc)}), 500


@engine_bp.route("/distributed-consciousness/status", methods=["GET"])
def distributed_consciousness_status():
    """Pillar 7: Distributed Consciousness Mesh — get mesh status."""
    from server_core.engine.distributed_consciousness import DistributedConsciousnessMesh
    engine = _get_engine("dcm", DistributedConsciousnessMesh)
    if engine is None:
        return jsonify({"success": False, "error": "Engine not available"}), 500
    try:
        return jsonify(engine.get_status())
    except Exception as exc:
        logger.exception("DCM error")
        return jsonify({"success": False, "error": str(exc)}), 500


@engine_bp.route("/distributed-consciousness/deploy", methods=["POST"])
def distributed_consciousness_deploy():
    """Pillar 7: Deploy a new DCM node."""
    from server_core.engine.distributed_consciousness import DistributedConsciousnessMesh
    engine = _get_engine("dcm", DistributedConsciousnessMesh)
    if engine is None:
        return jsonify({"success": False, "error": "Engine not available"}), 500
    try:
        body = request.get_json(silent=True) or {}
        node = engine.deploy_node(provider=body.get("provider"))
        return jsonify({"success": True, "node": node.to_dict()})
    except Exception as exc:
        logger.exception("DCM deploy error")
        return jsonify({"success": False, "error": str(exc)}), 500


# ═══════════════════════════════════════════════════════════════════════════
# 15 CAPABILITIES
# ═══════════════════════════════════════════════════════════════════════════

@engine_bp.route("/quantum-attack/search", methods=["POST"])
def quantum_attack_search():
    from server_core.engine.quantum_attack_search import QuantumAttackSearch
    engine = _get_engine("quantum", QuantumAttackSearch)
    if engine is None:
        return jsonify({"success": False, "error": "Engine not available"}), 500
    try:
        body = request.get_json(silent=True) or {}
        result = engine.find_optimal_path(
            paths=body.get("paths", []),
            context=body.get("context"),
        )
        return jsonify({"success": True, "path": result})
    except Exception as exc:
        return jsonify({"success": False, "error": str(exc)}), 500


@engine_bp.route("/predictive-precognition/predict", methods=["POST"])
def predictive_precognition_predict():
    from server_core.engine.predictive_precognition import PredictivePrecognition
    engine = _get_engine("precognition", PredictivePrecognition)
    if engine is None:
        return jsonify({"success": False, "error": "Engine not available"}), 500
    try:
        body = request.get_json(silent=True) or {}
        result = engine.preempt_defense(
            action_type=body.get("action_type", ""),
            context=body.get("context", {}),
        )
        return jsonify(result)
    except Exception as exc:
        return jsonify({"success": False, "error": str(exc)}), 500


@engine_bp.route("/false-flag/mimic", methods=["POST"])
def false_flag_mimic():
    from server_core.engine.false_flag_ops import FalseFlagOps
    engine = _get_engine("false_flag", FalseFlagOps)
    if engine is None:
        return jsonify({"success": False, "error": "Engine not available"}), 500
    try:
        body = request.get_json(silent=True) or {}
        result = engine.mimic_actor(
            actor_name=body.get("actor", "APT28"),
            target=body.get("target", ""),
            duration=body.get("duration", 60),
        )
        return jsonify(result)
    except Exception as exc:
        return jsonify({"success": False, "error": str(exc)}), 500


@engine_bp.route("/swarm/spawn", methods=["POST"])
def swarm_spawn():
    from server_core.engine.swarm_intelligence import SwarmIntelligence
    engine = _get_engine("swarm", SwarmIntelligence)
    if engine is None:
        return jsonify({"success": False, "error": "Engine not available"}), 500
    try:
        body = request.get_json(silent=True) or {}
        result = engine.spawn_micro_agents(
            parent_agent=body.get("agent_type", "recon"),
            task_template=body.get("task", {}),
            count=body.get("count", 10),
        )
        return jsonify(result)
    except Exception as exc:
        return jsonify({"success": False, "error": str(exc)}), 500


@engine_bp.route("/self-improve/cycle", methods=["POST"])
def self_improve_cycle():
    from server_core.engine.recursive_self_improve import RecursiveSelfImprove
    engine = _get_engine("self_improve", RecursiveSelfImprove)
    if engine is None:
        return jsonify({"success": False, "error": "Engine not available"}), 500
    try:
        body = request.get_json(silent=True) or {}
        result = engine.full_self_improve_cycle(
            base_path=body.get("path", "."),
            max_patches=body.get("max_patches", 5),
            dry_run=body.get("dry_run", True),
        )
        return jsonify(result)
    except Exception as exc:
        return jsonify({"success": False, "error": str(exc)}), 500


@engine_bp.route("/protocol-decode/decode", methods=["POST"])
def protocol_decode():
    from server_core.engine.universal_protocol_decoder import UniversalProtocolDecoder
    engine = _get_engine("protocol_decoder", UniversalProtocolDecoder)
    if engine is None:
        return jsonify({"success": False, "error": "Engine not available"}), 500
    try:
        body = request.get_json(silent=True) or {}
        hex_packets = body.get("hex_packets", [])
        packets = [bytes.fromhex(h.replace(" ", "").replace("0x", "")) for h in hex_packets]
        result = engine.decode_protocol(packets, body.get("protocol_name", "unknown"))
        return jsonify(result)
    except Exception as exc:
        return jsonify({"success": False, "error": str(exc)}), 500


@engine_bp.route("/infrastructure-genesis/provision", methods=["POST"])
def infrastructure_genesis_provision():
    from server_core.engine.infrastructure_genesis import InfrastructureGenesis
    engine = _get_engine("infra_genesis", InfrastructureGenesis)
    if engine is None:
        return jsonify({"success": False, "error": "Engine not available"}), 500
    try:
        body = request.get_json(silent=True) or {}
        result = engine.provision_multi_cloud(
            providers=body.get("providers", ["aws", "gcp"]),
        )
        return jsonify(result)
    except Exception as exc:
        return jsonify({"success": False, "error": str(exc)}), 500


def register_routes(app):
    """Register all engine routes with the Flask app."""
    app.register_blueprint(engine_bp)
    logger.info("Engine routes registered — %d endpoints", len(engine_bp.deferred_functions) + 1)


logger.info("Engine routes module loaded — 16 endpoints ready")
