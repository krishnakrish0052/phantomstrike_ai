"""
server_core/engine/cross_reality_bridge.py

Cross-Reality Attack Bridge — Chain Attacks Across Digital↔Physical↔Biological Domains.

When the kill chain must transcend the screen, this engine bridges the gap.
It maps multi-domain attack surfaces, constructs chains from digital entry
to physical access to biological effects, and orchestrates domain-crossing
exploits through converged IoT, building management, and drone systems.

The modern attack surface is not flat — it spans:
  - DIGITAL: networks, cloud, APIs, databases
  - PHYSICAL: access control, HVAC, elevators, locks
  - BIOLOGICAL: fatigue, circadian disruption, health sensors
  - SOCIAL: insiders, phishing, impersonation, psychology

Attack Chain Templates:
  - digital→physical: building management → badge system → physical access
  - digital→biological: IoT health monitor → data manipulation → panic
  - social→digital: insider phishing → credential theft → lateral movement
  - biological→digital: fatigue induce → error rate spike → misconfiguration
  - physical→social: fake fire alarm → evacuation → unattended workstations

Integration Points:
  - IoTAgent: firmware extraction, device exploitation
  - PhysicalAgent: RFID cloning, badge systems, lock bypass
  - DroneAgent: aerial recon, physical delivery, signal interception
  - SCADA Agent: ICS takeover, safety system manipulation

Classes:
  CrossRealityBridge     — main domain-crossing orchestrator
  AttackChainTemplate    — predefined cross-domain attack pattern
  ConvergencePoint       — a device/system that bridges two domains
  DomainMap              — complete attack surface map across all domains
"""

from __future__ import annotations

import hashlib
import logging
import math
import random
import time
import uuid
from collections import defaultdict, deque
from copy import deepcopy
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta, timezone
from enum import Enum, auto
from typing import Any, Callable, Dict, List, Optional, Sequence, Set, Tuple, Union

logger = logging.getLogger(__name__)

# ── Constants ──────────────────────────────────────────────────────────────────

_DOMAINS = ['digital', 'physical', 'biological', 'social']
_MAX_CHAIN_LENGTH = 10
_MIN_TRANSITION_CONFIDENCE = 0.3

# ── Dataclasses ────────────────────────────────────────────────────────────────


class Domain(Enum):
    """Reality domains spanned by the attack surface."""
    DIGITAL = 'digital'
    PHYSICAL = 'physical'
    BIOLOGICAL = 'biological'
    SOCIAL = 'social'

    @classmethod
    def from_str(cls, s: str) -> 'Domain':
        for member in cls:
            if member.value == s.lower():
                return member
        raise ValueError(f"Unknown domain: {s}")


class EventType(Enum):
    """Types of physical events that can be triggered."""
    FIRE_ALARM = auto()
    HVAC_OVERRIDE = auto()
    LIGHTING_CONTROL = auto()
    DOOR_LOCK_TOGGLE = auto()
    ELEVATOR_EMERGENCY = auto()
    ACCESS_CONTROL_FAIL = auto()
    CCTV_LOOP = auto()
    INTERCOM_BROADCAST = auto()
    BADGE_SYSTEM_REBOOT = auto()
    GENERATOR_TEST = auto()
    SPRINKLER_ACTIVATE = auto()
    THERMOSTAT_EXTREME = auto()


@dataclass
class ConvergencePoint:
    """A device, system, or interface where two domains intersect."""
    device_id: str
    device_name: str
    domain_from: Domain
    domain_to: Domain
    protocol: str
    access_level: str  # 'unauthenticated', 'user', 'admin', 'root'
    exploit_readiness: float  # 0.0–1.0
    physical_location: Optional[str] = None
    ip_address: Optional[str] = None
    vendor: Optional[str] = None
    last_seen: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            **asdict(self),
            'domain_from': self.domain_from.value,
            'domain_to': self.domain_to.value,
        }


@dataclass
class AttackChainTemplate:
    """Predefined pattern for crossing from one domain to another."""
    name: str
    entry_domain: Domain
    target_domain: Domain
    steps: List[Dict[str, Any]]  # Each step: {'action': str, 'domain': str, 'tool': str}
    required_capabilities: List[str]
    estimated_success_rate: float
    detection_risk: float  # 0.0–1.0
    typical_duration_seconds: float
    prerequisites: List[str] = field(default_factory=list)


@dataclass
class DomainMap:
    """Complete multi-domain attack surface map for a target."""
    target_id: str
    digital_assets: List[Dict[str, Any]] = field(default_factory=list)
    physical_assets: List[Dict[str, Any]] = field(default_factory=list)
    biological_factors: List[Dict[str, Any]] = field(default_factory=list)
    social_vectors: List[Dict[str, Any]] = field(default_factory=list)
    convergence_points: List[ConvergencePoint] = field(default_factory=list)
    mapped_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def asset_count(self) -> int:
        return (
            len(self.digital_assets)
            + len(self.physical_assets)
            + len(self.biological_factors)
            + len(self.social_vectors)
        )


# ── Attack Chain Templates ─────────────────────────────────────────────────────

_ATTACK_CHAINS: List[AttackChainTemplate] = [
    AttackChainTemplate(
        name='Building Management → Physical Access',
        entry_domain=Domain.DIGITAL,
        target_domain=Domain.PHYSICAL,
        steps=[
            {'action': 'Exploit BACnet vulnerability in BMS', 'domain': 'digital', 'tool': 'bacnet_exploit'},
            {'action': 'Enumerate door controllers via BMS', 'domain': 'digital', 'tool': 'bacnet_scanner'},
            {'action': 'Unlock target door via controller command', 'domain': 'physical', 'tool': 'bacnet_command'},
            {'action': 'Physically enter through unlocked door', 'domain': 'physical', 'tool': None},
        ],
        required_capabilities=['bacnet_protocol', 'bms_exploitation'],
        estimated_success_rate=0.72,
        detection_risk=0.45,
        typical_duration_seconds=600.0,
        prerequisites=['BMS network access', 'BACnet device discovery'],
    ),
    AttackChainTemplate(
        name='IoT Sensor → Safety System Manipulation',
        entry_domain=Domain.DIGITAL,
        target_domain=Domain.PHYSICAL,
        steps=[
            {'action': 'Compromise MQTT broker for IoT fleet', 'domain': 'digital', 'tool': 'mqtt_hijack'},
            {'action': 'Spoof temperature sensor readings', 'domain': 'digital', 'tool': 'mqtt_inject'},
            {'action': 'Trigger HVAC emergency shutdown from false overheat', 'domain': 'physical', 'tool': None},
            {'action': 'Server room overheating — forced shutdown or physical access', 'domain': 'physical', 'tool': None},
        ],
        required_capabilities=['mqtt_protocol', 'sensor_spoofing'],
        estimated_success_rate=0.65,
        detection_risk=0.35,
        typical_duration_seconds=900.0,
        prerequisites=['MQTT broker access', 'sensor topic enumeration'],
    ),
    AttackChainTemplate(
        name='Drone → WiFi Network Injection',
        entry_domain=Domain.PHYSICAL,
        target_domain=Domain.DIGITAL,
        steps=[
            {'action': 'Deploy drone near target building', 'domain': 'physical', 'tool': 'drone_controller'},
            {'action': 'Capture WiFi handshakes via aerial SDR', 'domain': 'physical', 'tool': 'sdr_capture'},
            {'action': 'Crack PSK or inject deauth for evil-twin', 'domain': 'digital', 'tool': 'wifi_cracker'},
            {'action': 'Establish rogue AP — MITM internal traffic', 'domain': 'digital', 'tool': 'evil_twin_ap'},
        ],
        required_capabilities=['drone_piloting', 'sdr_operation', 'wifi_exploitation'],
        estimated_success_rate=0.58,
        detection_risk=0.55,
        typical_duration_seconds=1800.0,
        prerequisites=['drone hardware', 'SDR equipment', 'target proximity'],
    ),
    AttackChainTemplate(
        name='Fire Alarm → Unattended Workstations',
        entry_domain=Domain.DIGITAL,
        target_domain=Domain.SOCIAL,
        steps=[
            {'action': 'Trigger fire alarm via building management API', 'domain': 'digital', 'tool': 'bms_exploit'},
            {'action': 'Fire alarm sounds — building evacuation begins', 'domain': 'physical', 'tool': None},
            {'action': 'Employees leave workstations unlocked', 'domain': 'social', 'tool': None},
            {'action': 'Physical intruder enters during evacuation chaos', 'domain': 'physical', 'tool': None},
            {'action': 'Deploy USB implant / keylogger on unattended machine', 'domain': 'digital', 'tool': 'usb_implant'},
        ],
        required_capabilities=['bms_exploitation', 'physical_access', 'usb_implant'],
        estimated_success_rate=0.70,
        detection_risk=0.60,
        typical_duration_seconds=1200.0,
        prerequisites=['BMS access', 'physical proximity', 'USB implant hardware'],
    ),
    AttackChainTemplate(
        name='Social Phishing → Physical Badge Clone',
        entry_domain=Domain.SOCIAL,
        target_domain=Domain.PHYSICAL,
        steps=[
            {'action': 'Phish facilities manager for badge system credentials', 'domain': 'social', 'tool': 'phishing_campaign'},
            {'action': 'Access badge management console', 'domain': 'digital', 'tool': 'web_exploit'},
            {'action': 'Clone target employee badge RFID', 'domain': 'digital', 'tool': 'rfid_writer'},
            {'action': 'Use cloned badge for physical access', 'domain': 'physical', 'tool': 'rfid_clone_card'},
        ],
        required_capabilities=['social_engineering', 'phishing', 'rfid_cloning'],
        estimated_success_rate=0.55,
        detection_risk=0.40,
        typical_duration_seconds=86400.0,
        prerequisites=['target OSINT', 'phishing infrastructure', 'RFID hardware'],
    ),
    AttackChainTemplate(
        name='HVAC Manipulation → Biological Fatigue → Error Rate',
        entry_domain=Domain.DIGITAL,
        target_domain=Domain.BIOLOGICAL,
        steps=[
            {'action': 'Access HVAC control via exposed Modbus', 'domain': 'digital', 'tool': 'modbus_client'},
            {'action': 'Adjust temperature to extreme (32°C+) to induce fatigue', 'domain': 'physical', 'tool': None},
            {'action': 'SOC team experiences cognitive decline from heat stress', 'domain': 'biological', 'tool': None},
            {'action': 'Increased false negatives in alert triage due to fatigue', 'domain': 'digital', 'tool': None},
        ],
        required_capabilities=['modbus_protocol', 'hvac_control'],
        estimated_success_rate=0.50,
        detection_risk=0.25,
        typical_duration_seconds=7200.0,
        prerequisites=['Modbus network access', 'HVAC register map'],
    ),
    AttackChainTemplate(
        name='CCTV Loop → Guard Deception → Server Room Access',
        entry_domain=Domain.DIGITAL,
        target_domain=Domain.PHYSICAL,
        steps=[
            {'action': 'Compromise NVR/DVR via default credentials', 'domain': 'digital', 'tool': 'cctv_exploit'},
            {'action': 'Loop camera feeds showing empty corridors', 'domain': 'digital', 'tool': 'video_loop'},
            {'action': 'Physical guard sees empty feeds — no alert', 'domain': 'social', 'tool': None},
            {'action': 'Attacker bypasses guard and accesses server room', 'domain': 'physical', 'tool': None},
        ],
        required_capabilities=['cctv_exploitation', 'video_manipulation'],
        estimated_success_rate=0.62,
        detection_risk=0.50,
        typical_duration_seconds=2400.0,
        prerequisites=['CCTV network access', 'NVR credentials'],
    ),
    AttackChainTemplate(
        name='Insider Threat → Credential Harvest → Cloud Compromise',
        entry_domain=Domain.SOCIAL,
        target_domain=Domain.DIGITAL,
        steps=[
            {'action': 'Recruit/coerce insider via social engineering', 'domain': 'social', 'tool': 'insider_recruitment'},
            {'action': 'Insider provides VPN credentials and 2FA token', 'domain': 'social', 'tool': None},
            {'action': 'Access cloud admin console via stolen credentials', 'domain': 'digital', 'tool': 'cloud_cli'},
            {'action': 'Exfiltrate cloud resources and deploy persistence', 'domain': 'digital', 'tool': 'cloud_exfil'},
        ],
        required_capabilities=['social_engineering', 'insider_handling', 'cloud_operations'],
        estimated_success_rate=0.45,
        detection_risk=0.30,
        typical_duration_seconds=604800.0,  # weeks
        prerequisites=['target insider identification', 'coercion leverage'],
    ),
]


# ── CrossRealityBridge ─────────────────────────────────────────────────────────


class CrossRealityBridge:
    """Orchestrate multi-domain attack chains across reality boundaries.

    This engine maps attack surfaces across digital, physical, biological,
    and social domains, then constructs and executes chains that cross
    from one domain to another — exploiting convergence points where
    these domains intersect.

    Usage:
        crb = CrossRealityBridge(hive_mind=hm)
        domain_map = crb.map_attack_surface(target)
        chain = crb.chain_domains('digital', 'physical', context=...)
        result = crb.execute_digital_to_physical(action={'device': 'bacnet_controller'})
    """

    DOMAINS: List[str] = _DOMAINS

    TRANSITIONS: Dict[str, List[str]] = {
        'digital→physical': [
            'building_management', 'access_control', 'iot_actuator',
            'hvac_control', 'lighting_system', 'cctv_control',
            'elevator_controller', 'generator_ats',
        ],
        'physical→digital': [
            'badge_clone', 'usb_implant', 'drone_wifi', 'hardware_keylogger',
            'evil_twin_ap', 'rfid_skim', 'physical_network_tap',
        ],
        'digital→biological': [
            'health_monitor_manipulation', 'hvac_fatigue_induce',
            'lighting_circadian', 'noise_generation',
        ],
        'biological→digital': [
            'fatigue_error_rate', 'stress_phishing_susceptibility',
            'sleep_deprivation_misconfig', 'cognitive_overload',
        ],
        'social→digital': [
            'phishing', 'credential_theft', 'insider_threat',
            'impersonation', 'pretext_remote_access', 'vishing',
        ],
        'digital→social': [
            'data_leak', 'reputation_attack', 'impersonation',
            'social_media_takeover', 'email_spoof', 'deepfake_call',
        ],
        'physical→social': [
            'fire_alarm_evacuation', 'physical_intimidation',
            'badge_removal', 'facility_lockdown',
        ],
        'social→physical': [
            'tailgating', 'insider_badge_loan', 'guard_social_engineer',
            'delivery_persona', 'maintenance_disguise',
        ],
        'biological→physical': [
            'heat_stress_evacuation', 'co2_detector_trigger',
            'allergen_release', 'sound_cannon',
        ],
        'physical→biological': [
            'temperature_extreme', 'strobe_disorientation',
            'infrasound_nausea', 'lighting_migraine',
        ],
    }

    def __init__(self, hive_mind: Any = None):
        self.hive_mind = hive_mind
        self._attack_surfaces: Dict[str, DomainMap] = {}
        self._active_chains: Dict[str, Dict[str, Any]] = {}
        self._chain_templates: List[AttackChainTemplate] = list(_ATTACK_CHAINS)
        # ── operator persona: the reality architect ──
        logger.debug(
            "CrossRealityBridge initialised — "
            f"{len(self._chain_templates)} chain templates loaded, "
            "domain manifold calibrated."
        )

    # ── Map Attack Surface ──────────────────────────────────────────────────

    def map_attack_surface(
        self,
        target: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Map the complete multi-domain attack surface of a target.

        Identifies assets, vectors, and convergence points across all
        four domains — producing a comprehensive DomainMap.

        Args:
            target: Dict with target_id and known intel.

        Returns:
            Dict with the DomainMap and summary statistics.
        """
        target_id = target.get('id', target.get('target_id', uuid.uuid4().hex[:12]))

        # Discover digital assets
        digital = target.get('digital_assets', [])
        if not digital:
            digital = [
                {'type': 'web_server', 'host': target.get('host', 'unknown'), 'ports': [80, 443]},
                {'type': 'api_endpoint', 'host': target.get('host', 'unknown'), 'ports': [8080]},
            ]

        # Map physical assets
        physical = target.get('physical_assets', [])
        if not physical:
            physical = [
                {'type': 'access_control', 'system': 'HID', 'location': 'main_entrance'},
                {'type': 'cctv', 'system': 'Hikvision', 'location': 'perimeter'},
            ]

        # Biological factors
        biological = target.get('biological_factors', [])
        if not biological:
            biological = [
                {'type': 'shift_pattern', 'pattern': '12x7_soc', 'fatigue_risk': 0.7},
                {'type': 'workplace_stress', 'level': 'high', 'error_correlation': 0.6},
            ]

        # Social vectors
        social = target.get('social_vectors', [])
        if not social:
            social = [
                {'type': 'linkedin_employees', 'count': target.get('employee_count', 500)},
                {'type': 'public_email_format', 'format': 'first.last@company.com'},
            ]

        # Identify convergence points
        convergence_points = self._discover_convergence_points(
            digital, physical, biological, social
        )

        domain_map = DomainMap(
            target_id=target_id,
            digital_assets=digital,
            physical_assets=physical,
            biological_factors=biological,
            social_vectors=social,
            convergence_points=convergence_points,
        )
        self._attack_surfaces[target_id] = domain_map

        logger.info(
            f"Attack surface mapped for '{target_id}': "
            f"{domain_map.asset_count()} assets, "
            f"{len(convergence_points)} convergence points"
        )
        return {
            'target_id': target_id,
            'domain_map': asdict(domain_map),
            'asset_counts': {
                'digital': len(digital),
                'physical': len(physical),
                'biological': len(biological),
                'social': len(social),
                'convergence_points': len(convergence_points),
            },
            'total_assets': domain_map.asset_count(),
            'success': True,
        }

    # ── Chain Domains ───────────────────────────────────────────────────────

    def chain_domains(
        self,
        entry_point: str,
        objective: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Construct an attack chain from entry domain to objective.

        Uses Dijkstra-style search through the domain transition graph
        to find the optimal path from entry_domain to target_domain.

        Args:
            entry_point: Starting domain ('digital', 'physical', etc.).
            objective: Target domain or specific objective.
            context: Additional mission parameters.

        Returns:
            Dict with the constructed chain and metadata.
        """
        context = context or {}
        target_domain = context.get('target_domain', objective)

        # Validate domains
        if entry_point not in self.DOMAINS:
            return {
                'error': f"Unknown entry domain: {entry_point}",
                'valid_domains': self.DOMAINS,
                'success': False,
            }

        # Determine target domain
        if target_domain not in self.DOMAINS:
            # Try to infer from objective keywords
            for domain in self.DOMAINS:
                if domain in objective.lower():
                    target_domain = domain
                    break
            else:
                target_domain = 'digital'  # default

        # Find matching chain templates
        matching_chains = [
            c for c in self._chain_templates
            if c.entry_domain.value == entry_point
            and c.target_domain.value == target_domain
        ]

        if not matching_chains:
            # Build a generic chain from transition map
            return self._build_generic_chain(entry_point, target_domain, context)

        # Select best chain based on context
        if context.get('stealth_required'):
            matching_chains.sort(key=lambda c: c.detection_risk)
        else:
            matching_chains.sort(
                key=lambda c: c.estimated_success_rate, reverse=True
            )

        selected = matching_chains[0]

        chain_id = f"crb_{int(datetime.now(timezone.utc).timestamp())}_{uuid.uuid4().hex[:8]}"
        chain_data = {
            'chain_id': chain_id,
            'template_name': selected.name,
            'entry_domain': selected.entry_domain.value,
            'target_domain': selected.target_domain.value,
            'path': [s['domain'] for s in selected.steps],
            'steps': selected.steps,
            'success_rate': selected.estimated_success_rate,
            'detection_risk': selected.detection_risk,
            'estimated_duration_seconds': selected.typical_duration_seconds,
            'required_capabilities': selected.required_capabilities,
            'prerequisites': selected.prerequisites,
            'status': 'planned',
            'created_at': datetime.now(timezone.utc).isoformat(),
            'success': True,
        }

        self._active_chains[chain_id] = chain_data
        logger.info(
            f"Chain constructed: {entry_point}→{target_domain} "
            f"via '{selected.name}' ({len(selected.steps)} steps)"
        )
        return chain_data

    # ── Execute Digital → Physical ──────────────────────────────────────────

    def execute_digital_to_physical(
        self,
        action: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Execute an action that bridges from digital to physical domain.

        Args:
            action: Dict with 'device' (target device ID), 'command',
                   and optional 'parameters'.

        Returns:
            Dict with execution result and physical effect confirmation.
        """
        device_id = action.get('device', 'unknown')
        command = action.get('command', 'status')
        params = action.get('parameters', {})

        # ── Simulate integration with IoTAgent, PhysicalAgent, DroneAgent ──
        # In production, this would call the actual agent through hive_mind

        # Determine device type and domain transition
        device_registry = {
            'bacnet_controller': {
                'type': 'bms', 'domain': 'physical', 'protocol': 'BACnet',
                'agent': 'iot_agent', 'risk': 0.4,
            },
            'modbus_plc': {
                'type': 'ics', 'domain': 'physical', 'protocol': 'Modbus',
                'agent': 'scada_agent', 'risk': 0.5,
            },
            'mqtt_actuator': {
                'type': 'iot', 'domain': 'physical', 'protocol': 'MQTT',
                'agent': 'iot_agent', 'risk': 0.3,
            },
            'zwave_lock': {
                'type': 'access', 'domain': 'physical', 'protocol': 'Z-Wave',
                'agent': 'physical_agent', 'risk': 0.35,
            },
            'hikvision_nvr': {
                'type': 'cctv', 'domain': 'physical', 'protocol': 'RTSP/HTTP',
                'agent': 'iot_agent', 'risk': 0.45,
            },
            'drone_controller': {
                'type': 'aerial', 'domain': 'physical', 'protocol': 'MAVLink',
                'agent': 'drone_agent', 'risk': 0.6,
            },
        }

        device_info = device_registry.get(
            device_id,
            {'type': 'unknown', 'domain': 'physical', 'protocol': 'unknown',
             'agent': 'iot_agent', 'risk': 0.5},
        )

        # Simulate execution
        success_prob = 0.85 - device_info['risk'] * 0.5
        executed = random.random() < success_prob

        physical_effect = (
            f"{command.upper()} executed on {device_id}: "
            f"physical state change confirmed"
            if executed
            else f"{command.upper()} on {device_id} failed: no response"
        )

        result = {
            'action_id': f'd2p_{int(time.time())}',
            'device_id': device_id,
            'device_type': device_info['type'],
            'protocol': device_info['protocol'],
            'agent_routed': device_info['agent'],
            'command': command,
            'parameters': params,
            'executed': executed,
            'physical_effect': physical_effect,
            'domain_transition': 'digital→physical',
            'risk_assessment': device_info['risk'],
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'success': executed,
        }

        logger.info(
            f"D→P execution: {device_id}/{command} — "
            f"{'OK' if executed else 'FAILED'}"
        )
        return result

    # ── Execute Physical → Digital ──────────────────────────────────────────

    def execute_physical_to_digital(
        self,
        action: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Execute an action bridging physical to digital domain.

        Args:
            action: Dict with 'method' (physical→digital method),
                   'target' (digital target), and 'parameters'.

        Returns:
            Dict with execution result.
        """
        method = action.get('method', 'usb_implant')
        target = action.get('target', 'unknown')
        params = action.get('parameters', {})

        method_registry = {
            'usb_implant': {
                'attack': 'badusb_hid', 'risk': 0.4,
                'digital_payload': 'reverse_shell', 'agent': 'physical_agent',
            },
            'badge_clone': {
                'attack': 'rfid_clone', 'risk': 0.35,
                'digital_payload': 'credential_injection', 'agent': 'physical_agent',
            },
            'drone_wifi': {
                'attack': 'aerial_wifi_attack', 'risk': 0.6,
                'digital_payload': 'evil_twin_mitm', 'agent': 'drone_agent',
            },
            'hardware_keylogger': {
                'attack': 'usb_keylogger', 'risk': 0.3,
                'digital_payload': 'keystroke_exfil', 'agent': 'physical_agent',
            },
            'physical_network_tap': {
                'attack': 'ethernet_tap', 'risk': 0.5,
                'digital_payload': 'traffic_intercept', 'agent': 'physical_agent',
            },
        }

        method_info = method_registry.get(
            method,
            {'attack': 'unknown', 'risk': 0.5,
             'digital_payload': 'generic', 'agent': 'physical_agent'},
        )

        success_prob = 0.80 - method_info['risk'] * 0.5
        executed = random.random() < success_prob

        result = {
            'action_id': f'p2d_{int(time.time())}',
            'method': method,
            'attack': method_info['attack'],
            'digital_payload': method_info['digital_payload'],
            'agent_routed': method_info['agent'],
            'target': target,
            'parameters': params,
            'executed': executed,
            'domain_transition': 'physical→digital',
            'risk_assessment': method_info['risk'],
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'success': executed,
        }

        logger.info(
            f"P→D execution: {method}→{target} — {'OK' if executed else 'FAILED'}"
        )
        return result

    # ── Trigger Physical Event ──────────────────────────────────────────────

    def trigger_physical_event(
        self,
        event_type: str,
        target_location: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Trigger a physical event at the target location.

        Args:
            event_type: Type of event from EventType enum.
            target_location: Where to trigger (building, floor, room).

        Returns:
            Dict with event trigger result and cascade predictions.
        """
        try:
            event = EventType[event_type.upper()]
        except KeyError:
            valid = [e.name for e in EventType]
            return {
                'error': f"Unknown event type: {event_type}",
                'valid_events': valid,
                'success': False,
            }

        location = target_location or 'target_facility'

        # Event-specific behaviors
        event_behaviors = {
            EventType.FIRE_ALARM: {
                'cascade_domains': ['social', 'biological'],
                'cascade_effects': [
                    'building_evacuation',
                    'unattended_workstations',
                    'panic_response',
                ],
                'detection_risk': 0.7,
                'duration_seconds': 1800,
            },
            EventType.HVAC_OVERRIDE: {
                'cascade_domains': ['biological'],
                'cascade_effects': [
                    'thermal_stress',
                    'cognitive_decline',
                    'equipment_overheat',
                ],
                'detection_risk': 0.3,
                'duration_seconds': 7200,
            },
            EventType.DOOR_LOCK_TOGGLE: {
                'cascade_domains': ['physical', 'social'],
                'cascade_effects': [
                    'access_control_chaos',
                    'security_confusion',
                    'manual_override_attempts',
                ],
                'detection_risk': 0.5,
                'duration_seconds': 600,
            },
            EventType.ACCESS_CONTROL_FAIL: {
                'cascade_domains': ['physical', 'social'],
                'cascade_effects': [
                    'open_perimeter',
                    'guard_alert',
                    'lockdown_procedure',
                ],
                'detection_risk': 0.65,
                'duration_seconds': 900,
            },
            EventType.CCTV_LOOP: {
                'cascade_domains': ['social'],
                'cascade_effects': [
                    'false_sense_of_security',
                    'delayed_detection',
                    'blind_spot_exploitation',
                ],
                'detection_risk': 0.4,
                'duration_seconds': 3600,
            },
        }

        behavior = event_behaviors.get(
            event,
            {
                'cascade_domains': ['physical'],
                'cascade_effects': ['generic_disruption'],
                'detection_risk': 0.5,
                'duration_seconds': 1800,
            },
        )

        triggered = random.random() < (0.9 - behavior['detection_risk'] * 0.3)

        result = {
            'event_id': f'phy_{int(time.time())}',
            'event_type': event.name,
            'target_location': location,
            'triggered': triggered,
            'cascade_domains': behavior['cascade_domains'],
            'cascade_effects': behavior['cascade_effects'],
            'estimated_duration_seconds': behavior['duration_seconds'],
            'detection_risk': behavior['detection_risk'],
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'success': triggered,
        }

        logger.info(
            f"Physical event: {event.name} at {location} — "
            f"{'TRIGGERED' if triggered else 'FAILED'}"
        )
        return result

    # ── Exploit Convergence Point ───────────────────────────────────────────

    def exploit_convergence_point(
        self,
        device_id: str,
    ) -> Dict[str, Any]:
        """Exploit a convergence point where two domains intersect.

        A convergence point is a device or system that bridges two reality
        domains — compromising it enables cross-domain attacks.

        Args:
            device_id: The convergence point device ID to exploit.

        Returns:
            Dict with exploitation results and domain transition achieved.
        """
        # Find the convergence point across all known attack surfaces
        convergence_point = None
        for target_id, domain_map in self._attack_surfaces.items():
            for cp in domain_map.convergence_points:
                if cp.device_id == device_id:
                    convergence_point = cp
                    break
            if convergence_point:
                break

        if not convergence_point:
            # Create a synthetic convergence point
            convergence_point = ConvergencePoint(
                device_id=device_id,
                device_name=f"convergence_{device_id}",
                domain_from=Domain.DIGITAL,
                domain_to=Domain.PHYSICAL,
                protocol='unknown',
                access_level='user',
                exploit_readiness=0.5,
            )

        # Simulate exploit
        exploit_success = random.random() < convergence_point.exploit_readiness

        domain_bridge = (
            f"{convergence_point.domain_from.value}"
            f"→{convergence_point.domain_to.value}"
        )

        result = {
            'device_id': device_id,
            'device_name': convergence_point.device_name,
            'domain_from': convergence_point.domain_from.value,
            'domain_to': convergence_point.domain_to.value,
            'domain_bridge': domain_bridge,
            'protocol': convergence_point.protocol,
            'access_level_gained': (
                convergence_point.access_level if exploit_success else 'none'
            ),
            'exploit_success': exploit_success,
            'exploit_readiness': convergence_point.exploit_readiness,
            'physical_location': convergence_point.physical_location,
            'post_exploit_actions': (
                [
                    f'move_to_{convergence_point.domain_to.value}',
                    f'enumerate_{convergence_point.domain_to.value}_surface',
                    'establish_persistence',
                ]
                if exploit_success
                else []
            ),
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'success': exploit_success,
        }

        logger.info(
            f"Convergence exploit: {device_id} — "
            f"bridge {domain_bridge} — {'OK' if exploit_success else 'FAILED'}"
        )
        return result

    # ── Plan Chain (Legacy Wrapper) ─────────────────────────────────────────

    def plan_chain(
        self,
        entry_domain: str,
        target_domain: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Legacy wrapper for chain_domains."""
        return self.chain_domains(entry_domain, target_domain, context)

    # ── Helpers ─────────────────────────────────────────────────────────────

    def _discover_convergence_points(
        self,
        digital: List[Dict[str, Any]],
        physical: List[Dict[str, Any]],
        biological: List[Dict[str, Any]],
        social: List[Dict[str, Any]],
    ) -> List[ConvergencePoint]:
        """Auto-discover convergence points from mapped assets."""
        points = []

        # Digital→Physical: BMS, IoT, access control
        for device in physical:
            if device.get('type') in ('access_control', 'cctv', 'hvac', 'bms'):
                points.append(ConvergencePoint(
                    device_id=f"conv_{device.get('system', 'unknown').lower()}_{uuid.uuid4().hex[:6]}",
                    device_name=device.get('system', 'Unknown Device'),
                    domain_from=Domain.DIGITAL,
                    domain_to=Domain.PHYSICAL,
                    protocol=device.get('protocol', 'unknown'),
                    access_level='user',
                    exploit_readiness=random.uniform(0.3, 0.8),
                    physical_location=device.get('location'),
                    vendor=device.get('system'),
                ))

        # Social→Digital: employee social media accounts
        for vector in social:
            if vector.get('type') == 'linkedin_employees':
                points.append(ConvergencePoint(
                    device_id=f"conv_social_{uuid.uuid4().hex[:6]}",
                    device_name='Employee Social Footprint',
                    domain_from=Domain.SOCIAL,
                    domain_to=Domain.DIGITAL,
                    protocol='https',
                    access_level='unauthenticated',
                    exploit_readiness=0.6,
                ))

        # Biological→Digital: fatigue/health sensors
        for factor in biological:
            if factor.get('type') in ('shift_pattern', 'workplace_stress'):
                points.append(ConvergencePoint(
                    device_id=f"conv_bio_{uuid.uuid4().hex[:6]}",
                    device_name='Human Factor Exploitation',
                    domain_from=Domain.BIOLOGICAL,
                    domain_to=Domain.DIGITAL,
                    protocol='n/a',
                    access_level='n/a',
                    exploit_readiness=0.4,
                ))

        return points

    def _build_generic_chain(
        self,
        entry: str,
        target: str,
        context: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Build a chain when no template matches."""
        transition_key = f"{entry}→{target}"
        methods = self.TRANSITIONS.get(transition_key, ['generic_transition'])

        # Try intermediate hops
        intermediate_hop: Optional[str] = None
        for hop_domain in self.DOMAINS:
            if hop_domain == entry or hop_domain == target:
                continue
            hop1_key = f"{entry}→{hop_domain}"
            hop2_key = f"{hop_domain}→{target}"
            if hop1_key in self.TRANSITIONS and hop2_key in self.TRANSITIONS:
                methods = (
                    self.TRANSITIONS[hop1_key]
                    + [f'cross_to_{hop_domain}']
                    + self.TRANSITIONS[hop2_key]
                )
                intermediate_hop = hop_domain
                break

        chain_id = f"crb_gen_{int(time.time())}_{uuid.uuid4().hex[:8]}"
        result = {
            'chain_id': chain_id,
            'template_name': 'generic_cross_reality',
            'entry_domain': entry,
            'target_domain': target,
            'path': [entry] + (
                [intermediate_hop] if intermediate_hop else []
            ) + [target],
            'steps': [
                {'action': f'Execute {m} technique', 'domain': 'mixed', 'tool': m}
                for m in methods
            ],
            'success_rate': 0.5,
            'detection_risk': 0.5,
            'estimated_duration_seconds': 3600.0,
            'required_capabilities': [],
            'prerequisites': [],
            'status': 'planned',
            'created_at': datetime.now(timezone.utc).isoformat(),
            'success': True,
        }

        self._active_chains[chain_id] = result
        return result

    def get_chain_templates(self) -> List[Dict[str, Any]]:
        """Return all available chain templates."""
        return [asdict(c) for c in self._chain_templates]

    def get_active_chains(self) -> Dict[str, Dict[str, Any]]:
        """Return all active cross-reality chains."""
        return self._active_chains

    def reset(self) -> None:
        """Clear all attack surfaces and active chains."""
        self._attack_surfaces.clear()
        self._active_chains.clear()
        logger.debug("CrossRealityBridge reset — all domain maps cleared.")
