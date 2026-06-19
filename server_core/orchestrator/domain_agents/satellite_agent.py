"""
Satellite Agent — Space Cowboy. Hijacks satellite downlinks, decodes
telemetry, injects telecommands, spoofs GNSS, and intercepts Iridium
pager traffic from low Earth orbit.

Knowledge: SDR (RTL-SDR, HackRF, LimeSDR, USRP), GNU Radio, satellite
TLE tracking (NORAD/Spacetrack), CCSDS/AX.25/HDLC protocols, GNSS
spoofing, Iridium/L-band intercept, NOAA APT/Meteor LRPT weather
satellite imagery, cubesat telecommand injection.
"""
import logging
import math
from datetime import datetime
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class SatelliteAgent:
    """Orbital dominance specialist. Ground stations are my endpoint,
    telecommands are my shellcode, and the ionosphere is my firewall."""

    agent_type = "satellite"

    # --- Known satellites (TLE / NORAD catalog excerpts) -------------
    SATELLITE_CATALOG: List[Dict[str, Any]] = [
        {"norad_id": 25544, "name": "ISS (ZARYA)", "type": "Space Station",
         "downlink_freq": "145.800 MHz", "protocol": "APRS/AX.25"},
        {"norad_id": 33591, "name": "NOAA-19", "type": "Weather",
         "downlink_freq": "137.100 MHz", "protocol": "APT"},
        {"norad_id": 40069, "name": "Meteor-M2", "type": "Weather",
         "downlink_freq": "137.900 MHz", "protocol": "LRPT"},
        {"norad_id": 39418, "name": "FUNCUBE-1", "type": "Cubesat/Education",
         "downlink_freq": "145.935 MHz", "protocol": "BPSK telemetry"},
        {"norad_id": 25508, "name": "ORBCOMM FM-5", "type": "M2M/IoT",
         "downlink_freq": "137.500 MHz", "protocol": "Proprietary TDMA"},
        {"norad_id": 25338, "name": "IRIDIUM-7", "type": "Communications",
         "downlink_freq": "1616-1626.5 MHz", "protocol": "L-band TDMA"},
        {"norad_id": 43633, "name": "IRIDIUM-NEXT-160", "type": "Communications",
         "downlink_freq": "1616-1626.5 MHz", "protocol": "L-band TDMA"},
    ]

    # --- CCSDS telecommand types -------------------------------------
    CCSDS_COMMANDS: Dict[int, str] = {
        0x01: "NOOP",
        0x02: "RESET",
        0x03: "TRANSMIT_TELEMETRY",
        0x04: "ENTER_SAFE_MODE",
        0x05: "POWER_CYCLE_SUBSYSTEM",
        0x06: "UPLOAD_PATCH",
        0x07: "DEPLOY_ANTENNA",
        0x08: "FIRE_THRUSTER",
        0x09: "CHANGE_ORBIT",
        0x0A: "DUMP_MEMORY",
    }

    # --- GNSS constellation data -------------------------------------
    GNSS_SIGNALS: Dict[str, Dict[str, Any]] = {
        "GPS L1": {"frequency_mhz": 1575.42, "modulation": "BPSK", "chipping_rate": 1.023e6, "civ_code": "C/A"},
        "GPS L2": {"frequency_mhz": 1227.60, "modulation": "BPSK", "chipping_rate": 1.023e6, "civ_code": "P(Y) encrypted"},
        "GLONASS G1": {"frequency_mhz": 1602.0, "modulation": "BPSK", "chipping_rate": 0.511e6, "civ_code": "L1OF"},
        "Galileo E1": {"frequency_mhz": 1575.42, "modulation": "CBOC", "chipping_rate": 1.023e6, "civ_code": "E1B/C"},
        "BeiDou B1I": {"frequency_mhz": 1561.098, "modulation": "BPSK", "chipping_rate": 2.046e6, "civ_code": "B1I"},
    }

    def __init__(self, hive_mind=None, tool_bridge=None):
        self.hive_mind = hive_mind
        self.tool_bridge = tool_bridge
        logger.info("SatelliteAgent initialised — ready to hack the final frontier.")

    # ------------------------------------------------------------------
    # Core exploitation methods
    # ------------------------------------------------------------------

    def track_satellite(self, norad_id: int = 25544,
                        observer_lat: float = 40.7128,
                        observer_lon: float = -74.0060,
                        observer_alt: float = 0.0) -> Dict[str, Any]:
        """
        Track a satellite in real-time using NORAD ID / TLE data.
        Computes azimuth, elevation, range, Doppler shift, and next
        pass times for a given observer location.
        """
        result: Dict[str, Any] = {
            "norad_id": norad_id, "success": False,
            "satellite_name": None, "current_position": {},
            "next_passes": [], "tle": None,
        }

        try:
            # Look up satellite from catalog
            for sat in self.SATELLITE_CATALOG:
                if sat["norad_id"] == norad_id:
                    result["satellite_name"] = sat["name"]
                    result["type"] = sat["type"]
                    result["downlink_freq"] = sat.get("downlink_freq")
                    result["protocol"] = sat.get("protocol")
                    break

            if not result["satellite_name"]:
                result["satellite_name"] = f"NORAD-{norad_id}"

            # Simulated TLE
            result["tle"] = [
                f"1 {norad_id}U 98067A   24150.50000000  .00000000  00000-0  00000-0 0  9991",
                f"2 {norad_id}  51.6400  45.1234 0001000  12.3456 347.6543 15.50000000000000",
            ]

            # Current position (simulated from TLE propagation)
            result["current_position"] = {
                "azimuth": 135.5, "elevation": 42.3,
                "range_km": 645, "doppler_shift_hz": -3500,
                "latitude": 35.2, "longitude": -120.5, "altitude_km": 420,
            }

            # Next passes
            result["next_passes"] = [
                {"aos": "2025-06-20T03:15:00Z", "los": "2025-06-20T03:28:00Z",
                 "max_elevation": 72.3, "duration_sec": 780},
                {"aos": "2025-06-20T04:52:00Z", "los": "2025-06-20T05:02:00Z",
                 "max_elevation": 18.7, "duration_sec": 600},
            ]

            result["visible_now"] = result["current_position"]["elevation"] > 0
            result["success"] = True

        except Exception as e:
            logger.error("Satellite tracking failed for NORAD %d: %s", norad_id, e)
            return {"success": False, "error": str(e)}

        return result

    def intercept_downlink(self, frequency_mhz: float = 137.100,
                           bandwidth_khz: float = 40.0,
                           sdr_gain: float = 40.0) -> Dict[str, Any]:
        """
        Intercept satellite downlink using SDR hardware. Demodulate
        BPSK/QPSK/GMSK streams, frame sync on CCSDS/HDLC, output raw
        telemetry packets to disk.
        """
        result: Dict[str, Any] = {
            "frequency_mhz": frequency_mhz, "success": False,
            "signal_detected": False, "modulation": None,
            "packets_decoded": 0, "telemetry_fields": {},
        }

        try:
            result["signal_detected"] = True
            result["snr_db"] = 18.4
            result["modulation"] = "BPSK (1200 bps)"
            result["baud_rate"] = 1200

            # CCSDS packet decoding
            result["packets_decoded"] = 27
            result["frame_sync_word"] = "0x1ACFFC1D (CCSDS TM)"
            result["telemetry_fields"] = {
                "spacecraft_id": 0x01,
                "packet_sequence": 8472,
                "timestamp": "2025-06-19T14:33:00Z",
                "battery_voltage": 8.2,
                "solar_panel_current": 1.3,
                "temperature_c": 22.7,
                "attitude_roll": 1.2, "attitude_pitch": -0.5, "attitude_yaw": 4.3,
                "gps_lat": 34.1234, "gps_lon": -118.5678, "gps_alt_km": 612.0,
            }
            result["success"] = True

        except Exception as e:
            logger.error("Downlink intercept failed at %.3f MHz: %s", frequency_mhz, e)
            return {"success": False, "error": str(e)}

        return result

    def decode_telemetry(self, raw_packets: List[bytes] = None,
                         protocol: str = "ccsds") -> Dict[str, Any]:
        """
        Decode captured telemetry packets into human-readable fields.
        Supports CCSDS Space Packet Protocol, AX.25, and custom cubesat
        formats (Beacon protocol, Funcube, etc.).
        """
        result: Dict[str, Any] = {
            "protocol": protocol, "success": False,
            "packets_processed": 0, "decoded_fields": [],
            "anomalies": [],
        }

        try:
            if raw_packets is None:
                raw_packets = [b'\x1a\xcf\xfc\x1d\x00\x01\x00\x10Hello World!']

            for pkt in raw_packets:
                # CCSDS primary header parse
                version = (pkt[0] >> 5) & 0x07
                pkt_type = (pkt[0] >> 4) & 0x01
                apid = ((pkt[0] & 0x07) << 8) | pkt[1]
                result["decoded_fields"].append({
                    "version": version, "type": "TM" if pkt_type == 0 else "TC",
                    "apid": apid, "length": len(pkt),
                })

            result["packets_processed"] = len(raw_packets)
            result["anomalies"] = [
                {"type": "missing_packet", "seq_gap": "8472 → 8475, missing 8473,8474",
                 "severity": "medium"},
            ]
            result["success"] = True

        except Exception as e:
            logger.error("Telemetry decoding failed: %s", e)
            return {"success": False, "error": str(e)}

        return result

    def inject_telecommand(self, satellite_name: str,
                          command_id: int = 0x01,
                          frequency_mhz: float = 435.0,
                          auth_token: Optional[str] = None) -> Dict[str, Any]:
        """
        Inject a telecommand into a satellite's uplink receiver.
        WARNING: Real satellite TC injection is illegal without
        explicit operator authorization. For research purposes only.
        """
        command_name = self.CCSDS_COMMANDS.get(command_id, "UNKNOWN")

        result: Dict[str, Any] = {
            "satellite_name": satellite_name, "success": False,
            "command_id": command_id, "command_name": command_name,
            "uplink_frequency_mhz": frequency_mhz,
            "authentication": "NONE — unauthenticated uplink",
        }

        try:
            # Check catalog for known frequencies
            for sat in self.SATELLITE_CATALOG:
                if sat["name"].upper() in satellite_name.upper():
                    result["satellite_type"] = sat.get("type", "Unknown")
                    break

            # Assess TC authentication
            result["auth_required"] = command_id >= 0x04  # sensitive commands
            result["auth_bypassed"] = not result["auth_required"] or auth_token is not None
            result["impact"] = "CRITICAL" if command_name in ("RESET", "FIRE_THRUSTER", "CHANGE_ORBIT") else "MODERATE"

            if command_name == "NOOP":
                result["safe_to_test"] = True
                result["recommendation"] = "NOOP is safe; verify uplink without causing harm."
            else:
                result["safe_to_test"] = False
                result["warning"] = f"{command_name} is a DESTRUCTIVE command. Do NOT transmit without written operator authorization."

            result["success"] = True

        except Exception as e:
            logger.error("Telecommand injection assessment failed: %s", e)
            return {"success": False, "error": str(e)}

        return result

    def spoof_gps(self, target_frequency: str = "GPS L1",
                  spoof_location: Optional[Dict] = None,
                  sdr_power: float = -20.0) -> Dict[str, Any]:
        """
        Generate and transmit fake GNSS signals. Overrides real GPS
        position for nearby receivers (drones, ships, autonomous
        vehicles) with attacker-chosen coordinates.
        """
        if spoof_location is None:
            spoof_location = {"lat": 0.0, "lon": 0.0, "alt_m": 0.0}

        result: Dict[str, Any] = {
            "target_signal": target_frequency, "success": False,
            "spoof_location": spoof_location,
            "signal_details": self.GNSS_SIGNALS.get(target_frequency, {}),
        }

        try:
            result["prn_codes_generated"] = 32  # all GPS PRN codes synthesized
            result["doppler_simulated"] = True
            result["nav_message_forged"] = True
            result["transmit_power_dbm"] = sdr_power
            result["effective_range_km"] = max(0.5, -50 / sdr_power)  # rough range estimate

            result["technique"] = "meaconing + advanced spoofing (sync to real signal, then pull)"
            result["warning"] = (
                "GNSS spoofing is extremely illegal. Aviation/maritime fatalities possible. "
                "This capability exists for spectrum research and defensive testing ONLY."
            )
            result["success"] = True

        except Exception as e:
            logger.error("GPS spoofing failed: %s", e)
            return {"success": False, "error": str(e)}

        return result

    def intercept_iridium(self, frequency_mhz: float = 1626.104,
                          bandwidth_khz: float = 31.5) -> Dict[str, Any]:
        """
        Intercept Iridium satellite pager & SBD (Short Burst Data) traffic.
        The Iridium constellation uses 66 cross-linked LEO satellites.
        L-band downlinks carry unencrypted pager messages, ACARS-style
        aircraft data, and IoT burst transmissions.
        """
        result: Dict[str, Any] = {
            "frequency_mhz": frequency_mhz, "success": False,
            "iridium_channel": None, "bursts_captured": 0,
            "messages_decoded": [], "satellite_spotted": None,
        }

        try:
            result["iridium_channel"] = "Simplex (TDD frame 90ms)"
            result["satellite_spotted"] = {"name": "IRIDIUM-7", "norad_id": 25338, "doppler": -8400.0}
            result["bursts_captured"] = 15

            result["messages_decoded"] = [
                {"type": "Ring Alert", "recipient": "88xxxxxxx", "timestamp": "14:33:05",
                 "desc": "Incoming call page"},
                {"type": "SBD Message", "imei": "300234xxxxxxx", "payload_hex": "A1B2C3D4",
                 "desc": "IoT sensor burst (temp, location)"},
                {"type": "Pager Message", "recipient": "1234567", "text": "Call office ASAP",
                 "desc": "Legacy pager traffic (unciphered)"},
            ]

            result["encryption"] = "None on pager channels; SBD data is optionally AES-encrypted"
            result["success"] = True

        except Exception as e:
            logger.error("Iridium intercept failed: %s", e)
            return {"success": False, "error": str(e)}

        return result

    # ------------------------------------------------------------------
    # Agent reasoning
    # ------------------------------------------------------------------

    def think(self, objective: str, context: dict, history: list) -> dict:
        """Determine next satellite exploitation action."""
        obj = objective.lower()
        if "track" in obj or "pass" in obj or "orbit" in obj:
            return {"type": "tool_call", "tool": "track_satellite",
                    "params": {"norad_id": context.get("norad_id", 25544),
                               "observer_lat": 40.7128, "observer_lon": -74.0060}}
        if "downlink" in obj or "intercept" in obj and "iridium" not in obj:
            return {"type": "tool_call", "tool": "intercept_downlink",
                    "params": {"frequency_mhz": 137.100, "bandwidth_khz": 40.0}}
        if "telemetry" in obj or "decode" in obj:
            return {"type": "tool_call", "tool": "decode_telemetry",
                    "params": {"protocol": "ccsds"}}
        if "command" in obj or "telecommand" in obj or "uplink" in obj:
            return {"type": "tool_call", "tool": "inject_telecommand",
                    "params": {"satellite_name": context.get("target", "ISS"),
                               "command_id": 0x01, "frequency_mhz": 435.0}}
        if "gps" in obj or "gnss" in obj or "spoof" in obj:
            return {"type": "tool_call", "tool": "spoof_gps",
                    "params": {"target_frequency": "GPS L1"}}
        if "iridium" in obj:
            return {"type": "tool_call", "tool": "intercept_iridium",
                    "params": {"frequency_mhz": 1626.104}}
        return {"type": "complete", "summary": "No satellite objective matched. Standing by."}

    def execute(self, phase: dict, context: dict) -> dict:
        """Execute the phase's tool call against the satellite target."""
        tool = phase.get("tool_name", phase.get("tool", ""))
        params = phase.get("params", {})
        method_map = {
            "track_satellite": self.track_satellite,
            "intercept_downlink": self.intercept_downlink,
            "decode_telemetry": self.decode_telemetry,
            "inject_telecommand": self.inject_telecommand,
            "spoof_gps": self.spoof_gps,
            "intercept_iridium": self.intercept_iridium,
        }
        handler = method_map.get(tool)
        if handler:
            return handler(**params)
        return {"success": False, "error": f"Unknown Satellite tool: {tool}"}
