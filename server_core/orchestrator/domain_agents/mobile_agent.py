"""
Mobile Agent — Mobile Application & Device Exploitation Specialist.

Covers Android (APK) and iOS (IPA) reverse engineering, runtime
instrumentation, SSL pinning bypass, root/jailbreak detection defeat,
keychain extraction, deep link exploitation, and API interception.

Elite knowledge: Frida, Objection, jadx, apktool, MobSF, iOS/Android
security models, Keychain/Keystore internals, App Transport Security.
"""

import logging
import random
from datetime import datetime
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class MobileAgent:
    """Nation-state grade mobile exploitation — APK/IPA dissection, runtime
    hooking, certificate pinning defeat, and device-level credential theft.

    Persona: The ghost in the app store. I don't just reverse engineer your
    mobile binary — I own its runtime, strip its TLS, and walk out with every
    secret it ever trusted. Your cert pinning? Cute. Your root detection?
    Already patched. Your keychain? Mine.
    """

    agent_type = "mobile"

    # --- Elite knowledge: common Android security providers ---
    ANDROID_SSL_PINNING_LIBS = [
        "okhttp3.CertificatePinner",
        "TrustManager (custom)",
        "Google Play Integrity",
        "SafetyNet Attestation",
        "DexGuard / ProGuard obfuscated pinning",
        "SSLPinning (custom X509TrustManager)",
    ]

    IOS_SSL_PINNING_METHODS = [
        "NSURLSession didReceiveChallenge",
        "Alamofire ServerTrustPolicy",
        "TrustKit pinning validator",
        "AFNetworking AFSecurityPolicy",
        "URLSessionDelegate with custom challenge handler",
    ]

    ROOT_DETECTION_TECHNIQUES = [
        "test-keys (Build.TAGS check)",
        "Superuser.apk presence",
        "su binary in PATH",
        "BusyBox detection",
        "Magisk mount inspection",
        "Xposed / EdXposed framework hooks",
        "Frida server port scanning (default 27042)",
    ]

    JAILBREAK_DETECTION_TECHNIQUES = [
        "Cydia.app URL scheme check",
        "/Applications/Cydia.app existence",
        "fork() sandbox escape check",
        "dyld insert libraries inspection",
        "Suspicious file paths (/private/var/lib/apt)",
        "Frida / Objection port detection",
    ]

    def __init__(self, hive_mind=None, tool_bridge=None):
        self.hive_mind = hive_mind
        self.tool_bridge = tool_bridge
        self._analyzed_targets: List[Dict] = []
        self._hooked_sessions: Dict[str, Dict] = {}

    # ------------------------------------------------------------------
    # APK Analysis
    # ------------------------------------------------------------------

    def analyze_apk(self, apk_path: str, deep_scan: bool = True) -> Dict:
        """Decompile and analyze an Android APK using jadx + apktool.

        Extracts manifest permissions, exported components, hardcoded secrets,
        native library symbols, and certificate fingerprints. Deep scan mode
        traces all network call sites and identifies crypto weaknesses.

        Tools: jadx, apktool, dex2jar, CFR, MobSF, APKLeaks
        """
        logger.info("[MobileAgent] Analyzing APK: %s (deep=%s)", apk_path, deep_scan)

        # Simulated jadx decompilation result
        result = {
            "success": True,
            "package": "com.example.target",
            "version_name": "4.2.1",
            "version_code": 421,
            "min_sdk": 26,
            "target_sdk": 34,
            "permissions": [
                "android.permission.INTERNET",
                "android.permission.ACCESS_FINE_LOCATION",
                "android.permission.READ_CONTACTS",
                "android.permission.CAMERA",
            ],
            "exported_components": {
                "activities": ["com.example.MainActivity (exported)", "com.example.DeepLinkActivity (exported, intent-filter)"],
                "services": ["com.example.PushService (exported)"],
                "receivers": ["com.example.BootReceiver (exported)"],
                "providers": ["com.example.FileProvider (exported, path traversal risk)"],
            },
            "certificate": {
                "signature_algorithm": "SHA256withRSA",
                "serial": "0x7a3b9c1d",
                "fingerprint_sha256": "A1B2C3D4E5F6...",
                "valid_until": "2027-06-15",
            },
            "hardcoded_secrets": [
                {"type": "API_KEY", "value": "sk_live_***REDACTED***", "file": "res/values/strings.xml"},
                {"type": "AWS_SECRET", "value": "***REDACTED***", "file": "com/example/config/Constants.smali"},
            ] if deep_scan else [],
            "native_libs": ["libnative-lib.so (armeabi-v7a)", "libssl-bypass.so (arm64-v8a)"],
            "proguard_obfuscation": True,
            "note": "[SIMULATED] Replace with real jadx + apktool + MobSF pipeline",
        }

        self._analyzed_targets.append({"path": apk_path, "type": "apk", "timestamp": datetime.now().isoformat()})
        if self.hive_mind:
            self.hive_mind.add_alert({"type": "mobile_apk_analyzed", "package": result["package"], "threat_level": 0})

        return result

    # ------------------------------------------------------------------
    # IPA Analysis
    # ------------------------------------------------------------------

    def analyze_ipa(self, ipa_path: str, decrypt_first: bool = True) -> Dict:
        """Analyze an iOS IPA — decrypt FairPlay if needed, extract Info.plist,
        enumerate Objective-C classes, and find ATS exceptions.

        Tools: ipatool, class-dump, Hopper, Ghidra, frida-ios-dump
        """
        logger.info("[MobileAgent] Analyzing IPA: %s (decrypt=%s)", ipa_path, decrypt_first)

        result = {
            "success": True,
            "bundle_id": "com.example.iosapp",
            "version": "3.1.0",
            "minimum_os": "15.0",
            "bitcode": False,
            "ats_exceptions": {
                "NSAllowsArbitraryLoads": False,
                "NSExceptionDomains": ["api.example.com"],
            },
            "url_schemes": ["exampleapp://", "exampleauth://"],
            "queries_schemes": ["fb://", "twitter://"],
            "objc_classes_of_interest": [
                "KeychainManager",
                "NetworkController",
                "SecureStorage",
            ],
            "frameworks": ["Alamofire", "TrustKit", "FirebaseAuth"],
            "encrypted": False if decrypt_first else True,
            "note": "[SIMULATED] Replace with real ipatool + class-dump + Hopper/IDA analysis",
        }

        self._analyzed_targets.append({"path": ipa_path, "type": "ipa", "timestamp": datetime.now().isoformat()})
        return result

    # ------------------------------------------------------------------
    # SSL Pinning Bypass
    # ------------------------------------------------------------------

    def bypass_ssl_pinning(self, target_app: str, platform: str = "android") -> Dict:
        """Universal SSL pinning bypass using Frida scripts.

        Android: Hooks javax.net.ssl.SSLContext, okhttp3.CertificatePinner,
        and TrustManagerImpl checkServerTrusted.
        iOS: Hooks SecTrustEvaluate, NSURLSession delegate, Alamofire
        ServerTrustPolicy.

        Tools: Frida, Objection (android sslpinning disable / ios sslpinning disable)
        """
        logger.info("[MobileAgent] Bypassing SSL pinning for %s on %s", target_app, platform)

        scripts = {
            "android": [
                "frida -U -l ssl_pinning_bypass.js -f {pkg} --no-pause",
                "objection -g {pkg} android sslpinning disable",
            ],
            "ios": [
                "frida -U -l ios_ssl_bypass.js -f {bundle_id}",
                "objection -g {bundle_id} ios sslpinning disable",
            ],
        }

        result = {
            "success": True,
            "platform": platform,
            "target": target_app,
            "scripts_deployed": scripts.get(platform, []),
            "intercepted_traffic": True,
            "mitm_proxy": "http://127.0.0.1:8080 (Burp Suite / mitmproxy)",
            "certificate_installed": True,
            "warnings": [
                "Ensure Frida server is running on device (frida-server)",
                "Some apps use custom pinning — may require manual hook writing",
                "Flutter apps use dart:io HttpClient — different bypass needed",
            ],
            "note": "[SIMULATED] Deploy real Frida scripts and verify with mitmproxy",
        }

        if self.hive_mind:
            self.hive_mind.add_alert({"type": "ssl_pinning_bypassed", "target": target_app, "threat_level": 0})

        return result

    # ------------------------------------------------------------------
    # Root / Jailbreak Detection Bypass
    # ------------------------------------------------------------------

    def bypass_root_detection(self, target_app: str, platform: str = "android") -> Dict:
        """Defeat root/jailbreak detection to allow running on compromised devices.

        Android: Hook RootBeer, SafetyNet, MagiskHide, su binary checks.
        iOS: Hook fileExistsAtPath, fork(), URL scheme checks, dyld inspection.

        Tools: Frida, Magisk (with DenyList), Shamiko, Liberty Lite (iOS)
        """
        logger.info("[MobileAgent] Bypassing root detection for %s on %s", target_app, platform)

        bypass_methods = {
            "android": {
                "frida_hooks": ["RootBeer.isRooted()", "su binary check", "Build.TAGS check", "Magisk mount path check"],
                "magisk_modules": ["Universal SafetyNet Fix", "Shamiko (Zygisk)"],
                "xposed_modules": ["RootCloak", "XPrivacyLua"],
            },
            "ios": {
                "frida_hooks": ["-[NSFileManager fileExistsAtPath:]", "fork() syscall", "dyld_get_image_name"],
                "jailbreak_bypass_tweaks": ["Liberty Lite", "Shadow", "A-Bypass"],
            },
        }

        result = {
            "success": True,
            "platform": platform,
            "target": target_app,
            "methods": bypass_methods.get(platform, {}),
            "frida_script": "root_bypass.js (generated)",
            "verified": True,
            "note": "[SIMULATED] Real bypass requires app-specific hook development",
        }

        return result

    # ------------------------------------------------------------------
    # Runtime Hooking
    # ------------------------------------------------------------------

    def hook_runtime(self, target_app: str, hook_spec: Optional[Dict] = None) -> Dict:
        """Generic runtime hook deployment via Frida.

        Hooks target methods (encryption, auth, network) to intercept
        parameters, return values, and modify execution flow on the fly.

        Tools: Frida, Objection, Frida-tools, frida-android-repinning
        """
        logger.info("[MobileAgent] Deploying runtime hooks on %s", target_app)

        session_id = f"hook_{random.randint(10000, 99999)}"
        default_hooks = [
            "javax.crypto.Cipher.doFinal() — intercept plaintext/ciphertext",
            "java.security.MessageDigest.digest() — capture hashed values",
            "android.util.Base64.encodeToString() — capture encoded secrets",
            "okhttp3.Request.Builder.build() — log all HTTP requests",
            "NSURLSession dataTaskWithRequest (iOS) — intercept network",
        ]

        hook_result = {
            "session_id": session_id,
            "target": target_app,
            "active_hooks": hook_spec.get("hooks", default_hooks) if hook_spec else default_hooks,
            "output_destination": f"/tmp/frida_hook_{session_id}.log",
            "frida_command": f"frida -U -l hook_script.js -f {target_app} --no-pause",
        }

        self._hooked_sessions[session_id] = hook_result

        result = {
            "success": True,
            "session": hook_result,
            "note": f"[SIMULATED] Hook session {session_id} ready. Use Frida to spawn and trace.",
        }

        return result

    # ------------------------------------------------------------------
    # Keychain / Keystore Extraction
    # ------------------------------------------------------------------

    def extract_keychain(self, target_app: str, platform: str = "ios") -> Dict:
        """Extract secrets from iOS Keychain or Android Keystore.

        iOS: Dump keychain items accessible to the app's keychain access group.
        Android: Extract entries from AndroidKeyStore (API 18+) via Frida hooks
        or root access to /data/misc/keystore.

        Tools: keychain_dumper (iOS), Frida scripts, objection keychain dump
        """
        logger.info("[MobileAgent] Extracting keychain/keystore for %s on %s", target_app, platform)

        if platform == "ios":
            extracted = {
                "keychain_items": [
                    {"service": "com.example.iosapp", "account": "user_token", "data": "***REDACTED_JWT***"},
                    {"service": "com.example.iosapp", "account": "refresh_token", "data": "***REDACTED***"},
                    {"service": "appleid", "account": "user@example.com", "data": "***REDACTED***"},
                ],
                "access_group": "ABCDEF1234.com.example.iosapp",
                "tool": "keychain_dumper (entitlement: keychain-access-groups)",
            }
        else:
            extracted = {
                "keystore_entries": [
                    {"alias": "user_auth_key", "type": "RSA/EC", "creation_date": "2024-01-15T10:30:00Z"},
                    {"alias": "api_encryption_key", "type": "AES", "creation_date": "2024-03-02T14:00:00Z"},
                ],
                "keymaster_blobs": "/data/misc/keystore/user_0/ (requires root)",
                "tool": "Frida script: android-keystore-audit.js",
            }

        result = {
            "success": True,
            "platform": platform,
            "target_app": target_app,
            "data": extracted,
            "warning": "Keychain access requires matching signing certificate / entitlements on iOS",
            "note": "[SIMULATED] Real extraction needs device-level access and app-specific entitlements",
        }

        if self.hive_mind:
            self.hive_mind.add_alert({"type": "keychain_extracted", "target": target_app, "platform": platform, "threat_level": 0})

        return result

    # ------------------------------------------------------------------
    # Deep Link Exploitation
    # ------------------------------------------------------------------

    def exploit_deep_links(self, target_app: str, platform: str = "android") -> Dict:
        """Discover and exploit deep link / URL scheme handlers.

        Fuzz custom URL schemes with parameter injection, path traversal,
        and intent redirection. Test for:
        - Arbitrary component launch via intent URLs
        - Fragment injection / tab-jacking
        - OAuth redirect URI hijacking
        - JavaScript bridge abuse (WebView.addJavascriptInterface)

        Tools: adb (am start), frida, objection, MobSF deep link tester
        """
        logger.info("[MobileAgent] Fuzzing deep links for %s on %s", target_app, platform)

        discovered_links = [
            {"scheme": "exampleapp://", "host": "open", "params": ["id", "type"], "risk": "medium"},
            {"scheme": "exampleauth://", "host": "callback", "params": ["code", "state", "redirect_uri"], "risk": "high"},
            {"scheme": "exampleapp://", "host": "webview", "params": ["url"], "risk": "critical — JS bridge abuse possible"},
        ]

        vulnerabilities = [
            {
                "link": "exampleapp://webview?url=javascript:alert(1)",
                "type": "JS Bridge Injection",
                "severity": "critical",
                "description": "WebView loads arbitrary URLs with JavaScript interface enabled",
            },
            {
                "link": "exampleauth://callback?redirect_uri=https://attacker.com",
                "type": "OAuth Redirect Hijacking",
                "severity": "high",
                "description": "redirect_uri parameter not validated against allowlist",
            },
        ]

        result = {
            "success": True,
            "target": target_app,
            "discovered_schemes": ["exampleapp://", "exampleauth://"],
            "deep_links_found": discovered_links,
            "vulnerabilities": vulnerabilities if platform == "android" else [],
            "adb_commands": [f"adb shell am start -W -a android.intent.action.VIEW -d '{link['scheme']}{link['host']}' {target_app}" for link in discovered_links],
            "note": "[SIMULATED] Real fuzzing requires adb + custom deep link fuzzer script",
        }

        return result

    # ------------------------------------------------------------------
    # API Call Interception
    # ------------------------------------------------------------------

    def intercept_api_calls(self, target_app: str, filter_pattern: Optional[str] = None) -> Dict:
        """Man-in-the-middle all API traffic from the mobile app.

        Sets up mitmproxy/Burp Suite, routes device traffic through proxy,
        and captures all REST/GraphQL/gRPC calls with request/response bodies.
        Decodes protocol buffers, unpacks message pack, and demangles
        custom encodings.

        Tools: mitmproxy, Burp Suite, Wireshark, Frida (for custom cert install)
        """
        logger.info("[MobileAgent] Intercepting API calls for %s (filter=%s)", target_app, filter_pattern)

        intercepted = [
            {
                "method": "POST",
                "url": "https://api.example.com/v2/auth/login",
                "request_body": '{"username":"user","password":"***","device_id":"android_abc123"}',
                "response_body": '{"access_token":"eyJ***REDACTED***","refresh_token":"***REDACTED***"}',
                "status": 200,
                "headers": {"Authorization": "Bearer eyJ***", "X-Device-Id": "android_abc123"},
            },
            {
                "method": "GET",
                "url": "https://api.example.com/v2/user/profile",
                "request_body": None,
                "response_body": '{"id":1234,"email":"user@example.com","role":"admin","company":"Target Corp"}',
                "status": 200,
                "headers": {"Authorization": "Bearer eyJ***"},
            },
            {
                "method": "POST",
                "url": "https://api.example.com/v2/data/export",
                "request_body": '{"format":"json","include_pii":true}',
                "response_body": '{"export_id":"exp_98765","status":"processing"}',
                "status": 202,
                "headers": {},
            },
        ]

        result = {
            "success": True,
            "target": target_app,
            "proxy": "127.0.0.1:8080",
            "calls_captured": len(intercepted),
            "intercepted_calls": intercepted,
            "api_base_url": "https://api.example.com",
            "auth_scheme": "Bearer JWT (HS256, no expiry check on server)",
            "graphql_endpoints": ["https://api.example.com/graphql"],
            "recommendation": "JWT tokens don't expire — persistent access possible",
            "note": "[SIMULATED] Real interception requires mitmproxy + device proxy config + CA cert install",
        }

        return result

    # ------------------------------------------------------------------
    # Agent Reasoning
    # ------------------------------------------------------------------

    def think(self, objective: str, context: dict, history: list) -> dict:
        """Decide next action based on objective and context."""
        if "ssl" in objective.lower() or "pinning" in objective.lower():
            return {"type": "tool_call", "tool": "bypass_ssl_pinning", "params": {"target_app": context.get("target_app", "unknown")}}
        if "apk" in objective.lower() or "android" in objective.lower():
            return {"type": "tool_call", "tool": "analyze_apk", "params": {"apk_path": context.get("apk_path", "/data/app/target.apk")}}
        if "keychain" in objective.lower() or "credential" in objective.lower():
            return {"type": "tool_call", "tool": "extract_keychain", "params": {"target_app": context.get("target_app", "unknown")}}
        return {"type": "complete", "summary": "Mobile agent standing by. Ready to dissect any app binary."}

    def execute(self, phase: dict, context: dict) -> dict:
        """Dispatch to correct handler based on phase parameters."""
        tool = phase.get("tool", phase.get("tool_name", ""))
        params = phase.get("params", phase.get("parameters", {}))
        method_map = {
            "analyze_apk": self.analyze_apk,
            "analyze_ipa": self.analyze_ipa,
            "bypass_ssl_pinning": self.bypass_ssl_pinning,
            "bypass_root_detection": self.bypass_root_detection,
            "hook_runtime": self.hook_runtime,
            "extract_keychain": self.extract_keychain,
            "exploit_deep_links": self.exploit_deep_links,
            "intercept_api_calls": self.intercept_api_calls,
        }
        handler = method_map.get(tool)
        if handler:
            try:
                return handler(**params)
            except Exception as e:
                return {"success": False, "error": str(e)}
        return {"success": False, "error": f"Unknown mobile tool: {tool}"}
