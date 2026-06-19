"""
gpu_manager.py — GPU resource management for hash cracking workloads.

Wraps hashcat and john-the-ripper invocations with GPU device detection
(via nvidia-smi / rocm-smi), job tracking, and structured result output.

Designed for the PhantomStrike `_Lazy` singleton pattern — instantiated
once in singletons.py and shared across blueprints.
"""

import json
import logging
import os
import shutil
import subprocess
import threading
import time
import uuid
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class GPUManager:
    """GPU resource manager for hashcat and john-the-ripper.

    Detects available GPUs on initialisation and provides convenient
    methods for running hashcat / john jobs with progress tracking.

    Attributes:
        gpus (list):  list of detected GPU device dicts, each with keys
                      ``"index"``, ``"name"``, ``"vendor"``, ``"memory_mb"``.
        jobs (dict):  ``{job_id: job_metadata}`` for active and completed jobs.
    """

    def __init__(self) -> None:
        self.gpus = self._detect_gpus()
        self.jobs: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.Lock()
        logger.info("gpu_manager: detected %d GPU(s)", len(self.gpus))

    # ── GPU detection ──────────────────────────────────────────────────────────

    def _detect_gpus(self) -> List[Dict[str, Any]]:
        """Probe the system for available GPUs.

        Tries nvidia-smi first (NVIDIA), then rocm-smi (AMD), and falls
        back to lspci for basic enumeration.  Returns a list of device
        dictionaries suitable for display and tool dispatch.
        """
        gpus: List[Dict[str, Any]] = []

        # ── NVIDIA (nvidia-smi) ────────────────────────────────────────────
        nvidia_smi = shutil.which("nvidia-smi")
        if nvidia_smi:
            try:
                result = subprocess.run(
                    [
                        nvidia_smi,
                        "--query-gpu=index,name,memory.total",
                        "--format=csv,noheader,nounits",
                    ],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                for line in result.stdout.strip().splitlines():
                    parts = [p.strip() for p in line.split(",")]
                    if len(parts) >= 3:
                        gpus.append(
                            {
                                "index": int(parts[0]),
                                "name": parts[1],
                                "vendor": "nvidia",
                                "memory_mb": int(parts[2]),
                            }
                        )
                if gpus:
                    logger.debug("gpu_manager: nvidia-smi found %d GPU(s)", len(gpus))
                    return gpus
            except Exception as exc:
                logger.debug("gpu_manager: nvidia-smi probe failed — %s", exc)

        # ── AMD (rocm-smi) ─────────────────────────────────────────────────
        rocm_smi = shutil.which("rocm-smi")
        if rocm_smi:
            try:
                result = subprocess.run(
                    [rocm_smi, "--showid", "--showproductname", "--csv"],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                for line in result.stdout.strip().splitlines():
                    if line.startswith("GPU"):
                        continue  # skip header
                    parts = [p.strip() for p in line.split(",")]
                    if len(parts) >= 3:
                        gpus.append(
                            {
                                "index": int(parts[1]) if parts[1].isdigit() else len(gpus),
                                "name": parts[2],
                                "vendor": "amd",
                                "memory_mb": 0,  # rocm-smi csv doesn't include memory easily
                            }
                        )
                if gpus:
                    logger.debug("gpu_manager: rocm-smi found %d GPU(s)", len(gpus))
                    return gpus
            except Exception as exc:
                logger.debug("gpu_manager: rocm-smi probe failed — %s", exc)

        # ── Fallback: lspci ────────────────────────────────────────────────
        try:
            result = subprocess.run(
                ["lspci"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            for line in result.stdout.splitlines():
                low = line.lower()
                if "vga" in low or "3d" in low or "display" in low:
                    gpus.append(
                        {
                            "index": len(gpus),
                            "name": line.split(": ", 1)[-1] if ": " in line else line,
                            "vendor": "unknown",
                            "memory_mb": 0,
                        }
                    )
            if gpus:
                logger.debug("gpu_manager: lspci fallback found %d device(s)", len(gpus))
        except Exception as exc:
            logger.debug("gpu_manager: lspci probe failed — %s", exc)

        return gpus

    # ── Hashcat ───────────────────────────────────────────────────────────────

    def run_hashcat(
        self,
        hash_file: str,
        wordlist: str,
        attack_mode: int = 0,
        rules: Optional[str] = None,
        hash_type: str = "auto",
        gpu_device: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Run hashcat against *hash_file* using *wordlist*.

        Args:
            hash_file:    path to a file containing the target hash(es).
            wordlist:     path to a wordlist file.
            attack_mode:  hashcat attack mode (0=straight, 1=combination, 3=mask, 6=hybrid, etc.).
            rules:        optional path to a rules file for rule-based attacks.
            hash_type:    hashcat hash-type identifier (number or name; default "auto").
            gpu_device:   GPU device index to use (None = let hashcat pick).

        Returns:
            A dict with keys ``"job_id"``, ``"tool"``, ``"status"``, and
            ``"progress"``.  Results are appended asynchronously as the
            job runs.
        """
        hashcat_bin = shutil.which("hashcat")
        if not hashcat_bin:
            return {"error": "hashcat not found on PATH — install hashcat first"}

        if not os.path.isfile(hash_file):
            return {"error": f"hash file not found: {hash_file}"}

        if not os.path.isfile(wordlist):
            return {"error": f"wordlist not found: {wordlist}"}

        job_id = f"hc_{uuid.uuid4().hex[:10]}"
        cmd = [
            hashcat_bin,
            "-m", str(hash_type),
            "-a", str(attack_mode),
            "--status",
            "--status-timer", "5",
            "--outfile", f"/tmp/{job_id}.pot",
            "--potfile-path", f"/tmp/{job_id}.pot",
            hash_file,
            wordlist,
        ]
        if rules:
            cmd.extend(["-r", rules])
        if gpu_device is not None:
            cmd.extend(["-d", str(gpu_device)])

        self._register_job(job_id, "hashcat", cmd)

        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                env=os.environ.copy(),
            )
        except Exception as exc:
            self._fail_job(job_id, str(exc))
            return self.jobs[job_id]

        # Run in background thread to capture output.
        threading.Thread(
            target=self._capture_output,
            args=(job_id, proc),
            daemon=True,
        ).start()

        return self.jobs[job_id]

    # ── John the Ripper ───────────────────────────────────────────────────────

    def run_john(
        self,
        hash_file: str,
        wordlist: Optional[str] = None,
        rules: Optional[str] = None,
        hash_format: str = "auto",
    ) -> Dict[str, Any]:
        """Run john-the-ripper against *hash_file*.

        Args:
            hash_file:    path to a file containing the target hash(es).
            wordlist:     optional path to a wordlist file (defaults to john's built-in).
            rules:        optional rules identifier (e.g. ``"Single"``, ``"Wordlist"``).
            hash_format:  john format string (default ``"auto"``).

        Returns:
            A dict with ``"job_id"``, ``"tool"``, ``"status"``, and
            ``"progress"``.  Results accumulate as the job runs.
        """
        john_bin = shutil.which("john")
        if not john_bin:
            return {"error": "john not found on PATH — install john-the-ripper first"}

        if not os.path.isfile(hash_file):
            return {"error": f"hash file not found: {hash_file}"}

        job_id = f"jr_{uuid.uuid4().hex[:10]}"
        cmd = [john_bin, f"--format={hash_format}", hash_file]

        if wordlist:
            cmd.extend([f"--wordlist={wordlist}"])
        if rules:
            cmd.extend([f"--rules={rules}"])

        self._register_job(job_id, "john", cmd)

        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                env=os.environ.copy(),
            )
        except Exception as exc:
            self._fail_job(job_id, str(exc))
            return self.jobs[job_id]

        threading.Thread(
            target=self._capture_output,
            args=(job_id, proc),
            daemon=True,
        ).start()

        return self.jobs[job_id]

    # ── Job tracking ──────────────────────────────────────────────────────────

    def _register_job(self, job_id: str, tool: str, cmd: List[str]) -> None:
        with self._lock:
            self.jobs[job_id] = {
                "job_id": job_id,
                "tool": tool,
                "command": " ".join(cmd),
                "status": "running",
                "started_at": time.time(),
                "progress": 0.0,
                "output": [],
                "cracked": [],
                "error": None,
            }

    def _fail_job(self, job_id: str, error: str) -> None:
        with self._lock:
            if job_id in self.jobs:
                self.jobs[job_id]["status"] = "failed"
                self.jobs[job_id]["error"] = error
                self.jobs[job_id]["completed_at"] = time.time()

    def _capture_output(self, job_id: str, proc: subprocess.Popen) -> None:
        """Read stdout lines from *proc* and update the job dict in real time."""
        try:
            for line in proc.stdout:
                line = line.strip()
                if not line:
                    continue
                with self._lock:
                    if job_id in self.jobs:
                        self.jobs[job_id]["output"].append(line)
                        # Attempt to detect a cracked hash from hashcat / john output.
                        if ":" in line and not line.startswith(("Session", "Status", "Progress", "Hash", "Warning", "Approaching")):
                            self.jobs[job_id]["cracked"].append(line)
                        # Naive progress parse from hashcat status lines.
                        if "Progress" in line:
                            try:
                                import re
                                m = re.search(r"(\d+)%", line)
                                if m:
                                    self.jobs[job_id]["progress"] = float(m.group(1))
                            except Exception:
                                pass
            proc.wait()
            with self._lock:
                if job_id in self.jobs:
                    self.jobs[job_id]["status"] = "completed" if proc.returncode == 0 else "failed"
                    self.jobs[job_id]["completed_at"] = time.time()
                    if proc.returncode != 0 and not self.jobs[job_id]["error"]:
                        self.jobs[job_id]["error"] = f"exit code {proc.returncode}"
        except Exception as exc:
            logger.warning("gpu_manager: output capture error for %s — %s", job_id, exc)
            self._fail_job(job_id, str(exc))

    def get_job_status(self, job_id: str) -> Dict[str, Any]:
        """Return the current job metadata dict, or an empty dict if unknown."""
        with self._lock:
            return self.jobs.get(job_id, {}).copy()

    def list_jobs(self) -> List[Dict[str, Any]]:
        """Return a summary list of all known jobs (running and completed)."""
        with self._lock:
            return [
                {
                    "job_id": j["job_id"],
                    "tool": j["tool"],
                    "status": j["status"],
                    "progress": j["progress"],
                    "cracked_count": len(j.get("cracked", [])),
                    "started_at": j.get("started_at"),
                }
                for j in self.jobs.values()
            ]

    @property
    def gpu_count(self) -> int:
        """Number of GPUs detected."""
        return len(self.gpus)
