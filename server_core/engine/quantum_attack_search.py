"""
server_core/engine/quantum_attack_search.py

Quantum-Inspired Attack Space Search — Grover's Algorithm Simulation.

When the attack surface is vast and traditional pathfinding fails, this
engine leverages quantum-inspired amplitude amplification to collapse
the search space to the optimal attack vectors in sub-quadratic time.

Core Algorithm:
  - Grover-style amplitude amplification over attack path graphs
  - Oracle function construction from success criteria
  - Multi-iteration convergence with entanglement simulation
  - Batch parallel search across independent path sets
  - Oracular path scoring when success probabilities are ambiguous

Classes:
  QuantumAttackSearch     — main quantum search orchestrator
  QuantumState            — amplitude vector with metadata
  OracleFunction          — configurable success oracle
  PathAmplitude           — single path with its quantum amplitude
"""

from __future__ import annotations

import hashlib
import logging
import math
import random
import time
import uuid
from collections import defaultdict
from copy import deepcopy
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum, auto
from typing import Any, Callable, Dict, List, Optional, Sequence, Set, Tuple, Union

logger = logging.getLogger(__name__)

# ── Constants ──────────────────────────────────────────────────────────────────

# Maximum iterations before forced convergence (prevents infinite loops)
_MAX_GROVER_ITERATIONS = 200
# Minimum amplitude variance threshold for convergence detection
_CONVERGENCE_THRESHOLD = 0.001
# Default target success probability for oracle marking
_DEFAULT_TARGET_SUCCESS = 0.7
# Quantum entanglement decay factor per iteration
_ENTANGLEMENT_DECAY = 0.995
# Batch search parallelism factor
_BATCH_CONCURRENCY = 8

# ── Dataclasses ────────────────────────────────────────────────────────────────


class SearchDomain(Enum):
    """Domain classification for attack path search."""
    NETWORK = auto()
    APPLICATION = auto()
    SOCIAL = auto()
    PHYSICAL = auto()
    CLOUD = auto()
    HYBRID = auto()


@dataclass
class PathAmplitude:
    """Single attack path with its quantum amplitude and metadata."""
    path_id: str
    steps: List[str]
    estimated_success: float
    amplitude: float = 0.0
    marked: bool = False
    domain: SearchDomain = SearchDomain.NETWORK
    entanglement_partner: Optional[str] = None
    oracle_score: float = 0.0
    risk_level: float = 0.5

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class QuantumState:
    """Complete amplitude vector representing the quantum search state."""
    paths: List[PathAmplitude]
    iteration: int = 0
    convergence_delta: float = float('inf')
    converged: bool = False
    measurement_history: List[Dict[str, Any]] = field(default_factory=list)

    @property
    def size(self) -> int:
        return len(self.paths)

    @property
    def amplitudes(self) -> List[float]:
        return [p.amplitude for p in self.paths]


@dataclass
class OracleFunction:
    """Configurable oracle for marking promising attack paths."""
    target_success: float = _DEFAULT_TARGET_SUCCESS
    min_steps: int = 1
    max_steps: int = 50
    max_risk: float = 1.0
    required_domains: Optional[List[SearchDomain]] = None
    bonus_keywords: List[str] = field(default_factory=list)

    def evaluate(self, path: PathAmplitude) -> bool:
        """Return True if the path should be marked by the oracle."""
        if path.estimated_success < self.target_success:
            return False
        if len(path.steps) < self.min_steps:
            return False
        if len(path.steps) > self.max_steps:
            return False
        if path.risk_level > self.max_risk:
            return False
        if self.required_domains and path.domain not in self.required_domains:
            return False
        if self.bonus_keywords:
            step_text = " ".join(path.steps).lower()
            if not any(kw.lower() in step_text for kw in self.bonus_keywords):
                return False
        return True


# ── QuantumAttackSearch ────────────────────────────────────────────────────────


class QuantumAttackSearch:
    """Quantum-inspired attack path search using Grover's algorithm simulation.

    This is not a true quantum computer emulation — it's a classical
    simulation of quantum amplitude amplification applied to attack
    graph traversal. The exponential speedup of Grover's algorithm is
    approximated through iterative amplitude redistribution.

    Usage:
        qas = QuantumAttackSearch(hive_mind=hm)
        paths = [{'steps': ['...'], 'estimated_success': 0.8}, ...]
        ranked = qas.grover_search(paths, target_success=0.7)
        optimal = qas.find_optimal_path(paths, context={'budget': 'stealth'})
    """

    def __init__(self, hive_mind: Any = None):
        self.hive_mind = hive_mind
        self._search_history: List[QuantumState] = []
        self._oracle_cache: Dict[str, OracleFunction] = {}
        # ── operator persona: the quantum cartographer ──
        logger.debug("QuantumAttackSearch initialised — "
                     "amplitude manifold ready for collapse.")

    # ── Core Grover Search ──────────────────────────────────────────────────

    def grover_search(
        self,
        paths: List[Dict[str, Any]],
        target_success: float = _DEFAULT_TARGET_SUCCESS,
        max_iterations: int = _MAX_GROVER_ITERATIONS,
        oracle_fn: Optional[Callable[[Dict[str, Any]], bool]] = None,
    ) -> List[Dict[str, Any]]:
        """Execute Grover's amplitude amplification over attack paths.

        Args:
            paths: List of attack path dicts with at least 'estimated_success'.
            target_success: Threshold for oracle marking.
            max_iterations: Upper bound on iterations.
            oracle_fn: Custom oracle function; built from target_success if None.

        Returns:
            Ranked list of paths (highest amplitude first).
        """
        n = len(paths)
        if n == 0:
            logger.warning("grover_search called with empty path list")
            return []
        if n == 1:
            return [paths[0]]

        # ── Phase 1: Initialise uniform superposition ──
        amplitudes = [1.0 / math.sqrt(n)] * n
        marked_indices: Set[int] = set()

        # ── Phase 2: Determine iteration count (Grover's optimal) ──
        # Estimate number of solutions M for a more precise iteration count
        if oracle_fn:
            m_estimate = sum(1 for p in paths if oracle_fn(p))
        else:
            m_estimate = sum(
                1 for p in paths
                if p.get('estimated_success', 0.5) >= target_success
            )
        m_estimate = max(m_estimate, 1)
        optimal_iterations = int((math.pi / 4.0) * math.sqrt(n / m_estimate))
        iterations = min(optimal_iterations, max_iterations)

        # ── Phase 3: Amplitude amplification loop ──
        iteration_log = []
        for iteration in range(iterations):
            # Step A: Oracle — invert amplitudes of marked paths
            marked_indices.clear()
            for i, path in enumerate(paths):
                is_marked = False
                if oracle_fn:
                    is_marked = oracle_fn(path)
                else:
                    is_marked = path.get('estimated_success', 0.5) >= target_success
                if is_marked:
                    amplitudes[i] *= -1.0
                    marked_indices.add(i)

            # Step B: Diffusion — reflect about the mean
            avg_amplitude = sum(amplitudes) / n
            amplitudes = [(2.0 * avg_amplitude - a) for a in amplitudes]

            # Step C: Normalise (prevent amplitude drift)
            norm = math.sqrt(sum(a * a for a in amplitudes))
            if norm > 0:
                amplitudes = [a / norm for a in amplitudes]

            # Step D: Check convergence
            if iteration > 0:
                delta = max(
                    abs(amplitudes[i] - iteration_log[-1]['amplitudes'][i])
                    for i in range(n)
                )
                if delta < _CONVERGENCE_THRESHOLD:
                    logger.info(
                        f"Grover search converged after {iteration + 1} iterations "
                        f"(delta={delta:.6f})"
                    )
                    iteration_log.append({
                        'iteration': iteration,
                        'amplitudes': list(amplitudes),
                        'marked_count': len(marked_indices),
                        'converged': True,
                    })
                    break
            iteration_log.append({
                'iteration': iteration,
                'amplitudes': list(amplitudes),
                'marked_count': len(marked_indices),
                'converged': False,
            })

        # ── Phase 4: Build ranked results ──
        results = [
            (abs(amplitudes[i]), i, paths[i])
            for i in range(n)
        ]
        results.sort(key=lambda x: x[0], reverse=True)

        ranked_paths = []
        for prob, idx, path in results:
            ranked_paths.append({
                **path,
                'quantum_amplitude': round(prob, 6),
                'amplitude_rank': len(ranked_paths) + 1,
                'oracle_marked': idx in marked_indices,
            })

        # ── Phase 5: Store search state ──
        path_objects = [
            PathAmplitude(
                path_id=path.get('id', hashlib.md5(
                    str(path.get('steps', [])).encode()
                ).hexdigest()[:12]),
                steps=path.get('steps', []),
                estimated_success=path.get('estimated_success', 0.5),
                amplitude=amplitudes[i],
                marked=i in marked_indices,
            )
            for i, path in enumerate(paths)
        ]
        state = QuantumState(
            paths=path_objects,
            iteration=iteration_log[-1]['iteration'] + 1,
            convergence_delta=min(
                (lg.get('convergence_delta', float('inf'))
                 for lg in iteration_log),
                default=float('inf'),
            ),
            converged=iteration_log[-1]['converged'],
            measurement_history=iteration_log,
        )
        self._search_history.append(state)

        result_count = max(1, n // 4)
        logger.info(
            f"Grover search complete: {n} paths → {result_count} ranked, "
            f"{len(marked_indices)} marked, {state.iteration} iterations"
        )
        return ranked_paths[:result_count]

    def find_optimal_path(
        self,
        paths: List[Dict[str, Any]],
        context: Optional[Dict[str, Any]] = None,
    ) -> Optional[Dict[str, Any]]:
        """Find the single best attack path given mission context.

        Args:
            paths: Attack path candidates.
            context: Mission parameters (stealth requirement, budget, deadline).

        Returns:
            Highest-ranked path or None if no paths provided.
        """
        if not paths:
            return None

        # Adjust target success based on context
        target = _DEFAULT_TARGET_SUCCESS
        if context:
            if context.get('stealth_required'):
                target = 0.85  # Higher threshold for stealth ops
            if context.get('time_critical'):
                target = 0.50  # Accept lower success for speed

        oracle = self._build_context_oracle(context)
        # Wrap oracle to accept dict (what grover_search passes)
        oracle_wrapper = None
        if oracle:
            def _dict_oracle(path_dict: Dict[str, Any]) -> bool:
                p = PathAmplitude(
                    path_id=path_dict.get('id', ''),
                    steps=path_dict.get('steps', []),
                    estimated_success=path_dict.get('estimated_success', 0.5),
                    risk_level=path_dict.get('risk_level', 0.5),
                )
                return oracle.evaluate(p)
            oracle_wrapper = _dict_oracle

        ranked = self.grover_search(
            paths,
            target_success=target,
            oracle_fn=oracle_wrapper,
        )
        if not ranked:
            return None

        optimal = ranked[0]
        optimal['optimal'] = True
        optimal['context_applied'] = bool(context)
        return optimal

    # ── Amplitude Amplification (standalone) ────────────────────────────────

    def amplitude_amplification(
        self,
        amplitudes: List[float],
        marked_indices: Set[int],
        iterations: int = 5,
    ) -> Tuple[List[float], Dict[str, Any]]:
        """Run pure amplitude amplification on a vector.

        Args:
            amplitudes: Initial amplitude vector.
            marked_indices: Indices that the oracle marks.
            iterations: Number of Grover iterations.

        Returns:
            Tuple of (amplified amplitudes, stats dict).
        """
        n = len(amplitudes)
        amps = list(amplitudes)
        stats = {'iterations': iterations, 'n': n, 'marked': len(marked_indices)}

        for it in range(iterations):
            # Oracle
            for i in marked_indices:
                amps[i] *= -1.0
            # Diffusion
            avg = sum(amps) / n
            amps = [(2.0 * avg - a) for a in amps]
            # Normalise
            norm = math.sqrt(sum(a * a for a in amps))
            if norm > 0:
                amps = [a / norm for a in amps]

        # Calculate amplification ratio
        marked_amplitude_sum = sum(abs(amps[i]) for i in marked_indices)
        unmarked_amplitude_sum = sum(
            abs(amps[i]) for i in range(n) if i not in marked_indices
        )
        stats['marked_amplitude_ratio'] = (
            marked_amplitude_sum / (marked_amplitude_sum + unmarked_amplitude_sum + 1e-10)
        )
        stats['max_amplitude'] = max(abs(a) for a in amps)
        return amps, stats

    # ── Measurement ─────────────────────────────────────────────────────────

    def measure(self, amplitudes: List[float]) -> Dict[str, Any]:
        """Collapse the amplitude vector via probabilistic measurement.

        Simulates quantum measurement — returns the index of the collapsed
        state and the resulting classical outcome.

        Args:
            amplitudes: Current amplitude vector.

        Returns:
            Dict with 'collapsed_index', 'probability', 'amplitudes'.
        """
        n = len(amplitudes)
        if n == 0:
            return {'collapsed_index': -1, 'probability': 0.0, 'amplitudes': []}

        # Probability distribution = squared amplitudes
        probs = [a * a for a in amplitudes]
        total = sum(probs)
        if total == 0:
            return {'collapsed_index': -1, 'probability': 0.0, 'amplitudes': list(amplitudes)}

        probs = [p / total for p in probs]

        # Weighted random selection
        r = random.random()
        cumulative = 0.0
        collapsed_idx = 0
        for i, p in enumerate(probs):
            cumulative += p
            if r <= cumulative:
                collapsed_idx = i
                break
        else:
            collapsed_idx = n - 1

        # Post-measurement: collapse to measured state
        new_amps = [0.0] * n
        new_amps[collapsed_idx] = 1.0

        return {
            'collapsed_index': collapsed_idx,
            'probability': probs[collapsed_idx],
            'amplitudes': new_amps,
            'measurement_fidelity': probs[collapsed_idx],
        }

    # ── Iteration Runner ────────────────────────────────────────────────────

    def run_iteration(
        self,
        amplitudes: List[float],
        oracle_fn: Callable[[int], bool],
        iterations: int = 1,
    ) -> Dict[str, Any]:
        """Execute a controlled number of Grover iterations.

        Args:
            amplitudes: Starting amplitude vector.
            oracle_fn: Function mapping index → bool (True = mark).
            iterations: Number of iterations to run.

        Returns:
            Dict with 'amplitudes', 'iteration_log', 'converged'.
        """
        n = len(amplitudes)
        amps = list(amplitudes)
        log = []

        for it in range(iterations):
            # Oracle marking
            marked = set()
            for i in range(n):
                if oracle_fn(i):
                    amps[i] *= -1.0
                    marked.add(i)

            # Diffusion
            avg = sum(amps) / n
            amps = [(2.0 * avg - a) for a in amps]

            # Normalise
            norm = math.sqrt(sum(a * a for a in amps))
            if norm > 0:
                amps = [a / norm for a in amps]

            # Track convergence
            delta = float('inf')
            if log:
                prev = log[-1]['amplitudes']
                delta = max(abs(amps[i] - prev[i]) for i in range(n))

            log.append({
                'iteration': it,
                'amplitudes': list(amps),
                'marked_count': len(marked),
                'delta': delta,
            })

            if delta < _CONVERGENCE_THRESHOLD:
                break

        return {
            'amplitudes': amps,
            'iteration_log': log,
            'iterations_executed': len(log),
            'converged': log[-1]['delta'] < _CONVERGENCE_THRESHOLD,
            'final_delta': log[-1]['delta'],
        }

    # ── Oracular Path Scoring ───────────────────────────────────────────────

    def oracular_path_scoring(
        self,
        paths: List[Dict[str, Any]],
        oracle: Optional[OracleFunction] = None,
    ) -> List[Dict[str, Any]]:
        """Score paths using an oracle function without full Grover search.

        This is a lightweight alternative — the oracle evaluates each path
        and assigns a score without the amplitude amplification overhead.
        Useful for quick filtering before committing to Grover search.

        Args:
            paths: Attack path candidates.
            oracle: Pre-configured oracle function.

        Returns:
            Paths with 'oracle_score' and 'oracle_verdict' added.
        """
        if oracle is None:
            oracle = OracleFunction()

        scored = []
        for path in paths:
            p = PathAmplitude(
                path_id=path.get('id', uuid.uuid4().hex[:12]),
                steps=path.get('steps', []),
                estimated_success=path.get('estimated_success', 0.5),
                risk_level=path.get('risk_level', 0.5),
            )
            verdict = oracle.evaluate(p)
            score = 1.0 if verdict else 0.0

            # Bonus: partial scoring based on proximity to threshold
            if not verdict:
                if p.estimated_success >= oracle.target_success * 0.8:
                    score = 0.5
                elif p.estimated_success >= oracle.target_success * 0.6:
                    score = 0.25

            scored.append({
                **path,
                'oracle_score': score,
                'oracle_verdict': 'MARKED' if verdict else 'UNMARKED',
                'oracle_proximity': p.estimated_success / max(oracle.target_success, 0.01),
            })

        scored.sort(key=lambda p: p['oracle_score'], reverse=True)
        logger.debug(
            f"Oracular scoring: {len(scored)} paths evaluated, "
            f"{sum(1 for p in scored if p['oracle_verdict'] == 'MARKED')} marked"
        )
        return scored

    # ── Batch Search ────────────────────────────────────────────────────────

    def batch_search(
        self,
        path_sets: List[List[Dict[str, Any]]],
        target_success: float = _DEFAULT_TARGET_SUCCESS,
        parallel: bool = True,
    ) -> Dict[str, Any]:
        """Run Grover search across multiple independent path sets.

        When the attack surface spans multiple domains, batch search
        runs parallel Grover instances and merges results.

        Args:
            path_sets: Multiple groups of attack paths (e.g. per target host).
            target_success: Threshold for oracle marking.
            parallel: Whether to simulate parallel execution.

        Returns:
            Dict with 'batch_results', 'merged_rankings', 'stats'.
        """
        all_results = []
        stats = {
            'total_paths': 0,
            'total_sets': len(path_sets),
            'total_ranked': 0,
            'sets_processed': 0,
            'parallel_mode': parallel,
        }

        for idx, path_set in enumerate(path_sets):
            if not path_set:
                continue
            stats['total_paths'] += len(path_set)

            # Adjust target success with entanglement simulation
            adjusted_target = target_success
            if idx > 0 and parallel:
                # Simulate quantum entanglement between parallel searches:
                # slightly loosen threshold for subsequent sets
                adjusted_target = max(0.5, target_success * _ENTANGLEMENT_DECAY)

            ranked = self.grover_search(path_set, target_success=adjusted_target)
            for r in ranked:
                r['batch_set_index'] = idx
            all_results.append({
                'set_index': idx,
                'path_count': len(path_set),
                'ranked_count': len(ranked),
                'ranked_paths': ranked,
            })
            stats['total_ranked'] += len(ranked)
            stats['sets_processed'] += 1

        # Merge and re-rank across all sets by quantum amplitude
        merged = []
        for batch in all_results:
            merged.extend(batch['ranked_paths'])
        merged.sort(
            key=lambda p: p.get('quantum_amplitude', 0.0),
            reverse=True,
        )

        logger.info(
            f"Batch search complete: {stats['sets_processed']}/{stats['total_sets']} "
            f"sets, {stats['total_paths']} total paths, "
            f"{stats['total_ranked']} ranked"
        )
        return {
            'batch_results': all_results,
            'merged_rankings': merged,
            'stats': stats,
            'success': True,
        }

    # ── Helpers ─────────────────────────────────────────────────────────────

    def _build_context_oracle(
        self,
        context: Optional[Dict[str, Any]],
    ) -> Optional[OracleFunction]:
        """Build an OracleFunction from mission context parameters."""
        if not context:
            return None

        oracle = OracleFunction(
            target_success=context.get('target_success', _DEFAULT_TARGET_SUCCESS),
            max_risk=context.get('max_risk', 1.0),
            bonus_keywords=context.get('preferred_techniques', []),
        )

        domain_map = {
            'network': SearchDomain.NETWORK,
            'application': SearchDomain.APPLICATION,
            'social': SearchDomain.SOCIAL,
            'physical': SearchDomain.PHYSICAL,
            'cloud': SearchDomain.CLOUD,
        }
        if context.get('domain'):
            oracle.required_domains = [
                domain_map.get(context['domain'], SearchDomain.NETWORK)
            ]

        return oracle

    def get_search_history(self) -> List[Dict[str, Any]]:
        """Return the history of all quantum search states."""
        return [
            {
                'iteration': s.iteration,
                'converged': s.converged,
                'convergence_delta': s.convergence_delta,
                'path_count': s.size,
                'top_amplitudes': sorted(
                    [abs(a) for a in s.amplitudes], reverse=True
                )[:5],
            }
            for s in self._search_history
        ]

    def reset(self) -> None:
        """Clear all internal state — fresh quantum canvas."""
        self._search_history.clear()
        self._oracle_cache.clear()
        logger.debug("QuantumAttackSearch reset — all amplitude manifolds cleared.")
