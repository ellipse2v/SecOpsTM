# Copyright 2025 ellipse2v
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Frozen-fixture IO, provider forcing, and the debate run wrapper for the
evaluation harness. See docs/superpowers/specs/2026-08-29-debate-gdaf-evaluation-design.md."""

from __future__ import annotations

import asyncio
import concurrent.futures
import copy as _copy
import logging
import os
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable, Dict, List, Tuple

import yaml

from threat_analysis.core.asset_technique_mapper import ScoredTechnique
from threat_analysis.core.gdaf_engine import AttackHop, AttackScenario

if TYPE_CHECKING:
    from threat_analysis.ai_engine.providers.litellm_provider import LiteLLMProvider
    from threat_analysis.core.debate_engine import DebateResult

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Scenario freeze / thaw
# ---------------------------------------------------------------------------

def _freeze_technique(t: ScoredTechnique) -> Dict[str, Any]:
    return {"id": t.id, "name": t.name, "tactics": list(t.tactics),
            "score": t.score, "rationale": t.rationale, "url": t.url}


def _freeze_hop(h: AttackHop) -> Dict[str, Any]:
    return {
        "asset_name": h.asset_name,
        "asset_type": h.asset_type,
        "techniques": [_freeze_technique(t) for t in h.techniques],
        "dataflow_name": h.dataflow_name,
        "protocol": h.protocol,
        "is_encrypted": h.is_encrypted,
        "is_authenticated": h.is_authenticated,
        "hop_score": h.hop_score,
        "hop_position": h.hop_position,
    }


def freeze(scenarios: List[AttackScenario]) -> List[Dict[str, Any]]:
    """Serialise GDAF scenarios to plain dicts for a committed fixture file."""
    out: List[Dict[str, Any]] = []
    for s in scenarios:
        out.append({
            "scenario_id": s.scenario_id,
            "objective_id": s.objective_id,
            "objective_name": s.objective_name,
            "objective_description": s.objective_description,
            "objective_business_impact": s.objective_business_impact,
            "objective_mitre_final_tactic": s.objective_mitre_final_tactic,
            "actor_id": s.actor_id,
            "actor_name": s.actor_name,
            "actor_sophistication": s.actor_sophistication,
            "entry_point": s.entry_point,
            "target_asset": s.target_asset,
            "hops": [_freeze_hop(h) for h in s.hops],
            "path_score": s.path_score,
            "risk_level": s.risk_level,
            "detection_coverage": s.detection_coverage,
            "unacceptable_risk": s.unacceptable_risk,
            "min_technique_score": s.min_technique_score,
        })
    return out


def _thaw_technique(d: Dict[str, Any]) -> ScoredTechnique:
    return ScoredTechnique(
        id=d["id"], name=d.get("name", ""), tactics=list(d.get("tactics", [])),
        score=d.get("score", 0.0), rationale=d.get("rationale", ""), url=d.get("url", ""),
    )


def _thaw_hop(d: Dict[str, Any]) -> AttackHop:
    return AttackHop(
        asset_name=d["asset_name"],
        asset_type=d.get("asset_type", ""),
        techniques=[_thaw_technique(t) for t in d.get("techniques", [])],
        dataflow_name=d.get("dataflow_name", ""),
        protocol=d.get("protocol", ""),
        is_encrypted=bool(d.get("is_encrypted", False)),
        is_authenticated=bool(d.get("is_authenticated", False)),
        hop_score=d.get("hop_score", 0.0),
        hop_position=d.get("hop_position", ""),
    )


def thaw(records: List[Dict[str, Any]]) -> List[AttackScenario]:
    """Rebuild GDAF scenario dataclasses from a fixture file's records."""
    out: List[AttackScenario] = []
    for d in records:
        out.append(AttackScenario(
            scenario_id=d["scenario_id"],
            objective_id=d.get("objective_id", ""),
            objective_name=d.get("objective_name", ""),
            objective_description=d.get("objective_description", ""),
            objective_business_impact=d.get("objective_business_impact", ""),
            objective_mitre_final_tactic=d.get("objective_mitre_final_tactic", ""),
            actor_id=d.get("actor_id", ""),
            actor_name=d.get("actor_name", ""),
            actor_sophistication=d.get("actor_sophistication", ""),
            entry_point=d.get("entry_point", ""),
            target_asset=d.get("target_asset", ""),
            hops=[_thaw_hop(h) for h in d.get("hops", [])],
            path_score=d["path_score"],
            risk_level=d.get("risk_level", ""),
            detection_coverage=d.get("detection_coverage", 0.0),
            unacceptable_risk=bool(d.get("unacceptable_risk", False)),
            min_technique_score=d.get("min_technique_score", 0.8),
        ))
    return out


def scenario_order(scenarios: List[AttackScenario]) -> List[str]:
    """Scenario ids ranked by path_score desc, ties broken by id for determinism."""
    return [s.scenario_id for s in sorted(
        scenarios, key=lambda s: (-s.path_score, s.scenario_id)
    )]


def risk_levels(scenarios: List[AttackScenario]) -> Dict[str, str]:
    return {s.scenario_id: s.risk_level for s in scenarios}


def band_ranks(scenarios: List[AttackScenario], rel_tol: float = 0.05) -> Dict[str, int]:
    """Map each scenario id to a confidence-band index (0 = highest-risk band).

    Scenarios are sorted by path_score desc; a new band starts when the gap to the
    previous score exceeds ``rel_tol`` of the top score. Ranking metrics computed
    over band indices (rather than the strict order) stop penalising the debate for
    permuting scenarios whose scores were never distinguishable — see
    docs/evaluation.md "GDAF confidence bands".
    """
    ordered = sorted(scenarios, key=lambda s: (-s.path_score, s.scenario_id))
    if not ordered:
        return {}
    top = ordered[0].path_score or 1.0
    tol = abs(top) * rel_tol
    out: Dict[str, int] = {}
    band = 0
    prev = ordered[0].path_score
    for s in ordered:
        if prev - s.path_score > tol:
            band += 1
        out[s.scenario_id] = band
        prev = s.path_score
    return out


# ---------------------------------------------------------------------------
# Multi-provider dispatch config — read from config/ai_config.yaml
# ---------------------------------------------------------------------------

def load_eval_multi_provider_config() -> Dict[str, Any]:
    """Read the `eval_multi_provider` section of config/ai_config.yaml (resolved
    relative to cwd, same as LiteLLMClient._load_ai_config — run harness scripts
    from the repo root).

    Only used by determinism.py/ablation.py when invoked with no explicit
    --provider(s) CLI flag — see docs/evaluation.md "Multi-provider dispatch".
    Returns {"enabled": bool, "mode": "fallback"|"parallel_merge", "providers": [...]}.
    An empty/missing `providers` list resolves to every `ai_providers` entry
    with `enabled: true`, in the order they appear in the file.
    """
    path = Path.cwd() / "config" / "ai_config.yaml"
    try:
        with open(path, "r", encoding="utf-8") as f:
            full = yaml.safe_load(f) or {}
    except FileNotFoundError:
        return {"enabled": False, "mode": "fallback", "providers": []}

    section = full.get("eval_multi_provider") or {}
    providers = [p for p in (section.get("providers") or []) if p]
    if not providers:
        providers = [
            name for name, pc in (full.get("ai_providers") or {}).items()
            if pc and pc.get("enabled", False)
        ]
    return {
        "enabled": bool(section.get("enabled", False)),
        "mode": section.get("mode", "fallback"),
        "providers": providers,
    }


# ---------------------------------------------------------------------------
# Provider forcing + debate run wrapper
# ---------------------------------------------------------------------------

def make_provider(name: str) -> LiteLLMProvider:
    """Return a fresh LiteLLMProvider pinned to `name`.

    The provider reads config/ai_config.yaml lazily on its first call. Build a
    NEW provider for every run_debate call — run_debate uses asyncio.run(),
    which closes its event loop on return, and a provider/client reused across
    a closed loop raises "Event loop is closed" on the next call.

    Sets SECOPSTM_FORCE_PROVIDER (kept for backward compatibility / single-
    threaded scripts) *and* passes `name` as LiteLLMProvider's explicit
    `forced_provider`, which takes precedence over the env var. The explicit
    parameter is what actually matters under `run_parallel_merge_attempts`:
    the env var is process-global and races when multiple providers'
    providers are constructed from concurrent threads, but each provider
    instance still resolves to the correct config regardless of which
    thread's env-var write won the race.
    """
    from threat_analysis.ai_engine.providers.litellm_provider import LiteLLMProvider
    os.environ["SECOPSTM_FORCE_PROVIDER"] = name
    return LiteLLMProvider({}, forced_provider=name)


def run_debate(
    scenarios: List[AttackScenario], *, provider: Any, config: Dict,
    sleep_s: float = 0.0,
) -> Tuple[List[AttackScenario], List[DebateResult]]:
    """Debate a deep copy of `scenarios` and return (mutated_copies, debate_results).

    `config` is passed straight to RedBlueDebateEngine. `sleep_s` is applied
    after every Red/Blue turn (each turn is one LLM call) to stay under provider
    rate limits (the engine does not self-throttle). Per-turn — not per-scenario —
    because a debate round fires two calls back to back, which blows past a low
    tokens-per-minute cap (e.g. Groq free tier, 8000 TPM) before a per-scenario
    sleep would ever run.
    """
    from threat_analysis.core.debate_engine import RedBlueDebateEngine

    work = _copy.deepcopy(list(scenarios))
    engine = RedBlueDebateEngine(provider, config=config)

    if sleep_s > 0:
        _orig_turn = engine._run_turn

        async def _throttled_turn(*args, **kwargs):
            result = await _orig_turn(*args, **kwargs)
            await asyncio.sleep(sleep_s)
            return result

        engine._run_turn = _throttled_turn

    results = asyncio.run(engine.run(work))
    return work, results


# ---------------------------------------------------------------------------
# Multi-provider dispatch — avoid a single provider's rate limit / quota
# ---------------------------------------------------------------------------
#
# Two modes, chosen by config/ai_config.yaml's `eval_multi_provider.mode`
# (see load_eval_multi_provider_config above — not a CLI flag; --providers on
# the CLI overrides the whole section and uses the legacy per-provider path):
#
#   fallback:       `runs` slots total. For each slot, try the given providers
#                   in order until one succeeds. Use this to keep a fixed
#                   sample count while riding out one provider's rate limit —
#                   it does not increase how many samples you get.
#   parallel_merge: every provider runs its own full `runs` attempts, all
#                   providers running concurrently, and every success from
#                   every provider is pooled into one combined sample set (up
#                   to len(providers) * runs values). Use this to get a firmer
#                   statistic (bigger n) in roughly the wall-clock time of the
#                   slowest provider instead of the sum of all of them.
#
# `attempt(provider_name, attempt_index)` performs one run against the named
# provider and returns its result, raising on failure (rate limit, timeout,
# bad response, ...). It is expected to build its own LiteLLMProvider via
# `make_provider(provider_name)` — passing `forced_provider` explicitly rather
# than relying solely on the SECOPSTM_FORCE_PROVIDER env var is what makes
# parallel_merge's concurrent threads safe: the env var is process-global and
# races across threads, but each provider instance still resolves to the
# correct config regardless of which thread's write won that race.

MULTI_PROVIDER_MODES = ("fallback", "parallel_merge")


def run_fallback_attempts(
    providers: List[str], runs: int, attempt: Callable[[str, int], Any],
) -> Tuple[List[Tuple[str, Any]], int]:
    """`runs` slots; for each slot, try `providers` in order until one succeeds.

    Returns (successes, failed_slots) where successes is a list of
    (provider_name_that_served_it, result) — a slot that exhausts every
    provider without success counts toward failed_slots, not toward successes.
    """
    successes: List[Tuple[str, Any]] = []
    failed = 0
    for i in range(runs):
        for prov in providers:
            try:
                successes.append((prov, attempt(prov, i)))
                break
            except Exception as exc:
                logger.warning(
                    "fallback: %s attempt %d/%d failed (%s) — trying next provider",
                    prov, i + 1, runs, exc,
                )
        else:
            failed += 1
    return successes, failed


def run_parallel_merge_attempts(
    providers: List[str], runs: int, attempt: Callable[[str, int], Any],
) -> Tuple[List[Tuple[str, Any]], int]:
    """Every provider runs its own `runs` attempts concurrently (one thread per
    provider — `attempt` typically calls `run_debate`/similar, which owns and
    closes its own asyncio loop via `asyncio.run()` per call; those can't be
    nested in one loop, so threads are used instead of `asyncio.gather`).
    Every success from every provider is pooled together.
    """
    successes: List[Tuple[str, Any]] = []
    failed = 0

    def _worker(prov: str) -> Tuple[List[Tuple[str, Any]], int]:
        local: List[Tuple[str, Any]] = []
        local_failed = 0
        for i in range(runs):
            try:
                local.append((prov, attempt(prov, i)))
            except Exception as exc:
                logger.warning("parallel_merge: %s attempt %d/%d failed (%s)",
                                prov, i + 1, runs, exc)
                local_failed += 1
        return local, local_failed

    with concurrent.futures.ThreadPoolExecutor(max_workers=len(providers)) as ex:
        for local, local_failed in ex.map(_worker, providers):
            successes.extend(local)
            failed += local_failed
    return successes, failed


def run_multi_provider(
    providers: List[str], runs: int, mode: str, attempt: Callable[[str, int], Any],
) -> Tuple[List[Tuple[str, Any]], int]:
    """Dispatch to `run_fallback_attempts` or `run_parallel_merge_attempts` by `mode`."""
    if mode == "fallback":
        return run_fallback_attempts(providers, runs, attempt)
    if mode == "parallel_merge":
        return run_parallel_merge_attempts(providers, runs, attempt)
    raise ValueError(f"unknown multi-provider mode: {mode!r} (expected one of {MULTI_PROVIDER_MODES})")
