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

"""Step 1 of the debate evaluation — determinism.

Runs the Red/Blue debate N times over the same frozen GDAF scenarios, per
provider, and reports how much the re-score moves run to run. See
docs/superpowers/specs/2026-08-29-debate-gdaf-evaluation-design.md and
docs/evaluation.md.

    export GROQ_API_KEY=...   # and XAI_API_KEY for the cross-provider check
    python -m tooling.eval.determinism \
        --fixtures GDAF_Debate_Smoke_Test Kubernetes_Helm_Cluster On-Prem_Enterprise_Network \
        --providers groq xai --runs 3 --top-n 3 --max-rounds 2 --sleep 8 \
        --out tooling/eval/results/determinism-2026-08-29.json
"""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import logging
import statistics
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from threat_analysis.core.gdaf_engine import AttackScenario
from tooling.eval import metrics
from tooling.eval._common import (
    make_provider,
    risk_levels,
    run_debate,
    scenario_order,
    thaw,
)

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
logger = logging.getLogger("determinism")

DEFAULT_FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures"


def _debate_config(top_n: int, max_rounds: int) -> Dict[str, Any]:
    return {
        "top_n": top_n,
        "min_viability_threshold": 0.5,
        "max_rounds": max_rounds,
        "viability_delta_threshold": 0.1,
        "debate_factor_min": 0.5,
        "debate_factor_max": 1.5,
    }


def _run_provider(
    fixture_scenarios: List[AttackScenario],
    provider_name: str,
    runs: int,
    cfg: Dict[str, Any],
    sleep_s: float,
) -> Tuple[Dict[str, Any], int, int]:
    """Return (per_scenario_records, runs_ok, runs_failed).

    per_scenario_records: {scenario_id: {"factor": [...], "viable": [...],
                                         "risk": [...]}}, plus "_orders": [order,...]
    """
    records: Dict[str, Any] = {}
    orders: List[List[str]] = []
    runs_ok = 0
    runs_failed = 0
    for i in range(runs):
        try:
            # fresh provider per run — see make_provider docstring (closed-loop guard)
            mutated, results = run_debate(
                fixture_scenarios, provider=make_provider(provider_name),
                config=cfg, sleep_s=sleep_s,
            )
        except Exception as exc:  # provider down / quota — count and continue
            logger.warning("%s run %d/%d failed: %s", provider_name, i + 1, runs, exc)
            runs_failed += 1
            continue
        if not results:
            logger.warning("%s run %d/%d produced no debate results", provider_name, i + 1, runs)
            runs_failed += 1
            continue
        runs_ok += 1
        orders.append(scenario_order(mutated))
        rl = risk_levels(mutated)
        factor_by_id = {s.scenario_id: s.debate_factor for s in mutated}
        viable_by_id = {r.scenario_id: bool(r.residual_path_viable) for r in results}
        for s in mutated:
            rec = records.setdefault(s.scenario_id, {"factor": [], "viable": [], "risk": []})
            rec["factor"].append(float(factor_by_id.get(s.scenario_id, 1.0)))
            rec["risk"].append(rl.get(s.scenario_id, ""))
            if s.scenario_id in viable_by_id:
                rec["viable"].append(viable_by_id[s.scenario_id])
    records["_orders"] = orders
    return records, runs_ok, runs_failed


def _aggregate_provider(records: Dict[str, Any], runs_ok: int) -> Dict[str, Any]:
    orders = records.get("_orders", [])
    scen_ids = [k for k in records if k != "_orders"]

    cvs = [metrics.coeff_variation(records[sid]["factor"]) for sid in scen_ids if records[sid]["factor"]]
    risk_flips = sum(
        1 for sid in scen_ids
        if records[sid]["risk"] and len(set(records[sid]["risk"])) > 1
    )
    dir_flips = sum(
        1 for sid in scen_ids
        if records[sid]["viable"] and len(set(records[sid]["viable"])) > 1
    )

    pair_taus: List[float] = []
    for a in range(len(orders)):
        for b in range(a + 1, len(orders)):
            pair_taus.append(metrics.kendall_tau(orders[a], orders[b]))

    n = len(scen_ids) or 1
    return {
        "runs_ok": runs_ok,
        "factor_cv_median": round(statistics.median(cvs), 4) if cvs else None,
        "factor_cv_max": round(max(cvs), 4) if cvs else None,
        "risk_level_flip_rate": round(risk_flips / n, 4),
        "rank_stability": round(statistics.fmean(pair_taus), 4) if pair_taus else None,
        "direction_flip_rate": round(dir_flips / n, 4),
    }


def _cross_provider(per_provider_records: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """direction_agreement + factor_delta_mean between exactly two providers."""
    names = [k for k in per_provider_records]
    if len(names) != 2:
        return None
    a, b = per_provider_records[names[0]], per_provider_records[names[1]]
    scen_ids = [k for k in a if k != "_orders" and k in b]
    if not scen_ids:
        return None

    agree = 0
    counted = 0
    deltas: List[float] = []
    for sid in scen_ids:
        va, vb = a[sid]["viable"], b[sid]["viable"]
        if va and vb:
            counted += 1
            if metrics.majority(va) == metrics.majority(vb):
                agree += 1
        fa, fb = a[sid]["factor"], b[sid]["factor"]
        if fa and fb:
            deltas.append(abs(statistics.fmean(fa) - statistics.fmean(fb)))
    return {
        "direction_agreement": round(agree / counted, 4) if counted else None,
        "factor_delta_mean": round(statistics.fmean(deltas), 4) if deltas else None,
    }


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixtures", nargs="+", required=True, metavar="NAME")
    parser.add_argument("--fixtures-dir", default=str(DEFAULT_FIXTURE_DIR))
    parser.add_argument("--providers", nargs="+", required=True, metavar="NAME")
    parser.add_argument("--runs", type=int, default=3)
    parser.add_argument("--top-n", type=int, default=3)
    parser.add_argument("--max-rounds", type=int, default=2)
    parser.add_argument("--sleep", type=float, default=8.0)
    parser.add_argument("--out", required=True)
    args = parser.parse_args(argv)

    cfg = _debate_config(args.top_n, args.max_rounds)
    fixture_dir = Path(args.fixtures_dir)
    result: Dict[str, Any] = {
        "step": "determinism",
        "generated_at": _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "params": {
            "runs": args.runs, "top_n": args.top_n, "max_rounds": args.max_rounds,
            "sleep": args.sleep, "providers": list(args.providers),
        },
        "fixtures": {},
    }

    for name in args.fixtures:
        path = fixture_dir / f"{name}.scenarios.json"
        if not path.exists():
            logger.error("fixture not found: %s — run freeze_scenarios first", path)
            return 2
        scenarios = thaw(json.loads(path.read_text(encoding="utf-8")))
        entry: Dict[str, Any] = {"scenario_count": len(scenarios), "by_provider": {}}
        per_provider_records: Dict[str, Any] = {}
        for prov in args.providers:
            records, runs_ok, runs_failed = _run_provider(
                scenarios, prov, args.runs, cfg, args.sleep
            )
            per_provider_records[prov] = records
            if runs_ok == 0 or runs_ok * 2 < args.runs:
                entry["by_provider"][prov] = {"runs_ok": runs_ok, "runs_failed": runs_failed,
                                              "status": "insufficient-data"}
                continue
            agg = _aggregate_provider(records, runs_ok)
            agg["runs_failed"] = runs_failed
            entry["by_provider"][prov] = agg
        cross = _cross_provider(per_provider_records)
        if cross:
            entry["cross_provider"] = cross
        result["fixtures"][name] = entry

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    logger.info("wrote %s", out)
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
