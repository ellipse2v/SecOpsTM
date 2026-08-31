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

"""Step 2 of the debate evaluation — ablation (debate on vs off).

For each frozen fixture, compares GDAF's pre-debate scenario ordering against
the post-debate ordering. See
docs/superpowers/specs/2026-08-29-debate-gdaf-evaluation-design.md and
docs/evaluation.md.

Run from the repo root (reads config/ai_config.yaml via cwd).

    export GROQ_API_KEY=...
    python -m tooling.eval.ablation --all --provider groq \
        --top-n 5 --max-rounds 3 --sleep 22 \
        --out tooling/eval/results/ablation-2026-08-29.json
"""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import logging
import statistics
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from tooling.eval import metrics
from tooling.eval._common import (
    make_provider,
    risk_levels,
    run_debate,
    scenario_order,
    thaw,
)

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
logger = logging.getLogger("ablation")

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


def _reason_for(result: Any) -> str:
    """One-line why, pulled from a DebateResult's rounds."""
    gaps: List[str] = []
    fails: List[str] = []
    for turn in getattr(result, "rounds", []):
        if getattr(turn, "role", "") == "blue":
            gaps += [g.step for g in getattr(turn, "detection_gaps", [])
                     if not getattr(g, "covered", False)]
        if getattr(turn, "role", "") == "red":
            fails += list(getattr(turn, "failed_alternatives", []))
    bits: List[str] = []
    if gaps:
        bits.append("no detection cited for: " + ", ".join(sorted(set(gaps))[:3]))
    if fails:
        bits.append("Red alt failed: " + ", ".join(sorted(set(fails))[:3]))
    return "; ".join(bits) or "score adjusted by debate viability"


def _run_fixture(
    name: str,
    path: Path,
    provider_name: str,
    cfg: Dict[str, Any],
    sleep_s: float,
) -> Dict[str, Any]:
    scenarios = thaw(json.loads(path.read_text(encoding="utf-8")))
    pre_order = scenario_order(scenarios)
    pre_risk = risk_levels(scenarios)

    provider = make_provider(provider_name)
    mutated, results = run_debate(scenarios, provider=provider, config=cfg, sleep_s=sleep_s)
    post_order = scenario_order(mutated)
    post_risk = risk_levels(mutated)

    k = min(5, len(pre_order))
    top5_jaccard = metrics.top_k_jaccard(pre_order, post_order, k)
    entry: Dict[str, Any] = {
        "scenario_count": len(scenarios),
        "kendall_tau": round(metrics.kendall_tau(pre_order, post_order), 4),
        "spearman_rho": round(metrics.spearman_rho(pre_order, post_order), 4),
        "top5_jaccard": round(top5_jaccard, 4),
        "top5_max_displacement": metrics.max_displacement(pre_order, post_order, k),
        "bucket_changes": metrics.bucket_change_count(pre_risk, post_risk),
        "top5_unchanged": top5_jaccard == 1.0,
    }

    # candidate worked example: the top-5 pre scenario that moved the most
    result_by_id = {r.scenario_id: r for r in results}
    post_pos = {sid: i for i, sid in enumerate(post_order)}
    best: Optional[Dict[str, Any]] = None
    for pre_rank, sid in enumerate(pre_order[:k]):
        move = abs(post_pos.get(sid, len(post_order)) - pre_rank)
        if best is None or move > best["move"]:
            best = {
                "move": move,
                "scenario_id": sid,
                "pre_rank": pre_rank + 1,
                "post_rank": post_pos.get(sid, len(post_order)) + 1,
                "reason": _reason_for(result_by_id[sid]) if sid in result_by_id
                else "not in debated top-N",
            }
    entry["_candidate_example"] = {**best, "fixture": name} if best else None
    return entry


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixtures", nargs="+", metavar="NAME")
    parser.add_argument("--all", action="store_true")
    parser.add_argument("--fixtures-dir", default=str(DEFAULT_FIXTURE_DIR))
    parser.add_argument("--provider", required=True)
    parser.add_argument("--top-n", type=int, default=5)
    parser.add_argument("--max-rounds", type=int, default=3)
    parser.add_argument("--sleep", type=float, default=8.0,
                        help="seconds to pause after every Red/Blue turn (LLM call) "
                             "to stay under a provider's tokens-per-minute limit; "
                             "~22 for the Groq free tier (8000 TPM)")
    parser.add_argument("--out", required=True)
    args = parser.parse_args(argv)

    fixture_dir = Path(args.fixtures_dir)
    if args.all:
        names = sorted(p.stem.replace(".scenarios", "")
                       for p in fixture_dir.glob("*.scenarios.json"))
    else:
        names = args.fixtures or []
    if not names:
        parser.error("pass --fixtures NAME ... or --all")

    cfg = _debate_config(args.top_n, args.max_rounds)
    result: Dict[str, Any] = {
        "step": "ablation",
        "generated_at": _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "params": {
            "provider": args.provider, "top_n": args.top_n,
            "max_rounds": args.max_rounds, "sleep": args.sleep,
        },
        "fixtures": {},
    }

    for name in names:
        path = fixture_dir / f"{name}.scenarios.json"
        if not path.exists():
            logger.error("fixture not found: %s", path)
            return 2
        try:
            result["fixtures"][name] = _run_fixture(name, path, args.provider, cfg, args.sleep)
        except Exception as exc:  # provider down / quota / bad fixture — record and continue
            logger.warning("%s: ablation run failed: %s", name, exc)
            result["fixtures"][name] = {"status": "failed", "error": str(exc)}

    # a 1-scenario fixture is τ==1.0 / top5_unchanged by the metric guards, not by
    # anything the debate did — exclude it from the aggregate (still listed in fixtures)
    ok = {k: v for k, v in result["fixtures"].items()
          if "kendall_tau" in v and v.get("scenario_count", 0) >= 2}
    excluded_lt2 = sum(1 for v in result["fixtures"].values()
                       if "kendall_tau" in v and v.get("scenario_count", 0) < 2)
    taus = [v["kendall_tau"] for v in ok.values()]
    unchanged = sum(1 for v in ok.values() if v["top5_unchanged"])
    candidates = [v["_candidate_example"] for v in ok.values() if v.get("_candidate_example")]
    worked = max(candidates, key=lambda c: c["move"]) if candidates else None
    result["aggregate"] = {
        "fixtures_ok": len(ok),
        "fixtures_excluded_lt2": excluded_lt2,
        "top5_unchanged_count": unchanged,
        "kendall_tau_median": round(statistics.median(taus), 4) if taus else None,
        "worked_example": {
            key: worked[key]
            for key in ("fixture", "scenario_id", "pre_rank", "post_rank", "reason")
        } if worked else None,
    }
    # strip the internal candidate field from the committed output
    for v in result["fixtures"].values():
        v.pop("_candidate_example", None)

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    logger.info("wrote %s", out)
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
