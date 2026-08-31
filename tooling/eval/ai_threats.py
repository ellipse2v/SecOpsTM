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

"""Determinism check for the per-component AI (STRIDE) threat pass.

The same move as Step 1 of the debate evaluation, applied to the other place the
tool trusts an LLM: generate the per-component threats N times on the same model,
same provider, no cache, and measure how much the threat set moves run to run —
count stability, set overlap (fuzzy, same key as ThreatConsolidator), per-threat
recurrence, and whether the grounding-flag rate reproduces.

    export MISTRAL_API_KEY=...
    python -m tooling.eval.ai_threats --templates Simple_Monolithic_Web_Application \
        --provider mistral --runs 3 --sleep 2 \
        --out tooling/eval/results/ai-threats-$(date +%F).json

Run from the repo root (reads config/ai_config.yaml via cwd).
"""

from __future__ import annotations

import argparse
import asyncio
import datetime as _dt
import json
import logging
import statistics
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from tooling.eval._common import make_provider  # noqa: F401  (forces SECOPSTM_FORCE_PROVIDER)

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
logger = logging.getLogger("ai_threats")

REPO_ROOT = Path(__file__).resolve().parents[2]
TEMPLATE_ROOT = REPO_ROOT / "threatModel_Template"

_STOP = frozenset(
    "the a an of to in on and or via with for by is are be this that it its "
    "attacker attack threat component using use unauthorized access could may".split()
)


def _title_words(title: str) -> frozenset:
    return frozenset(
        w for w in "".join(c.lower() if c.isalnum() else " " for c in title).split()
        if len(w) > 2 and w not in _STOP
    )


def _threat_key(t: Dict[str, Any]) -> Tuple[str, str, frozenset]:
    return (
        str(t.get("target", "")).lower(),
        str(t.get("category", "")).lower(),
        _title_words(str(t.get("title", ""))),
    )


def _same(a: Tuple[str, str, frozenset], b: Tuple[str, str, frozenset]) -> bool:
    if a[0] != b[0] or a[1] != b[1]:
        return False
    wa, wb = a[2], b[2]
    if not wa or not wb:
        return wa == wb
    return len(wa & wb) / len(wa | wb) >= 0.5


def _dice(run_a: List, run_b: List) -> float:
    matched = 0
    used = [False] * len(run_b)
    for ka in run_a:
        for i, kb in enumerate(run_b):
            if not used[i] and _same(ka, kb):
                used[i] = True
                matched += 1
                break
    denom = len(run_a) + len(run_b)
    return (2 * matched / denom) if denom else 1.0


async def _generate_once(template_dir: Path, provider_name: str) -> List[Dict[str, Any]]:
    """One no-cache AI-threat pass over a template. Returns threat dicts."""
    from threat_analysis.core.cve_service import CVEService
    from threat_analysis.core.model_factory import create_threat_model, pytm_build_lock
    from threat_analysis.server.ai_service import AIService

    make_provider(provider_name)  # sets SECOPSTM_FORCE_PROVIDER

    model_md = next((template_dir / n for n in ("model.md", "main.md") if (template_dir / n).exists()), None)
    if model_md is None:
        md = sorted(template_dir.glob("*.md"))
        model_md = md[0] if md else None
    if model_md is None:
        raise FileNotFoundError(f"no model file in {template_dir}")

    cve_service = CVEService(REPO_ROOT, REPO_ROOT / "cve_definitions.yml")
    markdown = model_md.read_text(encoding="utf-8")
    with pytm_build_lock():
        tm = create_threat_model(markdown, template_dir.name, "eval", cve_service, validate=False)
        tm.process_threats()
    tm._model_file_path = None  # -> AIThreatCache is a no-op, every run hits the LLM

    ai_service = AIService(config_path=str(REPO_ROOT / "config" / "ai_config.yaml"), force_disable_rag=True)
    ai_service._enrich_with_soc_analysis = lambda *a, **k: _noop()  # skip the SOC LLM pass
    await ai_service.init_ai()
    if not ai_service.ai_online:
        raise RuntimeError("AI provider offline")
    await ai_service._enrich_with_ai_threats(tm)

    out: List[Dict[str, Any]] = []
    elements = list(getattr(tm, "servers", [])) + list(getattr(tm, "actors", [])) + list(tm.boundaries.values())
    for entry in elements:
        elem = entry["object"] if isinstance(entry, dict) and "object" in entry else entry
        for th in getattr(elem, "threats", []):
            if getattr(th, "source", "") != "AI":
                continue
            det = getattr(th, "ai_details", {}) or {}
            out.append({
                "target": getattr(elem, "name", ""),
                "category": det.get("category", getattr(th, "_category", "")),
                "title": det.get("title", ""),
                "confidence": getattr(th, "confidence", None),
                "grounding_flags": list(getattr(th, "grounding_flags", []) or []),
            })
    return out


async def _noop():
    return None


def _run_template(name: str, provider: str, runs: int, sleep_s: float) -> Dict[str, Any]:
    template_dir = TEMPLATE_ROOT / name
    per_run: List[List[Dict[str, Any]]] = []
    ok = 0
    for i in range(runs):
        try:
            threats = asyncio.run(_generate_once(template_dir, provider))
        except Exception as exc:
            logger.warning("%s run %d/%d failed: %s", name, i + 1, runs, exc)
            continue
        per_run.append(threats)
        ok += 1
        if sleep_s and i < runs - 1:
            import time
            time.sleep(sleep_s)

    if ok < 2:
        return {"runs_ok": ok, "status": "insufficient-data"}

    counts = [len(r) for r in per_run]
    keys = [[_threat_key(t) for t in r] for r in per_run]
    dices = [
        _dice(keys[a], keys[b])
        for a in range(len(keys)) for b in range(a + 1, len(keys))
    ]
    # per-threat recurrence: for the fuzzy union, mean fraction of runs it appears in
    union: List = []
    for run in keys:
        for k in run:
            if not any(_same(k, u) for u in union):
                union.append(k)
    recur = [
        sum(1 for run in keys if any(_same(k, x) for x in run)) / len(keys)
        for k in union
    ]
    flag_rates = [
        (sum(1 for t in r if t["grounding_flags"]) / len(r)) if r else 0.0
        for r in per_run
    ]
    return {
        "runs_ok": ok,
        "threat_count_mean": round(statistics.fmean(counts), 2),
        "threat_count_cv": round(statistics.pstdev(counts) / statistics.fmean(counts), 4)
        if statistics.fmean(counts) else 0.0,
        "set_stability_dice": round(statistics.fmean(dices), 4) if dices else None,
        "recurrence_mean": round(statistics.fmean(recur), 4) if recur else None,
        "recurrence_full": round(sum(1 for x in recur if x == 1.0) / len(recur), 4) if recur else None,
        "grounding_flag_rate_mean": round(statistics.fmean(flag_rates), 4),
        "grounding_flag_rate_cv": round(
            statistics.pstdev(flag_rates) / statistics.fmean(flag_rates), 4
        ) if statistics.fmean(flag_rates) else 0.0,
    }


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--templates", nargs="+", required=True, metavar="NAME")
    p.add_argument("--provider", required=True)
    p.add_argument("--runs", type=int, default=3)
    p.add_argument("--sleep", type=float, default=2.0)
    p.add_argument("--out", required=True)
    args = p.parse_args(argv)

    # pytm.TM() parses sys.argv on construction — clear it so our flags don't reach it
    sys.argv = [sys.argv[0]]

    result: Dict[str, Any] = {
        "step": "ai_threats_determinism",
        "generated_at": _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "params": {"provider": args.provider, "runs": args.runs, "sleep": args.sleep},
        "templates": {},
    }
    for name in args.templates:
        logger.info("=== %s ===", name)
        result["templates"][name] = _run_template(name, args.provider, args.runs, args.sleep)

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    logger.info("wrote %s", out)
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
