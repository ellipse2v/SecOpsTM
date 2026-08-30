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

"""Freeze GDAF attack scenarios for a set of bundled templates into committed
JSON fixtures, so the debate evaluation harness has a stable, offline input.

Run from the repo root:

    python -m tooling.eval.freeze_scenarios --templates GDAF_Debate_Smoke_Test
    python -m tooling.eval.freeze_scenarios --all
"""

import argparse
import json
import logging
import sys
from pathlib import Path

from threat_analysis.core.cve_service import CVEService
from threat_analysis.core.model_factory import create_threat_model, pytm_build_lock
from threat_analysis.utils import run_gdaf_engine
from tooling.eval._common import freeze

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
logger = logging.getLogger("freeze_scenarios")

# threat_analysis.utils.PROJECT_ROOT points one level above the repo root
# (parents[2] from threat_analysis/utils.py), so derive the repo root locally.
REPO_ROOT = Path(__file__).resolve().parents[2]
TEMPLATE_ROOT = REPO_ROOT / "threatModel_Template"
FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures"

FIRST_PASS = [
    "GDAF_Debate_Smoke_Test",
    "Kubernetes_Helm_Cluster",
    "On-Prem_Enterprise_Network",
    "Serverless_AWS_Lambda",
]


def _model_file(template_dir: Path) -> Path | None:
    for name in ("model.md", "main.md"):
        p = template_dir / name
        if p.exists():
            return p
    md = sorted(template_dir.glob("*.md"))
    return md[0] if md else None


def freeze_template(name: str) -> int:
    """Freeze one template. Returns the scenario count (0 = skipped, not written)."""
    template_dir = TEMPLATE_ROOT / name
    model_md = _model_file(template_dir)
    if not model_md:
        logger.warning("%s: no model file found — skipping", name)
        return 0

    cve_service = CVEService(REPO_ROOT, REPO_ROOT / "cve_definitions.yml")
    markdown = model_md.read_text(encoding="utf-8")
    with pytm_build_lock():
        tm = create_threat_model(markdown, name, "eval", cve_service,
                                 validate=False, model_file_path=str(model_md))
        if tm is None:
            logger.error("%s: create_threat_model returned None — skipping", name)
            return 0
        tm.process_threats()

    scenarios = run_gdaf_engine(tm)
    if not scenarios:
        logger.warning("%s: GDAF produced no scenarios — skipping", name)
        # Drop any stale fixture from a previous run so a now-empty template
        # does not leave an outdated <name>.scenarios.json behind (--all reruns).
        (FIXTURE_DIR / f"{name}.scenarios.json").unlink(missing_ok=True)
        return 0

    FIXTURE_DIR.mkdir(parents=True, exist_ok=True)
    out = FIXTURE_DIR / f"{name}.scenarios.json"
    out.write_text(json.dumps(freeze(scenarios), indent=2) + "\n", encoding="utf-8")
    logger.info("%s: wrote %d scenarios -> %s", name, len(scenarios), out.name)
    return len(scenarios)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    g = parser.add_mutually_exclusive_group()
    g.add_argument("--templates", nargs="+", metavar="NAME",
                   help="template directory names under threatModel_Template/")
    g.add_argument("--all", action="store_true",
                   help="freeze every template directory that has a context/ dir")
    args = parser.parse_args(argv)

    # pytm's TM() parses sys.argv on construction — scrub our own CLI args so its
    # argparse does not choke on --templates/--all (mirrors threat_analysis.__main__).
    sys.argv = [sys.argv[0]]

    if args.all:
        names = sorted(
            p.name for p in TEMPLATE_ROOT.iterdir()
            if p.is_dir() and (p / "context").is_dir()
        )
    else:
        names = args.templates or FIRST_PASS

    total = 0
    for name in names:
        total += freeze_template(name)
    logger.info("done — %d templates, %d scenarios total", len(names), total)
    return 0 if total else 1


if __name__ == "__main__":
    sys.exit(main())
