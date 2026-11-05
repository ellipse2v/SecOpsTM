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

"""``secopstm demo``: analyse a bundled example model and open its diagram.

The first thing a new user can run after ``pip install SecOpsTM``: no model to
write, no API key, no config file. The example models ship inside the package
(``threat_analysis/demo_models/``, copies of two ``threatModel_Template/`` models
kept in sync by a test), the analysis runs on the rule engine only, and the
interactive HTML diagram opens in the browser.

Usage:
    secopstm demo                  # Advanced Cloud Web App (small, readable)
    secopstm demo on-prem          # On-Prem Enterprise Network (40+ elements)
    secopstm demo --no-browser     # just print where the files are
    secopstm demo --ai             # use the LLM providers of config/ai_config.yaml
    secopstm demo --list
"""

from __future__ import annotations

import argparse
import json
import sys
import webbrowser
from pathlib import Path
from typing import List, Optional

DEMO_MODELS_DIR = Path(__file__).resolve().parent / "demo_models"

# slug -> (short alias, title, template it is copied from)
DEMOS = {
    "advanced-cloud-webapp": (
        "cloud",
        "Advanced Cloud Web App: API gateway, microservices and a database across three trust zones",
        "threatModel_Template/Advanced_Cloud_WebApp",
    ),
    "on-prem-enterprise-network": (
        "on-prem",
        "On-Prem Enterprise Network: DMZ, AD, ERP, OT and backups, 40+ elements",
        "threatModel_Template/On-Prem_Enterprise_Network",
    ),
}
DEFAULT_DEMO = "advanced-cloud-webapp"


def resolve_demo(name: Optional[str]) -> str:
    """Return the slug for a slug or a short alias (``cloud``, ``on-prem``)."""
    if not name:
        return DEFAULT_DEMO
    key = name.strip().lower()
    if key in DEMOS:
        return key
    for slug, (alias, _, _) in DEMOS.items():
        if key == alias:
            return slug
    raise ValueError(
        f"unknown demo '{name}'. Choose one of: "
        + ", ".join(f"{alias} ({slug})" for slug, (alias, _, _) in DEMOS.items())
    )


def demo_model_path(slug: str) -> Path:
    return DEMO_MODELS_DIR / slug / "model.md"


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="secopstm demo",
        description="Analyse a bundled example threat model and open its interactive diagram.",
    )
    p.add_argument(
        "model", nargs="?", default=None,
        help="Which example: 'cloud' (default) or 'on-prem'. See --list.",
    )
    p.add_argument("--list", action="store_true", help="List the bundled examples and exit.")
    p.add_argument(
        "--no-browser", action="store_true", dest="no_browser",
        help="Do not open the diagram, only print where the files are.",
    )
    p.add_argument(
        "--ai", action="store_true",
        help="Also run the AI enrichment, with the providers enabled in config/ai_config.yaml\n"
             "(an API key or Ollama is needed). Without it the demo uses the rule engine only.",
    )
    return p


def _summary(json_report: Path) -> Optional[str]:
    """One line on what the analysis found, read from the JSON report."""
    try:
        stats = json.loads(json_report.read_text(encoding="utf-8")).get("statistics", {})
    except (OSError, ValueError):
        return None
    total = stats.get("total")
    if total is None:
        return None
    sev = stats.get("by_severity_level", {})
    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    parts = [f"{sev[k]} {k.lower()}" for k in order if sev.get(k)]
    return f"{total} threats" + (f" ({', '.join(parts)})" if parts else "")


def main(argv: Optional[List[str]] = None) -> int:
    args = _build_parser().parse_args(argv)

    if args.list:
        for slug, (alias, title, _) in DEMOS.items():
            default = "  [default]" if slug == DEFAULT_DEMO else ""
            print(f"  {alias:<8} {slug:<28} {title}{default}")
        return 0

    try:
        slug = resolve_demo(args.model)
    except ValueError as exc:
        print(f"secopstm demo: {exc}", file=sys.stderr)
        return 2

    model = demo_model_path(slug)
    if not model.is_file():
        print(f"secopstm demo: bundled model missing: {model}", file=sys.stderr)
        return 1

    # Run the regular single-model pipeline on the bundled file.
    from threat_analysis import __main__ as cli  # noqa: PLC0415  (heavy imports)
    from threat_analysis import config  # noqa: PLC0415

    run_argv = [sys.argv[0] or "secopstm", "--model-file", str(model)]
    if not args.ai:
        run_argv.append("--no-ai")
    saved_argv = sys.argv
    sys.argv = run_argv
    try:
        cli._main()
    finally:
        sys.argv = saved_argv

    out_dir = Path(config.OUTPUT_BASE_DIR)
    report = out_dir / config.HTML_REPORT_FILENAME_TPL.format(timestamp=config.TIMESTAMP)
    diagram = out_dir / config.HTML_DIAGRAM_FILENAME_TPL.format(timestamp=config.TIMESTAMP)
    json_report = out_dir / config.JSON_REPORT_FILENAME_TPL.format(timestamp=config.TIMESTAMP)

    if not report.is_file():
        print("secopstm demo: the analysis did not produce a report, see the log above.", file=sys.stderr)
        return 1

    target = diagram if diagram.is_file() else report
    found = _summary(json_report)

    print()
    print(f"✅ Demo ready: {DEMOS[slug][1].split(':')[0]}" + (f", {found}" if found else ""))
    if diagram.is_file():
        print(f"   Diagram: {diagram}")
    else:
        print("   Diagram: not generated (Graphviz is missing: install it, then run the demo again)")
    print(f"   Report:  {report}")
    print(f"   Model:   {model}")

    opened = False
    if not args.no_browser:
        try:
            opened = webbrowser.open(target.resolve().as_uri())
        except Exception:  # noqa: BLE001  (no browser, headless box)
            opened = False
    if opened:
        print(f"   Opened the {'diagram' if target == diagram else 'report'} in your browser:"
              " click a threat badge, try the STRIDE filter and the heat map in the legend.")
    elif not args.no_browser:
        print("   No browser available here: open the file above in any browser.")

    print()
    print("Next: start your own model from this one")
    print(f"   cp {model} my_model.md")
    print("   secopstm --model-file my_model.md")
    return 0
