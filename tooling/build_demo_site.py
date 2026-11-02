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

"""Build the static live-demo site published on GitHub Pages.

Runs ``secopstm`` (rule engine only, no LLM, no RAG) on a few bundled
templates and lays the outputs out under stable names:

    <out>/index.html
    <out>/<slug>/diagram.html   interactive diagram with the threat layer
    <out>/<slug>/report.html    full STRIDE / MITRE ATT&CK report
    <out>/<slug>/model.md       the model the demo was generated from

Usage:
    python tooling/build_demo_site.py --out site
"""

from __future__ import annotations

import argparse
import html
import shutil
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
OUTPUT_DIR = REPO_ROOT / "output"

DEMOS = [
    {
        "slug": "advanced-cloud-webapp",
        "title": "Advanced Cloud Web App",
        "model": "threatModel_Template/Advanced_Cloud_WebApp/model.md",
        "blurb": "API gateway, microservices and a database across three trust zones. "
                 "Small enough to read every threat.",
    },
    {
        "slug": "on-prem-enterprise-network",
        "title": "On-Prem Enterprise Network",
        "model": "threatModel_Template/On-Prem_Enterprise_Network/model.md",
        "blurb": "DMZ, Active Directory, OT/SCADA, finance and dev zones: 40+ elements. "
                 "Shows how the threat layer and STRIDE filter scale.",
    },
]


def _run_dirs() -> set[Path]:
    if not OUTPUT_DIR.is_dir():
        return set()
    return {p for p in OUTPUT_DIR.iterdir() if p.is_dir()}


def _single(run_dir: Path, pattern: str) -> Path:
    matches = sorted(run_dir.glob(pattern))
    if len(matches) != 1:
        raise RuntimeError(f"expected one {pattern} in {run_dir}, found {len(matches)}")
    return matches[0]


def build_demo(demo: dict, out: Path) -> None:
    before = _run_dirs()
    cmd = [sys.executable, "-m", "threat_analysis", "--model-file", demo["model"], "--no-rag"]
    print("+", " ".join(cmd), flush=True)
    subprocess.run(cmd, cwd=REPO_ROOT, check=True)
    new_dirs = _run_dirs() - before
    if len(new_dirs) != 1:
        raise RuntimeError(f"could not find the output folder of {demo['model']}: {new_dirs}")
    run_dir = new_dirs.pop()

    dest = out / demo["slug"]
    dest.mkdir(parents=True, exist_ok=True)
    report = _single(run_dir, "stride_mitre_report_*.html")
    diagram = _single(run_dir, "tm_diagram_*.html")

    shutil.copyfile(report, dest / "report.html")
    # The diagram's "Open in the full report" links point at the timestamped
    # report name; point them at the stable one instead.
    diagram_html = diagram.read_text(encoding="utf-8").replace(report.name, "report.html")
    (dest / "diagram.html").write_text(diagram_html, encoding="utf-8")
    shutil.copyfile(REPO_ROOT / demo["model"], dest / "model.md")
    shutil.rmtree(run_dir, ignore_errors=True)


def render_index(out: Path) -> None:
    cards = []
    for demo in DEMOS:
        slug = html.escape(demo["slug"])
        model_url = f"https://github.com/ellipse2v/SecOpsTM/blob/main/{demo['model']}"
        cards.append(f"""
      <article class="card">
        <h2>{html.escape(demo['title'])}</h2>
        <p>{html.escape(demo['blurb'])}</p>
        <div class="links">
          <a class="primary" href="{slug}/diagram.html">Interactive diagram</a>
          <a href="{slug}/report.html">Full threat report</a>
          <a href="{html.escape(model_url)}">Model source (Markdown)</a>
        </div>
      </article>""")

    page = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>SecOpsTM live demo</title>
  <meta name="description" content="Threat modeling as code: one Markdown file in, a STRIDE + MITRE ATT&amp;CK threat report out.">
  <link rel="icon" href="logo.svg">
  <style>
    :root {{ --fg:#1f2328; --muted:#59636e; --bg:#f6f8fa; --card:#fff; --line:#d1d9e0; --accent:#1f6feb; }}
    @media (prefers-color-scheme: dark) {{
      :root {{ --fg:#e6edf3; --muted:#9198a1; --bg:#0d1117; --card:#151b23; --line:#3d444d; --accent:#4493f8; }}
    }}
    * {{ box-sizing:border-box; }}
    body {{ margin:0; font:16px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Helvetica,Arial,sans-serif;
           color:var(--fg); background:var(--bg); }}
    main {{ max-width:960px; margin:0 auto; padding:48px 16px; }}
    header {{ text-align:center; margin-bottom:40px; }}
    header img {{ width:88px; height:88px; }}
    h1 {{ margin:8px 0 4px; font-size:2.2rem; }}
    .tagline {{ font-size:1.15rem; color:var(--muted); margin:0 0 16px; }}
    pre {{ display:inline-block; text-align:left; background:var(--card); border:1px solid var(--line);
          border-radius:8px; padding:12px 16px; margin:0; overflow-x:auto; max-width:100%; }}
    .grid {{ display:grid; gap:20px; grid-template-columns:repeat(auto-fit,minmax(280px,1fr)); }}
    .card {{ background:var(--card); border:1px solid var(--line); border-radius:12px; padding:20px; }}
    .card h2 {{ margin:0 0 8px; font-size:1.25rem; }}
    .card p {{ color:var(--muted); margin:0 0 16px; }}
    .links {{ display:flex; flex-wrap:wrap; gap:8px; }}
    .links a {{ border:1px solid var(--line); border-radius:6px; padding:6px 12px; color:var(--fg);
               text-decoration:none; font-size:.95rem; }}
    .links a.primary {{ background:var(--accent); border-color:var(--accent); color:#fff; }}
    .note {{ color:var(--muted); font-size:.9rem; margin-top:32px; text-align:center; }}
    .note a {{ color:var(--accent); }}
  </style>
</head>
<body>
  <main>
    <header>
      <img src="logo.svg" alt="">
      <h1>SecOpsTM</h1>
      <p class="tagline">Threat modeling as code. One Markdown file in, a STRIDE + MITRE ATT&amp;CK threat report out.</p>
      <pre><code>pip install SecOpsTM
secopstm --model-file threat_model.md</code></pre>
    </header>
    <section class="grid">{''.join(cards)}
    </section>
    <p class="note">
      Generated by the rule engine only (no LLM), straight from the templates in the repository, on every push to main.<br>
      <a href="https://github.com/ellipse2v/SecOpsTM">Source on GitHub</a> ·
      <a href="https://owasp.org/www-project-secopstm/">OWASP project page</a>
    </p>
  </main>
</body>
</html>
"""
    (out / "index.html").write_text(page, encoding="utf-8")
    (out / ".nojekyll").write_text("", encoding="utf-8")
    shutil.copyfile(REPO_ROOT / "docs" / "images" / "logo.svg", out / "logo.svg")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", default="site", help="output folder (default: site)")
    args = parser.parse_args()
    out = Path(args.out).resolve()
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)
    for demo in DEMOS:
        build_demo(demo, out)
    render_index(out)
    print(f"Demo site written to {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
