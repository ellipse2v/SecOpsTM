# Live demo (GitHub Pages)

The live demo at <https://ellipse2v.github.io/SecOpsTM/> is built by
`.github/workflows/pages-demo.yml`, which runs `tooling/build_demo_site.py` on
every push to `main` that touches the engine, the two demo templates or the
demo files.

| Demo slug | Template |
|---|---|
| `advanced-cloud-webapp` | `threatModel_Template/Advanced_Cloud_WebApp/model.md` |
| `on-prem-enterprise-network` | `threatModel_Template/On-Prem_Enterprise_Network/model.md` |

By default CI regenerates each demo with the **rule engine only** (no API key in
CI, `--no-rag`).

## Publishing AI-enriched reports

To show reports generated with the LLM and RAG passes, generate them locally
and **pin** them: a demo whose `docs/demo/<slug>/` folder holds `report.html`
and `diagram.html` is published as is instead of being regenerated.

```bash
# 1. Generate with AI on (provider and key set up as in docs/enriching_ai_threats.md)
secopstm --model-file threatModel_Template/Advanced_Cloud_WebApp/model.md

# 2. Pin the output folder that run created to the demo
python tooling/build_demo_site.py --import advanced-cloud-webapp output/<timestamp>

# 3. Optional: preview the whole site locally
python tooling/build_demo_site.py --out site   # then open site/index.html

# 4. Commit docs/demo/<slug>/ and merge to main: the workflow redeploys
```

`--import` copies the report and diagram under stable names, rewrites the
diagram's "Open in the full report" links, and keeps the run's `model.md`. The
demo's card on the index page then reads "pinned report" instead of "rule engine
only".

To go back to the CI-generated version:

```bash
python tooling/build_demo_site.py --unpin advanced-cloud-webapp
```

then commit the deletion. Note that a pinned report is a snapshot: it does not
follow later engine changes until you regenerate and re-import it.
