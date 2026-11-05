# Contributing to SecOpsTM

Thanks for helping. SecOpsTM is an [OWASP project](https://owasp.org/www-project-secopstm/): threat modeling as code, one Markdown file in, a STRIDE + MITRE ATT&CK report out. Contributions of every size are welcome, from a typo fix to a new IaC importer.

## Where to start

- **Issues labelled [`good first issue`](https://github.com/ellipse2v/SecOpsTM/labels/good%20first%20issue)** are small and self-contained, with the files to touch named in the issue.
- **A new example architecture** in `threatModel_Template/` is the easiest first contribution: no Python needed, and every model makes the tool more useful to someone. See below.
- **A new asset type or protocol mapping**: see [CONTRIBUTING_ASSET_TYPES.md](CONTRIBUTING_ASSET_TYPES.md).
- **Something bigger** (a new output format, an IaC importer, an AI provider): open an issue first so we can agree on the approach before you write the code.

## Set up

```bash
git clone https://github.com/ellipse2v/SecOpsTM.git
cd SecOpsTM
python -m venv .venv && source .venv/bin/activate
pip install -e .
pip install pytest
```

Install [Graphviz](https://graphviz.org/download/) for the diagrams (`dot -V` must answer). Check the setup:

```bash
secopstm demo          # analyses a bundled example and opens its diagram
python -m pytest       # the whole suite
```

No API key is needed: the rule engine and the tests run fully offline. The AI enrichment (LLM + RAG) is optional, see [docs/getting_started.md](docs/getting_started.md).

## Adding an example model

1. Create `threatModel_Template/<Your_Architecture>/model.md`. Start from a model close to yours (`secopstm demo --list` shows two, `threatModel_Template/` has 18) and the DSL reference in [docs/dsl-syntax.md](docs/dsl-syntax.md).
2. Optionally add a `BOM/` folder (one YAML per server, versions and known CVEs) and a `context/` folder, like the existing templates.
3. Check it: `secopstm validate --model-dir threatModel_Template/<Your_Architecture>` must pass, and `secopstm --model-file threatModel_Template/<Your_Architecture>/model.md` must produce a report and a diagram that read well.
4. The test suite runs `validate` on every template, so a broken model fails CI.

Use only public, generic architectures. Never contribute a real organisation's model.

## Pull requests

- One topic per pull request, with a short description of what changes and why. The pull request template lists the checks.
- Add or update tests for what you change. `python -m pytest` must pass.
- Every new `.py`, `.js` and `.html` file starts with the Apache 2.0 header used across the repository (copy it from an existing file such as `tests/test_main.py`). A test enforces it.
- PRs are merged with "Rebase and merge": keep a clean, linear history (rebase on `main` rather than merging it in).

## Reporting bugs and security issues

Use the issue templates for bugs and feature requests. Report vulnerabilities privately, as described in [SECURITY.md](SECURITY.md).

## License

By contributing, you agree that your contributions are licensed under the [Apache License 2.0](LICENSE).
