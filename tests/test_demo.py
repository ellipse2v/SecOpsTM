"""Tests for `secopstm demo` and the `--no-ai` flag it relies on."""

import filecmp
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from threat_analysis import demo

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def _tree_diff(a: Path, b: Path) -> list:
    """Paths that differ between two directory trees (missing, extra or changed)."""
    cmp = filecmp.dircmp(a, b)
    out = [str(a / n) for n in cmp.left_only] + [str(b / n) for n in cmp.right_only]
    _, mismatch, errors = filecmp.cmpfiles(a, b, cmp.common_files, shallow=False)
    out += [str(a / n) for n in mismatch + errors]
    for sub in cmp.common_dirs:
        out += _tree_diff(a / sub, b / sub)
    return out


@pytest.mark.parametrize("slug", list(demo.DEMOS))
def test_bundled_demo_models_match_their_template(slug):
    """The copies shipped in the package must stay identical to threatModel_Template/."""
    template = PROJECT_ROOT / demo.DEMOS[slug][2]
    bundled = demo.DEMO_MODELS_DIR / slug
    assert demo.demo_model_path(slug).is_file()
    diff = _tree_diff(template, bundled)
    assert not diff, (
        f"{bundled} is out of sync with {template}: {diff}. "
        f"Re-copy it: rm -rf {bundled} && cp -r {template} {bundled}"
    )


def test_demo_models_are_declared_as_package_data():
    text = (PROJECT_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert '"demo_models/**/*"' in text


@pytest.mark.parametrize("name,slug", [
    (None, "advanced-cloud-webapp"),
    ("cloud", "advanced-cloud-webapp"),
    ("ON-PREM", "on-prem-enterprise-network"),
    ("on-prem-enterprise-network", "on-prem-enterprise-network"),
])
def test_resolve_demo_accepts_slugs_and_aliases(name, slug):
    assert demo.resolve_demo(name) == slug


def test_unknown_demo_exits_2(capsys):
    assert demo.main(["nope"]) == 2
    assert "unknown demo 'nope'" in capsys.readouterr().err


def test_list(capsys):
    assert demo.main(["--list"]) == 0
    out = capsys.readouterr().out
    for slug, (alias, _, _) in demo.DEMOS.items():
        assert slug in out and alias in out


@pytest.fixture
def fake_run(monkeypatch, tmp_path):
    """Replace the heavy pipeline with one that writes the expected output files."""
    import threat_analysis.__main__ as cli
    from threat_analysis import config

    out_dir = tmp_path / "output" / config.TIMESTAMP
    monkeypatch.setattr(config, "OUTPUT_BASE_DIR", out_dir)
    calls = {}

    def fake_main():
        calls["argv"] = list(sys.argv)
        out_dir.mkdir(parents=True, exist_ok=True)
        ts = config.TIMESTAMP
        (out_dir / config.HTML_REPORT_FILENAME_TPL.format(timestamp=ts)).write_text("<html></html>")
        (out_dir / config.JSON_REPORT_FILENAME_TPL.format(timestamp=ts)).write_text(
            '{"statistics": {"total": 3, "by_severity_level": {"CRITICAL": 1, "LOW": 2}}}'
        )
        if calls.get("diagram", True):
            (out_dir / config.HTML_DIAGRAM_FILENAME_TPL.format(timestamp=ts)).write_text("<html></html>")

    opened = []
    monkeypatch.setattr(cli, "_main", fake_main)
    monkeypatch.setattr(demo.webbrowser, "open", lambda url: opened.append(url) or True)
    calls["opened"] = opened
    calls["out_dir"] = out_dir
    return calls


def test_demo_runs_rule_engine_only_and_opens_the_diagram(fake_run, capsys):
    assert demo.main([]) == 0
    argv = fake_run["argv"]
    assert argv[argv.index("--model-file") + 1] == str(demo.demo_model_path("advanced-cloud-webapp"))
    assert "--no-ai" in argv
    assert len(fake_run["opened"]) == 1 and "tm_diagram_" in fake_run["opened"][0]
    out = capsys.readouterr().out
    assert "3 threats (1 critical, 2 low)" in out
    assert "secopstm --model-file my_model.md" in out


def test_demo_ai_flag_keeps_ai_on(fake_run):
    assert demo.main(["--ai", "--no-browser"]) == 0
    assert "--no-ai" not in fake_run["argv"]
    assert fake_run["opened"] == []


def test_demo_falls_back_to_the_report_without_graphviz(fake_run, capsys):
    fake_run["diagram"] = False
    assert demo.main([]) == 0
    assert "stride_mitre_report_" in fake_run["opened"][0]
    assert "Graphviz is missing" in capsys.readouterr().out


def test_demo_restores_sys_argv(fake_run, monkeypatch):
    monkeypatch.setattr(sys, "argv", ["secopstm", "demo"])
    demo.main(["--no-browser"])
    assert sys.argv == ["secopstm", "demo"]


@pytest.mark.skipif(shutil.which("dot") is None, reason="Graphviz (dot) not installed")
def test_demo_end_to_end_outside_the_repo(tmp_path):
    """`secopstm demo` works from any directory, with an AI provider enabled in the
    local config: --no-ai must keep it from being initialised."""
    (tmp_path / "config").mkdir()
    (tmp_path / "config" / "ai_config.yaml").write_text(
        "ai_providers:\n  anthropic:\n    enabled: true\n    model: claude-haiku-4-5\n",
        encoding="utf-8",
    )
    env = dict(os.environ, PYTHONIOENCODING="utf-8",
               PYTHONPATH=str(PROJECT_ROOT) + os.pathsep + os.environ.get("PYTHONPATH", ""))
    proc = subprocess.run(
        [sys.executable, "-m", "threat_analysis", "demo", "--no-browser"],
        cwd=tmp_path, capture_output=True, text=True, encoding="utf-8", env=env, timeout=600,
    )
    log = proc.stdout + proc.stderr
    assert proc.returncode == 0, log[-3000:]
    assert "Demo ready: Advanced Cloud Web App" in proc.stdout
    assert "AI Provider" not in log
    assert "Severity multipliers file not found" not in log
    assert list((tmp_path / "output").glob("*/tm_diagram_*.html"))
    assert list((tmp_path / "output").glob("*/stride_mitre_report_*.html"))
