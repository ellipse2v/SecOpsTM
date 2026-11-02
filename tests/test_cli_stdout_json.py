"""Regression test: `secopstm --stdout` must print pure JSON on stdout.

Banners, config-generation messages and any other informational output must go
to stderr so that CI/SIEM consumers can pipe stdout straight into a JSON parser.
"""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
MODEL = PROJECT_ROOT / "threatModel_Template" / "CI_CD_Pipeline" / "model.md"


@pytest.mark.skipif(not MODEL.exists(), reason="template model not available")
def test_stdout_flag_emits_pure_json():
    env = dict(os.environ, PYTHONIOENCODING="utf-8")
    proc = subprocess.run(
        [sys.executable, "-m", "threat_analysis",
         "--model-file", str(MODEL.relative_to(PROJECT_ROOT)), "--stdout"],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        env=env,
        timeout=600,
    )
    assert proc.returncode == 0, proc.stderr[-2000:]
    # Whole stdout must parse as JSON: no banner, no config lines, no logs.
    report = json.loads(proc.stdout)
    assert isinstance(report, dict)
    # The informational banner still exists, just on stderr.
    assert "SecOpsTM Framework is starting" in proc.stderr
    assert "SecOpsTM Framework is starting" not in proc.stdout


def test_main_redirects_prints_to_stderr(monkeypatch, capsys):
    """main() routes stray print() calls to stderr when --stdout is set."""
    import threat_analysis.__main__ as cli

    def fake_main():
        print("noise that must not reach stdout")
        (cli._JSON_STDOUT or sys.stdout).write('{"ok": true}')

    monkeypatch.setattr(cli, "_main", fake_main)
    monkeypatch.setattr(sys, "argv", ["secopstm", "--model-file", "m.md", "--stdout"])
    cli.main()
    out, err = capsys.readouterr()
    assert json.loads(out) == {"ok": True}
    assert "noise that must not reach stdout" in err
    assert cli._JSON_STDOUT is None
