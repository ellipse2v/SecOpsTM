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

"""Regression test: `--output-file` must create missing parent directories.

Before the fix, `--output-file some/missing/dir/report.html` crashed with
FileNotFoundError in shutil.copy2 because the parent directory did not exist.
"""

import os
import subprocess
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
MODEL = PROJECT_ROOT / "threatModel_Template" / "CI_CD_Pipeline" / "model.md"


@pytest.mark.skipif(not MODEL.exists(), reason="template model not available")
@pytest.mark.parametrize("fmt,ext", [("html", "html"), ("json", "json")])
def test_output_file_creates_missing_parent_dirs(tmp_path, fmt, ext):
    target = tmp_path / "does" / "not" / "exist" / f"report.{ext}"
    assert not target.parent.exists()
    env = dict(os.environ, PYTHONIOENCODING="utf-8")
    proc = subprocess.run(
        [sys.executable, "-m", "threat_analysis",
         "--model-file", str(MODEL.relative_to(PROJECT_ROOT)),
         "--output-format", fmt, "--output-file", str(target)],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        env=env,
        timeout=600,
    )
    assert proc.returncode == 0, proc.stderr[-2000:]
    assert "FileNotFoundError" not in proc.stderr
    assert target.is_file()
    assert target.stat().st_size > 0
