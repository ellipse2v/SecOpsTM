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

"""A model that yields no threats must exit 1 with the validator errors, not crash."""

import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def test_model_without_threats_exits_cleanly(tmp_path):
    model_dir = PROJECT_ROOT / "output" / "tmp" / f"invalid_model_{tmp_path.name}"
    model_dir.mkdir(parents=True, exist_ok=True)
    model = model_dir / "model.md"
    model.write_text(
        '## Dataflows\n- **X**: from="Ghost", to="Nobody", protocol="HTTPS"\n',
        encoding="utf-8",
    )
    try:
        proc = subprocess.run(
            [sys.executable, "-m", "threat_analysis", "--model-file",
             str(model.relative_to(PROJECT_ROOT)), "--no-ai", "--output-format", "json"],
            cwd=PROJECT_ROOT, capture_output=True, text=True, timeout=300,
        )
    finally:
        model.unlink(missing_ok=True)
        model_dir.rmdir()
    out = proc.stdout + proc.stderr
    assert proc.returncode == 1, out[-2000:]
    assert "NameError" not in out
    assert "Traceback" not in out
