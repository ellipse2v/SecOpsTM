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

"""--project on a directory without main.md / model.md must exit 1, not 0."""

import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def test_project_without_root_model_exits_1(tmp_path):
    empty = tmp_path / "empty_project"
    empty.mkdir()
    proc = subprocess.run(
        [sys.executable, "-m", "threat_analysis", "--project", str(empty), "--no-ai"],
        cwd=PROJECT_ROOT, capture_output=True, text=True, timeout=300,
    )
    assert proc.returncode == 1, proc.stderr[-2000:]
    assert "no main.md or model.md" in proc.stderr
    # Nothing written: the output directory used to be created with static/ copied in.
    assert not list((PROJECT_ROOT / "output").glob(f"*/{empty.name}"))
