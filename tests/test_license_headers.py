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

"""Every Python, JavaScript and HTML source file starts with the Apache 2.0 header.

Files that predate this check and have no header are listed in KNOWN_WITHOUT_HEADER,
so the test only fails for new files. Remove a path from the list once it gets its
header; never add a new file to it.
"""

import subprocess
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SOURCE_DIRS = ("threat_analysis", "tests", "tooling")
SUFFIXES = {".py", ".js", ".html"}

KNOWN_WITHOUT_HEADER = {
    "tests/test_ansible_playbooks.py",
    "tests/test_iac_plugins.py",
    "tests/test_project_generation.py",
    "threat_analysis/generation/graphviz_to_konva.py",
    "threat_analysis/server/static/js/config.js",  # generated at startup
    "tooling/capec_mitre_parser.py",
}


def _needs_header(rel: str) -> bool:
    p = Path(rel)
    if p.suffix not in SUFFIXES or rel in KNOWN_WITHOUT_HEADER:
        return False
    if p.name == "__init__.py" or p.name.endswith(".min.js"):
        return False  # package markers and vendored minified libraries
    if "demo_models" in p.parts or "ansible_playbooks" in p.parts:
        return False
    return True


def _tracked_sources():
    try:
        out = subprocess.run(
            ["git", "ls-files", *SOURCE_DIRS], cwd=PROJECT_ROOT,
            capture_output=True, text=True, check=True,
        ).stdout
    except (OSError, subprocess.CalledProcessError):
        pytest.skip("not a git checkout")
    return [rel for rel in out.splitlines() if _needs_header(rel)]


def test_source_files_have_the_license_header():
    missing = []
    for rel in _tracked_sources():
        path = PROJECT_ROOT / rel
        if not path.is_file():
            continue
        head = path.read_text(encoding="utf-8", errors="replace")[:600]
        if "Copyright 20" not in head or "Apache License" not in head:
            missing.append(rel)
    assert not missing, (
        "These files are missing the Apache 2.0 header (copy it from tests/test_main.py): "
        + ", ".join(missing)
    )
