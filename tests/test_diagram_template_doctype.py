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

"""Every HTML template must declare a doctype, or browsers render it in quirks mode."""

from pathlib import Path

import pytest

TEMPLATES = Path(__file__).resolve().parents[1] / "threat_analysis" / "templates"


@pytest.mark.parametrize("name", ["navigable_diagram_template.html", "diagram_template.html"])
def test_diagram_templates_declare_doctype_and_charset(name):
    text = (TEMPLATES / name).read_text(encoding="utf-8")
    # Comments may precede the doctype; nothing else may.
    body = text.split("-->", 1)[1] if text.lstrip().startswith("<!--") else text
    assert body.lstrip().lower().startswith("<!doctype html>")
    assert '<meta charset="UTF-8">' in text
    assert "<title>" in text
