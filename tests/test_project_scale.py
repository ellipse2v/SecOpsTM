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

"""Scale tests for multi-model projects: 50 folders deep and 50 folders wide.

Every sub-model lives in its own folder and is named ``model.md`` — the layout
that used to break navigation, because sub-models were matched by file name.
Diagrams are rendered for real (Graphviz + custom SVG generator) and every link
of every generated ``*_diagram.html`` is resolved on disk.
"""

import argparse
import json
import re
import shutil
import xml.etree.ElementTree as ET
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from threat_analysis.core.cve_service import CVEService
from threat_analysis.core.mitre_mapping_module import MitreMapping
from threat_analysis.generation.report_generator import ReportGenerator
from threat_analysis.severity_calculator_module import SeverityCalculator

DEPTH = 50
WIDTH = 50

SVG_NS = "{http://www.w3.org/2000/svg}"
XLINK_HREF = "{http://www.w3.org/1999/xlink}href"

requires_graphviz = pytest.mark.skipif(
    shutil.which("dot") is None, reason="Graphviz 'dot' executable not installed"
)


def _model(servers: str, dataflows: str = "") -> str:
    return (
        "# Threat Model: M\n"
        "## Boundaries\n- **Zone**:\n"
        "## Servers\n" + servers + "\n"
        "## Dataflows\n" + dataflows
    )


def _deep_files(depth: int) -> dict:
    """main.md -> level1/model.md -> level1/level2/model.md -> ... (depth levels)."""
    files = {
        "main.md": _model(
            "- **Client**: boundary=Zone\n"
            "- **Node0**: boundary=Zone, submodel=./level1/model.md\n",
            "- **ClientToNode0**: from=Client, to=Node0, protocol=HTTPS\n",
        )
    }
    rel = ""
    for i in range(1, depth + 1):
        rel += f"level{i}/"
        servers = f"- **Entry{i}**: boundary=Zone\n"
        flows = ""
        if i < depth:
            servers += f"- **Node{i}**: boundary=Zone, submodel=./level{i + 1}/model.md\n"
            flows = f"- **Flow{i}**: from=Entry{i}, to=Node{i}, protocol=HTTPS\n"
        files[rel + "model.md"] = _model(servers, flows)
    return files


def _wide_files(width: int) -> dict:
    """main.md -> svc0/model.md ... svc{width-1}/model.md."""
    servers = "- **Client**: boundary=Zone\n"
    flows = ""
    files = {}
    for i in range(width):
        servers += f"- **Svc{i}**: boundary=Zone, submodel=./svc{i}/model.md\n"
        flows += f"- **Flow{i}**: from=Client, to=Svc{i}, protocol=HTTPS\n"
        files[f"svc{i}/model.md"] = _model(f"- **Inner{i}**: boundary=Zone\n")
    files["main.md"] = _model(servers, flows)
    return files


def _write_project(root: Path, files: dict) -> None:
    for rel, content in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")


def _generate(tmp_root: Path, files: dict) -> Path:
    project_path = tmp_root / "project"
    output_path = tmp_root / "output"
    project_path.mkdir()
    output_path.mkdir()
    _write_project(project_path, files)
    cve_defs = project_path / "cve_definitions.yml"
    cve_defs.touch()

    with patch("pytm.pytm.get_args") as mock_get_args:
        mock_get_args.return_value = argparse.Namespace(
            debug=False, sqldump=None, dfd=None, report=None, exclude=None, seq=None,
            list=None, colormap=None, describe=None, list_elements=None, json=None,
            levels=None, stale_days=None,
        )
        generator = ReportGenerator(
            SeverityCalculator(), MitreMapping(),
            cve_service=CVEService(tmp_root, cve_defs),
        )
        main_tm = generator.generate_project_reports(project_path, output_path)
    assert main_tm is not None
    return output_path


def _svg_root(html_text: str) -> ET.Element:
    """Parses the diagram's top-level <svg> (node icons are nested <svg>s)."""
    start = html_text.find("<svg")
    assert start != -1, "no inline <svg> in diagram HTML"
    depth = 0
    for tag in re.finditer(r"<(/?)svg\b[^>]*?(/?)>", html_text[start:]):
        if tag.group(1):
            depth -= 1
        elif not tag.group(2):
            depth += 1
        if depth == 0:
            return ET.fromstring(html_text[start:start + tag.end()])
    raise AssertionError("unbalanced <svg> in diagram HTML")


def _submodel_links(html_text: str) -> list:
    root = _svg_root(html_text)
    return [a.get(XLINK_HREF) for a in root.iter(f"{SVG_NS}a") if a.get(XLINK_HREF)]


def _breadcrumb(html_text: str) -> list:
    match = re.search(r'<div class="breadcrumb">(.*?)</div>', html_text, re.S)
    assert match, "no breadcrumb in diagram HTML"
    return re.findall(r'<a href="([^"]+)">([^<]+)</a>', match.group(1))


def _back_link(html_text: str):
    match = re.search(r'<a href="([^"]+)" class="back-button"', html_text)
    return match.group(1) if match else None


def _broken_local_links(html_path: Path) -> list:
    text = html_path.read_text(encoding="utf-8")
    broken = []
    for link in re.findall(r'(?:xlink:href|href|src)="([^"#]+)"', text):
        if re.match(r"^[a-z]+:", link) or link.startswith("/") or "{{" in link or "${" in link:
            continue
        if not (html_path.parent / link).exists():
            broken.append(link)
    return broken


@pytest.fixture(scope="module")
def deep_output(tmp_path_factory):
    return _generate(tmp_path_factory.mktemp("deep_project"), _deep_files(DEPTH))


@pytest.fixture(scope="module")
def wide_output(tmp_path_factory):
    return _generate(tmp_path_factory.mktemp("wide_project"), _wide_files(WIDTH))


# ---------------------------------------------------------------------------
# Static export: 50 levels deep
# ---------------------------------------------------------------------------

@requires_graphviz
def test_deep_project_generates_every_level(deep_output):
    diagrams = sorted(deep_output.rglob("*_diagram.html"))
    assert len(diagrams) == DEPTH + 1
    rel = Path()
    for i in range(1, DEPTH + 1):
        rel /= f"level{i}"
        assert (deep_output / rel / "model_diagram.html").is_file(), f"level {i} missing"
        assert (deep_output / rel / "model.svg").is_file(), f"level {i} SVG missing"


@requires_graphviz
def test_deep_project_svgs_are_valid_and_complete(deep_output):
    for svg_path in sorted(deep_output.rglob("*.svg")):
        if "static" in svg_path.relative_to(deep_output).parts:
            continue
        root = ET.fromstring(svg_path.read_text(encoding="utf-8"))  # must be well-formed
        assert root.tag == f"{SVG_NS}svg"
        assert float(root.get("width", "0").rstrip("pt")) > 0
        assert float(root.get("height", "0").rstrip("pt")) > 0

    rel = Path()
    for i in range(1, DEPTH + 1):
        rel /= f"level{i}"
        text = (deep_output / rel / "model_diagram.html").read_text(encoding="utf-8")
        assert f"Entry{i}" in "".join(_svg_root(text).itertext())


@requires_graphviz
def test_deep_project_navigation_reaches_the_bottom_and_back(deep_output):
    # Follow the sub-model link of each diagram down to the deepest level.
    current = deep_output / "main_diagram.html"
    for i in range(1, DEPTH + 1):
        links = _submodel_links(current.read_text(encoding="utf-8"))
        assert len(links) == 1, f"{current}: expected one sub-model link, got {links}"
        nxt = (current.parent / links[0]).resolve()
        assert nxt == (current.parent / f"level{i}" / "model_diagram.html").resolve()
        current = nxt
    assert _submodel_links(current.read_text(encoding="utf-8")) == []

    # ...then walk back up with the "Back" button.
    for i in range(DEPTH, 0, -1):
        back = _back_link(current.read_text(encoding="utf-8"))
        assert back is not None, f"level {i}: no back button"
        current = (current.parent / back).resolve()
    assert current == (deep_output / "main_diagram.html").resolve()
    assert _back_link(current.read_text(encoding="utf-8")) is None


@requires_graphviz
def test_deep_project_breadcrumbs_point_to_each_ancestor(deep_output):
    rel = Path()
    for i in range(1, DEPTH + 1):
        rel /= f"level{i}"
        html_path = deep_output / rel / "model_diagram.html"
        crumbs = _breadcrumb(html_path.read_text(encoding="utf-8"))
        assert [name for _, name in crumbs] == ["main"] + [f"level{k}" for k in range(1, i + 1)]
        for depth, (href, name) in enumerate(crumbs):
            target = (html_path.parent / href).resolve()
            expected_dir = deep_output.joinpath(*[f"level{k}" for k in range(1, depth + 1)])
            expected = expected_dir / ("main_diagram.html" if depth == 0 else "model_diagram.html")
            assert target == expected.resolve(), f"level {i}: breadcrumb '{name}' -> {href}"


@requires_graphviz
def test_deep_project_has_no_broken_local_link(deep_output):
    broken = {
        str(p.relative_to(deep_output)): links
        for p in deep_output.rglob("*_diagram.html")
        if (links := _broken_local_links(p))
    }
    assert broken == {}


# ---------------------------------------------------------------------------
# Static export: 50 folders wide
# ---------------------------------------------------------------------------

@requires_graphviz
def test_wide_project_generates_every_sibling(wide_output):
    assert len(list(wide_output.rglob("*_diagram.html"))) == WIDTH + 1
    for i in range(WIDTH):
        assert (wide_output / f"svc{i}" / "model_diagram.html").is_file(), f"svc{i} missing"
        assert (wide_output / f"svc{i}" / "model.svg").is_file(), f"svc{i} SVG missing"


@requires_graphviz
def test_wide_project_main_svg_links_every_sibling(wide_output):
    text = (wide_output / "main_diagram.html").read_text(encoding="utf-8")
    svg_text = "".join(_svg_root(text).itertext())
    for i in range(WIDTH):
        assert f"Svc{i}" in svg_text, f"Svc{i} not drawn in main SVG"

    links = _submodel_links(text)
    assert sorted(links) == sorted(f"svc{i}/model_diagram.html" for i in range(WIDTH))
    for link in links:
        assert (wide_output / link).is_file()


@requires_graphviz
def test_wide_project_children_navigate_back_to_main(wide_output):
    for i in range(WIDTH):
        html_path = wide_output / f"svc{i}" / "model_diagram.html"
        text = html_path.read_text(encoding="utf-8")
        assert f"Inner{i}" in "".join(_svg_root(text).itertext())
        assert _back_link(text) == "../main_diagram.html"
        assert _breadcrumb(text) == [("../main_diagram.html", "main"), ("model_diagram.html", f"svc{i}")]


@requires_graphviz
def test_wide_project_has_no_broken_local_link(wide_output):
    broken = {
        str(p.relative_to(wide_output)): links
        for p in wide_output.rglob("*_diagram.html")
        if (links := _broken_local_links(p))
    }
    assert broken == {}


# ---------------------------------------------------------------------------
# Web editor: /api/generate_all must rebuild the same tree from the open tabs
# ---------------------------------------------------------------------------

@pytest.fixture
def client():
    import threat_analysis.server.server as server_module
    server_module.app.config["TESTING"] = True
    server_module.initial_model_file_path = None
    with server_module.app.test_client() as c:
        yield c


@pytest.mark.parametrize("files_factory", [lambda: _deep_files(DEPTH), lambda: _wide_files(WIDTH)], ids=["deep", "wide"])
@pytest.mark.parametrize("prefix", ["", "myproject/"], ids=["server-tabs", "load-project-tabs"])
@pytest.mark.parametrize("active", ["main", "submodel"])
def test_generate_all_rebuilds_project_tree(client, tmp_path, files_factory, prefix, active):
    """The tabs are written under the project root whatever the active tab is.

    "Load project" prefixes every tab with the picked folder name, and the user
    may click "Generate" while looking at a sub-model: neither may move or
    overwrite a model, otherwise the submodel= links no longer resolve.
    """
    files = files_factory()
    tabs = {prefix + rel: content for rel, content in files.items()}
    active_rel = "main.md" if active == "main" else sorted(r for r in files if r != "main.md")[-1]
    active_tab = prefix + active_rel
    payload = {
        "markdown": tabs[active_tab],
        "path": active_tab,
        "submodels": [{"path": p, "content": c} for p, c in tabs.items() if p != active_tab],
        "extra_files": [],
    }

    with patch("threat_analysis.server.server.config.OUTPUT_BASE_DIR", str(tmp_path)), \
         patch("threat_analysis.server.server.get_threat_model_service") as mock_get_service:
        mock_service = MagicMock()
        mock_service.generate_full_project_export.return_value = {"reports": {}, "diagrams": {}}
        mock_get_service.return_value = mock_service
        response = client.post("/api/generate_all", data=json.dumps(payload), content_type="application/json")

    assert response.status_code == 200, response.get_data(as_text=True)
    generation_dir = Path(response.get_json()["generation_dir"])
    for rel, content in files.items():
        assert (generation_dir / rel).read_text(encoding="utf-8") == content, rel
    if prefix:
        assert not (generation_dir / prefix.rstrip("/")).exists()

    main_content = mock_service.generate_full_project_export.call_args.args[0]
    assert main_content == files["main.md"]
    assert mock_service.generate_full_project_export.call_args.kwargs["project_root"] == generation_dir


def test_rebase_project_files_drops_paths_escaping_the_project():
    from threat_analysis.server.server import _rebase_project_files

    files, active, main = _rebase_project_files(
        "proj/main.md", "MAIN",
        [
            {"path": "proj/a/model.md", "content": "A"},
            {"path": "../evil.md", "content": "X"},
            {"path": "/etc/evil.md", "content": "X"},
            {"path": "proj/../../evil.md", "content": "X"},
        ],
    )
    assert files == {"main.md": "MAIN", "a/model.md": "A"}
    assert active == "main.md"
    assert main == "MAIN"


def test_load_project_puts_root_main_first(tmp_path):
    from threat_analysis.server.threat_model_service import ThreatModelService

    _write_project(tmp_path, {**_deep_files(DEPTH), **{f"w{i}/main.md": "x" for i in range(3)}})
    service = ThreatModelService.__new__(ThreatModelService)
    paths = [Path(f["path"]).as_posix() for f in service.load_project(str(tmp_path))]
    assert paths[0] == "main.md"
    depths = [p.count("/") for p in paths]
    assert depths == sorted(depths)
