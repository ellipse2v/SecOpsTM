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

"""Regression tests for the path-traversal / XML / auth hardening pass."""

import json
import os
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from threat_analysis.utils import (
    UnsafePathError,
    resolve_bom_directory,
    resolve_gdaf_context,
    resolve_model_relative_path,
    safe_join,
    safe_xml_fromstring,
)


# ---------------------------------------------------------------------------
# safe_join / resolve_model_relative_path
# ---------------------------------------------------------------------------

def test_safe_join_accepts_nested_relative_path(tmp_path):
    assert safe_join(tmp_path, "a/b/c.md") == (tmp_path / "a" / "b" / "c.md").resolve()


@pytest.mark.parametrize("bad", ["../x.md", "a/../../x.md", "a/b/../../../x.md", "..\\x.md"])
def test_safe_join_rejects_traversal(tmp_path, bad):
    with pytest.raises(UnsafePathError):
        safe_join(tmp_path, bad)


def test_safe_join_treats_absolute_path_as_relative(tmp_path):
    # `/etc/passwd` must land under base, never at the real /etc/passwd
    assert safe_join(tmp_path, "/etc/passwd") == (tmp_path / "etc" / "passwd").resolve()


def test_safe_join_rejects_symlink_escape(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    base = tmp_path / "base"
    base.mkdir()
    (base / "link").symlink_to(outside)
    with pytest.raises(UnsafePathError):
        safe_join(base, "link/secret.md")


def test_safe_join_root_allows_dotdot_up_to_root_only(tmp_path):
    (tmp_path / "sub").mkdir()
    assert safe_join(tmp_path / "sub", "../shared.md", root=tmp_path) == (tmp_path / "shared.md").resolve()
    with pytest.raises(UnsafePathError):
        safe_join(tmp_path / "sub", "../../shared.md", root=tmp_path)


def test_resolve_model_relative_path_blocks_escape(tmp_path):
    model = tmp_path / "proj" / "model.md"
    model.parent.mkdir()
    assert resolve_model_relative_path("../secret.yaml", str(model)) is None
    assert resolve_model_relative_path("context/ok.yaml", str(model)) == (
        tmp_path / "proj" / "context" / "ok.yaml"
    ).resolve()


def test_resolve_gdaf_context_ignores_file_outside_model_dir(tmp_path):
    secret = tmp_path / "secret.yaml"
    secret.write_text("threat_actors: []")
    proj = tmp_path / "proj"
    proj.mkdir()
    tm = SimpleNamespace(
        context_config={"gdaf_context": "../secret.yaml"},
        _model_file_path=str(proj / "model.md"),
    )
    assert resolve_gdaf_context(tm) is None
    # an absolute path must not be honoured either
    tm.context_config = {"gdaf_context": str(secret)}
    assert resolve_gdaf_context(tm) is None


def test_resolve_gdaf_context_accepts_file_inside_model_dir(tmp_path):
    (tmp_path / "context").mkdir()
    ctx = tmp_path / "context" / "c.yaml"
    ctx.write_text("threat_actors: []")
    tm = SimpleNamespace(
        context_config={"gdaf_context": "context/c.yaml"},
        _model_file_path=str(tmp_path / "model.md"),
    )
    assert resolve_gdaf_context(tm) == str(ctx.resolve())


def test_resolve_bom_directory_ignores_directory_outside_model_dir(tmp_path):
    other = tmp_path / "other_project" / "BOM"
    other.mkdir(parents=True)
    proj = tmp_path / "proj"
    proj.mkdir()
    tm = SimpleNamespace(
        context_config={"bom_directory": "../other_project/BOM"},
        _model_file_path=str(proj / "model.md"),
    )
    assert resolve_bom_directory(tm) is None


# ---------------------------------------------------------------------------
# XML
# ---------------------------------------------------------------------------

def test_safe_xml_fromstring_parses_plain_svg():
    assert safe_xml_fromstring('<svg xmlns="http://www.w3.org/2000/svg"/>').tag.endswith("svg")


def test_safe_xml_fromstring_rejects_entity_declarations():
    bomb = '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "aaaa">]><svg>&a;</svg>'
    with pytest.raises(ValueError):
        safe_xml_fromstring(bomb)


# ---------------------------------------------------------------------------
# submodel= javascript: link
# ---------------------------------------------------------------------------

def test_add_links_to_svg_skips_non_path_submodel():
    from threat_analysis.generation.diagram_generator import DiagramGenerator

    svg = (
        '<svg xmlns="http://www.w3.org/2000/svg"><g id="Evil"><title>Evil</title></g></svg>'
    )
    tm = SimpleNamespace(servers=[{"name": "Evil", "submodel": "javascript:alert(1);//"}])
    out = DiagramGenerator().add_links_to_svg(svg, tm)
    assert "javascript:" not in out


# ---------------------------------------------------------------------------
# Flask routes
# ---------------------------------------------------------------------------

@pytest.fixture
def client():
    from threat_analysis.server.server import app

    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


def _post(client, url, payload):
    return client.post(url, data=json.dumps(payload), content_type="application/json")


@pytest.mark.parametrize("field", ["submodel", "extra_file", "active_path"])
def test_generate_all_rejects_traversal_and_writes_nothing_outside(client, tmp_path, field):
    out = tmp_path / "out"
    payload = {"markdown": "# T"}
    if field == "submodel":
        payload["submodels"] = [{"path": "a/../../../evil.md", "content": "pwned"}]
    elif field == "extra_file":
        payload["extra_files"] = [{"path": "a/../../../evil.yaml", "content": "pwned"}]
    else:
        payload["path"] = "a/../../../evil.md"

    with patch("threat_analysis.server.server.config.OUTPUT_BASE_DIR", str(out)), \
         patch("threat_analysis.server.server.get_threat_model_service") as svc:
        svc.return_value = MagicMock()
        resp = _post(client, "/api/generate_all", payload)

    assert resp.status_code == 400
    assert resp.get_json()["error"] == "Invalid file path"
    assert not list(tmp_path.rglob("evil.*"))


def test_generate_all_releases_lock_after_rejection(client, tmp_path):
    import threat_analysis.server.server as srv

    with patch("threat_analysis.server.server.config.OUTPUT_BASE_DIR", str(tmp_path)):
        _post(client, "/api/generate_all",
              {"markdown": "# T", "submodels": [{"path": "../x.md", "content": "y"}]})
    assert srv._generate_all_lock.acquire(blocking=False)
    srv._generate_all_lock.release()


def test_generate_all_rejects_too_many_submodels(client, tmp_path):
    with patch("threat_analysis.server.server.config.OUTPUT_BASE_DIR", str(tmp_path)):
        resp = _post(client, "/api/generate_all",
                     {"markdown": "# T", "submodels": [{"path": f"{i}.md", "content": "x"} for i in range(201)]})
    assert resp.status_code == 413


def test_generate_all_refuses_concurrent_generation(client, tmp_path):
    import threat_analysis.server.server as srv

    assert srv._generate_all_lock.acquire(blocking=False)
    try:
        with patch("threat_analysis.server.server.config.OUTPUT_BASE_DIR", str(tmp_path)):
            resp = _post(client, "/api/generate_all", {"markdown": "# T"})
        assert resp.status_code == 429
    finally:
        srv._generate_all_lock.release()


def test_load_metadata_opens_the_validated_path_not_the_raw_value(client, tmp_path, monkeypatch):
    """The guard resolved the request path against project_root, but the old code then
    open()ed the raw string relative to the CWD — so the file that was checked and the
    file that was read could differ."""
    root = tmp_path / "root"
    (root / "output").mkdir(parents=True)
    (root / "output" / "m.json").write_text('{"version": "1.0"}')
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)  # CWD != project_root

    with patch("threat_analysis.server.server.config.OUTPUT_BASE_DIR", str(root / "output")), \
         patch("threat_analysis.server.server.project_root", str(root)):
        resp = _post(client, "/api/load_metadata", {"metadata_path": "output/m.json"})

    assert resp.status_code == 200
    assert resp.get_json()["metadata"] == {"version": "1.0"}


def test_token_is_stripped_from_url_after_login(client, monkeypatch):
    monkeypatch.setenv("SECOPSTM_REQUIRE_AUTH", "true")
    monkeypatch.setenv("SECOPSTM_API_TOKEN", "s3cret")

    assert client.get("/").status_code == 401

    resp = client.get("/?token=s3cret&keep=1")
    assert resp.status_code == 302
    assert "token" not in resp.headers["Location"]
    assert "keep=1" in resp.headers["Location"]

    # session cookie now authenticates without the token
    assert client.get("/").status_code == 200


def test_wrong_token_is_rejected(client, monkeypatch):
    monkeypatch.setenv("SECOPSTM_REQUIRE_AUTH", "true")
    monkeypatch.setenv("SECOPSTM_API_TOKEN", "s3cret")
    assert client.get("/?token=nope").status_code == 401


# ---------------------------------------------------------------------------
# Archive extraction
# ---------------------------------------------------------------------------

def _tar_with(tmp_path, build):
    import io
    import tarfile

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        build(tf)
    buf.seek(0)
    return tarfile.open(fileobj=buf, mode="r:gz")


def _add_file(tf, name, data=b"x"):
    import io
    import tarfile

    info = tarfile.TarInfo(name)
    info.size = len(data)
    tf.addfile(info, io.BytesIO(data))


def test_safe_extract_tar_extracts_regular_archive(tmp_path):
    from threat_analysis.utils import safe_extract_tar

    with _tar_with(tmp_path, lambda tf: _add_file(tf, "external_data/a.json", b"{}")) as tf:
        safe_extract_tar(tf, tmp_path / "dest")
    assert (tmp_path / "dest" / "external_data" / "a.json").read_bytes() == b"{}"


def test_safe_extract_tar_rejects_dotdot_member(tmp_path):
    from threat_analysis.utils import safe_extract_tar

    with _tar_with(tmp_path, lambda tf: _add_file(tf, "../evil.py")) as tf:
        with pytest.raises(UnsafePathError):
            safe_extract_tar(tf, tmp_path / "dest")
    assert not (tmp_path / "evil.py").exists()


def test_safe_extract_tar_rejects_escaping_symlink(tmp_path):
    import tarfile

    from threat_analysis.utils import safe_extract_tar

    def build(tf):
        link = tarfile.TarInfo("link")
        link.type = tarfile.SYMTYPE
        link.linkname = "../../outside"
        tf.addfile(link)

    with _tar_with(tmp_path, build) as tf:
        with pytest.raises(UnsafePathError):
            safe_extract_tar(tf, tmp_path / "dest")


def test_safe_extract_tar_rejects_absolute_symlink(tmp_path):
    import tarfile

    from threat_analysis.utils import safe_extract_tar

    def build(tf):
        link = tarfile.TarInfo("link")
        link.type = tarfile.SYMTYPE
        link.linkname = "/etc/passwd"
        tf.addfile(link)

    with _tar_with(tmp_path, build) as tf:
        with pytest.raises(UnsafePathError):
            safe_extract_tar(tf, tmp_path / "dest")


# ---------------------------------------------------------------------------
# HTML output escaping
# ---------------------------------------------------------------------------

def test_diagram_html_escapes_model_controlled_values():
    from threat_analysis.generation.diagram_generator import DiagramGenerator

    payload = "</script><script>alert(1)</script>"
    tm = SimpleNamespace(name="x</title><script>alert(2)</script>")
    html_out = DiagramGenerator()._create_complete_html(
        "<svg/>", "<div>legend</div>", tm,
        graph_metadata={"nodes": [payload]},
        severity_map={payload: "HIGH"},
        report_url="';alert(3);//",
    )
    assert "<script>alert(" not in html_out
    assert "</script><script>" not in html_out
    assert "';alert(3);//" not in html_out


def test_diagram_generator_keeps_dot_template_unescaped():
    """Autoescape must not touch the .j2 DOT template (quotes would become &#34;)."""
    from threat_analysis.generation.diagram_generator import DiagramGenerator

    env = DiagramGenerator().template_env
    assert env.autoescape("diagram_template.html") is True
    assert env.autoescape("threat_model.dot.j2") is False


def test_report_generator_escapes_html_templates():
    from threat_analysis.generation.report_generator import ReportGenerator

    rg = ReportGenerator(MagicMock(), MagicMock(), cve_service=MagicMock())
    assert rg.env.autoescape("report_template.html") is True


# ---------------------------------------------------------------------------
# AI cache opt-out, GDAF bounds, caller-selected AI config
# ---------------------------------------------------------------------------

def test_ai_cache_disabled_by_env_ignores_and_never_writes_file(tmp_path, monkeypatch):
    from threat_analysis.core.ai_cache import AIThreatCache

    model = tmp_path / "model.md"
    model.write_text("# m")
    cache_file = tmp_path / ".secopstm_ai_cache.json"
    poisoned = {"version": 1, "entries": {"abc": {"threats": [], "component": "x", "provider": "p"}}}
    cache_file.write_text(json.dumps(poisoned))

    monkeypatch.setenv("SECOPSTM_DISABLE_AI_CACHE", "true")
    cache = AIThreatCache(str(model))
    assert cache.get("abc") is None  # poisoned entry not served
    cache.put("def", "comp", "prov", [{"title": "t"}])
    cache.save()
    assert json.loads(cache_file.read_text()) == poisoned  # untouched


def test_ai_cache_enabled_by_default(tmp_path, monkeypatch):
    from threat_analysis.core.ai_cache import AIThreatCache

    monkeypatch.delenv("SECOPSTM_DISABLE_AI_CACHE", raising=False)
    model = tmp_path / "model.md"
    model.write_text("# m")
    cache = AIThreatCache(str(model))
    cache.put("k", "comp", "prov", [])
    cache.save()
    assert (tmp_path / ".secopstm_ai_cache.json").exists()


def test_gdaf_bfs_stops_at_expansion_budget(monkeypatch):
    import threat_analysis.core.gdaf_engine as gdaf

    monkeypatch.setattr(gdaf, "_MAX_BFS_EXPANSIONS", 50)
    # Fully connected 12-node graph, unreachable target: unbounded search is exponential.
    names = [f"n{i}" for i in range(12)]
    graph = {n: {"edges": [{"target": m} for m in names if m != n]} for n in names}
    engine = gdaf.GDAFEngine.__new__(gdaf.GDAFEngine)
    assert engine._bfs_paths(graph, "n0", "unreachable", max_hops=11) == []


def test_litellm_client_reads_the_config_it_is_given(tmp_path):
    import asyncio

    from threat_analysis.ai_engine.providers.litellm_client import LiteLLMClient

    cfg = tmp_path / "chosen.yaml"
    cfg.write_text("ai_providers: {}\n")
    client = LiteLLMClient()
    asyncio.run(client._load_ai_config(config_path=cfg))
    assert client.ai_config == {"ai_providers": {}}


def test_litellm_provider_forwards_config_path(tmp_path):
    import asyncio
    from unittest.mock import AsyncMock

    from threat_analysis.ai_engine.providers.litellm_provider import LiteLLMProvider

    async def _run():
        with patch(
            "threat_analysis.ai_engine.providers.litellm_client.LiteLLMClient.create",
            new_callable=AsyncMock,
        ) as create:
            await LiteLLMProvider({}, config_path=tmp_path / "c.yaml")._get_client()
            assert create.call_args.kwargs["config_path"] == tmp_path / "c.yaml"

    asyncio.run(_run())
