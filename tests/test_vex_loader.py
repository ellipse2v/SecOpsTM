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

"""Tests for threat_analysis.core.vex_loader."""

import json
from pathlib import Path

import pytest

from threat_analysis.core.vex_loader import (
    ACTIVE_STATES,
    FIXED_STATES,
    IGNORED_STATES,
    VEXEntry,
    VEXLoader,
    _normalize_key,
    _parse_vex_document,
)


# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------


def _vex_doc(vulns: list) -> dict:
    """Build a minimal CycloneDX VEX document."""
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "vulnerabilities": vulns,
    }


def _vuln(cve_id: str, state: str, refs: list = None, detail: str = "") -> dict:
    """Build a single vulnerability entry."""
    v = {
        "id": cve_id,
        "analysis": {"state": state, "detail": detail},
    }
    if refs:
        v["affects"] = [{"ref": r} for r in refs]
    return v


def _write_vex(path: Path, vulns: list) -> Path:
    """Write a CycloneDX VEX file and return its path."""
    path.write_text(json.dumps(_vex_doc(vulns)), encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# _normalize_key
# ---------------------------------------------------------------------------


class TestNormalizeKey:
    def test_lowercase(self):
        assert _normalize_key("WebApp") == "webapp"

    def test_spaces_become_underscores(self):
        assert _normalize_key("Primary DC") == "primary_dc"

    def test_hyphens_become_underscores(self):
        assert _normalize_key("web-server") == "web_server"

    def test_special_chars_removed(self):
        assert _normalize_key("API (v2)") == "api_v2"

    def test_leading_trailing_stripped(self):
        assert _normalize_key("  app  ") == "app"


# ---------------------------------------------------------------------------
# _parse_vex_document
# ---------------------------------------------------------------------------


class TestParseVexDocument:
    def test_empty_vulns(self):
        entries = _parse_vex_document({"vulnerabilities": []})
        assert entries == []

    def test_single_affected(self):
        doc = _vex_doc([_vuln("CVE-2021-44228", "affected", ["log4j"])])
        entries = _parse_vex_document(doc)
        assert len(entries) == 1
        assert entries[0].cve_id == "CVE-2021-44228"
        assert entries[0].state == "affected"
        assert entries[0].component_ref == "log4j"

    def test_cve_id_uppercased(self):
        doc = _vex_doc([_vuln("cve-2021-44228", "affected", ["comp"])])
        entries = _parse_vex_document(doc)
        assert entries[0].cve_id == "CVE-2021-44228"

    def test_multiple_refs_creates_multiple_entries(self):
        doc = _vex_doc([_vuln("CVE-2021-1234", "fixed", ["A", "B", "C"])])
        entries = _parse_vex_document(doc)
        assert len(entries) == 3
        refs = {e.component_ref for e in entries}
        assert refs == {"a", "b", "c"}

    def test_no_refs_creates_global_entry(self):
        doc = _vex_doc([_vuln("CVE-2021-9999", "affected")])
        entries = _parse_vex_document(doc)
        assert len(entries) == 1
        assert entries[0].component_ref == "__global__"

    def test_detail_preserved(self):
        doc = _vex_doc([_vuln("CVE-2021-1111", "fixed", ["app"], detail="Patched in v2.1")])
        entries = _parse_vex_document(doc)
        assert entries[0].detail == "Patched in v2.1"

    def test_missing_id_skipped(self):
        doc = {"vulnerabilities": [{"analysis": {"state": "affected"}}]}
        entries = _parse_vex_document(doc)
        assert entries == []

    def test_non_dict_vuln_skipped(self):
        doc = {"vulnerabilities": ["not-a-dict", None]}
        entries = _parse_vex_document(doc)
        assert entries == []

    def test_all_active_states_parsed(self):
        for state in ACTIVE_STATES:
            doc = _vex_doc([_vuln("CVE-2021-0001", state, ["app"])])
            entries = _parse_vex_document(doc)
            assert entries[0].state == state

    def test_all_fixed_states_parsed(self):
        for state in FIXED_STATES:
            doc = _vex_doc([_vuln("CVE-2021-0002", state, ["app"])])
            entries = _parse_vex_document(doc)
            assert entries[0].state == state


# ---------------------------------------------------------------------------
# VEXLoader.empty()
# ---------------------------------------------------------------------------


class TestVEXLoaderEmpty:
    def test_empty_returns_no_data(self):
        loader = VEXLoader.empty()
        assert not loader.has_data()
        assert loader.get_active_cves("anything") == []
        assert loader.get_fixed_cves("anything") == []

    def test_bool_false(self):
        assert not VEXLoader.empty()


# ---------------------------------------------------------------------------
# VEXLoader.from_file()
# ---------------------------------------------------------------------------


class TestVEXLoaderFromFile:
    def test_loads_active_cve(self, tmp_path):
        p = tmp_path / "vex.json"
        _write_vex(p, [_vuln("CVE-2021-44228", "exploitable", ["webapp"])])
        loader = VEXLoader.from_file(p)
        assert loader.has_data()
        assert "CVE-2021-44228" in loader.get_active_cves("WebApp")

    def test_loads_fixed_cve(self, tmp_path):
        p = tmp_path / "vex.json"
        _write_vex(p, [_vuln("CVE-2021-1234", "fixed", ["db"])])
        loader = VEXLoader.from_file(p)
        assert "CVE-2021-1234" in loader.get_fixed_cves("DB")

    def test_ignored_state_not_in_active_or_fixed(self, tmp_path):
        p = tmp_path / "vex.json"
        _write_vex(p, [_vuln("CVE-2021-9999", "not_affected", ["app"])])
        loader = VEXLoader.from_file(p)
        assert loader.get_active_cves("app") == []
        assert loader.get_fixed_cves("app") == []

    def test_missing_file_returns_empty(self, tmp_path):
        loader = VEXLoader.from_file(tmp_path / "missing.json")
        assert not loader.has_data()

    def test_invalid_json_returns_empty(self, tmp_path):
        p = tmp_path / "bad.json"
        p.write_text("not json", encoding="utf-8")
        loader = VEXLoader.from_file(p)
        assert not loader.has_data()

    def test_bool_true_when_data(self, tmp_path):
        p = tmp_path / "vex.json"
        _write_vex(p, [_vuln("CVE-2021-1", "affected", ["a"])])
        loader = VEXLoader.from_file(p)
        assert bool(loader)

    def test_component_name_normalization(self, tmp_path):
        p = tmp_path / "vex.json"
        _write_vex(p, [_vuln("CVE-2021-5555", "affected", ["Primary DC"])])
        loader = VEXLoader.from_file(p)
        # Both the stored key and the query are normalised
        assert "CVE-2021-5555" in loader.get_active_cves("primary_dc")
        assert "CVE-2021-5555" in loader.get_active_cves("Primary DC")

    def test_global_entry_returned_for_any_component(self, tmp_path):
        """A VEX entry with no affects[] applies to all components."""
        p = tmp_path / "vex.json"
        _write_vex(p, [_vuln("CVE-2021-7777", "affected")])
        loader = VEXLoader.from_file(p)
        assert "CVE-2021-7777" in loader.get_active_cves("AnyComponent")
        assert "CVE-2021-7777" in loader.get_active_cves("AnotherComponent")

    def test_multiple_vulns_in_one_file(self, tmp_path):
        p = tmp_path / "vex.json"
        _write_vex(p, [
            _vuln("CVE-2021-0001", "affected", ["app"]),
            _vuln("CVE-2021-0002", "fixed", ["app"]),
            _vuln("CVE-2021-0003", "not_affected", ["app"]),
        ])
        loader = VEXLoader.from_file(p)
        assert loader.get_active_cves("app") == ["CVE-2021-0001"]
        assert loader.get_fixed_cves("app") == ["CVE-2021-0002"]


# ---------------------------------------------------------------------------
# VEXLoader.from_directory()
# ---------------------------------------------------------------------------


class TestVEXLoaderFromDirectory:
    def test_loads_multiple_files(self, tmp_path):
        _write_vex(tmp_path / "comp1.json", [_vuln("CVE-2021-0001", "affected", ["comp1"])])
        _write_vex(tmp_path / "comp2.json", [_vuln("CVE-2021-0002", "fixed", ["comp2"])])
        loader = VEXLoader.from_directory(tmp_path)
        assert "CVE-2021-0001" in loader.get_active_cves("comp1")
        assert "CVE-2021-0002" in loader.get_fixed_cves("comp2")

    def test_missing_directory_returns_empty(self, tmp_path):
        loader = VEXLoader.from_directory(tmp_path / "nonexistent")
        assert not loader.has_data()

    def test_non_json_files_ignored(self, tmp_path):
        (tmp_path / "notes.txt").write_text("irrelevant", encoding="utf-8")
        loader = VEXLoader.from_directory(tmp_path)
        assert not loader.has_data()


# ---------------------------------------------------------------------------
# VEXLoader.from_model_path()
# ---------------------------------------------------------------------------


class TestVEXLoaderFromModelPath:
    def test_discovers_vex_directory(self, tmp_path):
        model_file = tmp_path / "model.md"
        model_file.write_text("# Model", encoding="utf-8")
        vex_dir = tmp_path / "VEX"
        vex_dir.mkdir()
        _write_vex(vex_dir / "global.json", [_vuln("CVE-2021-0001", "affected", ["web"])])
        loader = VEXLoader.from_model_path(str(model_file))
        assert loader is not None
        assert "CVE-2021-0001" in loader.get_active_cves("web")

    def test_discovers_vex_json(self, tmp_path):
        model_file = tmp_path / "model.md"
        model_file.write_text("# Model", encoding="utf-8")
        _write_vex(tmp_path / "vex.json", [_vuln("CVE-2021-0002", "fixed", ["db"])])
        loader = VEXLoader.from_model_path(str(model_file))
        assert loader is not None
        assert "CVE-2021-0002" in loader.get_fixed_cves("db")

    def test_vex_dir_preferred_over_vex_json(self, tmp_path):
        """VEX/ directory takes precedence over vex.json."""
        model_file = tmp_path / "model.md"
        model_file.write_text("# Model", encoding="utf-8")
        vex_dir = tmp_path / "VEX"
        vex_dir.mkdir()
        _write_vex(vex_dir / "f.json", [_vuln("CVE-DIR", "affected", ["c"])])
        _write_vex(tmp_path / "vex.json", [_vuln("CVE-FILE", "affected", ["c"])])
        loader = VEXLoader.from_model_path(str(model_file))
        assert "CVE-DIR" in loader.get_active_cves("c")

    def test_returns_none_when_nothing_found(self, tmp_path):
        model_file = tmp_path / "model.md"
        model_file.write_text("# Model", encoding="utf-8")
        result = VEXLoader.from_model_path(str(model_file))
        assert result is None


# ---------------------------------------------------------------------------
# get_active_cves / get_fixed_cves — state distinctions
# ---------------------------------------------------------------------------


class TestStateDistinctions:
    def _loader_with(self, tmp_path, state: str) -> VEXLoader:
        p = tmp_path / f"vex_{state}.json"
        _write_vex(p, [_vuln("CVE-2021-9999", state, ["target"])])
        return VEXLoader.from_file(p)

    @pytest.mark.parametrize("state", sorted(ACTIVE_STATES))
    def test_active_states_in_get_active(self, tmp_path, state):
        loader = self._loader_with(tmp_path, state)
        assert "CVE-2021-9999" in loader.get_active_cves("target")
        assert "CVE-2021-9999" not in loader.get_fixed_cves("target")

    @pytest.mark.parametrize("state", sorted(FIXED_STATES))
    def test_fixed_states_in_get_fixed(self, tmp_path, state):
        loader = self._loader_with(tmp_path, state)
        assert "CVE-2021-9999" in loader.get_fixed_cves("target")
        assert "CVE-2021-9999" not in loader.get_active_cves("target")

    @pytest.mark.parametrize("state", sorted(IGNORED_STATES))
    def test_ignored_states_absent_everywhere(self, tmp_path, state):
        loader = self._loader_with(tmp_path, state)
        assert "CVE-2021-9999" not in loader.get_active_cves("target")
        assert "CVE-2021-9999" not in loader.get_fixed_cves("target")
