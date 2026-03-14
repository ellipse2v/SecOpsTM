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

"""Tests for threat_analysis/core/bom_loader.py"""

import json
import pytest
from pathlib import Path

from threat_analysis.core.bom_loader import (
    BOMLoader,
    _normalize_asset_key,
    _get_secopstm_prop,
    _parse_cyclonedx,
    _load_cyclonedx_file,
    _load_yaml_file,
)


# ---------------------------------------------------------------------------
# _normalize_asset_key
# ---------------------------------------------------------------------------

class TestNormalizeAssetKey:
    def test_lowercase_spaces_to_underscores(self):
        assert _normalize_asset_key("Primary Domain Controller") == "primary_domain_controller"

    def test_hyphens_to_underscores(self):
        assert _normalize_asset_key("web-server") == "web_server"

    def test_mixed(self):
        assert _normalize_asset_key("My  Server-01") == "my_server_01"

    def test_strips_special_chars(self):
        assert _normalize_asset_key("server!@#") == "server"

    def test_already_normalized(self):
        assert _normalize_asset_key("web_server") == "web_server"

    def test_empty_string(self):
        assert _normalize_asset_key("") == ""


# ---------------------------------------------------------------------------
# _get_secopstm_prop
# ---------------------------------------------------------------------------

class TestGetSecopstmProp:
    def test_found(self):
        props = [{"name": "secopstm:detection_level", "value": "high"}]
        assert _get_secopstm_prop(props, "detection_level") == "high"

    def test_not_found(self):
        props = [{"name": "secopstm:other", "value": "x"}]
        assert _get_secopstm_prop(props, "missing") is None

    def test_empty_list(self):
        assert _get_secopstm_prop([], "anything") is None

    def test_value_none_returns_none(self):
        props = [{"name": "secopstm:notes", "value": None}]
        assert _get_secopstm_prop(props, "notes") is None

    def test_non_dict_entry_skipped(self):
        props = ["not a dict", {"name": "secopstm:patch_level", "value": "current"}]
        assert _get_secopstm_prop(props, "patch_level") == "current"


# ---------------------------------------------------------------------------
# _parse_cyclonedx
# ---------------------------------------------------------------------------

class TestParseCyclonedx:
    def _minimal(self, **kwargs):
        base = {
            "components": [],
            "services": [],
            "vulnerabilities": [],
            "properties": [],
        }
        base.update(kwargs)
        return base

    def test_empty_data(self):
        result = _parse_cyclonedx({})
        assert result["os_version"] is None
        assert result["software_version"] is None
        assert result["running_services"] == []
        assert result["known_cves"] == []

    def test_os_component(self):
        data = self._minimal(components=[
            {"type": "operating-system", "name": "ubuntu", "version": "22.04"}
        ])
        result = _parse_cyclonedx(data)
        assert result["os_version"] == "ubuntu_22.04"

    def test_software_version_from_non_os_component(self):
        data = self._minimal(components=[
            {"type": "library", "name": "nginx", "version": "1.24.0"}
        ])
        result = _parse_cyclonedx(data)
        assert result["software_version"] == "nginx 1.24.0"

    def test_os_and_software(self):
        data = self._minimal(components=[
            {"type": "operating-system", "name": "windows_server", "version": "2019"},
            {"type": "application", "name": "iis", "version": "10"},
        ])
        result = _parse_cyclonedx(data)
        assert result["os_version"] == "windows_server_2019"
        assert result["software_version"] == "iis 10"

    def test_running_services(self):
        data = self._minimal(services=[{"name": "httpd"}, {"name": "sshd"}])
        result = _parse_cyclonedx(data)
        assert result["running_services"] == ["httpd", "sshd"]

    def test_known_cves(self):
        data = self._minimal(vulnerabilities=[{"id": "CVE-2023-1234"}, {"id": "CVE-2024-5678"}])
        result = _parse_cyclonedx(data)
        assert result["known_cves"] == ["CVE-2023-1234", "CVE-2024-5678"]

    def test_secopstm_properties(self):
        data = self._minimal(properties=[
            {"name": "secopstm:detection_level", "value": "medium"},
            {"name": "secopstm:credentials_stored", "value": "true"},
            {"name": "secopstm:patch_level", "value": "current"},
            {"name": "secopstm:notes", "value": "test notes"},
        ])
        result = _parse_cyclonedx(data)
        assert result["detection_level"] == "medium"
        assert result["credentials_stored"] is True
        assert result["patch_level"] == "current"
        assert result["notes"] == "test notes"

    def test_credentials_stored_false(self):
        data = self._minimal(properties=[
            {"name": "secopstm:credentials_stored", "value": "false"},
        ])
        result = _parse_cyclonedx(data)
        assert result["credentials_stored"] is False

    def test_credentials_stored_yes(self):
        data = self._minimal(properties=[
            {"name": "secopstm:credentials_stored", "value": "yes"},
        ])
        result = _parse_cyclonedx(data)
        assert result["credentials_stored"] is True

    def test_non_dict_component_skipped(self):
        data = self._minimal(components=["not a dict"])
        result = _parse_cyclonedx(data)
        assert result["os_version"] is None

    def test_os_version_with_spaces_normalized(self):
        data = self._minimal(components=[
            {"type": "operating-system", "name": "Red Hat Enterprise Linux", "version": "9"}
        ])
        result = _parse_cyclonedx(data)
        assert " " not in result["os_version"]

    def test_missing_component_version(self):
        data = self._minimal(components=[
            {"type": "library", "name": "curl", "version": ""}
        ])
        result = _parse_cyclonedx(data)
        assert result["software_version"] == "curl"


# ---------------------------------------------------------------------------
# _load_cyclonedx_file
# ---------------------------------------------------------------------------

class TestLoadCyclonedxFile:
    def test_valid_file(self, tmp_path):
        content = {
            "bomFormat": "CycloneDX",
            "components": [{"type": "operating-system", "name": "ubuntu", "version": "20.04"}],
        }
        f = tmp_path / "asset.cdx.json"
        f.write_text(json.dumps(content), encoding="utf-8")
        result = _load_cyclonedx_file(f)
        assert result is not None
        assert result["os_version"] == "ubuntu_20.04"

    def test_wrong_bom_format_returns_none(self, tmp_path):
        content = {"bomFormat": "SPDX"}
        f = tmp_path / "bad.json"
        f.write_text(json.dumps(content), encoding="utf-8")
        result = _load_cyclonedx_file(f)
        assert result is None

    def test_invalid_json_returns_none(self, tmp_path):
        f = tmp_path / "bad.json"
        f.write_text("not json {{", encoding="utf-8")
        result = _load_cyclonedx_file(f)
        assert result is None

    def test_non_object_json_returns_none(self, tmp_path):
        f = tmp_path / "array.json"
        f.write_text(json.dumps([1, 2, 3]), encoding="utf-8")
        result = _load_cyclonedx_file(f)
        assert result is None

    def test_nonexistent_file_returns_none(self, tmp_path):
        result = _load_cyclonedx_file(tmp_path / "missing.json")
        assert result is None


# ---------------------------------------------------------------------------
# _load_yaml_file
# ---------------------------------------------------------------------------

class TestLoadYamlFile:
    def test_valid_yaml(self, tmp_path):
        f = tmp_path / "asset.yaml"
        f.write_text("os_version: ubuntu_20.04\ncredentials_stored: true\n", encoding="utf-8")
        result = _load_yaml_file(f)
        assert result is not None
        assert result["os_version"] == "ubuntu_20.04"

    def test_invalid_yaml_returns_none(self, tmp_path):
        f = tmp_path / "bad.yaml"
        f.write_text(": invalid: yaml:\n  bad:\n", encoding="utf-8")
        # Actually may not fail — test with a truly invalid file
        # Use a non-mapping YAML instead
        f.write_text("- item1\n- item2\n", encoding="utf-8")
        result = _load_yaml_file(f)
        assert result is None

    def test_nonexistent_file_returns_none(self, tmp_path):
        result = _load_yaml_file(tmp_path / "missing.yaml")
        assert result is None

    def test_empty_yaml_returns_empty_dict(self, tmp_path):
        f = tmp_path / "empty.yaml"
        f.write_text("", encoding="utf-8")
        # yaml.safe_load of empty string returns None → _load_yaml_file returns {}
        result = _load_yaml_file(f)
        # Result should be {} (empty dict) since `yaml.safe_load(...) or {}`
        assert result == {}


# ---------------------------------------------------------------------------
# BOMLoader — constructor edge cases
# ---------------------------------------------------------------------------

class TestBOMLoaderConstructor:
    def test_none_directory(self):
        loader = BOMLoader(None)
        assert not loader
        assert loader.get("anything") == {}

    def test_nonexistent_directory(self, tmp_path):
        loader = BOMLoader(str(tmp_path / "does_not_exist"))
        assert not loader

    def test_empty_directory(self, tmp_path):
        loader = BOMLoader(str(tmp_path))
        assert not loader

    def test_bool_false_when_empty(self, tmp_path):
        loader = BOMLoader(str(tmp_path))
        assert bool(loader) is False

    def test_bool_true_when_loaded(self, tmp_path):
        content = {"bomFormat": "CycloneDX", "components": []}
        f = tmp_path / "server.cdx.json"
        f.write_text(json.dumps(content), encoding="utf-8")
        loader = BOMLoader(str(tmp_path))
        assert bool(loader) is True


# ---------------------------------------------------------------------------
# BOMLoader — get()
# ---------------------------------------------------------------------------

class TestBOMLoaderGet:
    def test_get_unknown_key(self, tmp_path):
        loader = BOMLoader(str(tmp_path))
        assert loader.get("Unknown Server") == {}

    def test_get_case_insensitive_yaml(self, tmp_path):
        f = tmp_path / "primary_domain_controller.yaml"
        f.write_text("os_version: windows_server_2019\n", encoding="utf-8")
        loader = BOMLoader(str(tmp_path))
        result = loader.get("Primary Domain Controller")
        assert result.get("os_version") == "windows_server_2019"

    def test_get_with_hyphens_in_name(self, tmp_path):
        f = tmp_path / "web_server.yaml"
        f.write_text("os_version: linux\n", encoding="utf-8")
        loader = BOMLoader(str(tmp_path))
        result = loader.get("web-server")
        assert result.get("os_version") == "linux"

    def test_cyclonedx_takes_priority_over_yaml(self, tmp_path):
        # Create both a YAML and a CycloneDX file for the same asset
        yaml_f = tmp_path / "database.yaml"
        yaml_f.write_text("os_version: from_yaml\n", encoding="utf-8")
        cdx_f = tmp_path / "database.cdx.json"
        cdx_data = {
            "bomFormat": "CycloneDX",
            "components": [{"type": "operating-system", "name": "from_cdx", "version": ""}],
        }
        cdx_f.write_text(json.dumps(cdx_data), encoding="utf-8")
        loader = BOMLoader(str(tmp_path))
        result = loader.get("database")
        # CycloneDX should win
        assert result.get("os_version") == "from_cdx"

    def test_multiple_assets(self, tmp_path):
        for name in ("server_a", "server_b"):
            f = tmp_path / f"{name}.yaml"
            f.write_text(f"notes: {name}\n", encoding="utf-8")
        loader = BOMLoader(str(tmp_path))
        assert loader.get("server_a").get("notes") == "server_a"
        assert loader.get("server_b").get("notes") == "server_b"

    def test_plain_json_loaded_when_cyclonedx_format(self, tmp_path):
        f = tmp_path / "firewall.json"
        content = {
            "bomFormat": "CycloneDX",
            "services": [{"name": "pf"}],
        }
        f.write_text(json.dumps(content), encoding="utf-8")
        loader = BOMLoader(str(tmp_path))
        result = loader.get("firewall")
        assert result.get("running_services") == ["pf"]

    def test_plain_json_skipped_when_not_cyclonedx(self, tmp_path):
        f = tmp_path / "other.json"
        content = {"bomFormat": "SPDX", "packages": []}
        f.write_text(json.dumps(content), encoding="utf-8")
        loader = BOMLoader(str(tmp_path))
        assert loader.get("other") == {}

    def test_malformed_yaml_skipped(self, tmp_path):
        f = tmp_path / "broken.yaml"
        f.write_text("- a\n- b\n", encoding="utf-8")  # list, not dict
        loader = BOMLoader(str(tmp_path))
        assert loader.get("broken") == {}

    def test_cdx_json_does_not_override_already_loaded_cdx(self, tmp_path):
        # .cdx.json has priority over plain .json for the same asset key
        cdx_f = tmp_path / "host.cdx.json"
        cdx_data = {"bomFormat": "CycloneDX", "properties": [
            {"name": "secopstm:notes", "value": "from_cdx"}
        ]}
        cdx_f.write_text(json.dumps(cdx_data), encoding="utf-8")
        plain_f = tmp_path / "host.json"
        plain_data = {"bomFormat": "CycloneDX", "properties": [
            {"name": "secopstm:notes", "value": "from_plain"}
        ]}
        plain_f.write_text(json.dumps(plain_data), encoding="utf-8")
        loader = BOMLoader(str(tmp_path))
        result = loader.get("host")
        assert result.get("notes") == "from_cdx"
