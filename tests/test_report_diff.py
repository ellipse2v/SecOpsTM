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

"""Tests for the report diff mechanism (utils.compare_threat_reports /
__main__.diff_threat_reports), used by `secopstm --diff` and wired into
action.yml's PR comment."""

import json
from pathlib import Path

import pytest

from threat_analysis.utils import compare_threat_reports
from threat_analysis.__main__ import diff_threat_reports


def _threat(target, stride, description, severity="HIGH", name=None):
    t = {
        "target": target,
        "stride_category": stride,
        "description": description,
        # ReportSerializer/the v1 schema nest severity as {score, level, ...}.
        "severity": {"score": None, "level": severity, "formatted_score": None},
    }
    if name is not None:
        t["name"] = name
    return t


def _report(threats):
    return {"schema_version": "1.0", "threats": threats}


class TestCompareThreatReports:
    def test_no_differences(self):
        threats = [_threat("WebApp", "Tampering", "SQL injection")]
        result = compare_threat_reports(_report(threats), _report(threats))
        assert result["added"] == []
        assert result["resolved"] == []
        assert result["changed"] == []

    def test_added_and_resolved(self):
        old = [_threat("WebApp", "Tampering", "SQL injection")]
        new = [_threat("WebApp", "Spoofing", "Credential theft")]
        result = compare_threat_reports(_report(old), _report(new))
        assert len(result["added"]) == 1
        assert len(result["resolved"]) == 1
        assert result["added"][0]["description"] == "Credential theft"
        assert result["resolved"][0]["description"] == "SQL injection"

    def test_severity_change_detected(self):
        old = [_threat("WebApp", "Tampering", "SQL injection", severity="LOW")]
        new = [_threat("WebApp", "Tampering", "SQL injection", severity="CRITICAL")]
        result = compare_threat_reports(_report(old), _report(new))
        assert result["added"] == []
        assert result["resolved"] == []
        assert len(result["changed"]) == 1
        assert result["changed"][0]["old"]["severity"]["level"] == "LOW"
        assert result["changed"][0]["new"]["severity"]["level"] == "CRITICAL"

    def test_distinct_threats_sharing_target_and_category_are_not_collapsed(self):
        """Real ReportSerializer output never populates "name" — keying only on
        (target, stride_category, name) previously collapsed every threat sharing
        a target+category onto a single dict entry, silently dropping the rest.
        """
        old = [
            _threat("Target Server", "Tampering", "Unpatched OS vulnerability"),
            _threat("Target Server", "Tampering", "Firmware downgrade attack"),
        ]
        new = [
            _threat("Target Server", "Tampering", "Unpatched OS vulnerability"),
        ]
        result = compare_threat_reports(_report(old), _report(new))
        # Only the second old threat should show up as resolved — if the key
        # collision bug were present, both old threats would collapse into one
        # and this would incorrectly report 0 resolved (or the wrong one).
        assert len(result["resolved"]) == 1
        assert result["resolved"][0]["description"] == "Firmware downgrade attack"
        assert result["added"] == []

    def test_legacy_name_field_still_used_when_present(self):
        old = [_threat("WebApp", "Tampering", "desc A", name="Legacy Name A")]
        new = [_threat("WebApp", "Tampering", "desc B", name="Legacy Name A")]
        # Same "name" despite different description → same key → no diff.
        result = compare_threat_reports(_report(old), _report(new))
        assert result["added"] == []
        assert result["resolved"] == []


class TestDiffThreatReportsCli:
    def _write(self, tmp_path: Path, filename: str, data: dict) -> str:
        p = tmp_path / filename
        p.write_text(json.dumps(data), encoding="utf-8")
        return str(p)

    def test_no_diff_returns_zero(self, tmp_path, capsys):
        threats = [_threat("WebApp", "Tampering", "SQL injection")]
        old_path = self._write(tmp_path, "old.json", _report(threats))
        new_path = self._write(tmp_path, "new.json", _report(threats))
        assert diff_threat_reports(old_path, new_path) == 0
        assert "No threat differences" in capsys.readouterr().out

    def test_diff_returns_one_and_prints_severity_level_not_dict_repr(self, tmp_path, capsys):
        old = [_threat("WebApp", "Tampering", "SQL injection", severity="LOW")]
        new = [_threat("WebApp", "Tampering", "SQL injection", severity="CRITICAL")]
        old_path = self._write(tmp_path, "old.json", _report(old))
        new_path = self._write(tmp_path, "new.json", _report(new))
        assert diff_threat_reports(old_path, new_path) == 1
        out = capsys.readouterr().out
        assert "LOW → CRITICAL" in out
        # Regression guard: must never print the raw severity dict repr.
        assert "'level':" not in out
        assert "{'score'" not in out

    def test_missing_file_returns_two(self, tmp_path):
        old_path = self._write(tmp_path, "old.json", _report([]))
        assert diff_threat_reports(old_path, str(tmp_path / "missing.json")) == 2
