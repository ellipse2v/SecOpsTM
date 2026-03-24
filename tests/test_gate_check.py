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

"""Tests for the CI/CD gate check (--gate / --baseline / --fail-on)."""

import json
from pathlib import Path

import pytest
import yaml

from threat_analysis.__main__ import run_gate_check


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _report(threats: list) -> dict:
    return {"schema_version": "1.0", "threats": threats}


def _threat(
    tid="T-0001",
    name="SQL injection",
    severity="HIGH",
    stride="Information Disclosure",
    target="WebApp",
    threat_key="TK-AAAAAAAA",
    accepted_risk=None,
):
    t = {
        "id": tid,
        "name": name,
        "severity": severity,
        "stride_category": stride,
        "target": target,
        "threat_key": threat_key,
        "description": name,
    }
    if accepted_risk is not None:
        t["accepted_risk"] = accepted_risk
    return t


def _write_json(tmp_path: Path, name: str, data: dict) -> Path:
    p = tmp_path / name
    p.write_text(json.dumps(data), encoding="utf-8")
    return p


def _write_yaml(tmp_path: Path, name: str, entries: list) -> Path:
    p = tmp_path / name
    p.write_text(yaml.safe_dump(entries), encoding="utf-8")
    return p


# ---------------------------------------------------------------------------
# I/O errors
# ---------------------------------------------------------------------------

class TestGateIOErrors:
    def test_missing_report_returns_2(self, tmp_path):
        assert run_gate_check(str(tmp_path / "missing.json")) == 2

    def test_invalid_json_returns_2(self, tmp_path):
        p = tmp_path / "bad.json"
        p.write_text("not json", encoding="utf-8")
        assert run_gate_check(str(p)) == 2

    def test_missing_baseline_returns_2(self, tmp_path):
        rp = _write_json(tmp_path, "report.json", _report([]))
        assert run_gate_check(str(rp), baseline_path=str(tmp_path / "missing.json")) == 2

    def test_non_list_threats_returns_2(self, tmp_path):
        rp = _write_json(tmp_path, "report.json", {"threats": "bad"})
        assert run_gate_check(str(rp)) == 2


# ---------------------------------------------------------------------------
# Basic severity filtering
# ---------------------------------------------------------------------------

class TestGateSeverityFilter:
    def test_no_threats_returns_0(self, tmp_path):
        rp = _write_json(tmp_path, "r.json", _report([]))
        assert run_gate_check(str(rp)) == 0

    def test_critical_threat_fails_on_critical(self, tmp_path):
        rp = _write_json(tmp_path, "r.json", _report([_threat(severity="CRITICAL")]))
        assert run_gate_check(str(rp), fail_on="CRITICAL") == 1

    def test_high_threat_passes_fail_on_critical(self, tmp_path):
        rp = _write_json(tmp_path, "r.json", _report([_threat(severity="HIGH")]))
        assert run_gate_check(str(rp), fail_on="CRITICAL") == 0

    def test_high_threat_fails_on_high(self, tmp_path):
        rp = _write_json(tmp_path, "r.json", _report([_threat(severity="HIGH")]))
        assert run_gate_check(str(rp), fail_on="HIGH") == 1

    def test_medium_threat_fails_on_medium(self, tmp_path):
        rp = _write_json(tmp_path, "r.json", _report([_threat(severity="MEDIUM")]))
        assert run_gate_check(str(rp), fail_on="MEDIUM") == 1

    def test_low_threat_passes_fail_on_medium(self, tmp_path):
        rp = _write_json(tmp_path, "r.json", _report([_threat(severity="LOW")]))
        assert run_gate_check(str(rp), fail_on="MEDIUM") == 0

    def test_low_threat_fails_on_low(self, tmp_path):
        rp = _write_json(tmp_path, "r.json", _report([_threat(severity="LOW")]))
        assert run_gate_check(str(rp), fail_on="LOW") == 1

    def test_unknown_severity_skipped(self, tmp_path):
        rp = _write_json(tmp_path, "r.json", _report([_threat(severity="UNKNOWN")]))
        assert run_gate_check(str(rp), fail_on="CRITICAL") == 0


# ---------------------------------------------------------------------------
# Accepted risk embedded in the report JSON
# ---------------------------------------------------------------------------

class TestGateAcceptedRiskInReport:
    def test_accepted_threat_excluded(self, tmp_path):
        t = _threat(severity="CRITICAL", accepted_risk={"decision": "accepted"})
        rp = _write_json(tmp_path, "r.json", _report([t]))
        assert run_gate_check(str(rp)) == 0

    def test_false_positive_excluded(self, tmp_path):
        t = _threat(severity="CRITICAL", accepted_risk={"decision": "false_positive"})
        rp = _write_json(tmp_path, "r.json", _report([t]))
        assert run_gate_check(str(rp)) == 0

    def test_mitigated_excluded(self, tmp_path):
        t = _threat(severity="CRITICAL", accepted_risk={"decision": "mitigated"})
        rp = _write_json(tmp_path, "r.json", _report([t]))
        assert run_gate_check(str(rp)) == 0

    def test_null_accepted_risk_not_excluded(self, tmp_path):
        t = _threat(severity="CRITICAL", accepted_risk=None)
        rp = _write_json(tmp_path, "r.json", _report([t]))
        assert run_gate_check(str(rp)) == 1

    def test_mixed_accepted_and_open(self, tmp_path):
        threats = [
            _threat(tid="T-0001", severity="CRITICAL", threat_key="TK-00000001",
                    accepted_risk={"decision": "accepted"}),
            _threat(tid="T-0002", severity="HIGH", threat_key="TK-00000002"),
        ]
        rp = _write_json(tmp_path, "r.json", _report(threats))
        assert run_gate_check(str(rp), fail_on="HIGH") == 1


# ---------------------------------------------------------------------------
# Accepted risk via accepted_risks.yaml file
# ---------------------------------------------------------------------------

class TestGateAcceptedRisksFile:
    def test_key_match_excludes_threat(self, tmp_path):
        t = _threat(severity="CRITICAL", threat_key="TK-DEADBEEF")
        rp = _write_json(tmp_path, "r.json", _report([t]))
        ar = _write_yaml(tmp_path, "ar.yaml", [
            {"threat_key": "TK-DEADBEEF", "decision": "accepted"},
        ])
        assert run_gate_check(str(rp), accepted_risks_path=str(ar)) == 0

    def test_pattern_match_excludes_threat(self, tmp_path):
        t = _threat(
            severity="CRITICAL",
            stride="Information Disclosure",
            target="WebApp",
            name="SQL injection via unparameterised query",
        )
        t["description"] = t["name"]
        rp = _write_json(tmp_path, "r.json", _report([t]))
        ar = _write_yaml(tmp_path, "ar.yaml", [
            {
                "stride_category": "Information Disclosure",
                "target": "WebApp",
                "description_contains": "SQL injection",
                "decision": "false_positive",
            },
        ])
        assert run_gate_check(str(rp), accepted_risks_path=str(ar)) == 0

    def test_unmatched_threat_still_fails(self, tmp_path):
        t = _threat(severity="CRITICAL", threat_key="TK-AABBCCDD")
        rp = _write_json(tmp_path, "r.json", _report([t]))
        ar = _write_yaml(tmp_path, "ar.yaml", [
            {"threat_key": "TK-DEADBEEF", "decision": "accepted"},
        ])
        assert run_gate_check(str(rp), accepted_risks_path=str(ar)) == 1

    def test_auto_discover_sibling_accepted_risks(self, tmp_path):
        t = _threat(severity="CRITICAL", threat_key="TK-AUTODISCOV")
        rp = _write_json(tmp_path, "r.json", _report([t]))
        # Write accepted_risks.yaml next to the report (same directory)
        (tmp_path / "accepted_risks.yaml").write_text(
            yaml.safe_dump([{"threat_key": "TK-AUTODISCOV", "decision": "accepted"}]),
            encoding="utf-8",
        )
        assert run_gate_check(str(rp)) == 0

    def test_explicit_path_overrides_auto_discover(self, tmp_path):
        """Explicit --accepted-risks path takes precedence over sibling file."""
        sub = tmp_path / "sub"
        sub.mkdir()
        t = _threat(severity="CRITICAL", threat_key="TK-EXPLICIT")
        rp = _write_json(sub, "r.json", _report([t]))
        # Sibling file accepts the threat
        (sub / "accepted_risks.yaml").write_text(
            yaml.safe_dump([{"threat_key": "TK-EXPLICIT", "decision": "accepted"}]),
            encoding="utf-8",
        )
        # Explicit file does NOT accept it (different key)
        explicit_ar = _write_yaml(tmp_path, "other_ar.yaml", [
            {"threat_key": "TK-DEADBEEF", "decision": "accepted"},
        ])
        # Explicit file passed → sibling ignored → threat NOT excluded → fail
        assert run_gate_check(str(rp), accepted_risks_path=str(explicit_ar)) == 1


# ---------------------------------------------------------------------------
# Baseline comparison
# ---------------------------------------------------------------------------

class TestGateBaseline:
    def test_threat_in_baseline_not_flagged(self, tmp_path):
        t = _threat(severity="CRITICAL", threat_key="TK-11111111")
        rp = _write_json(tmp_path, "r.json", _report([t]))
        bp = _write_json(tmp_path, "b.json", _report([t]))
        assert run_gate_check(str(rp), baseline_path=str(bp)) == 0

    def test_new_threat_flagged(self, tmp_path):
        old_t = _threat(severity="CRITICAL", threat_key="TK-11111111", tid="T-0001")
        new_t = _threat(severity="CRITICAL", threat_key="TK-22222222", tid="T-0002")
        rp = _write_json(tmp_path, "r.json", _report([old_t, new_t]))
        bp = _write_json(tmp_path, "b.json", _report([old_t]))
        assert run_gate_check(str(rp), baseline_path=str(bp)) == 1

    def test_all_in_baseline_passes(self, tmp_path):
        threats = [
            _threat(severity="CRITICAL", threat_key="TK-A", tid="T-0001"),
            _threat(severity="HIGH",     threat_key="TK-B", tid="T-0002"),
        ]
        rp = _write_json(tmp_path, "r.json", _report(threats))
        bp = _write_json(tmp_path, "b.json", _report(threats))
        assert run_gate_check(str(rp), baseline_path=str(bp), fail_on="HIGH") == 0

    def test_empty_baseline_all_new(self, tmp_path):
        t = _threat(severity="CRITICAL", threat_key="TK-NEW")
        rp = _write_json(tmp_path, "r.json", _report([t]))
        bp = _write_json(tmp_path, "b.json", _report([]))
        assert run_gate_check(str(rp), baseline_path=str(bp)) == 1

    def test_baseline_match_by_id_when_no_threat_key(self, tmp_path):
        t = {"id": "T-0001", "severity": "CRITICAL", "stride_category": "Spoofing",
             "target": "X", "name": "Test", "description": "Test"}
        rp = _write_json(tmp_path, "r.json", _report([t]))
        bp = _write_json(tmp_path, "b.json", _report([t]))
        assert run_gate_check(str(rp), baseline_path=str(bp)) == 0

    def test_baseline_new_threat_below_fail_on_passes(self, tmp_path):
        """New threat exists but is below the fail_on threshold."""
        old_t = _threat(severity="CRITICAL", threat_key="TK-OLD", tid="T-0001")
        new_t = _threat(severity="LOW",      threat_key="TK-NEW", tid="T-0002")
        rp = _write_json(tmp_path, "r.json", _report([old_t, new_t]))
        bp = _write_json(tmp_path, "b.json", _report([old_t]))
        assert run_gate_check(str(rp), baseline_path=str(bp), fail_on="HIGH") == 0

    def test_accepted_new_threat_not_flagged(self, tmp_path):
        """A new (not in baseline) threat that is accepted should NOT trigger gate failure."""
        new_t = _threat(
            severity="CRITICAL",
            threat_key="TK-NEW",
            accepted_risk={"decision": "accepted"},
        )
        rp = _write_json(tmp_path, "r.json", _report([new_t]))
        bp = _write_json(tmp_path, "b.json", _report([]))
        assert run_gate_check(str(rp), baseline_path=str(bp)) == 0
