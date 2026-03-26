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

"""Tests for AttackIdValidator (threat_analysis.core.attack_id_validator)."""

import json
from pathlib import Path

import pytest

from threat_analysis.core.attack_id_validator import (
    DEPRECATED,
    INVALID,
    REVOKED,
    AttackIdValidator,
    IdIssue,
    ValidationReport,
)


# ---------------------------------------------------------------------------
# Fixtures — minimal fake STIX bundle
# ---------------------------------------------------------------------------

def _make_stix_bundle(techniques: list) -> dict:
    """Build a minimal STIX 2.1 bundle for testing."""
    return {
        "type": "bundle",
        "id": "bundle--test",
        "objects": techniques,
    }


def _technique(tid: str, revoked: bool = False, deprecated: bool = False) -> dict:
    obj = {
        "type": "attack-pattern",
        "id": f"attack-pattern--{tid}",
        "external_references": [
            {"source_name": "mitre-attack", "external_id": tid,
             "url": f"https://attack.mitre.org/techniques/{tid}/"}
        ],
    }
    if revoked:
        obj["revoked"] = True
    if deprecated:
        obj["x_mitre_deprecated"] = True
    return obj


def _write_bundle(tmp_path: Path, techniques: list) -> Path:
    p = tmp_path / "enterprise-attack.json"
    p.write_text(json.dumps(_make_stix_bundle(techniques)), encoding="utf-8")
    return p


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _threat(tid="T-0001", techs=None, name="Test threat", target="WebApp"):
    return {
        "id": tid,
        "name": name,
        "target": target,
        "mitre_techniques": [{"id": t} for t in (techs or [])],
    }


def _validator(tmp_path: Path, techniques: list) -> AttackIdValidator:
    """Create a fresh validator with a custom STIX bundle."""
    AttackIdValidator._reset_cache()
    _write_bundle(tmp_path, techniques)
    return AttackIdValidator()


# ---------------------------------------------------------------------------
# _load_index
# ---------------------------------------------------------------------------

class TestLoadIndex:
    def test_loads_valid_ids(self, tmp_path):
        _write_bundle(tmp_path, [_technique("T1234"), _technique("T1234.001")])
        AttackIdValidator._reset_cache()
        valid, revoked, deprecated = AttackIdValidator._load_index(tmp_path / "enterprise-attack.json")
        assert "T1234" in valid
        assert "T1234.001" in valid

    def test_revoked_ids_indexed(self, tmp_path):
        _write_bundle(tmp_path, [_technique("T9999", revoked=True)])
        AttackIdValidator._reset_cache()
        valid, revoked, deprecated = AttackIdValidator._load_index(tmp_path / "enterprise-attack.json")
        assert "T9999" in valid
        assert "T9999" in revoked

    def test_deprecated_ids_indexed(self, tmp_path):
        _write_bundle(tmp_path, [_technique("T8888", deprecated=True)])
        AttackIdValidator._reset_cache()
        valid, revoked, deprecated = AttackIdValidator._load_index(tmp_path / "enterprise-attack.json")
        assert "T8888" in deprecated

    def test_missing_file_returns_empty_sets(self, tmp_path):
        AttackIdValidator._reset_cache()
        valid, revoked, deprecated = AttackIdValidator._load_index(tmp_path / "missing.json")
        assert len(valid) == 0
        assert len(revoked) == 0
        assert len(deprecated) == 0

    def test_invalid_json_returns_empty_sets(self, tmp_path):
        p = tmp_path / "enterprise-attack.json"
        p.write_text("not json", encoding="utf-8")
        AttackIdValidator._reset_cache()
        valid, _, _ = AttackIdValidator._load_index(p)
        assert len(valid) == 0

    def test_cache_used_on_second_call(self, tmp_path):
        _write_bundle(tmp_path, [_technique("T1111")])
        AttackIdValidator._reset_cache()
        p = tmp_path / "enterprise-attack.json"
        v1, _, _ = AttackIdValidator._load_index(p)
        # Overwrite file — second call should return cached result
        p.write_text("{}", encoding="utf-8")
        v2, _, _ = AttackIdValidator._load_index(p)
        assert v1 == v2

    def test_non_attack_pattern_objects_ignored(self, tmp_path):
        bundle = _make_stix_bundle([
            {"type": "malware", "external_references": [
                {"source_name": "mitre-attack", "external_id": "S0001"}
            ]},
            _technique("T1234"),
        ])
        p = tmp_path / "enterprise-attack.json"
        p.write_text(json.dumps(bundle), encoding="utf-8")
        AttackIdValidator._reset_cache()
        valid, _, _ = AttackIdValidator._load_index(p)
        assert "S0001" not in valid
        assert "T1234" in valid


# ---------------------------------------------------------------------------
# validate_all — basic cases
# ---------------------------------------------------------------------------

class TestValidateAll:
    def test_no_threats_returns_empty_report(self, tmp_path):
        v = _validator(tmp_path, [_technique("T1234")])
        r = v.validate_all([], stix_path=tmp_path / "enterprise-attack.json")
        assert r.total_techniques_checked == 0
        assert not r.has_issues

    def test_valid_id_no_issues(self, tmp_path):
        v = _validator(tmp_path, [_technique("T1234")])
        threats = [_threat(techs=["T1234"])]
        r = v.validate_all(threats, stix_path=tmp_path / "enterprise-attack.json")
        assert not r.has_issues
        assert r.total_techniques_checked == 1

    def test_invalid_id_detected(self, tmp_path):
        v = _validator(tmp_path, [_technique("T1234")])
        threats = [_threat(techs=["T9999"])]
        r = v.validate_all(threats, stix_path=tmp_path / "enterprise-attack.json")
        assert r.n_invalid == 1
        assert r.invalid[0].technique_id == "T9999"
        assert r.invalid[0].issue_type == INVALID

    def test_revoked_id_detected(self, tmp_path):
        v = _validator(tmp_path, [_technique("T1234", revoked=True)])
        threats = [_threat(techs=["T1234"])]
        r = v.validate_all(threats, stix_path=tmp_path / "enterprise-attack.json")
        assert r.n_revoked == 1
        assert r.revoked[0].issue_type == REVOKED

    def test_deprecated_id_detected(self, tmp_path):
        v = _validator(tmp_path, [_technique("T1234", deprecated=True)])
        threats = [_threat(techs=["T1234"])]
        r = v.validate_all(threats, stix_path=tmp_path / "enterprise-attack.json")
        assert r.n_deprecated == 1
        assert r.deprecated[0].issue_type == DEPRECATED

    def test_empty_corpus_returns_zero_total(self, tmp_path):
        """When index is empty (file missing), validation is silently disabled."""
        AttackIdValidator._reset_cache()
        v = AttackIdValidator()
        r = v.validate_all(
            [_threat(techs=["T1234"])],
            stix_path=tmp_path / "missing.json",
        )
        assert r.total_techniques_checked == 0
        assert not r.has_issues


# ---------------------------------------------------------------------------
# validate_all — deduplication
# ---------------------------------------------------------------------------

class TestDeduplication:
    def test_same_id_in_same_threat_counted_once(self, tmp_path):
        """Duplicate technique IDs within one threat are deduplicated."""
        v = _validator(tmp_path, [_technique("T9999")])  # T9999 is valid now
        threat = {"id": "T-0001", "name": "x", "target": "y",
                  "mitre_techniques": [{"id": "T9999"}, {"id": "T9999"}]}
        r = v.validate_all([threat], stix_path=tmp_path / "enterprise-attack.json")
        assert r.total_techniques_checked == 2   # counted but deduplicated for issues
        assert len(r.all_issues) == 0            # no issues (T9999 is valid here)

    def test_same_invalid_id_in_two_threats_creates_two_issues(self, tmp_path):
        # Corpus has T1111 (valid) but not T9999 → T9999 is invalid
        v = _validator(tmp_path, [_technique("T1111")])
        threats = [
            _threat(tid="T-0001", techs=["T9999"]),
            _threat(tid="T-0002", techs=["T9999"]),
        ]
        r = v.validate_all(threats, stix_path=tmp_path / "enterprise-attack.json")
        assert r.n_invalid == 2  # one issue per (threat_id, technique_id) pair

    def test_empty_technique_id_skipped(self, tmp_path):
        v = _validator(tmp_path, [])
        threat = {"id": "T-0001", "name": "x", "target": "y",
                  "mitre_techniques": [{"id": ""}, {"id": None}]}
        r = v.validate_all([threat], stix_path=tmp_path / "enterprise-attack.json")
        assert r.total_techniques_checked == 0

    def test_missing_mitre_techniques_key_skipped(self, tmp_path):
        v = _validator(tmp_path, [])
        threat = {"id": "T-0001", "name": "x", "target": "y"}
        r = v.validate_all([threat], stix_path=tmp_path / "enterprise-attack.json")
        assert r.total_techniques_checked == 0


# ---------------------------------------------------------------------------
# validate_all — mixed
# ---------------------------------------------------------------------------

class TestMixedResults:
    def test_all_three_issue_types_detected(self, tmp_path):
        v = _validator(tmp_path, [
            _technique("T1111"),               # valid
            _technique("T2222", revoked=True),
            _technique("T3333", deprecated=True),
        ])
        threats = [_threat(techs=["T1111", "T2222", "T3333", "T4444"])]
        r = v.validate_all(threats, stix_path=tmp_path / "enterprise-attack.json")
        assert r.n_invalid == 1    # T4444
        assert r.n_revoked == 1    # T2222
        assert r.n_deprecated == 1  # T3333
        assert len(r.all_issues) == 3

    def test_has_issues_false_when_all_valid(self, tmp_path):
        v = _validator(tmp_path, [_technique("T1111"), _technique("T2222")])
        threats = [_threat(techs=["T1111", "T2222"])]
        r = v.validate_all(threats, stix_path=tmp_path / "enterprise-attack.json")
        assert not r.has_issues


# ---------------------------------------------------------------------------
# IdIssue properties
# ---------------------------------------------------------------------------

class TestIdIssueProperties:
    def test_label_invalid(self):
        issue = IdIssue("T9999", INVALID, "T-0001", "Threat name", "WebApp")
        assert issue.label == "Invalid ID"

    def test_label_revoked(self):
        issue = IdIssue("T1234", REVOKED, "T-0001", "Threat name", "WebApp")
        assert issue.label == "Revoked"

    def test_label_deprecated(self):
        issue = IdIssue("T1234", DEPRECATED, "T-0001", "Threat name", "WebApp")
        assert issue.label == "Deprecated"

    def test_attack_url_top_level(self):
        issue = IdIssue("T1234", REVOKED, "T-0001", "x", "y")
        assert issue.attack_url == "https://attack.mitre.org/techniques/T1234/"

    def test_attack_url_subtechnique(self):
        issue = IdIssue("T1234.001", REVOKED, "T-0001", "x", "y")
        assert issue.attack_url == "https://attack.mitre.org/techniques/T1234/001/"


# ---------------------------------------------------------------------------
# ValidationReport properties
# ---------------------------------------------------------------------------

class TestValidationReport:
    def test_has_issues_false_when_empty(self):
        r = ValidationReport(total_techniques_checked=10)
        assert not r.has_issues

    def test_has_issues_true_when_invalid(self):
        issue = IdIssue("T9999", INVALID, "T-0001", "x", "y")
        r = ValidationReport(total_techniques_checked=1, invalid=[issue])
        assert r.has_issues

    def test_all_issues_combines_all_three_lists(self):
        r = ValidationReport(
            total_techniques_checked=3,
            invalid=[IdIssue("A", INVALID, "x", "n", "t")],
            revoked=[IdIssue("B", REVOKED, "x", "n", "t")],
            deprecated=[IdIssue("C", DEPRECATED, "x", "n", "t")],
        )
        assert len(r.all_issues) == 3
