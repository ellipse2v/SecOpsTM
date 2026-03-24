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

import datetime
import textwrap
import tempfile
from pathlib import Path

import pytest
import yaml

from threat_analysis.core.accepted_risks import (
    AcceptedRiskLoader,
    compute_threat_key,
    VALID_DECISIONS,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _threat(cat="Information Disclosure", target="WebApp", desc="SQL injection via unparameterised query"):
    return {"stride_category": cat, "target": target, "description": desc}


def _write_yaml(tmp_path: Path, entries: list) -> Path:
    f = tmp_path / "accepted_risks.yaml"
    f.write_text(yaml.safe_dump(entries), encoding="utf-8")
    return f


# ---------------------------------------------------------------------------
# compute_threat_key
# ---------------------------------------------------------------------------

class TestComputeThreatKey:
    def test_same_threat_same_key(self):
        t = _threat()
        assert compute_threat_key(t) == compute_threat_key(t)

    def test_different_cat_different_key(self):
        t1 = _threat(cat="Spoofing")
        t2 = _threat(cat="Tampering")
        assert compute_threat_key(t1) != compute_threat_key(t2)

    def test_different_target_different_key(self):
        assert compute_threat_key(_threat(target="A")) != compute_threat_key(_threat(target="B"))

    def test_different_desc_different_key(self):
        assert compute_threat_key(_threat(desc="x")) != compute_threat_key(_threat(desc="y"))

    def test_key_prefixed_tk(self):
        assert compute_threat_key(_threat()).startswith("TK-")

    def test_key_length(self):
        key = compute_threat_key(_threat())
        assert len(key) == len("TK-") + 8  # TK- + 8 hex chars

    def test_missing_fields_do_not_raise(self):
        key = compute_threat_key({})
        assert key.startswith("TK-")

    def test_description_truncated_at_80(self):
        t_long  = _threat(desc="A" * 200)
        t_short = _threat(desc="A" * 80)
        assert compute_threat_key(t_long) == compute_threat_key(t_short)


# ---------------------------------------------------------------------------
# AcceptedRiskLoader.from_file
# ---------------------------------------------------------------------------

class TestFromFile:
    def test_nonexistent_file_returns_empty(self):
        loader = AcceptedRiskLoader.from_file("/does/not/exist.yaml")
        assert len(loader) == 0

    def test_loads_valid_accepted_entry(self, tmp_path):
        f = _write_yaml(tmp_path, [
            {"threat_key": "TK-AAAAAAAA", "decision": "accepted", "rationale": "OK"},
        ])
        loader = AcceptedRiskLoader.from_file(str(f))
        assert len(loader) == 1

    def test_rejects_unknown_decision(self, tmp_path):
        f = _write_yaml(tmp_path, [
            {"threat_key": "TK-AAAAAAAA", "decision": "ignored_forever"},
        ])
        loader = AcceptedRiskLoader.from_file(str(f))
        assert len(loader) == 0

    def test_expired_entry_excluded(self, tmp_path):
        f = _write_yaml(tmp_path, [
            {"threat_key": "TK-AAAAAAAA", "decision": "accepted", "expires": "2000-01-01"},
        ])
        loader = AcceptedRiskLoader.from_file(str(f))
        assert len(loader) == 0

    def test_future_expiry_included(self, tmp_path):
        f = _write_yaml(tmp_path, [
            {"threat_key": "TK-AAAAAAAA", "decision": "accepted", "expires": "2099-12-31"},
        ])
        loader = AcceptedRiskLoader.from_file(str(f))
        assert len(loader) == 1

    def test_no_expiry_included(self, tmp_path):
        f = _write_yaml(tmp_path, [
            {"threat_key": "TK-AAAAAAAA", "decision": "false_positive"},
        ])
        loader = AcceptedRiskLoader.from_file(str(f))
        assert len(loader) == 1

    def test_non_list_yaml_returns_empty(self, tmp_path):
        f = tmp_path / "accepted_risks.yaml"
        f.write_text("not_a_list: true\n", encoding="utf-8")
        loader = AcceptedRiskLoader.from_file(str(f))
        assert len(loader) == 0

    def test_empty_file_returns_empty(self, tmp_path):
        f = tmp_path / "accepted_risks.yaml"
        f.write_text("", encoding="utf-8")
        loader = AcceptedRiskLoader.from_file(str(f))
        assert len(loader) == 0

    def test_mixed_valid_expired_entries(self, tmp_path):
        f = _write_yaml(tmp_path, [
            {"threat_key": "TK-AA", "decision": "accepted", "expires": "2000-01-01"},
            {"threat_key": "TK-BB", "decision": "mitigated"},
        ])
        loader = AcceptedRiskLoader.from_file(str(f))
        assert len(loader) == 1


# ---------------------------------------------------------------------------
# AcceptedRiskLoader.from_model_path
# ---------------------------------------------------------------------------

class TestFromModelPath:
    def test_none_model_path_returns_empty(self):
        loader = AcceptedRiskLoader.from_model_path(None)
        assert len(loader) == 0

    def test_discovers_sibling_file(self, tmp_path):
        model = tmp_path / "model.md"
        model.touch()
        ar = tmp_path / "accepted_risks.yaml"
        ar.write_text(yaml.safe_dump([
            {"threat_key": "TK-00000000", "decision": "accepted"},
        ]), encoding="utf-8")
        loader = AcceptedRiskLoader.from_model_path(str(model))
        assert len(loader) == 1

    def test_no_sibling_returns_empty(self, tmp_path):
        model = tmp_path / "model.md"
        model.touch()
        loader = AcceptedRiskLoader.from_model_path(str(model))
        assert len(loader) == 0


# ---------------------------------------------------------------------------
# AcceptedRiskLoader.get_decision — key-based matching
# ---------------------------------------------------------------------------

class TestGetDecisionKeyBased:
    def test_exact_key_match(self, tmp_path):
        t = _threat()
        key = compute_threat_key(t)
        f = _write_yaml(tmp_path, [
            {"threat_key": key, "decision": "accepted", "rationale": "OK", "reviewer": "alice"},
        ])
        loader = AcceptedRiskLoader.from_file(str(f))
        result = loader.get_decision(t)
        assert result is not None
        assert result["decision"] == "accepted"
        assert result["rationale"] == "OK"
        assert result["reviewer"] == "alice"

    def test_wrong_key_no_match(self, tmp_path):
        f = _write_yaml(tmp_path, [
            {"threat_key": "TK-DEADBEEF", "decision": "accepted"},
        ])
        loader = AcceptedRiskLoader.from_file(str(f))
        assert loader.get_decision(_threat()) is None

    def test_all_three_decisions_returned(self, tmp_path):
        for decision in VALID_DECISIONS:
            t = _threat(cat=decision)
            key = compute_threat_key(t)
            f = _write_yaml(tmp_path, [{"threat_key": key, "decision": decision}])
            loader = AcceptedRiskLoader.from_file(str(f))
            result = loader.get_decision(t)
            assert result["decision"] == decision

    def test_no_entries_returns_none(self):
        loader = AcceptedRiskLoader.empty()
        assert loader.get_decision(_threat()) is None


# ---------------------------------------------------------------------------
# AcceptedRiskLoader.get_decision — pattern-based matching
# ---------------------------------------------------------------------------

class TestGetDecisionPatternBased:
    def test_full_pattern_match(self, tmp_path):
        f = _write_yaml(tmp_path, [{
            "stride_category": "Information Disclosure",
            "target": "WebApp",
            "description_contains": "SQL injection",
            "decision": "false_positive",
            "rationale": "Inputs are parameterised",
        }])
        loader = AcceptedRiskLoader.from_file(str(f))
        result = loader.get_decision(_threat())
        assert result is not None
        assert result["decision"] == "false_positive"

    def test_description_case_insensitive(self, tmp_path):
        f = _write_yaml(tmp_path, [{
            "description_contains": "SQL INJECTION",
            "decision": "accepted",
        }])
        loader = AcceptedRiskLoader.from_file(str(f))
        assert loader.get_decision(_threat()) is not None

    def test_partial_description_match(self, tmp_path):
        f = _write_yaml(tmp_path, [{
            "description_contains": "unparameterised",
            "decision": "accepted",
        }])
        loader = AcceptedRiskLoader.from_file(str(f))
        assert loader.get_decision(_threat()) is not None

    def test_description_mismatch_no_match(self, tmp_path):
        f = _write_yaml(tmp_path, [{
            "description_contains": "buffer overflow",
            "decision": "accepted",
        }])
        loader = AcceptedRiskLoader.from_file(str(f))
        assert loader.get_decision(_threat()) is None

    def test_category_wildcard_matches_any(self, tmp_path):
        # No stride_category in entry → matches any category
        f = _write_yaml(tmp_path, [{
            "target": "WebApp",
            "description_contains": "SQL injection",
            "decision": "accepted",
        }])
        loader = AcceptedRiskLoader.from_file(str(f))
        result = loader.get_decision(_threat(cat="Spoofing"))
        assert result is not None

    def test_target_mismatch_no_match(self, tmp_path):
        f = _write_yaml(tmp_path, [{
            "stride_category": "Information Disclosure",
            "target": "Database",
            "decision": "accepted",
        }])
        loader = AcceptedRiskLoader.from_file(str(f))
        assert loader.get_decision(_threat(target="WebApp")) is None

    def test_empty_pattern_does_not_match_anything(self, tmp_path):
        # An entry with no stride_category, target, or description_contains
        # provides no signal — must not match everything
        f = _write_yaml(tmp_path, [{"decision": "accepted"}])
        loader = AcceptedRiskLoader.from_file(str(f))
        assert loader.get_decision(_threat()) is None

    def test_key_takes_priority_over_pattern(self, tmp_path):
        t = _threat()
        key = compute_threat_key(t)
        f = _write_yaml(tmp_path, [
            {"threat_key": key, "decision": "mitigated", "rationale": "key-match"},
            {"description_contains": "SQL injection", "decision": "accepted", "rationale": "pattern-match"},
        ])
        loader = AcceptedRiskLoader.from_file(str(f))
        result = loader.get_decision(t)
        assert result["decision"] == "mitigated"


# ---------------------------------------------------------------------------
# Expiry with date objects (YAML parses ISO dates as date objects)
# ---------------------------------------------------------------------------

class TestExpiryHandling:
    def test_date_object_expiry_past_excluded(self, tmp_path):
        entries = [{"threat_key": "TK-AAAAAAAA", "decision": "accepted",
                    "expires": datetime.date(2000, 1, 1)}]
        f = tmp_path / "accepted_risks.yaml"
        f.write_text(yaml.safe_dump(entries), encoding="utf-8")
        loader = AcceptedRiskLoader.from_file(str(f))
        assert len(loader) == 0

    def test_date_object_expiry_future_included(self, tmp_path):
        entries = [{"threat_key": "TK-AAAAAAAA", "decision": "accepted",
                    "expires": datetime.date(2099, 1, 1)}]
        f = tmp_path / "accepted_risks.yaml"
        f.write_text(yaml.safe_dump(entries), encoding="utf-8")
        loader = AcceptedRiskLoader.from_file(str(f))
        assert len(loader) == 1
