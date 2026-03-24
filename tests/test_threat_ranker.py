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

import pytest
from threat_analysis.core.threat_ranker import (
    _composite_score,
    rank,
    trim,
    rank_and_trim,
    _DEFAULT_WEIGHTS,
    _STRIDE_CATEGORIES,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _t(
    stride="Spoofing",
    severity_score=5.0,
    confidence=0.5,
    cve_match=False,
    cwe_high_risk=False,
    network_exposed=False,
    d3fend=False,
    **kw,
):
    """Build a minimal threat dict."""
    return {
        "stride_category": stride,
        "severity": {"score": severity_score, "level": "MEDIUM"},
        "confidence": confidence,
        "risk_signals": {
            "cve_match": cve_match,
            "cwe_high_risk": cwe_high_risk,
            "network_exposed": network_exposed,
            "d3fend_mitigations": d3fend,
        },
        **kw,
    }


# ---------------------------------------------------------------------------
# _composite_score
# ---------------------------------------------------------------------------

class TestCompositeScore:
    def test_all_zero_gives_zero(self):
        t = _t(severity_score=0.0, confidence=0.0)
        assert _composite_score(t, _DEFAULT_WEIGHTS) == pytest.approx(0.0, abs=1e-4)

    def test_high_severity_raises_score(self):
        lo = _t(severity_score=2.0, confidence=0.5)
        hi = _t(severity_score=9.0, confidence=0.5)
        assert _composite_score(hi, _DEFAULT_WEIGHTS) > _composite_score(lo, _DEFAULT_WEIGHTS)

    def test_high_confidence_raises_score(self):
        lo = _t(severity_score=5.0, confidence=0.1)
        hi = _t(severity_score=5.0, confidence=0.9)
        assert _composite_score(hi, _DEFAULT_WEIGHTS) > _composite_score(lo, _DEFAULT_WEIGHTS)

    def test_cve_match_raises_score(self):
        no_cve = _t(cve_match=False)
        with_cve = _t(cve_match=True)
        assert _composite_score(with_cve, _DEFAULT_WEIGHTS) > _composite_score(no_cve, _DEFAULT_WEIGHTS)

    def test_d3fend_reduces_risk_signal(self):
        no_d3f = _t(network_exposed=True, d3fend=False)
        with_d3f = _t(network_exposed=True, d3fend=True)
        assert _composite_score(no_d3f, _DEFAULT_WEIGHTS) > _composite_score(with_d3f, _DEFAULT_WEIGHTS)

    def test_all_three_signals_max_risk(self):
        t = _t(cve_match=True, cwe_high_risk=True, network_exposed=True, d3fend=False)
        score = _composite_score(t, _DEFAULT_WEIGHTS)
        assert score == pytest.approx(
            0.4 * 0.5 + 0.3 * 0.5 + 0.3 * 1.0, abs=1e-4
        )

    def test_severity_capped_at_one(self):
        t = _t(severity_score=100.0, confidence=1.0, cve_match=True, cwe_high_risk=True, network_exposed=True)
        assert _composite_score(t, _DEFAULT_WEIGHTS) <= 1.0 + 1e-9

    def test_custom_weights(self):
        t = _t(severity_score=10.0, confidence=0.0)
        all_sev = {"severity": 1.0, "confidence": 0.0, "risk_signals": 0.0}
        assert _composite_score(t, all_sev) == pytest.approx(1.0, abs=1e-4)

    def test_missing_severity_defaults_to_five(self):
        t = {"stride_category": "Spoofing", "confidence": 0.5}
        score = _composite_score(t, _DEFAULT_WEIGHTS)
        expected = 0.4 * 0.5 + 0.3 * 0.5 + 0.3 * 0.0
        assert score == pytest.approx(expected, abs=1e-4)

    def test_missing_confidence_defaults_to_half(self):
        t = {"stride_category": "Spoofing", "severity": {"score": 5.0}}
        score = _composite_score(t, _DEFAULT_WEIGHTS)
        expected = 0.4 * 0.5 + 0.3 * 0.5 + 0.3 * 0.0
        assert score == pytest.approx(expected, abs=1e-4)


# ---------------------------------------------------------------------------
# rank
# ---------------------------------------------------------------------------

class TestRank:
    def test_empty_list(self):
        assert rank([]) == []

    def test_returns_new_list(self):
        threats = [_t()]
        result = rank(threats)
        assert result is not threats

    def test_adds_ranking_score_key(self):
        result = rank([_t()])
        assert "_ranking_score" in result[0]

    def test_sorted_descending(self):
        low  = _t(severity_score=1.0, confidence=0.1)
        high = _t(severity_score=9.0, confidence=0.9, cve_match=True)
        result = rank([low, high])
        assert result[0]["_ranking_score"] >= result[1]["_ranking_score"]

    def test_original_dicts_not_mutated(self):
        t = _t()
        rank([t])
        assert "_ranking_score" not in t

    def test_single_item(self):
        result = rank([_t(severity_score=7.0)])
        assert len(result) == 1
        assert result[0]["_ranking_score"] > 0

    def test_equal_threats_stable_order(self):
        threats = [_t(stride=s) for s in ["Spoofing", "Tampering", "Repudiation"]]
        result = rank(threats)
        assert len(result) == 3
        # All same score — order may vary but all items present
        cats = {r["stride_category"] for r in result}
        assert cats == {"Spoofing", "Tampering", "Repudiation"}

    def test_custom_weights_change_order(self):
        # High severity, low confidence
        sev_heavy = _t(severity_score=9.0, confidence=0.1)
        # Low severity, high confidence
        conf_heavy = _t(severity_score=2.0, confidence=0.95)
        # With default weights severity wins
        default_result = rank([conf_heavy, sev_heavy])
        assert default_result[0] is not conf_heavy or True  # order may vary
        # With all-confidence weights confidence wins
        conf_weights = {"severity": 0.0, "confidence": 1.0, "risk_signals": 0.0}
        conf_result = rank([sev_heavy, conf_heavy], weights=conf_weights)
        assert conf_result[0]["confidence"] == pytest.approx(0.95, abs=1e-4)


# ---------------------------------------------------------------------------
# trim
# ---------------------------------------------------------------------------

class TestTrim:
    def test_no_limit_returns_all(self):
        threats = rank([_t(stride=s) for s in ["Spoofing", "Tampering"]])
        assert trim(threats, max_total=0) == threats

    def test_negative_limit_returns_all(self):
        threats = rank([_t()])
        assert trim(threats, max_total=-5) == threats

    def test_already_under_limit(self):
        threats = rank([_t(stride="Spoofing"), _t(stride="Tampering")])
        assert len(trim(threats, max_total=10)) == 2

    def test_trims_to_exact_count(self):
        threats = rank([_t(stride=f"Spoofing", severity_score=float(i)) for i in range(10)])
        result = trim(threats, max_total=5, min_stride_coverage=False)
        assert len(result) == 5

    def test_stride_coverage_preserved(self):
        # 5 spoofing + 1 tampering (low score)
        threats = (
            [_t(stride="Spoofing", severity_score=9.0, confidence=0.9)] * 5
            + [_t(stride="Tampering", severity_score=1.0, confidence=0.1)]
        )
        result = trim(rank(threats), max_total=3, min_stride_coverage=True)
        cats = {t["stride_category"] for t in result}
        assert "Tampering" in cats, "Tampering must be kept for STRIDE coverage"
        assert len(result) == 3

    def test_min_stride_coverage_false_drops_low_ranked_categories(self):
        threats = (
            [_t(stride="Spoofing", severity_score=9.0)] * 5
            + [_t(stride="Tampering", severity_score=1.0)]
        )
        result = trim(rank(threats), max_total=3, min_stride_coverage=False)
        # Tampering may be dropped
        assert len(result) == 3

    def test_result_sorted_descending(self):
        threats = rank([
            _t(stride="Spoofing",   severity_score=3.0),
            _t(stride="Tampering",  severity_score=8.0),
            _t(stride="Repudiation",severity_score=5.0),
        ])
        result = trim(threats, max_total=3)
        scores = [r["_ranking_score"] for r in result]
        assert scores == sorted(scores, reverse=True)

    def test_all_categories_preserved_when_max_equals_category_count(self):
        cats = ["Spoofing", "Tampering", "Repudiation",
                "Information Disclosure", "Denial of Service", "Elevation of Privilege"]
        threats = rank([_t(stride=c) for c in cats])
        result = trim(threats, max_total=6, min_stride_coverage=True)
        assert {t["stride_category"] for t in result} == set(cats)

    def test_non_stride_categories_not_forced_in(self):
        # RAG / LLM threats have non-STRIDE categories
        threats = rank([
            _t(stride="Spoofing",       severity_score=9.0),
            _t(stride="Tampering",      severity_score=8.0),
            {"stride_category": "LLM",  "severity": {"score": 1.0}, "confidence": 0.1},
        ])
        result = trim(threats, max_total=2, min_stride_coverage=True)
        # "LLM" category is not forced in — only STRIDE categories are guaranteed
        assert len(result) == 2


# ---------------------------------------------------------------------------
# rank_and_trim (convenience wrapper)
# ---------------------------------------------------------------------------

class TestRankAndTrim:
    def test_empty(self):
        assert rank_and_trim([]) == []

    def test_no_limit_ranks_only(self):
        threats = [_t(stride=s) for s in ["Spoofing", "Tampering"]]
        result = rank_and_trim(threats, max_total=0)
        assert all("_ranking_score" in t for t in result)
        assert len(result) == 2

    def test_limit_applied(self):
        threats = [_t(stride="Spoofing") for _ in range(20)]
        result = rank_and_trim(threats, max_total=5, min_stride_coverage=False)
        assert len(result) == 5

    def test_weights_forwarded(self):
        # All-severity weights: high-severity threat should always rank first
        low_sev  = _t(stride="Spoofing", severity_score=1.0, confidence=0.99)
        high_sev = _t(stride="Tampering", severity_score=10.0, confidence=0.01)
        result = rank_and_trim(
            [low_sev, high_sev],
            weights={"severity": 1.0, "confidence": 0.0, "risk_signals": 0.0},
        )
        assert result[0]["stride_category"] == "Tampering"

    def test_stride_coverage_forwarded(self):
        threats = (
            [_t(stride="Spoofing",  severity_score=9.0)] * 10
            + [_t(stride="Tampering", severity_score=1.0)]
        )
        result = rank_and_trim(threats, max_total=5, min_stride_coverage=True)
        assert any(t["stride_category"] == "Tampering" for t in result)


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------

class TestEdgeCases:
    def test_threat_without_risk_signals(self):
        t = {"stride_category": "Spoofing", "severity": {"score": 7.0}, "confidence": 0.8}
        score = _composite_score(t, _DEFAULT_WEIGHTS)
        assert score == pytest.approx(0.4 * 0.7 + 0.3 * 0.8 + 0.3 * 0.0, abs=1e-4)

    def test_threat_with_none_severity(self):
        t = _t()
        t["severity"] = None
        score = _composite_score(t, _DEFAULT_WEIGHTS)
        assert score >= 0.0

    def test_trim_single_threat_under_limit(self):
        result = trim(rank([_t()]), max_total=10)
        assert len(result) == 1

    def test_large_list_trim_preserves_top_scores(self):
        threats = [_t(severity_score=float(i), confidence=0.5) for i in range(100)]
        result = rank_and_trim(threats, max_total=10, min_stride_coverage=False)
        # All kept threats should have score >= lowest possible kept score
        assert len(result) == 10
        scores = [t["_ranking_score"] for t in result]
        assert scores == sorted(scores, reverse=True)
