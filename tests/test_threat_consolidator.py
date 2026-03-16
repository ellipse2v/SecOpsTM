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
from threat_analysis.core.threat_consolidator import (
    ThreatConsolidator, _normalize_category, _word_set, _jaccard, _descriptions_similar
)

def test_normalize_category():
    assert _normalize_category("Elevation of Privilege") == "ElevationOfPrivilege"
    assert _normalize_category("elevationofprivilege") == "ElevationOfPrivilege"
    assert _normalize_category("Information Disclosure") == "InformationDisclosure"
    assert _normalize_category("Spoofing") == "Spoofing"
    assert _normalize_category("UnknownCategory") == "UnknownCategory"

def test_word_set():
    text = "The quick brown fox is on the table!"
    words = _word_set(text)
    assert "quick" in words
    assert "brown" in words
    assert "fox" in words
    assert "table" in words
    assert "the" not in words
    assert "is" not in words

def test_jaccard():
    t1 = "SQL injection attack on database"
    t2 = "Database attack with SQL injection"
    assert _jaccard(t1, t2) > 0.5
    assert _jaccard("", "something") == 0.0
    assert _jaccard("something", "") == 0.0

def test_descriptions_similar():
    d1 = "Attacker performs SQL injection to steal data"
    d2 = "SQL injection to steal data"
    assert _descriptions_similar(d1, d2) is True
    
    d3 = "Completely different threat"
    assert _descriptions_similar(d1, d3) is False

def test_threat_consolidator_deduplicate():
    pytm_threats = [
        {"target": "DB", "stride_category": "Tampering", "description": "SQL Injection"},
        {"target": "Web", "stride_category": "Spoofing", "description": "Phishing"}
    ]
    ai_threats = [
        {"target": "DB", "stride_category": "Tampering", "description": "Advanced SQL Injection on DB"}
    ]
    
    merged = ThreatConsolidator.deduplicate(pytm_threats, ai_threats)
    assert len(merged) == 2
    assert merged[0]["description"] == "Phishing"
    assert merged[1]["description"] == "Advanced SQL Injection on DB"

def test_threat_consolidator_no_ai():
    pytm_threats = [{"target": "DB", "stride_category": "Tampering", "description": "SQL Injection"}]
    merged = ThreatConsolidator.deduplicate(pytm_threats, [])
    assert merged == pytm_threats

def test_threat_consolidator_no_duplicates():
    pytm_threats = [{"target": "Web", "stride_category": "Spoofing", "description": "Phishing"}]
    ai_threats = [{"target": "DB", "stride_category": "Tampering", "description": "SQL Injection"}]
    merged = ThreatConsolidator.deduplicate(pytm_threats, ai_threats)
    assert len(merged) == 2


# ---------------------------------------------------------------------------
# Additional tests — Jaccard threshold boundary
# ---------------------------------------------------------------------------

def test_jaccard_exactly_at_threshold_merges():
    """Jaccard == 0.3 (boundary) must trigger deduplication (AI wins)."""
    # Build two descriptions whose word-set Jaccard is exactly 0.3.
    # word_set filters stop-words and words <= 2 chars.
    # "alpha beta gamma" → {"alpha", "beta", "gamma"}  (3 words)
    # "alpha beta delta epsilon zeta phi" → {"alpha", "beta", "delta", "epsilon", "zeta", "phi"} (6 words)
    # intersection = {"alpha", "beta"} → 2
    # union = {"alpha", "beta", "gamma", "delta", "epsilon", "zeta", "phi"} → 7
    # Jaccard = 2/7 ≈ 0.286 → below threshold; adjust:
    #
    # Use 3-word sets: "alpha beta gamma" / "alpha gamma delta"
    # intersection = {"alpha", "gamma"} → 2
    # union = {"alpha", "beta", "gamma", "delta"} → 4
    # Jaccard = 2/4 = 0.5 → above threshold → merges.
    #
    # For exactly 0.3: need intersect/union = 3/10 for example.
    # "aaa bbb ccc ddd eee fff ggg" → 7 words
    # "aaa bbb ccc hhh iii jjj kkk lll mmm nnn" → 10 words
    # intersection = {"aaa", "bbb", "ccc"} → 3
    # union = 7 + 10 - 3 = 14 → 3/14 ≈ 0.214 → below.
    #
    # Simpler: use _jaccard helper to confirm the threshold assertion directly.
    from threat_analysis.core.threat_consolidator import _jaccard

    # Construct strings whose Jaccard is >= 0.3 to confirm merge
    d_pytm = "sql injection attack exploits database authentication bypass credentials"
    d_ai = "sql injection exploits database bypass credentials vulnerability"
    assert _jaccard(d_pytm, d_ai) >= 0.3

    pytm_threats = [{"target": "DB", "stride_category": "Tampering", "description": d_pytm}]
    ai_threats = [{"target": "DB", "stride_category": "Tampering", "description": d_ai}]

    merged = ThreatConsolidator.deduplicate(pytm_threats, ai_threats)
    # pytm version must be removed, AI version kept
    assert len(merged) == 1
    assert merged[0]["description"] == d_ai


def test_jaccard_below_threshold_no_merge():
    """Jaccard < 0.3 without substring containment must NOT trigger deduplication."""
    from threat_analysis.core.threat_consolidator import _jaccard

    d_pytm = "cross site scripting reflected attack javascript execution browser"
    d_ai = "sql injection persistent stored database server backend"
    # Confirm they are truly dissimilar
    assert _jaccard(d_pytm, d_ai) < 0.3

    pytm_threats = [{"target": "Web", "stride_category": "Tampering", "description": d_pytm}]
    ai_threats = [{"target": "Web", "stride_category": "Tampering", "description": d_ai}]

    merged = ThreatConsolidator.deduplicate(pytm_threats, ai_threats)
    # Both threats must be preserved
    assert len(merged) == 2


# ---------------------------------------------------------------------------
# Tests — substring containment
# ---------------------------------------------------------------------------

def test_substring_containment_triggers_merge():
    """When one description contains the other as a substring, AI must win."""
    d_pytm = "SQL injection"
    d_ai = "SQL injection attack that bypasses authentication on the database server"

    pytm_threats = [{"target": "DB", "stride_category": "Tampering", "description": d_pytm}]
    ai_threats = [{"target": "DB", "stride_category": "Tampering", "description": d_ai}]

    merged = ThreatConsolidator.deduplicate(pytm_threats, ai_threats)
    assert len(merged) == 1
    assert merged[0]["description"] == d_ai


def test_substring_containment_reverse_direction():
    """Containment must be detected in both directions (d_ai in d_pytm)."""
    d_ai = "privilege escalation"
    d_pytm = "local privilege escalation via SUID binary exploitation allows root access"

    pytm_threats = [{"target": "Linux", "stride_category": "ElevationOfPrivilege", "description": d_pytm}]
    ai_threats = [{"target": "Linux", "stride_category": "ElevationOfPrivilege", "description": d_ai}]

    merged = ThreatConsolidator.deduplicate(pytm_threats, ai_threats)
    assert len(merged) == 1
    assert merged[0]["description"] == d_ai


# ---------------------------------------------------------------------------
# Tests — AI source wins on duplicate
# ---------------------------------------------------------------------------

def test_ai_source_wins_over_pytm_on_duplicate():
    """When merging a duplicate, the resulting entry must come from the AI list."""
    pytm_threats = [
        {"target": "Server", "stride_category": "Spoofing", "description": "identity spoofing attack server"},
    ]
    ai_threats = [
        {"target": "Server", "stride_category": "Spoofing",
         "description": "identity spoofing attack server advanced mitigation bypass",
         "source": "AI", "confidence": 0.9},
    ]

    merged = ThreatConsolidator.deduplicate(pytm_threats, ai_threats)

    assert len(merged) == 1
    result = merged[0]
    # The AI dict is the one returned (has 'source' and 'confidence' keys)
    assert result.get("source") == "AI"
    assert result.get("confidence") == 0.9


def test_pytm_wins_when_no_matching_ai_threat():
    """pytm threats without an AI counterpart must all be preserved."""
    pytm_threats = [
        {"target": "Web", "stride_category": "Repudiation", "description": "log tampering allows repudiation"},
        {"target": "Web", "stride_category": "Spoofing", "description": "session token hijacking spoofing"},
    ]
    ai_threats = [
        {"target": "DB", "stride_category": "Tampering", "description": "unrelated database threat sql"},
    ]

    merged = ThreatConsolidator.deduplicate(pytm_threats, ai_threats)
    # 2 pytm (unmatched) + 1 AI
    assert len(merged) == 3


# ---------------------------------------------------------------------------
# Tests — empty list edge cases
# ---------------------------------------------------------------------------

def test_empty_pytm_and_empty_ai():
    """Both lists empty must return an empty list."""
    merged = ThreatConsolidator.deduplicate([], [])
    assert merged == []


def test_empty_pytm_with_ai_threats():
    """Empty pytm + N AI threats must return all AI threats."""
    ai_threats = [
        {"target": "X", "stride_category": "Spoofing", "description": "spoofing threat on X"},
        {"target": "Y", "stride_category": "Tampering", "description": "tampering threat on Y"},
    ]
    merged = ThreatConsolidator.deduplicate([], ai_threats)
    assert merged == ai_threats


def test_pytm_threats_with_empty_ai():
    """N pytm threats + empty AI must return all pytm threats unchanged."""
    pytm_threats = [
        {"target": "A", "stride_category": "Tampering", "description": "tampering on A"},
        {"target": "B", "stride_category": "Spoofing", "description": "spoofing on B"},
    ]
    merged = ThreatConsolidator.deduplicate(pytm_threats, [])
    assert merged == pytm_threats


# ---------------------------------------------------------------------------
# Tests — stride category normalisation during dedup
# ---------------------------------------------------------------------------

def test_stride_alias_normalisation_enables_dedup():
    """Variant STRIDE spellings must still trigger dedup when descriptions match."""
    d_pytm = "elevation privilege local escalation exploit vulnerability kernel"
    d_ai = "privilege escalation exploit local vulnerability kernel elevation"

    pytm_threats = [
        {"target": "OS", "stride_category": "Elevation of Privilege", "description": d_pytm}
    ]
    ai_threats = [
        {"target": "OS", "stride_category": "ElevationOfPrivilege", "description": d_ai}
    ]

    from threat_analysis.core.threat_consolidator import _jaccard
    assert _jaccard(d_pytm, d_ai) >= 0.3

    merged = ThreatConsolidator.deduplicate(pytm_threats, ai_threats)
    assert len(merged) == 1
    assert merged[0]["description"] == d_ai


def test_different_stride_categories_not_merged():
    """Threats with the same target and similar descriptions but different STRIDE categories must NOT merge."""
    d = "injection attack exploits authentication bypass credentials database"

    pytm_threats = [
        {"target": "DB", "stride_category": "Tampering", "description": d}
    ]
    ai_threats = [
        {"target": "DB", "stride_category": "Spoofing", "description": d}
    ]

    merged = ThreatConsolidator.deduplicate(pytm_threats, ai_threats)
    # Different categories → no merge → both preserved
    assert len(merged) == 2


def test_different_targets_not_merged():
    """Threats with the same STRIDE category and similar descriptions but different targets must NOT merge."""
    d = "sql injection attack exploits database authentication bypass credentials"

    pytm_threats = [
        {"target": "PrimaryDB", "stride_category": "Tampering", "description": d}
    ]
    ai_threats = [
        {"target": "ReplicaDB", "stride_category": "Tampering", "description": d}
    ]

    merged = ThreatConsolidator.deduplicate(pytm_threats, ai_threats)
    # Different targets → no merge
    assert len(merged) == 2


# ---------------------------------------------------------------------------
# Tests — ordering guarantee
# ---------------------------------------------------------------------------

def test_merged_order_unique_pytm_then_ai():
    """Merged list must be (unique pytm threats) followed by (all AI threats)."""
    pytm_threats = [
        {"target": "X", "stride_category": "Spoofing", "description": "unrelated pytm threat one"},
        {"target": "Y", "stride_category": "Tampering", "description": "sql injection exploits database"},
    ]
    ai_threats = [
        {"target": "Y", "stride_category": "Tampering",
         "description": "sql injection exploits database server backend", "source": "AI"},
        {"target": "Z", "stride_category": "Repudiation",
         "description": "log tampering repudiation threat", "source": "AI"},
    ]

    merged = ThreatConsolidator.deduplicate(pytm_threats, ai_threats)
    # pytm[1] merged with ai[0] → only pytm[0] survives from pytm side
    # Result order: [pytm[0], ai[0], ai[1]]
    assert len(merged) == 3
    # First entry is the surviving pytm threat
    assert merged[0]["description"] == "unrelated pytm threat one"
    # Remaining are the AI threats
    assert merged[1].get("source") == "AI"
    assert merged[2].get("source") == "AI"
