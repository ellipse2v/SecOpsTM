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
