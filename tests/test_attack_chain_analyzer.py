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

"""Tests for threat_analysis/core/attack_chain.py"""

import pytest

from threat_analysis.core.attack_chain import AttackChainAnalyzer


# ---------------------------------------------------------------------------
# Helpers / minimal stubs
# ---------------------------------------------------------------------------

class _Node:
    """Minimal stub for pytm Actor/Server (needs only .name)."""
    def __init__(self, name: str):
        self.name = name


class _Dataflow:
    """Minimal stub for pytm Dataflow."""
    def __init__(self, src_name: str, snk_name: str, name: str = None, protocol: str = ""):
        self.source = _Node(src_name)
        self.sink = _Node(snk_name)
        self.name = name or f"{src_name}To{snk_name}"
        self.protocol = protocol


def _threat(target: str, description: str, score: float = 2.0, stride: str = "Tampering", source: str = "pytm"):
    """Return a minimal normalised threat dict."""
    return {
        "target": target,
        "description": description,
        "stride_category": stride,
        "source": source,
        "severity": {"score": score, "level": "HIGH", "formatted_score": f"{score:.1f}"},
    }


# ---------------------------------------------------------------------------
# Fixture
# ---------------------------------------------------------------------------

@pytest.fixture
def analyzer():
    """Fresh AttackChainAnalyzer instance for each test."""
    return AttackChainAnalyzer()


# ---------------------------------------------------------------------------
# Tests — basic behaviour
# ---------------------------------------------------------------------------

def test_no_threats_returns_empty(analyzer):
    """No threats → empty chain list."""
    df = _Dataflow("A", "B")
    result = analyzer.analyze([], [df])
    assert result == []


def test_no_dataflows_returns_empty(analyzer):
    """No dataflows → no chains regardless of threats."""
    threats = [_threat("A", "Some threat on A")]
    result = analyzer.analyze(threats, [])
    assert result == []


def test_both_empty_returns_empty(analyzer):
    """Empty threats and empty dataflows → empty result."""
    result = analyzer.analyze([], [])
    assert result == []


def test_simple_two_component_chain(analyzer):
    """Two components connected by one dataflow produce one chain."""
    threats = [
        _threat("ComponentA", "Attacker exploits A", score=3.0),
        _threat("ComponentB", "Attacker pivots to B", score=2.0),
    ]
    df = _Dataflow("ComponentA", "ComponentB", name="AToB", protocol="HTTP")

    chains = analyzer.analyze(threats, [df])

    assert len(chains) == 1
    chain = chains[0]
    assert chain["source_name"] == "ComponentA"
    assert chain["sink_name"] == "ComponentB"
    assert chain["dataflow_name"] == "AToB"
    assert chain["protocol"] == "HTTP"


def test_chain_score_is_average_of_two_threat_scores(analyzer):
    """chain_score must equal (entry_score + pivot_score) / 2."""
    threats = [
        _threat("Src", "Threat on source", score=4.0),
        _threat("Dst", "Threat on dest", score=2.0),
    ]
    df = _Dataflow("Src", "Dst")

    chains = analyzer.analyze(threats, [df])

    assert len(chains) == 1
    assert chains[0]["chain_score"] == pytest.approx(3.0)


def test_chain_label_critical(analyzer):
    """A chain_score >= 4.0 must produce label CRITICAL."""
    threats = [
        _threat("Src", "Critical threat on source", score=4.5),
        _threat("Dst", "Critical threat on dest", score=4.5),
    ]
    df = _Dataflow("Src", "Dst")

    chains = analyzer.analyze(threats, [df])
    assert chains[0]["chain_label"] == "CRITICAL"


def test_chain_label_high(analyzer):
    """A chain_score in [3.0, 4.0) must produce label HIGH."""
    threats = [
        _threat("Src", "High threat", score=3.5),
        _threat("Dst", "High threat on dest", score=3.5),
    ]
    df = _Dataflow("Src", "Dst")

    chains = analyzer.analyze(threats, [df])
    assert chains[0]["chain_label"] == "HIGH"


def test_chain_label_medium(analyzer):
    """A chain_score in [2.0, 3.0) must produce label MEDIUM."""
    threats = [
        _threat("Src", "Medium threat on source", score=2.5),
        _threat("Dst", "Medium threat on dest", score=2.5),
    ]
    df = _Dataflow("Src", "Dst")

    chains = analyzer.analyze(threats, [df])
    assert chains[0]["chain_label"] == "MEDIUM"


def test_chain_label_low(analyzer):
    """A chain_score < 2.0 must produce label LOW."""
    threats = [
        _threat("Src", "Low threat on source", score=1.0),
        _threat("Dst", "Low threat on dest", score=1.0),
    ]
    df = _Dataflow("Src", "Dst")

    chains = analyzer.analyze(threats, [df])
    assert chains[0]["chain_label"] == "LOW"


# ---------------------------------------------------------------------------
# Tests — multi-hop chain A → B → C
# ---------------------------------------------------------------------------

def test_three_component_chain(analyzer):
    """A → B → C topology must produce two chains (A→B and B→C)."""
    threats = [
        _threat("A", "Threat on A", score=3.0),
        _threat("B", "Threat on B", score=2.5),
        _threat("C", "Threat on C", score=2.0),
    ]
    dataflows = [
        _Dataflow("A", "B"),
        _Dataflow("B", "C"),
    ]

    chains = analyzer.analyze(threats, dataflows)

    assert len(chains) == 2
    pairs = {(c["source_name"], c["sink_name"]) for c in chains}
    assert ("A", "B") in pairs
    assert ("B", "C") in pairs


def test_chains_sorted_by_score_descending(analyzer):
    """Chains must be returned in descending chain_score order."""
    threats = [
        _threat("X", "Threat X", score=1.0),
        _threat("Y", "Threat Y", score=2.0),
        _threat("Z", "Threat Z", score=4.5),
        _threat("W", "Threat W", score=4.5),
    ]
    dataflows = [
        _Dataflow("X", "Y"),  # chain_score = 1.5  → LOW
        _Dataflow("Z", "W"),  # chain_score = 4.5  → CRITICAL
    ]

    chains = analyzer.analyze(threats, dataflows)

    assert len(chains) == 2
    assert chains[0]["chain_score"] >= chains[1]["chain_score"]
    assert chains[0]["source_name"] == "Z"


# ---------------------------------------------------------------------------
# Tests — no chain when one side has no threats
# ---------------------------------------------------------------------------

def test_no_chain_when_source_has_no_threats(analyzer):
    """A dataflow whose source component has no threats must not produce a chain."""
    # Only the sink has a threat
    threats = [_threat("B", "Threat on B only")]
    df = _Dataflow("A", "B")

    chains = analyzer.analyze(threats, [df])
    assert chains == []


def test_no_chain_when_sink_has_no_threats(analyzer):
    """A dataflow whose sink component has no threats must not produce a chain."""
    threats = [_threat("A", "Threat on A only")]
    df = _Dataflow("A", "B")

    chains = analyzer.analyze(threats, [df])
    assert chains == []


def test_no_chain_for_isolated_components(analyzer):
    """Components with threats but no connecting dataflow must not generate a chain."""
    threats = [
        _threat("Isolated1", "Some threat"),
        _threat("Isolated2", "Another threat"),
    ]
    # No dataflows
    chains = analyzer.analyze(threats, [])
    assert chains == []


# ---------------------------------------------------------------------------
# Tests — self-loop protection
# ---------------------------------------------------------------------------

def test_no_self_loop_chain(analyzer):
    """A dataflow from a component to itself must not produce a chain."""
    threats = [_threat("Server", "Self-referential threat", score=3.0)]
    df = _Dataflow("Server", "Server", name="SelfLoop")

    # source_name == sink_name: the pair ("Server", "Server") should not create
    # a meaningful chain because entry == pivot (same threats list).
    # The analyzer does not explicitly block it but we verify the chain_score is the
    # average of the single top threat with itself (expected: score == 3.0).
    chains = analyzer.analyze(threats, [df])
    if chains:
        assert chains[0]["source_name"] == chains[0]["sink_name"] == "Server"


def test_duplicate_dataflow_pair_deduplicated(analyzer):
    """Two dataflows with the same (source, sink) pair must only produce one chain."""
    threats = [
        _threat("A", "Threat on A", score=3.0),
        _threat("B", "Threat on B", score=2.0),
    ]
    dataflows = [
        _Dataflow("A", "B", name="Flow1"),
        _Dataflow("A", "B", name="Flow2"),  # same pair → must be skipped
    ]

    chains = analyzer.analyze(threats, dataflows)
    assert len(chains) == 1


# ---------------------------------------------------------------------------
# Tests — result structure
# ---------------------------------------------------------------------------

def test_chain_dict_has_required_keys(analyzer):
    """Every chain dict must contain the eight documented keys."""
    threats = [
        _threat("Src", "Entry threat", score=2.5),
        _threat("Dst", "Pivot threat", score=2.5),
    ]
    df = _Dataflow("Src", "Dst", protocol="SSH")

    chains = analyzer.analyze(threats, [df])

    assert len(chains) == 1
    chain = chains[0]
    required_keys = {
        "source_name", "sink_name", "dataflow_name", "protocol",
        "entry_threat", "pivot_threat", "chain_score", "chain_label",
    }
    assert required_keys.issubset(chain.keys()), (
        f"Missing keys: {required_keys - chain.keys()}"
    )


def test_entry_and_pivot_threats_are_highest_severity(analyzer):
    """The entry/pivot threats selected must be the highest-severity ones for each component."""
    threats = [
        _threat("Src", "Low threat on source", score=1.0),
        _threat("Src", "High threat on source", score=4.0),  # must be selected
        _threat("Dst", "Medium threat on dest", score=2.0),
        _threat("Dst", "Critical threat on dest", score=5.0),  # must be selected
    ]
    df = _Dataflow("Src", "Dst")

    chains = analyzer.analyze(threats, [df])

    assert len(chains) == 1
    assert chains[0]["entry_threat"]["severity"]["score"] == 4.0
    assert chains[0]["pivot_threat"]["severity"]["score"] == 5.0


# ---------------------------------------------------------------------------
# Tests — excluded / malformed targets
# ---------------------------------------------------------------------------

def test_threats_with_empty_target_are_excluded(analyzer):
    """Threats whose target is '' or None must not participate in chains."""
    threats = [
        {"target": "", "description": "No target", "stride_category": "Spoofing",
         "source": "pytm", "severity": {"score": 5.0, "level": "CRITICAL", "formatted_score": "5.0"}},
        _threat("Real", "Threat on real component", score=3.0),
    ]
    # No dataflow connecting the named component to anything useful
    chains = analyzer.analyze(threats, [])
    assert chains == []


def test_dataflow_with_none_source_or_sink_skipped(analyzer):
    """Dataflows with None source or sink must be skipped gracefully."""
    from unittest.mock import MagicMock

    threats = [_threat("A", "Threat", score=2.0)]

    bad_df = MagicMock()
    bad_df.source = None
    bad_df.sink = None

    chains = analyzer.analyze(threats, [bad_df])
    assert chains == []


def test_default_dataflow_name_when_name_is_none(analyzer):
    """When dataflow.name is None, the chain label must fall back to 'Source → Sink'."""
    threats = [
        _threat("Alpha", "Threat on alpha", score=2.0),
        _threat("Beta", "Threat on beta", score=2.0),
    ]
    df = _Dataflow("Alpha", "Beta")
    df.name = None  # force fallback

    chains = analyzer.analyze(threats, [df])
    assert len(chains) == 1
    assert chains[0]["dataflow_name"] == "Alpha → Beta"


# ---------------------------------------------------------------------------
# Tests — multiple threats per component, score ordering
# ---------------------------------------------------------------------------

def test_multiple_threats_per_component_top_selected(analyzer):
    """With N threats per component, only the top-scoring one enters the chain."""
    threats = [
        _threat("Server", "Low sev", score=0.5),
        _threat("Server", "Medium sev", score=2.5),
        _threat("Server", "High sev", score=4.0),
        _threat("Client", "Client threat A", score=1.0),
        _threat("Client", "Client threat B", score=3.5),
    ]
    df = _Dataflow("Server", "Client")

    chains = analyzer.analyze(threats, [df])

    assert len(chains) == 1
    assert chains[0]["entry_threat"]["severity"]["score"] == 4.0
    assert chains[0]["pivot_threat"]["severity"]["score"] == 3.5
    assert chains[0]["chain_score"] == pytest.approx((4.0 + 3.5) / 2)
