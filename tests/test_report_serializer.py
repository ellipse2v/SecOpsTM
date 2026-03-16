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

"""Tests for threat_analysis/core/report_serializer.py"""

import json
import re
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from threat_analysis.core.report_serializer import ReportSerializer

# ---------------------------------------------------------------------------
# JSON Schema loading (offline — no network)
# ---------------------------------------------------------------------------

_SCHEMA_PATH = (
    Path(__file__).resolve().parents[1]
    / "threat_analysis"
    / "schemas"
    / "v1"
    / "threat_model_report.schema.json"
)


def _load_schema():
    with open(_SCHEMA_PATH, encoding="utf-8") as fh:
        return json.load(fh)


# ---------------------------------------------------------------------------
# Helpers / fixtures
# ---------------------------------------------------------------------------

def _make_threat_model(name="TestModel", description="A test model"):
    """Return a minimal mock ThreatModel that satisfies ReportSerializer._serialize_model."""
    tm_inner = MagicMock()
    tm_inner.name = name
    tm_inner.description = description

    tm = MagicMock()
    tm.tm = tm_inner
    tm.actors = []
    tm.servers = []
    tm.dataflows = []
    tm.boundaries = {}
    return tm


def _make_threat(
    description="Attacker exploits SQL injection",
    stride_category="Tampering",
    target="DatabaseServer",
    source="pytm",
    severity_score=3.5,
    severity_level="HIGH",
    confidence=None,
    mitre_techniques=None,
    capecs=None,
    cve=None,
    business_value=None,
):
    """Return a normalised threat dict as produced by ReportGenerator."""
    return {
        "description": description,
        "stride_category": stride_category,
        "target": target,
        "source": source,
        "severity": {
            "score": severity_score,
            "level": severity_level,
            "formatted_score": f"{severity_score:.1f}",
        },
        "confidence": confidence,
        "mitre_techniques": mitre_techniques or [],
        "capecs": capecs or [],
        "cve": cve or [],
        "business_value": business_value,
    }


# ---------------------------------------------------------------------------
# Tests — ID format
# ---------------------------------------------------------------------------

def test_threat_ids_format_t_nnnn():
    """Threat IDs must match the pattern T-NNNN (four zero-padded digits)."""
    threat_model = _make_threat_model()
    threats = [_make_threat() for _ in range(3)]

    report = ReportSerializer.serialize(threat_model, threats)

    ids = [t["id"] for t in report["threats"]]
    pattern = re.compile(r"^T-\d{4}$")
    for tid in ids:
        assert pattern.match(tid), f"ID '{tid}' does not match T-NNNN"


def test_threat_ids_are_sequential():
    """IDs must be T-0001, T-0002, T-0003 in order."""
    threat_model = _make_threat_model()
    threats = [_make_threat(description=f"Threat {i}") for i in range(5)]

    report = ReportSerializer.serialize(threat_model, threats)

    ids = [t["id"] for t in report["threats"]]
    assert ids == ["T-0001", "T-0002", "T-0003", "T-0004", "T-0005"]


def test_threat_id_single_threat():
    """A single threat gets id T-0001."""
    threat_model = _make_threat_model()
    report = ReportSerializer.serialize(threat_model, [_make_threat()])
    assert report["threats"][0]["id"] == "T-0001"


# ---------------------------------------------------------------------------
# Tests — schema_version
# ---------------------------------------------------------------------------

def test_schema_version_is_1_0():
    """The top-level schema_version field must be '1.0'."""
    threat_model = _make_threat_model()
    report = ReportSerializer.serialize(threat_model, [])
    assert report["schema_version"] == "1.0"


# ---------------------------------------------------------------------------
# Tests — JSON Schema validation
# ---------------------------------------------------------------------------

def _validate_report(report: dict) -> None:
    """Validate *report* against the v1 JSON schema (raises jsonschema.ValidationError)."""
    try:
        import jsonschema  # type: ignore
    except ImportError:
        pytest.skip("jsonschema not installed — skipping schema validation")

    schema = _load_schema()
    # Use Draft202012Validator if available, else fallback to default validator
    try:
        validator_cls = jsonschema.Draft202012Validator
    except AttributeError:
        validator_cls = jsonschema.Draft7Validator

    validator_cls(schema).validate(report)


def test_schema_valid_empty_threats():
    """An empty threat list must still produce a schema-valid report."""
    threat_model = _make_threat_model()
    report = ReportSerializer.serialize(threat_model, [])
    _validate_report(report)


def test_schema_valid_with_threats():
    """A report with several threats must pass schema validation."""
    threat_model = _make_threat_model()
    threats = [
        _make_threat(source="pytm"),
        _make_threat(description="Lateral movement", source="AI", stride_category="ElevationOfPrivilege"),
        _make_threat(description="RAG-generated threat", source="LLM"),
    ]
    report = ReportSerializer.serialize(threat_model, threats)
    _validate_report(report)


def test_schema_valid_full_model():
    """A model with actors, servers, dataflows, and boundaries must be schema-valid."""
    threat_model = _make_threat_model()

    # Add actors
    actor_obj = MagicMock()
    actor_obj.inBoundary = None
    threat_model.actors = [{"name": "EndUser", "object": actor_obj, "business_value": None}]

    # Add servers
    server_obj = MagicMock()
    server_obj.inBoundary = MagicMock()
    server_obj.inBoundary.name = "DMZ"
    threat_model.servers = [{"name": "WebServer", "object": server_obj, "business_value": "High"}]

    # Add dataflows
    df = MagicMock()
    df.name = "UserToWeb"
    df.source = MagicMock()
    df.source.name = "EndUser"
    df.sink = MagicMock()
    df.sink.name = "WebServer"
    df.protocol = "HTTPS"
    threat_model.dataflows = [df]

    # Add boundaries
    threat_model.boundaries = {"DMZ": {"color": "#ff0000"}}

    report = ReportSerializer.serialize(threat_model, [_make_threat()])
    _validate_report(report)


# ---------------------------------------------------------------------------
# Tests — mandatory fields
# ---------------------------------------------------------------------------

def test_top_level_required_fields_present():
    """The report dict must contain all required top-level keys."""
    threat_model = _make_threat_model()
    report = ReportSerializer.serialize(threat_model, [_make_threat()])

    for field in ("schema_version", "generated_at", "model", "threats", "statistics"):
        assert field in report, f"Missing top-level field '{field}'"


def test_threat_required_fields_present():
    """Each serialised threat must have all required fields from the schema."""
    threat_model = _make_threat_model()
    report = ReportSerializer.serialize(threat_model, [_make_threat()])

    required = {"id", "description", "source", "stride_category", "target", "severity"}
    threat_dict = report["threats"][0]
    for field in required:
        assert field in threat_dict, f"Missing required threat field '{field}'"


def test_statistics_keys_present():
    """The statistics block must contain total, by_source, by_stride_category, by_severity_level."""
    threat_model = _make_threat_model()
    report = ReportSerializer.serialize(threat_model, [_make_threat()])

    stats = report["statistics"]
    for key in ("total", "by_source", "by_stride_category", "by_severity_level"):
        assert key in stats, f"Missing statistics key '{key}'"


# ---------------------------------------------------------------------------
# Tests — empty threats edge case
# ---------------------------------------------------------------------------

def test_empty_threats_list():
    """Serializing with no threats must return an empty threats array and zero total."""
    threat_model = _make_threat_model()
    report = ReportSerializer.serialize(threat_model, [])

    assert report["threats"] == []
    assert report["statistics"]["total"] == 0
    assert report["statistics"]["by_source"] == {}
    assert report["statistics"]["by_stride_category"] == {}
    assert report["statistics"]["by_severity_level"] == {}


# ---------------------------------------------------------------------------
# Tests — robustness with missing optional fields
# ---------------------------------------------------------------------------

def test_threat_with_missing_optional_fields():
    """A threat dict missing optional fields must not raise and must produce valid output."""
    threat_model = _make_threat_model()
    minimal_threat = {
        "description": "Minimal threat",
        "stride_category": "Spoofing",
        "target": "Server",
        "source": "pytm",
    }
    # severity is absent — serializer should handle gracefully
    report = ReportSerializer.serialize(threat_model, [minimal_threat])

    assert len(report["threats"]) == 1
    t = report["threats"][0]
    assert t["id"] == "T-0001"
    assert t["mitre_techniques"] == []
    assert t["capecs"] == []
    assert t["cve"] == []
    # severity dict should exist with None values
    assert isinstance(t["severity"], dict)
    assert t["severity"]["score"] is None
    assert t["severity"]["level"] is None


def test_threat_with_none_severity():
    """A threat with severity=None must not raise."""
    threat_model = _make_threat_model()
    threat = _make_threat()
    threat["severity"] = None

    report = ReportSerializer.serialize(threat_model, [threat])
    assert report["threats"][0]["severity"]["score"] is None


def test_threat_with_empty_description():
    """A threat with empty description string must serialize without error."""
    threat_model = _make_threat_model()
    threat = _make_threat(description="")

    report = ReportSerializer.serialize(threat_model, [threat])
    assert report["threats"][0]["description"] == ""


def test_threat_model_with_no_description():
    """A ThreatModel whose tm.description is None must produce an empty string."""
    threat_model = _make_threat_model(description=None)
    report = ReportSerializer.serialize(threat_model, [])
    assert report["model"]["description"] == ""


# ---------------------------------------------------------------------------
# Tests — ID stability
# ---------------------------------------------------------------------------

def test_ids_stable_between_two_calls():
    """Calling serialize twice with identical data must produce identical IDs."""
    threat_model = _make_threat_model()
    threats = [
        _make_threat(description="First threat"),
        _make_threat(description="Second threat"),
    ]

    report_a = ReportSerializer.serialize(threat_model, threats)
    report_b = ReportSerializer.serialize(threat_model, threats)

    ids_a = [t["id"] for t in report_a["threats"]]
    ids_b = [t["id"] for t in report_b["threats"]]
    assert ids_a == ids_b


def test_ids_stable_regardless_of_source():
    """IDs are positional (index-based), so source field must not change them."""
    threat_model = _make_threat_model()
    threats = [
        _make_threat(source="pytm"),
        _make_threat(source="AI"),
        _make_threat(source="LLM"),
    ]

    report = ReportSerializer.serialize(threat_model, threats)
    ids = [t["id"] for t in report["threats"]]
    assert ids == ["T-0001", "T-0002", "T-0003"]


# ---------------------------------------------------------------------------
# Tests — statistics correctness
# ---------------------------------------------------------------------------

def test_statistics_total_matches_threat_count():
    """statistics.total must equal len(threats)."""
    threat_model = _make_threat_model()
    threats = [_make_threat() for _ in range(7)]
    report = ReportSerializer.serialize(threat_model, threats)
    assert report["statistics"]["total"] == 7


def test_statistics_by_source_counts():
    """by_source must count threats per source correctly."""
    threat_model = _make_threat_model()
    threats = [
        _make_threat(source="pytm"),
        _make_threat(source="pytm"),
        _make_threat(source="AI"),
        _make_threat(source="LLM"),
    ]
    report = ReportSerializer.serialize(threat_model, threats)
    stats = report["statistics"]["by_source"]
    assert stats["pytm"] == 2
    assert stats["AI"] == 1
    assert stats["LLM"] == 1


def test_statistics_by_stride_category():
    """by_stride_category must count threats per STRIDE category."""
    threat_model = _make_threat_model()
    threats = [
        _make_threat(stride_category="Spoofing"),
        _make_threat(stride_category="Spoofing"),
        _make_threat(stride_category="Tampering"),
    ]
    report = ReportSerializer.serialize(threat_model, threats)
    stats = report["statistics"]["by_stride_category"]
    assert stats["Spoofing"] == 2
    assert stats["Tampering"] == 1


def test_statistics_by_severity_level():
    """by_severity_level must aggregate severity levels correctly."""
    threat_model = _make_threat_model()
    threats = [
        _make_threat(severity_level="CRITICAL"),
        _make_threat(severity_level="HIGH"),
        _make_threat(severity_level="HIGH"),
        _make_threat(severity_level="LOW"),
    ]
    report = ReportSerializer.serialize(threat_model, threats)
    stats = report["statistics"]["by_severity_level"]
    assert stats["CRITICAL"] == 1
    assert stats["HIGH"] == 2
    assert stats["LOW"] == 1


# ---------------------------------------------------------------------------
# Tests — model serialization
# ---------------------------------------------------------------------------

def test_model_name_and_description():
    """Model name and description must be serialized faithfully."""
    threat_model = _make_threat_model(name="MyModel", description="My description")
    report = ReportSerializer.serialize(threat_model, [])
    assert report["model"]["name"] == "MyModel"
    assert report["model"]["description"] == "My description"


def test_boundary_name_from_element():
    """Boundary name must be extracted from element.inBoundary.name."""
    threat_model = _make_threat_model()
    boundary = MagicMock()
    boundary.name = "InternalZone"
    server_obj = MagicMock()
    server_obj.inBoundary = boundary
    threat_model.servers = [{"name": "AppServer", "object": server_obj, "business_value": None}]

    report = ReportSerializer.serialize(threat_model, [])
    server_entry = report["model"]["components"]["servers"][0]
    assert server_entry["boundary"] == "InternalZone"


def test_boundary_none_when_no_inboundary():
    """Boundary must be None when the element has no inBoundary."""
    threat_model = _make_threat_model()
    actor_obj = MagicMock()
    actor_obj.inBoundary = None
    threat_model.actors = [{"name": "ExternalUser", "object": actor_obj, "business_value": None}]

    report = ReportSerializer.serialize(threat_model, [])
    actor_entry = report["model"]["components"]["actors"][0]
    assert actor_entry["boundary"] is None


def test_dataflow_protocol_none_when_empty():
    """Dataflow protocol must serialize as None when the attribute is empty string."""
    threat_model = _make_threat_model()
    df = MagicMock()
    df.name = "SomeFlow"
    df.source = MagicMock()
    df.source.name = "A"
    df.sink = MagicMock()
    df.sink.name = "B"
    df.protocol = ""
    threat_model.dataflows = [df]

    report = ReportSerializer.serialize(threat_model, [])
    df_entry = report["model"]["components"]["dataflows"][0]
    assert df_entry["protocol"] is None


def test_boundaries_dict_serialized():
    """Boundaries dict must be serialized as a list of {name, color} dicts."""
    threat_model = _make_threat_model()
    threat_model.boundaries = {
        "DMZ": {"color": "#ff0000"},
        "Internal": {"color": None},
    }
    report = ReportSerializer.serialize(threat_model, [])
    boundaries = report["model"]["components"]["boundaries"]
    names = {b["name"] for b in boundaries}
    assert names == {"DMZ", "Internal"}
