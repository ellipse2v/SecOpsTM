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

"""Tests for ModelCompletenessChecker (threat_analysis.core.model_completeness)."""

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from threat_analysis.core.model_completeness import (
    CompletenessCheck,
    CompletenessReport,
    score_model,
    _grade,
    _ratio,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _df(is_authenticated=False, is_encrypted=False, protocol=""):
    df = SimpleNamespace(
        is_authenticated=is_authenticated,
        is_encrypted=is_encrypted,
        protocol=protocol,
    )
    return df


def _server(classification=None, description=""):
    return {"name": "srv", "object": SimpleNamespace(), "classification": classification, "description": description}


def _actor(description=""):
    return {"name": "act", "object": SimpleNamespace(), "description": description}


def _boundary(isTrusted=True, description=""):
    b = SimpleNamespace(description=description)
    return {"boundary": b, "isTrusted": isTrusted, "description": description}


def _make_model(
    dataflows=None,
    servers=None,
    actors=None,
    boundaries=None,
):
    m = SimpleNamespace(
        dataflows=dataflows if dataflows is not None else [],
        servers=servers if servers is not None else [],
        actors=actors if actors is not None else [],
        boundaries=boundaries if boundaries is not None else {},
    )
    return m


# ---------------------------------------------------------------------------
# _grade helper
# ---------------------------------------------------------------------------

class TestGradeHelper:
    def test_90_is_A(self):   assert _grade(90) == "A"
    def test_100_is_A(self):  assert _grade(100) == "A"
    def test_89_is_B(self):   assert _grade(89) == "B"
    def test_75_is_B(self):   assert _grade(75) == "B"
    def test_74_is_C(self):   assert _grade(74) == "C"
    def test_60_is_C(self):   assert _grade(60) == "C"
    def test_59_is_D(self):   assert _grade(59) == "D"
    def test_40_is_D(self):   assert _grade(40) == "D"
    def test_39_is_F(self):   assert _grade(39) == "F"
    def test_0_is_F(self):    assert _grade(0) == "F"


# ---------------------------------------------------------------------------
# _ratio helper
# ---------------------------------------------------------------------------

class TestRatioHelper:
    def test_zero_total_returns_one(self):
        assert _ratio(0, 0) == 1.0

    def test_all_passed_returns_one(self):
        assert _ratio(5, 5) == 1.0

    def test_partial(self):
        assert _ratio(2, 4) == 0.5

    def test_zero_passed(self):
        assert _ratio(0, 10) == 0.0


# ---------------------------------------------------------------------------
# Empty model
# ---------------------------------------------------------------------------

class TestEmptyModel:
    def test_empty_model_returns_report(self):
        report = score_model(_make_model())
        assert isinstance(report, CompletenessReport)

    def test_empty_model_has_10_checks(self):
        report = score_model(_make_model())
        assert len(report.checks) == 10

    def test_empty_dataflows_not_penalised(self):
        """Empty collections default to full score (not penalised)."""
        report = score_model(_make_model())
        auth_check = next(c for c in report.checks if c.id == "dataflows_authenticated")
        assert auth_check.score == 1.0

    def test_empty_model_fails_boolean_checks(self):
        report = score_model(_make_model())
        bnd_check = next(c for c in report.checks if c.id == "model_has_boundaries")
        df_check  = next(c for c in report.checks if c.id == "model_has_dataflows")
        assert bnd_check.score == 0.0
        assert df_check.score == 0.0

    def test_empty_model_score_is_float(self):
        report = score_model(_make_model())
        assert isinstance(report.score, float)

    def test_empty_model_grade_assigned(self):
        report = score_model(_make_model())
        assert report.grade in {"A", "B", "C", "D", "F"}


# ---------------------------------------------------------------------------
# Dataflow checks
# ---------------------------------------------------------------------------

class TestDataflowChecks:
    def test_all_authenticated_full_score(self):
        m = _make_model(dataflows=[_df(is_authenticated=True), _df(is_authenticated=True)])
        r = score_model(m)
        c = next(x for x in r.checks if x.id == "dataflows_authenticated")
        assert c.score == 1.0
        assert c.hint == ""

    def test_none_authenticated_zero_score(self):
        m = _make_model(dataflows=[_df(is_authenticated=False), _df(is_authenticated=False)])
        r = score_model(m)
        c = next(x for x in r.checks if x.id == "dataflows_authenticated")
        assert c.score == 0.0
        assert c.hint != ""

    def test_half_encrypted(self):
        m = _make_model(dataflows=[_df(is_encrypted=True), _df(is_encrypted=False)])
        r = score_model(m)
        c = next(x for x in r.checks if x.id == "dataflows_encrypted")
        assert c.score == 0.5
        assert c.passed == 1
        assert c.total == 2

    def test_all_have_protocol(self):
        m = _make_model(dataflows=[_df(protocol="HTTPS"), _df(protocol="gRPC")])
        r = score_model(m)
        c = next(x for x in r.checks if x.id == "dataflows_have_protocol")
        assert c.score == 1.0

    def test_empty_protocol_string_fails(self):
        m = _make_model(dataflows=[_df(protocol=""), _df(protocol="  ")])
        r = score_model(m)
        c = next(x for x in r.checks if x.id == "dataflows_have_protocol")
        assert c.score == 0.0


# ---------------------------------------------------------------------------
# Boundary checks
# ---------------------------------------------------------------------------

class TestBoundaryChecks:
    def test_boundaries_present_passes_boolean(self):
        m = _make_model(boundaries={"dmz": _boundary()})
        r = score_model(m)
        c = next(x for x in r.checks if x.id == "model_has_boundaries")
        assert c.score == 1.0

    def test_no_boundaries_fails_boolean(self):
        m = _make_model(boundaries={})
        r = score_model(m)
        c = next(x for x in r.checks if x.id == "model_has_boundaries")
        assert c.score == 0.0
        assert c.hint != ""

    def test_boundary_with_description_counted(self):
        m = _make_model(boundaries={"dmz": _boundary(description="Internet-facing zone")})
        r = score_model(m)
        c = next(x for x in r.checks if x.id == "boundaries_have_description")
        assert c.score == 1.0

    def test_boundary_without_description_fails(self):
        m = _make_model(boundaries={"dmz": _boundary(description="")})
        r = score_model(m)
        c = next(x for x in r.checks if x.id == "boundaries_have_description")
        assert c.score == 0.0

    def test_trust_key_presence_counts(self):
        m = _make_model(boundaries={"dmz": {"boundary": SimpleNamespace(), "isTrusted": False}})
        r = score_model(m)
        c = next(x for x in r.checks if x.id == "boundaries_trust_defined")
        assert c.score == 1.0

    def test_missing_trust_key_fails(self):
        m = _make_model(boundaries={"dmz": {"boundary": SimpleNamespace()}})
        r = score_model(m)
        c = next(x for x in r.checks if x.id == "boundaries_trust_defined")
        assert c.score == 0.0


# ---------------------------------------------------------------------------
# Server checks
# ---------------------------------------------------------------------------

class TestServerChecks:
    def test_classified_server(self):
        m = _make_model(servers=[_server(classification="INTERNAL")])
        r = score_model(m)
        c = next(x for x in r.checks if x.id == "servers_classified")
        assert c.score == 1.0

    def test_unclassified_server(self):
        m = _make_model(servers=[_server(classification=None)])
        r = score_model(m)
        c = next(x for x in r.checks if x.id == "servers_classified")
        assert c.score == 0.0

    def test_none_string_classification_fails(self):
        m = _make_model(servers=[_server(classification="none")])
        r = score_model(m)
        c = next(x for x in r.checks if x.id == "servers_classified")
        assert c.score == 0.0

    def test_server_with_description(self):
        m = _make_model(servers=[_server(description="Payment processor")])
        r = score_model(m)
        c = next(x for x in r.checks if x.id == "servers_described")
        assert c.score == 1.0

    def test_server_empty_description(self):
        m = _make_model(servers=[_server(description="")])
        r = score_model(m)
        c = next(x for x in r.checks if x.id == "servers_described")
        assert c.score == 0.0


# ---------------------------------------------------------------------------
# Actor checks
# ---------------------------------------------------------------------------

class TestActorChecks:
    def test_actor_with_description(self):
        m = _make_model(actors=[_actor(description="External user")])
        r = score_model(m)
        c = next(x for x in r.checks if x.id == "actors_described")
        assert c.score == 1.0

    def test_actor_without_description(self):
        m = _make_model(actors=[_actor(description="")])
        r = score_model(m)
        c = next(x for x in r.checks if x.id == "actors_described")
        assert c.score == 0.0

    def test_no_actors_not_penalised(self):
        m = _make_model(actors=[])
        r = score_model(m)
        c = next(x for x in r.checks if x.id == "actors_described")
        assert c.score == 1.0


# ---------------------------------------------------------------------------
# Overall score and grade
# ---------------------------------------------------------------------------

class TestOverallScore:
    def test_perfect_model_score_near_100(self):
        m = _make_model(
            dataflows=[_df(is_authenticated=True, is_encrypted=True, protocol="HTTPS")],
            servers=[_server(classification="INTERNAL", description="API server")],
            actors=[_actor(description="External client")],
            boundaries={"dmz": _boundary(isTrusted=False, description="Internet-facing zone")},
        )
        r = score_model(m)
        assert r.score >= 95.0
        assert r.grade == "A"

    def test_minimal_model_low_score(self):
        """A model with dataflows but no metadata gets a low score."""
        m = _make_model(
            dataflows=[_df()],
            servers=[_server()],
            actors=[_actor()],
            boundaries={"dmz": {"boundary": SimpleNamespace()}},  # no isTrusted key
        )
        r = score_model(m)
        assert r.score < 50.0

    def test_score_bounded_0_to_100(self):
        m = _make_model()
        r = score_model(m)
        assert 0.0 <= r.score <= 100.0

    def test_check_weighted_contribution(self):
        """The sum of weighted scores equals the overall score (within tolerance)."""
        m = _make_model(
            dataflows=[_df(is_authenticated=True, is_encrypted=False, protocol="HTTPS")],
            servers=[_server(classification="INTERNAL", description="x")],
            actors=[_actor(description="y")],
            boundaries={"b": _boundary(isTrusted=True, description="z")},
        )
        r = score_model(m)
        total_weight = sum(c.weight for c in r.checks)
        manual = sum(c.score * c.weight for c in r.checks) / total_weight * 100
        assert abs(r.score - manual) < 0.2  # rounding to 1 decimal

    def test_score_int_property(self):
        m = _make_model()
        r = score_model(m)
        assert r.score_int == round(r.score)


# ---------------------------------------------------------------------------
# CompletenessCheck properties
# ---------------------------------------------------------------------------

class TestCompletenessCheckProperties:
    def test_pct_property(self):
        c = CompletenessCheck("x", "X", 10, 3, 4, 0.75, "hint")
        assert c.pct == 75

    def test_weighted_score(self):
        c = CompletenessCheck("x", "X", 20, 1, 1, 0.5, "hint")
        assert c.weighted_score == 10.0

    def test_boolean_check_no_hint_when_passed(self):
        m = _make_model(dataflows=[_df()])
        r = score_model(m)
        c = next(x for x in r.checks if x.id == "model_has_dataflows")
        assert c.hint == ""

    def test_failed_boolean_check_has_hint(self):
        m = _make_model(dataflows=[])
        r = score_model(m)
        c = next(x for x in r.checks if x.id == "model_has_dataflows")
        assert c.hint != ""
