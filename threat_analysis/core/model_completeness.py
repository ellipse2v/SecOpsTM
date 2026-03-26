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

"""
ModelCompletenessChecker — rates DSL quality for a ThreatModel.

A complete model produces more accurate threat analysis.  This module scores
ten orthogonal dimensions of model quality, each with a weight.  The weighted
average becomes the overall completeness score (0–100).

Dimension                           Weight   What is checked
----------------------------------- -------  --------------------------------
dataflows_authenticated             15 pts   % of dataflows with is_authenticated=True
dataflows_encrypted                 15 pts   % of dataflows with is_encrypted=True
dataflows_have_protocol             10 pts   % of dataflows with a non-empty protocol
boundaries_trust_defined            15 pts   % of boundaries with isTrusted explicitly set
boundaries_have_description          5 pts   % of boundaries with a description
servers_classified                  15 pts   % of servers with a classification set
servers_described                    5 pts   % of servers with a description
actors_described                     5 pts   % of actors with a description
model_has_boundaries                 5 pts   Boolean — at least one boundary defined
model_has_dataflows                  5 pts   Boolean — at least one dataflow defined
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


# Grades
_GRADE_THRESHOLDS = [
    (90, "A"),
    (75, "B"),
    (60, "C"),
    (40, "D"),
    (0,  "F"),
]


@dataclass
class CompletenessCheck:
    """Result of a single completeness dimension."""
    id: str
    label: str
    weight: int
    passed: int   # number of items that passed
    total: int    # total items checked (0 for boolean checks)
    score: float  # 0.0 – 1.0 normalised score for this dimension
    hint: str     # actionable suggestion when score < 1.0
    is_boolean: bool = False  # True for binary (has/has-not) checks

    @property
    def weighted_score(self) -> float:
        return self.score * self.weight

    @property
    def pct(self) -> int:
        return round(self.score * 100)


@dataclass
class CompletenessReport:
    """Overall completeness report for a ThreatModel."""
    score: float          # 0.0 – 100.0 weighted score
    grade: str            # A / B / C / D / F
    checks: List[CompletenessCheck] = field(default_factory=list)

    @property
    def score_int(self) -> int:
        return round(self.score)


def _ratio(passed: int, total: int) -> float:
    return passed / total if total else 1.0  # empty → full score (not penalised)


def _pct_check(
    check_id: str,
    label: str,
    weight: int,
    passed: int,
    total: int,
    hint: str,
) -> CompletenessCheck:
    score = _ratio(passed, total)
    return CompletenessCheck(
        id=check_id,
        label=label,
        weight=weight,
        passed=passed,
        total=total,
        score=score,
        hint=hint if score < 1.0 else "",
    )


def _bool_check(
    check_id: str,
    label: str,
    weight: int,
    value: bool,
    hint: str,
) -> CompletenessCheck:
    return CompletenessCheck(
        id=check_id,
        label=label,
        weight=weight,
        passed=1 if value else 0,
        total=0,
        score=1.0 if value else 0.0,
        hint=hint if not value else "",
        is_boolean=True,
    )


def _grade(score: float) -> str:
    for threshold, letter in _GRADE_THRESHOLDS:
        if score >= threshold:
            return letter
    return "F"


def score_model(threat_model: Any) -> CompletenessReport:
    """Compute a completeness report for *threat_model*.

    Args:
        threat_model: A ``ThreatModel`` instance (from ``models_module``).

    Returns:
        A :class:`CompletenessReport` with per-check details and an overall
        weighted score (0–100) and grade (A–F).
    """
    dataflows = getattr(threat_model, "dataflows", []) or []
    servers   = getattr(threat_model, "servers", []) or []
    actors    = getattr(threat_model, "actors", []) or []
    boundaries = getattr(threat_model, "boundaries", {}) or {}

    n_df  = len(dataflows)
    n_srv = len(servers)
    n_act = len(actors)
    n_bnd = len(boundaries)

    # ---- dataflow checks ----
    auth_count = sum(
        1 for df in dataflows if getattr(df, "is_authenticated", False)
    )
    enc_count = sum(
        1 for df in dataflows if getattr(df, "is_encrypted", False)
    )
    proto_count = sum(
        1 for df in dataflows
        if (getattr(df, "protocol", "") or "").strip()
    )

    # ---- boundary checks ----
    # isTrusted is "explicitly set" when the property exists and is not the
    # default (False) — we can't distinguish "set to False" from "unset", so
    # we use a heuristic: boundary dict key 'isTrusted' was written by the DSL
    # parser (key is always present after add_boundary), so we check if the
    # props dict carries it.  Fallback: always count it as set.
    trust_set_count = 0
    desc_bnd_count  = 0
    for bname, bprops in boundaries.items():
        # 'isTrusted' key is explicitly written by the DSL parser → always set
        if "isTrusted" in bprops:
            trust_set_count += 1
        bobj = bprops.get("boundary")
        desc = (
            bprops.get("description")
            or getattr(bobj, "description", None)
            or ""
        )
        if desc.strip():
            desc_bnd_count += 1

    # ---- server checks ----
    classified_count = 0
    srv_desc_count   = 0
    _UNSET_CLASSIFICATIONS = {"", "none", "unknown", None}
    for sprops in servers:
        clf = (
            sprops.get("classification")
            or getattr(sprops.get("object"), "classification", None)
        )
        if str(clf).lower() not in _UNSET_CLASSIFICATIONS:
            classified_count += 1
        desc = (
            sprops.get("description")
            or getattr(sprops.get("object"), "description", None)
            or ""
        )
        if str(desc).strip():
            srv_desc_count += 1

    # ---- actor checks ----
    act_desc_count = 0
    for aprops in actors:
        desc = (
            aprops.get("description")
            or getattr(aprops.get("object"), "description", None)
            or ""
        )
        if str(desc).strip():
            act_desc_count += 1

    checks: List[CompletenessCheck] = [
        _pct_check(
            "dataflows_authenticated", "Dataflows authenticated", 15,
            auth_count, n_df,
            "Add is_authenticated=true to dataflows that require credentials "
            "or token-based auth to reduce false positives in threat scoring.",
        ),
        _pct_check(
            "dataflows_encrypted", "Dataflows encrypted", 15,
            enc_count, n_df,
            "Add is_encrypted=true to dataflows that use TLS/SSH/IPSec. "
            "Unencrypted flows receive higher STRIDE scores.",
        ),
        _pct_check(
            "dataflows_have_protocol", "Dataflows have protocol", 10,
            proto_count, n_df,
            "Specify a protocol (e.g. HTTPS, gRPC, SQL) on each dataflow. "
            "Protocol drives MITRE technique mapping and diagram rendering.",
        ),
        _pct_check(
            "boundaries_trust_defined", "Boundaries trust defined", 15,
            trust_set_count, n_bnd,
            "Set isTrusted=true or isTrusted=false on every boundary. "
            "Untrusted boundaries unlock additional STRIDE threat categories.",
        ),
        _pct_check(
            "boundaries_have_description", "Boundaries described", 5,
            desc_bnd_count, n_bnd,
            "Add a description to boundaries (e.g. 'DMZ — internet-facing zone'). "
            "Descriptions improve AI prompt quality.",
        ),
        _pct_check(
            "servers_classified", "Servers have classification", 15,
            classified_count, n_srv,
            "Set classification= (PUBLIC/INTERNAL/RESTRICTED/SECRET) on servers. "
            "Classification affects severity scoring.",
        ),
        _pct_check(
            "servers_described", "Servers described", 5,
            srv_desc_count, n_srv,
            "Add description= to servers. Descriptions are used in AI prompts "
            "and improve threat specificity.",
        ),
        _pct_check(
            "actors_described", "Actors described", 5,
            act_desc_count, n_act,
            "Add description= to actors. Descriptions help the AI identify "
            "privilege levels and attack surfaces.",
        ),
        _bool_check(
            "model_has_boundaries", "Model defines at least one boundary", 5,
            n_bnd > 0,
            "Define at least one boundary (## Boundaries section). "
            "Boundaries are required for trust-zone threat analysis.",
        ),
        _bool_check(
            "model_has_dataflows", "Model defines at least one dataflow", 5,
            n_df > 0,
            "Define at least one dataflow (## Dataflows section). "
            "Dataflows are the primary carrier of STRIDE threats.",
        ),
    ]

    total_weight = sum(c.weight for c in checks)
    raw_score = sum(c.weighted_score for c in checks) / total_weight * 100

    return CompletenessReport(
        score=round(raw_score, 1),
        grade=_grade(raw_score),
        checks=checks,
    )
