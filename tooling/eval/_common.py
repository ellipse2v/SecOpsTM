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

"""Frozen-fixture IO, provider forcing, and the debate run wrapper for the
evaluation harness. See docs/superpowers/specs/2026-08-29-debate-gdaf-evaluation-design.md."""

import logging
from typing import Any, Dict, List

from threat_analysis.core.asset_technique_mapper import ScoredTechnique
from threat_analysis.core.gdaf_engine import AttackHop, AttackScenario

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Scenario freeze / thaw
# ---------------------------------------------------------------------------

def _freeze_technique(t: ScoredTechnique) -> Dict[str, Any]:
    return {"id": t.id, "name": t.name, "tactics": list(t.tactics),
            "score": t.score, "rationale": t.rationale, "url": t.url}


def _freeze_hop(h: AttackHop) -> Dict[str, Any]:
    return {
        "asset_name": h.asset_name,
        "asset_type": h.asset_type,
        "techniques": [_freeze_technique(t) for t in h.techniques],
        "dataflow_name": h.dataflow_name,
        "protocol": h.protocol,
        "is_encrypted": h.is_encrypted,
        "is_authenticated": h.is_authenticated,
        "hop_score": h.hop_score,
        "hop_position": h.hop_position,
    }


def freeze(scenarios: List[AttackScenario]) -> List[Dict[str, Any]]:
    """Serialise GDAF scenarios to plain dicts for a committed fixture file."""
    out: List[Dict[str, Any]] = []
    for s in scenarios:
        out.append({
            "scenario_id": s.scenario_id,
            "objective_id": s.objective_id,
            "objective_name": s.objective_name,
            "objective_description": s.objective_description,
            "objective_business_impact": s.objective_business_impact,
            "objective_mitre_final_tactic": s.objective_mitre_final_tactic,
            "actor_id": s.actor_id,
            "actor_name": s.actor_name,
            "actor_sophistication": s.actor_sophistication,
            "entry_point": s.entry_point,
            "target_asset": s.target_asset,
            "hops": [_freeze_hop(h) for h in s.hops],
            "path_score": s.path_score,
            "risk_level": s.risk_level,
            "detection_coverage": s.detection_coverage,
            "unacceptable_risk": s.unacceptable_risk,
            "min_technique_score": s.min_technique_score,
        })
    return out


def _thaw_technique(d: Dict[str, Any]) -> ScoredTechnique:
    return ScoredTechnique(
        id=d["id"], name=d.get("name", ""), tactics=list(d.get("tactics", [])),
        score=d.get("score", 0.0), rationale=d.get("rationale", ""), url=d.get("url", ""),
    )


def _thaw_hop(d: Dict[str, Any]) -> AttackHop:
    return AttackHop(
        asset_name=d["asset_name"],
        asset_type=d.get("asset_type", ""),
        techniques=[_thaw_technique(t) for t in d.get("techniques", [])],
        dataflow_name=d.get("dataflow_name", ""),
        protocol=d.get("protocol", ""),
        is_encrypted=bool(d.get("is_encrypted", False)),
        is_authenticated=bool(d.get("is_authenticated", False)),
        hop_score=d.get("hop_score", 0.0),
        hop_position=d.get("hop_position", ""),
    )


def thaw(records: List[Dict[str, Any]]) -> List[AttackScenario]:
    """Rebuild GDAF scenario dataclasses from a fixture file's records."""
    out: List[AttackScenario] = []
    for d in records:
        out.append(AttackScenario(
            scenario_id=d["scenario_id"],
            objective_id=d.get("objective_id", ""),
            objective_name=d.get("objective_name", ""),
            objective_description=d.get("objective_description", ""),
            objective_business_impact=d.get("objective_business_impact", ""),
            objective_mitre_final_tactic=d.get("objective_mitre_final_tactic", ""),
            actor_id=d.get("actor_id", ""),
            actor_name=d.get("actor_name", ""),
            actor_sophistication=d.get("actor_sophistication", ""),
            entry_point=d.get("entry_point", ""),
            target_asset=d.get("target_asset", ""),
            hops=[_thaw_hop(h) for h in d.get("hops", [])],
            path_score=d["path_score"],
            risk_level=d.get("risk_level", ""),
            detection_coverage=d.get("detection_coverage", 0.0),
            unacceptable_risk=bool(d.get("unacceptable_risk", False)),
            min_technique_score=d.get("min_technique_score", 0.8),
        ))
    return out


def scenario_order(scenarios: List[AttackScenario]) -> List[str]:
    """Scenario ids ranked by path_score desc, ties broken by id for determinism."""
    return [s.scenario_id for s in sorted(
        scenarios, key=lambda s: (-s.path_score, s.scenario_id)
    )]


def risk_levels(scenarios: List[AttackScenario]) -> Dict[str, str]:
    return {s.scenario_id: s.risk_level for s in scenarios}
