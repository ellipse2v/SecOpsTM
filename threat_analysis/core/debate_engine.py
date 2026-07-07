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
RedBlueDebateEngine — adversarial Red/Blue debate over GDAF attack scenarios.

A single configured LLM provider plays two personas (Red: attack, Blue: defence)
across multiple rounds on the top-N highest-viability AttackScenario objects.
The debate is grounded on facts already present in the model (hop protocol/
auth/encryption, BOM CVEs) — no network calls beyond the existing LLM provider.

The final viability adjusts the scenario's path_score/risk_level in place
(never the STRIDE threat table). All processing degrades to an empty result
when the provider is unavailable or returns malformed data — never raises.
"""

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from threat_analysis.ai_engine.prompt_loader import get as _get_prompt
from threat_analysis.core.gdaf_engine import GDAFEngine, compute_risk_level

logger = logging.getLogger(__name__)


@dataclass
class Evidence:
    claim: str
    evidence_type: str  # "cve" | "misconfig" | "port_service" | "privilege_boundary" | "none"
    evidence_ref: str
    confidence: str  # "high" | "medium" | "low"
    verified: bool


@dataclass
class DetectionGap:
    step: str
    control_family: str  # "SIEM" | "EDR" | "IDS" | "NONE"
    covered: bool
    detail: str
    confidence: str


@dataclass
class DebateTurn:
    role: str  # "red" | "blue"
    round_index: int
    viability_score: float
    techniques_attempted: List[str] = field(default_factory=list)
    techniques_blocked: List[str] = field(default_factory=list)
    detection_gaps: List[DetectionGap] = field(default_factory=list)
    failed_alternatives: List[str] = field(default_factory=list)
    evidence: List[Evidence] = field(default_factory=list)
    rationale: str = ""


@dataclass
class DebateResult:
    scenario_id: str
    objective_name: str
    entry_point: str
    target_asset: str
    rounds: List[DebateTurn]
    blocked_paths: List[str]
    residual_detection_gaps: List[DetectionGap]
    red_failed_attempts: List[str]
    round_count: int
    convergence_delta: float
    converged: bool
    final_viability: float
    residual_path_viable: bool
    debate_factor: float = 1.0


def _clamp(value: float, low: float = 0.0, high: float = 1.0) -> float:
    return max(low, min(high, value))


class RedBlueDebateEngine:
    """Runs the Red/Blue debate loop over GDAF AttackScenario objects.

    ``provider`` must implement ``async generate_debate_turn(prompt, system_prompt) -> Dict``
    (see BaseLLMProvider.generate_debate_turn). ``bom_directory`` is optional — grounding
    falls back to hop protocol/auth/encryption facts only when no BOM directory is given.
    """

    def __init__(
        self,
        provider: Any,
        config: Optional[Dict] = None,
        bom_directory: Optional[str] = None,
    ):
        self.provider = provider
        cfg = config or {}
        self.top_n: int = int(cfg.get("top_n", 5))
        self.min_viability_threshold: float = float(cfg.get("min_viability_threshold", 0.5))
        self.max_rounds: int = int(cfg.get("max_rounds", 3))
        self.viability_delta_threshold: float = float(cfg.get("viability_delta_threshold", 0.1))
        self.debate_factor_min: float = float(cfg.get("debate_factor_min", 0.5))
        self.debate_factor_max: float = float(cfg.get("debate_factor_max", 1.5))
        self._bom_directory = bom_directory

    async def run(self, scenarios: List[Any]) -> List[DebateResult]:
        """Debates the top-N eligible scenarios and mutates them in place with the outcome."""
        selected = self._select_scenarios(scenarios)
        results: List[DebateResult] = []
        for scenario in selected:
            result = await self._debate_scenario(scenario)
            if result is None:
                continue
            self._reinject_score(scenario, result)
            results.append(result)
        return results

    # ------------------------------------------------------------------
    # Selection
    # ------------------------------------------------------------------

    def _select_scenarios(self, scenarios: List[Any]) -> List[Any]:
        critical = GDAFEngine.get_risk_thresholds().get("CRITICAL", 4.0)
        eligible = [
            s for s in scenarios
            if self._initial_viability(s, critical) >= self.min_viability_threshold
        ]
        eligible.sort(key=lambda s: s.path_score, reverse=True)
        return eligible[: self.top_n]

    @staticmethod
    def _initial_viability(scenario: Any, critical_threshold: float) -> float:
        detection = float(getattr(scenario, "detection_coverage", 0.0))
        raw = (scenario.path_score / critical_threshold) * (1.0 - 0.5 * detection)
        return _clamp(raw)

    # ------------------------------------------------------------------
    # Grounding (evidence-first — facts already in the model, no new lookups)
    # ------------------------------------------------------------------

    def _build_grounding(self, scenario: Any) -> str:
        bom_loader = None
        if self._bom_directory:
            from threat_analysis.core.bom_loader import BOMLoader  # lazy: avoid cost when unused
            bom_loader = BOMLoader(self._bom_directory)

        lines: List[str] = []
        for hop in getattr(scenario, "hops", []):
            auth = "authenticated" if hop.is_authenticated else "unauthenticated"
            enc = "encrypted" if hop.is_encrypted else "unencrypted"
            techniques = ", ".join(t.id for t in hop.techniques[:3]) if hop.techniques else "none mapped"
            cve_str = "no known CVEs on file"
            if bom_loader:
                bom_data = bom_loader.get(hop.asset_name)
                cves = bom_data.get("known_cves") or []
                if cves:
                    cve_str = f"known CVEs: {', '.join(cves)}"
            lines.append(
                f"- {hop.asset_name} [{hop.hop_position}]: protocol={hop.protocol or 'unknown'}, "
                f"{auth}, {enc}, candidate techniques: {techniques}; {cve_str}"
            )
        return "\n".join(lines) if lines else "No hop data available."

    # ------------------------------------------------------------------
    # Debate loop
    # ------------------------------------------------------------------

    async def _debate_scenario(self, scenario: Any) -> Optional[DebateResult]:
        grounding = self._build_grounding(scenario)
        critical = GDAFEngine.get_risk_thresholds().get("CRITICAL", 4.0)
        prev_viability = self._initial_viability(scenario, critical)
        final_viability = prev_viability

        rounds: List[DebateTurn] = []
        blue_prior = "No prior Blue response yet — this is the first round."
        converged = False
        convergence_delta = 0.0

        for round_index in range(self.max_rounds):
            red_turn = await self._run_turn(scenario, "red", round_index, grounding, blue_prior)
            if red_turn is None:
                break
            rounds.append(red_turn)

            blue_turn = await self._run_turn(
                scenario, "blue", round_index, grounding, self._summarize_turn(red_turn)
            )
            if blue_turn is None:
                break
            rounds.append(blue_turn)

            viability = _clamp(red_turn.viability_score - 0.15 * len(blue_turn.techniques_blocked))
            convergence_delta = abs(viability - prev_viability)
            blue_prior = self._summarize_turn(blue_turn)
            final_viability = viability

            if convergence_delta < self.viability_delta_threshold:
                converged = True
                prev_viability = viability
                break
            prev_viability = viability

        if not rounds:
            return None

        return self._summarize_result(scenario, rounds, final_viability, converged, convergence_delta)

    async def _run_turn(
        self,
        scenario: Any,
        role: str,
        round_index: int,
        grounding: str,
        prior_summary: str,
    ) -> Optional[DebateTurn]:
        try:
            if role == "red":
                system_prompt = _get_prompt("red_blue_debate", "red_system")
                user_prompt = _get_prompt(
                    "red_blue_debate", "red_round_user",
                    objective=scenario.objective_name,
                    entry_point=scenario.entry_point,
                    target_asset=scenario.target_asset,
                    grounding=grounding,
                    blue_prior=prior_summary,
                )
            else:
                system_prompt = _get_prompt("red_blue_debate", "blue_system")
                user_prompt = _get_prompt(
                    "red_blue_debate", "blue_round_user",
                    grounding=grounding,
                    red_attack=prior_summary,
                )
        except KeyError as exc:
            logger.warning("Red/Blue debate: prompt key missing (%s) — skipping.", exc)
            return None

        try:
            raw = await self.provider.generate_debate_turn(user_prompt, system_prompt)
        except Exception as exc:
            logger.warning(
                "Red/Blue debate: %s turn failed for scenario %s: %s",
                role, getattr(scenario, "scenario_id", "?"), exc,
            )
            return None

        if not isinstance(raw, dict) or "viability_score" not in raw:
            logger.warning(
                "Red/Blue debate: malformed %s turn for scenario %s — skipping",
                role, getattr(scenario, "scenario_id", "?"),
            )
            return None

        try:
            return DebateTurn(
                role=role,
                round_index=round_index,
                viability_score=_clamp(float(raw.get("viability_score", 0.0))),
                techniques_attempted=list(raw.get("techniques_attempted") or []),
                techniques_blocked=list(raw.get("techniques_blocked") or []),
                detection_gaps=self._parse_detection_gaps(raw.get("detection_gaps")),
                failed_alternatives=list(raw.get("failed_alternatives") or []),
                evidence=self._parse_evidence(raw.get("evidence")),
                rationale=str(raw.get("rationale", "")),
            )
        except (TypeError, ValueError) as exc:
            logger.warning("Red/Blue debate: could not parse %s turn: %s", role, exc)
            return None

    @staticmethod
    def _parse_evidence(raw_list: Any) -> List[Evidence]:
        result: List[Evidence] = []
        for item in raw_list or []:
            if not isinstance(item, dict):
                continue
            etype = str(item.get("evidence_type", "none")).lower()
            ref = str(item.get("evidence_ref", ""))
            result.append(Evidence(
                claim=str(item.get("claim", "")),
                evidence_type=etype,
                evidence_ref=ref,
                confidence=str(item.get("confidence", "low")).lower(),
                verified=bool(etype != "none" and ref),
            ))
        return result

    @staticmethod
    def _parse_detection_gaps(raw_list: Any) -> List[DetectionGap]:
        result: List[DetectionGap] = []
        for item in raw_list or []:
            if not isinstance(item, dict):
                continue
            result.append(DetectionGap(
                step=str(item.get("step", "")),
                control_family=str(item.get("control_family", "none")).upper(),
                covered=bool(item.get("covered", False)),
                detail=str(item.get("detail", "")),
                confidence=str(item.get("confidence", "low")).lower(),
            ))
        return result

    @staticmethod
    def _summarize_turn(turn: DebateTurn) -> str:
        if turn.role == "red":
            techs = ", ".join(turn.techniques_attempted) or "none"
            return f"Red attempted: {techs}. Rationale: {turn.rationale}"
        blocked = ", ".join(turn.techniques_blocked) or "none"
        return f"Blue blocked: {blocked}. Rationale: {turn.rationale}"

    def _summarize_result(
        self,
        scenario: Any,
        rounds: List[DebateTurn],
        final_viability: float,
        converged: bool,
        convergence_delta: float,
    ) -> DebateResult:
        blocked_paths: List[str] = []
        residual_gaps: List[DetectionGap] = []
        failed_attempts: List[str] = []
        for turn in rounds:
            if turn.role == "red":
                failed_attempts.extend(turn.failed_alternatives)
            else:
                blocked_paths.extend(turn.techniques_blocked)
                residual_gaps.extend(g for g in turn.detection_gaps if not g.covered)

        residual_path_viable = final_viability >= self.min_viability_threshold

        return DebateResult(
            scenario_id=getattr(scenario, "scenario_id", ""),
            objective_name=getattr(scenario, "objective_name", ""),
            entry_point=getattr(scenario, "entry_point", ""),
            target_asset=getattr(scenario, "target_asset", ""),
            rounds=rounds,
            blocked_paths=blocked_paths,
            residual_detection_gaps=residual_gaps,
            red_failed_attempts=failed_attempts,
            round_count=sum(1 for t in rounds if t.role == "red"),
            convergence_delta=round(convergence_delta, 3),
            converged=converged,
            final_viability=round(final_viability, 3),
            residual_path_viable=residual_path_viable,
            debate_factor=1.0,
        )

    # ------------------------------------------------------------------
    # Scoring reinjection (GDAF scenario only — never the STRIDE threat table)
    # ------------------------------------------------------------------

    def _reinject_score(self, scenario: Any, result: DebateResult) -> None:
        span = self.debate_factor_max - self.debate_factor_min
        base = self.debate_factor_min + span * result.final_viability
        factor = base if result.residual_path_viable else min(base, 1.0)

        scenario.path_score_pre_debate = scenario.path_score
        scenario.path_score = round(scenario.path_score * factor, 2)
        thresholds = GDAFEngine.get_risk_thresholds()
        scenario.risk_level = compute_risk_level(scenario.path_score, thresholds)
        scenario.debate_factor = round(factor, 2)
        result.debate_factor = scenario.debate_factor
