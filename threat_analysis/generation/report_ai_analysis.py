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
AI-authored report sections: CISO risk triage, discovered-attack-path narratives,
and the Red/Blue GDAF debate. Mixed into ReportGenerator (report_generator.py).
"""
import importlib
import logging
import re
from typing import Any, Dict, List, Optional

from threat_analysis.core.models_module import ThreatModel
from threat_analysis.utils import resolve_bom_directory

# Attack-path narrative persona (threat_analysis/config/prompts.yaml → attack_path_narrative) is
# instructed to never emit an ID — the path's hops/techniques are already fixed by
# AttackFlowGenerator before the LLM sees them, so any ID in free text is a grounding
# violation, not a fact worth trusting. Matched independently of the persona's
# cooperation — this is enforced in code, not just requested in the prompt.
_ID_LEAKAGE_PATTERN = re.compile(
    r"\bT\d{4}(?:\.\d{3})?\b|\bCVE-\d{4}-\d+\b|\bCAPEC-\d+\b|\bD3-[A-Z]+\b"
)


def _narrative_has_id_leakage(text: str) -> bool:
    """True if free text contains anything shaped like an ATT&CK/CVE/CAPEC/D3FEND ID."""
    return bool(text) and bool(_ID_LEAKAGE_PATTERN.search(text))


class AIAnalysisMixin:
    """Mixed into ReportGenerator. Requires self.ai_provider, self._ai_config_path,
    self._ai_service, self._disable_rag, self._debate_config, self._attack_flows_config
    (all set in ReportGenerator.__init__)."""

    async def _run_ciso_triage(
        self,
        all_threats: List[Dict],
        gdaf_scenarios: Optional[List[Any]] = None,
        debate_results: Optional[List[Any]] = None,
    ) -> Dict:
        """Generates a CISO-level risk briefing via the AI provider.

        ``gdaf_scenarios``/``debate_results`` are optional — when provided (post-debate,
        since the caller runs the debate before this), the briefing can reference
        goal-driven attack paths and how the Red/Blue debate changed their risk level,
        not just the flat STRIDE threat list. Returns an empty dict when AI is
        unavailable or the provider does not implement ``generate_ciso_triage``.
        Never raises.
        """
        if not self.ai_provider:
            return {}
        # Use cached ai_online flag when available (avoids a second network round-trip).
        # Fall back to check_connection() for providers that don't expose _get_client.
        try:
            _client = await self.ai_provider._get_client()
            if not _client.ai_online:
                return {}
        except Exception:
            try:
                if not await self.ai_provider.check_connection():
                    return {}
            except Exception:
                pass  # proceed; generate_ciso_triage() will fail safely if offline

        from threat_analysis.ai_engine.prompt_loader import get as _get_prompt
        try:
            system_prompt = _get_prompt("ciso_triage", "system")
            template = _get_prompt("ciso_triage", "template")
        except KeyError as exc:
            logging.warning("CISO triage: prompt key missing (%s) — skipping.", exc)
            return {}

        # Build compact threat summary (top 20 by ranking score)
        sev_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
        counts: Dict[str, int] = {}
        for t in all_threats:
            sev = str(t.get("severity") or "").upper()
            counts[sev] = counts.get(sev, 0) + 1

        stride_counts: Dict[str, int] = {}
        for t in all_threats:
            cat = t.get("stride_category", "Unknown")
            stride_counts[cat] = stride_counts.get(cat, 0) + 1

        top20 = sorted(
            all_threats,
            key=lambda x: (sev_order.get(str(x.get("severity") or "").upper(), 0),
                           x.get("_ranking_score", 0.0)),
            reverse=True,
        )[:20]

        threats_summary_lines = []
        for t in top20:
            tid = t.get("id", "?")
            sev = t.get("severity", "?")
            stride = t.get("stride_category", "?")
            target = t.get("target", "?")
            name = t.get("name") or t.get("description", "?")
            threats_summary_lines.append(f"- [{sev}] {tid} | {stride} | {target} | {name[:80]}")

        # Build a compact GDAF attack-scenario summary, noting debate outcomes when a
        # scenario's score was adjusted by the Red/Blue debate.
        debate_by_scenario = {getattr(r, "scenario_id", None): r for r in (debate_results or [])}
        gdaf_lines: List[str] = []
        for scenario in (gdaf_scenarios or [])[:10]:
            sid = getattr(scenario, "scenario_id", "?")
            obj = getattr(scenario, "objective_name", "?")
            actor = getattr(scenario, "actor_name", "?")
            risk = getattr(scenario, "risk_level", "?")
            score = getattr(scenario, "path_score", 0.0) or 0.0
            pre_score = getattr(scenario, "path_score_pre_debate", None)
            line = f"- {sid} | Objective: {obj} | Actor: {actor} | Risk: {risk} | Score: {score:.2f}"
            debate_result = debate_by_scenario.get(sid)
            if debate_result is not None and pre_score is not None:
                outcome = "path still viable after Blue's defences" if getattr(debate_result, "residual_path_viable", False) else "largely blocked by Blue"
                line += (
                    f" (was {pre_score:.2f} pre-debate — Red/Blue debate over "
                    f"{getattr(debate_result, 'round_count', 0)} round(s): {outcome})"
                )
            gdaf_lines.append(line)
        gdaf_summary = "\n".join(gdaf_lines) if gdaf_lines else "No GDAF attack scenarios were generated for this model."

        stride_breakdown = ", ".join(f"{cat}={cnt}" for cat, cnt in sorted(stride_counts.items()))
        prompt = (
            template
            .replace("<<total>>", str(len(all_threats)))
            .replace("<<n_critical>>", str(counts.get("CRITICAL", 0)))
            .replace("<<n_high>>", str(counts.get("HIGH", 0)))
            .replace("<<n_medium>>", str(counts.get("MEDIUM", 0)))
            .replace("<<n_low>>", str(counts.get("LOW", 0)))
            .replace("<<stride_breakdown>>", stride_breakdown)
            .replace("<<threats_summary>>", "\n".join(threats_summary_lines))
            .replace("<<gdaf_summary>>", gdaf_summary)
        )

        try:
            result = await self.ai_provider.generate_ciso_triage(prompt, system_prompt)
        except Exception as exc:
            logging.warning("CISO triage call failed: %s", exc)
            return {}

        if not isinstance(result, dict) or "posture_score" not in result:
            logging.debug("CISO triage: unexpected response — %s", type(result))
            return {}

        # Normalise types
        try:
            result["posture_score"] = round(float(result["posture_score"]), 1)
        except (TypeError, ValueError):
            result["posture_score"] = 0.0

        logging.info(
            "CISO triage: posture_score=%.1f label=%s",
            result["posture_score"],
            result.get("posture_label", "?"),
        )
        return result

    async def _generate_path_narratives(self, discovered_attack_paths: List[Dict]) -> None:
        """Adds a grounded narrative + business_impact to each discovered attack path,
        in place. One LLM call per path — naturally capped at one path per STRIDE
        category (at most 6), since that's all AttackFlowGenerator.get_paths_summary()
        ever returns. Never raises; skips silently when AI is unavailable, disabled via
        config, or the provider does not implement the persona.

        Grounding: each path's hops/techniques/targets are already fixed by
        AttackFlowGenerator before this call — the persona explains them, it does not
        design them, and is instructed to never emit an ID. Any response that does
        anyway (T-numbers, CVE, CAPEC, D3-) is discarded entirely, not partially
        trusted — the code has no way to tell a correct ID from a hallucinated one in
        ungrounded free text, so the only safe move is to drop the whole response.
        """
        if not discovered_attack_paths or not self.ai_provider:
            return
        if not self._attack_flows_config.get("include_narrative", True):
            return
        try:
            _client = await self.ai_provider._get_client()
            if not _client.ai_online:
                return
        except Exception:
            try:
                if not await self.ai_provider.check_connection():
                    return
            except Exception:
                pass  # proceed; generate_attack_path_narrative() will fail safely if offline

        from threat_analysis.ai_engine.prompt_loader import get as _get_prompt
        try:
            system_prompt = _get_prompt("attack_path_narrative", "system")
            template = _get_prompt("attack_path_narrative", "template")
        except KeyError as exc:
            logging.warning("Attack path narrative: prompt key missing (%s) — skipping.", exc)
            return

        for path in discovered_attack_paths:
            try:
                hops_lines = []
                for i, hop in enumerate(path.get("hops", []), start=1):
                    line = f"{i}. {hop.get('target', '?')} — technique: {hop.get('technique_name', '?')}"
                    if hop.get("tactic"):
                        line += f" (tactic: {hop['tactic']})"
                    threat_id = hop.get("threat_id")
                    threat_desc = hop.get("threat_description")
                    if threat_id or threat_desc:
                        line += f"\n   Related threat: {threat_id or '?'} — {threat_desc or ''}"
                    hops_lines.append(line)
                hops_detail = "\n".join(hops_lines) if hops_lines else "No hop data available."

                prompt = (
                    template
                    .replace("<<stride_category>>", str(path.get("stride_category", "?")))
                    .replace("<<path_score>>", str(path.get("path_score", 0)))
                    .replace("<<hop_count>>", str(path.get("hop_count", 0)))
                    .replace("<<path_label>>", str(path.get("path_label", "?")))
                    .replace("<<hops_detail>>", hops_detail)
                )

                result = await self.ai_provider.generate_attack_path_narrative(prompt, system_prompt)
                if not isinstance(result, dict):
                    continue

                narrative = result.get("narrative")
                business_impact = result.get("business_impact")
                if not narrative and not business_impact:
                    continue

                if _narrative_has_id_leakage(narrative or "") or _narrative_has_id_leakage(business_impact or ""):
                    logging.warning(
                        "Attack path narrative for '%s' discarded — response contained an "
                        "ID pattern, which the persona is grounded never to emit.",
                        path.get("stride_category", "?"),
                    )
                    continue

                path["narrative"] = narrative
                path["business_impact"] = business_impact
            except Exception as exc:
                logging.warning(
                    "Attack path narrative generation failed for '%s' (non-fatal): %s",
                    path.get("stride_category", "?"), exc,
                )

    async def _run_debate(self, threat_model: Any) -> List[Any]:
        """Runs the Red/Blue adversarial debate over GDAF attack scenarios.

        Returns an empty list when debate is disabled, AI is unavailable, or no
        GDAF scenarios exist. Never raises — mirrors _run_ciso_triage's
        degrade-silently contract.
        """
        if not self._debate_config.get("enabled", False):
            return []
        if not self.ai_provider:
            return []

        scenarios = getattr(threat_model, "gdaf_scenarios", None) or []
        if not scenarios:
            return []

        try:
            _client = await self.ai_provider._get_client()
            if not _client.ai_online:
                return []
        except Exception:
            try:
                if not await self.ai_provider.check_connection():
                    return []
            except Exception:
                pass  # proceed; generate_debate_turn() will fail safely if offline

        from threat_analysis.core.debate_engine import RedBlueDebateEngine  # noqa: PLC0415
        bom_dir = resolve_bom_directory(threat_model)

        engine = RedBlueDebateEngine(self.ai_provider, config=self._debate_config, bom_directory=bom_dir)
        try:
            results = await engine.run(scenarios)
        except Exception as exc:
            logging.warning("Red/Blue debate failed (non-fatal): %s", exc)
            return []

        logging.info("Red/Blue debate: produced %d results", len(results))
        return results

    async def _get_ai_service(self):
        """Lazily constructs and initializes an AIService for the full AI-enrichment
        pipeline (per-component AIThreatCache, boundary-trust-aware prompts, SOC
        analysis pass, system-level RAG threats) — see server/ai_service.py.

        Cached on self for the ReportGenerator's lifetime so repeated calls (e.g. the
        per-submodel loop in project mode) don't re-run the connection check / RAG
        pre-warm every time. Returns None (never raises) if AIService can't be built —
        mirrors every other AI degrade-silently path in this codebase.
        """
        if self._ai_service is not None:
            return self._ai_service
        if not self._ai_config_path:
            return None
        try:
            ai_service_module = importlib.import_module("threat_analysis.server.ai_service")
            AIService = ai_service_module.AIService
            service = AIService(config_path=str(self._ai_config_path), force_disable_rag=self._disable_rag)
            await service.init_ai()
            self._ai_service = service
            return service
        except Exception as exc:
            logging.warning("AIService init failed for report enrichment (non-fatal): %s", exc)
            return None

    async def _run_ai_enrichment(self, threat_model: ThreatModel, progress_callback=None) -> None:
        """Runs the full AI enrichment pipeline via AIService, mutating threat_model in
        place (appends to each element's `.threats` and to `tm.global_threats_llm`).

        Must be called BEFORE _get_all_threats_with_mitre_info() — that method's
        existing collectors read exactly these two mutation points to build the
        AI/LLM-sourced entries in the final threat list; this replaces the previous,
        weaker duplicate enrichment (no cache, no SOC analysis) that used to run after.
        """
        if not self.ai_provider:
            logging.warning("AI enrichment skipped: No AI provider initialized.")
            return
        service = await self._get_ai_service()
        if service is None:
            return
        if progress_callback:
            progress_callback("Starting AI enrichment...")
        try:
            await service._enrich_with_ai_threats(threat_model)
        except Exception as exc:
            logging.warning("AI enrichment failed (non-fatal): %s", exc)
