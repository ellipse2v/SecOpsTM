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

"""Tests for the discovered-attack-path narrative AI pass
(ReportGenerator._generate_path_narratives) and its ID-leakage guard.
"""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from threat_analysis.ai_engine.providers.base_provider import BaseLLMProvider
from threat_analysis.ai_engine.providers.litellm_provider import LiteLLMProvider
from threat_analysis.generation.report_generator import _narrative_has_id_leakage


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_path(stride_category="Tampering", threat_id="T-0001"):
    return {
        "stride_category": stride_category,
        "path_score": 6.5,
        "hop_count": 2,
        "hops": [
            {
                "technique_id": "T1190",
                "technique_name": "Exploit Public-Facing Application",
                "tactic": "Initial Access",
                "target": "WebApp",
                "threat_id": threat_id,
                "threat_description": "Unpatched web app accepts malicious input.",
            },
            {
                "technique_id": "T1485",
                "technique_name": "Data Destruction",
                "tactic": "Impact",
                "target": "Database",
                "threat_id": "T-0002",
                "threat_description": "DB has no backup and is reachable from WebApp.",
            },
        ],
        "threat_ids": [threat_id, "T-0002"],
        "path_label": "WebApp → Database",
    }


def _make_report_generator(provider=None, include_narrative=True):
    from threat_analysis.generation.report_generator import ReportGenerator

    rg = object.__new__(ReportGenerator)
    rg.ai_provider = provider
    rg._attack_flows_config = {"include_narrative": include_narrative}
    return rg


def _make_provider(return_value: dict) -> MagicMock:
    provider = MagicMock(spec=BaseLLMProvider)
    provider.check_connection = AsyncMock(return_value=True)
    provider.generate_attack_path_narrative = AsyncMock(return_value=return_value)
    return provider


VALID_NARRATIVE = {
    "narrative": "An attacker exploits the public-facing web app to pivot into the database.",
    "business_impact": "Loss of customer data integrity and availability.",
}


# ---------------------------------------------------------------------------
# _narrative_has_id_leakage — pure function
# ---------------------------------------------------------------------------

class TestNarrativeHasIdLeakage:
    def test_clean_text_has_no_leakage(self):
        assert not _narrative_has_id_leakage(VALID_NARRATIVE["narrative"])

    def test_empty_text_has_no_leakage(self):
        assert not _narrative_has_id_leakage("")
        assert not _narrative_has_id_leakage(None)

    def test_attack_technique_id_detected(self):
        assert _narrative_has_id_leakage("The attacker uses T1190 to gain access.")

    def test_attack_subtechnique_id_detected(self):
        assert _narrative_has_id_leakage("Leverages T1078.001 for valid accounts.")

    def test_cve_id_detected(self):
        assert _narrative_has_id_leakage("Exploiting CVE-2023-12345 on the server.")

    def test_capec_id_detected(self):
        assert _narrative_has_id_leakage("This matches CAPEC-66 injection pattern.")

    def test_d3fend_id_detected(self):
        assert _narrative_has_id_leakage("Mitigated by D3-NTA network analysis.")

    def test_plain_word_starting_with_t_is_not_a_false_positive(self):
        assert not _narrative_has_id_leakage("The team escalates to management.")


# ---------------------------------------------------------------------------
# _generate_path_narratives — gating
# ---------------------------------------------------------------------------

class TestGeneratePathNarrativesGating:
    def test_no_ai_provider_skips(self):
        rg = _make_report_generator(provider=None)
        paths = [_make_path()]
        asyncio.run(rg._generate_path_narratives(paths))
        assert "narrative" not in paths[0]

    def test_empty_paths_skips(self):
        provider = _make_provider(VALID_NARRATIVE)
        rg = _make_report_generator(provider=provider)
        asyncio.run(rg._generate_path_narratives([]))
        provider.generate_attack_path_narrative.assert_not_called()

    def test_include_narrative_disabled_skips(self):
        provider = _make_provider(VALID_NARRATIVE)
        rg = _make_report_generator(provider=provider, include_narrative=False)
        paths = [_make_path()]
        asyncio.run(rg._generate_path_narratives(paths))
        assert "narrative" not in paths[0]
        provider.generate_attack_path_narrative.assert_not_called()

    def test_provider_offline_skips(self):
        provider = MagicMock(spec=BaseLLMProvider)
        provider.check_connection = AsyncMock(return_value=False)
        rg = _make_report_generator(provider=provider)
        paths = [_make_path()]
        asyncio.run(rg._generate_path_narratives(paths))
        assert "narrative" not in paths[0]
        provider.generate_attack_path_narrative.assert_not_called()


# ---------------------------------------------------------------------------
# _generate_path_narratives — success + grounding
# ---------------------------------------------------------------------------

class TestGeneratePathNarrativesSuccess:
    def test_valid_result_applied_to_path(self):
        provider = _make_provider(VALID_NARRATIVE)
        rg = _make_report_generator(provider=provider)
        paths = [_make_path()]

        with patch("threat_analysis.ai_engine.prompt_loader.get", return_value="stub <<hops_detail>>"):
            asyncio.run(rg._generate_path_narratives(paths))

        assert paths[0]["narrative"] == VALID_NARRATIVE["narrative"]
        assert paths[0]["business_impact"] == VALID_NARRATIVE["business_impact"]

    def test_prompt_includes_hop_details_and_no_technique_ids(self):
        """The grounding block gives technique names, not IDs — reduces the model's
        raw material to echo back a malformed or hallucinated ID.
        """
        captured = {}

        async def _capture(prompt, system_prompt):
            captured["prompt"] = prompt
            return VALID_NARRATIVE

        provider = MagicMock(spec=BaseLLMProvider)
        provider.check_connection = AsyncMock(return_value=True)
        provider.generate_attack_path_narrative = _capture
        rg = _make_report_generator(provider=provider)
        paths = [_make_path()]

        def _fake_prompt(section, key):
            if key == "template":
                return "<<stride_category>> <<path_score>> <<hop_count>> <<path_label>> <<hops_detail>>"
            return "system"

        with patch("threat_analysis.ai_engine.prompt_loader.get", side_effect=_fake_prompt):
            asyncio.run(rg._generate_path_narratives(paths))

        prompt = captured["prompt"]
        assert "Exploit Public-Facing Application" in prompt
        assert "WebApp" in prompt
        assert "T1190" not in prompt  # technique IDs are not fed into the grounding text

    def test_multiple_paths_each_get_a_call(self):
        provider = _make_provider(VALID_NARRATIVE)
        rg = _make_report_generator(provider=provider)
        paths = [_make_path("Tampering"), _make_path("Spoofing")]

        with patch("threat_analysis.ai_engine.prompt_loader.get", return_value="stub"):
            asyncio.run(rg._generate_path_narratives(paths))

        assert provider.generate_attack_path_narrative.await_count == 2
        assert all("narrative" in p for p in paths)


# ---------------------------------------------------------------------------
# _generate_path_narratives — hallucination guard
# ---------------------------------------------------------------------------

class TestGeneratePathNarrativesGroundingViolation:
    def test_narrative_with_technique_id_is_discarded(self):
        provider = _make_provider({
            "narrative": "Attacker uses T1190 to breach the app.",
            "business_impact": "Data loss.",
        })
        rg = _make_report_generator(provider=provider)
        paths = [_make_path()]

        with patch("threat_analysis.ai_engine.prompt_loader.get", return_value="stub"):
            asyncio.run(rg._generate_path_narratives(paths))

        assert "narrative" not in paths[0]
        assert "business_impact" not in paths[0]

    def test_business_impact_with_cve_is_discarded(self):
        provider = _make_provider({
            "narrative": "A realistic pivot from the app to the database.",
            "business_impact": "Exploits CVE-2024-00001 for full compromise.",
        })
        rg = _make_report_generator(provider=provider)
        paths = [_make_path()]

        with patch("threat_analysis.ai_engine.prompt_loader.get", return_value="stub"):
            asyncio.run(rg._generate_path_narratives(paths))

        assert "narrative" not in paths[0]

    def test_non_dict_result_ignored(self):
        provider = MagicMock(spec=BaseLLMProvider)
        provider.check_connection = AsyncMock(return_value=True)
        provider.generate_attack_path_narrative = AsyncMock(return_value=[])
        rg = _make_report_generator(provider=provider)
        paths = [_make_path()]

        with patch("threat_analysis.ai_engine.prompt_loader.get", return_value="stub"):
            asyncio.run(rg._generate_path_narratives(paths))

        assert "narrative" not in paths[0]

    def test_empty_narrative_and_impact_ignored(self):
        provider = _make_provider({"narrative": "", "business_impact": ""})
        rg = _make_report_generator(provider=provider)
        paths = [_make_path()]

        with patch("threat_analysis.ai_engine.prompt_loader.get", return_value="stub"):
            asyncio.run(rg._generate_path_narratives(paths))

        assert "narrative" not in paths[0]

    def test_provider_exception_is_non_fatal_and_other_paths_still_processed(self):
        provider = MagicMock(spec=BaseLLMProvider)
        provider.check_connection = AsyncMock(return_value=True)
        provider.generate_attack_path_narrative = AsyncMock(
            side_effect=[RuntimeError("LLM error"), VALID_NARRATIVE]
        )
        rg = _make_report_generator(provider=provider)
        paths = [_make_path("Tampering"), _make_path("Spoofing")]

        with patch("threat_analysis.ai_engine.prompt_loader.get", return_value="stub"):
            asyncio.run(rg._generate_path_narratives(paths))

        assert "narrative" not in paths[0]
        assert paths[1]["narrative"] == VALID_NARRATIVE["narrative"]

    def test_missing_prompt_key_skips_all_paths(self):
        provider = _make_provider(VALID_NARRATIVE)
        rg = _make_report_generator(provider=provider)
        paths = [_make_path()]

        with patch("threat_analysis.ai_engine.prompt_loader.get", side_effect=KeyError("attack_path_narrative")):
            asyncio.run(rg._generate_path_narratives(paths))

        assert "narrative" not in paths[0]
        provider.generate_attack_path_narrative.assert_not_called()


# ---------------------------------------------------------------------------
# BaseLLMProvider default
# ---------------------------------------------------------------------------

class TestBaseLLMProviderDefault:
    def test_default_returns_empty_dict(self):
        class _ConcreteProvider(BaseLLMProvider):
            async def check_connection(self): return True
            async def generate_threats(self, c, ctx): return []
            async def generate_markdown(self, p, m=None):
                yield ""

        provider = _ConcreteProvider()
        result = asyncio.run(provider.generate_attack_path_narrative("prompt", "system"))
        assert result == {}


# ---------------------------------------------------------------------------
# LiteLLMProvider.generate_attack_path_narrative
# ---------------------------------------------------------------------------

class TestLiteLLMProviderAttackPathNarrative:
    def test_returns_dict_from_client(self):
        provider = object.__new__(LiteLLMProvider)
        provider._client = None
        provider._config = {}

        async def _fake_generate_content(prompt, system_prompt, output_format, **kw):
            yield VALID_NARRATIVE

        mock_client = MagicMock()
        mock_client.generate_content = _fake_generate_content

        async def _run():
            provider._client = mock_client
            return await provider.generate_attack_path_narrative("prompt", "system")

        result = asyncio.run(_run())
        assert result["narrative"] == VALID_NARRATIVE["narrative"]

    def test_client_exception_returns_empty(self):
        provider = object.__new__(LiteLLMProvider)
        provider._client = None
        provider._config = {}

        async def _fake_generate_content(*a, **kw):
            raise RuntimeError("timeout")
            yield  # make it an async generator

        mock_client = MagicMock()
        mock_client.generate_content = _fake_generate_content

        async def _run():
            provider._client = mock_client
            return await provider.generate_attack_path_narrative("prompt", "system")

        result = asyncio.run(_run())
        assert result == {}
