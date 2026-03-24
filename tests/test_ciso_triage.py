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

"""Tests for CISO triage AI pass (ReportGenerator._run_ciso_triage)."""

import asyncio
from typing import Dict, List
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from threat_analysis.ai_engine.providers.base_provider import BaseLLMProvider
from threat_analysis.ai_engine.providers.litellm_provider import LiteLLMProvider


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_threat(tid="T-0001", severity="HIGH", stride="Information Disclosure",
                 target="WebApp", name="SQL injection", score=0.75):
    return {
        "id": tid,
        "severity": severity,
        "stride_category": stride,
        "target": target,
        "name": name,
        "description": name,
        "_ranking_score": score,
    }


def _make_report_generator(provider=None):
    """Build a minimal ReportGenerator with a mocked provider."""
    from unittest.mock import MagicMock
    from threat_analysis.generation.report_generator import ReportGenerator

    rg = object.__new__(ReportGenerator)
    rg.ai_provider = provider
    rg.ai_context = {}
    return rg


def _make_provider(return_value: dict) -> MagicMock:
    """Creates a mock BaseLLMProvider that returns ``return_value`` from generate_ciso_triage."""
    provider = MagicMock(spec=BaseLLMProvider)
    provider.check_connection = AsyncMock(return_value=True)
    provider.generate_ciso_triage = AsyncMock(return_value=return_value)
    return provider


VALID_TRIAGE = {
    "posture_score": 7.5,
    "posture_label": "HIGH",
    "top_findings": [
        {
            "rank": 1,
            "title": "Unauthenticated SQL injection",
            "detail": "The web app accepts unsanitised input.",
            "threat_ids": ["T-0001"],
        }
    ],
    "quick_wins": [
        {
            "action": "Enable parameterised queries",
            "impact": "HIGH",
            "effort": "LOW",
            "addresses": ["T-0001"],
        }
    ],
    "narrative": "The system presents a HIGH risk posture.",
}


# ---------------------------------------------------------------------------
# BaseLLMProvider default
# ---------------------------------------------------------------------------

class TestBaseLLMProviderDefault:
    def test_default_returns_empty_dict(self):
        """Default implementation returns {} without raising."""

        class _ConcreteProvider(BaseLLMProvider):
            async def check_connection(self): return True
            async def generate_threats(self, c, ctx): return []
            async def generate_attack_flow(self, t, c, ctx): return {}
            async def generate_markdown(self, p, m=None):
                yield ""

        provider = _ConcreteProvider()
        result = asyncio.run(provider.generate_ciso_triage("prompt", "system"))
        assert result == {}


# ---------------------------------------------------------------------------
# _run_ciso_triage — no provider
# ---------------------------------------------------------------------------

class TestRunCisoTriageNoProvider:
    def test_no_ai_provider_returns_empty(self):
        rg = _make_report_generator(provider=None)
        result = asyncio.run(rg._run_ciso_triage([_make_threat()]))
        assert result == {}

    def test_provider_offline_returns_empty(self):
        provider = MagicMock(spec=BaseLLMProvider)
        provider.check_connection = AsyncMock(return_value=False)
        rg = _make_report_generator(provider=provider)
        result = asyncio.run(rg._run_ciso_triage([_make_threat()]))
        assert result == {}
        provider.generate_ciso_triage.assert_not_called()


# ---------------------------------------------------------------------------
# _run_ciso_triage — prompt construction
# ---------------------------------------------------------------------------

class TestRunCisoTriagePrompt:
    def test_prompt_contains_severity_counts(self):
        threats = [
            _make_threat(tid="T-0001", severity="CRITICAL"),
            _make_threat(tid="T-0002", severity="CRITICAL"),
            _make_threat(tid="T-0003", severity="HIGH"),
            _make_threat(tid="T-0004", severity="LOW"),
        ]
        captured = {}

        async def _capture_triage(prompt, system_prompt):
            captured["prompt"] = prompt
            return VALID_TRIAGE

        provider = MagicMock(spec=BaseLLMProvider)
        provider.check_connection = AsyncMock(return_value=True)
        provider.generate_ciso_triage = _capture_triage

        with patch("threat_analysis.ai_engine.prompt_loader.get", return_value="<<total>>\n<<n_critical>>\n<<n_high>>\n<<n_low>>\n<<n_medium>>\n<<stride_breakdown>>\n<<threats_summary>>"):
            rg = _make_report_generator(provider=provider)
            asyncio.run(rg._run_ciso_triage(threats))

        prompt = captured.get("prompt", "")
        assert "4" in prompt          # total
        assert "2" in prompt          # n_critical
        assert "1" in prompt          # n_high (≥ 1 occurrence)

    def test_prompt_caps_at_20_threats(self):
        threats = [_make_threat(tid=f"T-{i:04d}", severity="HIGH") for i in range(50)]
        captured = {}

        async def _capture_triage(prompt, system_prompt):
            captured["prompt"] = prompt
            return VALID_TRIAGE

        provider = MagicMock(spec=BaseLLMProvider)
        provider.check_connection = AsyncMock(return_value=True)
        provider.generate_ciso_triage = _capture_triage

        with patch("threat_analysis.ai_engine.prompt_loader.get", return_value="<<threats_summary>>"):
            rg = _make_report_generator(provider=provider)
            asyncio.run(rg._run_ciso_triage(threats))

        # At most 20 threat lines in the summary
        lines = [l for l in captured.get("prompt", "").splitlines() if l.startswith("- [")]
        assert len(lines) <= 20


# ---------------------------------------------------------------------------
# _run_ciso_triage — result handling
# ---------------------------------------------------------------------------

class TestRunCisoTriageResult:
    def test_valid_result_returned(self):
        provider = _make_provider(VALID_TRIAGE)
        with patch("threat_analysis.ai_engine.prompt_loader.get", return_value="stub"):
            rg = _make_report_generator(provider=provider)
            result = asyncio.run(rg._run_ciso_triage([_make_threat()]))
        assert result["posture_score"] == 7.5
        assert result["posture_label"] == "HIGH"
        assert len(result["top_findings"]) == 1
        assert len(result["quick_wins"]) == 1

    def test_posture_score_normalised_to_float(self):
        triage = {**VALID_TRIAGE, "posture_score": "8"}
        provider = _make_provider(triage)
        with patch("threat_analysis.ai_engine.prompt_loader.get", return_value="stub"):
            rg = _make_report_generator(provider=provider)
            result = asyncio.run(rg._run_ciso_triage([_make_threat()]))
        assert result["posture_score"] == 8.0
        assert isinstance(result["posture_score"], float)

    def test_missing_posture_score_returns_empty(self):
        provider = _make_provider({"posture_label": "HIGH", "narrative": "x"})
        with patch("threat_analysis.ai_engine.prompt_loader.get", return_value="stub"):
            rg = _make_report_generator(provider=provider)
            result = asyncio.run(rg._run_ciso_triage([_make_threat()]))
        assert result == {}

    def test_non_dict_result_returns_empty(self):
        provider = MagicMock(spec=BaseLLMProvider)
        provider.check_connection = AsyncMock(return_value=True)
        provider.generate_ciso_triage = AsyncMock(return_value=[])  # wrong type
        with patch("threat_analysis.ai_engine.prompt_loader.get", return_value="stub"):
            rg = _make_report_generator(provider=provider)
            result = asyncio.run(rg._run_ciso_triage([_make_threat()]))
        assert result == {}

    def test_provider_exception_returns_empty(self):
        provider = MagicMock(spec=BaseLLMProvider)
        provider.check_connection = AsyncMock(return_value=True)
        provider.generate_ciso_triage = AsyncMock(side_effect=RuntimeError("LLM error"))
        with patch("threat_analysis.ai_engine.prompt_loader.get", return_value="stub"):
            rg = _make_report_generator(provider=provider)
            result = asyncio.run(rg._run_ciso_triage([_make_threat()]))
        assert result == {}

    def test_missing_prompt_key_returns_empty(self):
        provider = _make_provider(VALID_TRIAGE)
        with patch("threat_analysis.ai_engine.prompt_loader.get", side_effect=KeyError("ciso_triage")):
            rg = _make_report_generator(provider=provider)
            result = asyncio.run(rg._run_ciso_triage([_make_threat()]))
        assert result == {}

    def test_empty_threats_list_skipped(self):
        """No LLM call when threat list is empty (ai_provider guard in generate_html_report)."""
        provider = _make_provider(VALID_TRIAGE)
        with patch("threat_analysis.ai_engine.prompt_loader.get", return_value="stub"):
            rg = _make_report_generator(provider=provider)
            # _run_ciso_triage still runs but LLM returns valid response
            result = asyncio.run(rg._run_ciso_triage([]))
        # Empty threats summary — still returns whatever provider returns
        assert "posture_score" in result

    def test_invalid_posture_score_defaults_to_zero(self):
        triage = {**VALID_TRIAGE, "posture_score": "not-a-number"}
        provider = _make_provider(triage)
        with patch("threat_analysis.ai_engine.prompt_loader.get", return_value="stub"):
            rg = _make_report_generator(provider=provider)
            result = asyncio.run(rg._run_ciso_triage([_make_threat()]))
        assert result["posture_score"] == 0.0


# ---------------------------------------------------------------------------
# LiteLLMProvider.generate_ciso_triage
# ---------------------------------------------------------------------------

class TestLiteLLMProviderCisoTriage:
    def test_returns_dict_from_client(self):
        provider = object.__new__(LiteLLMProvider)
        provider._client = None
        provider._config = {}

        async def _fake_generate_content(prompt, system_prompt, output_format, **kw):
            yield VALID_TRIAGE

        mock_client = MagicMock()
        mock_client.generate_content = _fake_generate_content

        async def _run():
            provider._client = mock_client
            return await provider.generate_ciso_triage("prompt", "system")

        result = asyncio.run(_run())
        assert result["posture_score"] == 7.5

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
            return await provider.generate_ciso_triage("prompt", "system")

        result = asyncio.run(_run())
        assert result == {}
