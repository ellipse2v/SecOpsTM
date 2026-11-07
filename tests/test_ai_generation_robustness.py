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

"""Regressions found by the NVIDIA NIM run of 2026-11-07."""

import argparse
import asyncio
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
import yaml

from threat_analysis import __main__ as cli
from threat_analysis.ai_engine.ai_runtime import (
    AIRunStats,
    resolve_profile,
    run_stats,
    select_provider,
    thinking_params,
)
from threat_analysis.ai_engine.providers.litellm_client import LiteLLMClient
from threat_analysis.core.ai_threat_grounding import (
    contains_placeholder,
    score_grounding,
    scrub_placeholders,
)
from threat_analysis.core.mitre_mapping_module import MitreMapping
from threat_analysis.generation.report_ai_analysis import (
    _is_near_duplicate,
    _narrative_has_id_leakage,
)
from threat_analysis.generation.report_scoring import _ai_mitigations
from threat_analysis.severity_calculator_module import SeverityCalculator

REPO = Path(__file__).resolve().parents[1]


def _client(module, provider_config=None, model="nvidia_nim/some/model", retries=2):
    client = LiteLLMClient()
    client.ai_online = True
    client._litellm_module = module
    client.model_name = model
    client.provider_config = provider_config or {}
    client.ai_config = {"threat_generation": {"num_retries": retries}}
    return client


def _response(content, finish_reason="stop"):
    return SimpleNamespace(choices=[SimpleNamespace(
        message=SimpleNamespace(content=content), finish_reason=finish_reason,
    )])


async def _collect(client, **kwargs):
    return [c async for c in client.generate_content("p", "s", **kwargs)]


# --- reasoning toggle --------------------------------------------------------

def test_nim_gets_thinking_through_chat_template_kwargs():
    assert thinking_params("nvidia_nim", {"enable_thinking": False}, "quality") == {
        "extra_body": {"chat_template_kwargs": {"enable_thinking": False}}
    }


def test_other_providers_keep_the_top_level_field():
    assert thinking_params("vllm", {"enable_thinking": True}, "quality") == {"enable_thinking": True}


def test_quality_sends_nothing_when_thinking_is_not_configured():
    assert thinking_params("nvidia_nim", {}, "quality") == {}


def test_perf_turns_thinking_off_over_the_config():
    assert thinking_params("vllm", {"enable_thinking": True}, "perf") == {"enable_thinking": False}
    assert thinking_params("nvidia_nim", {}, "perf") == {
        "extra_body": {"chat_template_kwargs": {"enable_thinking": False}}
    }


def test_perf_sends_nothing_to_a_provider_without_a_toggle():
    """Anthropic rejects an unknown enable_thinking field."""
    assert thinking_params("anthropic", {}, "perf") == {}


# --- profile -----------------------------------------------------------------

def test_profile_defaults_to_quality(monkeypatch):
    monkeypatch.delenv("SECOPSTM_AI_PROFILE", raising=False)
    assert resolve_profile({}) == "quality"


def test_profile_env_wins_over_config(monkeypatch):
    monkeypatch.setenv("SECOPSTM_AI_PROFILE", "perf")
    assert resolve_profile({"threat_generation": {"profile": "quality"}}) == "perf"


def test_unknown_profile_cannot_loosen_the_filter(monkeypatch):
    monkeypatch.delenv("SECOPSTM_AI_PROFILE", raising=False)
    assert resolve_profile({"threat_generation": {"profile": "fast"}}) == "quality"


# --- provider selection ------------------------------------------------------

def test_force_provider_applies_to_every_caller(monkeypatch):
    config = {"ai_providers": {"a": {"enabled": True}, "b": {"enabled": False, "model": "m"}}}
    monkeypatch.setenv("SECOPSTM_FORCE_PROVIDER", "b")
    assert select_provider(config)[0] == "b"


def test_report_generator_honours_force_provider(monkeypatch, tmp_path):
    from threat_analysis.generation.report_generator import ReportGenerator
    path = tmp_path / "ai.yaml"
    path.write_text(yaml.safe_dump({"ai_providers": {
        "ollama": {"enabled": True, "model": "x"},
        "groq": {"enabled": False, "model": "y"},
    }}), encoding="utf-8")
    monkeypatch.setenv("SECOPSTM_FORCE_PROVIDER", "groq")
    generator = ReportGenerator(MagicMock(), MagicMock(), cve_service=MagicMock(), ai_config_path=path)
    assert type(generator.ai_provider).__name__ == "LiteLLMProvider"


# --- empty content -----------------------------------------------------------

@pytest.mark.parametrize("output_format", ["json", "text"])
def test_none_content_gives_a_clear_error(output_format):
    module = MagicMock()
    module.acompletion = AsyncMock(return_value=_response(None, "length"))
    chunks = asyncio.run(_collect(_client(module), output_format=output_format, stream=False))
    assert len(chunks) == 1
    assert chunks[0].startswith("Error: LLM returned no content")
    assert "reasoning" in chunks[0]


# --- retries -----------------------------------------------------------------

class _Timeout(Exception):
    pass


class _RateLimit(Exception):
    pass


def _retry_module(side_effect):
    module = MagicMock()
    module.RateLimitError = _RateLimit
    module.APIConnectionError = None
    module.InternalServerError = None
    module.ServiceUnavailableError = None
    module.acompletion = AsyncMock(side_effect=side_effect)
    return module


def test_timeout_is_not_retried():
    module = _retry_module(_Timeout("slow"))
    chunks = asyncio.run(_collect(_client(module), stream=False))
    assert module.acompletion.await_count == 1
    assert chunks[0].startswith("Error:")


def test_rate_limit_is_retried(monkeypatch):
    monkeypatch.setattr(asyncio, "sleep", AsyncMock())
    module = _retry_module([_RateLimit("429"), _response("ok")])
    chunks = asyncio.run(_collect(_client(module), stream=False))
    assert module.acompletion.await_count == 2
    assert chunks == ["ok"]


def test_litellm_timeout_is_not_a_retried_type():
    """Runs in a subprocess: other tests leave a mock in sys.modules['litellm']."""
    pytest.importorskip("litellm")
    code = (
        "import litellm\n"
        "for n in ('RateLimitError', 'APIConnectionError', 'InternalServerError',\n"
        "          'ServiceUnavailableError'):\n"
        "    assert not issubclass(litellm.Timeout, getattr(litellm, n)), n\n"
    )
    subprocess.run([sys.executable, "-c", code], check=True, timeout=120)


# --- run stats and exit code -------------------------------------------------

def test_clean_run_has_no_problems():
    stats = AIRunStats()
    stats.add("calls", 3)
    assert stats.problems() == []


def test_offline_provider_is_a_problem():
    stats = AIRunStats()
    stats.add("offline_checks")
    assert "unreachable" in stats.problems()[0]


def test_failed_components_are_named():
    stats = AIRunStats()
    stats.add("calls")
    stats.component_failed("Database")
    assert any("Database" in p for p in stats.problems())


def test_problems_are_scoped_to_the_mark():
    stats = AIRunStats()
    stats.add("failed_calls")
    stats.component_failed("Old")
    mark = stats.mark()
    stats.add("calls")
    assert stats.problems(since=mark) == []


def _args(tmp_path, strict, enabled=True):
    path = tmp_path / "ai.yaml"
    path.write_text(yaml.safe_dump({"ai_providers": {"x": {"enabled": enabled}}}), encoding="utf-8")
    return argparse.Namespace(ai_config_file=str(path), fail_on_ai_error=strict, no_ai=False)


def test_ai_failure_exits_non_zero_only_on_request(tmp_path, capsys):
    mark = run_stats.mark()
    run_stats.add("offline_checks")
    cli._finish_ai_run(_args(tmp_path, strict=False), mark)
    assert "AI problem" in capsys.readouterr().err
    with pytest.raises(SystemExit) as exc:
        cli._finish_ai_run(_args(tmp_path, strict=True), mark)
    assert exc.value.code == cli.EXIT_AI_FAILED


def test_offline_user_without_ai_config_sees_nothing(tmp_path, capsys):
    cli._finish_ai_run(_args(tmp_path, strict=False, enabled=False), run_stats.mark())
    assert capsys.readouterr().err == ""


# --- config lookup -----------------------------------------------------------

def test_default_ai_config_falls_back_to_the_package(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    path = cli._resolve_ai_config_path(argparse.Namespace(ai_config_file="config/ai_config.yaml"))
    assert path == REPO / "threat_analysis" / "config" / "ai_config.yaml"
    assert path.is_file()


def test_explicit_ai_config_never_falls_back(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    missing = tmp_path / "mine.yaml"
    assert cli._resolve_ai_config_path(argparse.Namespace(ai_config_file=str(missing))) == missing


def test_packaged_ai_config_matches_the_repository_one():
    packaged = REPO / "threat_analysis" / "config" / "ai_config.yaml"
    assert packaged.read_bytes() == (REPO / "config" / "ai_config.yaml").read_bytes()


# --- grounding ---------------------------------------------------------------

@pytest.mark.parametrize("text", [
    "CVE-2023-XXXX", "cve-2022-yyyy", "CVE-YYYY-NNNN", "CVE-20XX-1234", "T1XXX",
    "VulnerabilityID IN (CVE-2023-XXXX, CVE-2022-YYYY)",
])
def test_placeholders_are_detected(text):
    assert contains_placeholder(text)


@pytest.mark.parametrize("text", ["CVE-2021-44228", "CVE-2023-1234567", "T1110", "T1110.001", "no id"])
def test_real_identifiers_are_not_placeholders(text):
    assert not contains_placeholder(text)


def test_placeholder_is_found_in_nested_values():
    assert contains_placeholder({"siem_rules": [{"logic": "x = CVE-2023-XXXX"}]})


def test_scrub_keeps_the_prose():
    assert scrub_placeholders({"a": ["see CVE-2023-XXXX now"]}) == {
        "a": ["see [unverified identifier removed] now"]
    }


def test_narrative_with_placeholder_is_rejected():
    assert _narrative_has_id_leakage("exploits CVE-2023-XXXX on the host")


def _details(**over):
    details = {
        "technology_tags": "N/A", "security_controls": "None declared in the model",
        "inbound_flows": "", "outbound_flows": "", "is_public": False, "trust_boundary": "",
    }
    details.update(over)
    return details


def _threat_with_signals(count):
    """Valid category, CAPEC id, then real control gaps."""
    words = ["waf", "ids"][: max(0, count - 2)]
    return {"category": "Tampering", "title": "t", "description": " ".join(words),
            "capec_ids": ["CAPEC-66"]}


def test_threshold_075_keeps_the_same_threats_as_before():
    """The finer grid must not let a two-signal threat through the default filter."""
    controls = "WAF: No | IDS: No"
    two = score_grounding(_threat_with_signals(2), _details(security_controls=controls))
    three = score_grounding(_threat_with_signals(3), _details(security_controls=controls))
    assert two.confidence == 0.7 and two.confidence < 0.75
    assert three.confidence == 0.8 and three.confidence >= 0.75


def test_control_keyword_must_be_a_word():
    """'relationships' contains 'ips', 'bids' contains 'ids'."""
    threat = {"category": "x", "title": "relationships and bids", "description": ""}
    assert score_grounding(threat, _details(security_controls="IDS: No | IPS: No")).signals == []


@pytest.mark.parametrize("title,description,flagged", [
    ("Unencrypted VPN Tunnel Data Interception", "The tunnel is encrypted with IPsec.", True),
    ("Unencrypted API traffic", "The flow carries data that is not encrypted.", False),
    ("Plaintext credentials in logs", "Secrets are written unencrypted to disk.", False),
    ("VPN session hijack", "The tunnel is encrypted with IPsec.", False),
])
def test_title_contradiction(title, description, flagged):
    result = score_grounding({"title": title, "description": description}, _details())
    assert any("title claims" in f for f in result.flags) is flagged


# --- ATT&CK coherence --------------------------------------------------------

@pytest.fixture(scope="module")
def techniques():
    return {
        "T1027": {"tactics": ["Defense Evasion"]},
        "T1110": {"tactics": ["Credential Access"]},
        "T1498": {"tactics": ["Impact"]},
        "T1499.004": {"tactics": ["Impact"]},
        "T1565": {"tactics": ["Impact"]},
    }


def test_dos_keeps_only_impact_techniques(techniques):
    kept = MitreMapping._coherent_techniques(techniques, "Denial of Service")
    assert set(kept) == {"T1498", "T1499.004", "T1565"}


def test_dos_techniques_stay_out_of_other_categories(techniques):
    kept = MitreMapping._coherent_techniques(techniques, "Tampering")
    assert "T1565" in kept and "T1498" not in kept and "T1499.004" not in kept


def test_unknown_category_is_not_filtered(techniques):
    assert MitreMapping._coherent_techniques(techniques, "Generic RAG Threat") == techniques


# --- severity ----------------------------------------------------------------

def test_category_with_spaces_uses_its_base_score():
    calc = SeverityCalculator(markdown_content="")
    assert calc.calculate_score("Elevation of Privilege", "x") == 9.0


def test_score_separates_what_used_to_saturate():
    calc = SeverityCalculator(markdown_content="")
    worst = calc.calculate_score("Tampering", "x", impact=5, likelihood=5)
    middle = calc.calculate_score("Tampering", "x", impact=4, likelihood=4)
    low = calc.calculate_score("Tampering", "x", impact=3, likelihood=3)
    assert worst == 9.0
    assert worst > middle > low
    assert calc.get_severity_level(middle)[0] != "CRITICAL"


# --- narratives and mitigations ----------------------------------------------

def test_near_duplicate_narrative_is_detected():
    text = "The attacker reaches the gateway then pivots into the database server and steals records."
    assert _is_near_duplicate(text + " Quickly.", [text])
    assert not _is_near_duplicate("Logs get wiped so nobody can prove what happened on the host.", [text])


def test_llm_mitigations_win():
    assert _ai_mitigations({"mitigations": ["Rotate keys"]}, [{"mitre_mitigations": [{"name": "M"}]}]) == ["Rotate keys"]


def test_cached_threat_falls_back_to_mitre_mitigations():
    techniques = [{"mitre_mitigations": [{"name": "Audit"}, {"name": "Audit"}]}]
    assert _ai_mitigations({}, techniques) == ["Audit"]
