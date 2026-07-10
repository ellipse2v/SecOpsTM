
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

import pytest
import asyncio
import json
import os
from pathlib import Path
from unittest.mock import MagicMock, patch, mock_open, AsyncMock as _StdAsyncMock
from threat_analysis.generation.report_generator import (
    ReportGenerator, 
    _is_network_exposed, 
    _boundary_untrusted,
    load_implemented_mitigations
)
from pytm import Dataflow, Server, Actor, Boundary

def test_boundary_untrusted():
    # No boundary
    element = MagicMock()
    element.inBoundary = None
    assert _boundary_untrusted(element) is True

    # Trusted boundary
    boundary = MagicMock()
    boundary.isTrusted = True
    element.inBoundary = boundary
    assert _boundary_untrusted(element) is False

    # Untrusted boundary
    boundary.isTrusted = False
    assert _boundary_untrusted(element) is True

def test_is_network_exposed():
    # Dataflow cases
    df = MagicMock(spec=Dataflow)
    df.is_authenticated = False
    df.is_encrypted = False
    assert _is_network_exposed(df) is True

    df.is_authenticated = True
    df.is_encrypted = True
    assert _is_network_exposed(df) is False

    # Tuple cases
    src = MagicMock()
    src.inBoundary = None
    sink = MagicMock()
    sink.inBoundary = MagicMock(isTrusted=True)
    assert _is_network_exposed((src, sink)) is True

    # Single element
    assert _is_network_exposed(src) is True

def test_load_implemented_mitigations(tmp_path):
    # Missing file
    assert load_implemented_mitigations(tmp_path / "none") == set()

    # Valid file
    mit_file = tmp_path / "mitigations.txt"
    mit_file.write_text("# Comment\nM-1\n  M-2  \n\n", encoding="utf-8")
    assert load_implemented_mitigations(mit_file) == {"M-1", "M-2"}

@pytest.fixture
def report_generator():
    severity_calc = MagicMock()
    mitre_mapping = MagicMock()
    return ReportGenerator(severity_calc, mitre_mapping)

def test_run_ai_enrichment_no_provider(report_generator):
    """No ai_provider -> _get_ai_service() must not even be attempted."""
    report_generator.ai_provider = None
    with patch.object(report_generator, "_get_ai_service") as mock_get_service:
        asyncio.run(report_generator._run_ai_enrichment(MagicMock()))
    mock_get_service.assert_not_called()


def test_run_ai_enrichment_service_unavailable(report_generator):
    """AIService init failed (_get_ai_service returns None) -> enrichment is a no-op,
    not an error — matches the AI degrade-silently contract used everywhere else.
    """
    report_generator.ai_provider = MagicMock()
    with patch.object(report_generator, "_get_ai_service", new=_StdAsyncMock(return_value=None)):
        # Must not raise.
        asyncio.run(report_generator._run_ai_enrichment(MagicMock()))


def test_run_ai_enrichment_delegates_to_ai_service(report_generator):
    """_run_ai_enrichment() must call AIService._enrich_with_ai_threats(threat_model) —
    the real, cache- and SOC-analysis-aware pipeline — passing the threat_model through
    so it can mutate element.threats / tm.global_threats_llm in place.
    """
    report_generator.ai_provider = MagicMock()
    threat_model = MagicMock()
    mock_service = MagicMock()
    mock_service._enrich_with_ai_threats = _StdAsyncMock()

    with patch.object(report_generator, "_get_ai_service", new=_StdAsyncMock(return_value=mock_service)):
        asyncio.run(report_generator._run_ai_enrichment(threat_model))

    mock_service._enrich_with_ai_threats.assert_awaited_once_with(threat_model)


def test_get_ai_service_caches_across_calls(report_generator):
    """The AIService instance is built once (connection check + RAG pre-warm are not
    free) and reused for the ReportGenerator's lifetime — e.g. across the per-submodel
    loop in project mode.
    """
    report_generator._ai_config_path = Path("/some/ai_config.yaml")
    mock_service_instance = MagicMock()
    mock_service_instance.init_ai = _StdAsyncMock()
    mock_service_cls = MagicMock(return_value=mock_service_instance)
    mock_module = MagicMock(AIService=mock_service_cls)

    with patch("importlib.import_module", return_value=mock_module):
        first = asyncio.run(report_generator._get_ai_service())
        second = asyncio.run(report_generator._get_ai_service())

    assert first is second is mock_service_instance
    mock_service_cls.assert_called_once()
    mock_service_instance.init_ai.assert_awaited_once()


def test_get_ai_service_passes_disable_rag_through(report_generator):
    """report_generator._disable_rag (set from --no-rag) must reach AIService's
    force_disable_rag param.
    """
    report_generator._ai_config_path = Path("/some/ai_config.yaml")
    report_generator._disable_rag = True
    mock_service_instance = MagicMock()
    mock_service_instance.init_ai = _StdAsyncMock()
    mock_service_cls = MagicMock(return_value=mock_service_instance)
    mock_module = MagicMock(AIService=mock_service_cls)

    with patch("importlib.import_module", return_value=mock_module):
        asyncio.run(report_generator._get_ai_service())

    mock_service_cls.assert_called_once_with(
        config_path="/some/ai_config.yaml", force_disable_rag=True
    )


def test_get_ai_service_returns_none_without_config_path(report_generator):
    report_generator._ai_config_path = None
    result = asyncio.run(report_generator._get_ai_service())
    assert result is None


def test_get_ai_service_returns_none_on_init_failure(report_generator):
    report_generator._ai_config_path = Path("/some/ai_config.yaml")
    mock_module = MagicMock()
    mock_module.AIService.side_effect = RuntimeError("boom")

    with patch("importlib.import_module", return_value=mock_module):
        result = asyncio.run(report_generator._get_ai_service())
    assert result is None

def test_open_report_in_browser(report_generator):
    with patch("webbrowser.open", return_value=True):
        assert report_generator.open_report_in_browser(Path("report.html")) is True
    
    with patch("webbrowser.open", side_effect=Exception("Error")):
        assert report_generator.open_report_in_browser(Path("report.html")) is False

def test_generate_stix_export(report_generator, tmp_path):
    threat_model = MagicMock()
    threat_model.tm.name = "TestModel"
    threat_model._report_all_detailed_threats = None  # no HTML-report cache — force recompute
    grouped_threats = {}

    with patch.object(report_generator, "_get_all_threats_with_mitre_info", return_value=[]) as mock_recompute, \
         patch("threat_analysis.generation.report_generator.StixGenerator") as mock_stix_gen:

        mock_stix_gen.return_value.generate_stix_bundle.return_value = {"type": "bundle"}

        output_dir = tmp_path / "stix"
        result = report_generator.generate_stix_export(threat_model, grouped_threats, output_dir)

        assert result == output_dir / "TestModel_stix_attack_flow.json"
        assert result.exists()
        mock_recompute.assert_called_once()


def test_generate_stix_export_reuses_ai_enriched_cache(report_generator, tmp_path):
    """generate_stix_export must reuse threat_model._report_all_detailed_threats (set by
    generate_html_report after AI enrichment) instead of recomputing pytm-only threats.
    """
    threat_model = MagicMock()
    threat_model.tm.name = "TestModel"
    cached_ai_threat = {"id": "T-0001", "description": "AI-enriched threat", "source": "AI"}
    threat_model._report_all_detailed_threats = [cached_ai_threat]
    grouped_threats = {}

    with patch.object(report_generator, "_get_all_threats_with_mitre_info") as mock_recompute, \
         patch("threat_analysis.generation.report_generator.StixGenerator") as mock_stix_gen:

        mock_stix_gen.return_value.generate_stix_bundle.return_value = {"type": "bundle"}

        output_dir = tmp_path / "stix"
        report_generator.generate_stix_export(threat_model, grouped_threats, output_dir)

        mock_recompute.assert_not_called()
        mock_stix_gen.assert_called_once_with(threat_model, [cached_ai_threat])

def test_generate_summary_stats(report_generator):
    # Empty
    assert report_generator.generate_summary_stats([]) == {}
    
    # Mixed
    threats = [
        {"severity": {"level": "High", "score": 8.0}, "stride_category": "Spoofing"},
        {"severity": {"level": "Low", "score": 2.0}, "stride_category": "Tampering"},
        {"severity": {"level": "UNKNOWN", "score": 0.0}, "stride_category": "Unknown"}
    ]
    stats = report_generator.generate_summary_stats(threats)
    assert stats["total_threats"] == 2
    assert stats["average_severity"] == 5.0
    assert stats["max_severity"] == 8.0
    assert stats["min_severity"] == 2.0
    assert stats["severity_distribution"] == {"High": 1, "Low": 1}

def test_get_all_threats_with_mitre_info(report_generator):
    threat_model = MagicMock()
    
    # Mock Actors
    actor_obj = MagicMock()
    actor_obj.name = "Actor1"
    actor_obj.threats = [
        MagicMock(description="AI Threat", source="AI", category="Spoofing", confidence=0.9, capec_ids=[])
    ]
    threat_model.actors = [{"object": actor_obj, "name": "Actor1", "business_value": "High"}]
    
    # Mock Servers
    server_obj = MagicMock()
    server_obj.name = "Server1"
    server_obj.threats = []
    threat_model.servers = [{"object": server_obj, "name": "Server1", "business_value": "Critical"}]
    
    # Mock Dataflows
    df = MagicMock()
    df.name = "Flow1"
    df.source = actor_obj
    df.sink = server_obj
    df.threats = []
    threat_model.dataflows = [df]
    
    # Mock Boundaries
    threat_model.boundaries = {"B1": {"boundary": MagicMock(), "business_value": "Low"}}
    
    # Mock other needed parts
    threat_model.tm.global_threats_llm = [
        MagicMock(description="Global RAG", category="LLM", source="LLM", confidence=0.7)
    ]
    
    report_generator.mitre_mapping.map_threat_to_mitre.return_value = {"techniques": [], "capecs": []}
    report_generator.severity_calculator.get_severity_info.return_value = {"level": "Medium", "score": 5.0}
    
    grouped_threats = {
        "Spoofing": [(MagicMock(description="Pytm Threat", stride_category="Spoofing", source="pytm"), server_obj)]
    }
    
    result = report_generator._get_all_threats_with_mitre_info(grouped_threats, threat_model)

    # We expect: 1 from grouped_threats, 1 from AI Actor threat, 1 from Global RAG
    # Note: deduplication might happen.
    assert len(result) >= 3
    sources = [t["source"] for t in result]
    assert "pytm" in sources
    assert "AI" in sources
    assert "LLM" in sources


def test_get_all_threats_with_mitre_info_collects_boundary_ai_threats(report_generator):
    """AI threats attached to a boundary (a valid enrichment target, see decisions.md
    A3) must be collected into the final report — previously the collector only
    iterated actors/servers/dataflows, silently dropping every AI threat whose target
    was a boundary even though AIService attaches threats to boundaries too.
    """
    threat_model = MagicMock()
    threat_model.actors = []
    threat_model.servers = []
    threat_model.dataflows = []
    threat_model.tm.global_threats_llm = []

    boundary_obj = MagicMock()
    boundary_obj.threats = [
        MagicMock(description="Boundary AI Threat", source="AI", category="Spoofing",
                  confidence=0.9, capec_ids=[])
    ]
    threat_model.boundaries = {
        "Internet": {"boundary": boundary_obj, "business_value": "High"}
    }

    report_generator.mitre_mapping.map_threat_to_mitre.return_value = {"techniques": [], "capecs": []}
    report_generator.severity_calculator.get_severity_info.return_value = {"level": "Medium", "score": 5.0}

    result = report_generator._get_all_threats_with_mitre_info({}, threat_model)

    ai_threats = [t for t in result if t["source"] == "AI"]
    assert len(ai_threats) == 1
    assert ai_threats[0]["target"] == "Internet"


def test_get_all_threats_with_mitre_info_rag_threat_uses_affected_components_as_target(report_generator):
    """RAG (system-level) threats must use the LLM-provided affected_components as
    target when available, instead of the generic 'Threat Model (Global)' label the
    LLM's affected_components field was previously requested but never read.
    """
    threat_model = MagicMock()
    threat_model.actors = []
    threat_model.servers = []
    threat_model.dataflows = []
    threat_model.boundaries = {}

    rag_threat = MagicMock(
        description="Cross-component pivot", category="Elevation of Privilege",
        source="LLM", capec_ids=[], impact=None, likelihood=None,
    )
    rag_threat.ai_details = {"affected_components": ["External Attacker", "Target Server"]}
    threat_model.tm.global_threats_llm = [rag_threat]

    report_generator.mitre_mapping.map_threat_to_mitre.return_value = {"techniques": [], "capecs": []}
    report_generator.severity_calculator.get_severity_info.return_value = {"level": "High", "score": 7.0}

    result = report_generator._get_all_threats_with_mitre_info({}, threat_model)

    llm_threats = [t for t in result if t["source"] == "LLM"]
    assert len(llm_threats) == 1
    assert llm_threats[0]["target"] == "External Attacker → Target Server"


def test_get_all_threats_with_mitre_info_rag_threat_without_affected_components_falls_back(report_generator):
    threat_model = MagicMock()
    threat_model.actors = []
    threat_model.servers = []
    threat_model.dataflows = []
    threat_model.boundaries = {}

    rag_threat = MagicMock(
        description="Generic system-level threat", category="Tampering",
        source="LLM", capec_ids=[], impact=None, likelihood=None,
    )
    rag_threat.ai_details = {}
    threat_model.tm.global_threats_llm = [rag_threat]

    report_generator.mitre_mapping.map_threat_to_mitre.return_value = {"techniques": [], "capecs": []}
    report_generator.severity_calculator.get_severity_info.return_value = {"level": "High", "score": 7.0}

    result = report_generator._get_all_threats_with_mitre_info({}, threat_model)

    llm_threats = [t for t in result if t["source"] == "LLM"]
    assert len(llm_threats) == 1
    assert llm_threats[0]["target"] == "Threat Model (Global)"


def test_get_all_threats_with_mitre_info_syncs_severity_multipliers(report_generator):
    """_get_all_threats_with_mitre_info() must sync self.severity_calculator's target
    multipliers from threat_model.severity_multipliers (parsed by ModelParser from the
    model's own '## Severity Multipliers' section) before any scoring happens —
    self.severity_calculator may be a long-lived singleton reused across different
    models (server mode) and must not score this model using a previous one's values.
    """
    threat_model = MagicMock()
    threat_model.actors = []
    threat_model.servers = []
    threat_model.boundaries = {}
    threat_model.tm.global_threats_llm = []
    threat_model.severity_multipliers = {"WebServer": 1.5}

    report_generator.mitre_mapping.map_threat_to_mitre.return_value = {"techniques": [], "capecs": []}
    report_generator.severity_calculator.get_severity_info.return_value = {"level": "Medium", "score": 5.0}

    report_generator._get_all_threats_with_mitre_info({}, threat_model)

    report_generator.severity_calculator.update_target_multipliers.assert_called_once_with({"WebServer": 1.5})


def test_get_all_business_values(report_generator):
    threat_model = MagicMock()
    threat_model.boundaries = {"B1": {"business_value": "BV1"}}
    threat_model.actors = [{"business_value": "BV2"}]
    threat_model.servers = [{"business_value": "BV3"}]
    
    values = report_generator._get_all_business_values(threat_model)
    assert "BV1" in values
    assert "BV2" in values
    assert "BV3" in values

class AsyncMock(MagicMock):
    async def __call__(self, *args, **kwargs):
        return super(AsyncMock, self).__call__(*args, **kwargs)

    def assert_awaited_once(self):
        if not self.called:
            raise AssertionError("Expected to be awaited once, but was never called")
