
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
from unittest.mock import MagicMock, patch, mock_open
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

def test_enrich_threats_with_ai_no_provider(report_generator):
    report_generator.ai_provider = None
    threats = [{"id": 1}]
    result = asyncio.run(report_generator._enrich_threats_with_ai(None, threats))
    assert result == threats

def test_enrich_threats_with_ai_not_reachable(report_generator):
    report_generator.ai_provider = MagicMock()
    report_generator.ai_provider.check_connection = AsyncMock(return_value=False)
    report_generator.ai_context = {"ctx": 1}
    threats = [{"id": 1}]
    result = asyncio.run(report_generator._enrich_threats_with_ai(None, threats))
    assert result == threats

def test_enrich_threats_with_ai_success(report_generator):
    report_generator.ai_provider = MagicMock()
    report_generator.ai_provider.check_connection = AsyncMock(return_value=True)
    report_generator.ai_provider.generate_threats = AsyncMock(return_value=[
        {
            "category": "Spoofing",
            "description": "AI Spoof",
            "business_impact": {"impact_score": 5, "likelihood_score": 5},
            "mitre_techniques": ["T1000"],
            "real_world_precedents": ["CVE-2023-1234"],
            "confidence": 0.9
        }
    ])
    report_generator.ai_context = {"ctx": 1}
    report_generator.severity_calculator.get_severity_info.return_value = {"level": "High", "score": 8.0}

    threat_model = MagicMock()
    threat_model.servers = [{"name": "S1", "description": "desc"}]
    threat_model.actors = []
    threat_model.boundaries = {}

    result = asyncio.run(report_generator._enrich_threats_with_ai(threat_model, []))
    assert len(result) == 1
    assert result[0]["description"] == "AI Spoof"
    assert result[0]["source"] == "AI"

def test_open_report_in_browser(report_generator):
    with patch("webbrowser.open", return_value=True):
        assert report_generator.open_report_in_browser(Path("report.html")) is True
    
    with patch("webbrowser.open", side_effect=Exception("Error")):
        assert report_generator.open_report_in_browser(Path("report.html")) is False

def test_generate_stix_export(report_generator, tmp_path):
    threat_model = MagicMock()
    threat_model.tm.name = "TestModel"
    grouped_threats = {}
    
    with patch.object(report_generator, "_get_all_threats_with_mitre_info", return_value=[]), \
         patch("threat_analysis.generation.report_generator.StixGenerator") as mock_stix_gen:
        
        mock_stix_gen.return_value.generate_stix_bundle.return_value = {"type": "bundle"}
        
        output_dir = tmp_path / "stix"
        result = report_generator.generate_stix_export(threat_model, grouped_threats, output_dir)
        
        assert result == output_dir / "TestModel_stix_attack_flow.json"
        assert result.exists()

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
