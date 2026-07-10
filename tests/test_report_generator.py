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

from unittest.mock import MagicMock, mock_open, patch
import pytest
from pathlib import Path
from threat_analysis.generation.report_generator import ReportGenerator
from threat_analysis.core.cve_service import CVEService

@pytest.fixture
def cve_service(tmp_path):
    """Provides a CVEService instance with a mock project root."""
    project_root = tmp_path
    cve_definitions_path = project_root / "cve_definitions.yml"
    cve_definitions_path.touch()  # Create an empty file
    
    # Mock the cve2capec directory
    (project_root / "threat_analysis" / "external_data" / "cve2capec").mkdir(parents=True, exist_ok=True)

    return CVEService(project_root, cve_definitions_path)

@pytest.fixture
def report_generator(cve_service):
    severity_calculator = MagicMock()
    mitre_mapping = MagicMock()
    return ReportGenerator(severity_calculator, mitre_mapping, cve_service=cve_service)

@patch('threat_analysis.generation.report_generator.get_framework_mitigation_suggestions')
def test_generate_html_report(mock_get_framework_mitigations, report_generator):
    threat_model = MagicMock()
    threat_model.mitre_analysis_results = {
        'total_threats': 1,
        'mitre_techniques_count': 1,
        'stride_distribution': {'S': 1}
    }
    threat_model.tm.name = "Test Architecture"

    threat_mock = MagicMock(description="Test Threat", stride_category='S', target=MagicMock(data=MagicMock(classification=MagicMock(name='Public'))))
    if hasattr(threat_mock, 'mitigations'):
        del threat_mock.mitigations

    grouped_threats = {
        'Spoofing': [
            (threat_mock, MagicMock(name="Test Target"))
        ]
    }

    report_generator.severity_calculator.get_severity_info.return_value = {
        'level': 'High',
        'score': 8.0
    }
    report_generator.mitre_mapping.map_threat_to_mitre.return_value = {
        'techniques': [
            {
                'id': 'T1190',
                'name': 'SQL Injection',
                'defend_mitigations': [],
                'mitre_mitigations': [],
                'owasp_mitigations': [],
                'nist_mitigations': [],
                'cis_mitigations': []
            }
        ],
        'capecs': []
    }

    mock_get_framework_mitigations.return_value = []

    output_file = "test_report.html"
    with patch.object(report_generator.env, 'get_template') as mock_get_template:
        mock_template = MagicMock()
        mock_get_template.return_value = mock_template
        with patch("builtins.open", mock_open()) as mock_file:
            result = report_generator.generate_html_report(threat_model, grouped_threats, output_file)
            mock_file.assert_any_call(output_file, "w", encoding="utf-8")

    assert result == output_file
    mock_template.render.assert_called_once()


@patch('threat_analysis.generation.report_generator.get_framework_mitigation_suggestions')
def test_generate_html_report_assigns_stable_threat_ids(mock_get_framework_mitigations, report_generator):
    """generate_html_report() must assign T-0001-style ids onto all_detailed_threats
    before CISO triage / threat graph build, so those consumers (and the later JSON/STIX
    export, which now reuses this same cached list) all reference the same ids.
    """
    threat_model = MagicMock()
    threat_model.mitre_analysis_results = {
        'total_threats': 2, 'mitre_techniques_count': 0, 'stride_distribution': {}
    }
    threat_model.tm.name = "Test Architecture"

    def _mock_threat(desc):
        m = MagicMock(description=desc, stride_category='S',
                       target=MagicMock(data=MagicMock(classification=MagicMock(name='Public'))))
        if hasattr(m, 'mitigations'):
            del m.mitigations
        return m

    grouped_threats = {
        'Spoofing': [
            (_mock_threat("First threat"), MagicMock(name="Target A")),
            (_mock_threat("Second threat"), MagicMock(name="Target B")),
        ]
    }

    report_generator.severity_calculator.get_severity_info.return_value = {'level': 'High', 'score': 8.0}
    report_generator.mitre_mapping.map_threat_to_mitre.return_value = {'techniques': [], 'capecs': []}
    mock_get_framework_mitigations.return_value = []

    with patch.object(report_generator.env, 'get_template') as mock_get_template:
        mock_get_template.return_value = MagicMock()
        with patch("builtins.open", mock_open()):
            report_generator.generate_html_report(threat_model, grouped_threats, "test_report.html")

    cached = threat_model._report_all_detailed_threats
    assert [t["id"] for t in cached] == ["T-0001", "T-0002"]


@patch('threat_analysis.generation.report_generator.get_framework_mitigation_suggestions')
def test_generate_html_report_computes_discovered_attack_paths(mock_get_framework_mitigations, report_generator):
    """generate_html_report() must compute discovered_attack_paths (AttackFlowGenerator's
    best-path-per-STRIDE-category, independent of GDAF) and pass it to the template —
    this is the new 'Automatically Discovered Attack Paths' HTML section.
    """
    threat_model = MagicMock()
    threat_model.mitre_analysis_results = {
        'total_threats': 1, 'mitre_techniques_count': 1, 'stride_distribution': {}
    }
    threat_model.tm.name = "Test Architecture"

    threat_mock = MagicMock(description="Data destruction", stride_category='Tampering',
                             target=MagicMock(data=MagicMock(classification=MagicMock(name='Public'))))
    if hasattr(threat_mock, 'mitigations'):
        del threat_mock.mitigations

    grouped_threats = {
        'Tampering': [
            (threat_mock, MagicMock(name="FileServer")),
        ]
    }

    report_generator.severity_calculator.get_severity_info.return_value = {'level': 'HIGH', 'score': 9.0}
    report_generator.mitre_mapping.map_threat_to_mitre.return_value = {
        'techniques': [{'id': 'T1485', 'name': 'Data Destruction', 'tactics': ['Impact'],
                        'defend_mitigations': [], 'mitre_mitigations': [],
                        'owasp_mitigations': [], 'nist_mitigations': [], 'cis_mitigations': []}],
        'capecs': [],
    }
    mock_get_framework_mitigations.return_value = []

    with patch.object(report_generator.env, 'get_template') as mock_get_template:
        mock_template = MagicMock()
        mock_get_template.return_value = mock_template
        with patch("builtins.open", mock_open()):
            report_generator.generate_html_report(threat_model, grouped_threats, "test_report.html")

    render_kwargs = mock_template.render.call_args.kwargs
    paths = render_kwargs["discovered_attack_paths"]
    assert len(paths) == 1
    assert paths[0]["stride_category"] == "Tampering"
    assert paths[0]["hops"][0]["technique_id"] == "T1485"
    assert "FileServer" in paths[0]["path_label"]


@patch('threat_analysis.generation.report_generator.get_framework_mitigation_suggestions')
def test_generate_html_report_skips_discovered_attack_paths_when_disabled(mock_get_framework_mitigations, report_generator):
    """attack_flows.enabled: false was previously dead config — must actually skip
    discovered-path computation.
    """
    threat_model = MagicMock()
    threat_model.mitre_analysis_results = {
        'total_threats': 1, 'mitre_techniques_count': 1, 'stride_distribution': {}
    }
    threat_model.tm.name = "Test Architecture"

    threat_mock = MagicMock(description="Data destruction", stride_category='Tampering',
                             target=MagicMock(data=MagicMock(classification=MagicMock(name='Public'))))
    if hasattr(threat_mock, 'mitigations'):
        del threat_mock.mitigations

    grouped_threats = {'Tampering': [(threat_mock, MagicMock(name="FileServer"))]}

    report_generator.severity_calculator.get_severity_info.return_value = {'level': 'HIGH', 'score': 9.0}
    report_generator.mitre_mapping.map_threat_to_mitre.return_value = {
        'techniques': [{'id': 'T1485', 'name': 'Data Destruction', 'tactics': ['Impact'],
                        'defend_mitigations': [], 'mitre_mitigations': [],
                        'owasp_mitigations': [], 'nist_mitigations': [], 'cis_mitigations': []}],
        'capecs': [],
    }
    mock_get_framework_mitigations.return_value = []
    report_generator._attack_flows_config = {"enabled": False}

    with patch.object(report_generator.env, 'get_template') as mock_get_template:
        mock_template = MagicMock()
        mock_get_template.return_value = mock_template
        with patch("builtins.open", mock_open()):
            report_generator.generate_html_report(threat_model, grouped_threats, "test_report.html")

    assert mock_template.render.call_args.kwargs["discovered_attack_paths"] == []


def test_generate_json_export(report_generator):
    threat_model = MagicMock()
    threat_model.tm.name = "Test Architecture"
    threat_model.actors = []
    threat_model.servers = []
    threat_model.boundaries = {}

    # Use a real object or a simple mock that behaves like one but isn't a MagicMock for target
    class SimpleTarget:
        def __init__(self, name):
            self.name = name
    
    class SimpleThreat:
        def __init__(self, description, stride_category):
            self.description = description
            self.stride_category = stride_category
            self.capec_ids = []
            self.source = "pytm"
            self.confidence = 1.0
            self.mitigations = []
            # Mock the target.data.classification.name chain simply
            self.target = MagicMock()
            self.target.data.classification.name = 'Public'

    threat_obj = SimpleThreat("Test Threat", 'S')
    target_obj = SimpleTarget("TestTarget")

    grouped_threats = {
        'Spoofing': [
            (threat_obj, target_obj)
        ]
    }

    report_generator.severity_calculator.get_severity_info.return_value = {
        'level': 'High',
        'score': 8.0
    }
    report_generator.mitre_mapping.map_threat_to_mitre.return_value = {'techniques': [], 'capecs': []}
    report_generator.mitre_mapping.configure_mock(capec_to_mitre_map={})

    output_file = "test_export.json"
    with patch("builtins.open", mock_open()) as mock_file:
        result = report_generator.generate_json_export(threat_model, grouped_threats, output_file)
        mock_file.assert_called_once_with(output_file, "w", encoding="utf-8")

    assert result == output_file


def test_generate_json_export_reuses_ai_enriched_cache(report_generator):
    """generate_json_export must reuse threat_model._report_all_detailed_threats (set by
    generate_html_report after AI enrichment) instead of recomputing pytm-only threats —
    otherwise AI/LLM-sourced threats present in the HTML report silently vanish from the
    JSON/STIX exports.
    """
    threat_model = MagicMock()
    threat_model.tm.name = "Test Architecture"

    cached_ai_threat = {
        "id": "T-0001",
        "description": "AI-enriched threat",
        "stride_category": "Spoofing",
        "target": "TestTarget",
        "source": "AI",
        "severity": {"level": "High", "score": 8.0},
        "confidence": 0.9,
        "capec_ids": [],
        "mitigations": [],
    }
    threat_model._report_all_detailed_threats = [cached_ai_threat]

    with patch.object(report_generator, "_get_all_threats_with_mitre_info") as mock_recompute, \
         patch("threat_analysis.generation.report_generator.ReportSerializer") as mock_serializer, \
         patch("builtins.open", mock_open()):
        mock_serializer.serialize.return_value = {"threats": [cached_ai_threat]}
        report_generator.generate_json_export(threat_model, {}, "test_export.json")

        mock_recompute.assert_not_called()
        mock_serializer.serialize.assert_called_once_with(threat_model, [cached_ai_threat])

def test_get_all_threats_with_mitre_info_handles_missing_url_friendly_name_source(report_generator):
    threat_model = MagicMock()
    threat_model.mitre_analysis_results = {
        'total_threats': 1,
        'mitre_techniques_count': 1,
        'stride_distribution': {'S': 1}
    }
    threat_model.tm.name = "Test Architecture"

    grouped_threats = {
        'Spoofing': [
            (MagicMock(description="Test Threat", stride_category='S', target=MagicMock(data=MagicMock(classification=MagicMock(name='Public')))), MagicMock(name="Test Target"))
        ]
    }

    report_generator.severity_calculator.get_severity_info.return_value = {
        'level': 'High',
        'score': 8.0
    }
    report_generator.mitre_mapping.map_threat_to_mitre.return_value = {
        'techniques': [
            {
                'id': 'T1588.002',
                'name': 'Tool',
                'defend_mitigations': [
                    {
                        'id': 'D3-SCA',
                        'description': 'Software Component Analysis',
                        'url_friendly_name': 'Software-Component-Analysis' # Added key
                    }
                ],
                'mitre_mitigations': [
                    {
                        'id': 'M1051',
                        'name': 'Update Software'
                    }
                ]
            }
        ],
        'capecs': []
    }

    all_detailed_threats = report_generator._get_all_threats_with_mitre_info(grouped_threats, threat_model)

    assert len(all_detailed_threats) == 1
    assert 'mitre_techniques' in all_detailed_threats[0]
    assert len(all_detailed_threats[0]['mitre_techniques']) == 1
    assert 'defend_mitigations' in all_detailed_threats[0]['mitre_techniques'][0]
    assert len(all_detailed_threats[0]['mitre_techniques'][0]['defend_mitigations']) == 1
    assert 'url_friendly_name' in all_detailed_threats[0]['mitre_techniques'][0]['defend_mitigations'][0]
    assert all_detailed_threats[0]['mitre_techniques'][0]['defend_mitigations'][0]['url_friendly_name'] == 'Software-Component-Analysis'

def test_d3fend_mitigations_have_descriptions(report_generator):
    """
    Tests that D3FEND mitigations processed for the report include their
    descriptions.
    """
    threat_model = MagicMock()
    threat_model.tm.name = "Test Architecture"
    
    threat_mock = MagicMock(description="Test Threat", stride_category='S', target=MagicMock(data=MagicMock(classification=MagicMock(name='Public'))))
    grouped_threats = {'Spoofing': [(threat_mock, MagicMock(name="Test Target"))]}

    report_generator.severity_calculator.get_severity_info.return_value = {'level': 'Low', 'score': 1.0}

    report_generator.mitre_mapping.map_threat_to_mitre.return_value = {
        'techniques': [
            {
                'id': 'T1078',
                'name': 'Valid Accounts',
                'defend_mitigations': [
                    {
                        'id': 'D3-DO',
                        'name': 'Decoy Object',
                        'description': 'A Decoy Object is created and deployed for the purposes of deceiving attackers.',
                        'url_friendly_name': 'Decoy-Object'
                    }
                ],
                'mitre_mitigations': []
            }
        ],
        'capecs': []
    }

    all_detailed_threats = report_generator._get_all_threats_with_mitre_info(grouped_threats, threat_model)

    assert len(all_detailed_threats) == 1
    mitre_techniques = all_detailed_threats[0]['mitre_techniques']
    assert len(mitre_techniques) == 1
    d3fend_mitigations = mitre_techniques[0]['defend_mitigations']
    assert len(d3fend_mitigations) == 1
    assert 'description' in d3fend_mitigations[0]
    assert d3fend_mitigations[0]['description'] == 'A Decoy Object is created and deployed for the purposes of deceiving attackers.'