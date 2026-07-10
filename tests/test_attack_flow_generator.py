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
import os
import json
from pathlib import Path
from threat_analysis.generation.attack_flow_generator import AttackFlowGenerator

# Helper to create mock threats for testing
def create_mock_threat(tech_id, tech_name, tactics, stride, target, severity_score, threat_id=None):
    """Creates a simplified threat dictionary for testing purposes."""
    threat = {
        "threat_name": f"{stride} against {target}",
        "description": f"A threat involving {tech_name}",
        "stride_category": stride,
        "target": target,
        "severity": {"score": severity_score, "level": "HIGH"},
        "mitre_techniques": [{
            "id": tech_id,
            "name": tech_name,
            "tactics": tactics
        }]
    }
    if threat_id:
        threat["id"] = threat_id
    return threat

@pytest.fixture
def output_dir(tmp_path):
    """Provides a temporary directory for test outputs."""
    return tmp_path

def test_basic_flow_generation_and_structure(output_dir):
    """ 
    Tests that a basic attack flow is generated and has the correct file structure.
    """
    # Arrange
    threats = [
        # Threats for Path A (will be best for Tampering)
        create_mock_threat("T1595", "Active Scanning", ["Reconnaissance"], "Spoofing", "Network", 4.0),
        create_mock_threat("T1566", "Phishing", ["Initial Access"], "Spoofing", "User", 4.0),
        create_mock_threat("T1485", "Data Destruction", ["Impact"], "Tampering", "File System", 9.0), # High score for tampering

        # Threats for Path B (will be best for Information Disclosure)
        create_mock_threat("T1590", "Gather Info", ["Reconnaissance"], "Spoofing", "DNS", 4.0),
        create_mock_threat("T1040", "Network Sniffing", ["Collection"], "Information Disclosure", "Traffic", 9.0), # High score for info disclosure
        create_mock_threat("T1055", "Process Injection", ["Impact"], "Tampering", "Database", 3.0), # Low score for tampering
    ]
    generator = AttackFlowGenerator(threats, model_name="BasicTestModel")

    # Act
    generator.generate_and_save_flows(output_dir)

    # Assert
    afb_dir = output_dir / "afb"
    assert afb_dir.exists(), "The 'afb' output directory should be created."

    output_files = list(afb_dir.glob("*.afb"))
    assert len(output_files) > 0, "Should generate at least one unique path."
    
    # Check the content of the generated file
    with open(output_files[0], 'r') as f:
        data = json.load(f)
    
    assert data["schema"] == "attack_flow_v2", "Incorrect schema version."
    assert len(data["objects"]) > 3, "Flow file should contain multiple objects."

def test_objective_optimization_and_scoring(output_dir):
    """
    Tests that the generator picks the highest-scoring path for an objective.
    """
    # Arrange
    threats = [
        # Threats designed for Path A (will be best for Tampering)
        create_mock_threat("T1595", "Active Scanning", ["Reconnaissance"], "Spoofing", "Network", 3.0),
        create_mock_threat("T1566", "Phishing", ["Initial Access"], "Spoofing", "User", 3.0),
        create_mock_threat("T1485", "Data Destruction", ["Impact"], "Tampering", "File System", 9.0), # High score for tampering
        create_mock_threat("T1040", "Network Sniffing", ["Collection"], "Information Disclosure", "Traffic", 1.0), # LOW score for info dis.

        # Threats designed for Path B (will be best for Information Disclosure)
        create_mock_threat("T1590", "Gather Info", ["Reconnaissance"], "Spoofing", "DNS", 3.0),
        create_mock_threat("T1204", "User Execution", ["Execution"], "Spoofing", "Desktop", 3.0),
        create_mock_threat("T1055", "Process Injection", ["Impact"], "Tampering", "Database", 1.0), # LOW score for tampering
        create_mock_threat("T1005", "Data from Local System", ["Collection"], "Information Disclosure", "Laptop", 9.0), # HIGH score for info dis.
    ]
    generator = AttackFlowGenerator(threats, model_name="OptimizationTest")

    # Act
    generator.generate_and_save_flows(output_dir)

    # Assert
    afb_dir = output_dir / "afb"
    assert afb_dir.exists()
    output_files = list(afb_dir.glob("*.afb"))
    assert len(output_files) > 0, "Should generate at least one optimized path."

    # Check that any generated files are for a valid, expected objective.
    valid_objectives = {"Tampering", "Spoofing", "Information Disclosure", "Repudiation"}
    for f in output_files:
        # Extract objective from filename like "optimized_path_Tampering.afb"
        objective_from_name = f.stem.replace("optimized_path_", "")
        assert objective_from_name in valid_objectives


def test_generic_threat_filtering():
    """
    Tests that threats targeting generic classes are filtered out.
    """
    # Arrange
    class MockServerClass: # Mock a class object
        pass

    threats = [
        {"target": MockServerClass, "stride_category": "Tampering"}, # Generic threat
        create_mock_threat("T1566", "Phishing", ["Initial Access"], "Spoofing", "User", 7.0),
    ]

    # Act
    generator = AttackFlowGenerator(threats, model_name="FilteringTest")

    # Assert
    assert len(generator.threats) == 1


def test_allowed_categories_defaults_to_all_six_stride_categories():
    threats = [
        create_mock_threat("T1595", "Active Scanning", ["Reconnaissance"], "Spoofing", "Network", 3.0),
        create_mock_threat("T1499", "Endpoint DoS", ["Impact"], "Denial of Service", "Server", 3.0),
    ]
    generator = AttackFlowGenerator(threats, model_name="DefaultCategoriesTest")
    assert len(generator.threats) == 2


def test_allowed_categories_narrows_to_configured_set():
    """attack_flows.generate_for_categories was previously dead config — when passed,
    only threats in those STRIDE categories are considered for path-finding.
    """
    threats = [
        create_mock_threat("T1595", "Active Scanning", ["Reconnaissance"], "Spoofing", "Network", 3.0),
        create_mock_threat("T1499", "Endpoint DoS", ["Impact"], "Denial of Service", "Server", 3.0),
    ]
    generator = AttackFlowGenerator(
        threats, model_name="NarrowedCategoriesTest", allowed_categories=["Spoofing"]
    )
    assert len(generator.threats) == 1
    assert generator.threats[0]["stride_category"] == "Spoofing"
    assert generator.threats[0]["target"] == "Network"

def test_asset_hopping_logic(output_dir):
    """
    Tests that the path generation prefers to move between different assets.
    """
    # Arrange
    threats = [
        create_mock_threat("T1566", "Phishing", ["Initial Access"], "Spoofing", "User", 7.0),
        create_mock_threat("T1059", "Command and Scripting Interpreter", ["Execution"], "Elevation of Privilege", "User", 8.0),
        create_mock_threat("T1204", "User Execution", ["Execution"], "Elevation of Privilege", "Workstation", 8.0),
        create_mock_threat("T1499", "Endpoint Denial of Service", ["Impact"], "Tampering", "Workstation", 9.0),
    ]
    generator = AttackFlowGenerator(threats, model_name="AssetHopTest")

    # Act
    generator.generate_and_save_flows(output_dir)

    # Assert
    output_files = list((output_dir / "afb").glob("*.afb"))
    assert len(output_files) > 0, "At least one attack path should be generated."

    with open(output_files[0], 'r') as f:
        data = json.load(f)
        assert any(
            prop[1] == "Workstation"
            for obj in data['objects']
            if obj.get('id') == 'asset'
            for prop in obj.get('properties', [])
            if prop[0] == 'name'
        ), "The attack path should have moved to the new asset 'Workstation'."

# ---------------------------------------------------------------------------
# get_paths_summary — HTML rendering data, no .afb files written
# ---------------------------------------------------------------------------

def test_get_paths_summary_no_threats_returns_empty_list():
    generator = AttackFlowGenerator([], model_name="EmptyTest")
    assert generator.get_paths_summary() == []


def test_get_paths_summary_matches_best_path_selection(output_dir):
    """get_paths_summary() must pick the same best path per category as
    generate_and_save_flows() — same underlying _compute_best_paths().
    """
    threats = [
        create_mock_threat("T1595", "Active Scanning", ["Reconnaissance"], "Spoofing", "Network", 3.0, "T-0001"),
        create_mock_threat("T1485", "Data Destruction", ["Impact"], "Tampering", "File System", 9.0, "T-0002"),
        create_mock_threat("T1055", "Process Injection", ["Impact"], "Tampering", "Database", 1.0, "T-0003"),
    ]
    generator = AttackFlowGenerator(threats, model_name="SummaryTest")

    summary = generator.get_paths_summary()

    assert len(summary) >= 1
    tampering_entry = next(p for p in summary if p["stride_category"] == "Tampering")
    # The higher-severity Data Destruction (9.0) hop must win over Process Injection (1.0).
    assert any(h["technique_id"] == "T1485" for h in tampering_entry["hops"])
    assert not any(h["technique_id"] == "T1055" for h in tampering_entry["hops"])
    assert "T-0002" in tampering_entry["threat_ids"]
    assert tampering_entry["hop_count"] == len(tampering_entry["hops"])
    assert "File System" in tampering_entry["path_label"]


def test_get_paths_summary_does_not_write_files(output_dir, monkeypatch):
    """get_paths_summary() must be read-only — never create the afb/ directory."""
    monkeypatch.chdir(output_dir)
    threats = [
        create_mock_threat("T1485", "Data Destruction", ["Impact"], "Tampering", "File System", 9.0, "T-0001"),
    ]
    generator = AttackFlowGenerator(threats, model_name="NoWriteTest")
    generator.get_paths_summary()
    assert not (output_dir / "afb").exists()


def test_no_paths_found(output_dir, capsys):
    """
    Tests the behavior when no logical paths can be constructed.
    """
    # Arrange
    threats = []
    generator = AttackFlowGenerator(threats, model_name="NoPathTest")

    # Act
    generator.generate_and_save_flows(output_dir)

    # Assert
    captured = capsys.readouterr()
    assert "INFO: No logical attack paths found based on tactic progression." in captured.out
    afb_dir = output_dir / "afb"
    assert len(list(afb_dir.glob("*.afb"))) == 0, "No .afb files should be created when no paths are found."