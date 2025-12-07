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
from unittest.mock import patch, mock_open
import yaml
import json
from pathlib import Path
import logging

# This is needed to import from the project root
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from threat_analysis.core.cve_service import CVEService

@pytest.fixture
def mock_project_root(tmp_path):
    """Creates a mock project root directory structure for testing."""
    project_root = tmp_path / "SecOpsTM"
    project_root.mkdir()
    
    # Create cve_definitions.yml
    cve_definitions_content = """
    WebServer:
      - CVE-2021-44228
      - CVE-2023-1234
    DatabaseServer :
      - CVE-2022-5678
    """
    (project_root / "cve_definitions.yml").write_text(cve_definitions_content)

    # Create CVE2CAPEC database
    cve2capec_dir = project_root / "threat_analysis" / "external_data" / "cve2capec"
    cve2capec_dir.mkdir(parents=True)
    
    cve_2021_content = '{"CVE-2021-44228": {"CWE": ["502"], "CAPEC": ["153", "242"], "TECHNIQUES": []}}'
    (cve2capec_dir / "CVE-2021.jsonl").write_text(cve_2021_content)

    cve_2022_content = '{"CVE-2022-5678": {"CWE": ["89"], "CAPEC": ["7"], "TECHNIQUES": []}}'
    (cve2capec_dir / "CVE-2022.jsonl").write_text(cve_2022_content)

    cve_2023_content = '{"CVE-2023-1234": {"CWE": ["22"], "CAPEC": ["126"], "TECHNIQUES": []}}'
    (cve2capec_dir / "CVE-2023.jsonl").write_text(cve_2023_content)

    return project_root

def test_cve_service_initialization(mock_project_root):
    """Test that CVEService initializes correctly and loads data."""
    cve_definitions_path = mock_project_root / "cve_definitions.yml"
    service = CVEService(mock_project_root, cve_definitions_path)
    
    assert service.cve_definitions is not None
    assert "WebServer" in service.cve_definitions
    assert "DatabaseServer" in service.cve_definitions # Check stripping of space
    assert service.cve_to_capec_map is not None
    assert "CVE-2021-44228" in service.cve_to_capec_map

def test_load_cve_definitions_file_not_found(tmp_path, caplog):
    """Test that a warning is logged if cve_definitions.yml is not found."""
    project_root = tmp_path
    cve_definitions_path = project_root / "cve_definitions.yml"
    caplog.set_level(logging.INFO)
    service = CVEService(project_root, cve_definitions_path)
    assert service.cve_definitions == {}
    assert "Default CVE definitions file not found" in caplog.text

def test_load_cve_definitions_invalid_yaml(tmp_path, caplog):
    """Test that an error is logged for an invalid YAML file."""
    project_root = tmp_path
    cve_definitions_path = project_root / "cve_definitions.yml"
    cve_definitions_path.write_text("WebServer: - CVE-2021-44228\n  - CVE-2023-1234") # Invalid indentation
    
    service = CVEService(project_root, cve_definitions_path, is_path_explicit=True)
    assert service.cve_definitions == {}
    assert "Error loading CVE definitions file" in caplog.text

def test_load_cve_to_capec_map_no_dir(tmp_path, caplog):
    """Test that a warning is logged if the cve2capec directory is missing."""
    project_root = tmp_path
    cve_definitions_path = project_root / "cve_definitions.yml"
    cve_definitions_path.touch() # Create empty file to avoid other warning
    service = CVEService(project_root, cve_definitions_path)
    assert service.cve_to_capec_map == {}
    assert "CVE2CAPEC database directory not found" in caplog.text

def test_load_cve_to_capec_map_with_prefix(mock_project_root):
    """Test that CAPEC IDs are correctly prefixed."""
    cve_definitions_path = mock_project_root / "cve_definitions.yml"
    service = CVEService(mock_project_root, cve_definitions_path)
    assert service.cve_to_capec_map["CVE-2021-44228"] == ["CAPEC-153", "CAPEC-242"]
    assert service.cve_to_capec_map["CVE-2022-5678"] == ["CAPEC-7"]

def test_get_capecs_for_cve(mock_project_root):
    """Test retrieving CAPECs for a given CVE."""
    cve_definitions_path = mock_project_root / "cve_definitions.yml"
    service = CVEService(mock_project_root, cve_definitions_path)
    assert service.get_capecs_for_cve("CVE-2021-44228") == ["CAPEC-153", "CAPEC-242"]
    assert service.get_capecs_for_cve("NON_EXISTENT_CVE") == []

def test_get_cves_for_equipment(mock_project_root):
    """Test retrieving CVEs for a given equipment name."""
    cve_definitions_path = mock_project_root / "cve_definitions.yml"
    service = CVEService(mock_project_root, cve_definitions_path)
    assert service.get_cves_for_equipment("WebServer") == ["CVE-2021-44228", "CVE-2023-1234"]
    assert service.get_cves_for_equipment("  DatabaseServer  ") == ["CVE-2022-5678"]
    assert service.get_cves_for_equipment("NonExistentEquipment") == []
