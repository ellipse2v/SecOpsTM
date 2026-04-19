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
from threat_analysis.server.threat_model_service import ThreatModelService
from unittest.mock import MagicMock, mock_open, patch
from datetime import datetime
from typing import List, Dict, Any

@pytest.fixture
def service():
    return ThreatModelService()

def test_get_element_name(service):
    # Test with an object having a name attribute
    element_with_name = MagicMock()
    element_with_name.name = "TestElement"
    assert service._get_element_name(element_with_name) == "TestElement"

    # Test with a dictionary having a 'name' key
    element_dict = {"name": "TestDict"}
    assert service._get_element_name(element_dict) == "TestDict"

    # Test with a string
    element_str = "TestString"
    assert service._get_element_name(element_str) == "TestString"

    # Test with an unknown type
    element_unknown = 123
    assert service._get_element_name(element_unknown) == "Unknown"

def test_check_version_compatibility(service):
    # Test with matching versions
    markdown_content = "# Version: 1.0\n# Version ID: 123"
    metadata_content = '{"version": "1.0", "version_id": "123"}'
    
    mock_file = mock_open()
    mock_file.side_effect = [
        mock_open(read_data=markdown_content).return_value,
        mock_open(read_data=metadata_content).return_value
    ]
    with patch("builtins.open", mock_file):
        assert service.check_version_compatibility("md.md", "meta.json") is True

    # Test with mismatching versions
    metadata_content_mismatch = '{"version": "1.1", "version_id": "123"}'
    mock_file.side_effect = [
        mock_open(read_data=markdown_content).return_value,
        mock_open(read_data=metadata_content_mismatch).return_value
    ]
    with patch("builtins.open", mock_file):
        assert service.check_version_compatibility("md.md", "meta.json") is False

    # Test with file not found
    with patch("builtins.open", side_effect=FileNotFoundError):
        assert service.check_version_compatibility("md.md", "meta.json") is False

@patch("builtins.open", new_callable=mock_open)
@patch("threat_analysis.server.diagram_service.DiagramService._generate_positions_from_graphviz")
@patch("threat_analysis.server.model_management_service.create_threat_model")
def test_save_model_with_metadata(mock_create_tm, mock_generate_positions, mock_file, service):
    mock_create_tm.return_value = MagicMock()

    # Scenario 1: with provided positions
    # Note: call_count is not asserted here because the cve-warmup daemon thread
    # started in ThreatModelService.__init__ may open JSONL files concurrently
    # while builtins.open is mocked, making the count non-deterministic.
    with patch('datetime.datetime') as mock_dt:
        mock_dt.now.return_value = datetime(2026, 2, 19, 22, 37, 5)
        service.save_model_with_metadata("markdown", "out.md", {"pos": 1})

        mock_file.assert_any_call("out.md", "w", encoding="utf-8")
        mock_file.assert_any_call("out_metadata.json", "w")

    # Reset mocks
    mock_file.reset_mock()
    mock_generate_positions.reset_mock()
    mock_create_tm.reset_mock()

    # Scenario 2: with fallback to generate positions
    mock_generate_positions.return_value = {"pos": 2}
    service.save_model_with_metadata("markdown", "out.md")

    mock_file.assert_any_call("out.md", "w", encoding="utf-8")
    mock_file.assert_any_call("out_metadata.json", "w")
    mock_generate_positions.assert_called_once()

def test_merge_with_ui_positions(service):
    base_positions = {
        "boundaries": {"b1": {"x": 0, "y": 0}},
        "actors": {"a1": {"x": 0, "y": 0}},
        "servers": {"s1": {"x": 0, "y": 0}},
        "dataflows": {"d1": {"points": []}}
    }
    ui_positions = {
        "boundaries": {"b1": {"x": 1, "y": 1}},
        "actors": {"a1": {"x": 1, "y": 1}},
        "servers": {"s1": {"x": 1, "y": 1}},
        "dataflows": {"d1": {"points": [1,1]}}
    }
    merged = service._merge_with_ui_positions(base_positions, ui_positions)
    assert merged["boundaries"]["b1"]["x"] == 1
    assert merged["actors"]["a1"]["x"] == 1
    assert merged["servers"]["s1"]["x"] == 1
    assert merged["dataflows"]["d1"]["points"] == [1,1]

@patch("threat_analysis.server.diagram_service.create_threat_model")
def test_markdown_to_json_for_gui(mock_create_threat_model, service):
    mock_boundary = MagicMock()
    mock_boundary.name = "b1"
    mock_actor = MagicMock()
    mock_actor.name = "a1"
    mock_server = MagicMock()
    mock_server.name = "s1"
    mock_data = MagicMock()
    mock_data.name = "d1"
    mock_dataflow = MagicMock()
    mock_dataflow.name = "df1"
    mock_dataflow.source = mock_actor
    mock_dataflow.sink = mock_server
    mock_dataflow.data = [mock_data]

    mock_threat_model = MagicMock()
    mock_threat_model.boundaries = {"b1": {"boundary": mock_boundary}}
    mock_threat_model.actors = [{"name": "a1", "object": mock_actor}]
    mock_threat_model.servers = [{"name": "s1", "object": mock_server}]
    mock_threat_model.data_objects = {"d1": mock_data}
    mock_threat_model.dataflows = [mock_dataflow]

    mock_create_threat_model.return_value = mock_threat_model

    result = service.markdown_to_json_for_gui("markdown")
    assert len(result["boundaries"]) == 1
    assert result["boundaries"][0]["name"] == "b1"
    assert len(result["actors"]) == 1
    assert result["actors"][0]["name"] == "a1"
    assert len(result["servers"]) == 1
    assert result["servers"][0]["name"] == "s1"
    assert len(result["data"]) == 1
    assert result["data"][0]["name"] == "d1"
    assert len(result["dataflows"]) == 1
    assert result["dataflows"][0]["from"] == "a1"

import glob
import os

@patch("os.path.isdir", return_value=True)
@patch("glob.glob")
@patch("builtins.open", new_callable=mock_open, read_data="content")
def test_load_project_with_files(mock_open, mock_glob, mock_isdir, service):
    mock_glob.side_effect = [
        ["/path/to/project/main.md"],
        ["/path/to/project/sub/model.md"]
    ]
    with patch("os.path.relpath", side_effect=lambda path, start: path.replace(start, "").lstrip("/")):
        result = service.load_project("/path/to/project")
        # In the real implementation, glob.glob(..., recursive=True) returns all files at once.
        # But here side_effect is used. Let's adjust to match real glob behavior if possible or just mock it simply.
        # Current service.load_project uses glob.glob once.
        pass

@patch("os.path.isdir", return_value=True)
@patch("glob.glob")
@patch("builtins.open", new_callable=mock_open, read_data="content")
def test_load_project_with_files_v2(mock_open, mock_glob, mock_isdir, service):
    mock_glob.return_value = ["/path/to/project/main.md", "/path/to/project/sub/model.md"]
    
    def mock_relpath(path, start):
        return path.replace(start, "").lstrip("/")
        
    with patch("os.path.relpath", side_effect=mock_relpath):
        result = service.load_project("/path/to/project")
        assert len(result) == 2
        paths = [r["path"] for r in result]
        assert "main.md" in paths
        assert "sub/model.md" in paths

@patch("os.path.isdir", return_value=True)
@patch("glob.glob", return_value=[])
def test_load_project_no_files(mock_glob, mock_isdir, service):
    result = service.load_project("/path/to")
    assert len(result) == 1
    assert result[0]["path"] == "main.md"

@patch("os.path.isdir", return_value=False)
def test_load_project_no_project_dir(mock_isdir, service):
    result = service.load_project("/path/to/nonexistent")
    assert len(result) == 1
    assert "Project path not found" in result[0]["content"]

def test_resolve_submodels(service):
    main_model_content = 'sub_model_path="sub1.md"'
    project_files = [
        {"path": "sub1.md", "content": 'sub_model_path="sub2.md"'},
        {"path": "sub2.md", "content": "no more submodels"}
    ]
    result = service.resolve_submodels(main_model_content, project_files)
    assert len(result) >= 2
    paths = [r["path"] for r in result]
    assert "sub1.md" in paths
    assert "sub2.md" in paths

    project_files_missing = [
        {"path": "sub2.md", "content": "no more submodels"}
    ]
    result = service.resolve_submodels(main_model_content, project_files_missing)
    assert len(result) == 0
