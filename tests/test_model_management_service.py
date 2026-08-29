# Copyright 2025 ellipse2v
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may not use this file except in compliance with the License.
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
from unittest.mock import MagicMock, mock_open, patch
import json

from threat_analysis.server.model_management_service import ModelManagementService

@pytest.fixture
def model_management_service():
    cve_service = MagicMock()
    diagram_service = MagicMock()
    return ModelManagementService(cve_service, diagram_service)

def test_check_version_compatibility(model_management_service, tmp_path):
    # Create dummy files
    md_content = "# Version: 1.0\n# Version ID: 123\n"
    md_file = tmp_path / "model.md"
    md_file.write_text(md_content)

    meta_content = {"version": "1.0", "version_id": "123"}
    meta_file = tmp_path / "model_metadata.json"
    meta_file.write_text(json.dumps(meta_content))
    
    assert model_management_service.check_version_compatibility(str(md_file), str(meta_file)) is True

    # Test mismatch version
    meta_content_bad_version = {"version": "1.1", "version_id": "123"}
    meta_file_bad_version = tmp_path / "model_metadata_bad_version.json"
    meta_file_bad_version.write_text(json.dumps(meta_content_bad_version))
    assert model_management_service.check_version_compatibility(str(md_file), str(meta_file_bad_version)) is False

    # Test mismatch version id
    meta_content_bad_id = {"version": "1.0", "version_id": "456"}
    meta_file_bad_id = tmp_path / "model_metadata_bad_id.json"
    meta_file_bad_id.write_text(json.dumps(meta_content_bad_id))
    assert model_management_service.check_version_compatibility(str(md_file), str(meta_file_bad_id)) is False

def test_save_model_with_metadata_uses_pytm_build_lock(model_management_service, tmp_path, monkeypatch):
    """Regression guard: save_model_with_metadata() must serialize model building
    through pytm_build_lock(), not call create_threat_model() unprotected."""
    from threat_analysis.core import model_factory

    lock_calls = []
    original_lock = model_factory.pytm_build_lock

    def spy_lock():
        lock_calls.append(1)
        return original_lock()

    monkeypatch.setattr(
        "threat_analysis.server.model_management_service.pytm_build_lock", spy_lock
    )

    fake_threat_model = MagicMock()
    model_management_service.diagram_service._generate_positions_from_graphviz.return_value = {}
    with patch(
        "threat_analysis.server.model_management_service.create_threat_model",
        return_value=fake_threat_model,
    ) as mock_create:
        output_path = tmp_path / "model.md"
        model_management_service.save_model_with_metadata(
            "## Actors\n- User", str(output_path), positions_data=None
        )

    mock_create.assert_called_once()
    assert lock_calls, "pytm_build_lock() was never entered"
