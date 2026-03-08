
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
from pathlib import Path
from threat_analysis.utils import (
    _validate_path_within_project, 
    extract_json_from_llm_response, 
    resolve_path
)

# Define project root for testing purposes
PROJECT_ROOT = Path(__file__).resolve().parents[1]


def test_validate_path_within_project_valid():
    # Create a dummy file inside the project for testing
    dummy_file = PROJECT_ROOT / "dummy_file_test.txt"
    dummy_file.touch()

    try:
        validated_path = _validate_path_within_project(str(dummy_file), base_dir=PROJECT_ROOT)
        assert validated_path == dummy_file
    finally:
        # Clean up the dummy file
        if dummy_file.exists():
            dummy_file.unlink()


def test_validate_path_does_not_exist():
    non_existent_file = PROJECT_ROOT / "non_existent_file_test.txt"
    with pytest.raises(ValueError, match="Path does not exist"):
        _validate_path_within_project(str(non_existent_file), base_dir=PROJECT_ROOT)


def test_validate_path_outside_project():
    # Create a dummy file outside the project for testing
    outside_file = Path("/tmp/outside_file_test.txt")
    outside_file.touch()

    try:
        with pytest.raises(ValueError, match="Path is outside the allowed project directory"):
            _validate_path_within_project(str(outside_file), base_dir=PROJECT_ROOT)
    finally:
        # Clean up the dummy file
        if outside_file.exists():
            outside_file.unlink()

def test_extract_json_from_llm_response():
    # Valid JSON in code fences
    text = "Here is the JSON: ```json\n{\"key\": \"value\"}\n```"
    assert extract_json_from_llm_response(text) == "{\"key\": \"value\"}"

    # Valid JSON in code fences (no language)
    text = "```\n[1, 2, 3]\n```"
    assert extract_json_from_llm_response(text) == "[1, 2, 3]"

    # Invalid JSON in fences, but valid JSON outside
    text = "```json\ninvalid\n``` But here is valid: {\"a\": 1}"
    assert extract_json_from_llm_response(text) == "{\"a\": 1}"

    # Raw JSON object
    text = "Prose before {\"key\": \"value\"} prose after"
    assert extract_json_from_llm_response(text) == "{\"key\": \"value\"}"

    # Raw JSON array
    text = "List: [1, 2, 3] end."
    assert extract_json_from_llm_response(text) == "[1, 2, 3]"

    # Nested brackets/braces
    text = "Nested: {\"a\": [1, 2], \"b\": {\"c\": 3}}."
    assert extract_json_from_llm_response(text) == "{\"a\": [1, 2], \"b\": {\"c\": 3}}"

    # Array priority
    text = "[1, 2] and { \"a\": 1 }"
    assert extract_json_from_llm_response(text) == "[1, 2]"

    # No JSON found
    assert extract_json_from_llm_response("Just plain text.") is None

    # Unmatched brackets
    assert extract_json_from_llm_response("Found [ but no end.") is None
    
    # Invalid JSON string
    assert extract_json_from_llm_response("{ not json }") is None

def test_resolve_path():
    base_dir = Path("/tmp/base")
    default_name = "default.txt"
    
    # Explicit path
    path, explicit = resolve_path("explicit.txt", base_dir, default_name)
    assert path == Path("explicit.txt")
    assert explicit is True
    
    # Default path
    path, explicit = resolve_path(None, base_dir, default_name)
    assert path == base_dir / default_name
    assert explicit is False
