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

"""Tests for threat_analysis/core/model_factory.py"""

from unittest.mock import MagicMock, patch

import pytest

from threat_analysis.core.model_factory import create_threat_model


@pytest.fixture
def cve_service():
    return MagicMock()


@patch('threat_analysis.core.model_factory.ModelValidator')
@patch('threat_analysis.core.model_factory.ModelParser')
@patch('threat_analysis.core.model_factory.ThreatModel')
def test_create_threat_model_success_without_validation(mock_tm_cls, mock_parser_cls, mock_validator_cls, cve_service):
    mock_tm = MagicMock()
    mock_tm_cls.return_value = mock_tm

    result = create_threat_model(
        markdown_content="# System Model: X\n", model_name="X",
        model_description="desc", cve_service=cve_service, validate=False,
    )

    assert result is mock_tm
    mock_parser_cls.return_value.parse_markdown.assert_called_once_with("# System Model: X\n")
    mock_validator_cls.assert_not_called()


@patch('threat_analysis.core.model_factory.ModelValidator')
@patch('threat_analysis.core.model_factory.ModelParser')
@patch('threat_analysis.core.model_factory.ThreatModel')
def test_create_threat_model_success_with_validation_passing(mock_tm_cls, mock_parser_cls, mock_validator_cls, cve_service):
    mock_tm = MagicMock()
    mock_tm_cls.return_value = mock_tm
    mock_validator_cls.return_value.validate.return_value = []

    result = create_threat_model(
        markdown_content="# System Model: X\n", model_name="X",
        model_description="desc", cve_service=cve_service, validate=True,
    )

    assert result is mock_tm
    mock_validator_cls.return_value.validate.assert_called_once()


@patch('threat_analysis.core.model_factory.ModelValidator')
@patch('threat_analysis.core.model_factory.ModelParser')
@patch('threat_analysis.core.model_factory.ThreatModel')
def test_create_threat_model_validation_failure_returns_none(mock_tm_cls, mock_parser_cls, mock_validator_cls, cve_service):
    mock_tm_cls.return_value = MagicMock()
    mock_validator_cls.return_value.validate.return_value = ["Dataflow points to unknown element"]

    result = create_threat_model(
        markdown_content="# System Model: X\n", model_name="X",
        model_description="desc", cve_service=cve_service, validate=True,
    )

    assert result is None


@patch('threat_analysis.core.model_factory.ModelParser')
@patch('threat_analysis.core.model_factory.ThreatModel')
def test_create_threat_model_parse_exception_returns_none(mock_tm_cls, mock_parser_cls, cve_service):
    mock_tm_cls.return_value = MagicMock()
    mock_parser_cls.return_value.parse_markdown.side_effect = RuntimeError("malformed DSL")

    result = create_threat_model(
        markdown_content="not valid", model_name="X",
        model_description="desc", cve_service=cve_service, validate=False,
    )

    assert result is None


@patch('threat_analysis.core.model_factory.ModelValidator')
@patch('threat_analysis.core.model_factory.ModelParser')
@patch('threat_analysis.core.model_factory.ThreatModel')
def test_create_threat_model_sets_model_file_path_when_given(mock_tm_cls, mock_parser_cls, mock_validator_cls, cve_service):
    mock_tm = MagicMock()
    mock_tm_cls.return_value = mock_tm

    create_threat_model(
        markdown_content="# System Model: X\n", model_name="X",
        model_description="desc", cve_service=cve_service, validate=False,
        model_file_path="/path/to/model.md",
    )

    assert mock_tm._model_file_path == "/path/to/model.md"


@patch('threat_analysis.core.model_factory.ModelValidator')
@patch('threat_analysis.core.model_factory.ModelParser')
@patch('threat_analysis.core.model_factory.ThreatModel')
def test_create_threat_model_constructs_with_given_name_description_and_cve_service(
    mock_tm_cls, mock_parser_cls, mock_validator_cls, cve_service
):
    create_threat_model(
        markdown_content="# System Model: X\n", model_name="MyModel",
        model_description="My description", cve_service=cve_service, validate=False,
    )

    mock_tm_cls.assert_called_once_with("MyModel", "My description", cve_service=cve_service)
