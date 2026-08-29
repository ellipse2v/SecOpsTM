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

import threading
import time
from unittest.mock import MagicMock, patch

import pytest

from threat_analysis.core.model_factory import create_threat_model, pytm_build_lock


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


def test_pytm_build_lock_serializes_concurrent_holders():
    """Two threads racing for the lock must never be inside the `with` block
    at the same time — the whole point of the lock."""
    concurrent_holders = []
    max_concurrent = [0]
    lock_for_counter = threading.Lock()

    def worker():
        with pytm_build_lock():
            with lock_for_counter:
                concurrent_holders.append(1)
                max_concurrent[0] = max(max_concurrent[0], sum(concurrent_holders))
            time.sleep(0.05)  # widen the window so a broken lock would show >1 holder
            with lock_for_counter:
                concurrent_holders.pop()

    threads = [threading.Thread(target=worker) for _ in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=5)

    assert max_concurrent[0] == 1


def test_pytm_build_lock_is_reentrant_for_same_thread():
    """The same thread must be able to nest `with pytm_build_lock():` blocks
    (e.g. an outer call site delegating to an inner one that also acquires the
    lock) without deadlocking."""
    entered_inner = []

    with pytm_build_lock():
        with pytm_build_lock():
            entered_inner.append(True)

    assert entered_inner == [True]


def test_pytm_build_lock_times_out_if_held_by_another_thread():
    """A thread that can't acquire the lock within the timeout gets a clear
    TimeoutError, not an indefinite hang."""
    release_event = threading.Event()
    entered_event = threading.Event()

    def holder():
        with pytm_build_lock():
            entered_event.set()
            release_event.wait(timeout=5)

    holder_thread = threading.Thread(target=holder)
    holder_thread.start()
    entered_event.wait(timeout=2)

    from threat_analysis.core import model_factory
    original_timeout = model_factory._PYTM_LOCK_TIMEOUT_S
    model_factory._PYTM_LOCK_TIMEOUT_S = 0.2
    try:
        with pytest.raises(TimeoutError):
            with pytm_build_lock():
                pass
    finally:
        model_factory._PYTM_LOCK_TIMEOUT_S = original_timeout
        release_event.set()
        holder_thread.join(timeout=5)
