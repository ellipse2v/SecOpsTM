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

"""References to undefined boundaries, elements or data must be reported, not dropped.

The parser used to detach or drop such elements silently: `secopstm validate`
rejected the model while the analysis and the web editor accepted it.
"""

from unittest.mock import MagicMock

from threat_analysis.core.cve_service import CVEService
from threat_analysis.core.model_factory import create_threat_model
from threat_analysis.core.model_validator import ModelValidator

BROKEN = """## Boundaries
- **DMZ**: isTrusted=True

## Actors
- **User**: boundary=Internet

## Servers
- **Web**: boundary=Nowhere
- **App**: boundary=DMZ

## Data
- **Creds**: classification="SECRET"

## Dataflows
- **X**: from="Ghost", to="Web", protocol="HTTPS"
- **Y**: from="User", to="Phantom", protocol="HTTPS"
- **Z**: from="User", to="App", protocol="HTTPS", data="Missing"
- **W**: to="App", protocol="HTTPS"
"""

VALID = """## Boundaries
- **Internet**: isTrusted=False
- **DMZ**: isTrusted=True

## Actors
- **User**: boundary=Internet

## Servers
- **App**: boundary=DMZ

## Data
- **Creds**: classification="SECRET"

## Dataflows
- **Login**: from="User", to="App", protocol="HTTPS", data="Creds"
"""


def _build(markdown, validate=False):
    return create_threat_model(
        markdown_content=markdown,
        model_name="T",
        model_description="",
        cve_service=MagicMock(spec=CVEService),
        validate=validate,
    )


def test_validator_reports_every_unresolved_reference():
    errors = ModelValidator(_build(BROKEN)).validate()
    assert "Actor 'User' refers to a non-existent boundary: 'Internet'." in errors
    assert "Server 'Web' refers to a non-existent boundary: 'Nowhere'." in errors
    assert "Dataflow 'X' refers to a non-existent 'from' element: 'Ghost'." in errors
    assert "Dataflow 'Y' refers to a non-existent 'to' element: 'Phantom'." in errors
    assert "Dataflow 'Z' refers to non-existent data: 'Missing'." in errors
    assert "Dataflow 'W' is missing mandatory parameters (from, to)." in errors


def test_validator_does_not_duplicate_errors_when_run_twice():
    model = _build(BROKEN)
    ModelValidator(model).validate()
    errors = ModelValidator(model).validate()
    assert len(errors) == len(set(errors))


def test_create_threat_model_with_validation_rejects_broken_model():
    assert _build(BROKEN, validate=True) is None


def test_valid_model_has_no_reference_errors():
    model = _build(VALID, validate=True)
    assert model is not None
    assert model.reference_errors == []


def test_nested_boundaries_are_parsed_as_their_own_boundaries():
    # A nested list item used to be swallowed as a continuation line of its
    # parent, so "Main" never existed and its servers lost their boundary.
    markdown = """## Boundaries
- **Infra**: isTrusted=True
  - **Main**: isTrusted=True
  - **Fallback**: isTrusted=False

## Actors
- **Operator**: boundary=Infra

## Servers
- **S1**: boundary=Main
- **S2**: boundary=Fallback

## Dataflows
- **F**: from="S1", to="S2", protocol="HTTPS"
- **G**: from="Operator", to="S1", protocol="SSH"
"""
    model = _build(markdown, validate=True)
    assert model is not None
    assert {"infra", "main", "fallback"} <= set(model.boundaries)
    main = model.boundaries["main"]["boundary"]
    assert main.inBoundary is model.boundaries["infra"]["boundary"]
    assert model.boundaries["fallback"]["isTrusted"] is False
    assert model.boundaries["infra"].get("isTrusted") is True
