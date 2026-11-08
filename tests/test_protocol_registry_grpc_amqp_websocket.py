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

"""Checks that gRPC, AMQP and WebSocket are registered in protocols_community.yaml."""

import re
from pathlib import Path

import pytest
import yaml

REGISTRY = Path(__file__).resolve().parent.parent / "threat_analysis" / "config" / "protocols_community.yaml"
NEW_PROTOCOLS = ["grpc", "amqp", "websocket"]


@pytest.fixture(scope="module")
def protocols():
    data = yaml.safe_load(REGISTRY.read_text(encoding="utf-8"))
    return data["protocols"]


@pytest.mark.parametrize("name", NEW_PROTOCOLS)
def test_new_protocol_entry_is_well_formed(protocols, name):
    assert name in protocols, f"protocol {name!r} missing from registry"
    entry = protocols[name]
    assert entry["tactic_boost"], f"{name}: tactic_boost must not be empty"
    for tactic in entry["tactic_boost"]:
        assert re.fullmatch(r"[a-z]+(-[a-z]+)*", tactic), f"{name}: tactic {tactic!r} not kebab-case"
    for tech in entry["key_techniques"]:
        assert re.fullmatch(r"T\d{4}(\.\d{3})?", tech), f"{name}: technique {tech!r} malformed"


def test_registry_keys_are_lowercase(protocols):
    """Keys are lowercase; the mapper lowercases the dataflow protocol before lookup."""
    assert [k for k in protocols if k != k.lower()] == []


@pytest.mark.parametrize("svc", ["gRPC", "grpc", "AMQP", "WebSocket", "websocket"])
def test_mixed_case_dataflow_protocol_matches_registry_entry(protocols, svc):
    """A dataflow protocol="gRPC" (or any case) must match the 'grpc' registry entry."""
    from unittest.mock import patch

    from threat_analysis.core.asset_technique_mapper import AssetTechniqueMapper

    with patch.object(AssetTechniqueMapper, "_load_protocols", return_value=protocols):
        result = AssetTechniqueMapper().get_techniques("database", {}, top_k=50, services={svc})
    reasons = [t.rationale for t in result]
    tokens = {tok for r in reasons for tok in r.split(", ")}
    assert tokens & {f"service:{svc}", f"key-tech:{svc}"}, \
        f"no service boost applied to protocol {svc!r}"
