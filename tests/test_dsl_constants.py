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

from threat_analysis.core.dsl_constants import (
    DSL_ENUMS,
    PROTOCOL_STYLE_ATTRS,
    SEVERITY_MULTIPLIER_MIN,
    SEVERITY_MULTIPLIER_MAX,
)


def test_dsl_enums_has_required_keys():
    required = {
        "Boundary.type", "Boundary.traversal_difficulty",
        "Actor.authenticity",
        "Server.type", "Server.machine", "Server.classification",
        "Data.classification", "Data.credentialsLife",
        "Dataflow.authentication", "Dataflow.isEncrypted",
    }
    assert required <= DSL_ENUMS.keys()


def test_server_type_contains_core_pytm_types():
    core = {"firewall", "database", "web-server", "workstation", "default"}
    assert core <= set(DSL_ENUMS["Server.type"])


def test_server_type_contains_modern_types():
    modern = {"api_server", "microservice", "secrets_manager", "cache"}
    assert modern <= set(DSL_ENUMS["Server.type"])


def test_boundary_type_values():
    assert "execution-environment" in DSL_ENUMS["Boundary.type"]
    assert "network-on-prem" in DSL_ENUMS["Boundary.type"]


def test_bool_enums_contain_both_values():
    for key in ("Boundary.isTrusted", "Server.internet_facing", "Dataflow.isEncrypted"):
        assert True in DSL_ENUMS[key]
        assert False in DSL_ENUMS[key]


def test_protocol_style_attrs():
    assert "color" in PROTOCOL_STYLE_ATTRS
    assert "line_style" in PROTOCOL_STYLE_ATTRS


def test_severity_range():
    assert SEVERITY_MULTIPLIER_MIN == 0.0
    assert SEVERITY_MULTIPLIER_MAX == 5.0
