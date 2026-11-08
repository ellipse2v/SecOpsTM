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

"""A dataflow without is_encrypted takes it from its protocol (protocols_community.yaml).

72 template flows over HTTPS, TLS, SSH or mTLS used to get "Data interception on an
unencrypted channel" because they did not repeat is_encrypted=True.
"""

import pytest

from threat_analysis.core.asset_technique_mapper import protocol_is_encrypted
from threat_analysis.core.model_parser import ModelParser
from threat_analysis.core.models_module import ThreatModel
from threat_analysis.custom_threats import get_custom_threats


@pytest.mark.parametrize("protocol", [
    "HTTPS", "https", "SSH", "IPSEC", "WSS", "HTTPS/mTLS", "PostgreSQL/TLS",
    "Encrypted TLS", "gRPC/mTLS", "Redis/TLS", "HTTPS/SSH",
])
def test_encrypted_protocols(protocol):
    assert protocol_is_encrypted(protocol)


@pytest.mark.parametrize("protocol", [
    None, "", "HTTP", "TCP", "FTP", "MQTT", "HTTP/S", "HTTPS/MQTT", "HTTP/gRPC",
    "Internal API", "Kafka/SASL", "kerberos",
])
def test_unencrypted_or_unknown_protocols(protocol):
    assert not protocol_is_encrypted(protocol)


DSL = """# System Model: Encryption

## Boundaries
- **Zone**: isTrusted=True

## Servers
- **A**: boundary="Zone"
- **B**: boundary="Zone"

## Dataflows
- **Implicit HTTPS**: from="A", to="B", protocol=HTTPS
- **Implicit HTTP**: from="A", to="B", protocol=HTTP
- **Declared Off**: from="A", to="B", protocol=HTTPS, is_encrypted=False
- **Declared On**: from="A", to="B", protocol=TCP, is_encrypted=True
"""


@pytest.fixture(scope="module")
def model() -> ThreatModel:
    tm = ThreatModel("Encryption", "protocol encryption fixture")
    ModelParser(tm, tm.mitre_mapper).parse_markdown(DSL)
    return tm


@pytest.mark.parametrize("flow,expected", [
    ("Implicit HTTPS", True),
    ("Implicit HTTP", False),
    ("Declared Off", False),  # an explicit value always wins
    ("Declared On", True),
])
def test_dataflow_encryption(model, flow, expected):
    assert next(f for f in model.dataflows if f.name == flow).is_encrypted is expected


def test_https_flow_gets_no_interception_threat(model):
    intercepted = {
        t["component"] for t in get_custom_threats(model)
        if "unencrypted channel" in t["description"]
    }
    assert intercepted == {"Implicit HTTP", "Declared Off"}
