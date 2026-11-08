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

"""THREAT_RULES against a model built by the real DSL parser.

The MagicMock-based tests in test_custom_threats.py answer any attribute, so they could not
catch rules whose conditions never resolve on real pytm objects (sink.type, DataSet, ...).
"""

import pytest

from threat_analysis.core.model_parser import ModelParser
from threat_analysis.core.models_module import ThreatModel
from threat_analysis.core.stride_constants import STRIDE_CATEGORIES
from threat_analysis.custom_threats import RuleBasedThreatGenerator, get_custom_threats
from threat_analysis.threat_rules import THREAT_RULES

# One component per rule condition. Types use '_' on purpose where rules use '-'.
FIXTURE_DSL = """# System Model: Rule Coverage

## Boundaries
- **DMZ**: isTrusted=False
- **Internal**: isTrusted=True

## Actors
- **Attacker**: authenticity=credentials, isTrusted=False
- **Operator**: boundary="Internal", authenticity=two-factor, isTrusted=True

## Servers
- **Edge LB**: boundary="DMZ", type="load_balancer"
- **Edge Firewall**: boundary="DMZ", type=firewall, waf=False, ids=False
- **Public API**: boundary="DMZ", type="api_gateway"
- **Jump Host**: boundary="DMZ", type=bastion
- **Core Switch**: boundary="DMZ", type=switch
- **Assets Bucket**: boundary="DMZ", type=s3-bucket, is_public=True
- **Image Registry**: boundary="DMZ", type="docker_registry"
- **Orders DB**: boundary="Internal", type=database, database_type=sql, encryption=none, confidentiality=critical, redundant=False, availability=critical
- **Login Service**: boundary="Internal", type=auth-server, mfa_enabled=False, auth_protocol=ldap, machine=container
- **Directory**: boundary="Internal", type="domain_controller"
- **Admin Console**: boundary="Internal", type=management-server, can_pivot=True, has_management_interface=True, is_public=True, machine=serverless
- **Source Repo**: boundary="Internal", type=git-repo
- **Sensor**: boundary="Internal", type=iot-device
- **Billing App**: boundary="Internal", type=app-service
- **Shipping App**: boundary="Internal", type=app-service

## Data
- **DB Password**: type=credentials, classification=SECRET
- **Signing Key**: type=secret, classification=TOP_SECRET

## Dataflows
- **Internet To Edge**: from="Attacker", to="Edge LB", protocol=HTTP, authentication=none
- **Edge To DB**: from="Edge LB", to="Orders DB", protocol=FTP, data="DB Password", authentication=none, authorization=none, readonly=False, vpn=False, ip_filtered=False
- **Repo To Registry**: from="Source Repo", to="Image Registry", protocol=HTTPS, data="Signing Key"
- **Sensor To Billing**: from="Sensor", to="Billing App", protocol=MQTT
- **Billing To Shipping**: from="Billing App", to="Shipping App", protocol=HTTP
- **Shipping To DB**: from="Shipping App", to="Orders DB", protocol=TCP, authentication=credentials, is_encrypted=False
- **Operator To Console**: from="Operator", to="Admin Console", protocol=SSH, authentication=two-factor, is_encrypted=True
- **Console To Directory**: from="Admin Console", to="Directory", protocol=HTTPS, authentication=token, is_encrypted=True
"""

_SECTIONS = {"servers": "servers", "dataflows": "dataflows", "actors": "actors"}


@pytest.fixture(scope="module")
def model() -> ThreatModel:
    tm = ThreatModel("Rule Coverage", "THREAT_RULES coverage fixture")
    ModelParser(tm, tm.mitre_mapper).parse_markdown(FIXTURE_DSL)
    return tm


def _flow(tm: ThreatModel, name: str):
    return next(f for f in tm.dataflows if f.name == name)


def _rule_ids():
    return [
        (section, i)
        for section, rules in THREAT_RULES.items()
        for i, rule in enumerate(rules)
    ]


@pytest.mark.parametrize("section,index", _rule_ids(), ids=lambda v: str(v))
def test_every_rule_fires_on_the_fixture(model, section, index):
    rule = THREAT_RULES[section][index]
    generator = RuleBasedThreatGenerator(model)
    components = getattr(model, _SECTIONS[section])
    assert any(generator._matches(c, rule["conditions"]) for c in components), (
        f"{section}[{index}] {rule['conditions']} matches no component of the fixture"
    )


@pytest.mark.parametrize("section,index", _rule_ids(), ids=lambda v: str(v))
def test_every_rule_uses_a_stride_category(section, index):
    # A non-STRIDE category is dropped by ThreatModel._group_threats() (Kerberoasting was).
    for threat in THREAT_RULES[section][index]["threats"]:
        assert threat["stride_category"] in STRIDE_CATEGORIES


def test_sink_type_resolves_from_the_server_props(model):
    generator = RuleBasedThreatGenerator(model)
    assert generator._matches(_flow(model, "Edge To DB"), {"sink.type": "database"})
    assert not generator._matches(_flow(model, "Sensor To Billing"), {"sink.type": "database"})


def test_source_boundary_trust_resolves(model):
    generator = RuleBasedThreatGenerator(model)
    flow = _flow(model, "Edge To DB")
    assert generator._matches(flow, {"source.boundary.isTrusted": False, "sink.boundary.isTrusted": True})


def test_underscore_and_hyphen_types_are_equivalent(model):
    generator = RuleBasedThreatGenerator(model)
    lb = next(s for s in model.servers if s["name"] == "Edge LB")
    assert generator._matches(lb, {"type": "load-balancer"})


def test_sensitive_data_is_read_from_the_dataset(model):
    generator = RuleBasedThreatGenerator(model)
    assert generator._matches(_flow(model, "Edge To DB"), {"contains_sensitive_data": True})
    assert generator._matches(_flow(model, "Sensor To Billing"), {"contains_sensitive_data": False})


def test_declared_authentication_counts_as_authenticated(model):
    generator = RuleBasedThreatGenerator(model)
    assert generator._matches(_flow(model, "Shipping To DB"), {"is_authenticated": True})
    assert generator._matches(_flow(model, "Internet To Edge"), {"is_authenticated": False})
    assert generator._matches(_flow(model, "Sensor To Billing"), {"is_authenticated": False})


def _spoofing_threats(model, flow_name):
    return [
        t["description"] for t in get_custom_threats(model)
        if t["component"] == flow_name and t["stride_category"] == "Spoofing"
    ]


def test_weak_authentication_keeps_a_spoofing_threat(model):
    # Declaring an authentication method drops "lack of authentication", but a
    # single-factor or token flow can still be spoofed with stolen secrets.
    assert any("single-factor" in d for d in _spoofing_threats(model, "Shipping To DB"))
    assert any("token" in d for d in _spoofing_threats(model, "Console To Directory"))
    assert not any("lack of authentication" in d for d in _spoofing_threats(model, "Shipping To DB"))


def test_two_factor_flow_has_no_spoofing_threat(model):
    assert _spoofing_threats(model, "Operator To Console") == []


def test_kerberoasting_survives_grouping(model):
    model.threats_raw = model._apply_custom_threats()
    grouped = [t for threats in model._group_threats().values() for t, _ in threats]
    assert any("Kerberoasting" in getattr(t, "description", "") for t in grouped)


def test_unauthenticated_database_flow_threat_is_generated(model):
    threats = get_custom_threats(model)
    assert any(
        t["component"] == "Edge To DB" and "Unauthenticated data flow" in t["description"]
        for t in threats
    )
    assert not any(
        t["component"] == "Shipping To DB" and "Unauthenticated data flow" in t["description"]
        for t in threats
    )
