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

from threat_analysis.core.ai_threat_grounding import score_grounding, _CONF_GRID


def _details(**over):
    d = {
        "name": "web-01",
        "technology_tags": "apache, centos",
        "security_controls": "WAF: No | IDS: No | MFA: No | Encryption at rest: unknown",
        "inbound_flows": "  - user -> web-01 [HTTPS]",
        "outbound_flows": "  - web-01 -> db-01 [SQL]",
        "is_public": True,
        "trust_boundary": "DMZ (UNTRUSTED)",
    }
    d.update(over)
    return d


def test_confidence_is_always_on_the_grid():
    for signals, flags in [(0, 0), (5, 0), (0, 3), (2, 1)]:
        t = {"category": "Tampering" if signals else "nonsense",
             "description": " ".join(["waf", "https"][:signals]),
             "title": "CVE-2021-44228 " * flags}
        assert score_grounding(t, _details()).confidence in _CONF_GRID


def test_cve_citation_in_stride_threat_is_flagged():
    t = {"category": "Elevation of Privilege", "title": "RCE via CVE-2021-44228 in the logging lib",
         "description": "Attacker exploits CVE-2021-44228", "attack_scenario": ""}
    r = score_grounding(t, _details())
    assert any("CVE-2021-44228" in f for f in r.flags)


def test_cross_domain_tech_mismatch_is_flagged():
    t = {"category": "Elevation of Privilege",
         "title": "Kubernetes RBAC misconfiguration allows pod escalation",
         "description": "The kubelet exposes an unauthenticated API", "attack_scenario": ""}
    r = score_grounding(t, _details(technology_tags="apache, centos"))
    assert any("kubernetes" in f.lower() for f in r.flags)


def test_no_mismatch_flag_when_tags_are_na():
    t = {"category": "Tampering", "title": "Kubernetes API abuse", "description": "kubectl proxy", "attack_scenario": ""}
    r = score_grounding(t, _details(technology_tags="N/A"))
    assert not any("kubernetes" in f.lower() for f in r.flags)


def test_control_gap_and_protocol_are_signals():
    t = {
        "category": "Spoofing",
        "title": "Auth bypass on the HTTPS login endpoint",
        "description": "No WAF in front, so payloads reach the app directly over HTTPS",
        "attack_scenario": "1. connect 2. bypass 3. done",
        "capec_ids": ["CAPEC-115"],
    }
    r = score_grounding(t, _details())
    assert "valid STRIDE category" in r.signals
    assert "cites a CAPEC id" in r.signals
    assert any("control gap (waf)" in s for s in r.signals)
    assert "uses a real connected protocol" in r.signals
    assert r.confidence >= 0.7
    assert r.flags == []


def test_flags_drag_confidence_below_signals():
    grounded_but_hallucinated = {
        "category": "Tampering",
        "title": "Tamper via CVE-2020-1472 and CVE-2021-34527 over HTTPS with no WAF",
        "description": "waf https",
        "attack_scenario": "",
    }
    r = score_grounding(grounded_but_hallucinated, _details())
    assert len(r.flags) == 2
    assert r.confidence <= 0.5
