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
from threat_analysis.core.mitre_mapping_module import MitreMapping

@pytest.fixture(scope="module")
def mitre_mapping_instance():
    """Fixture to initialize the MitreMapping class once per module."""
    # The constructor now requires a threat_model, but for these tests,
    # we can pass None as we are testing mapping logic, not model interaction.
    return MitreMapping(threat_model=None)

def test_mitre_mapping_initialization(mitre_mapping_instance):
    """Test that MitreMapping initializes correctly and loads its data maps."""
    assert mitre_mapping_instance is not None
    assert isinstance(mitre_mapping_instance.capec_to_mitre_map, dict)
    assert isinstance(mitre_mapping_instance.stride_to_capec, dict)
    assert isinstance(mitre_mapping_instance.all_attack_techniques, dict)
    assert len(mitre_mapping_instance.capec_to_mitre_map) > 0
    assert len(mitre_mapping_instance.stride_to_capec) > 0
    assert len(mitre_mapping_instance.all_attack_techniques) > 0

def test_map_threat_to_mitre_spoofing(mitre_mapping_instance):
    """Test the map_threat_to_mitre method for a Spoofing threat."""
    # This threat should map to CAPEC-98 (Phishing) and then to T1566.
    threat = {
        "description": "A phishing attack was performed.",
        "stride_category": "Spoofing"
    }
    mapping_results = mitre_mapping_instance.map_threat_to_mitre(threat)
    
    assert "techniques" in mapping_results
    assert "capecs" in mapping_results
    
    techniques = mapping_results['techniques']
    capecs = mapping_results['capecs']
    
    assert isinstance(techniques, list)
    assert isinstance(capecs, list)
    
    # Check if we have some results (the exact number can change)
    assert len(techniques) > 0
    assert len(capecs) > 0

    # Check for a specific expected technique
    technique_ids = [t['id'] for t in techniques]
    assert "T1566" in technique_ids

def test_map_threat_to_mitre_caps_capecs_without_explicit_ids(mitre_mapping_instance):
    """A threat with no explicit capec_ids must not get the entire STRIDE-category CAPEC
    bucket (Tampering alone has ~149 entries) — only the ones relevant to its description,
    capped at _CAPEC_RELEVANCE_MAX.
    """
    full_bucket_size = len(mitre_mapping_instance.stride_to_capec.get("Tampering", []))
    assert full_bucket_size > MitreMapping._CAPEC_RELEVANCE_MAX, "fixture data too small to exercise the cap"

    threat = {
        "description": "Untrusted actor may attempt to inject malicious data.",
        "stride_category": "Tampering",
    }
    mapping_results = mitre_mapping_instance.map_threat_to_mitre(threat)
    capecs = mapping_results["capecs"]

    assert 0 < len(capecs) <= MitreMapping._CAPEC_RELEVANCE_MAX
    assert len(capecs) < full_bucket_size


def test_rank_capecs_by_relevance_prefers_keyword_overlap():
    """Ranking must prefer CAPECs whose own description shares words with the threat
    description, not just return the list truncated in its original order.
    """
    capec_list = [
        {"capec_id": "CAPEC-1", "description": "Buffer Overflow via Environment Variables"},
        {"capec_id": "CAPEC-2", "description": "Injection of malicious data into network traffic"},
        {"capec_id": "CAPEC-3", "description": "Unrelated pattern about physical access"},
    ]
    ranked = MitreMapping._rank_capecs_by_relevance(
        "An attacker may inject malicious data over the network.", capec_list, max_results=1
    )
    assert ranked == [capec_list[1]]


def test_get_stride_categories(mitre_mapping_instance):
    """Test the get_stride_categories method."""
    categories = mitre_mapping_instance.get_stride_categories()
    assert isinstance(categories, list)
    assert len(categories) > 0
    assert "Spoofing" in categories
    assert "Information Disclosure" in categories
