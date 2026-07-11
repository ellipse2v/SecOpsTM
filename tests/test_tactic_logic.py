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

"""Tests for threat_analysis/generation/tactic_logic.py

TACTIC_PROGRESSION and TACTIC_INFO are consumed together by
AttackFlowGenerator._build_tactic_phase_map(), which looks up each
TACTIC_PROGRESSION slug in TACTIC_INFO's values(). A slug present in one but not
the other is not an error — that tactic is just silently dropped from the phase
map and never appears in a generated attack path. These tests guard the
cross-consistency between the two structures.
"""

from threat_analysis.generation.tactic_logic import TACTIC_PROGRESSION, TACTIC_INFO


def test_tactic_progression_is_a_list_of_lists():
    assert isinstance(TACTIC_PROGRESSION, list)
    assert all(isinstance(phase, list) for phase in TACTIC_PROGRESSION)
    assert all(phase for phase in TACTIC_PROGRESSION)  # no empty phases


def test_tactic_info_has_slug_and_id_for_every_entry():
    for tactic_name, info in TACTIC_INFO.items():
        assert "slug" in info, f"{tactic_name} missing 'slug'"
        assert "id" in info, f"{tactic_name} missing 'id'"
        assert info["id"].startswith("TA"), f"{tactic_name} has a non-MITRE-looking id: {info['id']}"


def test_every_progression_slug_has_a_matching_tactic_info_entry():
    """The core cross-consistency invariant _build_tactic_phase_map() relies on."""
    known_slugs = {info["slug"] for info in TACTIC_INFO.values()}
    progression_slugs = {slug for phase in TACTIC_PROGRESSION for slug in phase}
    missing = progression_slugs - known_slugs
    assert not missing, f"TACTIC_PROGRESSION references slugs with no TACTIC_INFO entry: {missing}"


def test_every_tactic_info_slug_appears_somewhere_in_progression():
    """The reverse direction — a TACTIC_INFO entry never referenced by
    TACTIC_PROGRESSION means that tactic can never be placed in a generated path.
    """
    known_slugs = {info["slug"] for info in TACTIC_INFO.values()}
    progression_slugs = {slug for phase in TACTIC_PROGRESSION for slug in phase}
    unused = known_slugs - progression_slugs
    assert not unused, f"TACTIC_INFO entries never referenced by TACTIC_PROGRESSION: {unused}"


def test_all_twelve_standard_mitre_tactics_present():
    assert len(TACTIC_INFO) == 12


def test_tactic_ids_match_known_mitre_values():
    """Canary against typos — these IDs are fixed, official MITRE ATT&CK identifiers."""
    expected = {
        "Initial Access": "TA0001",
        "Execution": "TA0002",
        "Persistence": "TA0003",
        "Privilege Escalation": "TA0004",
        "Defense Evasion": "TA0005",
        "Credential Access": "TA0006",
        "Discovery": "TA0007",
        "Lateral Movement": "TA0008",
        "Collection": "TA0009",
        "Exfiltration": "TA0010",
        "Command and Control": "TA0011",
        "Impact": "TA0040",
    }
    for tactic_name, tactic_id in expected.items():
        assert TACTIC_INFO[tactic_name]["id"] == tactic_id


def test_progression_slugs_have_no_duplicates_within_a_single_phase():
    for phase in TACTIC_PROGRESSION:
        assert len(phase) == len(set(phase)), f"Duplicate slug within phase: {phase}"
