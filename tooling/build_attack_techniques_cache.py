#!/usr/bin/env python
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

"""
Derives external_data/attack_techniques.json (~800 flat technique records) from the
full enterprise-attack.json STIX bundle (~43 MB, thousands of unrelated STIX objects).

data_loader.load_attack_techniques() reads the small derived file at runtime instead of
re-parsing the full STIX bundle. Re-run this script whenever enterprise-attack.json is
refreshed (see tooling/download_attack_data.py).
"""

import json
from pathlib import Path


def build_attack_techniques(stix_data: dict) -> dict:
    """Same extraction logic as data_loader.load_attack_techniques()."""
    techniques = {}
    for obj in stix_data.get("objects", []):
        if obj.get("type") == "attack-pattern":
            external_id = next(
                (ref['external_id'] for ref in obj.get('external_references', [])
                 if ref.get('source_name') == 'mitre-attack'), None
            )
            if external_id:
                techniques[external_id] = {
                    "id": external_id,
                    "name": obj.get("name"),
                    "description": obj.get("description"),
                    "url": next(
                        (ref['url'] for ref in obj.get('external_references', [])
                         if ref.get('source_name') == 'mitre-attack'), None
                    ),
                    "tactics": [
                        phase['phase_name'].replace('-', ' ').title()
                        for phase in obj.get('kill_chain_phases', [])
                        if phase.get('kill_chain_name') == 'mitre-attack'
                    ]
                }
    return techniques


def main():
    project_root = Path(__file__).resolve().parents[1]
    external_data = project_root / "threat_analysis" / "external_data"
    stix_path = external_data / "enterprise-attack.json"
    output_path = external_data / "attack_techniques.json"

    print(f"Reading {stix_path}...")
    with open(stix_path, "r", encoding="utf-8") as f:
        stix_data = json.load(f)

    techniques = build_attack_techniques(stix_data)

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(techniques, f, ensure_ascii=False, indent=2, sort_keys=True)

    print(f"Wrote {len(techniques)} techniques to {output_path} "
          f"({output_path.stat().st_size / 1024:.0f} KB, "
          f"vs {stix_path.stat().st_size / 1024 / 1024:.0f} MB source)")


if __name__ == "__main__":
    main()
