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

import json
import uuid
import os
import logging
from datetime import datetime, timezone
from collections import defaultdict
from .tactic_logic import TACTIC_PROGRESSION, TACTIC_INFO
from .utils import extract_name_from_object, get_target_name

class AttackFlowGenerator:
    """
    Generates multiple attack flow files by finding all possible attack paths
    through the identified MITRE ATT&CK techniques, based on tactic progression.
    Each path shows the sequence of actions and the assets they target.
    """

    def __init__(self, threats, model_name="Attack Flow"):
        self.model_name = model_name

        # Filter out generic/class-based threats as requested
        filtered_threats = []
        for threat in threats:
            target = threat.get('target')
            if isinstance(target, type):
                continue
            if isinstance(target, tuple) and len(target) > 0 and any(isinstance(t, type) for t in target):
                continue
            filtered_threats.append(threat)

        allowed_categories = {
            "Spoofing",
            "Tampering",
            "Repudiation",
            "Information Disclosure",
            "Denial of Service",
            "Elevation of Privilege"
        }
        self.threats = [
            threat for threat in filtered_threats
            if threat.get("stride_category") in allowed_categories
        ]

        self.techniques = self._get_techniques_from_threats(self.threats)
        self.tactic_phase_map = self._build_tactic_phase_map()

    def _get_techniques_from_threats(self, threats):
        techniques = {}
        for threat_dict in threats:
            for tech in threat_dict.get('mitre_techniques', []):
                tech_id = str(tech['id'])
                if tech_id not in techniques:
                    techniques[tech_id] = {
                        'id': tech_id,
                        'name': str(tech.get('name', 'Unknown Technique')),
                        'tactics': [str(t) for t in tech.get('tactics', [])],
                        'threats': []
                    }
                techniques[tech_id]['threats'].append(threat_dict)
        return techniques

    def _build_tactic_phase_map(self):
        phase_map = {}
        for i, phase in enumerate(TACTIC_PROGRESSION):
            for tactic_slug in phase:
                for tactic_name, info in TACTIC_INFO.items():
                    if info['slug'] == tactic_slug:
                        phase_map[tactic_name] = i
                        break
        return phase_map

    def _find_attack_paths(self, max_paths=100):
        if not self.techniques:
            return []

        threats_by_phase = defaultdict(list)
        for tech_id, tech_data in self.techniques.items():
            for tactic in tech_data['tactics']:
                if tactic in self.tactic_phase_map:
                    phase_index = self.tactic_phase_map[tactic]
                    for threat in tech_data['threats']:
                        threat_tuple = (tech_id, threat)
                        if threat_tuple not in threats_by_phase[phase_index]:
                            threats_by_phase[phase_index].append(threat_tuple)

        if not threats_by_phase:
            return []

        all_paths = []
        sorted_phases = sorted(threats_by_phase.keys())
        if not sorted_phases:
            return []

        def find_paths_recursive(current_path, phase_idx):
            if len(all_paths) >= max_paths:
                return

            if phase_idx >= len(sorted_phases):
                if current_path:
                    all_paths.append(list(current_path))
                return

            current_phase_key = sorted_phases[phase_idx]
            
            # Explore paths by adding a threat from the current phase
            for threat_tuple in threats_by_phase[current_phase_key]:
                if threat_tuple not in current_path:
                    current_path.append(threat_tuple)
                    find_paths_recursive(current_path, phase_idx + 1)
                    current_path.pop()  # Backtrack

                    if len(all_paths) >= max_paths:
                        return
            
            # We are not exploring paths that skip phases for now to create more distinct paths
            # find_paths_recursive(current_path, phase_idx + 1)

        find_paths_recursive([], 0)
        return all_paths

    def generate_and_save_flows(self, output_dir):
        afb_output_dir = os.path.join(output_dir, "afb")
        os.makedirs(afb_output_dir, exist_ok=True)
        
        attack_paths = self._find_attack_paths()
        if not attack_paths:
            print("INFO: No logical attack paths found based on tactic progression.")
            return

        paths_by_objective = defaultdict(list)
        final_objectives = {"Spoofing", "Tampering", "Repudiation", "Information Disclosure", "Denial of Service", "Elevation of Privilege"}
        
        for path in attack_paths:
            if not path:
                continue
            
            path_objectives = set()
            for _, threat in path:
                objective = threat.get('stride_category')
                if objective in final_objectives:
                    path_objectives.add(objective)
            
            for objective in path_objectives:
                paths_by_objective[objective].append(path)

        best_paths_data = {}
        for objective, path_list in paths_by_objective.items():
            best_path_for_objective = None
            max_score = -1
            
            for path in path_list:
                current_score = sum(threat.get('severity', {}).get('score', 0) for _, threat in path)
                
                if current_score > max_score:
                    max_score = current_score
                    best_path_for_objective = path
            
            if best_path_for_objective:
                best_paths_data[objective] = {"path": best_path_for_objective, "objectives": [objective]}

        if not best_paths_data:
            print("INFO: No valid attack paths found after optimization.")
            return

        print(f"INFO: Found {len(best_paths_data)} unique attack paths after optimization.")
        i = 0
        for objective, path_data in best_paths_data.items():
            path = path_data["path"]
            
            flow_data = self._generate_single_path_flow(path, i + 1)
            if flow_data:
                file_path = os.path.join(afb_output_dir, f"optimized_path_{objective}.afb")
                try:
                    with open(file_path, 'w') as f:
                        json.dump(flow_data, f, indent=4)
                    print(f"INFO: Successfully generated optimized attack path for objective '{objective}' at {file_path}")
                except Exception as e:
                    print(f"ERROR: Error writing file for objective '{objective}': {e}")
            i += 1

    # Use shared utility functions instead of duplicated methods
    def _get_target_name(self, target: any) -> str:
        """Determines the target name, handling different target types."""
        return get_target_name(target)

    def _generate_single_path_flow(self, path, path_number):
        all_objects, layout, nodes_in_path, asset_node_cache = [], {}, [], {}
        for tech_id, threat in path:
            tech_data = self.techniques[tech_id]

            target_obj = threat.get('target')
            target_asset_name = self._get_target_name(target_obj)

            if target_asset_name == "Unspecified" or not target_asset_name or target_asset_name == "Unknown":
                continue

            action_obj, action_anchors = self._create_action_object(tech_data)
            all_objects.extend([action_obj] + action_anchors)
            nodes_in_path.append(action_obj)

            if target_asset_name not in asset_node_cache:
                asset_obj, asset_anchors = self._create_asset_object(target_asset_name)
                asset_node_cache[target_asset_name] = asset_obj
                all_objects.extend([asset_obj] + asset_anchors)
            
            nodes_in_path.append(asset_node_cache[target_asset_name])

        if not nodes_in_path:
            return None

        last_threat = path[-1][1]
        impact_category = str(last_threat.get('stride_category', ''))
        if impact_category and impact_category != 'Unknown':
            impact_node, impact_anchors = self._create_asset_object(f"Impact: {impact_category}")
            all_objects.extend([impact_node] + impact_anchors)
            nodes_in_path.append(impact_node)
        for i in range(len(nodes_in_path) - 1):
            source_node, target_node = nodes_in_path[i], nodes_in_path[i+1]
            conn_objects = self._create_connection_objects(source_node, target_node)
            all_objects.extend(conn_objects)
        for i, node in enumerate(nodes_in_path):
            layout[node['instance']] = [i * 300, 0]
        flow_name = f"{self.model_name}: Attack Path #{path_number}"
        description = " -> ".join([node['properties'][0][1] for node in nodes_in_path])
        return self._generate_flow_file(flow_name, description, all_objects, layout)

    def _create_anchor_objects(self):
        anchors, anchor_objects = {}, []
        for angle in range(0, 360, 30):
            anchor_id = str(uuid.uuid4())
            anchors[str(angle)] = anchor_id
            anchor_type = "vertical_anchor" if angle % 90 == 0 and angle % 180 != 0 else "horizontal_anchor"
            anchor_objects.append({"id": anchor_type, "instance": anchor_id, "latches": []})
        return anchors, anchor_objects

    def _create_action_object(self, technique):
        instance_id = str(uuid.uuid4())
        anchors, anchor_objects = self._create_anchor_objects()
        tactic_name = technique['tactics'][0] if technique['tactics'] else "Unknown"
        tactic_id = TACTIC_INFO.get(tactic_name, {}).get('id', '')
        tech_name, tech_id = technique['name'], technique['id']
        action_obj = {
            "id": "action", "instance": instance_id,
            "properties": [["name", tech_name], ["ttp", [["tactic", tactic_id], ["technique", tech_id]]], ["description", f"{tech_name} ({tech_id})"],],
            "anchors": anchors, "_anchors_list": anchor_objects
        }
        return action_obj, anchor_objects

    def _create_asset_object(self, asset_name):
        instance_id = str(uuid.uuid4())
        anchors, anchor_objects = self._create_anchor_objects()
        asset_obj = {
            "id": "asset", "instance": instance_id,
            "properties": [["name", str(asset_name)], ["description", "Target or Objective Asset"]],
            "anchors": anchors, "_anchors_list": anchor_objects
        }
        return asset_obj, anchor_objects

    def _create_connection_objects(self, source_obj, target_obj, source_anchor_angle=0, target_anchor_angle=180):
        line_instance, source_latch_instance, target_latch_instance, handle_instance = str(uuid.uuid4()), str(uuid.uuid4()), str(uuid.uuid4()), str(uuid.uuid4())
        source_anchor_id, target_anchor_id = source_obj["anchors"][str(source_anchor_angle)], target_obj["anchors"][str(target_anchor_angle)]
        dynamic_line = {"id": "dynamic_line", "instance": line_instance, "source": source_latch_instance, "target": target_latch_instance, "handles": [handle_instance]}
        source_latch, target_latch, handle = {"id": "generic_latch", "instance": source_latch_instance}, {"id": "generic_latch", "instance": target_latch_instance}, {"id": "generic_handle", "instance": handle_instance}
        connection_objects = [dynamic_line, source_latch, target_latch, handle]
        source_anchor_obj = next((obj for obj in source_obj["_anchors_list"] if obj["instance"] == source_anchor_id), None)
        if source_anchor_obj: source_anchor_obj.setdefault("latches", []).append(source_latch_instance)
        target_anchor_obj = next((obj for obj in target_obj["_anchors_list"] if obj["instance"] == target_anchor_id), None)
        if target_anchor_obj: target_anchor_obj.setdefault("latches", []).append(target_latch_instance)
        return connection_objects

    def _generate_flow_file(self, name, description, objects, layout):
        flow_instance_id = str(uuid.uuid4())
        now = datetime.now().astimezone()
        for obj in objects:
            if "_anchors_list" in obj: del obj["_anchors_list"]
        drawable_instances = [obj["instance"] for obj in objects if obj["id"] in ["action", "asset", "dynamic_line"]]
        flow_container = {
            "id": "flow", "instance": flow_instance_id,
            "properties": [["name", name], ["description", description], ["author", [["name", None], ["identity_class", None], ["contact_information", None]]], ["scope", "incident"], ["external_references", []], ["created", {"time": now.isoformat(), "zone": str(now.tzinfo)}]],
            "objects": drawable_instances
        }
        return {"schema": "attack_flow_v2", "theme": "dark_theme", "objects": [flow_container] + objects, "layout": layout, "camera": {"x": 0, "y": 0, "k": 1}}