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
AttackFlowBuilder — generates Attack Flow (.afb) files from GDAF AttackScenario objects.

Each scenario produces one AFB file in output_dir/gdaf/<objective_id>/<actor_id>_<scenario_id>.afb
Also produces a summary_matrix.json for the HTML report.
"""

import json
import logging
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from threat_analysis.core.gdaf_engine import AttackScenario, AttackHop

logger = logging.getLogger(__name__)

DARK_THEME = "dark_theme"


class AttackFlowBuilder:
    """Builds AFB files from GDAF AttackScenario objects."""

    def __init__(self, scenarios: List[AttackScenario], model_name: str = "Threat Model"):
        self.scenarios = scenarios
        self.model_name = model_name

    def generate_and_save(self, output_dir: str) -> Dict[str, Any]:
        """
        Generate AFB files for all scenarios.
        Returns summary dict: {objective_id: {actor_id: [file_paths]}}
        """
        out = Path(output_dir) / "gdaf"
        out.mkdir(parents=True, exist_ok=True)

        summary = {}
        generated = []

        for scenario in self.scenarios:
            obj_dir = out / scenario.objective_id
            obj_dir.mkdir(exist_ok=True)

            filename = f"{scenario.actor_id}_{scenario.scenario_id}.afb"
            file_path = obj_dir / filename

            flow_data = self._build_afb(scenario)
            # Strip internal tracking keys before serialisation
            for obj in flow_data.get("objects", []):
                obj.pop("_anchors_list", None)
            try:
                with open(file_path, "w", encoding="utf-8") as f:
                    json.dump(flow_data, f, indent=2)
                generated.append(str(file_path))
                logger.info("GDAF: wrote %s", file_path)
            except Exception as exc:
                logger.error("GDAF: failed to write %s: %s", file_path, exc)
                continue

            key = f"{scenario.objective_id}/{scenario.actor_id}"
            summary.setdefault(key, []).append(filename)

        # Write summary matrix JSON
        self._write_summary(out, summary)
        logger.info("GDAF AttackFlowBuilder: generated %d scenario files", len(generated))
        return summary

    # ------------------------------------------------------------------
    # AFB construction
    # ------------------------------------------------------------------

    def _build_afb(self, scenario: AttackScenario) -> Dict:
        all_objects = []
        layout = {}

        # previous_nodes: last node(s) before the current hop.
        # For OR branches this is the list of action nodes; otherwise a single-element list.
        previous_nodes: List[Dict] = []
        min_score = getattr(scenario, "min_technique_score", 0.8)

        x_pos = 0
        y_increment = 220  # vertical spacing between OR-branch action nodes

        # Entry point node
        entry_node = self._make_asset_node(
            f"Entry: {scenario.entry_point}",
            f"Attacker entry point — {scenario.actor_name} ({scenario.actor_sophistication})"
        )
        all_objects.extend(self._flatten(entry_node))
        previous_nodes = [entry_node["node"]]
        layout[entry_node["node"]["instance"]] = [x_pos, 0]
        x_pos += 360

        for hop in scenario.hops:
            # Filter techniques above the score threshold (always keep at least the best one)
            eligible = [t for t in hop.techniques if t.score >= min_score]
            if not eligible and hop.techniques:
                eligible = [hop.techniques[0]]  # fallback: always show the best

            # Build OR-branch action nodes (one per eligible technique)
            action_nodes: List[Dict] = []
            n = len(eligible)
            # Spread action nodes vertically around y=0
            for idx, tech in enumerate(eligible):
                y_offset = (idx - (n - 1) / 2) * y_increment
                action_node = self._make_action_node(tech)
                all_objects.extend(self._flatten(action_node))
                action_nodes.append(action_node["node"])
                layout[action_node["node"]["instance"]] = [x_pos, int(y_offset)]
            x_pos += 360

            # Asset node for this hop (convergence point of all OR branches)
            vuln_notes = []
            if not hop.is_authenticated:
                vuln_notes.append("no authentication")
            if not hop.is_encrypted:
                vuln_notes.append("cleartext")
            vuln_str = " | ".join(vuln_notes) if vuln_notes else "authenticated + encrypted"
            best_tech = eligible[0] if eligible else None
            asset_desc = (
                f"[{hop.asset_type}] {hop.protocol} — {vuln_str}"
                + (f" — {best_tech.rationale}" if best_tech else "")
            )
            asset_node = self._make_asset_node(hop.asset_name, asset_desc)
            all_objects.extend(self._flatten(asset_node))
            layout[asset_node["node"]["instance"]] = [x_pos, 0]
            x_pos += 360

            # Connect: each previous node → each action node (OR fan-out from previous asset)
            for prev in previous_nodes:
                for act in action_nodes:
                    all_objects.extend(self._make_connection(prev, act))

            # Connect: each action node → current asset node (OR fan-in to asset)
            for act in action_nodes:
                all_objects.extend(self._make_connection(act, asset_node["node"]))

            previous_nodes = [asset_node["node"]]

        # Objective node (final goal)
        obj_desc = (
            f"Objective: {scenario.objective_name}\n"
            f"Impact: {scenario.objective_business_impact}\n"
            f"Risk: {scenario.risk_level} (score {scenario.path_score})"
        )
        obj_node = self._make_objective_node(scenario.objective_name, obj_desc)
        all_objects.extend(self._flatten(obj_node))
        layout[obj_node["node"]["instance"]] = [x_pos, 0]

        # Connect last asset(s) → objective
        for prev in previous_nodes:
            all_objects.extend(self._make_connection(prev, obj_node["node"]))

        # Build flow container
        now = datetime.now().astimezone()
        drawable_ids = [
            obj["instance"] for obj in all_objects
            if obj.get("id") in ("action", "asset", "condition", "operator", "dynamic_line")
        ]
        flow_name = (
            f"{self.model_name} | {scenario.objective_name} | {scenario.actor_name}"
        )
        flow_description = " → ".join(
            [scenario.entry_point] + [h.asset_name for h in scenario.hops] + [scenario.objective_name]
        )
        flow_container = {
            "id": "flow",
            "instance": str(uuid.uuid4()),
            "properties": [
                ["name", flow_name],
                ["description", flow_description],
                ["author", [["name", "SecOpsTM GDAF"], ["identity_class", "system"], ["contact_information", ""]]],
                ["scope", "incident"],
                ["external_references", []],
                ["created", {"time": now.isoformat(), "zone": str(now.tzinfo)}],
            ],
            "objects": drawable_ids,
        }

        return {
            "schema": "attack_flow_v2",
            "theme": DARK_THEME,
            "objects": [flow_container] + all_objects,
            "layout": layout,
            "camera": {"x": 0, "y": 0, "k": 0.7},
            "_gdaf_meta": {
                "scenario_id": scenario.scenario_id,
                "objective_id": scenario.objective_id,
                "actor_id": scenario.actor_id,
                "path_score": scenario.path_score,
                "risk_level": scenario.risk_level,
                "unacceptable_risk": scenario.unacceptable_risk,
                "hop_count": len(scenario.hops),
            },
        }

    # ------------------------------------------------------------------
    # Node factories
    # ------------------------------------------------------------------

    def _make_anchors(self) -> tuple:
        """Create 12 anchor objects (every 30°) matching the AFB corpus format."""
        anchors: Dict[str, str] = {}
        anchor_objs: List[Dict] = []
        for angle in range(0, 360, 30):
            aid = str(uuid.uuid4())
            anchors[str(angle)] = aid
            atype = "vertical_anchor" if angle % 90 == 0 and angle % 180 != 0 else "horizontal_anchor"
            anchor_objs.append({"id": atype, "instance": aid, "latches": []})
        return anchors, anchor_objs

    def _make_action_node(self, tech) -> Dict:
        """Create an AFB action node from a ScoredTechnique."""
        instance_id = str(uuid.uuid4())
        anchors, anchor_objs = self._make_anchors()
        tactic_slug = tech.tactics[0] if tech.tactics else "unknown"
        node = {
            "id": "action",
            "instance": instance_id,
            "properties": [
                ["name", tech.name],
                ["ttp", [["tactic", tactic_slug], ["technique", tech.id]]],
                ["description", f"{tech.name} ({tech.id}) — {tech.rationale}"],
            ],
            "anchors": anchors,
            "_anchors_list": anchor_objs,
        }
        return {"node": node, "anchors": anchor_objs}

    def _make_asset_node(self, name: str, description: str) -> Dict:
        instance_id = str(uuid.uuid4())
        anchors, anchor_objs = self._make_anchors()
        node = {
            "id": "asset",
            "instance": instance_id,
            "properties": [
                ["name", name],
                ["description", description],
            ],
            "anchors": anchors,
            "_anchors_list": anchor_objs,
        }
        return {"node": node, "anchors": anchor_objs}

    def _make_objective_node(self, name: str, description: str) -> Dict:
        # Attack Flow Builder does not have an "objective" template type.
        # Valid types: action, asset, condition, operator.
        # Represent the objective as an asset node with a visual prefix.
        instance_id = str(uuid.uuid4())
        anchors, anchor_objs = self._make_anchors()
        node = {
            "id": "asset",
            "instance": instance_id,
            "properties": [
                ["name", f"[Objective] {name}"],
                ["description", description],
            ],
            "anchors": anchors,
            "_anchors_list": anchor_objs,
        }
        return {"node": node, "anchors": anchor_objs}

    def _flatten(self, node_dict: Dict) -> List[Dict]:
        """Return flat list: [node, ...anchor_objs]"""
        return [node_dict["node"]] + node_dict["anchors"]

    def _make_connection(self, source_node: Dict, target_node: Dict,
                         src_angle: int = 0, tgt_angle: int = 180) -> List[Dict]:
        """Wire a connection using the nodes' existing anchors at the given angles.

        Matches the approach in attack_flow_generator.py: latches are attached to
        the anchor objects (via the ``latches`` list) so the AFB builder can resolve
        connection endpoints correctly.
        """
        line_id = str(uuid.uuid4())
        src_latch_id = str(uuid.uuid4())
        tgt_latch_id = str(uuid.uuid4())
        handle_id = str(uuid.uuid4())

        # Attach latch UUIDs to the anchor objects so the builder can resolve them
        src_anchors_list = source_node.get("_anchors_list", [])
        src_anchor_uuid = source_node.get("anchors", {}).get(str(src_angle))
        src_anchor_obj = next((a for a in src_anchors_list if a["instance"] == src_anchor_uuid), None)
        if src_anchor_obj is not None:
            src_anchor_obj.setdefault("latches", []).append(src_latch_id)

        tgt_anchors_list = target_node.get("_anchors_list", [])
        tgt_anchor_uuid = target_node.get("anchors", {}).get(str(tgt_angle))
        tgt_anchor_obj = next((a for a in tgt_anchors_list if a["instance"] == tgt_anchor_uuid), None)
        if tgt_anchor_obj is not None:
            tgt_anchor_obj.setdefault("latches", []).append(tgt_latch_id)

        return [
            {"id": "dynamic_line", "instance": line_id, "source": src_latch_id,
             "target": tgt_latch_id, "handles": [handle_id]},
            {"id": "generic_latch", "instance": src_latch_id},
            {"id": "generic_latch", "instance": tgt_latch_id},
            {"id": "generic_handle", "instance": handle_id},
        ]

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------

    def _write_summary(self, gdaf_dir: Path, summary: Dict) -> None:
        rows = []
        for scenario in self.scenarios:
            rows.append({
                "scenario_id": scenario.scenario_id,
                "objective": scenario.objective_name,
                "actor": scenario.actor_name,
                "entry_point": scenario.entry_point,
                "target": scenario.target_asset,
                "hops": len(scenario.hops),
                "path_score": scenario.path_score,
                "risk_level": scenario.risk_level,
                "unacceptable_risk": scenario.unacceptable_risk,
                "techniques": [
                    {"hop": h.asset_name, "tech_id": h.techniques[0].id, "tech_name": h.techniques[0].name}
                    for h in scenario.hops if h.techniques
                ],
            })
        summary_data = {"model": "GDAF Summary", "scenarios": rows, "files": summary}
        summary_path = gdaf_dir / "gdaf_summary.json"
        try:
            with open(summary_path, "w", encoding="utf-8") as f:
                json.dump(summary_data, f, indent=2)
        except Exception as exc:
            logger.error("GDAF: cannot write summary: %s", exc)
