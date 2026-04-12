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

import logging
import json
import subprocess
import time
import os
import tempfile
import re
from typing import Dict, Optional
from pathlib import Path

from threat_analysis.core.model_factory import create_threat_model
from threat_analysis.core.model_validator import ModelValidator
from threat_analysis.generation.graphviz_to_json_metadata import GraphvizToJsonMetadataConverter

PROJECT_ROOT = Path(__file__).resolve().parents[2]

class DiagramService:
    def __init__(self, cve_service, diagram_generator):
        self.cve_service = cve_service
        self.diagram_generator = diagram_generator
        self.element_positions = {}

    def _generate_positions_from_graphviz(self, threat_model):
        """
        Generates element positions by using the Graphviz JSON output.
        """
        logging.info("Generating layout positions using Graphviz JSON...")
        try:
            dot_code = self.diagram_generator._generate_manual_dot(threat_model)
            if not dot_code:
                return {}
            result = subprocess.run(
                ["dot", "-Tjson"],
                input=dot_code,
                text=True,
                encoding="utf-8",
                capture_output=True,
                check=True
            )
            graphviz_json = json.loads(result.stdout)
            converter = GraphvizToJsonMetadataConverter()
            positions = converter.convert(graphviz_json, threat_model)
            logging.info("Successfully generated positions from Graphviz JSON.")
            return positions
        except (subprocess.CalledProcessError, json.JSONDecodeError, Exception) as e:
            logging.error(f"An unexpected error occurred in _generate_positions_from_graphviz: {e}", exc_info=True)
            if isinstance(e, subprocess.CalledProcessError):
                logging.error(f"Stderr: {e.stderr}")
            return {}

    def markdown_to_json_for_gui(self, markdown_content: str):
        """
        Converts markdown content to a JSON structure suitable for the GUI.
        """
        if not markdown_content:
            raise ValueError("Markdown content is empty")
        threat_model = create_threat_model(
            markdown_content=markdown_content,
            model_name="TempModelForConversion",
            model_description="Temporary model for GUI conversion",
            cve_service=self.cve_service,
            validate=False,
        )
        if not threat_model:
            raise RuntimeError("Failed to create threat model from markdown")
        model_json = {"boundaries": [], "actors": [], "servers": [], "data": [], "dataflows": []}
        element_to_id = {}
        for name, b_info in threat_model.boundaries.items():
            boundary_obj = b_info['boundary']
            b_id = str(id(boundary_obj))
            element_to_id[boundary_obj] = b_id
            parent_id = None
            if hasattr(boundary_obj, 'inBoundary') and boundary_obj.inBoundary:
                parent_id = element_to_id.get(boundary_obj.inBoundary)
            model_json["boundaries"].append({
                "id": b_id, "name": name, "type": "BOUNDARY", "parentId": parent_id,
                "description": b_info.get('description', ''), "isTrusted": b_info.get('isTrusted', False),
                "isFilled": b_info.get('isFilled', False), "lineStyle": b_info.get('line_style', 'solid'),
                "color": b_info.get('color', 'lightgray'),
            })
        for actor_info in threat_model.actors:
            actor_obj = actor_info['object']
            a_id = str(id(actor_obj))
            element_to_id[actor_obj] = a_id
            parent_id = None
            if actor_info.get('boundary'):
                parent_id = element_to_id.get(actor_info['boundary'])
            model_json["actors"].append({
                "id": a_id, "name": actor_info['name'], "parentId": parent_id,
                "description": actor_info.get('description', ''),
            })
        for server_info in threat_model.servers:
            server_obj = server_info['object']
            s_id = str(id(server_obj))
            element_to_id[server_obj] = s_id
            parent_id = None
            if server_info.get('boundary'):
                parent_id = element_to_id.get(server_info['boundary'])
            model_json["servers"].append({
                "id": s_id, "name": server_info['name'], "parentId": parent_id,
                "description": server_info.get('description', ''), "os": server_info.get('os', ''),
                "stereotype": server_info.get('type', 'server'),
            })
        for name, data_obj in threat_model.data_objects.items():
            d_id = str(id(data_obj))
            element_to_id[data_obj] = d_id
            classification_obj = getattr(data_obj, 'classification', 'public')
            classification_val = str(getattr(classification_obj, 'name', classification_obj)).lower()
            model_json["data"].append({
                "id": d_id, "name": name, "description": getattr(data_obj, 'description', ''),
                "classification": classification_val,
            })
        for df in threat_model.dataflows:
            df_id = str(id(df))
            from_name = getattr(df.source, 'name', None)
            to_name = getattr(df.sink, 'name', None)
            if from_name and to_name:
                data_name = ""
                if hasattr(df, 'data') and df.data:
                    try:
                        first_data_obj = next(iter(df.data))
                        if hasattr(first_data_obj, 'name'):
                            data_name = first_data_obj.name
                    except StopIteration:
                        pass
                properties = {
                    "name": getattr(df, 'name', f"{from_name}_to_{to_name}"),
                    "protocol": getattr(df, 'protocol', None),
                    "description": getattr(df, 'description', ''),
                    "color": getattr(df, 'color', '#000000'),
                    "data": data_name,
                    "isEncrypted": getattr(df, 'is_encrypted', False) or getattr(df, 'isEncrypted', False),
                    "isAuthenticated": getattr(df, 'is_authenticated', False) or getattr(df, 'authenticatedWith', False),
                }
                model_json["dataflows"].append({
                    "id": df_id, "from": from_name, "to": to_name, "properties": properties
                })
        return model_json

    def _extract_graph_metadata_for_frontend(self, threat_model) -> dict:
        graph_metadata = {"nodes": {}, "edges": {}}
        def _sanitize_name_for_id(name: str) -> str:
            if not name: return "unnamed"
            sanitized = re.sub(r'[^a-zA-Z0-9_]', '_', str(name))
            if sanitized and sanitized[0].isdigit():
                sanitized = f"_{sanitized}"
            return sanitized or "unnamed"
        for name, info in threat_model.boundaries.items():
            sanitized_name = _sanitize_name_for_id(name)
            cluster_id = f"cluster_{sanitized_name}"
            graph_metadata["nodes"][cluster_id] = {"id": cluster_id, "type": "boundary", "label": name, "connections": []}
            hidden_node_name = f"__hidden_node_{sanitized_name}"
            graph_metadata["nodes"][hidden_node_name] = {"id": hidden_node_name, "type": "hidden_boundary_node", "label": f"Hidden node for {name}", "connections": []}
        for actor_info in threat_model.actors:
            name = actor_info['name']
            sanitized_name = _sanitize_name_for_id(name)
            graph_metadata["nodes"][sanitized_name] = {"id": sanitized_name, "type": "actor", "label": name, "connections": []}
        for server_info in threat_model.servers:
            name = server_info['name']
            sanitized_name = _sanitize_name_for_id(name)
            graph_metadata["nodes"][sanitized_name] = {"id": sanitized_name, "type": "server", "label": name, "connections": []}
        for df in threat_model.dataflows:
            source_name = getattr(df.source, 'name', None)
            sink_name = getattr(df.sink, 'name', None)
            protocol = getattr(df, 'protocol', None)
            if not source_name or not sink_name:
                logging.warning(f"Skipping dataflow with missing source or sink: {df}")
                continue
            sanitized_source = _sanitize_name_for_id(source_name)
            sanitized_sink = _sanitize_name_for_id(sink_name)
            is_source_boundary = False
            for b_name, info in threat_model.boundaries.items():
                if b_name == source_name:
                    sanitized_source = f"__hidden_node_{_sanitize_name_for_id(b_name)}"
                    is_source_boundary = True
                    break
            is_sink_boundary = False
            for b_name, info in threat_model.boundaries.items():
                if b_name == sink_name:
                    sanitized_sink = f"__hidden_node_{_sanitize_name_for_id(b_name)}"
                    is_sink_boundary = True
                    break
            actual_src_id = _sanitize_name_for_id(source_name)
            actual_dst_id = _sanitize_name_for_id(sink_name)
            edge_id = f"edge_{actual_src_id}_{actual_dst_id}"
            graph_metadata["edges"][edge_id] = {"id": edge_id, "source": sanitized_source, "target": sanitized_sink, "protocol": protocol, "label": df.name if hasattr(df, 'name') else f"{source_name} to {sink_name}"}
            if sanitized_source in graph_metadata["nodes"]:
                graph_metadata["nodes"][sanitized_source]["connections"].append(edge_id)
            if sanitized_sink in graph_metadata["nodes"]:
                graph_metadata["nodes"][sanitized_sink]["connections"].append(edge_id)
            if is_source_boundary:
                actual_boundary_id = _sanitize_name_for_id(source_name)
                if actual_boundary_id in graph_metadata["nodes"]:
                    graph_metadata["nodes"][actual_boundary_id]["connections"].append(edge_id)
            if is_sink_boundary:
                actual_boundary_id = _sanitize_name_for_id(sink_name)
                if actual_boundary_id in graph_metadata["nodes"]:
                    graph_metadata["nodes"][actual_boundary_id]["connections"].append(edge_id)
        return graph_metadata

    def update_diagram_logic(self, markdown_content: str, submodels: list | None = None,
                             model_file_path: Optional[str] = None):
        logging.info("update_diagram_logic: Starting diagram update.")
        if not markdown_content:
            logging.error("update_diagram_logic: Markdown content is empty.")
            raise ValueError("Markdown content is empty")
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_md_path = os.path.join(tmpdir, "live_model.md")
            with open(tmp_md_path, "w", encoding="utf-8") as f:
                f.write(markdown_content)
            logging.info(f"Saved live markdown to {tmp_md_path}")
            threat_model = create_threat_model(
                markdown_content=markdown_content, model_name="WebThreatModel",
                model_description="Live-updated threat model", cve_service=self.cve_service, validate=False,
            )
            if not threat_model:
                raise RuntimeError("Failed to create threat model")
            # Propagate model_file_path so BOM/VEX auto-discovery works in server mode
            if model_file_path:
                threat_model._model_file_path = model_file_path
            if submodels and len(submodels) > 0:
                for submodel_data in submodels:
                    sub_path = submodel_data['path']
                    sub_content = submodel_data['content']
                    sub_model = create_threat_model(
                        markdown_content=sub_content, model_name=os.path.basename(sub_path),
                        model_description=f"Submodel for {sub_path}", cve_service=self.cve_service, validate=False
                    )
                    if sub_model:
                        threat_model.sub_models.append(sub_model)
            validator = ModelValidator(threat_model)
            errors = validator.validate()
            if errors:
                logging.warning(f"update_diagram_logic: Model has validation warnings: {errors}")
            self.element_positions = self._generate_positions_from_graphviz(threat_model)
            dot_code = self.diagram_generator._generate_manual_dot(threat_model)
            if not dot_code:
                raise RuntimeError("Failed to generate DOT code from model")
            temp_svg_path = os.path.join(tmpdir, "live_preview.svg")
            svg_path = self.diagram_generator.generate_diagram_from_dot(dot_code, temp_svg_path, "svg")
            logging.info(f"update_diagram_logic: SVG generated at {svg_path}")
            if not svg_path or not os.path.exists(svg_path):
                raise RuntimeError("Failed to generate SVG diagram")
            with open(svg_path, "r", encoding="utf-8") as f:
                svg_content = f.read()
            static_path_base = str(PROJECT_ROOT / 'threat_analysis' / 'server' / 'static')
            svg_content = svg_content.replace(static_path_base, '/static')
            # Add sub-model navigation links for interactive editor (href="#submodel:<path>" intercepted by JS)
            has_submodels = any(isinstance(s, dict) and 'submodel' in s for s in threat_model.servers)
            if has_submodels:
                svg_content = self.diagram_generator.add_links_to_svg(
                    svg_content, threat_model,
                    href_builder=lambda p: f"#submodel:{p}",
                )
            # No severity section in editor preview: threats have not been generated yet
            legend_html = self.diagram_generator._generate_legend_html(threat_model, show_severity_section=False)
            full_html = self.diagram_generator._create_complete_html(svg_content, legend_html, threat_model, severity_map={})
            graph_metadata = self._extract_graph_metadata_for_frontend(threat_model)
            logging.debug(f"Generated graph_metadata for frontend: {json.dumps(graph_metadata, indent=2)}")
            logging.info("update_diagram_logic: Successfully updated diagram.")
            result = {
                "diagram_html": full_html, "diagram_svg": svg_content,
                "legend_html": legend_html, "graph_metadata": graph_metadata,
            }
            if errors:
                result["validation_errors"] = errors
            return result

    def _merge_with_ui_positions(self, base_positions: dict, ui_positions: dict) -> dict:
        if 'boundaries' in ui_positions:
            for boundary_name, ui_pos in ui_positions['boundaries'].items():
                if boundary_name in base_positions['boundaries']:
                    base_positions['boundaries'][boundary_name].update({
                        'x': ui_pos.get('x', 0), 'y': ui_pos.get('y', 0),
                        'width': ui_pos.get('width', 0), 'height': ui_pos.get('height', 0)
                    })
        if isinstance(ui_positions, dict) and 'actors' in ui_positions:
            for actor_name, ui_pos in ui_positions['actors'].items():
                if actor_name in base_positions['actors']:
                    base_positions['actors'][actor_name].update({'x': ui_pos.get('x', 0), 'y': ui_pos.get('y', 0)})
        if isinstance(ui_positions, dict) and 'servers' in ui_positions:
            for server_name, ui_pos in ui_positions['servers'].items():
                if server_name in base_positions['servers']:
                    base_positions['servers'][server_name].update({'x': ui_pos.get('x', 0), 'y': ui_pos.get('y', 0)})
        if 'dataflows' in ui_positions:
            for df_name, ui_pos in ui_positions['dataflows'].items():
                if df_name in base_positions['dataflows']:
                    base_positions['dataflows'][df_name]['points'] = ui_pos.get('points', [])
        return base_positions
        
    def get_element_positions(self):
        return self.element_positions
