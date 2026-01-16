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
Converts Graphviz JSON output to a metadata format with element positions.
"""

import logging
from typing import Dict, Any

class GraphvizToJsonMetadataConverter:
    """
    Converts Graphviz JSON to a dictionary of element positions.
    """

    def convert(self, graphviz_json: Dict[str, Any], threat_model: Any) -> Dict[str, Any]:
        """
        Converts the Graphviz JSON to a positions dictionary.

        Args:
            graphviz_json: The JSON output from Graphviz (`dot -Tjson`).
            threat_model: The ThreatModel object to map names to types.

        Returns:
            A dictionary containing the positions of the elements.
        """
        positions = {
            "boundaries": {},
            "actors": {},
            "servers": {},
            "data": {}
        }

        bb = graphviz_json.get('bb', '0,0,100,100')
        _, _, _, graph_height = map(float, bb.split(','))

        # Create a mapping from sanitized name to element type
        name_to_type = {}
        for name in threat_model.boundaries.keys():
            name_to_type[self._sanitize_name(name)] = "boundaries"
        for actor_info in threat_model.actors:
            name_to_type[self._sanitize_name(actor_info['name'])] = "actors"
        for server_info in threat_model.servers:
            name_to_type[self._sanitize_name(server_info['name'])] = "servers"

        # Process clusters (boundaries)
        for obj in graphviz_json.get("objects", []):
            if obj.get("name", "").startswith("cluster_"):
                self._process_cluster(obj, positions, name_to_type, graph_height)
        
        # Process nodes (actors, servers)
        for obj in graphviz_json.get("objects", []):
            if "pos" in obj and not obj.get("name", "").startswith("cluster_"):
                self._process_node(obj, positions, name_to_type, graph_height)

        return positions

    def _process_cluster(self, cluster: Dict[str, Any], positions: Dict[str, Any], name_to_type: Dict[str, str], graph_height: float):
        """Processes a cluster object from the Graphviz JSON."""
        label = cluster.get("label", "")
        if not label:
            return

        sanitized_name = self._sanitize_name(label)
        category = name_to_type.get(sanitized_name)
        if category != "boundaries":
            return

        bb = cluster.get("bb")
        if not bb:
            return
            
        x1, y1, x2, y2 = map(float, bb.split(','))

        positions[category][label] = {
            "x": x1,
            "y": graph_height - y2, # Flipped Y
            "width": x2 - x1,
            "height": y2 - y1,
        }

    def _process_node(self, node: Dict[str, Any], positions: Dict[str, Any], name_to_type: Dict[str, str], graph_height: float):
        """Processes a node object from the Graphviz JSON."""
        name = node.get("name")
        if not name:
            return

        sanitized_name = self._sanitize_name(name)
        category = name_to_type.get(sanitized_name)
        if not category:
            return

        pos_str = node.get("pos")
        if not pos_str:
            return
            
        x, y = map(float, pos_str.split(','))
        width = float(node.get("width", 0)) * 72  # inches to points
        height = float(node.get("height", 0)) * 72  # inches to points

        positions[category][name] = {
            "x": x - (width / 2),
            "y": graph_height - (y + (height / 2)), # Flipped Y
            "width": width,
            "height": height,
        }

    def _sanitize_name(self, name: str) -> str:
        """Sanitizes a name to be used as a key."""
        return name.lower().replace(" ", "_")

