#!/usr/bin/env python3
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
Custom SVG Generator for Threat Models
Replaces Graphviz SVG generation with manual SVG creation from xdot JSON data
"""

import json
import re
import logging
from typing import Dict, List, Tuple, Optional, Any
from pathlib import Path
import subprocess
import tempfile
from dataclasses import dataclass


import json
import re
import logging
import base64
from typing import Dict, List, Optional
from pathlib import Path
import subprocess

class CustomSVGGenerator:
    """Generates SVG diagrams from Graphviz JSON format data"""
    
    def __init__(self):
        self.image_cache = {}
        self.default_styles = {
            'graph': {'background': '#ffffff'},
            'node': {'fill': '#ffffff', 'stroke': '#000000', 'font-family': 'Times-Roman', 'font-size': '14'},
            'edge': {'stroke': '#000000', 'fill': 'none', 'font-family': 'Times-Roman', 'font-size': '14'}
        }
    
    def generate_svg_from_dot(self, dot_code: str, output_file: str) -> Optional[str]:
        """Generate SVG from DOT code using a JSON-based custom SVG generator"""
        try:
            graph_json = self._generate_graph_json_from_dot(dot_code)
            if not graph_json:
                return None
            svg_content = self._generate_svg(graph_json)
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(svg_content)
            return output_file
        except Exception as e:
            logging.error(f"❌ Error in custom SVG generation: {e}", exc_info=True)
            return None
    
    def _generate_graph_json_from_dot(self, dot_code: str) -> Optional[Dict]:
        """Generate graph data in JSON format from DOT code using Graphviz."""
        try:
            result = subprocess.run(
                ['dot', '-Tjson'],
                input=dot_code, text=True, encoding='utf-8',
                capture_output=True, check=True
            )
            return json.loads(result.stdout)
        except (subprocess.CalledProcessError, json.JSONDecodeError, Exception) as e:
            logging.error(f"❌ Failed to generate or parse Graphviz JSON: {e}")
            if isinstance(e, subprocess.CalledProcessError):
                logging.error(f"Stderr: {e.stderr}")
            return None

    def _load_image_as_data_uri(self, image_path: str) -> Optional[str]:
        """Loads an image file and encodes it as a base64 data URI."""
        if image_path in self.image_cache:
            return self.image_cache[image_path]
        try:
            p = Path(image_path)
            if not p.exists():
                logging.warning(f"⚠️ Image file not found: {image_path}")
                return None
            
            mime_map = {'.svg': 'image/svg+xml', '.png': 'image/png', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg'}
            mime_type = mime_map.get(p.suffix, 'application/octet-stream')
            
            with open(image_path, 'rb') as f:
                encoded = base64.b64encode(f.read()).decode()
            data_uri = f"data:{mime_type};base64,{encoded}"
            self.image_cache[image_path] = data_uri
            return data_uri
        except Exception as e:
            logging.error(f"❌ Error loading image {image_path}: {e}")
            return None

    def _generate_svg(self, data: Dict) -> str:
        bb = data.get('bb', '0,0,100,100')
        _, _, width, height = map(float, bb.split(','))
        
        elements = [
            f'<svg width="{width}" height="{height}" viewBox="0 0 {width} {height}" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">',
            f'  <g transform="translate(0, {height}) scale(1, -1)">'
        ]
        
        default_style = self.default_styles['graph']
        elements.append(f'<rect fill="{data.get("bgcolor", default_style["background"])}" stroke="none" x="0" y="0" width="{width}" height="{height}"/>')

        objects = data.get('objects', [])
        for obj in objects:
            if obj.get('name', '').startswith('cluster'):
                elements.extend(self._generate_cluster_svg(obj))
        for edge in data.get('edges', []):
            elements.extend(self._generate_edge_svg(edge))
        for obj in objects:
            if 'pos' in obj and not obj.get('name', '').startswith('cluster'):
                elements.extend(self._generate_node_svg(obj))
                
        elements.extend(['  </g>', '</svg>'])
        return '\n'.join(elements)

    def _process_draw_ops(self, ops: List[Dict], style: Dict) -> List[str]:
        return [self._convert_draw_op_to_svg(op, style) for op in ops if op.get('op') in ['p', 'P', 'e', 'E', 'b', 'B', 't', 'l']]

    def _generate_node_svg(self, node: Dict) -> List[str]:
        elements = [f'  <g id="{self._escape_html(node["name"])}">']
        
        style = self.default_styles['node'].copy()
        
        # Process shape drawing ops, which use absolute coordinates
        if '_draw_' in node:
            elements.extend(self._update_and_process_ops(node['_draw_'], style))
        
        # Handle image, which also needs to be placed using absolute coordinates
        if node.get('image'):
            try:
                xc, yc = map(float, node['pos'].split(','))
                w, h = float(node['width']) * 72, float(node['height']) * 72
                uri = self._load_image_as_data_uri(node['image'])
                if uri:
                    x_attr = xc - w/2
                    # The y-coordinate needs to be calculated to place the image correctly
                    # within the globally y-flipped coordinate system, considering the
                    # image's own y-inverting transform.
                    y_attr = -yc - h/2
                    elements.append(f'    <image transform="scale(1, -1)" href="{uri}" x="{x_attr}" y="{y_attr}" width="{w}" height="{h}" />')
            except (ValueError, TypeError):
                logging.warning(f"⚠️ Invalid image attributes for node {node['name']}.")

        # Process label drawing ops, which also use absolute coordinates
        if '_ldraw_' in node:
            elements.extend(self._update_and_process_ops(node['_ldraw_'], style))
            
        elements.append('  </g>')
        return elements

    def _generate_cluster_svg(self, cluster: Dict) -> List[str]:
        elements = [f'  <g id="{self._escape_html(cluster["name"])}">']
        style = self.default_styles['node'].copy()
        for key in ('_draw_', '_ldraw_'):
            if key in cluster: elements.extend(self._update_and_process_ops(cluster[key], style))
        elements.append('  </g>')
        return elements

    def _generate_edge_svg(self, edge: Dict) -> List[str]:
        name = f"edge_{edge.get('tail','')}_{edge.get('head','')}"
        elements = [f'  <g id="{self._escape_html(name)}">']
        style = self.default_styles['edge'].copy()
        for key in ('_draw_', '_hdraw_', '_tdraw_', '_ldraw_'):
            if key in edge: elements.extend(self._update_and_process_ops(edge[key], style))
        elements.append('  </g>')
        return elements
        
    def _update_and_process_ops(self, ops: List[Dict], style: Dict) -> List[str]:
        processed_ops = []
        for op in ops:
            op_type = op.get('op')
            if op_type == 'c': style['stroke'] = op['color']
            elif op_type == 'C': style['fill'] = op['color']
            elif op_type == 'S': style['style'] = op['style']
            elif op_type == 'F':
                style.update(size=op['size'], face=op['face'])
            else:
                processed_ops.append(self._convert_draw_op_to_svg(op, style))
        return processed_ops

    def _convert_draw_op_to_svg(self, op: Dict, style: Dict) -> str:
        op_type = op.get('op')
        attrs_str = self._get_style_attrs(op_type, style)
        
        if op_type in ('b', 'B'):
            points = op['points']
            d = f"M {points[0][0]},{points[0][1]} C " + " ".join([f"{p[0]},{p[1]}" for p in points[1:]])
            return f'    <path d="{d}" {attrs_str} />'
        elif op_type in ('p', 'P', 'l'):
            points = " ".join([f"{p[0]},{p[1]}" for p in op['points']])
            return f'    <polygon points="{points}" {attrs_str} />' if op_type == 'P' else f'    <polyline points="{points}" {attrs_str} fill="none"/>'
        elif op_type in ('e', 'E'):
            cx, cy, rx, ry = op['rect'][0], op['rect'][1], op['rect'][2], op['rect'][3]
            return f'    <ellipse cx="{cx}" cy="{cy}" rx="{rx}" ry="{ry}" {attrs_str} />'
        elif op_type == 't':
            x, y = op['pos']
            anchor = {'left': 'start', 'center': 'middle', 'right': 'end'}.get(op['align'], 'start')
            text = self._escape_html(op['text'])
            # The global g transform handles the y-up coordinate system.
            # No need for an extra flip on the text element.
            return f'    <text x="{x}" y="{y}" font-family="{style.get("face", "Arial")}" font-size="{style.get("size", 14)}" text-anchor="{anchor}" fill="{style["stroke"]}">{text}</text>'
        return f"<!-- Unsupported op: {op_type} -->"

    def _get_style_attrs(self, op_type: str, style: Dict) -> str:
        is_label = op_type == 't'
        fill = style.get('fill', 'none') if not is_label else style.get('stroke', '#000000')
        stroke = style.get('stroke', '#000000') if not is_label else 'none'
        
        attrs = [f'fill="{fill}"', f'stroke="{stroke}"']
        style_val = style.get('style')
        if style_val == 'dashed': attrs.append('stroke-dasharray="5,2"')
        elif style_val == 'dotted': attrs.append('stroke-dasharray="1,2"')
        return ' '.join(attrs)

    def _escape_html(self, text: str) -> str:
        return text.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')