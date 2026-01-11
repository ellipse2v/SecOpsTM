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
            'node': {'fill': '#ffffff', 'stroke': '#000000', 'font-family': 'sans-serif', 'font-size': '14'},
            'edge': {'stroke': '#000000', 'fill': 'none', 'font-family': 'sans-serif', 'font-size': '14'}
        }
    
    def generate_svg_from_dot(self, dot_code: str, output_file: str) -> Optional[str]:
        """Generate SVG from DOT code using a JSON-based custom SVG generator"""
        try:
            graph_json = self._generate_graph_json_from_dot(dot_code)
            if not graph_json:
                return None
            try:
                output_path = Path(output_file)
                debug_dir = output_path.parent / "debug"
                debug_dir.mkdir(parents=True, exist_ok=True)

                # 1️⃣ Dump DOT
                dot_path = debug_dir / "graphviz_input.dot"
                with open(dot_path, "w", encoding="utf-8") as f:
                    f.write(dot_code)

                logging.info(f"🧪 DOT dumped to {dot_path}")

                # 2️⃣ Dump Graphviz JSON
                json_path = debug_dir / "graphviz_output.json"
                result = subprocess.run(
                    ["dot", "-Tjson"],
                    input=dot_code,
                    text=True,
                    encoding="utf-8",
                    capture_output=True
                )

                if result.returncode != 0:
                    logging.error("❌ Graphviz JSON generation failed")
                    logging.error(result.stderr)
                    return None
                
                # Update graph_json with the fresh content
                graph_json = json.loads(result.stdout)

                with open(json_path, "w", encoding="utf-8") as f:
                    f.write(result.stdout)

                logging.info(f"🧪 Graphviz JSON dumped to {json_path}")


                # 3️⃣ Dump native Graphviz SVG (for visual comparison)
                native_svg_path = debug_dir / "graphviz_native.svg"
                subprocess.run(
                    ["dot", "-Tsvg", "-o", str(native_svg_path)],
                    input=dot_code,
                    text=True,
                    encoding="utf-8",
                    check=True
                )

                logging.info(f"🧪 Native Graphviz SVG dumped to {native_svg_path}")
            except Exception as e:
                logging.error(f"❌ Error in custom SVG export generation: {e}", exc_info=True)
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

    def _load_image(self, image_path: str) -> Optional[str]:
        """
        Loads an image.
        - SVG → returned as inline SVG content
        - PNG/JPG → returned as base64 data URI
        """
        if image_path in self.image_cache:
            return self.image_cache[image_path]

        try:
            p = Path(image_path)
            if not p.exists():
                logging.warning(f"⚠️ Image file not found: {image_path}")
                return None

            if p.suffix.lower() == '.svg':
                svg_content = p.read_text(encoding='utf-8')
                self.image_cache[image_path] = svg_content
                return svg_content

            mime_map = {
                '.png': 'image/png',
                '.jpg': 'image/jpeg',
                '.jpeg': 'image/jpeg'
            }
            mime_type = mime_map.get(p.suffix.lower(), 'application/octet-stream')

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
        svg = []
        for op in ops:
            op_type = op.get('op')

            if op_type == 'c':
                style['stroke'] = op['color']
            elif op_type == 'C':
                style['fill'] = op['color']
            elif op_type == 'S':
                style['style'] = op['style']
            elif op_type == 'F':
                style['font-size'] = op['size']
                style['font-family'] = op['face']
            else:
                svg_el = self._convert_draw_op_to_svg(op, style)
                if svg_el:
                    svg.append(svg_el)
        return svg
   

    def _generate_node_svg(self, node: Dict) -> List[str]:
        """
        Generates SVG for a single node.
        - Preserves Graphviz text rendering (_ldraw_)
        - Supports HTML labels with SVG/PNG icons
        - Handles server layout (icon left, text right) as a centered unit
        """
        elements = [f'  <g id="{self._escape_html(node["name"])}">']
        style = self.default_styles['node'].copy()

        # --- Draw node shape ---
        if '_draw_' in node:
            elements.extend(self._update_and_process_ops(node['_draw_'], style))

        # --- Check if this is a server layout ---
        label = node.get('label', '')
        is_server_layout = 'ALIGN="LEFT"' in label.upper()
        
        # Get node center position and dimensions
        pos_str = node.get('pos', '0,0')
        try:
            node_x, node_y = map(float, pos_str.split(','))
        except:
            node_x, node_y = 0, 0
        
        # Get node width (in inches, need to convert to points: 1 inch = 72 points)
        node_width_inches = float(node.get('width', 1.5))
        node_width = node_width_inches * 72  # Convert to points
        
        # --- Adjust text position BEFORE rendering ---
        if '_ldraw_' in node:
            if is_server_layout:
                # Server layout: calculate spacing based on node width
                # Icon is 30px wide, we want it at the left edge with some padding
                # Layout: [padding | icon 30px | spacing | text | padding]
                # Total available = node_width
                # Icon should be at: -node_width/2 + padding + icon_width/2
                # Text should start at: -node_width/2 + padding + icon_width + spacing
                
                icon_width = 30
                padding = 10
                spacing = 10  # Small gap between icon and text
                
                # Text starts at this offset from center
                text_start_from_center = -node_width/2 + padding + icon_width + spacing
                
                for op in node['_ldraw_']:
                    if op.get('op') in ('t', 'T') and op.get('align') == 'l':
                        # Get current text position
                        if 'pt' in op and len(op['pt']) == 2:
                            current_x = op['pt'][0]
                            # Calculate offset needed to move text to desired position
                            offset = text_start_from_center - (current_x - node_x)
                            op['pt'][0] += offset
                        elif 'pos' in op and len(op['pos']) == 2:
                            current_x = op['pos'][0]
                            offset = text_start_from_center - (current_x - node_x)
                            op['pos'][0] += offset
            else:
                           # Top-and-bottom layout: shift text down 10px to avoid overlapping icon
            # Only apply for specific shapes: circle (Actor), diamond (Switch), hexagon (Firewall), cylinder (Database)
                node_shape = node.get('shape', '').lower()
                shapes_needing_offset = ['circle', 'diamond', 'hexagon', 'cylinder']
                
                if node_shape in shapes_needing_offset:
                    y_offset = 10
                    
                    for op in node['_ldraw_']:
                        if op.get('op') in ('t', 'T'):
                            # Move text down
                            if 'pos' in op and len(op['pos']) == 2:
                                op['pos'][1] -= y_offset
                            elif 'pt' in op and len(op['pt']) == 2:
                                op['pt'][1] -= y_offset
        
        # --- Extract and render images from HTML label ---
        if 'label' in node and '<IMG' in label.upper():
            image_svg = self._extract_image_from_html_label(node, is_server_layout, node_x, node_y)
            if image_svg:
                elements.append(image_svg)

        # --- Render remaining Graphviz text (labels, titles, etc.) ---
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
        # Safety guard: Graphviz JSON is not always consistent
        if not isinstance(op, dict) or 'op' not in op:
            return ''

        op_type = op.get('op')
        attrs_str = self._get_style_attrs(op_type, style)

        # --- Bezier curves (edges) ---
        if op_type in ('b', 'B'):
            points = op.get('points', [])
            if len(points) < 2:
                return ''
            d = f"M {points[0][0]},{points[0][1]} C " + " ".join([f"{p[0]},{p[1]}" for p in points[1:]])
            return f'    <path d="{d}" {attrs_str} />'

        # --- Polygons / polylines ---
        elif op_type in ('p', 'P', 'l'):
            points_list = op.get('points', [])
            if not points_list:
                return ''
            points = " ".join([f"{p[0]},{p[1]}" for p in points_list])
            if op_type == 'P':
                return f'    <polygon points="{points}" {attrs_str} />'
            else:
                return f'    <polyline points="{points}" {attrs_str} fill="none"/>'

        # --- Ellipses ---
        elif op_type in ('e', 'E'):
            rect = op.get('rect')
            if not rect or len(rect) < 4:
                return ''
            cx, cy, rx, ry = rect
            return f'    <ellipse cx="{cx}" cy="{cy}" rx="{rx}" ry="{ry}" {attrs_str} />'

        # --- Text ---
        elif op_type in ('t', 'T'):
            # Graphviz may use pos, pt or rect
            if 'pos' in op:
                x, y = op['pos']
            elif 'pt' in op:
                x, y = op['pt']
            elif 'rect' in op and len(op['rect']) >= 2:
                x, y = op['rect'][0], op['rect'][1]
            else:
                return ''
            
            anchor = {'l': 'start', 'c': 'middle', 'r': 'end'}.get(op.get('align'), 'start')
            text = self._escape_html(op.get('text', ''))

            font_family = style.get("face", "Arial")
            font_size = style.get("size", 14)
            fill = style.get("stroke", "#000000")

            return (
                f'    <text x="{x}" y="{y}" '
                f'transform="translate({x},{y}) scale(1,-1) translate({-x},{-y})" '
                f'font-family="{font_family}" '
                f'font-size="{font_size}" '
                f'text-anchor="{anchor}" '
                f'fill="{fill}">{text}</text>'
            )

        # --- Images ---
        elif op_type == 'I':
            # Graphviz may use pos or rect
            if 'pos' in op:
                x, y = op['pos']
            elif 'rect' in op and len(op['rect']) >= 2:
                x, y = op['rect'][0], op['rect'][1]
            else:
                return ''

            if 'size' in op:
                w, h = op['size']
            elif 'rect' in op and len(op['rect']) >= 4:
                w, h = op['rect'][2], op['rect'][3]
            else:
                return ''

            src = op.get('name')
            if not src:
                return ''

            icon = self._load_image(src)
            if not icon:
                return ''

            if icon.lstrip().startswith('<svg'):
                scale = min(w, h) / 100.0
                return (
                    f'    <g transform="translate({x},{y}) scale({scale})">'
                    f'{icon}'
                    f'</g>'
                )
            else:
                return (
                    f'    <image href="{icon}" '
                    f'x="{x}" y="{y}" '
                    f'width="{w}" height="{h}" />'
                )

        return ''
    


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
    

    def _extract_image_from_html_label(self, node: Dict, is_server_layout: bool, node_x: float, node_y: float) -> Optional[str]:
        """Extract image path from HTML label and render it as SVG with proper centering"""
        import re
        
        label = node.get('label', '')
        match = re.search(r'<IMG\s+SRC="([^"]+)"', label, re.IGNORECASE)
        if not match:
            return None
        
        image_path = match.group(1)
        
        # Load the image
        image_data = self._load_image(image_path)
        if not image_data:
            return None
        
        # Icon size (30x30 as specified in HTML label)
        icon_size = 30
        
        # Get node width for server layout positioning
        node_width_inches = float(node.get('width', 1.5))
        node_width = node_width_inches * 72  # Convert to points
        
        if image_data.lstrip().startswith('<'):
            # SVG inline
            svg_clean = re.sub(r'<\?xml[^?]*\?>\s*', '', image_data)
            svg_clean = re.sub(r'<!DOCTYPE[^>]*>\s*', '', svg_clean)
            
            # Calculate scale
            viewbox_match = re.search(r'viewBox=["\']([^"\']+)["\']', svg_clean)
            if viewbox_match:
                parts = viewbox_match.group(1).split()
                if len(parts) >= 4:
                    svg_width = float(parts[2])
                    svg_height = float(parts[3])
                    scale = icon_size / max(svg_width, svg_height)
                else:
                    scale = icon_size / 100
            else:
                width_match = re.search(r'width=["\']?(\d+(?:\.\d+)?)', svg_clean)
                height_match = re.search(r'height=["\']?(\d+(?:\.\d+)?)', svg_clean)
                if width_match and height_match:
                    svg_width = float(width_match.group(1))
                    svg_height = float(height_match.group(1))
                    scale = icon_size / max(svg_width, svg_height)
                else:
                    scale = icon_size / 100
            
            if is_server_layout:
                # Server layout: position icon at left edge with padding
                padding = 10
                # Icon center should be at: -node_width/2 + padding + icon_size/2
                icon_center_offset_x = -node_width/2 + padding + icon_size/2
                icon_offset_y = -icon_size / 2
                
                return (
                    f'    <g transform="translate({node_x},{node_y}) scale({scale},-{scale}) translate({icon_center_offset_x/scale},{icon_offset_y/scale})">'
                    f'{svg_clean}'
                    f'</g>'
                )
            else:
                # Top-and-bottom layout: center the icon
                offset = -icon_size / 2
                
                return (
                    f'    <g transform="translate({node_x},{node_y}) scale({scale},-{scale}) translate({offset/scale},{offset/scale})">'
                    f'{svg_clean}'
                    f'</g>'
                )
        else:
            # Base64 image
            if is_server_layout:
                # Server layout: position icon at left edge with padding
                padding = 10
                icon_x = node_x - node_width/2 + padding
                icon_y = node_y - icon_size / 2
            else:
                # Top-and-bottom layout: center the icon
                icon_x = node_x - icon_size / 2
                icon_y = node_y - icon_size / 2
            
            return (
                f'    <image href="{image_data}" '
                f'x="{icon_x}" y="{icon_y}" '
                f'width="{icon_size}" height="{icon_size}" '
                f'transform="translate({node_x},{node_y}) scale(1,-1) translate({-node_x},{-node_y})" />'
            )