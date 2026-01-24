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
Test module for graphviz_to_konva.py
This module tests the Graphviz to Konva conversion functionality.
"""

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock
import xml.etree.ElementTree as ET

# Add project root to sys.path
import sys
project_root = Path(__file__).parent.parent
sys.path.append(str(project_root))

from threat_analysis.generation.graphviz_to_konva import GraphvizToKonvaConverter


class TestGraphvizToKonvaConverter(unittest.TestCase):
    """Test cases for GraphvizToKonvaConverter class"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.converter = GraphvizToKonvaConverter()
        self.temp_dir = tempfile.mkdtemp()
        
    def tearDown(self):
        """Clean up test fixtures"""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_extract_canvas_info(self):
        """Test canvas info extraction"""
        # Create a mock SVG root element
        root = ET.Element('svg')
        root.set('viewBox', '0 0 1024 768')
        
        canvas_info = self.converter._extract_canvas_info(root)
        self.assertEqual(canvas_info['x'], 0)
        self.assertEqual(canvas_info['y'], 0)
        self.assertEqual(canvas_info['width'], 1024)
        self.assertEqual(canvas_info['height'], 768)
    
    def test_extract_canvas_info_default(self):
        """Test canvas info extraction with default values"""
        root = ET.Element('svg')
        canvas_info = self.converter._extract_canvas_info(root)
        self.assertEqual(canvas_info['width'], 800)
        self.assertEqual(canvas_info['height'], 600)
    
    def test_parse_points(self):
        """Test points parsing"""
        points_str = "10,20 30,40 50,60"
        points = self.converter._parse_points(points_str)
        self.assertEqual(len(points), 3)
        self.assertEqual(points[0], (10.0, 20.0))
        self.assertEqual(points[1], (30.0, 40.0))
        self.assertEqual(points[2], (50.0, 60.0))
    
    def test_parse_points_empty(self):
        """Test empty points parsing"""
        points = self.converter._parse_points("")
        self.assertEqual(len(points), 0)
    
    def test_parse_path_to_points(self):
        """Test path parsing to points"""
        path_data = "M10,20 L30,40 L50,60"
        points = self.converter._parse_path_to_points(path_data)
        self.assertEqual(len(points), 3)
        self.assertEqual(points[0]['x'], 10.0)
        self.assertEqual(points[0]['y'], 20.0)
    
    def test_extract_text_content(self):
        """Test text content extraction"""
        # Create a mock text element with tspan
        # Note: We need to use the SVG namespace for proper XML parsing
        text = ET.Element('text')
        text.text = "Main text"
        
        tspan1 = ET.SubElement(text, 'tspan')
        tspan1.text = "Sub text 1"
        
        tspan2 = ET.SubElement(text, 'tspan')
        tspan2.text = "Sub text 2"
        
        content = self.converter._extract_text_content(text)
        self.assertIn("Main text", content)
        # The tspan elements are found using .//svg:tspan, but since we're not using
        # the namespace in this test, they won't be found. So we only test main text.
        self.assertEqual(content.strip(), "Main text")
    
    def test_extract_text_content_empty(self):
        """Test empty text content extraction"""
        content = self.converter._extract_text_content(None)
        self.assertEqual(content, '')
    
    def test_extract_node_styles(self):
        """Test node styles extraction"""
        element = ET.Element('rect')
        element.set('fill', 'red')
        element.set('stroke', 'blue')
        element.set('stroke-width', '2')
        element.set('style', 'fill: green; stroke: yellow; stroke-width: 3px')
        
        styles = self.converter._extract_node_styles(element)
        self.assertEqual(styles['fill'], 'green')  # style attr should override
        self.assertEqual(styles['stroke'], 'yellow')  # style attr should override
        self.assertEqual(styles['strokeWidth'], 3.0)
    
    def test_extract_edge_styles(self):
        """Test edge styles extraction"""
        element = ET.Element('path')
        element.set('stroke', 'red')
        element.set('stroke-width', '2')
        element.set('stroke-dasharray', '5,5')
        
        styles = self.converter._extract_edge_styles(element)
        self.assertEqual(styles['stroke'], 'red')
        self.assertEqual(styles['strokeWidth'], 2.0)
        self.assertEqual(styles['dash'], [5.0, 5.0])
    
    def test_extract_boundary_styles(self):
        """Test boundary styles extraction"""
        element = ET.Element('polygon')
        element.set('fill', 'lightgray')
        element.set('stroke', 'black')
        element.set('stroke-width', '1')
        
        styles = self.converter._extract_boundary_styles(element)
        self.assertEqual(styles['fill'], 'lightgray')
        self.assertEqual(styles['stroke'], 'black')
        self.assertEqual(styles['strokeWidth'], 1.0)
    
    def test_determine_node_type(self):
        """Test node type determination"""
        # Test actor
        node_type = self.converter._determine_node_type("actor1", "User")
        self.assertEqual(node_type, 'actor')
        
        # Test database - need to include "database" in the ID
        node_type = self.converter._determine_node_type("database1", "Database")
        self.assertEqual(node_type, 'database')
        
        # Test web server
        node_type = self.converter._determine_node_type("web_server", "Web Server")
        self.assertEqual(node_type, 'web_server')
        
        # Test default (server)
        node_type = self.converter._determine_node_type("node1", "Node")
        self.assertEqual(node_type, 'server')
    
    def test_extract_protocol(self):
        """Test protocol extraction"""
        # Test from label
        label = "Connection Protocol: HTTPS"
        protocol = self.converter._extract_protocol(label, "")
        self.assertEqual(protocol, 'HTTPS')
        
        # Test from class
        protocol = self.converter._extract_protocol("", "HTTP TCP SSH")
        self.assertEqual(protocol, 'HTTP')
        
        # Test no protocol
        protocol = self.converter._extract_protocol("", "")
        self.assertEqual(protocol, '')
    
    def test_extract_shape_bounds_ellipse(self):
        """Test ellipse shape bounds extraction"""
        element = ET.Element('ellipse')
        element.set('cx', '100')
        element.set('cy', '100')
        element.set('rx', '50')
        element.set('ry', '30')
        
        position, dimensions = self.converter._extract_shape_bounds(element, 'ellipse')
        self.assertEqual(position['x'], 50)  # cx - rx
        self.assertEqual(position['y'], 70)  # cy - ry
        self.assertEqual(dimensions['width'], 100)  # rx * 2
        self.assertEqual(dimensions['height'], 60)  # ry * 2
    
    def test_extract_shape_bounds_rect(self):
        """Test rectangle shape bounds extraction"""
        element = ET.Element('rect')
        element.set('x', '10')
        element.set('y', '20')
        element.set('width', '100')
        element.set('height', '50')
        
        position, dimensions = self.converter._extract_shape_bounds(element, 'rect')
        self.assertEqual(position['x'], 10.0)
        self.assertEqual(position['y'], 20.0)
        self.assertEqual(dimensions['width'], 100.0)
        self.assertEqual(dimensions['height'], 50.0)
    
    def test_extract_boundary_bounds_polygon(self):
        """Test polygon boundary bounds extraction"""
        element = ET.Element('polygon')
        element.set('points', '0,0 100,0 100,100 0,100')
        
        bounds = self.converter._extract_boundary_bounds(element)
        self.assertEqual(bounds['x'], 0)
        self.assertEqual(bounds['y'], 0)
        self.assertEqual(bounds['width'], 100)
        self.assertEqual(bounds['height'], 100)
    
    def test_extract_boundary_bounds_rect(self):
        """Test rectangle boundary bounds extraction"""
        element = ET.Element('rect')
        element.set('x', '10')
        element.set('y', '20')
        element.set('width', '200')
        element.set('height', '150')
        
        bounds = self.converter._extract_boundary_bounds(element)
        self.assertEqual(bounds['x'], 10.0)
        self.assertEqual(bounds['y'], 20.0)
        self.assertEqual(bounds['width'], 200.0)
        self.assertEqual(bounds['height'], 150.0)
    
    def test_save_metadata_success(self):
        """Test successful metadata saving"""
        metadata = {
            'version': '1.0',
            'nodes': [],
            'edges': [],
            'boundaries': []
        }
        
        output_path = Path(self.temp_dir) / "test_metadata.json"
        result = self.converter.save_metadata(metadata, output_path)
        
        self.assertTrue(result)
        self.assertTrue(output_path.exists())
        
        # Verify content
        with open(output_path, 'r', encoding='utf-8') as f:
            saved_data = json.load(f)
        
        self.assertEqual(saved_data, metadata)
    
    def test_save_metadata_failure(self):
        """Test metadata saving failure"""
        metadata = {'version': '1.0'}
        
        # Try to save to invalid path
        invalid_path = Path("/invalid/path/metadata.json")
        result = self.converter.save_metadata(metadata, invalid_path)
        
        self.assertFalse(result)
    
    def test_extract_metadata_from_svg_invalid_file(self):
        """Test metadata extraction from invalid SVG file"""
        invalid_path = Path("/invalid/path/file.svg")
        result = self.converter.extract_metadata_from_svg(invalid_path)
        self.assertIsNone(result)
    
    def test_extract_metadata_from_svg_malformed(self):
        """Test metadata extraction from malformed SVG"""
        # Create a temporary malformed SVG file
        svg_path = Path(self.temp_dir) / "malformed.svg"
        svg_path.write_text("<svg><invalid></svg>")
        
        result = self.converter.extract_metadata_from_svg(svg_path)
        self.assertIsNone(result)
    
    def test_extract_metadata_from_svg_empty(self):
        """Test metadata extraction from empty SVG"""
        # Create a temporary empty SVG file
        svg_path = Path(self.temp_dir) / "empty.svg"
        svg_path.write_text("<svg></svg>")
        
        result = self.converter.extract_metadata_from_svg(svg_path)
        self.assertIsNotNone(result)
        self.assertEqual(result['version'], '1.0')
        self.assertEqual(result['generator'], 'graphviz')
    
    def test_extract_node_metadata_missing_shape(self):
        """Test node metadata extraction when shape is missing"""
        # Create a mock node group without shape
        g = ET.Element('g')
        g.set('class', 'node')
        g.set('id', 'node1')
        
        result = self.converter._extract_node_metadata(g)
        self.assertIsNone(result)
    
    def test_extract_edge_metadata_missing_path(self):
        """Test edge metadata extraction when path is missing"""
        # Create a mock edge group without path
        g = ET.Element('g')
        g.set('class', 'edge')
        g.set('id', 'edge1')
        
        result = self.converter._extract_edge_metadata(g)
        self.assertIsNone(result)
    
    def test_extract_boundary_metadata_missing_shape(self):
        """Test boundary metadata extraction when shape is missing"""
        # Create a mock boundary group without shape
        g = ET.Element('g')
        g.set('class', 'cluster')
        g.set('id', 'cluster_boundary1')
        
        result = self.converter._extract_boundary_metadata(g)
        self.assertIsNone(result)
    
    def test_integration_simple_svg(self):
        """Integration test with a simple SVG structure"""
        # Create a simple SVG with one node
        svg_content = '''<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 200 100">
  <g class="node" id="node1">
    <title>Server</title>
    <ellipse cx="50" cy="50" rx="40" ry="25" fill="lightblue" stroke="blue"/>
    <text x="50" y="50" text-anchor="middle">Server</text>
  </g>
</svg>'''
        
        svg_path = Path(self.temp_dir) / "simple.svg"
        svg_path.write_text(svg_content)
        
        metadata = self.converter.extract_metadata_from_svg(svg_path)
        
        self.assertIsNotNone(metadata)
        self.assertEqual(len(metadata['nodes']), 1)
        self.assertEqual(metadata['nodes'][0]['id'], 'node1')
        # The name comes from the title element, not the text
        self.assertEqual(metadata['nodes'][0]['name'], 'Server')
        self.assertEqual(metadata['nodes'][0]['type'], 'server')
        self.assertEqual(metadata['nodes'][0]['shape'], 'ellipse')


if __name__ == '__main__':
    unittest.main()
