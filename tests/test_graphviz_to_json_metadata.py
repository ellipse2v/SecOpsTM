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
Test module for graphviz_to_json_metadata.py
This module tests the Graphviz JSON to metadata conversion functionality.
"""

import unittest
from pathlib import Path
from unittest.mock import MagicMock

# Add project root to sys.path
import sys
project_root = Path(__file__).parent.parent
sys.path.append(str(project_root))

from threat_analysis.generation.graphviz_to_json_metadata import GraphvizToJsonMetadataConverter


class TestGraphvizToJsonMetadataConverter(unittest.TestCase):
    """Test cases for GraphvizToJsonMetadataConverter class"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.converter = GraphvizToJsonMetadataConverter()
        
        # Create a mock threat model
        self.threat_model = MagicMock()
        self.threat_model.boundaries = {
            "Internet": {},
            "Internal Network": {}
        }
        self.threat_model.actors = [
            {"name": "User"},
            {"name": "Admin"}
        ]
        self.threat_model.servers = [
            {"name": "Web Server"},
            {"name": "Database Server"}
        ]
    
    def test_sanitize_name(self):
        """Test name sanitization"""
        self.assertEqual(self.converter._sanitize_name("Test Name"), "test_name")
        self.assertEqual(self.converter._sanitize_name("ANOTHER_TEST"), "another_test")
        self.assertEqual(self.converter._sanitize_name("mixed Case"), "mixed_case")
    
    def test_convert_empty_graphviz_json(self):
        """Test conversion with empty Graphviz JSON"""
        graphviz_json = {
            "bb": "0,0,100,100",
            "objects": []
        }
        
        result = self.converter.convert(graphviz_json, self.threat_model)
        
        # Should return empty positions structure
        self.assertEqual(result, {
            "boundaries": {},
            "actors": {},
            "servers": {},
            "data": {}
        })
    
    def test_convert_with_boundaries(self):
        """Test conversion with boundary clusters"""
        graphviz_json = {
            "bb": "0,0,800,600",
            "objects": [
                {
                    "name": "cluster_Internet",
                    "label": "Internet",
                    "bb": "50,50,300,200"
                },
                {
                    "name": "cluster_Internal_Network", 
                    "label": "Internal Network",
                    "bb": "350,100,700,400"
                }
            ]
        }
        
        result = self.converter.convert(graphviz_json, self.threat_model)
        
        # Check boundaries are processed correctly
        self.assertIn("Internet", result["boundaries"])
        self.assertIn("Internal Network", result["boundaries"])
        
        # Check Internet boundary position and dimensions
        internet_boundary = result["boundaries"]["Internet"]
        self.assertEqual(internet_boundary["x"], 50.0)
        self.assertEqual(internet_boundary["y"], 400.0)  # 600 - 200 (flipped Y)
        self.assertEqual(internet_boundary["width"], 250.0)  # 300 - 50
        self.assertEqual(internet_boundary["height"], 150.0)  # 200 - 50
        
        # Check Internal Network boundary
        internal_boundary = result["boundaries"]["Internal Network"]
        self.assertEqual(internal_boundary["x"], 350.0)
        self.assertEqual(internal_boundary["y"], 200.0)  # 600 - 400 (flipped Y)
        self.assertEqual(internal_boundary["width"], 350.0)  # 700 - 350
        self.assertEqual(internal_boundary["height"], 300.0)  # 400 - 100
    
    def test_convert_with_actors_and_servers(self):
        """Test conversion with actor and server nodes"""
        graphviz_json = {
            "bb": "0,0,800,600",
            "objects": [
                {
                    "name": "User",
                    "pos": "100,100",
                    "width": 1.0,
                    "height": 0.5
                },
                {
                    "name": "Web_Server",
                    "pos": "400,200", 
                    "width": 1.5,
                    "height": 1.0
                }
            ]
        }
        
        result = self.converter.convert(graphviz_json, self.threat_model)
        
        # Check actors are processed correctly
        self.assertIn("User", result["actors"])
        user_actor = result["actors"]["User"]
        self.assertEqual(user_actor["x"], 100.0 - (72 * 1.0 / 2))  # x - width/2
        self.assertEqual(user_actor["y"], 600.0 - (100.0 + (72 * 0.5 / 2)))  # flipped Y
        self.assertEqual(user_actor["width"], 72.0)  # 1.0 inch to points
        self.assertEqual(user_actor["height"], 36.0)  # 0.5 inch to points
        
        # Check servers are processed correctly
        self.assertIn("Web_Server", result["servers"])
        web_server = result["servers"]["Web_Server"]
        self.assertEqual(web_server["x"], 400.0 - (72 * 1.5 / 2))
        self.assertEqual(web_server["y"], 600.0 - (200.0 + (72 * 1.0 / 2)))
        self.assertEqual(web_server["width"], 108.0)  # 1.5 inches to points
        self.assertEqual(web_server["height"], 72.0)  # 1.0 inch to points
    
    def test_convert_mixed_elements(self):
        """Test conversion with mixed clusters and nodes"""
        graphviz_json = {
            "bb": "0,0,1000,800",
            "objects": [
                # Cluster (boundary)
                {
                    "name": "cluster_Internet",
                    "label": "Internet",
                    "bb": "50,50,400,300"
                },
                # Actor node
                {
                    "name": "User",
                    "pos": "100,100",
                    "width": 0.8,
                    "height": 0.4
                },
                # Server node
                {
                    "name": "Database_Server",
                    "pos": "600,400",
                    "width": 2.0,
                    "height": 1.2
                }
            ]
        }
        
        result = self.converter.convert(graphviz_json, self.threat_model)
        
        # Verify all categories are populated
        self.assertEqual(len(result["boundaries"]), 1)
        self.assertEqual(len(result["actors"]), 1)
        self.assertEqual(len(result["servers"]), 1)
        self.assertEqual(len(result["data"]), 0)
        
        # Verify boundary
        internet_boundary = result["boundaries"]["Internet"]
        self.assertEqual(internet_boundary["x"], 50.0)
        self.assertEqual(internet_boundary["y"], 500.0)  # 800 - 300
        
        # Verify actor
        user_actor = result["actors"]["User"]
        self.assertAlmostEqual(user_actor["x"], 100.0 - (72 * 0.8 / 2), places=2)
        self.assertAlmostEqual(user_actor["y"], 800.0 - (100.0 + (72 * 0.4 / 2)), places=2)
        
        # Verify server
        db_server = result["servers"]["Database_Server"]
        self.assertAlmostEqual(db_server["x"], 600.0 - (72 * 2.0 / 2), places=2)
        self.assertAlmostEqual(db_server["y"], 800.0 - (400.0 + (72 * 1.2 / 2)), places=2)
    
    def test_process_cluster_missing_label(self):
        """Test cluster processing with missing label"""
        cluster = {
            "name": "cluster_test",
            "bb": "0,0,100,100"
            # No label field
        }
        
        positions = {"boundaries": {}, "actors": {}, "servers": {}, "data": {}}
        name_to_type = {"test": "boundaries"}
        
        # Should not raise an exception and should not add to positions
        self.converter._process_cluster(cluster, positions, name_to_type, 600.0)
        self.assertEqual(len(positions["boundaries"]), 0)
    
    def test_process_cluster_missing_bb(self):
        """Test cluster processing with missing bounding box"""
        cluster = {
            "name": "cluster_test",
            "label": "test"
            # No bb field
        }
        
        positions = {"boundaries": {}, "actors": {}, "servers": {}, "data": {}}
        name_to_type = {"test": "boundaries"}
        
        # Should not raise an exception and should not add to positions
        self.converter._process_cluster(cluster, positions, name_to_type, 600.0)
        self.assertEqual(len(positions["boundaries"]), 0)
    
    def test_process_node_missing_name(self):
        """Test node processing with missing name"""
        node = {
            "pos": "100,100",
            "width": 1.0,
            "height": 1.0
            # No name field
        }
        
        positions = {"boundaries": {}, "actors": {}, "servers": {}, "data": {}}
        name_to_type = {"test": "actors"}
        
        # Should not raise an exception and should not add to positions
        self.converter._process_node(node, positions, name_to_type, 600.0)
        self.assertEqual(len(positions["actors"]), 0)
    
    def test_process_node_missing_pos(self):
        """Test node processing with missing position"""
        node = {
            "name": "test",
            "width": 1.0,
            "height": 1.0
            # No pos field
        }
        
        positions = {"boundaries": {}, "actors": {}, "servers": {}, "data": {}}
        name_to_type = {"test": "actors"}
        
        # Should not raise an exception and should not add to positions
        self.converter._process_node(node, positions, name_to_type, 600.0)
        self.assertEqual(len(positions["actors"]), 0)
    
    def test_process_node_unknown_type(self):
        """Test node processing with unknown element type"""
        node = {
            "name": "unknown_element",
            "pos": "100,100",
            "width": 1.0,
            "height": 1.0
        }
        
        positions = {"boundaries": {}, "actors": {}, "servers": {}, "data": {}}
        name_to_type = {}  # Empty mapping
        
        # Should not raise an exception and should not add to positions
        self.converter._process_node(node, positions, name_to_type, 600.0)
        self.assertEqual(len(positions["actors"]), 0)
        self.assertEqual(len(positions["servers"]), 0)
        self.assertEqual(len(positions["boundaries"]), 0)
    
    def test_process_cluster_non_boundary_type(self):
        """Test cluster processing with non-boundary type"""
        cluster = {
            "name": "cluster_test",
            "label": "test",
            "bb": "0,0,100,100"
        }
        
        positions = {"boundaries": {}, "actors": {}, "servers": {}, "data": {}}
        name_to_type = {"test": "actors"}  # Cluster mapped to actors instead of boundaries
        
        # Should not raise an exception and should not add to positions
        self.converter._process_cluster(cluster, positions, name_to_type, 600.0)
        self.assertEqual(len(positions["boundaries"]), 0)


if __name__ == "__main__":
    unittest.main()