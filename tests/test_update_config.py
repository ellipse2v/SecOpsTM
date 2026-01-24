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
Test module for update_config.py
This module tests the configuration update functionality.
"""

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

# Add project root to sys.path
project_root = Path(__file__).parent.parent
sys.path.append(str(project_root))

from threat_analysis.update_config import main as update_config_main
from threat_analysis.config_generator import generate_config_js, main as config_generator_main


class TestConfigGenerator(unittest.TestCase):
    """Test cases for config_generator.py"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.temp_dir = tempfile.mkdtemp()
        self.output_path = Path(self.temp_dir) / "config.js"
        
    def tearDown(self):
        """Clean up test fixtures"""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_generate_config_js_success(self):
        """Test successful config.js generation"""
        result = generate_config_js(self.output_path)
        self.assertTrue(result)
        self.assertTrue(self.output_path.exists())
        
        # Verify file content
        content = self.output_path.read_text()
        self.assertIn("ThreatModelConfig", content)
        self.assertIn("ICON_MAPPING", content)
        self.assertIn("DEFAULT_PROPERTIES", content)
    
    def test_generate_config_js_existing_file(self):
        """Test config.js generation when file already exists"""
        # Generate once
        result1 = generate_config_js(self.output_path)
        self.assertTrue(result1)
        
        # Generate again - should still succeed
        result2 = generate_config_js(self.output_path)
        self.assertTrue(result2)
    
    def test_generate_config_js_invalid_path(self):
        """Test config.js generation with invalid path"""
        invalid_path = Path("/invalid/path/config.js")
        result = generate_config_js(invalid_path)
        self.assertFalse(result)
    
    def test_config_generator_main_success(self):
        """Test config_generator main function success"""
        with patch('threat_analysis.config_generator.generate_config_js') as mock_generate:
            mock_generate.return_value = True
            result = config_generator_main()
            self.assertEqual(result, 0)
    
    def test_config_generator_main_failure(self):
        """Test config_generator main function failure"""
        with patch('threat_analysis.config_generator.generate_config_js') as mock_generate:
            mock_generate.return_value = False
            result = config_generator_main()
            self.assertEqual(result, 1)


class TestUpdateConfig(unittest.TestCase):
    """Test cases for update_config.py"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.original_path = sys.path.copy()
        self.original_argv = sys.argv.copy()
    
    def tearDown(self):
        """Clean up test fixtures"""
        sys.path = self.original_path
        sys.argv = self.original_argv
    
    @patch('subprocess.run')
    def test_update_config_success(self, mock_run):
        """Test successful configuration update"""
        # Mock successful subprocess run
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "Configuration generated successfully"
        mock_result.stderr = ""
        mock_run.return_value = mock_result
        
        result = update_config_main()
        self.assertEqual(result, 0)
        
        # Verify subprocess was called with correct arguments
        mock_run.assert_called_once()
        args, kwargs = mock_run.call_args
        self.assertIn('config_generator.py', str(args[0]))
    
    @patch('subprocess.run')
    def test_update_config_failure(self, mock_run):
        """Test failed configuration update"""
        # Mock failed subprocess run
        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stdout = ""
        mock_result.stderr = "Error generating config"
        mock_run.return_value = mock_result
        
        result = update_config_main()
        self.assertEqual(result, 1)
    
    @patch('subprocess.run')
    def test_update_config_exception(self, mock_run):
        """Test configuration update with exception"""
        # Mock subprocess to raise exception
        mock_run.side_effect = Exception("Test exception")
        
        result = update_config_main()
        self.assertEqual(result, 1)
    
    def test_update_config_main_integration(self):
        """Test update_config main function integration"""
        # This is a basic integration test - in a real scenario, you might want to
        # test with actual file system operations
        with patch('subprocess.run') as mock_run:
            mock_result = MagicMock()
            mock_result.returncode = 0
            mock_result.stdout = "Success"
            mock_result.stderr = ""
            mock_run.return_value = mock_result
            
            # Test that main() returns 0 on success
            result = update_config_main()
            self.assertEqual(result, 0)


if __name__ == '__main__':
    unittest.main()
