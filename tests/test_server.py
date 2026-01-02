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

import pytest
import json
import os
from unittest.mock import patch, MagicMock, mock_open
from io import BytesIO
import base64
import sys

# This is a bit tricky. We need to add the project root to the path
# BEFORE we import the app, so the app can find its own modules.
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Now we can import the app
from threat_analysis.server.server import app, run_gui, DEFAULT_EMPTY_MARKDOWN, threat_model_service

@pytest.fixture
def client():
    """Create a test client for the Flask app."""
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

def test_index_route(client):
    """Test the main route that serves the web interface."""
    response = client.get('/')
    assert response.status_code == 200
    assert b'Threat Model Editor' in response.data

def test_update_api_success(client):
    """Test the /api/update endpoint with valid markdown."""
    with patch('threat_analysis.server.server.threat_model_service.update_diagram_logic') as mock_update_diagram_logic:
        mock_update_diagram_logic.return_value = {
            "diagram_html": "<html>Diagram</html>",
            "diagram_svg": "<svg>mocked svg</svg>",
            "legend_html": "<div>Legend</div>",
        }
        markdown_payload = {'markdown': """## Actors
- User"""}
        response = client.post('/api/update', data=json.dumps(markdown_payload), content_type='application/json')

        assert response.status_code == 200
        json_data = response.get_json()
        assert 'diagram_html' in json_data
        assert json_data['diagram_html'] == "<html>Diagram</html>"
        mock_update_diagram_logic.assert_called_once_with(markdown_payload['markdown'])

def test_update_api_empty_markdown(client):
    """Test the /api/update endpoint with empty markdown content."""
    with patch('threat_analysis.server.server.threat_model_service.update_diagram_logic') as mock_update_diagram_logic:
        mock_update_diagram_logic.side_effect = ValueError("Markdown content is empty")
        markdown_payload = {'markdown': ''}
        response = client.post('/api/update', data=json.dumps(markdown_payload), content_type='application/json')
        assert response.status_code == 400
        json_data = response.get_json()
        assert 'error' in json_data
        assert json_data['error'] == 'Markdown content is empty'

@pytest.mark.parametrize("export_format", ["svg", "diagram", "report"])
def test_export_api_success(client, export_format):
    """Test the /api/export endpoint for all supported formats."""
    # Save original sys.argv and temporarily set it to avoid argparse conflicts with pytm
    original_argv = sys.argv
    sys.argv = [original_argv[0]] # Set to script name only

    try:
        with patch('threat_analysis.server.server.threat_model_service.export_files_logic') as mock_export_files_logic, \
             patch('threat_analysis.server.server.send_from_directory') as mock_send:

            mock_export_files_logic.return_value = ("/fake/path/to/output", "mock_file.ext")
            mock_send.return_value = MagicMock(status_code=200)
            markdown_payload = {'markdown': """## Actors
- User""", 'format': export_format}
            response = client.post('/api/export', data=json.dumps(markdown_payload), content_type='application/json')

            assert response.status_code == 200
            mock_export_files_logic.assert_called_once_with(markdown_payload['markdown'], export_format)
            mock_send.assert_called_once_with("/fake/path/to", "mock_file.ext", as_attachment=True)
    finally:
        # Restore original sys.argv
        sys.argv = original_argv

def test_export_api_invalid_format(client):
    """Test the /api/export endpoint with an invalid format."""
    with patch('threat_analysis.server.server.threat_model_service.export_files_logic') as mock_export_files_logic:
        mock_export_files_logic.side_effect = ValueError("Invalid export format")
        markdown_payload = {'markdown': """## Actors
- User""", 'format': 'invalid_format'}
        response = client.post('/api/export', data=json.dumps(markdown_payload), content_type='application/json')
        assert response.status_code == 400
        json_data = response.get_json()
        assert 'error' in json_data
        assert json_data['error'] == 'Invalid export format'
        mock_export_files_logic.assert_called_once_with(markdown_payload['markdown'], markdown_payload['format'])

def test_export_api_missing_data(client):
    """Test the /api/export endpoint with missing markdown or format."""
    # Missing format
    payload_no_format = {'markdown': 'some content'}
    response = client.post('/api/export', data=json.dumps(payload_no_format), content_type='application/json')
    assert response.status_code == 400
    json_data = response.get_json()
    assert 'error' in json_data
    assert json_data['error'] == 'Missing markdown content or export format'

    # Missing markdown
    payload_no_markdown = {'format': 'svg'}
    response = client.post('/api/export', data=json.dumps(payload_no_markdown), content_type='application/json')
    assert response.status_code == 400
    json_data = response.get_json()
    assert 'error' in json_data
    assert json_data['error'] == 'Missing markdown content or export format'



def test_run_gui_with_no_model_file(client):
    """Test that run_gui starts with DEFAULT_EMPTY_MARKDOWN if no model file is provided."""
    with patch('os.path.exists', return_value=False): # Simulate file not found
        with patch('threat_analysis.server.server.app.run'): # Prevent Flask from actually running
            with patch('threat_analysis.server.server.render_template') as mock_render_template:
                run_gui(model_filepath=None)
                # After run_gui, the global initial_markdown_content should be set
                # We then make a request to the index route to get the rendered HTML
                client.get('/') # This will call the real index route, which calls render_template
                mock_render_template.assert_called_once_with('web_interface.html', initial_markdown=base64.b64encode(DEFAULT_EMPTY_MARKDOWN.encode('utf-8')).decode('utf-8'), model_name='New Model')

def test_run_gui_with_non_existent_model_file(client):
    """Test that run_gui starts with DEFAULT_EMPTY_MARKDOWN if a non-existent model file is provided."""
    with patch('os.path.exists', return_value=False): # Simulate file not found
        with patch('threat_analysis.server.server.app.run'): # Prevent Flask from actually running
            with patch('threat_analysis.server.server.render_template') as mock_render_template:
                run_gui(model_filepath='/non/existent/path/to/model.md')
                client.get('/') # This will call the real index route, which calls render_template
                mock_render_template.assert_called_once_with('web_interface.html', initial_markdown=base64.b64encode(DEFAULT_EMPTY_MARKDOWN.encode('utf-8')).decode('utf-8'), model_name='New Model')

def test_run_gui_with_existing_model_file(client):
    """Test that run_gui loads content from an existing model file."""
    mock_file_content = "# Threat Model: Test Model\n## Description\nA test model."
    with patch('os.path.exists', return_value=True):
        with patch('builtins.open', mock_open(read_data=mock_file_content)) as mock_file:
            with patch('threat_analysis.server.server.app.run'):
                with patch('threat_analysis.server.server.render_template') as mock_render_template:
                    run_gui(model_filepath='/path/to/existing/model.md')
                    client.get('/')
                    expected_encoded_markdown = base64.b64encode(mock_file_content.encode('utf-8')).decode('utf-8')
                    mock_render_template.assert_called_once_with('web_interface.html', initial_markdown=expected_encoded_markdown, model_name='Test Model')
                    mock_file.assert_called_once_with('/path/to/existing/model.md', "r", encoding="utf-8")

def test_export_all_api_success(client):
    """Test the /api/export_all endpoint for successful ZIP file generation."""
    mock_markdown = "# Test Model"
    with patch('threat_analysis.server.server.threat_model_service.export_all_files_logic') as mock_export_all_files_logic, \
         patch('threat_analysis.server.server.send_file') as mock_send_file:

        mock_export_all_files_logic.return_value = (BytesIO(b"zip_content"), "2025-01-01_12-00-00")
        mock_send_file.return_value = MagicMock(status_code=200, data=b'zip_content')

        markdown_payload = {'markdown': mock_markdown}
        response = client.post('/api/export_all', data=json.dumps(markdown_payload), content_type='application/json')

        assert response.status_code == 200
        mock_export_all_files_logic.assert_called_once_with(mock_markdown)
        mock_send_file.assert_called_once()

def test_export_all_api_missing_markdown(client):
    """Test the /api/export_all endpoint with missing markdown content."""
    with patch('threat_analysis.server.server.threat_model_service.export_all_files_logic') as mock_export_all_files_logic:
        mock_export_all_files_logic.side_effect = ValueError("Missing markdown content")
        response = client.post('/api/export_all', data=json.dumps({}), content_type='application/json')
        assert response.status_code == 400
        json_data = response.get_json()
        assert 'error' in json_data
        assert json_data['error'] == 'Missing markdown content'

def test_update_api_with_full_model_content(client):
    """Test the /api/update endpoint with a full threat model content (simulating paste)."""
    full_markdown_content = """
# Threat Model: Example System

## Description
A simple example system.

## Boundaries
- **Internet**: color=red

## Actors
- **External User**: boundary=Internet

## Servers
- **Web Server**: boundary=Internet

## Dataflows
- **Request**: from="External User", to="Web Server", protocol="HTTPS"
"""

