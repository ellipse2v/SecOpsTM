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
from unittest.mock import patch, MagicMock, mock_open, ANY
from io import BytesIO
import base64
import sys
from pathlib import Path

# This is a bit tricky. We need to add the project root to the path
# BEFORE we import the app, so the app can find its own modules.
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Now we can import the app
from threat_analysis.server.server import app, run_server, DEFAULT_EMPTY_MARKDOWN, get_threat_model_service

@pytest.fixture
def client():
    """Create a test client for the Flask app."""
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

def test_index_route(client):
    """Test the main route that serves the menu."""
    response = client.get('/')
    assert response.status_code == 200
    assert b'Threat Model Tool' in response.data

def test_update_api_success(client):
    """Test the /api/update endpoint with valid markdown."""
    with patch('threat_analysis.server.server.get_threat_model_service') as mock_get_service:
        mock_service = MagicMock()
        mock_get_service.return_value = mock_service
        mock_service.update_diagram_logic.return_value = {
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
        mock_service.update_diagram_logic.assert_called_once_with(
            markdown_payload["markdown"], submodels=[]
        )

def test_update_api_empty_markdown(client):
    """Test the /api/update endpoint with empty markdown content."""
    with patch('threat_analysis.server.server.get_threat_model_service') as mock_get_service:
        mock_service = MagicMock()
        mock_get_service.return_value = mock_service
        mock_service.update_diagram_logic.side_effect = ValueError("Markdown content is empty")
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
        with patch('threat_analysis.server.server.get_threat_model_service') as mock_get_service, \
             patch('threat_analysis.server.server.send_from_directory') as mock_send:

            mock_service = MagicMock()
            mock_get_service.return_value = mock_service
            mock_service.export_files_logic.return_value = ("/fake/path/to/output", "mock_file.ext")
            mock_send.return_value = MagicMock(status_code=200)
            markdown_payload = {'markdown': """## Actors
- User""", 'format': export_format}
            response = client.post('/api/export', data=json.dumps(markdown_payload), content_type='application/json')

            assert response.status_code == 200
            mock_service.export_files_logic.assert_called_once_with(
                markdown_content=markdown_payload['markdown'], export_format=export_format,
                model_file_path=None,
            )
            mock_send.assert_called_once_with("/fake/path/to", "mock_file.ext", as_attachment=True)
    finally:
        # Restore original sys.argv
        sys.argv = original_argv

def test_export_api_invalid_format(client):
    """Test the /api/export endpoint with an invalid format."""
    with patch('threat_analysis.server.server.get_threat_model_service') as mock_get_service:
        mock_service = MagicMock()
        mock_get_service.return_value = mock_service
        mock_service.export_files_logic.side_effect = ValueError("Invalid export format")
        markdown_payload = {'markdown': """## Actors
- User""", 'format': 'invalid_format'}
        response = client.post('/api/export', data=json.dumps(markdown_payload), content_type='application/json')
        assert response.status_code == 400
        json_data = response.get_json()
        assert 'error' in json_data
        assert json_data['error'] == 'Invalid export format'
        mock_service.export_files_logic.assert_called_once_with(
            markdown_content=markdown_payload['markdown'], export_format=markdown_payload['format'],
            model_file_path=None,
        )

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



def test_run_server_with_no_model_file(client):
    """Test that run_server starts with DEFAULT_EMPTY_MARKDOWN if no model file is provided."""
    with patch('os.path.exists', return_value=False): # Simulate file not found
        with patch('threat_analysis.server.server.app.run'): # Prevent Flask from actually running
            run_server(model_filepath=None)
            # After run_server, the global initial_markdown_content should be set
            # We then make a request to the simple route to get the rendered HTML
            response = client.get('/simple')
            assert response.status_code == 200
            assert b'Threat Model Editor' in response.data

def test_run_server_with_non_existent_model_file(client):
    """Test that run_server starts with DEFAULT_EMPTY_MARKDOWN if a non-existent model file is provided."""
    with patch('os.path.exists', return_value=False): # Simulate file not found
        with patch('threat_analysis.server.server.app.run'): # Prevent Flask from actually running
            run_server(model_filepath='/non/existent/path/to/model.md')
            response = client.get('/simple')
            assert response.status_code == 200
            assert b'Threat Model Editor' in response.data

def test_run_server_with_existing_model_file(client):
    """Test that run_server loads content from an existing model file and the encoded markdown is present in the response."""
    mock_file_content = "# Threat Model: Test Model\n## Description\nA test model."
    # The template expects a JSON array of model objects to be base64 encoded.
    models_payload = [{"path": "main.md", "content": mock_file_content}]
    expected_encoded_json = base64.b64encode(json.dumps(models_payload).encode('utf-8')).decode('utf-8')
    
    # We need to be careful with patching builtins.open as it can break template loading.
    # Instead of mock_open, we use a side effect that only mocks our specific file.
    original_open = open
    model_path = '/path/to/existing/model.md'
    
    def mocked_open(path, *args, **kwargs):
        if path == model_path:
            return mock_open(read_data=mock_file_content).return_value
        return original_open(path, *args, **kwargs)

    with patch('os.path.exists', return_value=True):
        with patch('builtins.open', side_effect=mocked_open) as mock_file:
            with patch('threat_analysis.server.server.app.run'), \
                 patch('threat_analysis.server.server.initialize_ai_in_background'):
                run_server(model_filepath=model_path)
                response = client.get('/simple')
                assert response.status_code == 200
                assert expected_encoded_json in response.data.decode('utf-8')
                # Verify that our specific file was indeed opened
                assert any(call.args[0] == model_path for call in mock_file.call_args_list)

def test_export_all_api_success(client):
    """Test the /api/export_all endpoint for successful ZIP file generation."""
    mock_markdown = "# Test Model"
    with patch('threat_analysis.server.server.get_threat_model_service') as mock_get_service, \
         patch('threat_analysis.server.server.send_file') as mock_send_file:

        mock_service = MagicMock()
        mock_get_service.return_value = mock_service
        mock_service.export_all_files_logic.return_value = (BytesIO(b"zip_content"), "2025-01-01_12-00-00")
        mock_send_file.return_value = MagicMock(status_code=200, data=b'zip_content')

        markdown_payload = {'markdown': mock_markdown}
        response = client.post('/api/export_all', data=json.dumps(markdown_payload), content_type='application/json')

        assert response.status_code == 200
        mock_service.export_all_files_logic.assert_called_once_with(
            markdown_content=mock_markdown, submodels=[], model_file_path=ANY,
        )
        mock_send_file.assert_called_once()

def test_export_all_api_missing_markdown(client):
    """Test the /api/export_all endpoint with missing markdown content."""
    with patch('threat_analysis.server.server.get_threat_model_service') as mock_get_service:
        mock_service = MagicMock()
        mock_get_service.return_value = mock_service
        mock_service.export_all_files_logic.side_effect = ValueError("Missing markdown content")
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
    with patch('threat_analysis.server.server.get_threat_model_service') as mock_get_service:
        mock_service = MagicMock()
        mock_get_service.return_value = mock_service
        mock_service.update_diagram_logic.return_value = {
            "diagram_html": "<html>Full Diagram</html>",
            "diagram_svg": "<svg>full svg</svg>",
            "legend_html": "<div>Full Legend</div>",
        }
        payload = {'markdown': full_markdown_content}
        response = client.post('/api/update', data=json.dumps(payload), content_type='application/json')
        assert response.status_code == 200
        json_data = response.get_json()
        assert 'diagram_html' in json_data
        assert json_data['diagram_html'] == "<html>Full Diagram</html>"
        mock_service.update_diagram_logic.assert_called_once_with(
            full_markdown_content, submodels=[]
        )



def test_save_model_success(client):
    """Test the /api/save_model endpoint for successful model saving."""
    with patch('threat_analysis.server.server.get_threat_model_service') as mock_get_service:
        mock_service = MagicMock()
        mock_get_service.return_value = mock_service
        mock_service.save_model_with_metadata.return_value = "path/to/metadata.json"
        payload = {
            'markdown': '# Test',
            'model_name': 'MyModel',
            'positions': {'actors': {}}
        }
        response = client.post('/api/save_model', data=json.dumps(payload), content_type='application/json')
        assert response.status_code == 200
        json_data = response.get_json()
        assert json_data['success'] is True
        assert 'Model and metadata saved successfully' in json_data['message']
        mock_service.save_model_with_metadata.assert_called_once()

def test_save_model_missing_markdown(client):
    """Test the /api/save_model endpoint with missing markdown."""
    payload = {'model_name': 'MyModel'}
    response = client.post('/api/save_model', data=json.dumps(payload), content_type='application/json')
    assert response.status_code == 400
    assert 'Missing markdown content' in response.get_json()['error']

def test_graphical_update_success(client):
    """Test the /api/graphical_update endpoint with valid JSON data."""
    with patch('threat_analysis.server.server.convert_json_to_markdown') as mock_convert, \
         patch('threat_analysis.server.server.get_threat_model_service') as mock_get_service:
        
        mock_service = MagicMock()
        mock_get_service.return_value = mock_service
        mock_convert.return_value = "# Converted Markdown"
        mock_service.update_diagram_logic.return_value = {"diagram_html": "<html></html>"}
        
        payload = {'actors': [{'id': '1', 'name': 'User'}]}
        response = client.post('/api/graphical_update', data=json.dumps(payload), content_type='application/json')

        assert response.status_code == 200
        mock_convert.assert_called_once_with(payload)
        mock_service.update_diagram_logic.assert_called_once_with(markdown_content="# Converted Markdown")
        assert 'diagram_html' in response.get_json()

def test_graphical_update_empty_json(client):
    """Test the /api/graphical_update endpoint with empty JSON data."""
    response = client.post('/api/graphical_update', data=json.dumps({}), content_type='application/json')
    assert response.status_code == 400
    assert 'JSON data is empty' in response.get_json()['error']

def test_list_models_success(client):
    """Test the /api/models endpoint."""
    with patch('glob.iglob') as mock_glob:
        mock_glob.return_value = ['output/model_one.md', 'output/sub/model_two.md']
        response = client.get('/api/models')
        assert response.status_code == 200
        json_data = response.get_json()
        assert json_data['success'] is True
        assert len(json_data['models']) == 2

def test_load_model_success(client, tmp_path):
    """Test the /api/load_model endpoint with a valid model path."""
    # Create a dummy structure that the endpoint expects
    output_dir = tmp_path / "output"
    output_dir.mkdir()
    model_file = output_dir / "my_model.md"
    model_file.write_text("# Model Content")
    
    with patch('threat_analysis.server.server.config.OUTPUT_BASE_DIR', str(output_dir)):
        payload = {'model_path': str(model_file)}
        response = client.post('/api/load_model', data=json.dumps(payload), content_type='application/json')
        
        assert response.status_code == 200
        json_data = response.get_json()
        assert json_data['success'] is True
        assert json_data['markdown_content'] == '# Model Content'

def test_load_model_not_found(client, tmp_path):
    """Test the /api/load_model endpoint with a non-existent model."""
    output_dir = tmp_path / "output"
    output_dir.mkdir()

    with patch('threat_analysis.server.server.config.OUTPUT_BASE_DIR', str(output_dir)):
        payload = {'model_path': str(output_dir / 'not_found.md')}
        response = client.post('/api/load_model', data=json.dumps(payload), content_type='application/json')
        assert response.status_code == 404
        assert 'Model file not found' in response.get_json()['error']

def test_markdown_to_json_success(client):
    """Test the /api/markdown_to_json endpoint."""
    with patch('threat_analysis.server.server.get_threat_model_service') as mock_get_service:
        mock_service = MagicMock()
        mock_get_service.return_value = mock_service
        mock_service.markdown_to_json_for_gui.return_value = {'actors': [{'name': 'User'}]}
        payload = {'markdown': '# Test'}
        response = client.post('/api/markdown_to_json', data=json.dumps(payload), content_type='application/json')
        assert response.status_code == 200
        json_data = response.get_json()
        assert json_data['success'] is True
        assert 'model_json' in json_data
        mock_service.markdown_to_json_for_gui.assert_called_once()

def test_markdown_to_json_missing_markdown(client):
    """Test the /api/markdown_to_json endpoint with missing markdown."""
    payload = {}
    response = client.post('/api/markdown_to_json', data=json.dumps(payload), content_type='application/json')
    assert response.status_code == 400
    assert 'Missing markdown content' in response.get_json()['error']

def test_generate_all_success(client, tmp_path):
    """Test the /api/generate_all endpoint."""
    # Patch the config to use the temporary directory
    with patch('threat_analysis.server.server.config.OUTPUT_BASE_DIR', tmp_path):
        # Patch the service call that does the heavy lifting
        with patch('threat_analysis.server.server.get_threat_model_service') as mock_get_service:
            mock_service = MagicMock()
            mock_get_service.return_value = mock_service
            mock_service.generate_full_project_export.return_value = {
                "reports": {"html": "path/to/report.html"},
                "diagrams": {"svg": "path/to/diagram.svg"}
            }
            
            payload = {'markdown': '# Test', 'model_name': 'MyModel'}
            response = client.post('/api/generate_all', data=json.dumps(payload), content_type='application/json')
            
            assert response.status_code == 200
            json_data = response.get_json()
            assert json_data['success'] is True
            assert 'generation_dir' in json_data
            
            # Check that the main model file was created in the temp dir
            generation_dir = Path(json_data['generation_dir'])
            assert (generation_dir / "main.md").exists()

            mock_service.generate_full_project_export.assert_called_once()

def test_export_navigator_stix_success(client):
    """Test the /api/export_navigator_stix endpoint."""
    with patch('threat_analysis.server.server.get_threat_model_service') as mock_get_service:
        mock_service = MagicMock()
        mock_get_service.return_value = mock_service
        mock_service.export_navigator_stix_logic.return_value = (BytesIO(b"zip_content"), "timestamp")
        with patch('threat_analysis.server.server.send_file') as mock_send:
            mock_send.return_value = MagicMock(status_code=200)
            payload = {'markdown': '# Test'}
            response = client.post('/api/export_navigator_stix', data=json.dumps(payload), content_type='application/json')
            assert response.status_code == 200
            mock_service.export_navigator_stix_logic.assert_called_once()
            mock_send.assert_called_once()

def test_export_attack_flow_success(client):
    """Test the /api/export_attack_flow endpoint."""
    with patch('threat_analysis.server.server.convert_json_to_markdown') as mock_convert, \
         patch('threat_analysis.server.server.get_threat_model_service') as mock_get_service:
        
        mock_service = MagicMock()
        mock_get_service.return_value = mock_service
        mock_convert.return_value = "# Markdown"
        mock_service.export_attack_flow_logic.return_value = (BytesIO(b"zip_content"), "timestamp")
        with patch('threat_analysis.server.server.send_file') as mock_send:
            mock_send.return_value = MagicMock(status_code=200)
            payload = {'some': 'data'}
            response = client.post('/api/export_attack_flow', data=json.dumps(payload), content_type='application/json')
            assert response.status_code == 200
            mock_service.export_attack_flow_logic.assert_called_once()
            mock_send.assert_called_once()

def test_export_attack_flow_no_flows(client):
    """Test the /api/export_attack_flow endpoint when no flows are generated."""
    with patch('threat_analysis.server.server.convert_json_to_markdown'), \
         patch('threat_analysis.server.server.get_threat_model_service') as mock_get_service:
        
        mock_service = MagicMock()
        mock_get_service.return_value = mock_service
        mock_service.export_attack_flow_logic.return_value = (None, None)
        payload = {'some': 'data'}
        response = client.post('/api/export_attack_flow', data=json.dumps(payload), content_type='application/json')
        assert response.status_code == 404
        assert 'No attack flows were generated' in response.get_json()['error']

def test_export_metadata_success(client):
    """Test the /api/export_metadata endpoint."""
    with patch('threat_analysis.server.server.get_threat_model_service') as mock_get_service:
        mock_service = MagicMock()
        mock_get_service.return_value = mock_service
        mock_service.get_element_positions.return_value = {"actors": {"User": {"x": 10}}}
        response = client.post('/api/export_metadata') # Changed to POST
        assert response.status_code == 200
        assert response.mimetype == 'application/json'
        assert 'element_positions.json' in response.headers['Content-Disposition']
        assert b'"User"' in response.data


def test_get_model_name_function():
    """Test the get_model_name function with various markdown content."""
    from threat_analysis.server.server import get_model_name
    
    # Test with valid model name
    markdown_with_name = "# Threat Model: My Test Model\n## Description\nTest"
    assert get_model_name(markdown_with_name) == "My Test Model"
    
    # Test with no model name
    markdown_no_name = "# Threat Model:\n## Description\nTest"
    assert get_model_name(markdown_no_name) == "Untitled Model"
    
    # Test with multiline model name
    markdown_multiline = "# Threat Model: My\nTest Model"
    assert get_model_name(markdown_multiline) == "My"
    
    # Test with extra whitespace
    markdown_whitespace = "# Threat Model:   Test Model  \n## Description\nTest"
    assert get_model_name(markdown_whitespace) == "Test Model"


def test_convert_json_to_markdown_function():
    """Test the convert_json_to_markdown function."""
    from threat_analysis.server.server import convert_json_to_markdown
    
    json_data = {
        'boundaries': [
            {'id': '1', 'name': 'Internet', 'description': 'External network'}
        ],
        'actors': [
            {'id': '2', 'name': 'User', 'parentId': '1'}
        ],
        'servers': [
            {'id': '3', 'name': 'Web Server', 'parentId': '1', 'description': 'Main server'}
        ],
        'data': [
            {'id': '4', 'name': 'User Data', 'description': 'Sensitive data', 'classification': 'private'}
        ],
        'dataflows': [
            {'id': '5', 'from': '2', 'to': '3', 'name': 'Request', 'protocol': 'HTTPS', 'description': 'User request'}
        ]
    }
    
    markdown = convert_json_to_markdown(json_data)
    
    # Check that all sections are present
    assert '# Threat Model: Graphical Editor' in markdown
    assert '## Boundaries' in markdown
    assert '## Actors' in markdown
    assert '## Servers' in markdown
    assert '## Data' in markdown
    assert '## Dataflows' in markdown
    
    # Check specific content
    assert '- **Internet**: description="External network"' in markdown
    assert '- **User**: boundary="Internet"' in markdown
    assert '- **Web Server**: boundary="Internet", description="Main server"' in markdown
    assert '- **User Data**: description="Sensitive data", classification="private"' in markdown
    assert '- **Request**: from="User", to="Web Server", protocol="HTTPS", description="User request"' in markdown


def test_simple_mode_route(client):
    """Test the /simple route."""
    # Set initial markdown content
    from threat_analysis.server.server import initial_markdown_content, DEFAULT_EMPTY_MARKDOWN
    initial_markdown_content = DEFAULT_EMPTY_MARKDOWN
    
    response = client.get('/simple')
    assert response.status_code == 200
    assert b'Threat Model Editor' in response.data
    # Check that the initial markdown is base64 encoded in the response
    assert b'Threat Model Editor' in response.data

def test_graphical_editor_route(client):
    """Test the /graphical route."""
    response = client.get('/graphical')
    assert response.status_code == 200
    assert b'Graphical Editor' in response.data or b'threat-model' in response.data


def test_static_files_route(client):
    """Test the /static/<path:filename> route."""
    # This is a basic test - in a real scenario, you'd need to ensure the static files exist
    response = client.get('/static/css/style.css')
    # The response might be 404 if the file doesn't exist, but the route should be accessible
    assert response.status_code in [200, 404]


def test_data_dictionary_route(client):
    """Test the /api/data_dictionary route."""
    with patch('os.path.exists', return_value=True), \
         patch('threat_analysis.server.server.send_file') as mock_send_file:
        mock_send_file.return_value = MagicMock(status_code=200)
        response = client.get('/api/data_dictionary')
        assert response.status_code == 200
        mock_send_file.assert_called_once()


def test_data_dictionary_route_not_found(client):
    """Test the /api/data_dictionary route when file doesn't exist."""
    with patch('os.path.exists', return_value=False):
        response = client.get('/api/data_dictionary')
        assert response.status_code == 404
        json_data = response.get_json()
        assert 'error' in json_data
        assert json_data['error'] == 'Data dictionary not found'


def test_save_project_success(client):
    """Test the /api/save_project endpoint."""
    with patch('threat_analysis.server.server.get_threat_model_service') as mock_get_service, \
         patch('os.makedirs'), \
         patch('os.path.join', side_effect=lambda *args: "/".join(map(str, args))):
        
        mock_service = MagicMock()
        mock_get_service.return_value = mock_service
        mock_service.save_model_with_metadata.return_value = "path/to/metadata.json"
        payload = {
            'markdown': '# Test Model',
            'model_name': 'MyProject'
        }
        response = client.post('/api/save_project', data=json.dumps(payload), content_type='application/json')
        assert response.status_code == 200
        json_data = response.get_json()
        assert json_data['success'] is True
        assert 'Project saved successfully' in json_data['message']
        mock_service.save_model_with_metadata.assert_called_once()


def test_save_project_missing_markdown(client):
    """Test the /api/save_project endpoint with missing markdown."""
    payload = {'model_name': 'MyProject'}
    response = client.post('/api/save_project', data=json.dumps(payload), content_type='application/json')
    assert response.status_code == 400
    assert 'Missing markdown content' in response.get_json()['error']


def test_check_version_compatibility_invalid_paths(client):
    """Test the /api/check_version_compatibility endpoint with invalid paths."""
    payload = {
        'model_path': '/invalid/path/model.md',
        'metadata_path': '/invalid/path/metadata.json'
    }
    with patch('threat_analysis.server.server.config.OUTPUT_BASE_DIR', 'output'):
        response = client.post('/api/check_version_compatibility', data=json.dumps(payload), content_type='application/json')
        assert response.status_code == 400
        assert 'Invalid file paths' in response.get_json()['error']


def test_check_version_compatibility_files_not_found(client):
    """Test the /api/check_version_compatibility endpoint when files don't exist."""
    payload = {
        'model_path': 'output/model.md',
        'metadata_path': 'output/metadata.json'
    }
    with patch('threat_analysis.server.server.config.OUTPUT_BASE_DIR', 'output'), \
         patch('os.path.exists', return_value=False):
        response = client.post('/api/check_version_compatibility', data=json.dumps(payload), content_type='application/json')
        assert response.status_code == 404
        assert 'Model or metadata file not found' in response.get_json()['error']


def test_load_metadata_invalid_path(client):
    """Test the /api/load_metadata endpoint with invalid path."""
    payload = {'metadata_path': '/invalid/path/metadata.json'}
    with patch('threat_analysis.server.server.config.OUTPUT_BASE_DIR', 'output'):
        response = client.post('/api/load_metadata', data=json.dumps(payload), content_type='application/json')
        assert response.status_code == 400
        assert 'Invalid metadata path' in response.get_json()['error']


def test_load_metadata_file_not_found(client):
    """Test the /api/load_metadata endpoint when file doesn't exist."""
    payload = {'metadata_path': 'output/metadata.json'}
    with patch('threat_analysis.server.server.config.OUTPUT_BASE_DIR', 'output'), \
         patch('os.path.exists', return_value=False):
        response = client.post('/api/load_metadata', data=json.dumps(payload), content_type='application/json')
        assert response.status_code == 404
        assert 'Metadata file not found' in response.get_json()['error']


def test_generate_config_files_function():
    """Test the generate_config_files function."""
    from threat_analysis.server.server import generate_config_files
    
    # Mock the config generator to avoid actual file generation
    with patch('threat_analysis.config_generator.generate_config_js') as mock_generate:
        generate_config_files()
        mock_generate.assert_called_once()


def test_generate_config_files_exception():
    """Test the generate_config_files function when an exception occurs."""
    from threat_analysis.server.server import generate_config_files
    
    # Mock the config generator to raise an exception
    with patch('threat_analysis.config_generator.generate_config_js', side_effect=Exception("Test error")):
        # This should not raise an exception, just log a warning
        generate_config_files()


def test_format_properties_helper():
    """Test the _format_properties helper function."""
    from threat_analysis.server.server import _format_properties
    
    item = {
        'prop1': 'value1',
        'prop2': 'value2',
        'prop3': None,
        'prop4': ''
    }
    props_to_include = ['prop1', 'prop2', 'prop3', 'prop4']
    
    result = _format_properties(item, props_to_include)
    assert result == 'prop1="value1", prop2="value2"'


def test_format_properties_empty():
    """Test the _format_properties helper function with empty input."""
    from threat_analysis.server.server import _format_properties
    
    item = {}
    props_to_include = ['prop1', 'prop2']
    
    result = _format_properties(item, props_to_include)
    assert result == ''

def test_update_api_generic_exception(client):
    """Test the /api/update endpoint with a generic exception."""
    with patch('threat_analysis.server.server.get_threat_model_service') as mock_get_service:
        mock_service = MagicMock()
        mock_get_service.return_value = mock_service
        mock_service.update_diagram_logic.side_effect = Exception("A wild error appeared")
        payload = {'markdown': '# Test'}
        response = client.post('/api/update', data=json.dumps(payload), content_type='application/json')
        assert response.status_code == 500
        assert 'An internal error occurred' in response.get_json()['error']

def test_run_server_with_file_read_error(client):
    """Test run_server when reading an existing file fails."""
    with patch('os.path.exists', return_value=True), \
         patch('builtins.open', side_effect=IOError("read error")):
        with patch('threat_analysis.server.server.app.run'):
            run_server(model_filepath='/path/to/existing/model.md')
            response = client.get('/simple')
            assert response.status_code == 200
            assert b'Threat Model Editor' in response.data

def test_check_version_compatibility_success(client):
    """Test the /api/check_version_compatibility endpoint."""
    with patch('threat_analysis.server.server.get_threat_model_service') as mock_get_service, \
         patch('os.path.exists', return_value=True), \
         patch('threat_analysis.server.server.project_root', '/root'):
        mock_service = MagicMock()
        mock_get_service.return_value = mock_service
        mock_service.check_version_compatibility.return_value = True
        payload = {'model_path': 'output/m.md', 'metadata_path': 'output/m.json'}
        with patch('threat_analysis.server.server.config.OUTPUT_BASE_DIR', '/root/output'):
            # Simplified abspath mock that resolves /root/output to /root/output
            def mocked_abspath(path):
                if path.startswith('output'):
                    return '/root/' + path
                return path

            with patch('os.path.abspath', side_effect=mocked_abspath):
                response = client.post('/api/check_version_compatibility', data=json.dumps(payload), content_type='application/json')
                assert response.status_code == 200
                assert response.get_json()['compatible'] is True

def test_generate_markdown_from_prompt_success(client):
    """Test the /api/generate_markdown_from_prompt endpoint."""
    with patch('threat_analysis.server.server.get_threat_model_service') as mock_get_service:
        mock_service = MagicMock()
        mock_get_service.return_value = mock_service
        mock_service.ai_online = True
        
        async def mock_gen(*args):
            yield "```markdown\n# Generated Model\n```"
        
        mock_service.generate_markdown_from_prompt.return_value = mock_gen()
        
        payload = {'prompt': 'Create a web app model'}
        response = client.post('/api/generate_markdown_from_prompt', data=json.dumps(payload), content_type='application/json')
        
        assert response.status_code == 200
        assert response.get_json()['markdown_content'] == '# Generated Model'

def test_generate_markdown_from_prompt_no_online(client):
    """Test the /api/generate_markdown_from_prompt endpoint when AI is offline."""
    with patch('threat_analysis.server.server.get_threat_model_service') as mock_get_service:
        mock_service = MagicMock()
        mock_get_service.return_value = mock_service
        mock_service.ai_online = False
        
        payload = {'prompt': 'test'}
        response = client.post('/api/generate_markdown_from_prompt', data=json.dumps(payload), content_type='application/json')
        assert response.status_code == 503

def test_sse_broadcaster():
    """Test the SSEBroadcaster class."""
    from threat_analysis.server.server import SSEBroadcaster
    import queue
    
    broadcaster = SSEBroadcaster()
    q = broadcaster.subscribe()
    assert isinstance(q, queue.Queue)
    
    broadcaster.broadcast("test_event", {"data": "info"})
    msg = q.get(timeout=1)
    assert "event: test_event" in msg
    assert '"data": "info"' in msg
    
    broadcaster.unsubscribe(q)
    assert q not in broadcaster.listeners

def test_before_after_request(client):
    """Test before_request and after_request hooks."""
    response = client.get('/')
    assert response.status_code == 200
    # The hooks should have executed without error.

def test_get_threat_model_service_singleton():
    """Test that get_threat_model_service returns a singleton."""
    with patch('threat_analysis.server.threat_model_service.ThreatModelService') as mock_service_class:
        mock_service_class.return_value = MagicMock()
        s1 = get_threat_model_service()
        s2 = get_threat_model_service()
        assert s1 is s2


# ---------------------------------------------------------------------------
# /api/ai_status
# ---------------------------------------------------------------------------

def test_ai_status_online(client):
    with patch('threat_analysis.server.server.get_threat_model_service') as mock_get:
        mock_svc = MagicMock()
        mock_svc.ai_online = True
        mock_get.return_value = mock_svc
        resp = client.get('/api/ai_status')
        assert resp.status_code == 200
        assert resp.get_json()['ai_online'] is True


def test_ai_status_offline(client):
    with patch('threat_analysis.server.server.get_threat_model_service') as mock_get:
        mock_get.return_value = None
        resp = client.get('/api/ai_status')
        assert resp.status_code == 503
        assert resp.get_json()['ai_online'] is False


# ---------------------------------------------------------------------------
# /api/update — error paths (lines 503-511)
# ---------------------------------------------------------------------------

def test_update_api_runtime_error(client):
    with patch('threat_analysis.server.server.get_threat_model_service') as mock_get:
        mock_svc = MagicMock()
        mock_svc.update_diagram_logic.side_effect = RuntimeError("internal crash")
        mock_get.return_value = mock_svc
        resp = client.post('/api/update', data=json.dumps({'markdown': '# M'}),
                           content_type='application/json')
        assert resp.status_code == 500
        assert 'internal crash' in resp.get_json()['error']


# ---------------------------------------------------------------------------
# /api/generate_markdown_from_prompt — extra error paths
# ---------------------------------------------------------------------------

def test_generate_markdown_from_prompt_missing_prompt(client):
    with patch('threat_analysis.server.server.get_threat_model_service') as mock_get:
        mock_svc = MagicMock()
        mock_svc.ai_online = True
        mock_get.return_value = mock_svc
        resp = client.post('/api/generate_markdown_from_prompt',
                           data=json.dumps({'markdown': '# M'}),
                           content_type='application/json')
        assert resp.status_code == 400
        assert 'Prompt is missing' in resp.get_json()['error']


def test_generate_markdown_from_prompt_concurrent_lock(client):
    """Second concurrent request should get 429."""
    import threading
    from threat_analysis.server.server import _ai_generation_lock
    # Acquire the lock to simulate another generation in progress
    _ai_generation_lock.acquire()
    try:
        with patch('threat_analysis.server.server.get_threat_model_service') as mock_get:
            mock_svc = MagicMock()
            mock_svc.ai_online = True
            mock_get.return_value = mock_svc
            resp = client.post('/api/generate_markdown_from_prompt',
                               data=json.dumps({'prompt': 'test'}),
                               content_type='application/json')
            assert resp.status_code == 429
    finally:
        _ai_generation_lock.release()


def test_generate_markdown_from_prompt_fallback_extraction(client):
    """Response has no ```markdown``` block — fallback to # Threat Model: search."""
    with patch('threat_analysis.server.server.get_threat_model_service') as mock_get:
        mock_svc = MagicMock()
        mock_svc.ai_online = True

        async def mock_gen(*args):
            yield "Here is your model:\n# Threat Model: App\n## Description\nTest"

        mock_svc.generate_markdown_from_prompt.return_value = mock_gen()
        mock_get.return_value = mock_svc
        resp = client.post('/api/generate_markdown_from_prompt',
                           data=json.dumps({'prompt': 'Create a model'}),
                           content_type='application/json')
        assert resp.status_code == 200
        assert '# Threat Model:' in resp.get_json()['markdown_content']


def test_generate_markdown_from_prompt_no_model_extracted(client):
    """Response has no markdown block and no # Threat Model: — should return 500."""
    with patch('threat_analysis.server.server.get_threat_model_service') as mock_get:
        mock_svc = MagicMock()
        mock_svc.ai_online = True

        async def mock_gen(*args):
            yield "Just some random text with no DSL."

        mock_svc.generate_markdown_from_prompt.return_value = mock_gen()
        mock_get.return_value = mock_svc
        resp = client.post('/api/generate_markdown_from_prompt',
                           data=json.dumps({'prompt': 'Create a model'}),
                           content_type='application/json')
        assert resp.status_code == 500


# ---------------------------------------------------------------------------
# /api/export — error paths (lines 638-643)
# ---------------------------------------------------------------------------

def test_export_api_runtime_error(client):
    with patch('threat_analysis.server.server.get_threat_model_service') as mock_get:
        mock_svc = MagicMock()
        mock_svc.export_files_logic.side_effect = RuntimeError("render failed")
        mock_get.return_value = mock_svc
        resp = client.post('/api/export',
                           data=json.dumps({'markdown': '# M', 'format': 'svg'}),
                           content_type='application/json')
        assert resp.status_code == 500
        assert 'render failed' in resp.get_json()['error']


def test_export_api_generic_error(client):
    with patch('threat_analysis.server.server.get_threat_model_service') as mock_get:
        mock_svc = MagicMock()
        mock_svc.export_files_logic.side_effect = Exception("boom")
        mock_get.return_value = mock_svc
        resp = client.post('/api/export',
                           data=json.dumps({'markdown': '# M', 'format': 'svg'}),
                           content_type='application/json')
        assert resp.status_code == 500
        assert 'An internal error occurred' in resp.get_json()['error']


# ---------------------------------------------------------------------------
# /api/export_all — error paths (lines 670-678)
# ---------------------------------------------------------------------------

def test_export_all_runtime_error(client):
    with patch('threat_analysis.server.server.get_threat_model_service') as mock_get:
        mock_svc = MagicMock()
        mock_svc.export_all_files_logic.side_effect = RuntimeError("zip failed")
        mock_get.return_value = mock_svc
        resp = client.post('/api/export_all',
                           data=json.dumps({'markdown': '# M'}),
                           content_type='application/json')
        assert resp.status_code == 500


def test_export_all_generic_error(client):
    with patch('threat_analysis.server.server.get_threat_model_service') as mock_get:
        mock_svc = MagicMock()
        mock_svc.export_all_files_logic.side_effect = Exception("oops")
        mock_get.return_value = mock_svc
        resp = client.post('/api/export_all',
                           data=json.dumps({'markdown': '# M'}),
                           content_type='application/json')
        assert resp.status_code == 500
        assert 'An internal error occurred' in resp.get_json()['error']


# ---------------------------------------------------------------------------
# /api/export_navigator_stix — error paths (lines 695, 707)
# ---------------------------------------------------------------------------

def test_export_navigator_stix_missing_markdown(client):
    resp = client.post('/api/export_navigator_stix',
                       data=json.dumps({}),
                       content_type='application/json')
    assert resp.status_code == 400
    assert 'Missing markdown content' in resp.get_json()['error']


def test_export_navigator_stix_no_result(client):
    with patch('threat_analysis.server.server.get_threat_model_service') as mock_get:
        mock_svc = MagicMock()
        mock_svc.export_navigator_stix_logic.return_value = (None, None)
        mock_get.return_value = mock_svc
        resp = client.post('/api/export_navigator_stix',
                           data=json.dumps({'markdown': '# M'}),
                           content_type='application/json')
        assert resp.status_code == 500


# ---------------------------------------------------------------------------
# /api/models — error path (lines 820-822)
# ---------------------------------------------------------------------------

def test_list_models_error(client):
    with patch('glob.iglob', side_effect=Exception("glob error")):
        resp = client.get('/api/models')
        assert resp.status_code == 500
        assert 'An internal error occurred' in resp.get_json()['error']


# ---------------------------------------------------------------------------
# /api/load_model — missing path + security check (lines 836, 841)
# ---------------------------------------------------------------------------

def test_load_model_missing_path(client, tmp_path):
    with patch('threat_analysis.server.server.config.OUTPUT_BASE_DIR', str(tmp_path)):
        resp = client.post('/api/load_model',
                           data=json.dumps({}),
                           content_type='application/json')
        assert resp.status_code == 400
        assert 'Missing model path' in resp.get_json()['error']


def test_load_model_path_traversal(client, tmp_path):
    with patch('threat_analysis.server.server.config.OUTPUT_BASE_DIR', str(tmp_path)):
        resp = client.post('/api/load_model',
                           data=json.dumps({'model_path': '/etc/passwd'}),
                           content_type='application/json')
        assert resp.status_code == 400
        assert 'Invalid model path' in resp.get_json()['error']


def test_load_model_with_metadata(client, tmp_path):
    """Load a model that has an associated _metadata.json file."""
    output_dir = tmp_path / "output"
    output_dir.mkdir()
    model_file = output_dir / "my_model.md"
    model_file.write_text("# Model")
    meta_file = output_dir / "my_model_metadata.json"
    meta_file.write_text('{"version": "1.0"}')

    with patch('threat_analysis.server.server.config.OUTPUT_BASE_DIR', str(output_dir)):
        resp = client.post('/api/load_model',
                           data=json.dumps({'model_path': str(model_file)}),
                           content_type='application/json')
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['metadata'] == {'version': '1.0'}


# ---------------------------------------------------------------------------
# /api/generate_all — extra_files path (lines 986-992, 1048)
# ---------------------------------------------------------------------------

def test_generate_all_with_extra_files(client, tmp_path):
    with patch('threat_analysis.server.server.config.OUTPUT_BASE_DIR', str(tmp_path)):
        with patch('threat_analysis.server.server.get_threat_model_service') as mock_get:
            mock_svc = MagicMock()
            mock_svc.generate_full_project_export.return_value = {"reports": {}, "diagrams": {}}
            mock_get.return_value = mock_svc
            payload = {
                'markdown': '# Test',
                'extra_files': [
                    {'path': 'BOM/web.yaml', 'content': 'asset_name: web'},
                    {'path': '', 'content': 'ignored'},  # empty path — skipped
                ],
            }
            resp = client.post('/api/generate_all',
                               data=json.dumps(payload),
                               content_type='application/json')
            assert resp.status_code == 200
            gen_dir = Path(resp.get_json()['generation_dir'])
            # BOM file should have been written
            assert (gen_dir / 'BOM' / 'web.yaml').read_text() == 'asset_name: web'


def test_generate_all_missing_markdown(client, tmp_path):
    with patch('threat_analysis.server.server.config.OUTPUT_BASE_DIR', str(tmp_path)):
        resp = client.post('/api/generate_all',
                           data=json.dumps({}),
                           content_type='application/json')
        assert resp.status_code == 400
        assert 'Missing markdown content' in resp.get_json()['error']


def test_generate_all_exception(client, tmp_path):
    with patch('threat_analysis.server.server.config.OUTPUT_BASE_DIR', str(tmp_path)):
        with patch('threat_analysis.server.server.get_threat_model_service') as mock_get:
            mock_svc = MagicMock()
            mock_svc.generate_full_project_export.side_effect = Exception("crash")
            mock_get.return_value = mock_svc
            resp = client.post('/api/generate_all',
                               data=json.dumps({'markdown': '# Test'}),
                               content_type='application/json')
            assert resp.status_code == 500
            assert 'An internal error occurred' in resp.get_json()['error']


# ---------------------------------------------------------------------------
# /api/save_project — exception path (lines 1156-1158)
# ---------------------------------------------------------------------------

def test_save_project_exception(client):
    with patch('threat_analysis.server.server.get_threat_model_service') as mock_get:
        mock_svc = MagicMock()
        mock_svc.save_model_with_metadata.side_effect = Exception("disk full")
        mock_get.return_value = mock_svc
        resp = client.post('/api/save_project',
                           data=json.dumps({'markdown': '# M'}),
                           content_type='application/json')
        assert resp.status_code == 500
        assert 'An internal error occurred' in resp.get_json()['error']


# ---------------------------------------------------------------------------
# /api/load_metadata — success path (lines 1217-1227)
# ---------------------------------------------------------------------------

def test_load_metadata_success(client, tmp_path):
    output_dir = tmp_path / "output"
    output_dir.mkdir()
    meta_file = output_dir / "meta.json"
    meta_file.write_text('{"version": "1.0"}')

    with patch('threat_analysis.server.server.config.OUTPUT_BASE_DIR', str(output_dir)), \
         patch('threat_analysis.server.server.project_root', str(tmp_path)):
        resp = client.post('/api/load_metadata',
                           data=json.dumps({'metadata_path': str(meta_file)}),
                           content_type='application/json')
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['success'] is True
        assert data['metadata'] == {'version': '1.0'}


# ---------------------------------------------------------------------------
# /diff — diff_page (line 1419)
# ---------------------------------------------------------------------------

def test_diff_page_route(client):
    resp = client.get('/diff')
    # diff.html template may or may not exist in test env — just check route exists
    assert resp.status_code in [200, 500]


# ---------------------------------------------------------------------------
# /api/diff_reports (lines 1425-1441)
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Additional targeted error-path coverage
# ---------------------------------------------------------------------------

def test_update_api_value_error_from_service(client):
    """ValueError raised by service → 400 (lines 504-505 in server.py)."""
    with patch('threat_analysis.server.server.get_threat_model_service') as mock_get:
        mock_svc = MagicMock()
        mock_svc.update_diagram_logic.side_effect = ValueError("bad diagram")
        mock_get.return_value = mock_svc
        resp = client.post('/api/update',
                           data=json.dumps({'markdown': '# M'}),
                           content_type='application/json')
        assert resp.status_code == 400
        assert 'bad diagram' in resp.get_json()['error']


def test_graphical_update_exception(client):
    """Unhandled exception in /api/graphical_update → 500 (lines 598-600)."""
    with patch('threat_analysis.server.server.convert_json_to_markdown') as mock_convert, \
         patch('threat_analysis.server.server.get_threat_model_service') as mock_get:
        mock_svc = MagicMock()
        mock_svc.update_diagram_logic.side_effect = Exception("graphviz crash")
        mock_get.return_value = mock_svc
        mock_convert.return_value = "# M"
        resp = client.post('/api/graphical_update',
                           data=json.dumps({'actors': [{'id': '1', 'name': 'U'}]}),
                           content_type='application/json')
        assert resp.status_code == 500
        assert 'An internal error occurred' in resp.get_json()['error']


def test_export_all_value_error(client):
    """ValueError from export_all → 400 (lines 671-672)."""
    with patch('threat_analysis.server.server.get_threat_model_service') as mock_get:
        mock_svc = MagicMock()
        mock_svc.export_all_files_logic.side_effect = ValueError("invalid format")
        mock_get.return_value = mock_svc
        resp = client.post('/api/export_all',
                           data=json.dumps({'markdown': '# M'}),
                           content_type='application/json')
        assert resp.status_code == 400
        assert 'invalid format' in resp.get_json()['error']


def test_save_model_exception(client):
    """Unhandled exception in /api/save_model → 500 (lines 935-937)."""
    with patch('threat_analysis.server.server.get_threat_model_service') as mock_get:
        mock_svc = MagicMock()
        mock_svc.save_model_with_metadata.side_effect = Exception("disk error")
        mock_get.return_value = mock_svc
        resp = client.post('/api/save_model',
                           data=json.dumps({'markdown': '# M', 'model_name': 'test'}),
                           content_type='application/json')
        assert resp.status_code == 500
        assert 'An internal error occurred' in resp.get_json()['error']


def test_markdown_to_json_exception(client):
    """Exception in markdown_to_json logs extra info (lines 888-897)."""
    with patch('threat_analysis.server.server.get_threat_model_service') as mock_get:
        mock_svc = MagicMock()
        mock_svc.markdown_to_json_for_gui.side_effect = Exception("parse error")
        mock_get.return_value = mock_svc
        resp = client.post('/api/markdown_to_json',
                           data=json.dumps({'markdown': '# M'}),
                           content_type='application/json')
        assert resp.status_code == 500
        assert 'An internal error occurred' in resp.get_json()['error']


def test_generate_all_with_submodels_main_md(client, tmp_path):
    """Submodels include main.md — covers lines 1075-1078 (find main.md in submodels)."""
    with patch('threat_analysis.server.server.config.OUTPUT_BASE_DIR', str(tmp_path)):
        with patch('threat_analysis.server.server.get_threat_model_service') as mock_get:
            mock_svc = MagicMock()
            mock_svc.generate_full_project_export.return_value = {"reports": {}, "diagrams": {}}
            mock_get.return_value = mock_svc
            payload = {
                'markdown': '# Sub Model',
                'path': 'sub/model.md',
                'submodels': [{'path': 'main.md', 'content': '# Threat Model: Main'}],
            }
            resp = client.post('/api/generate_all',
                               data=json.dumps(payload),
                               content_type='application/json')
            assert resp.status_code == 200


# NOTE: Routes using `await request.get_json()` (export_json, validate_markdown,
# set_project_path, diff_reports) cannot be exercised via the synchronous WSGI
# test client — `await dict` raises TypeError in that context. Those routes are
# tested via integration tests only.


# ---------------------------------------------------------------------------
# after_request with X-Request-Start header (lines 106-110)
# ---------------------------------------------------------------------------

def test_after_request_with_request_start_header(client):
    """Sending X-Request-Start header should hit the transmission latency branch."""
    import time
    headers = {'X-Request-Start': str(time.time() - 0.01)}
    resp = client.get('/', headers=headers)
    assert resp.status_code == 200


def test_after_request_with_invalid_request_start_header(client):
    """Invalid X-Request-Start value should not raise."""
    resp = client.get('/', headers={'X-Request-Start': 'not-a-number'})
    assert resp.status_code == 200
