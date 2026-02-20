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

import os
import sys
import base64
import logging
import re
import datetime
import json
import glob
from typing import Optional
from flask import Flask, render_template, request, jsonify, send_from_directory, send_file, make_response
from threat_analysis import config
from threat_analysis.server.threat_model_service import ThreatModelService

# Add project root to sys.path
project_root = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..")
)
if project_root not in sys.path:
    sys.path.insert(0, project_root)

# Get the absolute path to the server directory
server_dir = os.path.dirname(os.path.abspath(__file__))

app = Flask(__name__, 
          template_folder=os.path.join(server_dir, "templates"),
          static_folder=os.path.join(server_dir, "static"),
          static_url_path="/static")

# Initialize the service layer
threat_model_service = ThreatModelService()

# Generate configuration files if needed
def generate_config_files():
    """Generate configuration files to ensure they're up to date"""
    try:
        # Add the threat_analysis directory to the path
        import sys
        from pathlib import Path
        sys.path.append(str(Path(__file__).parent))
        
        # Import and use the config generator directly
        from threat_analysis.config_generator import generate_config_js
        generate_config_js()
        
    except Exception as e:
        print(f"Warning: Error generating configuration files: {e}")

# Generate config.js on startup
generate_config_files()

# Verify that the config file was generated successfully
import os
import time
config_js_path = os.path.join(os.path.dirname(__file__), "static", "js", "config.js")
max_attempts = 3
attempt = 0

while attempt < max_attempts:
    if os.path.exists(config_js_path):
        # Check if the file has content
        try:
            with open(config_js_path, 'r') as f:
                content = f.read()
                if len(content) > 100:  # Basic check for valid content
                    print(f"Configuration file verified: {config_js_path}")
                    break
        except Exception as e:
            print(f"Warning: Could not read config.js: {e}")
    else:
        print(f"Warning: config.js not found at {config_js_path}, attempt {attempt + 1}")
    
    attempt += 1
    if attempt < max_attempts:
        time.sleep(0.5)  # Wait a bit before retrying

if attempt == max_attempts:
    print("Warning: Could not verify config.js generation")

initial_markdown_content = ""

DEFAULT_EMPTY_MARKDOWN = """# Threat Model: New Model

## Description
A new threat model. Describe your system here.

## Boundaries
- **Default Boundary**: color=lightgray

## Actors
- **User**: boundary=Default Boundary

## Servers
- **Application Server**: boundary=Default Boundary

## Dataflows
- **User to Application Server**: from="User", to="Application Server", protocol="HTTPS"

## Severity Multipliers
# Example:
# - **Application Server**: 1.5

## Custom Mitre Mapping
# Example:
# - **Custom Attack**: tactics=["Initial Access"], techniques=[{"id": "T1000", "name": "Custom Technique"}]
"""


def get_model_name(markdown_content: str) -> str:
    match = re.search(r"^# Threat Model: (.*)$", markdown_content, re.MULTILINE)
    if match:
        return match.group(1).strip()
    return "Untitled Model"


def run_server(model_filepath: Optional[str] = None, project_path: Optional[str] = None):
    """
    This function is the main entry point for the web server.
    It launches the Flask application on a single port and serves a menu
    to choose between the simple and graphical modes.
    """
    global initial_markdown_content
    if model_filepath and os.path.exists(model_filepath):
        try:
            with open(model_filepath, "r", encoding="utf-8") as f:
                initial_markdown_content = f.read()
            logging.info(f"Loaded initial threat model from {model_filepath}")
        except Exception as e:
            logging.error(f"Error loading initial model from {model_filepath}: {e}")
            initial_markdown_content = DEFAULT_EMPTY_MARKDOWN
            logging.info("Loaded initial threat model from a temporary model due to file loading error.")
    else:
        initial_markdown_content = DEFAULT_EMPTY_MARKDOWN
        logging.info("No initial threat model file provided or found. Starting with a default empty model.")
    
    if project_path:
        app.config['PROJECT_PATH'] = project_path

    print(
        "\n🚀 Starting Threat Model Server. Open your browser to: http://127.0.0.1:5000/\n"
    )
    app.run(debug=os.environ.get('FLASK_DEBUG', 'false').lower() == 'true', port=5000)


@app.route('/static/<path:filename>')
def serve_static(filename):
    """Serve static files from the static directory."""
    static_folder = app.static_folder or os.path.join(server_dir, "static")
    return send_from_directory(static_folder, filename)

@app.route('/api/data_dictionary')
def get_data_dictionary():
    """Serves the data dictionary XML file."""
    xml_path = os.path.join(project_root, 'threat_analysis', 'external_data', 'data_dictionary.xml')
    if os.path.exists(xml_path):
        return send_file(xml_path, mimetype='application/xml')
    return jsonify({"error": "Data dictionary not found"}), 404

@app.route("/")
def index():
    """Serves the main menu."""
    return render_template("index.html")

@app.route("/simple")
def simple_mode():
    """Serves the simple web interface."""
    project_path = app.config.get('PROJECT_PATH')
    models = []
    if project_path and os.path.isdir(project_path):
        # Logic to load models from project
        model_files = glob.glob(os.path.join(project_path, '**', 'main.md'), recursive=True)
        model_files.extend(glob.glob(os.path.join(project_path, '**', 'model.md'), recursive=True))
        for model_file in model_files:
            with open(model_file, "r", encoding="utf-8") as f:
                content = f.read()
                models.append({
                    "path": os.path.relpath(model_file, project_path),
                    "content": content
                })
    else:
        # Fallback for single file or no project
        models.append({
            "path": "main.md",
            "content": initial_markdown_content
        })

    encoded_models = base64.b64encode(json.dumps(models).encode('utf-8')).decode('utf-8')

    return render_template(
        "simple_mode.html",
        initial_models=encoded_models
    )


@app.route("/graphical")
def graphical_editor():
    """Serves the main web interface."""
    return render_template("graphical_editor.html")



@app.route("/api/update", methods=["POST"])
def update_diagram():
    """
    Receives Markdown content, generates a threat model diagram,
    and returns the HTML representation of the diagram.
    """
    logging.info("Entering update_diagram function.")
    data = request.json
    markdown_content = data.get("markdown", "")
    submodels = data.get("submodels", [])

    if not markdown_content:
        return jsonify({"error": "Markdown content is empty"}), 400

    try:
        result = threat_model_service.update_diagram_logic(
            markdown_content=markdown_content, submodels=submodels
        )
        model_name = get_model_name(markdown_content)
        result["model_name"] = model_name
        return jsonify(result)

    except ValueError as e:
        logging.error(f"Error during diagram update: {e}")
        return jsonify({"error": str(e)}), 400
    except RuntimeError as e:
        logging.error(f"Error during diagram update: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500
    except Exception as e:
        logging.error(f"An unexpected error occurred during diagram update: {e}", exc_info=True)
        return jsonify({"error": f"An unexpected error occurred: {str(e)}"}), 500


def _format_properties(item: dict, props_to_include: list) -> str:
    """Helper to format key-value properties for Markdown."""
    props = []
    for prop_key in props_to_include:
        prop_value = item.get(prop_key)
        if prop_value:
            props.append(f'{prop_key}="{prop_value}"')
    return ", ".join(props)

def convert_json_to_markdown(data: dict) -> str:
    """Converts JSON from the graphical editor to Markdown DSL."""
    markdown_lines = ["# Threat Model: Graphical Editor"]
    
    boundaries = data.get('boundaries', [])
    actors = data.get('actors', [])
    servers = data.get('servers', [])
    data_elements = data.get('data', [])
    dataflows = data.get('dataflows', [])

    boundary_map = {b['id']: b['name'] for b in boundaries}

    markdown_lines.append("\n## Boundaries")
    for boundary in boundaries:
        props_str = _format_properties(boundary, ['description'])
        markdown_lines.append(f"- **{boundary['name']}**: {props_str}")

    markdown_lines.append("\n## Actors")
    for actor in actors:
        props = {'boundary': boundary_map.get(actor.get('parentId'))}
        props_str = _format_properties({**actor, **props}, ['boundary', 'description'])
        markdown_lines.append(f"- **{actor['name']}**: {props_str}")

    markdown_lines.append("\n## Servers")
    for server in servers:
        props = {'boundary': boundary_map.get(server.get('parentId'))}
        props_str = _format_properties({**server, **props}, ['boundary', 'description'])
        markdown_lines.append(f"- **{server['name']}**: {props_str}")

    markdown_lines.append("\n## Data")
    for data_item in data_elements:
        props_str = _format_properties(data_item, ['description', 'classification'])
        markdown_lines.append(f"- **{data_item['name']}**: {props_str}")

    markdown_lines.append("\n## Dataflows")
    nodes = {item['id']: item for item in actors + servers + data_elements}
    for df in dataflows:
        from_node = nodes.get(df['from'])
        to_node = nodes.get(df['to'])
        if from_node and to_node:
            df_name = df.get("name") or f"{from_node['name']} to {to_node['name']}"
            props_str = _format_properties(df, ['protocol', 'description'])
            markdown_lines.append(f'- **{df_name}**: from="{from_node["name"]}", to="{to_node["name"]}", {props_str}')

    return "\n".join(markdown_lines)


@app.route("/api/graphical_update", methods=["POST"])
def graphical_update():
    """
    Receives JSON graph data, converts it to Markdown, and returns the analysis.
    """
    logging.info("Entering graphical_update function.")
    json_data = request.json
    if not json_data:
        return jsonify({"error": "JSON data is empty"}), 400

    try:
        markdown_content = convert_json_to_markdown(json_data)
        logging.info(f"Converted Markdown:\n{markdown_content}")
        
        # Ensure output directory exists (using the same structure as other modes)
        os.makedirs(config.OUTPUT_BASE_DIR, exist_ok=True)
        
        # Reuse the existing service logic
        result = threat_model_service.update_diagram_logic(
            markdown_content=markdown_content
        )
        model_name = get_model_name(markdown_content)
        result["model_name"] = model_name
        result["output_dir"] = str(config.OUTPUT_BASE_DIR)
        return jsonify(result)

    except Exception as e:
        logging.error(f"An unexpected error occurred during graphical update: {e}", exc_info=True)
        return jsonify({"error": f"An unexpected error occurred: {str(e)}"}), 500



@app.route("/api/export", methods=["POST"])
def export_files():
    """
    Handles exporting the model in various formats (SVG, HTML diagram, HTML report).
    """
    markdown_content = request.json.get("markdown", "")
    export_format = request.json.get("format")  # "svg", "diagram", "report"
    logging.info(f"Entering export_files function for format: {export_format}")

    if not markdown_content or not export_format:
        return (
            jsonify({"error": "Missing markdown content or export format"}),
            400,
        )

    try:
        output_path, output_filename = threat_model_service.export_files_logic(
            markdown_content=markdown_content, export_format=export_format
        )
        absolute_output_directory = os.path.join(project_root, os.path.dirname(output_path))
        
        # Return both the file and the output directory information
        response = send_from_directory(
            absolute_output_directory, output_filename, as_attachment=True
        )
        
        # Add custom header with output directory information
        response.headers['X-Output-Directory'] = str(config.OUTPUT_BASE_DIR)
        return response

    except ValueError as e:
        logging.error(f"Error during export: {e}")
        return jsonify({"error": str(e)}), 400
    except RuntimeError as e:
        logging.error(f"Error during export: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500
    except Exception as e:
        logging.error(f"An unexpected error occurred during export: {e}", exc_info=True)
        return jsonify({"error": f"An unexpected error occurred: {str(e)}"}), 500


@app.route("/api/export_all", methods=["POST"])
def export_all_files():
    """
    Handles exporting all generated files (Markdown, SVG, HTML diagram, HTML report, JSON analysis)
    as a single ZIP archive.
    """
    markdown_content = request.json.get("markdown", "")
    if not markdown_content:
        return jsonify({"error": "Missing markdown content"}), 400
    logging.info("Entering export_all_files function.")

    try:
        submodels = request.json.get("submodels", [])
        zip_buffer, timestamp = threat_model_service.export_all_files_logic(
            markdown_content=markdown_content, submodels=submodels
        )
        return send_file(
            zip_buffer,
            mimetype="application/zip",
            as_attachment=True,
            download_name=f"threat_model_export_{timestamp}.zip",
        )

    except ValueError as e:
        logging.error(f"Error during export all: {e}")
        return jsonify({"error": str(e)}), 400
    except RuntimeError as e:
        logging.error(f"Error during export all: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500
    except Exception as e:
        logging.error(f"An unexpected error occurred during export all: {e}", exc_info=True)
        return jsonify({"error": f"An unexpected error occurred: {str(e)}"}), 500

@app.route("/api/export_navigator_stix", methods=["POST"])

def export_navigator_stix_files():

    logging.info("Received request for /api/export_navigator_stix.")

    """

    Handles exporting ATT&CK Navigator layer and STIX report as a single ZIP archive.

    """

    markdown_content = request.json.get("markdown", "")

    if not markdown_content:

        return jsonify({"error": "Missing markdown content"}), 400

    logging.info("Entering export_navigator_stix_files function.")



    try:
        submodels = request.json.get("submodels", [])
        zip_buffer, timestamp = threat_model_service.export_navigator_stix_logic(markdown_content, submodels=submodels)
        if not zip_buffer:
            return jsonify({"error": "Failed to generate navigator and STIX files."}), 500
        logging.info(f"Generated zip buffer size: {zip_buffer.getbuffer().nbytes} bytes")
        return send_file(
            zip_buffer,
            mimetype="application/zip",
            as_attachment=True,
            download_name=f"navigator_stix_export_{timestamp}.zip",
        )



    except ValueError as e:

        logging.error(f"Error during export navigator and stix: {e}")

        return jsonify({"error": str(e)}), 400

    except RuntimeError as e:

        logging.error(f"Error during export navigator and stix: {e}", exc_info=True)

        return jsonify({"error": str(e)}), 500

    except Exception as e:

        logging.error(f"An unexpected error occurred during export navigator and stix: {e}", exc_info=True)

        return jsonify({"error": f"An unexpected error occurred: {str(e)}"}), 500





@app.route("/api/export_attack_flow", methods=["POST"])

def export_attack_flow():

    """

    Handles exporting Attack Flow diagrams as a single ZIP archive.

    """

    json_data = request.json

    if not json_data:

        return jsonify({"error": "Missing model data"}), 400



    logging.info("Entering export_attack_flow function.")



    try:

        markdown_content = convert_json_to_markdown(json_data)

        zip_buffer, timestamp = threat_model_service.export_attack_flow_logic(markdown_content)



        if not zip_buffer:

            return jsonify({"error": "No attack flows were generated. The model may be too simple."}), 404



        return send_file(

            zip_buffer,

            mimetype="application/zip",

            as_attachment=True,

            download_name=f"attack_flows_{timestamp}.zip",

        )



    except ValueError as e:

        logging.error(f"Error during Attack Flow export: {e}")

        return jsonify({"error": str(e)}), 400

    except RuntimeError as e:

        logging.error(f"Error during Attack Flow export: {e}", exc_info=True)

        return jsonify({"error": str(e)}), 500

    except Exception as e:
        logging.error(f"An unexpected error occurred during Attack Flow export: {e}", exc_info=True)
        return jsonify({"error": f"An unexpected error occurred: {str(e)}"}), 500


@app.route("/api/models", methods=["GET"])
def list_models():
    """
    Lists all threat models (.md files) in the output directory.
    """
    try:
        output_dir = config.OUTPUT_BASE_DIR
        model_files = []
        for filepath in glob.iglob(os.path.join(output_dir, '**', '*.md'), recursive=True):
            model_files.append(os.path.relpath(filepath, project_root))
        return jsonify({"success": True, "models": model_files})
    except Exception as e:
        logging.error(f"Error listing models: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500


@app.route("/api/load_model", methods=["POST"])
def load_model():
    """
    Loads a threat model and its metadata.
    """
    try:
        data = request.get_json()
        model_path = data.get('model_path', '')
        logging.info(f"Received request to load model: {model_path}")

        if not model_path:
            return jsonify({"error": "Missing model path"}), 400

        # Security check: ensure the path is within the project
        full_model_path = os.path.abspath(os.path.join(project_root, model_path))
        # Corrected security check to use startswith on the output directory
        if not full_model_path.startswith(os.path.abspath(config.OUTPUT_BASE_DIR)):
            return jsonify({"error": "Invalid model path"}), 400

        if not os.path.exists(full_model_path):
            return jsonify({"error": "Model file not found"}), 404

        with open(full_model_path, 'r', encoding="utf-8") as f:
            markdown_content = f.read()

        metadata = None
        metadata_path = full_model_path.replace('.md', '_metadata.json')
        logging.info(f"Looking for metadata at: {metadata_path}")
        if os.path.exists(metadata_path):
            logging.info("Metadata file found. Loading.")
            with open(metadata_path, 'r', encoding="utf-8") as f:
                metadata = json.load(f)
        else:
            logging.warning("Metadata file not found.")

        return jsonify({
            "success": True,
            "markdown_content": markdown_content,
            "metadata": metadata,
            "message": "Model loaded successfully"
        })
    except Exception as e:
        logging.error(f"Error during model load: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500


@app.route("/api/markdown_to_json", methods=["POST"])
def markdown_to_json():
    """
    Converts markdown content to a JSON representation for the GUI.
    """
    try:
        data = request.get_json()
        markdown_content = data.get('markdown', '')
        
        if not markdown_content:
            return jsonify({"error": "Missing markdown content"}), 400
            
        model_json = threat_model_service.markdown_to_json_for_gui(markdown_content)
        
        return jsonify({
            "success": True,
            "model_json": model_json
        })
    except Exception as e:
        logging.error(f"Error during markdown to json conversion: {e}", exc_info=True)
        # Also log the markdown content that caused the error
        try:
            data = request.get_json()
            markdown_content = data.get('markdown', '')
            logging.error(f"Problematic markdown content:\n{markdown_content}")
        except Exception as log_e:
            logging.error(f"Could not log markdown content: {log_e}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/save_model", methods=["POST"])
def save_model():
    """
    Saves the threat model along with its metadata and exact positions.
    """
    try:
        data = request.get_json()
        markdown_content = data.get('markdown', '')
        model_name = data.get('model_name', 'threat_model')
        positions_data = data.get('positions', None)  # Exact positions from UI
        
        if not markdown_content:
            return jsonify({"error": "Missing markdown content"}), 400
        
        # Ensure output directory exists
        os.makedirs(config.OUTPUT_BASE_DIR, exist_ok=True)
        
        # Create a unique filename with timestamp
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_model_name = re.sub(r'[^a-zA-Z0-9_]', '_', model_name)
        output_filename = f"{safe_model_name}_{timestamp}.md"
        output_path = os.path.join(config.OUTPUT_BASE_DIR, output_filename)
        
        # Save model with metadata and positions
        metadata_path = threat_model_service.save_model_with_metadata(
            markdown_content, output_path, positions_data
        )
        
        return jsonify({
            "success": True,
            "model_path": output_path,
            "metadata_path": metadata_path,
            "message": "Model and metadata saved successfully",
            "version": "1.0"
        })
    except Exception as e:
        logging.error(f"Error during model save: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500

@app.route("/api/generate_all", methods=["POST"])
def generate_all():
    """
    Generates all artifacts for a threat model: reports, diagrams, metadata, etc.
    This is the complete 'Generate' button functionality.
    """
    try:
        data = request.get_json()
        markdown_content = data.get('markdown', '')
        model_name = get_model_name(markdown_content)
        positions_data = data.get('positions', None)
        submodels = data.get('submodels', [])
        
        if not markdown_content:
            return jsonify({"error": "Missing markdown content"}), 400
        
        # Ensure output directory exists
        os.makedirs(config.OUTPUT_BASE_DIR, exist_ok=True)
        
        # Create a unique directory for this generation
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_model_name = re.sub(r'[^a-zA-Z0-9_]', '_', model_name)
        generation_dir = os.path.join(config.OUTPUT_BASE_DIR, f"{safe_model_name}_{timestamp}")
        os.makedirs(generation_dir, exist_ok=True)
        
        # Save the main model file
        model_filename = "main.md" # Standardize to main.md for clarity
        model_path = os.path.join(generation_dir, model_filename)
        with open(model_path, "w", encoding="utf-8") as f:
            f.write(markdown_content)

        # Save submodels
        for submodel in submodels:
            submodel_path_str = submodel.get('path', '').lstrip('./\\')
            if not submodel_path_str:
                continue
            submodel_path = os.path.join(generation_dir, submodel_path_str)
            os.makedirs(os.path.dirname(submodel_path), exist_ok=True)
            with open(submodel_path, "w", encoding="utf-8") as f:
                f.write(submodel['content'])

        # Generate all reports and diagrams using the main model path
        result = threat_model_service.generate_full_project_export(
            markdown_content, generation_dir, submodels=submodels
        )
        
        # Create a summary of generated files
        generated_files = {
            "model": model_path,
            "reports": result.get("reports", {}),
            "diagrams": result.get("diagrams", {})
        }
        
        return jsonify({
            "success": True,
            "generation_dir": generation_dir,
            "generated_files": generated_files,
            "message": "All artifacts generated successfully"
        })
    except Exception as e:
        logging.error(f"Error during complete generation: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500


@app.route("/api/save_project", methods=["POST"])
def save_project():
    """
    Saves the threat model markdown and its metadata (with calculated positions).
    This is a lightweight version of 'generate_all' for saving work in progress.
    """
    try:
        data = request.get_json()
        markdown_content = data.get('markdown', '')
        model_name = get_model_name(markdown_content)
        
        if not markdown_content:
            return jsonify({"error": "Missing markdown content"}), 400
        
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_model_name = re.sub(r'[^a-zA-Z0-9_]', '_', model_name)
        
        # Unlike generate_all, save to a consistent folder if it exists, or create one.
        project_dir = os.path.join(config.OUTPUT_BASE_DIR, safe_model_name)
        os.makedirs(project_dir, exist_ok=True)
        
        model_filename = f"{safe_model_name}_{timestamp}.md"
        model_path = os.path.join(project_dir, model_filename)
        
        # This will save the .md and create the _metadata.json with positions
        metadata_path = threat_model_service.save_model_with_metadata(
            markdown_content, model_path, positions_data=None # Pass None to trigger Graphviz layout
        )
        
        return jsonify({
            "success": True,
            "message": f"Project saved successfully in {project_dir}",
            "model_path": model_path,
            "metadata_path": metadata_path,
        })
    except Exception as e:
        logging.error(f"Error during project save: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500


@app.route("/api/check_version_compatibility", methods=["POST"])
def check_version_compatibility():
    """
    Checks if a model and its metadata have compatible versions.
    """
    try:
        data = request.get_json()
        model_path = data.get('model_path', '')
        metadata_path = data.get('metadata_path', '')
        
        if not model_path or not metadata_path:
            return jsonify({"error": "Missing model or metadata path"}), 400
        
        # Check if paths are valid and within allowed directory
        if not model_path.startswith(config.OUTPUT_BASE_DIR) or not metadata_path.startswith(config.OUTPUT_BASE_DIR):
            return jsonify({"error": "Invalid file paths"}), 400
        
        if not os.path.exists(model_path) or not os.path.exists(metadata_path):
            return jsonify({"error": "Model or metadata file not found"}), 404
        
        # Check version compatibility
        is_compatible = threat_model_service.check_version_compatibility(model_path, metadata_path)
        
        return jsonify({
            "success": True,
            "compatible": is_compatible,
            "message": "Version compatibility checked successfully"
        })
    except Exception as e:
        logging.error(f"Error during version compatibility check: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500

@app.route("/api/load_metadata", methods=["POST"])
def load_metadata():
    """
    Loads metadata from a saved metadata file.
    """
    try:
        data = request.get_json()
        metadata_path = data.get('metadata_path', '')
        
        if not metadata_path:
            return jsonify({"error": "Missing metadata path"}), 400
        
        # Check if path is valid and within allowed directory
        if not metadata_path.startswith(config.OUTPUT_BASE_DIR):
            return jsonify({"error": "Invalid metadata path"}), 400
        
        if not os.path.exists(metadata_path):
            return jsonify({"error": "Metadata file not found"}), 404
        
        # Load and return the metadata
        with open(metadata_path, 'r') as f:
            metadata = json.load(f)
        
        return jsonify({
            "success": True,
            "metadata": metadata,
            "message": "Metadata loaded successfully"
        })
    except Exception as e:
        logging.error(f"Error during metadata load: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500

@app.route("/api/export_metadata", methods=["POST"])
def export_metadata():
    """
    Exports metadata containing element positions for layout restoration.
    """
    try:
        # Get the current element positions from the service
        metadata = threat_model_service.get_element_positions()
        
        # Create a response with the metadata
        response = make_response(json.dumps(metadata, indent=2))
        response.headers['Content-Disposition'] = 'attachment; filename=element_positions.json'
        response.headers['Content-Type'] = 'application/json'
        return response
    except Exception as e:
        logging.error(f"Error during metadata export: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500


@app.route("/api/load_project", methods=["POST"])
def load_project():
    """
    Loads all threat model files from the configured project directory.
    """
    try:
        project_path = app.config.get('PROJECT_PATH')
        if not project_path:
            # Fallback to a default or scan for a project directory if one isn't explicitly set
            # For now, we'll assume a project must be set on startup.
            return jsonify({"error": "No project path is configured for the server."}), 404

        models = threat_model_service.load_project(project_path)
        
        return jsonify({
            "success": True,
            "models": models,
            "message": f"Project loaded successfully from {project_path}"
        })
    except Exception as e:
        logging.error(f"Error loading project: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500


@app.route("/api/resolve_submodels", methods=["POST"])
def resolve_submodels():
    """
    Resolves sub_model_path references from a main model against a project file structure.
    """
    try:
        data = request.get_json()
        main_model_content = data.get('main_model_content')
        project_files = data.get('project_files')

        if not main_model_content or not isinstance(project_files, list):
            return jsonify({"error": "Missing main_model_content or project_files"}), 400

        # The method is part of the class instance, so `self` is passed implicitly.
        resolved = threat_model_service.resolve_submodels(main_model_content, project_files)
        
        return jsonify({
            "success": True,
            "submodels": resolved
        })

    except Exception as e:
        logging.error(f"Error resolving submodels: {e}", exc_info=True)
        return jsonify({"error": f"An unexpected error occurred: {str(e)}"}), 500



