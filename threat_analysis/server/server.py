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
from flask import Flask, render_template, request, jsonify, send_from_directory, send_file

from threat_analysis.server.threat_model_service import ThreatModelService
from threat_analysis import config

# Add project root to sys.path
project_root = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..")
)
if project_root not in sys.path:
    sys.path.insert(0, project_root)

app = Flask(__name__, template_folder="templates")

# Initialize the service layer
threat_model_service = ThreatModelService()

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


def run_gui(model_filepath: str = None):
    """
    This function is the main entry point for the simple web server.
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

    print(
        "\n🚀 Starting Threat Model GUI. Open your browser to: http://127.0.0.1:5000/\n"
    )
    app.run(debug=True, port=5000)


def run_full_gui(model_filepath: str = None):
    """
    This function is the main entry point for the web server.
    """
    global initial_markdown_content
    if model_filepath and os.path.exists(model_filepath):
        try:
            with open(model_filepath, "r", encoding="utf-8") as f:
                initial_markdown_content = f.read()
            logging.info(f"Loaded initial threat model from {model_filepath}")
        except Exception as e:
            logging.error(
                f"Error loading initial model from {model_filepath}: {e}"
            )
            initial_markdown_content = DEFAULT_EMPTY_MARKDOWN
            logging.info(
                "Loaded initial threat model from a temporary model due to "
                "file loading error."
            )
    else:
        initial_markdown_content = DEFAULT_EMPTY_MARKDOWN
        logging.info(
            "No initial threat model file provided or found. "
            "Starting with a default empty model."
        )

    print(
        "\n🚀 Starting Threat Model Full GUI. Open your browser to: "
        "http://127.0.0.1:5001/full\n"
    )
    app.run(debug=True, port=5001)


@app.route("/")
def simple_gui():
    """Serves the simple web interface."""
    model_name = get_model_name(initial_markdown_content)
    encoded_markdown = base64.b64encode(initial_markdown_content.encode('utf-8')).decode('utf-8')
    return render_template(
        "web_interface.html",
        initial_markdown=encoded_markdown,
        model_name=model_name
    )


@app.route("/full")
def full_gui():
    """Serves the main web interface."""
    return render_template(
        "full_gui.html"
    )



@app.route("/api/update", methods=["POST"])
def update_diagram():
    """
    Receives Markdown content, generates a threat model diagram,
    and returns the HTML representation of the diagram.
    """
    logging.info("Entering update_diagram function.")
    markdown_content = request.json.get("markdown", "")
    logging.info(
        f"Received markdown content for update (first 500 chars): "
        f"\n{markdown_content[:500]}..."
    )
    if not markdown_content:
        return jsonify({"error": "Markdown content is empty"}), 400

    try:
        result = threat_model_service.update_diagram_logic(markdown_content)
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
        
        # Reuse the existing service logic
        result = threat_model_service.update_diagram_logic(markdown_content)
        model_name = get_model_name(markdown_content)
        result["model_name"] = model_name
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
        output_path, output_filename = threat_model_service.export_files_logic(markdown_content, export_format)
        absolute_output_directory = os.path.join(project_root, os.path.dirname(output_path))
        return send_from_directory(
            absolute_output_directory, output_filename, as_attachment=True
        )

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
        zip_buffer, timestamp = threat_model_service.export_all_files_logic(markdown_content)
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

        zip_buffer, timestamp = threat_model_service.export_navigator_stix_logic(markdown_content)

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

