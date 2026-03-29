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
import threading
import time
from pathlib import Path
from typing import Dict, List, Any, Optional
from flask import Flask, render_template, request, jsonify, send_from_directory, send_file, make_response, Response, stream_with_context, g
from threat_analysis import config
import asyncio
from threat_analysis.server.events import ai_status_event_queue

# Initialize the service layer lazily to speed up startup
_threat_model_service = None
_service_lock = threading.Lock()

# Rate-limit AI generation: only one long-running LLM call at a time
_ai_generation_lock = threading.Lock()

class SSEBroadcaster:
    def __init__(self):
        self.listeners = []
        self.lock = threading.Lock()

    def subscribe(self):
        import queue
        q = queue.Queue()
        with self.lock:
            self.listeners.append(q)
        return q

    def unsubscribe(self, q):
        with self.lock:
            if q in self.listeners:
                self.listeners.remove(q)

    def broadcast(self, event_name, data):
        message = f"event: {event_name}\ndata: {json.dumps(data)}\n\n"
        with self.lock:
            for q in self.listeners:
                q.put(message)

ai_status_broadcaster = SSEBroadcaster()
progress_broadcaster = SSEBroadcaster()

def get_threat_model_service():
    global _threat_model_service
    if _threat_model_service is None:
        with _service_lock:
            if _threat_model_service is None:
                from threat_analysis.server.threat_model_service import ThreatModelService
                _threat_model_service = ThreatModelService()
    return _threat_model_service


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

@app.before_request
def before_request():
    g.start_time = time.time()
    g.request_received_time = time.time()

@app.after_request
def after_request(response):
    if hasattr(g, "start_time"):
        # Total time from request start to response ready
        total_duration_ms = (time.time() - g.start_time) * 1000

        processing_time_ms = g.get("processing_time_ms", 0)
        generation_time_ms = g.get("generation_time_ms", 0)

        transmission_latency_ms = 0
        if "X-Request-Start" in request.headers:
            try:
                request_start_time = float(request.headers["X-Request-Start"])
                transmission_latency_ms = (g.request_received_time - request_start_time) * 1000
            except (ValueError, TypeError):
                pass
        
        # The time to send the response is what's left over
        response_transmission_ms = total_duration_ms - processing_time_ms - generation_time_ms - transmission_latency_ms

        logging.debug(
            f"API Latency Report for {request.path} - "
            f"Latence de transmission: {transmission_latency_ms:.2f}ms, "
            f"Temps de traitement: {processing_time_ms:.2f}ms, "
            f"Temps de génération de réponse: {generation_time_ms:.2f}ms, "
            f"Temps de transmission de réponse: {response_transmission_ms:.2f}ms"
        )
    return response

def initialize_ai_in_background():
    """Run AI initialization in a separate thread with its own event loop."""
    import asyncio

    async def init_and_log():
        logging.info("Starting AI initialization in background...")
        try:
            service = get_threat_model_service()
            await service.init_ai()
            
            # The status is already updated inside service.init_ai()
            # but we force a broadcast here to be sure the frontend gets it
            logging.info(f"Background AI initialization complete. Online: {service.ai_online}")

            data = {"ai_online": service.ai_online}
            ai_status_broadcaster.broadcast("ai_status", data)
            
            # Also put it in the event queue for other services
            try:
                from threat_analysis.server.events import ai_status_event_queue
                ai_status_event_queue.put(f"event: ai_status\ndata: {json.dumps(data)}\n\n")
            except:
                pass

        except Exception as e:
            logging.error(f"Error during background AI initialization: {e}", exc_info=True)
            service = get_threat_model_service()
            if service:
                service.ai_online = False

            data = {"ai_online": False, "error": "AI initialization failed."}
            ai_status_broadcaster.broadcast("ai_status", data)

    try:
        asyncio.run(init_and_log())
    except Exception as e:
        logging.error(f"Error during background AI initialization: {e}", exc_info=True)

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

config_js_path = os.path.join(os.path.dirname(__file__), "static", "js", "config.js")
max_attempts = 3
attempt = 0

while attempt < max_attempts:
    if os.path.exists(config_js_path):
        # Check if the file has content
        try:
            with open(config_js_path, "r") as f:
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
initial_project_path = None
initial_model_file_path: Optional[str] = None

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
    start_time = time.time()
    logging.info(f"[{time.time() - start_time:.4f}s] Server startup sequence initiated.")

    global initial_markdown_content
    global initial_project_path
    global initial_model_file_path
    effective_model_path = None

    if project_path and os.path.isdir(project_path):
        initial_project_path = project_path
        logging.info(f"[{time.time() - start_time:.4f}s] Project mode: loading from {project_path}")
        effective_model_path = os.path.join(project_path, "main.md")
        if not os.path.exists(effective_model_path):
             logging.warning(f"main.md not found in project path, will start with an empty model.")

    elif model_filepath:
        effective_model_path = model_filepath

    if effective_model_path and os.path.exists(effective_model_path):
        try:
            with open(effective_model_path, "r", encoding="utf-8") as f:
                initial_markdown_content = f.read()
            initial_model_file_path = os.path.abspath(effective_model_path)
            logging.info(f"[{time.time() - start_time:.4f}s] Loaded initial threat model from {effective_model_path}")
        except Exception as e:
            logging.error(f"[{time.time() - start_time:.4f}s] Error loading initial model from {effective_model_path}: {e}")
            initial_markdown_content = DEFAULT_EMPTY_MARKDOWN
            logging.debug(f"[{time.time() - start_time:.4f}s] Loaded initial threat model from a temporary model due to file loading error.")
    else:
        initial_markdown_content = DEFAULT_EMPTY_MARKDOWN
        if project_path or model_filepath:
             logging.warning(f"[{time.time() - start_time:.4f}s] No initial threat model file found at the specified path. Starting with a default empty model.")
        else:
            logging.debug(f"[{time.time() - start_time:.4f}s] No initial threat model file provided. Starting with a default empty model.")

    logging.info(f"[{time.time() - start_time:.4f}s] Initializing threat model service...")
    # The ThreatModelService is already instantiated globally
    logging.info(f"[{time.time() - start_time:.4f}s] Threat model service initialized.")

    # Start AI initialization in a background thread
    import threading
    logging.info(f"[{time.time() - start_time:.4f}s] Starting AI initialization in background thread...")
    ai_init_thread = threading.Thread(target=initialize_ai_in_background, daemon=True)
    ai_init_thread.start()
    logging.info(f"[{time.time() - start_time:.4f}s] AI initialization thread started.")
    
    print(
        "\n🚀 Starting Threat Model Server. Open your browser to: http://127.0.0.1:5000/\n"
    )
    logging.info(f"[{time.time() - start_time:.4f}s] Starting Flask app...")
    app.run(debug=os.environ.get("FLASK_DEBUG", "false").lower() == "true", port=5000, threaded=True)


@app.route("/static/<path:filename>")
def serve_static(filename):
    """Serve static files from the static directory."""
    static_folder = app.static_folder or os.path.join(server_dir, "static")
    return send_from_directory(static_folder, filename)

@app.route("/api/data_dictionary")
def get_data_dictionary():
    """Serves the data dictionary XML file."""
    xml_path = os.path.join(project_root, "threat_analysis", "external_data", "data_dictionary.xml")
    if os.path.exists(xml_path):
        return send_file(xml_path, mimetype="application/xml")
    return jsonify({"error": "Data dictionary not found"}), 404

@app.route("/")
def index():
    """Serves the main menu."""
    return render_template("index.html")

@app.route("/simple")
def simple_mode():
    """
    Serves the simple web interface.
    """
    model_name = get_model_name(initial_markdown_content)
    
    # Prepare initial_models for the template
    if initial_project_path:
        initial_models_data = get_threat_model_service().load_project(initial_project_path)
    else:
        initial_models_data = [{
            "path": "main.md",
            "content": initial_markdown_content
        }]
    
    initial_models_json = json.dumps(initial_models_data)
    initial_models_b64 = base64.b64encode(initial_models_json.encode('utf-8')).decode('utf-8')

    return render_template(
        "simple_mode.html",
        initial_markdown=json.dumps(initial_markdown_content),
        DEFAULT_EMPTY_MARKDOWN=json.dumps(DEFAULT_EMPTY_MARKDOWN),
        model_name=model_name,
        ai_online=get_threat_model_service().ai_online,
        initial_models=initial_models_b64,
    )


@app.route("/graphical")
def graphical_editor():
    """
    Serves the main web interface.
    """
    return render_template(
        "graphical_editor.html",
        ai_online=get_threat_model_service().ai_online  # Pass AI status to template
    )


@app.route("/api/ai_status")
def ai_status():
    """Returns the status of the AI server."""
    service = get_threat_model_service()
    if service:
        return jsonify({"ai_online": service.ai_online})
    return jsonify({"ai_online": False}), 503


@app.route("/api/ai_status_stream")
def ai_status_stream():
    def generate_events():
        # Send current status immediately upon connection
        service = get_threat_model_service()
        is_online = service.ai_online if service else False
        data = {"ai_online": is_online}
        yield f"event: ai_status\ndata: {json.dumps(data)}\n\n"

        q = ai_status_broadcaster.subscribe()
        try:
            while True:
                try:
                    event_data = q.get(timeout=30)
                except Exception:
                    yield ": keepalive\n\n"
                    continue
                yield event_data
        finally:
            ai_status_broadcaster.unsubscribe(q)

    return Response(stream_with_context(generate_events()), mimetype="text/event-stream")

@app.route("/api/progress_stream")
def progress_stream():
    def generate_events():
        q = progress_broadcaster.subscribe()
        try:
            while True:
                try:
                    event_data = q.get(timeout=30)
                except Exception:
                    yield ": keepalive\n\n"
                    continue
                yield event_data
        finally:
            progress_broadcaster.unsubscribe(q)

    return Response(stream_with_context(generate_events()), mimetype="text/event-stream")


@app.route("/api/generate_markdown_from_prompt", methods=["POST"])
async def generate_markdown_from_prompt():
    """
    Receives a natural language prompt, uses AI to generate a threat model in Markdown DSL,
    and returns it in a JSON object. This version is more robust to AI response variations.
    """
    logging.info("Received request for /api/generate_markdown_from_prompt")
    service = get_threat_model_service()
    if not service.ai_online:
        logging.warning("AI request rejected: service.ai_online is False")
        return jsonify({"error": "AI server is not available. This feature is disabled."}), 503

    if not _ai_generation_lock.acquire(blocking=False):
        logging.warning("AI generation already in progress — rejecting concurrent request")
        return jsonify({"error": "AI generation already in progress. Please wait and retry."}), 429

    data = request.json
    prompt = data.get("prompt")
    markdown = data.get("markdown")  # Existing markdown
    if not prompt:
        _ai_generation_lock.release()
        return jsonify({"error": "Prompt is missing"}), 400

    try:
        full_chunks = []
        logging.info(f"Starting AI generation for prompt: {prompt[:50]}...")
        async for chunk in service.generate_markdown_from_prompt(prompt, markdown):
            if chunk.startswith("Error:"):
                logging.error(f"AI Service returned an error chunk: {chunk}")
                return jsonify({"error": chunk}), 500
            full_chunks.append(chunk)

        full_response = "".join(full_chunks)
        logging.info(f"AI generation complete. Response length: {len(full_response)}")

        extracted_markdown = None
        # Improved regex: makes 'markdown' optional and is non-greedy.
        match = re.search(r"```(?:markdown)?\n(.*?)\n```", full_response, re.DOTALL)

        if match:
            extracted_markdown = match.group(1).strip()
        else:
            logging.warning(f"AI response did not contain a clear markdown block. Raw response preview: {full_response[:200]}")
            # Fallback: find the start of the threat model and clean up common AI chatter.
            model_start_index = full_response.find("# Threat Model:")
            if model_start_index != -1:
                extracted_markdown = full_response[model_start_index:].strip()
                end_block_index = extracted_markdown.rfind("```")
                if end_block_index != -1:
                    extracted_markdown = extracted_markdown[:end_block_index].strip()
            else:
                logging.error("Failed to extract valid DSL from AI response.")
                return jsonify({
                    "error": "Failed to extract a valid threat model from the AI response.",
                    "raw_response": full_response
                }), 500

        return jsonify({"markdown_content": extracted_markdown})

    except Exception as e:
        logging.exception(f"Exception during AI generation: {e}")
        return jsonify({"error": "An internal error occurred during AI generation. Check server logs for details."}), 500
    finally:
        _ai_generation_lock.release()



@app.route("/api/update", methods=["POST"])
def update_diagram():
    """
    Receives Markdown content, generates a threat model diagram,
    and returns the HTML representation of the diagram.
    """
    logging.debug("Entering update_diagram function.")
    data = request.json
    markdown_content = data.get("markdown", "")
    submodels = data.get("submodels", [])

    if not markdown_content:
        return jsonify({"error": "Markdown content is empty"}), 400

    try:
        result = get_threat_model_service().update_diagram_logic(markdown_content, submodels=submodels)
        g.processing_time_ms = result.get("processing_time_ms", 0)
        g.generation_time_ms = result.get("generation_time_ms", 0)
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
        return jsonify({"error": "An internal error occurred. Check server logs for details."}), 500


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
    
    boundaries = data.get("boundaries", [])
    actors = data.get("actors", [])
    servers = data.get("servers", [])
    data_elements = data.get("data", [])
    dataflows = data.get("dataflows", [])

    boundary_map = {b["id"]: b["name"] for b in boundaries}

    markdown_lines.append("\n## Boundaries")
    for boundary in boundaries:
        props_str = _format_properties(boundary, ["description"])
        markdown_lines.append(f"- **{boundary['name']}**: {props_str}")

    markdown_lines.append("\n## Actors")
    for actor in actors:
        props = {"boundary": boundary_map.get(actor.get("parentId"))}
        props_str = _format_properties({**actor, **props}, ["boundary", "description"])
        markdown_lines.append(f"- **{actor['name']}**: {props_str}")

    markdown_lines.append("\n## Servers")
    for server in servers:
        props = {"boundary": boundary_map.get(server.get("parentId"))}
        props_str = _format_properties({**server, **props}, ["boundary", "description"])
        markdown_lines.append(f"- **{server['name']}**: {props_str}")

    markdown_lines.append("\n## Data")
    for data_item in data_elements:
        props_str = _format_properties(data_item, ["description", "classification"])
        markdown_lines.append(f"- **{data_item['name']}**: {props_str}")

    markdown_lines.append("\n## Dataflows")
    nodes = {item["id"]: item for item in actors + servers + data_elements}
    for df in dataflows:
        from_node = nodes.get(df["from"])
        to_node = nodes.get(df["to"])
        if from_node and to_node:
            df_name = df.get("name") or f"{from_node['name']} to {to_node['name']}"
            props_str = _format_properties(df, ["protocol", "description"])
            markdown_lines.append(
                f'- **{df_name}**: from="{from_node["name"]}", to="{to_node["name"]}", {props_str}'
            )

    return "\n".join(markdown_lines)


@app.route("/api/graphical_update", methods=["POST"])
def graphical_update():
    """
    Receives JSON graph data, converts it to Markdown, and returns the analysis.
    """
    logging.debug("Entering graphical_update function.")
    json_data = request.json
    if not json_data:
        return jsonify({"error": "JSON data is empty"}), 400

    try:
        markdown_content = convert_json_to_markdown(json_data)
        logging.debug(f"Converted Markdown:\n{markdown_content}")
        
        # Ensure output directory exists (using the same structure as other modes)
        os.makedirs(config.OUTPUT_BASE_DIR, exist_ok=True)
        
        # Reuse the existing service logic
        result = get_threat_model_service().update_diagram_logic(
            markdown_content=markdown_content
        )
        model_name = get_model_name(markdown_content)
        result["model_name"] = model_name
        result["output_dir"] = str(config.OUTPUT_BASE_DIR)
        return jsonify(result)

    except Exception as e:
        logging.error(f"An unexpected error occurred during graphical update: {e}", exc_info=True)
        return jsonify({"error": "An internal error occurred. Check server logs for details."}), 500



@app.route("/api/export", methods=["POST"])
def export_files():
    """
    Handles exporting the model in various formats (SVG, HTML diagram, HTML report).
    """
    markdown_content = request.json.get("markdown", "")
    export_format = request.json.get("format")  # "svg", "diagram", "report"
    logging.debug(f"Entering export_files function for format: {export_format}")

    if not markdown_content or not export_format:
        return (
            jsonify({"error": "Missing markdown content or export format"}),
            400,
        )

    try:
        output_path, output_filename = get_threat_model_service().export_files_logic(
            markdown_content=markdown_content, export_format=export_format,
            model_file_path=initial_model_file_path,
        )
        absolute_output_directory = os.path.join(project_root, os.path.dirname(output_path))
        
        # Return both the file and the output directory information
        response = send_from_directory(
            absolute_output_directory, output_filename, as_attachment=True
        )
        
        # Add custom header with output directory information
        response.headers["X-Output-Directory"] = str(config.OUTPUT_BASE_DIR)
        return response

    except ValueError as e:
        logging.error(f"Error during export: {e}")
        return jsonify({"error": str(e)}), 400
    except RuntimeError as e:
        logging.error(f"Error during export: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500
    except Exception as e:
        logging.error(f"An unexpected error occurred during export: {e}", exc_info=True)
        return jsonify({"error": "An internal error occurred. Check server logs for details."}), 500


@app.route("/api/export_all", methods=["POST"])
def export_all_files():
    """
    Handles exporting all generated files (Markdown, SVG, HTML diagram, HTML report, JSON analysis)
    as a single ZIP archive.
    """
    markdown_content = request.json.get("markdown", "")
    if not markdown_content:
        return jsonify({"error": "Missing markdown content"}), 400
    logging.debug("Entering export_all_files function.")

    try:
        submodels = request.json.get("submodels", [])
        zip_buffer, timestamp = get_threat_model_service().export_all_files_logic(
            markdown_content=markdown_content, submodels=submodels,
            model_file_path=initial_model_file_path,
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
        return jsonify({"error": "An internal error occurred. Check server logs for details."}), 500

@app.route("/api/export_navigator_stix", methods=["POST"])
def export_navigator_stix_files():

    logging.debug("Received request for /api/export_navigator_stix.")

    """

    Handles exporting ATT&CK Navigator layer and STIX report as a single ZIP archive.

    """

    markdown_content = request.json.get("markdown", "")

    if not markdown_content:

        return jsonify({"error": "Missing markdown content"}), 400

    logging.debug("Entering export_navigator_stix_files function.")



    try:
        submodels = request.json.get("submodels", [])
        zip_buffer, timestamp = get_threat_model_service().export_navigator_stix_logic(
            markdown_content, submodels=submodels, model_file_path=initial_model_file_path,
        )
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

        return jsonify({"error": "An internal error occurred. Check server logs for details."}), 500





@app.route("/api/export_attack_flow", methods=["POST"])

def export_attack_flow():

    """

    Handles exporting Attack Flow diagrams as a single ZIP archive.

    """

    json_data = request.json

    if not json_data:

        return jsonify({"error": "Missing model data"}), 400



    logging.debug("Entering export_attack_flow function.")



    try:

        markdown_content = convert_json_to_markdown(json_data)

        zip_buffer, timestamp = get_threat_model_service().export_attack_flow_logic(
            markdown_content, model_file_path=initial_model_file_path,
        )



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
        return jsonify({"error": "An internal error occurred. Check server logs for details."}), 500


@app.route("/api/models", methods=["GET"])
def list_models():
    """
    Lists all threat models (.md files) in the output directory.
    """
    try:
        output_dir = config.OUTPUT_BASE_DIR
        model_files = []
        for filepath in glob.iglob(os.path.join(output_dir, "**", "*.md"), recursive=True):
            model_files.append(os.path.relpath(filepath, project_root))
        return jsonify({"success": True, "models": model_files})
    except Exception as e:
        logging.error(f"Error listing models: {e}", exc_info=True)
        return jsonify({"error": "An internal error occurred. Check server logs for details."}), 500


@app.route("/api/load_model", methods=["POST"])
def load_model():
    """
    Loads a threat model and its metadata.
    """
    try:
        data = request.get_json()
        model_path = data.get("model_path", "")
        logging.debug(f"Received request to load model: {model_path}")

        if not model_path:
            return jsonify({"error": "Missing model path"}), 400

        # Security check: ensure the path is within the output directory (symlink-safe).
        full_model_path = Path(os.path.abspath(os.path.join(project_root, model_path)))
        if not full_model_path.is_relative_to(Path(config.OUTPUT_BASE_DIR).resolve()):
            return jsonify({"error": "Invalid model path"}), 400

        if not os.path.exists(full_model_path):
            return jsonify({"error": "Model file not found"}), 404

        with open(full_model_path, "r", encoding="utf-8") as f:
            markdown_content = f.read()

        metadata = None
        metadata_path = os.path.splitext(str(full_model_path))[0] + "_metadata.json"
        logging.debug(f"Looking for metadata at: {metadata_path}")
        if os.path.exists(metadata_path):
            logging.debug("Metadata file found. Loading.")
            with open(metadata_path, "r", encoding="utf-8") as f:
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
        return jsonify({"error": "An internal error occurred. Check server logs for details."}), 500


@app.route("/api/markdown_to_json", methods=["POST"])
def markdown_to_json():
    """
    Converts markdown content to a JSON representation for the GUI.
    """
    try:
        data = request.get_json()
        markdown_content = data.get("markdown", "")
        
        if not markdown_content:
            return jsonify({"error": "Missing markdown content"}), 400
            
        model_json = get_threat_model_service().markdown_to_json_for_gui(markdown_content)
        
        return jsonify({
            "success": True,
            "model_json": model_json
        })
    except Exception as e:
        logging.error(f"Error during markdown to json conversion: {e}", exc_info=True)
        # Also log the markdown content that caused the error
        try:
            data = request.get_json()
            markdown_content = data.get("markdown", "")
            logging.error(f"Problematic markdown content:\n{markdown_content}")
        except Exception as log_e:
            logging.error(f"Could not log markdown content: {log_e}")
        return jsonify({"error": "An internal error occurred. Check server logs for details."}), 500


@app.route("/api/save_model", methods=["POST"])
def save_model():
    """
    Saves the threat model along with its metadata and exact positions.
    """
    try:
        data = request.get_json()
        markdown_content = data.get("markdown", "")
        model_name = data.get("model_name", "threat_model")
        positions_data = data.get("positions", None)  # Exact positions from UI
        
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
        metadata_path = get_threat_model_service().save_model_with_metadata(
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
        return jsonify({"error": "An internal error occurred. Check server logs for details."}), 500

@app.route("/api/generate_all", methods=["POST"])
def generate_all():
    """
    Generates all artifacts for a threat model: reports, diagrams, metadata, etc.
    This is the complete 'Generate' button functionality.
    """
    try:
        data = request.get_json()
        markdown_content = data.get("markdown", "")
        active_path = data.get("path", "main.md")
        model_name = get_model_name(markdown_content)
        positions_data = data.get("positions", None)
        submodels = data.get("submodels", [])
        
        if not markdown_content:
            return jsonify({"error": "Missing markdown content"}), 400
        
        # Ensure output directory exists
        os.makedirs(config.OUTPUT_BASE_DIR, exist_ok=True)
        
        # Create a unique directory for this generation
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_model_name = re.sub(r'[^a-zA-Z0-9_]', '_', model_name)
        generation_dir = os.path.join(config.OUTPUT_BASE_DIR, f"{safe_model_name}_{timestamp}")
        os.makedirs(generation_dir, exist_ok=True)
        
        # In Project mode, we need to reconstruct the project structure.
        # We save every tab to its ACTUAL path.
        # The main entry point for the generator is ALWAYS main.md at the root of generation_dir.
        
        # 1. Save all submodels (other tabs)
        for submodel in submodels:
            sub_path = submodel.get("path")
            sub_content = submodel.get("content")
            if sub_path and sub_content:
                full_sub_path = os.path.join(generation_dir, sub_path.lstrip('./\\'))
                os.makedirs(os.path.dirname(full_sub_path), exist_ok=True)
                with open(full_sub_path, "w", encoding="utf-8") as f:
                    f.write(sub_content)

        # 1b. Write extra files (BOM/*.yaml, context/*.yaml) sent directly by the client.
        # When the browser explicitly sends "extra_files" (even an empty list), it has taken
        # ownership of BOM/context delivery — skip the server-side filesystem copy (1c) to
        # prevent stale server globals from contaminating the output with a different project.
        browser_managed_files = "extra_files" in data
        extra_files = data.get("extra_files", [])
        for ef in extra_files:
            ef_path = ef.get("path", "").lstrip('./\\')
            ef_content = ef.get("content", "")
            if ef_path and ef_content:
                full_ef_path = os.path.join(generation_dir, ef_path)
                os.makedirs(os.path.dirname(full_ef_path), exist_ok=True)
                with open(full_ef_path, "w", encoding="utf-8") as f:
                    f.write(ef_content)

        # 1c. Copy supporting directories (context/, BOM/) from the source project.
        # Only performed when the browser did NOT explicitly send extra_files (e.g. CLI usage
        # or server started with --model / --project and no browser UI involved).
        # When the browser is active (browser_managed_files=True), it already sent the correct
        # files for the currently-loaded project — using server globals here would risk copying
        # from a stale/different project if the user navigated between projects in the UI.
        if not browser_managed_files:
            def _find_src_root() -> Optional[Path]:
                candidates = []
                if initial_model_file_path:
                    p = Path(initial_model_file_path).parent
                    if p.is_dir():
                        candidates.append(p)
                if initial_project_path:
                    candidates.append(Path(initial_project_path))
                for c in candidates:
                    if (c / "main.md").exists() or (c / "model.md").exists():
                        return c
                return None

            _src_root = _find_src_root()
            if _src_root:
                import shutil as _shutil
                src_root = _src_root
                dst_root = Path(generation_dir)
                logging.debug("generate_all: copying context/BOM from source root: %s", src_root)
                for extra_name in ("context",):
                    src = src_root / extra_name
                    if src.is_dir():
                        dst = dst_root / extra_name
                        if not dst.exists():
                            try:
                                _shutil.copytree(str(src), str(dst))
                                logging.info("generate_all: copied %s → %s", src, dst)
                            except Exception as _copy_err:
                                logging.warning("generate_all: could not copy %s: %s", src, _copy_err)
                # BOM directories may exist at root and inside each sub-model directory
                for bom_dir in src_root.rglob("BOM"):
                    if bom_dir.is_dir():
                        rel = bom_dir.relative_to(src_root)
                        dst = dst_root / rel
                        if not dst.exists():
                            try:
                                _shutil.copytree(str(bom_dir), str(dst))
                                logging.info("generate_all: copied BOM %s → %s", bom_dir, dst)
                            except Exception as _copy_err:
                                logging.warning("generate_all: could not copy BOM %s: %s", bom_dir, _copy_err)
            else:
                logging.info(
                    "generate_all: no source project path known (server started without --model / --project). "
                    "context/ and BOM/ files must be sent via extra_files by the browser. "
                    "Received %d extra_files.", len(extra_files)
                )
        else:
            logging.debug(
                "generate_all: browser_managed_files=True — skipping server-side BOM/context copy. "
                "Received %d extra_files from browser.", len(extra_files)
            )

        # 2. Save the active tab content to its ACTUAL path
        full_active_path = os.path.join(generation_dir, active_path.lstrip('./\\'))
        os.makedirs(os.path.dirname(full_active_path), exist_ok=True)
        with open(full_active_path, "w", encoding="utf-8") as f:
            f.write(markdown_content)

        # 3. Handle Metadata/Positions for the active file
        # We use standard main.md for metadata if the active file IS main.md, otherwise we use its name
        metadata_filename = active_path.replace(".md", "_metadata.json")
        metadata_path = os.path.join(generation_dir, metadata_filename)
        # Note: save_model_with_metadata is used here to generate/save positions
        get_threat_model_service().save_model_with_metadata(
            markdown_content, full_active_path, positions_data
        )

        # 4. Ensure a main.md exists at the root for the generator.
        # We need the ACTUAL main.md content for the first argument of the service call.
        target_main_md = os.path.join(generation_dir, "main.md")
        final_main_content = markdown_content if active_path == "main.md" else None
        
        if not final_main_content:
            # Look for main.md in submodels
            for sub in submodels:
                if sub.get("path") == "main.md":
                    final_main_content = sub.get("content")
                    break
        
        if not final_main_content:
            # Fallback: if no main.md found, use active tab as main
            final_main_content = markdown_content
            if not os.path.exists(target_main_md):
                with open(target_main_md, "w", encoding="utf-8") as f:
                    f.write(markdown_content)

        # Helper to bridge progress to broadcaster
        def progress_cb(percent, message):
            progress_broadcaster.broadcast("progress", {"percent": percent, "message": message})

        # Generate all reports and diagrams.
        # Pass the generation_dir main.md as model_file_path so that single-model
        # GDAF context resolution (which uses _model_file_path to anchor relative paths
        # like "context/my_context.yaml") searches inside generation_dir, where
        # step 1b/1c already wrote context/ and BOM/ files.
        _gen_main_md = str(Path(generation_dir) / "main.md")
        result = get_threat_model_service().generate_full_project_export(
            final_main_content, Path(generation_dir), submodels=submodels,
            progress_callback=progress_cb, project_root=Path(generation_dir),
            model_file_path=_gen_main_md,
        )
        
        # Create a summary of generated files
        generated_files = {
            "model": target_main_md,
            "metadata": metadata_path,
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
        return jsonify({"error": "An internal error occurred. Check server logs for details."}), 500


@app.route("/api/save_project", methods=["POST"])
def save_project():
    """
    Saves the threat model markdown and its metadata (with calculated positions).
    This is a lightweight version of 'generate_all' for saving work in progress.
    """
    try:
        data = request.get_json()
        markdown_content = data.get("markdown", "")
        model_name = get_model_name(markdown_content)
        
        if not markdown_content:
            return jsonify({"error": "Missing markdown content"}), 400
        
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_model_name = re.sub(r'[^a-zA-Z0-9_]', '_', model_name)
        
        project_dir = os.path.join(config.OUTPUT_BASE_DIR, safe_model_name)
        os.makedirs(project_dir, exist_ok=True)
        
        model_filename = f"{safe_model_name}_{timestamp}.md"
        model_path = os.path.join(project_dir, model_filename)
        
        # This will save the .md and create the _metadata.json with positions
        metadata_path = get_threat_model_service().save_model_with_metadata(
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
        return jsonify({"error": "An internal error occurred. Check server logs for details."}), 500


@app.route("/api/check_version_compatibility", methods=["POST"])
def check_version_compatibility():
    """
    Checks if a model and its metadata have compatible versions.
    """
    try:
        data = request.get_json()
        model_path = data.get("model_path", "")
        metadata_path = data.get("metadata_path", "")
        
        if not model_path or not metadata_path:
            return jsonify({"error": "Missing model or metadata path"}), 400
        
        # Security check: ensure the paths are within the output directory (symlink-safe).
        output_base_resolved = Path(config.OUTPUT_BASE_DIR).resolve()
        full_model_path = Path(os.path.abspath(os.path.join(project_root, model_path)))
        full_metadata_path = Path(os.path.abspath(os.path.join(project_root, metadata_path)))

        if not full_model_path.is_relative_to(output_base_resolved) or not full_metadata_path.is_relative_to(output_base_resolved):
            return jsonify({"error": "Invalid file paths"}), 400

        if not os.path.exists(full_model_path) or not os.path.exists(full_metadata_path):
            return jsonify({"error": "Model or metadata file not found"}), 404

        is_compatible = get_threat_model_service().check_version_compatibility(full_model_path, full_metadata_path)

        return jsonify({
            "success": True,
            "compatible": is_compatible
        })
    except Exception as e:
        logging.error(f"Error during version check: {e}", exc_info=True)
        return jsonify({"error": "An internal error occurred. Check server logs for details."}), 500


@app.route("/api/load_metadata", methods=["POST"])
def load_metadata():
    """
    Loads metadata from a saved metadata file.
    """
    try:
        data = request.get_json()
        metadata_path = data.get("metadata_path", "")
        
        if not metadata_path:
            return jsonify({"error": "Missing metadata path"}), 400
        
        # Security check: ensure the path is within the output directory (symlink-safe).
        full_metadata_path = Path(os.path.abspath(os.path.join(project_root, metadata_path)))
        if not full_metadata_path.is_relative_to(Path(config.OUTPUT_BASE_DIR).resolve()):
            return jsonify({"error": "Invalid metadata path"}), 400

        if not os.path.exists(full_metadata_path):
            return jsonify({"error": "Metadata file not found"}), 404
        
        # Load and return the metadata
        with open(metadata_path, "r") as f:
            metadata = json.load(f)
        
        return jsonify({
            "success": True,
            "metadata": metadata,
            "message": "Metadata loaded successfully"
        })
    except Exception as e:
        logging.error(f"Error during metadata load: {e}", exc_info=True)
        return jsonify({"error": "An internal error occurred. Check server logs for details."}), 500

@app.route("/api/export_metadata", methods=["POST"])
def export_metadata():
    """
    Exports metadata containing element positions for layout restoration.
    """
    try:
        # Get the current element positions from the service
        metadata = get_threat_model_service().get_element_positions()

        # Create a response with the metadata
        response = make_response(json.dumps(metadata, indent=2))
        response.headers["Content-Disposition"] = "attachment; filename=element_positions.json"
        response.headers["Content-Type"] = "application/json"
        return response
    except Exception as e:
        logging.error(f"Error during metadata export: {e}", exc_info=True)
        return jsonify({"error": "An internal error occurred. Check server logs for details."}), 500


@app.route("/api/export_json", methods=["POST"])
async def export_json():
    """Export threat model as validated JSON report (schema v1.0)."""
    data = await request.get_json()
    if not data:
        return jsonify({"error": "Missing request body"}), 400

    markdown_content = data.get("markdown_content") or data.get("markdown", "")
    if not markdown_content:
        return jsonify({"error": "Missing markdown_content"}), 400

    try:
        from threat_analysis.core.model_factory import create_threat_model
        import tempfile

        threat_model = create_threat_model(
            markdown_content=markdown_content,
            model_name=get_model_name(markdown_content),
            model_description="JSON export from web interface",
            cve_service=get_threat_model_service().cve_service,
            validate=True,
            model_file_path=initial_model_file_path,
        )
        if not threat_model:
            return jsonify({"error": "Failed to create threat model"}), 400

        grouped_threats = threat_model.process_threats()

        with tempfile.TemporaryDirectory() as tmp_dir:
            json_path = Path(tmp_dir) / "threat_model.json"
            get_threat_model_service().report_generator.generate_json_export(
                threat_model, grouped_threats, json_path
            )
            with open(json_path, "r", encoding="utf-8") as f:
                json_content = f.read()

        response = make_response(json_content)
        response.headers["Content-Type"] = "application/json"
        response.headers["Content-Disposition"] = 'attachment; filename="threat_model.json"'
        return response

    except ValueError as e:
        logging.error(f"Validation error during JSON export: {e}")
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        logging.error(f"Unexpected error during JSON export: {e}", exc_info=True)
        return jsonify({"error": "An internal error occurred. Check server logs for details."}), 500


@app.route("/api/validate_markdown", methods=["POST"])
async def validate_markdown():
    """Fast structural validation of DSL markdown (no threat processing)."""
    try:
        data = await request.get_json()
    except Exception:
        data = None
    if not data:
        return jsonify({"error": "Missing request body"}), 400

    markdown_content = data.get("markdown_content") or data.get("markdown", "")
    if not markdown_content:
        return jsonify({"valid": False, "errors": ["Empty markdown content"], "warnings": [],
                        "component_count": {"actors": 0, "servers": 0, "dataflows": 0, "boundaries": 0}}), 200

    try:
        from threat_analysis.core.model_factory import create_threat_model
        from threat_analysis.core.model_validator import ModelValidator

        threat_model = create_threat_model(
            markdown_content=markdown_content,
            model_name="ValidationCheck",
            model_description="",
            cve_service=get_threat_model_service().cve_service,
            validate=False,  # Skip heavy validation; we run ModelValidator manually below
            model_file_path=None,
        )
        if not threat_model:
            return jsonify({
                "valid": False,
                "errors": ["Failed to parse the threat model. Check DSL syntax."],
                "warnings": [],
                "component_count": {"actors": 0, "servers": 0, "dataflows": 0, "boundaries": 0},
            }), 200

        validator = ModelValidator(threat_model)
        errors = validator.validate()
        warnings: List[str] = []

        # Soft warnings: unused boundaries already emitted as errors by validator;
        # extract them to downgrade to warnings for the UI
        hard_errors = []
        for e in errors:
            if "defined but not used" in e:
                warnings.append(e)
            else:
                hard_errors.append(e)

        component_count = {
            "actors": len(threat_model.actors),
            "servers": len(threat_model.servers),
            "dataflows": len(threat_model.dataflows),
            "boundaries": len(threat_model.boundaries),
        }

        return jsonify({
            "valid": len(hard_errors) == 0,
            "errors": hard_errors,
            "warnings": warnings,
            "component_count": component_count,
        })

    except Exception as e:
        logging.debug("Markdown validation skipped (concurrent edit): %s", e)
        return jsonify({"skipped": True}), 200


@app.route("/api/set_project_path", methods=["POST"])
async def set_project_path():
    """Set the project base path for BOM/context auto-discovery."""
    global initial_model_file_path, initial_project_path

    data = await request.get_json()
    if not data:
        return jsonify({"success": False, "error": "Missing request body"}), 400

    path_str = data.get("path", "").strip()
    if not path_str:
        return jsonify({"success": False, "error": "Missing path"}), 400

    try:
        path_obj = Path(path_str)
        if not path_obj.is_dir():
            return jsonify({"success": False, "error": "Path does not exist or is not a directory"}), 400

        # Accept paths anywhere on disk (not restricted to PROJECT_ROOT) because users
        # may have their models outside the installation directory.
        resolved = str(path_obj.resolve())

        bom_available = (path_obj / "BOM").is_dir()
        context_available = (path_obj / "context").is_dir()

        # Point initial_model_file_path at a plausible model file within the directory so
        # that ExportService auto-discovery of BOM/ and context/ is activated.
        for candidate in ("main.md", "model.md"):
            candidate_path = path_obj / candidate
            if candidate_path.exists():
                initial_model_file_path = str(candidate_path.resolve())
                break
        else:
            # No .md found — use a synthetic path so the parent dir is set correctly
            initial_model_file_path = str(path_obj.resolve() / "main.md")

        initial_project_path = resolved
        logging.info("Project path set to: %s (bom=%s, context=%s)", resolved, bom_available, context_available)
        return jsonify({
            "success": True,
            "path": resolved,
            "bom_available": bom_available,
            "context_available": context_available,
        })

    except Exception as e:
        logging.error(f"Error setting project path: {e}", exc_info=True)
        return jsonify({"success": False, "error": "An internal error occurred. Check server logs for details."}), 500


@app.route("/diff")
def diff_page():
    """Serves the visual report diff page."""
    return render_template("diff.html")


@app.route("/api/diff_reports", methods=["POST"])
async def diff_reports():
    """Compare two JSON threat reports and return added/resolved/changed threats."""
    data = await request.get_json()
    if not data:
        return jsonify({"error": "Missing request body"}), 400

    old_report = data.get("old_report")
    new_report = data.get("new_report")

    if not old_report or not new_report:
        return jsonify({"error": "Both old_report and new_report are required"}), 400

    try:
        from threat_analysis.utils import compare_threat_reports
        result = compare_threat_reports(old_report, new_report)
        return jsonify(result)
    except Exception:
        logging.error("Error comparing threat reports", exc_info=True)
        return jsonify({"error": "Failed to compare reports"}), 500
