# Architecture Overview: Diagram Generation

This document outlines the architecture of the diagram generation process, highlighting the key components and their roles. Understanding this flow is crucial for debugging rendering inconsistencies between the GUI and SVG exports.

## Key Components

1.  **`threat_analysis/generation/diagram_generator.py`**:
    *   **Role**: Primary DOT code generator.
    *   **Function**: Takes the threat model data structure as input and produces a graph representation in the DOT language.
    *   **Details**: This component is responsible for creating complex, HTML-like labels (e.g., `<TABLE>...</TABLE>`) to structure nodes with both icons and text. It defines the layout and styling attributes that are passed to the rendering engine.

2.  **Rendering Engines**: There are two distinct rendering pathways, which can lead to different visual outputs.

    *   **A) Web GUI Rendering**:
        *   **File**: `threat_analysis/server/templates/full_gui.html`
        *   **Engine**: A JavaScript library in the browser (e.g., d3-graphviz or a similar library using Konva.js) renders the DOT string provided by the backend.
        *   **Behavior**: The rendering is subject to the browser's engine, its support for SVG, fonts (including font fallback for emojis), and the specific features of the JS library.

    *   **B) Custom SVG Export**:
        *   **File**: `threat_analysis/generation/svg_generator.py`
        *   **Engine**: This is a custom, manual SVG builder, **not** a direct Graphviz SVG export.
        *   **Process**:
            1.  The `dot` command-line tool is called with the `-Tjson` flag to convert the DOT string into a JSON representation of drawing primitives.
            2.  The `svg_generator.py` script parses this JSON object.
            3.  It then manually constructs an SVG file string by interpreting the JSON data (e.g., drawing paths, placing text, embedding images).
        *   **Implication**: This component **re-implements** the rendering logic. Any feature from DOT/HTML-labels (like `ALIGN="LEFT"` in a `TD`) must be explicitly handled by the Python script. Discrepancies between the native Graphviz output and the output of this script are likely due to features not being implemented in this custom generator.

## AI-Powered Threat Model Generation and Modification

This section details the architecture behind the AI-driven generation and modification of threat models, available primarily through the "simple mode" interface. This feature leverages large language models to interpret natural language prompts and either create new threat models or iteratively refine existing ones.

### Workflow:

1.  **User Interaction (Frontend - `threat_analysis/server/templates/simple_mode.html`)**:
    *   The user accesses the "simple mode" web interface.
    *   A text area (`prompt-textarea`) allows the user to describe their system or request modifications to an existing threat model.
    *   Upon clicking "Generate with AI" (`ai-generate-btn`), the client-side JavaScript (`generateFromPromptBtn.onclick`) gathers two pieces of information:
        *   The user's natural language `prompt` for the AI.
        *   The `markdown` content currently displayed in the CodeMirror editor, representing the existing threat model (if any).
    *   These two pieces of data are sent as a JSON payload via a POST request to the backend endpoint `/api/generate_markdown_from_prompt`.

2.  **Backend Processing (`threat_analysis/server/server.py`)**:
    *   The Flask route `/api/generate_markdown_from_prompt` receives the JSON payload.
    *   It extracts both the `prompt` and the `markdown` (existing model content) from the request body.
    *   These parameters are then passed to the `threat_model_service.generate_markdown_from_prompt` method.
    *   The backend now handles the potentially streaming output from the service layer, wrapping it in a `Response` object with `stream_with_context` to stream the content back to the client as `text/plain`.

3.  **Service Layer Logic (`threat_analysis/server/threat_model_service.py`)**:
    *   The `generate_markdown_from_prompt` method in `ThreatModelService` is the central orchestrator for AI interaction.
    *   It now uses the `ollama` library (via `ollama.Client`) for direct interaction with the Ollama server.
    *   It conditionally constructs the `system_prompt` sent to the AI:
        *   **New Generation**: If no `markdown` content is provided (i.e., the user is starting a new model), a `system_prompt` is used to instruct the AI to generate a complete threat model from scratch based solely on the user's `prompt`.
        *   **Modification**: If `markdown` content is provided, a specialized `system_prompt` is used. This prompt explicitly instructs the AI to *modify* the given `markdown` content according to the user's `prompt`, preserving the existing structure where possible and making only the requested changes. The full existing `markdown` content is included in the `user_prompt` sent to the AI, along with the modification request.
    *   Crucially, the `ollama.Client.generate` method is called with a `stream` parameter (configured in `ai_config.yaml`). If streaming is enabled, this method returns a generator that yields chunks of the response as they are received from the LLM.
    *   The `generate_markdown_from_prompt` method itself now acts as a generator, yielding these chunks directly.

4.  **AI Provider Interaction (`threat_analysis/ai_engine/providers/ollama_provider.py`)**:
    *   The configured AI provider (`OllamaProvider` in this case) formats the `system_prompt` and `user_prompt` into a request suitable for the chosen LLM (e.g., Ollama).
    *   The LLM processes the request and returns the AI-generated or AI-modified threat model content in Markdown DSL.

5.  **Result Handling**:
    *   The generated/modified Markdown content is returned through the service layer and the Flask backend to the `simple_mode.html` frontend.
    *   The `editor.setValue()` function in the frontend updates the CodeMirror editor with the new content, and the diagram is re-rendered to reflect the changes.

This architecture enables an iterative threat modeling process, allowing users to start with a basic model and refine it incrementally through natural language commands, significantly enhancing the usability and flexibility of the tool compared to an overwrite-only approach.

## Frontend JavaScript Architecture (Graphical Editor)

The JavaScript codebase for the graphical editor (`threat_analysis/server/templates/graphical_editor.html`) has been modularized to improve maintainability, readability, and separation of concerns. The main application logic is now split into several manager classes, each responsible for a specific aspect of the editor's functionality.

### Module Overview:

*   **`App.js`**:
    *   **Role**: The main entry point for the graphical editor.
    *   **Function**: Initializes all other manager classes and orchestrates their interactions by injecting dependencies and setting up global event listeners.
    *   **Details**: Ensures that all components are set up correctly when the DOM is fully loaded.

*   **`KonvaManager.js`**:
    *   **Role**: Manages the Konva.js stage, layer, transformer, and core canvas interactions.
    *   **Function**: Handles canvas initialization, zooming, custom panning (dragging empty space), selection of nodes and connections, double-click to resize, and keyboard events (like deletion).
    *   **Details**: Emits custom events (`itemSelected`, `selectionCleared`, `nodeDeleted`) to notify other modules about user interactions on the canvas.

*   **`NodeManager.js`**:
    *   **Role**: Manages the creation, properties, and interactions of individual nodes (elements) on the Konva canvas.
    *   **Function**: Provides methods to add different types of nodes (e.g., Boundary, Actor, Server) with their specific shapes, text, and icons. Manages unique naming for nodes.
    *   **Details**: Nodes are represented as Konva `Group` objects, encapsulating their visual components and properties. Dispatches `portClicked` and `nodeDragMove` events.

*   **`ConnectionManager.js`**:
    *   **Role**: Manages the creation, updates, and interactions of connections (dataflows) between nodes.
    *   **Function**: Handles starting a new connection, attaching it to a target node, recomputing connection paths (especially for overlapping connections), and selecting/deselecting connections.
    *   **Details**: Listens for `itemSelected` and `nodeDragMove` events to ensure connections are visually updated when nodes are moved or selected.

*   **`PropertiesPanelManager.js`**:
    *   **Role**: Manages the dynamic display and editing of properties for the currently selected node or connection.
    *   **Function**: Updates the properties form based on the selected item's attributes and handles input changes to modify those properties directly on the Konva elements.
    *   **Details**: Listens for `itemSelected`, `selectionCleared`, and `nodeDeleted` events to update its state.

*   **`ToolbarManager.js`**:
    *   **Role**: Manages the interactive buttons in the editor's toolbar.
    *   **Function**: Sets up event listeners for buttons that add new elements to the canvas (e.g., "Add Boundary", "Add Actor").
    *   **Details**: Utilizes `NodeManager` to create new nodes and `PropertiesPanelManager` to immediately display their properties upon creation.

*   **`ThreatModelGenerator.js`**:
    *   **Role**: Handles the process of converting the visual graph into a structured threat model representation and initiating the backend generation process.
    *   **Function**: Collects all nodes and connections from the canvas, constructs a JSON representation of the threat model, converts it to Markdown, and sends it to the `/api/generate_all` endpoint.
    *   **Details**: Also responsible for displaying generation status and results.

*   **`ModelManager.js`**:
    *   **Role**: Manages loading and saving threat models from the server or local files.
    *   **Function**: Handles interactions with the "Open Model" modal, fetches lists of saved models, loads models via API calls, and handles local file uploads (Markdown and metadata JSON).
    *   **Details**: Utilizes `NodeManager` and `ConnectionManager` to repopulate the graph from loaded model data and positions.

This modular design promotes reusability, testability, and a clear separation of concerns, making the graphical editor more robust and easier to extend.