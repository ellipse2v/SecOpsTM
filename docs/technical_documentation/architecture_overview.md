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

## AI Provider Architecture

The framework uses a pluggable AI provider architecture to support various Large Language Models (LLMs) for threat generation and enrichment.

### Key Components:

1.  **`threat_analysis/ai_engine/providers/base_provider.py`**:
    *   **Role**: Abstract Base Class (`BaseLLMProvider`) defining the interface for all AI providers.
    *   **Interface**: Requires implementation of `check_connection()`, `generate_threats()`, and `generate_attack_flow()`.

2.  **`threat_analysis/ai_engine/providers/litellm_client.py`**:
    *   **Role**: A unified client leveraging the `litellm` library.
    *   **Function**: Provides a consistent interface to interact with numerous AI providers (OpenAI, Anthropic, Google Gemini, Mistral, Ollama, etc.) using a single completion function.
    *   **Configuration**: Loads settings from `config/ai_config.yaml` and handles API keys via environment variables (e.g., `GOOGLE_API_KEY` for Gemini).

3.  **`threat_analysis/ai_engine/providers/litellm_provider.py`**:
    *   **Role**: A concrete implementation of `BaseLLMProvider` that wraps `LiteLLMClient`.
    *   **Function**: Bridges the gap between the internal `LiteLLMClient` and the standardized provider interface used by the rest of the framework (like `ReportGenerator`).

4.  **`threat_analysis/ai_engine/providers/ollama_provider.py`**:
    *   **Role**: A dedicated provider for local Ollama instances.
    *   **Function**: Uses direct HTTP calls to the Ollama API for low-latency local inference.

## AI-Powered Threat Model Generation and Modification

This section details the architecture behind the AI-driven generation and modification of threat models, available primarily through the "simple mode" interface.

### Workflow:

1.  **User Interaction (Frontend - `threat_analysis/server/templates/simple_mode.html`)**:
    *   The user accesses the "simple mode" web interface.
    *   A text area allows for natural language prompts.
    *   Data is sent to the `/api/generate_markdown_from_prompt` endpoint.

2.  **Backend Processing (`threat_analysis/server/server.py`)**:
    *   The Flask route receives the prompt and current markdown.
    *   It delegates to `threat_model_service.generate_markdown_from_prompt`.

3.  **Service Layer Logic (`threat_analysis/server/ai_service.py`)**:
    *   The `AiService` (formerly integrated into the threat model service) is the central orchestrator.
    *   It utilizes `LiteLLMClient` to communicate with the configured AI provider.
    *   It supports streaming responses, allowing the user to see the threat model being generated in real-time.

4.  **AI Provider Interaction**:
    *   Based on `config/ai_config.yaml`, the `LiteLLMClient` identifies the enabled provider (e.g., `gemini`, `openai`, or `ollama`).
    *   It retrieves the necessary API keys from environment variables and sends the formatted prompts to the LLM.

5.  **Result Handling**:
    *   The generated Markdown content is streamed back to the frontend.
    *   The CodeMirror editor is updated, and the diagram is re-rendered.

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