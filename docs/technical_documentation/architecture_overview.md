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

## Attack Chain Analysis

The **`threat_analysis/core/attack_chain.py`** module provides offline graph traversal to detect
multi-step attack paths across the system architecture.

### How It Works

```
AttackChainAnalyzer.analyze(all_threats, dataflows)
    1. Index threats by target component name
    2. Sort each component's threats by severity score (desc)
    3. Iterate dataflows as directed edges: source → sink
    4. For each dataflow, find the top threat on both source and sink
    5. If both exist → emit a chain: entry_threat (source) + pivot_threat (sink)
    6. chain_score = (entry_score + pivot_score) / 2.0
    7. chain_label = CRITICAL (≥8) / HIGH (≥6) / MEDIUM (≥4) / LOW
    8. Deduplicate by (source_name, sink_name) pair
    9. Return chains sorted by chain_score descending
```

The results are injected into `generate_html_report()` as `attack_chains` and rendered in a
**"⛓️ Attack Chain Analysis"** section that appears before the severity explanation in the HTML report.
Component deep-link anchors (`#component-{sid}`) enable the severity heat map's "View threats →"
links to navigate directly to each component's threat table.

### Integration Point

`ReportGenerator.generate_html_report()` calls:
```python
analyzer = AttackChainAnalyzer()
attack_chains = analyzer.analyze(all_threats_flat, threat_model.tm.dataflows)
```

---

## Diagram Visual Conventions

### Trust Boundary Colors

The DOT template (`threat_analysis/templates/threat_model.dot.j2`) uses the following convention:

| Boundary type | Color | Style | Meaning |
|---|---|---|---|
| `isTrusted=true` | `#2e7d32` (dark green) | solid, penwidth=2 | Trusted security zone |
| `isTrusted=false` | `#c62828` (dark red) | dashed, penwidth=2 | Untrusted / exposed zone |

These colors are baked directly into the DOT output, which means they appear in both the exported
SVG and the HTML diagrams. The legend section in exported HTML diagrams is updated to show
"🔒 Trusted Zone" (green) and "⚠ Untrusted Zone" (red dashed).

**Why baked into DOT**: The user generates SVG files independently via `generate_custom_svg_export()`.
Putting trust colors in the DOT template guarantees that exported SVGs always reflect trust levels
without any extra post-processing step.

### Severity Heat Map Overlay

The HTML diagram templates (`diagram_template.html`, `navigable_diagram_template.html`) include a
JavaScript severity overlay that:

- Injects `severity_map_json` from the Jinja2 template context (computed by `_compute_severity_map()`)
- Provides a toggle button "🎨 Severity Heat Map" that applies/restores SVG `fill` per node
- Shows a tooltip on hover: component name, severity label, and "View threats →" deep-link
  to `#component-{sid}` anchor in the paired HTML report
- Hides the toggle section automatically when `severity_map` is empty (e.g. live editor preview)

**`_compute_severity_map(threat_model)`** in `ReportGenerator`:
- Reads `mitre_analysis_results["processed_threats"]` (pytm threats post-scoring)
- Also reads `element.threats` (AI/LLM threats, `source="AI"`)
- Returns `{component_name: "CRITICAL"|"HIGH"|"MEDIUM"|"LOW"}` using the highest severity per component

**Propagation chain:**
```
ReportGenerator._compute_severity_map()
    → ExportService.generate_full_project_export()  (single-file path)
    → DiagramGenerator._generate_html_with_legend(..., severity_map, report_url)
    → DiagramGenerator._create_complete_html(..., severity_map, report_url)
    → template: {{ severity_map_json | tojson }}
```

In the live editor preview (`DiagramService.update_diagram_logic()`), `severity_map={}` is passed —
the JS toggle hides itself when the map is empty, so no stale severity data appears during editing.

---

## Threat Consolidation and VOC Scoring Pipeline

This section describes how the three threat sources (pytm rules, component-level AI, RAG system-level)
are deduplicated and scored into a single unified output.

### Components

1. **`threat_analysis/core/threat_consolidator.py`** — `ThreatConsolidator`
   - **Role**: Eliminates duplicate threats that cover the same `(target, stride_category)` with
     similar descriptions across pytm and AI sources.
   - **Algorithm**: Offline Jaccard word-overlap (`|s1 ∩ s2| / |s1 ∪ s2| ≥ 0.3`) or substring
     containment. When a duplicate is found, the AI version is kept (richer context). No NLP
     library or network access required — purely offline string comparison.

2. **`threat_analysis/severity_calculator_module.py`** — `RiskContext` + `SeverityCalculator`
   - **Role**: Encodes four binary context signals that adjust the base STRIDE score:
     - `has_cve_match` → +0.5 (confirmed exploitability evidence for this target/category)
     - `cwe_high_risk` → +0.3 (CWE class in `_HIGH_RISK_CWES`: injection, memory corruption, hardcoded creds…)
     - `network_exposed` → +0.7 (Dataflow without auth/encryption, or element in untrusted boundary)
     - `has_d3fend_mitigations` → −0.5 (active defensive controls reduce residual risk)
   - **Why CWE instead of CVSS**: The CVE JSONL files carry only `CWE`, `CAPEC`, and `TECHNIQUES`
     keys — no CVSS scores. CWE class is used as an offline exploitability proxy.

3. **`threat_analysis/core/report_serializer.py`** — `ReportSerializer`
   - **Role**: Serialises the consolidated threat list into a stable, versioned dict stamped
     `schema_version: "1.0"`. Threats receive sequential IDs (`T-0001`, `T-0002`, …).
   - **Validation**: The output is validated against
     `threat_analysis/schemas/v1/threat_model_report.schema.json` (JSON Schema 2020-12) before
     being written to disk.

### Scoring order in `ReportGenerator._get_all_threats_with_mitre_info()`

```
For each threat:
    1. MitreMapping.analyze()        → ATT&CK techniques, D3FEND mitigations
    2. CVEService.get_cwes_for_cve() → CWE IDs (single-pass JSONL, lazy-loaded)
    3. _is_network_exposed(target)   → Dataflow auth/encryption or Boundary trust
    4. RiskContext(...)              → assemble context signals
    5. SeverityCalculator.calculate_score(..., risk_context)  → final clamped score
```

After all threats are collected:
```
ThreatConsolidator.deduplicate(pytm_threats, ai_threats)
    → unique_pytm + ai_threats
ReportSerializer.serialize(threat_model, all_threats)
    → validated versioned dict
```

## Goal-Driven Attack Flow Engine (GDAF)

The GDAF is a top-down attack scenario generator implemented in three cooperating modules.

### Key Components

1. **`threat_analysis/core/gdaf_engine.py`** — `GDAFEngine`, `AttackScenario`, `AttackHop`
   - Reads `attack_objectives`, `threat_actors`, and `risk_criteria` from a YAML context file.
   - `_build_graph()` creates a dict-based directed graph: nodes are actors/servers, edges are dataflows with metadata (protocol, `is_encrypted`, `is_authenticated`, `authentication`).
   - `_find_entry_points()` selects start nodes from the graph based on the actor's `entry_preference` (`internet-facing` → untrusted boundary actors; `insider` → trusted actors with edges).
   - `_bfs_paths()` performs bounded BFS (max_hops, max 20 raw paths per pair) to enumerate paths from entry points to target nodes.
   - `_build_scenario()` converts a raw BFS path into an `AttackScenario` by calling `AssetTechniqueMapper.get_techniques()` for each hop, computing `hop_score` and `path_score`, and classifying risk level.

2. **`threat_analysis/core/asset_technique_mapper.py`** — `AssetTechniqueMapper`, `ScoredTechnique`
   - Loads `enterprise-attack.json` once (class-level cache, lazy).
   - `get_techniques(asset_type, asset_attrs, hop_position, actor_known_ttps, actor_capable_tactics, top_k)` returns the top-k ranked MITRE techniques for the given asset.
   - Scoring is a sum of additive bonuses: platform match (+0.5), primary tactic (+0.4), hop position tactic (+0.3), key technique for asset type (+0.6), actor known TTP (+0.5), vulnerability signals (+0.2–0.3 each).
   - `_normalize_type()` maps fuzzy DSL type strings to canonical keys in `ASSET_TYPE_TO_PLATFORMS` and `ASSET_TYPE_TO_TACTICS`.

3. **`threat_analysis/generation/attack_flow_builder.py`** — `AttackFlowBuilder`
   - Serializes `AttackScenario` objects to Attack Flow `.afb` JSON files.
   - One file per scenario, written to `output/gdaf/<objective_id>/<actor_id>_<scenario_id>.afb`.
   - Produces a `gdaf_summary.json` collecting all scenarios.

### Data Flow

```
GDAFEngine.__init__(threat_model, context_path, extra_models)
    → _load_context()          reads YAML: attack_objectives, threat_actors, risk_criteria
    → AssetTechniqueMapper()   loads enterprise-attack.json (lazy, cached)

GDAFEngine.run()
    → _build_graph()
        for each model in [main] + extra_models:
            add actors and servers as nodes
            add dataflows as directed edges
        second pass: add bridging edges for servers with _submodel_tm
    → for each objective × actor:
        _find_entry_points(actor)
        for each entry → target:
            _bfs_paths(graph, entry, target, max_hops)
            for each path:
                _build_scenario(path, objective, actor, graph, acceptable_risk)
                    for each hop:
                        AssetTechniqueMapper.get_techniques(...)
                        compute hop_score (avg_technique_score × hop_weight)
                    path_score = mean(hop_scores) + target_cia_bonus
                    classify → CRITICAL / HIGH / MEDIUM / LOW
    → return List[AttackScenario] (sorted by score, top max_paths_per_objective kept)
```

### GDAF and Sub-model Bridging

When `_build_graph()` finds a server with `server_props['_submodel_tm']` (set by
`_recursively_generate_reports()` for servers with `submodel=` in the DSL), it adds two sets
of bridging edges:

- **Entry bridge**: `parent_server → sub_root_servers` — represents internal access after
  compromising the parent node. Root servers are those that are not the sink of any sub-model
  dataflow.
- **Exit bridge**: `sub_leaf_servers → original_targets` — leaf servers (not the source of any
  sub-model dataflow) inherit the parent's outgoing edges, allowing attack paths to exit the
  component after traversing its internals.

This mechanism enables GDAF to trace paths that span multiple files in a project, crossing into
sub-model internals transparently.

---

## Sub-model Drill-down

Sub-model drill-down connects a server in a parent model to a child threat model file via the
`submodel=./path/to/model.md` DSL keyword. The child IS the parent server at higher detail.

### Parent diagram (hyperlink nodes)

`_recursively_generate_reports()` in `report_generator.py` pre-creates the sub-model's
`ThreatModel` and stores it in `server_props['_submodel_tm']`. `DiagramGenerator` renders the
parent server as a hyperlink pointing to the child's diagram HTML file.

### Child diagram (ghost connections)

`_collect_parent_connections()` in `report_generator.py` collects all dataflows in the parent
model that connect to the parent server. These are passed as `external_connections` to
`DiagramGenerator._generate_manual_dot()`.

`_build_ghost_connections()` in `diagram_generator.py` generates a ghost cluster at the edge of
the child diagram:

- **Ghost nodes** — dashed gray rectangles representing external peers from the parent model.
  Lock/key badges indicate encryption and authentication status.
- **Ghost edges** — incoming connections wire to the child model's root servers (servers with no
  incoming dataflows within the child model). Outgoing connections wire from the child model's
  leaf servers (servers with no outgoing dataflows).
- **Cluster label** — "External connections (parent model)" clearly marks the ghost region.

The ghost cluster is rendered at the end of the DOT template (`threat_model.dot.j2`) after the
main graph content.

### GDAF integration

See [GDAF and Sub-model Bridging](#gdaf-and-sub-model-bridging) above. The same
`_submodel_tm` reference that drives ghost node rendering also drives bridging edge injection
in `GDAFEngine._build_graph()`.

---

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