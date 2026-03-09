# Architecture — SecOpsTM

## Directory Structure

```
threatModelBypyTm/
├── threat_analysis/              Main installable package
│   ├── __init__.py
│   ├── __main__.py               Entry point (python -m threat_analysis)
│   ├── config.py                 Global config constants
│   ├── config_generator.py       CONFIG_DATA dict used by DiagramGenerator
│   ├── custom_threats.py         User-defined threat rule functions
│   ├── threat_rules.py           Additional threat rule definitions
│   ├── mitigation_suggestions.py MitigationStixMapper, framework mitigations
│   ├── severity_calculator_module.py  SeverityCalculator + RiskContext VOC scoring
│   ├── update_config.py          CLI helper to update ai_config.yaml
│   ├── utils.py                  _validate_path_within_project, extract_json_from_llm_response
│   ├── data_loader.py            Lazy loaders for external data files
│   │
│   ├── core/                     Domain model
│   │   ├── models_module.py      ThreatModel, ExtendedThreat, CustomThreat
│   │   │                         (wraps pytm TM/Actor/Server/Dataflow/Boundary)
│   │   │                         SecOpsBoundary(pytm.Boundary) — replaces monkey-patch
│   │   ├── model_parser.py       ModelParser — Markdown DSL → ThreatModel (2-pass)
│   │   ├── model_factory.py      create_threat_model() — wires parser + model
│   │   ├── model_validator.py    ModelValidator — pre-process validation
│   │   ├── mitre_mapping_module.py  MitreMapping — STRIDE→CAPEC→ATT&CK→D3FEND
│   │   ├── mitre_static_maps.py  Hard-coded ATTACK_D3FEND_MAPPING dict
│   │   ├── cve_service.py        CVEService — single-pass JSONL (CAPEC+CWE) + YAML definitions
│   │   ├── attack_chain.py       AttackChainAnalyzer — graph traversal, chained threat paths
│   │   ├── threat_consolidator.py  ThreatConsolidator — Jaccard dedup, AI wins over pytm
│   │   └── report_serializer.py  ReportSerializer — stable versioned dict, IDs T-NNNN
│   │
│   ├── ai_engine/                AI inference layer
│   │   ├── embedding_factory.py  get_embeddings() — provider-agnostic factory
│   │   ├── rag_service.py        RAGThreatGenerator — ChromaDB + LangChain RAG chain
│   │   ├── providers/
│   │   │   ├── base_provider.py  BaseLLMProvider (ABC): check_connection,
│   │   │   │                     generate_threats, generate_attack_flow
│   │   │   ├── litellm_client.py LiteLLMClient — low-level async LiteLLM wrapper
│   │   │   │                     (static factory create(), generate_content generator)
│   │   │   ├── litellm_provider.py  LiteLLMProvider(BaseLLMProvider) — orchestrates client
│   │   │   └── ollama_provider.py   OllamaProvider(BaseLLMProvider) — Ollama-specific
│   │   └── prompts/
│   │       ├── stride_prompts.py    STRIDE_SYSTEM_PROMPT, build_component_prompt()
│   │       └── attack_flow_prompts.py  ATTACK_FLOW_SYSTEM_PROMPT, build_attack_flow_prompt()
│   │
│   ├── generation/               Output artifact generators
│   │   ├── diagram_generator.py  DiagramGenerator — DOT/SVG via Graphviz subprocess
│   │   ├── svg_generator.py      SvgGenerator — standalone SVG manipulation
│   │   ├── report_generator.py   ReportGenerator — HTML report via Jinja2
│   │   ├── stix_generator.py     StixGenerator — STIX 2.1 bundle JSON
│   │   ├── attack_navigator_generator.py  AttackNavigatorGenerator — Navigator layer JSON
│   │   ├── attack_flow_generator.py       AttackFlowGenerator — Attack Flow STIX objects
│   │   ├── graphviz_to_json_metadata.py   DOT → JSON with element metadata
│   │   ├── graphviz_to_konva.py           DOT → Konva.js canvas JSON (GUI editor)
│   │   ├── tactic_logic.py       Tactic ordering and filtering helpers
│   │   └── utils.py              extract_name_from_object, get_target_name
│   │
│   ├── server/                   Flask web application
│   │   ├── server.py             Flask app factory, all route handlers, SSEBroadcaster
│   │   ├── events.py             Shared ai_status_event_queue (global queue.Queue)
│   │   ├── threat_model_service.py  ThreatModelService — service facade (lazy init)
│   │   ├── ai_service.py         AIService — LLM init, markdown gen, threat enrichment
│   │   ├── export_service.py     ExportService — all export logic, ZIP bundles
│   │   ├── diagram_service.py    DiagramService — diagram update + position mgmt
│   │   └── model_management_service.py  ModelManagementService — save/load/version
│   │   └── templates/
│   │       ├── index.html        Main web editor UI (Monaco editor + Konva canvas)
│   │       ├── simple_mode.html  Simplified UI mode
│   │       └── graphical_editor.html  Full graphical editor
│   │
│   ├── iac_plugins/              IaC adapter layer
│   │   ├── __init__.py           IaCPlugin ABC definition
│   │   └── ansible_plugin.py     AnsiblePlugin — parses inventory + playbook → components
│   │
│   ├── external_data/            Static security knowledge base (not modified at runtime)
│   │   ├── enterprise-attack.json  Full MITRE ATT&CK Enterprise dataset
│   │   ├── CAPEC_VIEW_ATT&CK_Related_Patterns.{csv,xml}
│   │   ├── capec_to_mitre_structured_mapping.json
│   │   ├── stride_to_capec.json
│   │   ├── d3fend.csv            MITRE D3FEND defensive techniques
│   │   ├── cis_to_mitre_mapping.json
│   │   ├── nist800-53-r5-mappings.xlsx
│   │   ├── CIS_Controls_v8_to_Enterprise_ATTCK_v82_Master_Mapping__5262021.xlsx
│   │   └── cve2capec/            CVE-XXXX.jsonl files (1999-2025, ~26 files)
│   │
│   ├── vector_store/             ChromaDB persistent directory (built offline)
│   │   └── chroma.sqlite3 + UUID collection dir
│   │
│   ├── schemas/
│   │   └── v1/
│   │       └── threat_model_report.schema.json  JSON Schema 2020-12 for versioned JSON export
│   │
│   └── templates/                Jinja2 HTML templates for generated reports/diagrams
│       ├── report_template.html
│       ├── diagram_template.html
│       ├── navigable_diagram_template.html
│       └── threat_model.dot.j2   Graphviz DOT Jinja2 template
│
├── config/
│   ├── ai_config.yaml            AI providers (gemini ON by default), RAG, embeddings
│   ├── context.yaml              System-level context for threat generation
│   └── user_context.example.json User threat intelligence JSON schema
│
├── tooling/                      Offline data pipeline scripts (run once)
│   ├── build_vector_store.py     Loads external_data/ → ChromaDB vector store
│   ├── download_attack_data.py   Downloads enterprise-attack.json from MITRE
│   ├── download_nist_data.py     Downloads NIST 800-53 mappings
│   ├── capec_mitre_parser.py     Parses CAPEC XML
│   ├── capec_to_mitre_builder.py Builds capec_to_mitre_structured_mapping.json
│   ├── build_stride_capec_mapping.py
│   ├── cis_controls_parser.py
│   ├── copy_cve_data.py
│   ├── generate_attack_flow.py
│   ├── validate_capec_json.py
│   └── test_rag_generation.py    Manual RAG smoke test
│
├── tests/                        pytest suite (~30 test files)
├── threatModel_Template/         Ready-to-use DSL model templates
├── docs/                         User and technical documentation
└── .github/workflows/            CI: coverage_check.yml, sync-wiki.yml
```

## Key Components and Interactions

### 1. Markdown DSL → Threat Model

```
Markdown file
    → ModelParser.parse_markdown()     (2-pass: elements then relationships)
        Pass 1: Boundaries, Actors, Servers, Data
        Pass 2: Dataflows, Protocol Styles, Severity Multipliers, Custom MITRE
    → ThreatModel (wraps pytm.TM)
        .boundaries{}  .actors[]  .servers[]  .dataflows[]
    → ThreatModel.process_threats()
        → pytm.TM.process()            (PyTM built-in rules)
        → _expand_class_targets()      (class → instances)
        → _apply_custom_threats()      (custom_threats.py rules)
        → _group_threats()             (by STRIDE category)
        → _perform_mitre_analysis()    (MitreMapping.analyze_pytm_threats_list())
```

### 2. AI Enrichment Pipeline

```
AIService.init_ai()
    → LiteLLMClient.create()           (async factory, reads ai_config.yaml)
        → provider selection (first `enabled: true` in yaml)
        → check_connection() ping  (sets ai_online; never raises)
    → RAGThreatGenerator.__init__()    (if rag.enabled: true)
        → embedding_factory.get_embeddings()
        → Chroma(persist_directory=vector_store/)

AIService._enrich_with_ai_threats(threat_model)
    → RAGThreatGenerator.generate_threats(markdown)   (system-level, RAG)
        → vector_store.similarity_search(query, k=5)
        → ChatLiteLLM | prompt | invoke()
        → JSON extraction + parse → ExtendedThreat(source="LLM")
    → For each element (actors + servers + boundaries):
        → prompt includes boundary trust level (TRUSTED/UNTRUSTED)
        → LiteLLMClient.generate_content(prompt, system_prompt, stream=False)
        → JSON extraction → ExtendedThreat(source="AI")
        → element.threats.append(new_threat)
        → SSE progress event → ai_status_event_queue

AIService._generate_rag_threats(threat_model)         (cross-model context)
    → concatenates main model markdown + all sub_models markdown
    → single RAG call with full project context
    → returns List[ExtendedThreat(source="LLM")]

AIService.generate_rag_threats_sync(threat_model)     (sync wrapper)
    → asyncio.run_coroutine_threadsafe(_generate_rag_threats, _get_sync_loop())
    → called from ReportGenerator.generate_project_reports() after sub_models populated
```

**Cross-model RAG in project mode (wiring):**
```
ReportGenerator.generate_project_reports(project_path, export_path, ai_service=None)
    → recurse sub-models → all_processed_models
    → populate main_threat_model.sub_models from all_processed_models
    → if ai_service and rag_generator and ai_online:
        rag_threats = ai_service.generate_rag_threats_sync(main_threat_model)
        → main_threat_model.tm.global_threats_llm.extend(rag_threats)
    → generate_global_project_report()       (uses global_threats_llm)
```

### 3. Flask Server Request Flow

```
GET /                     → index.html (Monaco editor + Konva canvas)
POST /update_diagram      → ThreatModelService.update_diagram_logic()
                              → DiagramService → ModelParser → DiagramGenerator → DOT → SVG
POST /export              → ThreatModelService.export_files_logic()
                              → ExportService → various generators
POST /export_all          → full ZIP bundle (HTML, SVG, STIX, Navigator, Attack Flow)
POST /ai/generate_markdown → SSE stream → AIService.generate_markdown_from_prompt()
GET  /api/ai_status_stream → SSE stream of ai_status_event_queue
POST /api/export_project   → generate_full_project_export() with progress SSE
```

### 4. MITRE Mapping Chain

```
STRIDE category
    → stride_to_capec.json             (STRIDE → CAPEC IDs)
    → capec_to_mitre_structured_mapping.json  (CAPEC → ATT&CK techniques)
    → enterprise-attack.json           (technique details: name, tactic, URL)
    → d3fend.csv                       (ATT&CK technique → D3FEND mitigations)
    → cis_to_mitre_mapping.json        (ATT&CK → CIS Controls)
    → nist800-53-r5-mappings.xlsx      (ATT&CK → NIST 800-53)
```

### 5. Threat Consolidation + Scoring Pipeline

```
ReportGenerator._get_all_threats_with_mitre_info()
    For each pytm grouped threat:
        → MitreMapping.analyze_pytm_threats_list()   (STRIDE → CAPEC → ATT&CK → D3FEND)
        → CVEService.get_cves_for_equipment()        (YAML definitions)
        → CVEService.get_cwes_for_cve()              (JSONL single-pass lookup)
        → _is_network_exposed(target)                (Dataflow auth/encryption, Boundary trust)
        → RiskContext(has_cve_match, cwe_ids, network_exposed, has_d3fend_mitigations)
        → SeverityCalculator.calculate_score(..., risk_context)

    For each AI element threat (source="AI"):
        → same CVE/CWE/network pipeline as above

    → ThreatConsolidator.deduplicate(pytm_threats, ai_threats)
        → Jaccard(word_set_1, word_set_2) ≥ 0.3 OR substring match → AI wins
        → returns unique_pytm + ai_threats

    → ReportSerializer.serialize(threat_model, all_threats)
        → schema_version: "1.0", threats[].id: "T-NNNN"
        → jsonschema.validate(report, schema)        (offline, stdlib json)

    → AttackChainAnalyzer.analyze(all_threats, dataflows)
        → returns chains sorted by score desc
        → injected into HTML report as "⛓️ Attack Chain Analysis" section
```

### 6b. Diagram Generation + Trust Colors

```
ThreatModel → DiagramGenerator._generate_manual_dot(threat_model)
    → threat_model.dot.j2 template
        For each boundary:
            isTrusted=true  → color="#2e7d32"; penwidth=2; style=solid
            isTrusted=false → color="#c62828"; penwidth=2; style=dashed
    → DOT string → graphviz subprocess → SVG

DiagramGenerator._generate_html_with_legend(svg_path, out_path, threat_model,
                                             graph_metadata, severity_map, report_url)
    → _generate_legend_html()   (includes Trusted/Untrusted boundary legend + severity toggle)
    → _create_complete_html()   (injects severity_map_json + report_url into template)

ReportGenerator._compute_severity_map(threat_model)
    → reads processed_threats + AI element threats
    → returns {name: "CRITICAL"|"HIGH"|"MEDIUM"|"LOW"} (highest per component)
```

### 6. RAG Vector Store Build (offline)

```
tooling/build_vector_store.py
    → load external_data/ (CSV, JSON, JSONL, XML, XLSX)
    → RecursiveCharacterTextSplitter
    → HuggingFaceEmbeddings(all-MiniLM-L6-v2)
    → Chroma.from_documents() → threat_analysis/vector_store/
```

## External Dependencies and Rationale

| Dependency | Why |
|---|---|
| `pytm` | Core STRIDE threat rule engine — the project is built around it |
| `Flask[async]` | Simple web framework; async needed for streaming AI responses |
| `litellm` | Single interface to multiple LLM APIs (OpenAI compat) — avoids vendor lock-in |
| `langchain` + `langchain-chroma` | RAG pipeline abstraction over vector retrieval |
| `chromadb` | Local persistent vector DB — no external service needed |
| `sentence-transformers` | Local embeddings — air-gap/sovereign deployments supported |
| `langchain-litellm` | LangChain adapter for LiteLLM — used in RAGThreatGenerator |
| `graphviz` | Python wrapper for `dot` binary — diagram rendering |
| `Jinja2` | Report and diagram templating |
| `PyYAML` | Config file parsing (`ai_config.yaml`) |
| `openpyxl` / `msoffcrypto-tool` | Parse CIS Controls and NIST XLSX data files |
| `lxml` | Parse CAPEC XML data |
| `aiohttp` | Async HTTP (used internally by some LLM providers) |

## Known Technical Debt / Fragile Areas

1. ~~**Duplicated JSON extraction logic**~~ — **Fixed**: `extract_json_from_llm_response()` is
   now a single shared function in `threat_analysis/utils.py`, used by `LiteLLMClient`,
   `RAGThreatGenerator`, and `AIService`.

2. **pytm.Boundary monkey-patching** (`models_module.py:27-35`) — Adds `isTrusted`, `protocol`,
   `port`, `data` attributes because pytm does not provide them. Labelled `# HACK` in code.
   Breaks if pytm is updated.

3. **Sync wrapper over async generator** (`ai_service.py:generate_markdown_from_prompt_sync`) —
   Uses `loop.run_until_complete(gen.__anext__())` per chunk inside a Flask thread. Fragile in
   concurrent request scenarios.

4. **Hardcoded rate limit sleep** (`ai_service.py:303`) — `await asyncio.sleep(1.5)` for Gemini
   free tier. Should be config-driven.

5. ~~**`_get_output_dir` defined twice**~~ — **Fixed**: duplicate removed from `ExportService`.

6. **`venv-py310/` in the repo tree** — The virtualenv directory is present on disk and was found
   by file listing. Should be in `.gitignore`.

7. **`requirements.txt` vs `pyproject.toml` diverge** — `pyproject.toml` lists minimal runtime
   deps; `requirements.txt` includes all AI/ML extras. Installing from `pyproject.toml` alone is
   insufficient for AI features.

8. **`package-lock.json` at root** — Untracked file suggesting a Node.js tool was run. No
   `package.json` exists; this file is orphaned.

9. **`ThreatModel` requires `CVEService`** injected at construction — tight coupling; if
   CVE data files are missing the entire model fails to instantiate.

10. **`config/ai_config.yaml` YAML indentation error** — `rag:` section is mis-indented
    (not under `ai_providers`), which may cause `yaml.safe_load` to mis-parse the structure
    depending on strict mode.
