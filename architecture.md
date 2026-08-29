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
│   ├── update_config.py          Dev script: regenerates static/js/config.js from
│   │                             config_generator.py — run manually before commits
│   ├── utils.py                  _validate_path_within_project, extract_json_from_llm_response,
│   │                             minimal_subprocess_env (env allowlist for `dot` subprocess calls
│   │                             — LLM API keys in os.environ are never inherited by children)
│   ├── validate.py               `secopstm validate` subcommand — offline DSL/config lint
│   │
│   ├── core/                     Domain model
│   │   ├── models_module.py      ThreatModel, ExtendedThreat, CustomThreat
│   │   │                         (wraps pytm TM/Actor/Server/Dataflow/Boundary)
│   │   │                         SecOpsBoundary(pytm.Boundary) — replaces monkey-patch
│   │   ├── model_parser.py       ModelParser — Markdown DSL → ThreatModel (2-pass)
│   │   ├── model_factory.py      create_threat_model() — wires parser + model
│   │   ├── model_validator.py    ModelValidator — pre-process validation
│   │   ├── model_completeness.py ModelCompletenessChecker — DSL quality score
│   │   ├── dsl_constants.py      DSL_ENUMS — single source of truth for DSL field values
│   │   ├── mitre_mapping_module.py  MitreMapping — STRIDE→CAPEC→ATT&CK→D3FEND
│   │   ├── mitre_static_maps.py  Hard-coded ATTACK_D3FEND_MAPPING dict
│   │   ├── attack_id_validator.py  AttackIdValidator — validates ATT&CK/CAPEC/D3FEND IDs
│   │   │                         (incl. LLM-cited ones) against the committed corpora
│   │   ├── asset_technique_mapper.py  AssetTechniqueMapper — asset type/attrs → ATT&CK techniques
│   │   ├── cve_service.py        CVEService — single-pass JSONL (CAPEC+CWE) + YAML definitions
│   │   ├── data_loader.py        Lazy loaders for external_data/ files (ATT&CK, CAPEC, D3FEND, NIST…)
│   │   ├── vex_loader.py         VEXLoader — CycloneDX VEX document loader (standalone/dir/auto)
│   │   ├── bom_loader.py         BOMLoader — BOM YAML per asset; active_cves/fixed_cves via VEX state
│   │   ├── accepted_risks.py     AcceptedRiskLoader — analyst risk-acceptance decisions per threat
│   │   ├── ai_cache.py           AIThreatCache — SHA-256-keyed cache (.secopstm_ai_cache.json)
│   │   ├── attack_chain.py       AttackChainAnalyzer — bottom-up: chains existing threats via dataflows
│   │   ├── gdaf_engine.py        GDAFEngine — top-down: objectives + threat actors → attack scenarios
│   │   ├── debate_engine.py      RedBlueDebateEngine — adversarial Red/Blue debate over GDAF scenarios
│   │   ├── threat_consolidator.py  ThreatConsolidator — Jaccard dedup, AI wins over pytm
│   │   ├── threat_ranker.py      ThreatRanker — weighted composite rank + trim of consolidated threats
│   │   ├── stride_constants.py   STRIDE_CATEGORIES — single source of truth for the 6 STRIDE names
│   │   └── report_serializer.py  ReportSerializer — stable versioned dict, IDs T-NNNN
│   │
│   ├── ai_engine/                AI inference layer
│   │   ├── embedding_factory.py  get_embeddings() — provider-agnostic factory
│   │   ├── prompt_loader.py      Loads threat_analysis/config/prompts.yaml sections for each AI role
│   │   ├── rag_service.py        RAGThreatGenerator — ChromaDB + LangChain RAG chain
│   │   ├── providers/
│   │   │   ├── base_provider.py  BaseLLMProvider (ABC): check_connection, generate_threats
│   │   │   ├── litellm_client.py LiteLLMClient — low-level async LiteLLM wrapper
│   │   │   │                     (static factory create(), generate_content generator)
│   │   │   ├── litellm_provider.py  LiteLLMProvider(BaseLLMProvider) — orchestrates client
│   │   │   └── ollama_provider.py   OllamaProvider(BaseLLMProvider) — Ollama-specific
│   │   └── prompts/
│   │       └── stride_prompts.py    STRIDE_SYSTEM_PROMPT, build_component_prompt()
│   │
│   ├── generation/               Output artifact generators
│   │   ├── diagram_generator.py  DiagramGenerator — DOT/SVG via Graphviz subprocess
│   │   ├── svg_generator.py      SvgGenerator — standalone SVG manipulation
│   │   ├── report_generator.py   ReportGenerator — orchestration, Jinja2 HTML render, project
│   │   │                         mode; composes ScoringMixin/AIAnalysisMixin/ProjectReportMixin
│   │   ├── report_scoring.py     ScoringMixin + score_threat() — MITRE/CVE/network/severity
│   │   │                         pipeline shared by pytm- and AI-derived threats
│   │   ├── report_ai_analysis.py AIAnalysisMixin — CISO triage, attack-path narratives, GDAF debate
│   │   ├── report_project.py    ProjectReportMixin — multi-model project report generation
│   │   ├── stix_generator.py     StixGenerator — STIX 2.1 bundle JSON
│   │   ├── attack_navigator_generator.py  AttackNavigatorGenerator — Navigator layer JSON
│   │   ├── sarif_generator.py    SarifGenerator — SARIF 2.1.0 (GitHub Security > Code scanning)
│   │   ├── attack_flow_generator.py       AttackFlowGenerator — STRIDE-technique attack paths
│   │   │                                  (pure graph traversal, no LLM — see decisions.md)
│   │   ├── attack_flow_builder.py         AttackFlowBuilder — writes GDAF scenarios to .afb files
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
│   │   ├── model_management_service.py  ModelManagementService — save/load/version
│   │   ├── static/js/
│   │   │   └── dsl_schema.js     DSL single source of truth (sections, entities, field types,
│   │   │                         autocomplete metadata) — drives Component Panel + autocomplete
│   │   └── templates/
│   │       ├── index.html        Menu page (mode selection). CSP script-src is 'self'
│   │       │                     'unsafe-inline' (templates use inline on*= handlers a nonce
│   │       │                     can't cover); 'unsafe-eval' stays out (see decisions.md)
│   │       ├── simple_mode.html  Simple editor: CodeMirror + DSL autocomplete, Component Panel
│   │       │                     helper, localStorage autosave, _diagramInFlight concurrency guard
│   │       └── graphical_editor.html  Full graphical editor: Konva.js canvas (KonvaManager.js)
│   │
│   ├── iac_plugins/              IaC adapter layer — auto-discovered via `*_plugin.py` glob,
│   │   │                         no manual registration (see load_iac_plugins() in __main__.py)
│   │   ├── __init__.py           IaCPlugin ABC definition
│   │   ├── ansible_plugin.py     AnsiblePlugin — parses inventory + playbook → components
│   │   ├── terraform_plugin.py   TerraformPlugin — parses .tf / tfstate; 50+ AWS/Azure/GCP types
│   │   └── docker_compose_plugin.py  DockerComposePlugin — services→Servers, networks→Boundaries,
│   │                             depends_on + shared-network → Dataflows, image→Server.type map
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
│   ├── ai_config.yaml            AI providers, generation settings, RAG, embeddings, GDAF risk criteria
│   ├── context.yaml              Migration notice (AI context keys now in DSL ## Context)
│   ├── prompts.yaml              All LLM prompts (DSL gen, STRIDE, Attack Flow, RAG)
│   └── user_context.example.json User threat intelligence JSON schema
│
├── action.yml                    Official SecOpsTM GitHub Action (threat-model-analysis)
├── examples/
│   └── threat-model.yml          Template CI workflow — copy into a consumer repo's
│                                 .github/workflows/ (not run in this repo)
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
├── tests/                        pytest suite (~40 test files, 1487 tests)
├── threatModel_Template/         Ready-to-use DSL model templates
│   ├── Kubernetes_Helm_Cluster/  14 servers, 8 boundaries, 22 dataflows, 78 pytm threats
│   ├── Serverless_AWS_Lambda/    21 servers, 8 boundaries, 23 dataflows, 106 pytm threats
│   └── …                         Six_Tier, Microservices, CI_CD, Mobile, Cloud_Native, etc.
├── docs/                         User and technical documentation
└── .github/workflows/            CI: coverage_check.yml, sync-wiki.yml, docker-publish.yml, …
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
        → reads tm.findings (condition-matched, already per-instance)
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
    → AIThreatCache.load(threat_model._model_file_path)  (from .secopstm_ai_cache.json)
    → RAGThreatGenerator.generate_threats(markdown)   (system-level, RAG)
        → vector_store.similarity_search(query, k=5)
        → litellm.completion() direct (no langchain)
        → JSON extraction + parse → ExtendedThreat(source="LLM")
    → For each element (actors + servers + boundaries):
        → AIThreatCache.get(sha256(component_details)) → skip LLM if hit
        → prompt includes boundary trust level (TRUSTED/UNTRUSTED)
        → LiteLLMClient.generate_content(prompt, system_prompt, stream=False)
        → JSON extraction → ExtendedThreat(source="AI")
        → AIThreatCache.put(hash, threats) → cache.save() once after all
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
GET /                     → index.html (menu page)
GET /simple               → simple_mode.html (CodeMirror, DSL autocomplete, Component Panel, autosave)
POST /update_diagram      → ThreatModelService.update_diagram_logic()
                              → DiagramService → ModelParser → DiagramGenerator → DOT → SVG
POST /api/validate_markdown → concurrent-safe DSL validation (returns {skipped:true} if
                              _diagramInFlight; guards prevent concurrent pytm TM instantiation)
POST /export              → ThreatModelService.export_files_logic()
                              → ExportService → various generators
POST /export_all          → full ZIP bundle (HTML, SVG, STIX, Navigator, Attack Flow)
POST /ai/generate_markdown → SSE stream → AIService.generate_markdown_from_prompt()
GET  /api/ai_status_stream → SSE stream of ai_status_event_queue
POST /api/export_project   → generate_full_project_export() with progress SSE
```

### 3b. Server Security Hardening

Single-user tool, no auth by default (see "Offline-First"/single-user design throughout this
doc) — these are the mitigations that exist without requiring one:

```
serve(app, ...)             waitress (production WSGI) unless FLASK_DEBUG=true on loopback —
                             replaces Werkzeug's single-process dev server (server.py)

_reject_cross_origin_mutations()   before_request hook — rejects POST/PUT/PATCH/DELETE whose
                             Host or Origin header isn't loopback / FLASK_HOST's configured
                             value. Defeats both classic cross-origin drive-by requests and
                             DNS-rebinding attacks (server.py:_is_allowed_request_host)

_enforce_bearer_auth()      before_request hook, opt-in via SECOPSTM_REQUIRE_AUTH=true +
                             SECOPSTM_API_TOKEN=<secret>. Accepts `Authorization: Bearer <token>`
                             or `?token=<token>` (bookmarkable — plain navigation can't set
                             headers), sets a signed session cookie once validated. Refuses to
                             start if REQUIRE_AUTH=true with no token set (fail loud, not open).
                             Off by default — the documented Docker onboarding
                             (`-p 127.0.0.1:5000:5000`) stays frictionless.

CSP script-src              'self' 'unsafe-inline' — external scripts blocked (no CDN; every
                             script is a same-origin vendored file: CodeMirror, Konva,
                             svg-pan-zoom, split.js), 'unsafe-eval' kept out (no eval()/
                             new Function() in scope). 'unsafe-inline' is required: the
                             templates rely on inline on*= event handlers, which a nonce cannot
                             cover. A nonce-based script-src was tried (commit f1c2bcd) and
                             reverted — it silently broke every toolbar button (see decisions.md).

minimal_subprocess_env()    env allowlist (PATH/HOME/LANG/...) passed to every `dot` subprocess
                             call (diagram_generator.py, svg_generator.py, diagram_service.py) —
                             LiteLLMClient's os.environ[api_key_env] writes are never inherited.
```

### 3c. Lightweight Multi-User Workspaces

```
pytm_build_lock()            threading.RLock()-based context manager (core/model_factory.py) —
                              serializes every create_threat_model()+process_threats() pair
                              across concurrent server requests. Required because pytm >=1.4.0
                              keeps TM's element/flow registry at the CLASS level, shared by the
                              whole process — TM.reset() (called in ThreatModel.__init__) from one
                              request can wipe another's in-flight state. Every acquisition wraps
                              only a single model's create+process pair, released before any
                              report/AI/RAG/GDAF generation runs — no call site currently nests.
                              RLock (not Lock) is kept anyway as a defensive default against a
                              future call site nesting on the same thread, at zero extra cost.

GET /api/workspaces          Scans SECOPSTM_WORKSPACES_DIR (unset by default — the whole feature
                              is invisible when it is) for subdirectories containing main.md or
                              model.md. Feeds a dropdown in simple_mode.html's toolbar that calls
                              the pre-existing POST /api/set_project_path (session-scoped, not a
                              process-wide global — see _get_active_project_path()).

Design doc: docs/superpowers/specs/2026-07-23-lightweight-multi-user-workspaces-design.md
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
    CVE resolution priority (per asset):
        1. VEXLoader (standalone vex_file / vex_directory from DSL ## Context)
        2. BOMLoader active_cves / fixed_cves (BOM with analysis.state)
        3. BOMLoader known_cves (stateless BOM, treated as active)
        4. CVEService YAML definitions (last resort)
    _warn_bom_mismatches(): logs WARNING for BOM file stems not matching any component name

    For each pytm grouped threat:
        → MitreMapping.analyze_pytm_threats_list()   (STRIDE → CAPEC → ATT&CK → D3FEND)
        → _resolve_active_cves() + CVEService.get_cwes_for_cve()
        → _is_network_exposed(target)                (Dataflow auth/encryption, Boundary trust)
        → has_fixed_cves → treated as D3FEND-equivalent mitigation signal
        → RiskContext(has_cve_match, cwe_ids, network_exposed, has_d3fend_mitigations)
        → SeverityCalculator.calculate_score(..., risk_context)

    For each AI element threat (source="AI"):
        → same CVE/VEX/CWE/network pipeline as above

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

### 5b. GDAF Attack Path Generation + Red/Blue Debate

```
GDAFEngine.run(threat_model, context_yaml)      (top-down, complementary to AttackChainAnalyzer)
    → reads attack_objectives + threat_actors from context YAML
      (or _auto_context() — a minimal context synthesized from the model's servers if no YAML given)
    → _build_graph()                             (nodes = components, edges = dataflows +
                                                    sub-model bridging edges for submodel= servers)
    → per (objective, threat_actor) pair: graph traversal from actor's entry point to objective
        → hop_weight includes boundary.traversal_difficulty bonus (low=+0.3, medium=+0.1, high=+0.0)
        → per-hop MITRE technique assignment (AssetTechniqueMapper)
    → returns List[AttackScenario], stored as threat_model.gdaf_scenarios
    → AttackFlowBuilder(gdaf_scenarios).generate_and_save()   (.afb export, MITRE Attack Flow v3.0)

ReportGenerator.generate_html_report() — after attack_id_validation, before CISO triage:
    → if debate.enabled and gdaf_scenarios:
        RedBlueDebateEngine.run(gdaf_scenarios)    (one configured LLM provider, two personas)
            → per top-N scenario, N rounds:
                Red persona:  advances the attack using only facts in the grounding block
                Blue persona: blocks/detects, cites SIEM/EDR/IDS, lists detection_gaps
            → mutates scenario.score / risk_level in place (does NOT create new threats)
        → re-run AttackFlowBuilder(...).generate_and_save()   (.afb files re-written so they
                                                                 agree with debate-adjusted scores)
```

### 5c. SOC Analyst + CISO Triage

```
ReportGenerator.generate_html_report() — after the debate re-write, before the final template render:
    → _build_threat_graph_data(threat_model, all_detailed_threats, gdaf_scenarios, debate_results)
        → node/edge graph with GDAF path overlays, reflects debate-adjusted scores

    → if ai_provider and all_detailed_threats:
        AIService._enrich_with_soc_analysis()      (per-threat, soc_analyst prompt persona)
            → Sigma / Splunk SPL / KQL rule suggestions + IOCs
            → stored on threat.ai_details["soc_analysis"], rendered in the "SOC Analysis" section

        ReportGenerator._run_ciso_triage(all_detailed_threats, gdaf_scenarios, debate_results)
            → LiteLLMProvider.generate_ciso_triage()   (ciso_triage prompt persona)
            → board-level risk summary, rendered in the "CISO Briefing" section
```

### 5d. Discovered Attack Paths + Narrative

```
ReportGenerator.generate_html_report() — after CISO triage, before the template render:
    → if attack_flows.enabled:
        AttackFlowGenerator(all_detailed_threats, allowed_categories=...).get_paths_summary()
            → best (highest-severity) path per STRIDE category through the threats' own
              MITRE techniques — pure graph traversal, no LLM call, no GDAF context needed
            → each hop self-reports its own threat_id/threat_description (not positional
              lookup into threat_ids[i] — that list silently skips threats with no id)

        → if ai_provider and attack_flows.include_narrative:
            ReportGenerator._generate_path_narratives(discovered_attack_paths)   (in place)
                → per path (≤6 — one per STRIDE category): builds a grounding block from the
                  path's own hops (target, technique NAME — not ID, tactic, related threat
                  description) and calls LiteLLMProvider.generate_attack_path_narrative()
                  (attack_path_narrative prompt persona)
                → persona is instructed to never emit an ID (T-number, CVE, CAPEC, D3-) —
                  _narrative_has_id_leakage() regex-checks the response regardless of
                  cooperation; any match discards the entire narrative (fail closed, not a
                  partial-trust patch), logged as a grounding violation
                → on success, path["narrative"] / path["business_impact"] are set
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

### 7. CI/CD Gate + SARIF (GitHub Action)

```
action.yml (composite action, ellipse2v/SecOpsTM@v1)
    1. Install system deps (graphviz, jq) + Python + SecOpsTM
    2. Run analysis → secopstm --output-format json --output-file <sidecar>
       [+ --sarif if inputs.sarif == 'true']
    3. Diff against baseline (if inputs.baseline set)
        → secopstm --diff <baseline> <current> → step summary + PR comment
    4. Post PR comment (top-5 threats table + diff, if comment-on-pr == 'true')
    5. Upload artifacts (HTML/JSON/STIX/Navigator/.afb)
    6. Upload SARIF → github/codeql-action/upload-sarif (if inputs.sarif == 'true';
       calling workflow needs `permissions: security-events: write`)
    7. Apply security gate — calls `secopstm --gate <report> --fail-on <level>
       [--baseline ...] [--accepted-risks ...]` (threat_analysis/__main__.py:run_gate_check),
       not a bash reimplementation — baseline/accepted-risks are honoured this way.

jq stat field names MUST match ReportSerializer's actual v1 schema:
    .statistics.total              (not .statistics.total_threats)
    .statistics.by_severity_level.X (not .statistics.by_severity.X)
severity fields in the JSON report are {score, level, formatted_score} objects,
never plain strings — see run_gate_check/diff_threat_reports/compare_threat_reports
in __main__.py / utils.py.
```

## External Dependencies and Rationale

| Dependency | Why |
|---|---|
| `pytm` | Core STRIDE threat rule engine — the project is built around it |
| `Flask[async]` | Simple web framework; async needed for streaming AI responses |
| `waitress` | Production WSGI server for `secopstm --server` — replaces Werkzeug's dev server outside FLASK_DEBUG |
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
   now a single shared function in `threat_analysis/utils.py`.

2. ~~**pytm.Boundary monkey-patching**~~ — **Fixed**: replaced by the `SecOpsBoundary(Boundary)`
   subclass in `models_module.py`, which adds `isTrusted`, `protocol`, `port`, `data` without
   patching the pytm class at runtime.

3. ~~**Sync wrapper over async generator**~~ — **Fixed**: `generate_markdown_from_prompt_sync`
   now submits to a persistent background event loop via `asyncio.run_coroutine_threadsafe()`
   (see the "RAG init parallel to AI connection check" and cross-model RAG decisions in
   `decisions.md`), instead of calling `loop.run_until_complete()` per chunk.

4. ~~**Hardcoded rate limit sleep**~~ — **Fixed**: `rate_limit_sleep` is now configurable via
   `ai_config.yaml → threat_generation.rate_limit_sleep`.

5. ~~**`_get_output_dir` defined twice**~~ — **Fixed**: duplicate removed from `ExportService`.

6. ~~**`venv-py310/` in the repo tree**~~ — **Fixed**: already listed in `.gitignore`.

7. **`requirements.txt` vs `pyproject.toml` diverge** — `pyproject.toml`'s base `dependencies`
   already include `litellm`, `chromadb`, `sentence-transformers` (core AI/RAG works via
   `pip install -e .` alone). `requirements.txt` adds the heavier full RAG stack on top
   (`langchain*`, `jq`, `unstructured[all]`) — use it only if you need those. There is no
   `[project.optional-dependencies]` group in `pyproject.toml` (removed at some point;
   `pip install -e ".[ai]"` no longer applies).

8. **`package-lock.json` at root** — Present on disk but already gitignored (no `package.json`
   exists). Harmless local artifact, not tracked; safe to delete locally if it bothers you.

9. ~~**`ThreatModel` requires `CVEService`** injected at construction~~ — **Fixed**: falls back
   to a lazily-constructed default `CVEService` (same fallback `ReportGenerator.__init__`
   already used) instead of raising `ValueError`. `CVEService` itself already degrades
   gracefully when `cve_definitions.yml` is missing, so this closes an inconsistency rather
   than opening a new risk. `ThreatModel("name")` is now constructible with zero services —
   useful for domain-only unit tests. The 2 real production call sites
   (`model_factory.py`, `report_project.py`) always pass a real `cve_service` — unaffected.

10. ~~**`config/ai_config.yaml` YAML indentation error**~~ — **Fixed**: stray space before `rag:`
    removed; `config/ai_config.yaml` restructured into three clear sections.

11. **`config/context.yaml` is deprecated** — AI context keys (`project_description`, `compliance_requirements`, etc.)
    are now declared in the DSL `## Context` section or in `context/*.yaml` per-model files.
    `config/context.yaml` contains only a migration notice. The global file path is no longer read
    at runtime; remove the `--ai-context-file` CLI flag usage from existing scripts.

12. **localStorage autosave key collision** (`simple_mode.html`) — Draft key is
    `'secopstm_autosave_' + path` where `path` is a relative path (e.g., `main.md`). Two
    projects with identically-named files share the same key. User must confirm before the
    draft is applied (banner + Discard button), so data loss requires user action. Low urgency.

13. ~~**`diagram_svg` / `legend_html` rendered via `innerHTML`; component names not
    HTML-escaped**~~ — **Verified already mitigated**, this note was stale. Empirically tested
    (component names containing `<script>`, `onerror=`, quotes) through the real DOT→SVG
    pipeline: `DiagramGenerator._escape_label()` already runs `html.escape()` before any name
    reaches a DOT label (both plain and HTML-like label syntax); `id=`/`class=` attributes go
    through `_sanitize_name()`/`_safe_css_value()`; `add_links_to_svg()` uses `ElementTree`'s
    `.set()`/`.text=` API, which escapes automatically. Graphviz's own SVG serializer
    re-escapes the mandatory XML metacharacters (`<`, `>`, `&`) on output. No unescaped
    injection point found in the current code. `innerHTML` is still used client-side for the
    SVG/legend — fine given the above, but still worth switching to safer DOM insertion as
    defense-in-depth if this ever becomes a multi-user deployment.

14. ~~**`prompts.yaml`'s `attack_flow` persona was dead code**~~ — **Fixed**: removed. It was a
    single-shot LLM attack-flow generator (`BaseLLMProvider.generate_attack_flow()` + the
    `attack_flow_prompts.py` module + `prompts.yaml`'s `attack_flow:` section) that was only ever
    called from unit tests, never from the application — see the "Attack Flow generation: graph
    traversal, not a single-shot LLM persona" decision in `decisions.md` for why it stayed removed.
    The real "Discovered Attack Paths" feature and `.afb` export (`generation/attack_flow_generator.py`,
    `generation/attack_flow_builder.py`) are unaffected — pure STRIDE-technique graph traversal over
    the fully consolidated pytm+AI+LLM threat list, no LLM call needed.
