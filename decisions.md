# Technical Decisions — SecOpsTM

---

## Decision: pytm as the core threat rule engine

**Choice:** Build on top of the `pytm` library rather than writing STRIDE rules from scratch.

**Why it matters:** pytm provides a mature, tested rule set for STRIDE applied to Actor/Server/Dataflow
topologies. It handles threat enumeration automatically once the model is built. This means the
project gets rule coverage for free and can focus on enrichment (MITRE mapping, AI, reporting).

**Trade-off accepted:** pytm's data model is rigid (Boundary, Actor, Server, Dataflow, Data) and its
threat targeting (class-level, not instance-level) required `_expand_class_targets()` to fix.
The `Boundary` class also lacks several attributes needed by the project, requiring runtime
monkey-patching.

---

## Decision: Custom Markdown DSL instead of Python API

**Choice:** Users define their threat models in a custom Markdown format (`## Actors`, `## Servers`,
`## Dataflows`, etc.) rather than writing Python code against the pytm API.

**Why it matters:** Makes threat models accessible to security architects who are not Python
developers. The DSL files are human-readable, version-controllable, and can be edited in the
Monaco editor in the web UI. Templates in `threatModel_Template/` lower the barrier to entry.

**Trade-off accepted:** The `ModelParser` is custom-built and fragile — section headers are
hard-coded strings, and the 2-pass design adds complexity. Breaking the DSL grammar breaks all
existing model files.

---

## Decision: LiteLLM as the LLM abstraction layer

**Choice:** All LLM calls go through LiteLLM (`litellm.acompletion`) rather than vendor-specific
SDKs (e.g., `openai`, `google-generativeai`).

**Why it matters:** A single provider can be swapped by changing one line in `ai_config.yaml`
(`enabled: true/false`). Supports Gemini, OpenAI, Mistral, and Ollama with a unified interface.
Enterprise users can point `api_base` at an internal proxy (OpenAI-compatible) without code changes.

**What was rejected:** Direct SDK calls per provider would require separate code paths and would not
support the "first enabled provider wins" selection logic cleanly.

---

## Decision: RAG pipeline using ChromaDB + LangChain

**Choice:** Retrieval-Augmented Generation using a local ChromaDB vector store pre-built from
the `external_data/` knowledge base (CAPEC, CVE, ATT&CK, D3FEND, CIS, NIST).

**Why it matters:** Enables the LLM to ground its threat generation in real security knowledge
(CVE precedents, CAPEC attack patterns) without fine-tuning. The vector store is built once
offline (`tooling/build_vector_store.py`) and ships with the project.

**What was rejected:** Fine-tuning (Phase 3 in the roadmap) was explicitly deferred — too costly
and less flexible than RAG for a knowledge base that updates frequently.

---

## Decision: HuggingFace `all-MiniLM-L6-v2` as default embedding model

**Choice:** Local sentence-transformer model run on CPU as the default for vector similarity search.

**Why it matters:** Zero network dependency and zero API cost for embeddings. Supports fully
air-gapped/sovereign deployments. The model is small (80 MB) and fast enough for the query
volumes involved (single-user tool, not a SaaS).

**What was rejected:** Cloud embedding APIs (Google, OpenAI) are supported via `embedding_factory.py`
but not the default, to avoid mandatory API key setup for the RAG feature.

---

## Decision: Flask (not FastAPI) as the web framework

**Choice:** Flask with `Flask[async]` extension.

**Why it matters:** The project started without AI streaming and Flask was the natural choice for
a simple single-user tool. `Flask[async]` was added to support SSE streaming of AI generation
output without a full framework migration.

**Trade-off accepted:** The sync/async boundary is awkward — `generate_markdown_from_prompt_sync`
uses `loop.run_until_complete(gen.__anext__())` per chunk, which is not safe under concurrent load.
FastAPI would handle this more cleanly but would require significant route refactoring.

---

## Decision: Server-Sent Events (SSE) for AI progress

**Choice:** Use a global `queue.Queue` (`ai_status_event_queue`) and SSE endpoint
(`/api/ai_status_stream`) to push real-time AI processing progress to the browser.

**Why it matters:** AI enrichment (per-component LLM calls) can take 30–120 seconds. Without live
feedback the UI appears frozen. SSE is simpler than WebSockets for unidirectional server→client
streams and requires no additional dependencies.

**What was rejected:** Polling (too many requests) and WebSockets (overkill for unidirectional flow).

---

## Decision: Lazy imports throughout the codebase

**Choice:** Heavy imports (`litellm`, `langchain`, `chromadb`, `sentence_transformers`) are done
inside methods or `__init__`, not at module top level.

**Why it matters:** The Flask server starts fast even when AI features are disabled or dependencies
are not installed. `ThreatModelService` is also lazy-initialized on first request.

**Consequence:** Import errors for optional AI deps surface at runtime, not at import time. This
is intentional — the tool works without AI deps if AI config is disabled.

---

## Decision: `ExtendedThreat` subclassing `pytm.Threat`

**Choice:** AI-generated and custom threats are represented as `ExtendedThreat(pytm.Threat)` with
an added `source` attribute (`"pytm"`, `"AI"`, `"LLM"`).

**Why it matters:** Allows the rest of the pipeline (grouping, MITRE mapping, reporting) to treat
all threats uniformly regardless of origin. The `source` field enables the report to distinguish
traditional vs. AI-generated threats and apply different rendering.

**What was rejected:** A parallel `AIThreat` class with no pytm inheritance would have required
forking all downstream threat processing logic.

---

## Decision: Offline data pipeline in `tooling/`

**Choice:** Scripts that download, parse, and transform security data (MITRE ATT&CK JSON, CAPEC XML,
CVE JSONL, NIST XLSX) are separate one-shot tools, not part of the runtime application.

**Why it matters:** The transformed artifacts (`external_data/*.json`, `vector_store/`) are committed
to the repo so end users do not need network access or tool dependencies to use the threat model.
The pipeline only needs to run when upstream data sources update.

**Trade-off accepted:** The repo is large (CVE JSONL files from 1999–2025 are significant).
The vector store binary files are also committed, which inflates repo size.

---

## Decision: `config/ai_config.yaml` as the single AI configuration surface

**Choice:** All AI provider selection, model parameters, RAG settings, and embedding config live
in one YAML file rather than environment variables or a `.env` file.

**Why it matters:** A single file to edit for setup. Enterprise users can template this file
for different deployment environments. The `api_key_env` indirection keeps secrets in environment
variables while keeping non-sensitive config in the file.

**Consequence:** The YAML file must be present at runtime even if AI is disabled. Path is resolved
relative to `PROJECT_ROOT` (detected via `Path(__file__).resolve().parents[N]`).

---

## Decision: Jaccard-based deduplication — AI source wins

**Choice:** When a pytm threat and an AI/LLM threat cover the same `(target, stride_category)` with
similar descriptions (Jaccard word-overlap ≥ 0.3 or substring containment), the AI version replaces
the pytm version. Implemented in `threat_analysis/core/threat_consolidator.py`.

**Why it matters:** Without deduplication, the same risk (e.g. "SQL injection on DB server") appears
two or three times in the report — once from pytm rules, once from the component LLM, possibly again
from the RAG pipeline. This inflates threat counts and confuses prioritisation.

**Why Jaccard and not embedding similarity:** Embedding similarity would require loading the
sentence-transformer model during report generation, breaking the offline-without-AI-deps path.
Jaccard on word sets is purely offline, instantaneous, and sufficient for the overlap patterns
observed in practice (same STRIDE category, same target, paraphrased description).

**Why AI wins over pytm:** AI-generated threats include richer context (attack scenario, recommended
controls). Keeping the AI version provides more actionable output. The pytm threat is only removed
when similarity is confirmed — unrelated pytm threats are always preserved.

---

## Decision: Versioned JSON schema — `schema_version: "1.0"`

**Choice:** Every JSON export is serialised by `ReportSerializer` and stamped `schema_version: "1.0"`.
The schema is validated against `threat_analysis/schemas/v1/threat_model_report.schema.json`
(JSON Schema 2020-12). Threats get stable IDs in the format `T-0001`.

**Why it matters:** SIEM integrations, dashboards, and CI gates that consume the JSON output break
silently when the structure changes. A versioned, validated schema gives consumers a stable contract
and allows the tool to signal breaking changes explicitly.

**What was rejected:** Ad-hoc dict construction (the previous approach) offered no contract and
generated different key sets depending on which code path ran. Migration to a serialiser was
preferred over adding version guards to the ad-hoc dict.

---

## Decision: RiskContext VOC scoring — CWE as CVSS proxy

**Choice:** Instead of a CVSS score (absent from the CVE JSONL files), the `RiskContext` dataclass
encodes four binary context signals that adjust the STRIDE base score:
- CVE match for target/category → +0.5 (confirmed exploitability evidence)
- High-risk CWE class (injection, memory corruption, hardcoded creds…) → +0.3
- Network-exposed without auth/encryption → +0.7
- D3FEND defensive mitigations in place → −0.5

**Why CWE instead of CVSS:** Inspection of the CVE JSONL corpus revealed that entries only carry
`CWE`, `CAPEC`, and `TECHNIQUES` keys — no CVSS scores. CWE class is used as an exploitability
proxy: the `_HIGH_RISK_CWES` frozenset covers the 14 most commonly weaponised weakness classes.

**Why additive deltas instead of a new scoring model:** The existing base-score system (by STRIDE
category, target multiplier, protocol, classification) already has calibrated values. Additive
deltas from `RiskContext` layer on top without invalidating historical scores or requiring
re-calibration of the full model.

---

## Decision: CVEService single-pass JSONL loading

**Choice:** `CVEService._ensure_maps_loaded()` populates both `_cve_to_capec_map` and
`_cve_to_cwe_map` in a single traversal of all JSONL files (~26 files, 1999–2025).

**Why it matters:** The JSONL corpus is large. A separate pass to build the CWE map (naively
added alongside the existing CAPEC pass) would double I/O and parse time at startup. A single
lazy-loaded pass, gated by `if self._cve_to_capec_map is not None: return`, ensures both maps
are always consistent and the files are opened exactly once.

---

## Decision: `secopstm` CLI entry point via pyproject.toml

**Choice:** A `secopstm` command is installed by `pip install -e .` via
`[project.scripts] secopstm = "threat_analysis.__main__:main"`. New flags added:
`--output-format {all,html,json,stix}`, `--output-file PATH`, `--stdout`.

**Why it matters:** CI pipelines need a stable, pip-installable command — not `python -m
threat_analysis` with an implicit working directory. `--stdout` enables direct piping to `jq`
or a SIEM without writing intermediate files. All legacy invocations (`python -m threat_analysis
--server`, `--gui`, `--project`, `--ansible-path`) remain 100% backward-compatible because new
flags all default to the previous behaviour.

---

## Decision: AttackChainAnalyzer — pure graph traversal, no ML

**Choice:** `threat_analysis/core/attack_chain.py` uses simple directed graph traversal (dataflows
as edges, threats indexed by component name) to identify multi-step attack paths. No NLP, no
ML, no network access.

**Why it matters:** A common question in threat review is "how do these threats chain together
into a realistic attack scenario?" The attack chain section gives reviewers a pre-computed answer
without additional tooling. It reuses the already-computed `all_threats` list — no extra AI call,
no extra cost.

**Why not ML/graph DB:** The system topology is small (typically <50 nodes). Simple iteration over
dataflows is O(E × max_threats_per_node). Graph DB (Neo4j) or ML clustering would add heavyweight
dependencies for zero additional accuracy at this scale.

**Trade-off accepted:** Chains are identified by dataflow adjacency only — threats within the same
boundary but not connected by a modelled dataflow are not chained. This is intentional: if no
dataflow is modelled, no data movement is assumed.

---

## Decision: Trust boundary colors baked into DOT template (B1)

**Choice:** Trusted boundaries use `color="#2e7d32"` (dark green, solid), untrusted use
`color="#c62828"` (dark red, dashed). These values are in `threat_model.dot.j2` — they affect
the DOT output directly, which means both the Graphviz-generated SVG export and the HTML diagram
render consistent colors.

**Why baked into DOT and not post-processed in SVG:** The user generates SVG files independently
via `DiagramGenerator.generate_custom_svg_export()`. Any coloring applied only at the HTML stage
would be absent from the exported SVG. Putting the color logic in the DOT template is the only
way to guarantee consistency across all output formats.

**What was rejected:** A JavaScript overlay that colorizes boundaries in the HTML view only was
considered but rejected for the trust convention specifically (B1). It was however adopted for
the severity heat map (B2) because severity data requires threat processing, which is not
available during SVG generation.

---

## Decision: Severity heat map as JS-only toggle (B2)

**Choice:** The severity overlay in HTML diagrams is implemented entirely in JavaScript — it reads
`severity_map_json` injected at template render time and toggles SVG `fill` attributes on demand.
The base SVG is never modified. The toggle button hides itself when `severity_map` is empty.

**Why JS-only:** Severity requires the full threat scoring pipeline to run (`process_threats()` →
`_compute_severity_map()`). In the live editor preview, this pipeline does not run (too slow for
real-time editing). A JS toggle that receives pre-computed data at render time is the only approach
that works in both the live preview (empty map → button hidden) and the exported HTML (data
present → button shown).

**Why preserve original fills:** The overlay must be reversible so users can compare the
architectural diagram (original colors) against the severity view. The `originalNodeFills` map
saves each node's fill before the overlay is applied and restores it on toggle-off.

---

## Decision: Cross-model RAG analysis via sync wrapper (A2)

**Choice:** `AIService.generate_rag_threats_sync()` uses `asyncio.run_coroutine_threadsafe()` on
a persistent background event loop (`_get_sync_loop()`) rather than `asyncio.run()` or a new
`ThreadPoolExecutor`. It is called from `ReportGenerator.generate_project_reports()` after all
sub-models are processed and `main_threat_model.sub_models` is populated.

**Why a persistent loop instead of `asyncio.run()`:** `generate_project_reports()` is called from
a Flask route handler which already runs inside an event loop. `asyncio.run()` would raise
`RuntimeError: cannot run nested event loop`. The persistent background loop pattern (already used
by `generate_markdown_from_prompt_sync`) avoids this issue cleanly.

**Why after sub-model recursion:** The RAG query needs the full project markdown to generate
cross-boundary threats. The sub-model list is only complete after the recursive pass over
`all_processed_models`. Calling RAG before that would give it only the main model's context,
defeating the purpose of cross-model analysis.

---

## Decision: Boundaries as AI threat targets (A3)

**Choice:** `SecOpsBoundary` and `Boundary` objects are added to `all_elements` in
`AIService._enrich_with_ai_threats()`. Because boundaries lack `is_public` and `is_authenticated`
attributes (those belong to Servers/Actors), boundary-specific logic was added: `elem_type` is set
to `"Trust Boundary (Trusted|Untrusted)"` and the trust level is injected into the prompt.

**Why boundaries merit their own AI threats:** Boundaries represent trust zone transitions —
exactly the places where privilege escalation, lateral movement, and data exfiltration paths are
most likely. pytm does not generate threats targeting boundaries directly (only the dataflows
crossing them). Adding boundaries as AI targets surfaces zone-level threats that the rule engine
misses.

**What was rejected:** Generating boundary threats as a separate post-processing step (e.g. from
the ATT&CK mapping alone) was considered but would not leverage the contextual knowledge of the
LLM about the specific architecture described in the model.

---

## Decision: GDAF top-down approach alongside bottom-up AttackChainAnalyzer

**Choice:** Implement `GDAFEngine` as a separate, complementary attack path generator that works
top-down from attacker objectives, rather than extending `AttackChainAnalyzer` (which works
bottom-up from discovered threats).

**Why it matters:** The two engines answer different questions:
- `AttackChainAnalyzer` answers: "Given the threats already found, which ones can be chained
  across dataflows?" It starts from the threat inventory and finds adjacencies.
- `GDAFEngine` answers: "If an adversary with these capabilities wanted to reach this target,
  what path through the architecture would they take?" It starts from intent and finds paths.

The bottom-up approach surfaces unexpected chaining of individually low-risk threats. The
top-down approach guarantees that high-value objectives (domain compromise, data exfiltration)
are always evaluated, even if no pytm or AI threats have been generated yet — which matters for
architectures described in the DSL but not yet enriched by AI.

**Why not replace `AttackChainAnalyzer`:** The two outputs are structurally different.
`AttackChainAnalyzer` chains existing `ExtendedThreat` objects with their STRIDE categories,
MITRE mappings, and severity scores — directly linkable to the threat report. `GDAFEngine`
produces new `AttackScenario` objects with per-hop MITRE technique assignments from a graph
traversal — suited for Attack Flow export and adversary simulation, not for augmenting the
existing threat table.

**Trade-off accepted:** GDAF requires a context YAML file with objectives and actor profiles.
Without this file, `GDAFEngine.run()` returns an empty list. This is intentional: the engine
is opt-in and the context file is the mechanism for expressing organizational threat intelligence
that cannot be inferred from the architecture model alone.

---

## Decision: Services collectés depuis les dataflows — pas de duplication DSL

**Choice:** Les protocoles exposés par un asset sont inférés depuis les dataflows adjacents (entrants + sortants) plutôt qu'un champ `services=[]` explicite sur le serveur.

**Why it matters:** Le DSL modélise déjà les protocoles sur chaque dataflow. Exiger une déclaration redondante `services=[SSH, RDP]` sur le serveur violerait DRY et introduirait des incohérences (services déclarés mais aucun dataflow correspondant). Le collecteur de `_build_graph()` fait un agrégat automatique au moment de la construction du graphe.

**Trade-off accepted:** Les services locaux sans dataflow modélisé (ex. un port ouvert mais jamais utilisé dans le modèle) ne sont pas visibles. Cette limitation est intentionnelle : si un flux n'est pas modélisé, aucun chemin d'attaque ne l'emprunte de toute façon.

---

## Decision: BOM (Bill of Materials) comme enrichissement optionnel hors-DSL

**Choice:** Les données d'inventaire (version OS, CVEs, patch level, detection level) sont stockées dans des fichiers YAML séparés par asset (`BOM/{asset_name}.yaml`), pas dans le DSL.

**Why it matters:** Le DSL décrit l'architecture logique (composants, flux, confiance). L'inventaire technique (versions, CVEs) est une donnée opérationnelle qui change fréquemment, doit pouvoir être générée depuis des outils tiers (Qualys, Tenable, CMDB), et ne doit pas polluer la lisibilité du modèle d'architecture.

**Why YAML and not inline DSL:** Un export de scanner de vulnérabilités peut directement alimenter le répertoire `BOM/`. Le format YAML est compatible avec les exports Ansible inventory, Tenable, Qualys. L'intégration directe dans le DSL nécessiterait une migration de tous les modèles existants.

**Auto-discovery:** `BOMLoader` cherche `{model_parent}/BOM/` automatiquement si `bom_directory` n'est pas déclaré dans `## Context`. Pas de configuration requise pour commencer.

---

## Decision: `traversal_difficulty` sur les boundaries — coût de traversée dans GDAF

**Choice:** Un attribut `traversal_difficulty=low|medium|high` sur les boundaries contrôle un bonus de `hop_weight` : `low` → +0.3 (zone facile à traverser = chemin plus exploitable), `medium` → +0.1, `high` → +0.0 (attaquant très capable requis = chemin moins probable mais toujours évalué).

**Why it matters:** Le trust binaire (`isTrusted=true/false`) ne distingue pas une DMZ d'un réseau OT airgappé. Un attaquant peut traverser les deux, mais la probabilité et les techniques nécessaires sont radicalement différentes. Le bonus de hop_weight reflète l'accessibilité relative.

**Why NOT reduce score for high difficulty:** Un chemin traversant un réseau OT (traversal_difficulty=high) doit toujours apparaître dans les résultats — c'est précisément ce chemin qu'un analyste doit évaluer. La difficulté réduit légèrement son score relatif mais ne l'élimine pas.

---

## Decision: Sub-model drill-down — child IS the parent at higher detail

**Choice:** A server in a threat model can reference a child model via `submodel=./path/to/model.md`.
The child is not a separate dependency or a called service — it IS the same component described
at a finer granularity. The parent diagram links to the child; the child diagram shows ghost
nodes for external connections from the parent.

**Why it matters:** Large architectures become unreadable when everything is in one flat diagram.
Drill-down allows a threat model to be decomposed: the top-level model shows the overall
architecture with summarized components, and each component that merits deeper analysis gets its
own model file with the same full DSL support (actors, servers, dataflows, STRIDE analysis, AI
enrichment).

**Why ghost nodes in the child diagram:** When a security reviewer drills into a sub-component,
they need to know what external systems communicate with it — this context is essential for
identifying trust boundary threats and data flow risks. Ghost nodes provide that context without
requiring the child model to re-declare all parent-level connections, which would create
maintenance duplication.

**Why bridging edges in GDAF:** An attacker who compromises a server does not stop at that node
— they move into the server's internals. Without bridging edges, GDAF would treat the parent
server as a terminal node and miss all internal paths. Bridging reuses the already-parsed
sub-model graph, adding only two passes of edge injection (entry + exit bridges), at essentially
zero extra cost.

**What was rejected:** A separate "project dependencies" section in the DSL (defining which
models communicate with each other) was considered but would require maintaining two separate
representations of the same relationship — the server definition and a separate link declaration.
The `submodel=` inline keyword keeps the link co-located with the server definition.

---

## Decision: RAG init parallel to AI connection check — `run_in_executor`

**Choice:** `AIService.init_ai()` starts `RAGThreatGenerator()` in `loop.run_in_executor(None, ...)`
immediately, before calling `provider.check_connection()`. The asyncio Future is awaited only
after the connection check completes.

**Why it matters:** The two operations are completely independent:
- `check_connection()` is bottlenecked by `import litellm` (~64s on WSL2 cold cache, network
  call to fetch model pricing/metadata).
- `RAGThreatGenerator.__init__()` is bottlenecked by `import langchain_chroma` (~26s cold).
By overlapping them, the 26s chroma import is hidden inside the 64s litellm import.
Net saving: ~26s on every cold start where RAG is enabled.

**Why `run_in_executor` and not `asyncio.create_task`:** `RAGThreatGenerator.__init__()` is
synchronous and blocking (disk I/O, model loading). `create_task` would run in the same thread
and block the event loop. `run_in_executor` offloads to the default `ThreadPoolExecutor`,
keeping the event loop responsive.

**Fallback:** If the pre-warm raises (vector store missing, config error), `init_ai()` retries
synchronously once before setting `rag_generator = None`.

**What was rejected:** Starting RAG initialization from `ThreatModelService.__init__()` (before
`init_ai()` is even called) was considered but would require passing the AI config status back
and creates a race condition if the AI goes offline between warmup and use.

---

## Decision: BOM known_cves augment CVEService in scoring pipeline

**Choice:** `ReportGenerator._get_bom_loader(threat_model)` resolves a `BOMLoader` from the
model's `_model_file_path` (auto-discovers `{parent}/BOM/`) or `context_config['bom_directory']`.
In `_get_all_threats_with_mitre_info()`, BOM `known_cves` are appended to the list returned by
`cve_service.get_cves_for_equipment()` before the CAPEC intersection check — for both pytm and
AI-element threat scoring loops.

**Why it matters:** `CVEService.get_cves_for_equipment()` only knows CVEs declared in
`cve_definitions.yml` (YAML definitions keyed by equipment name). BOM files carry the
authoritative list of CVEs for each deployed asset (from vulnerability scanners, patch managers,
or SBOM pipelines). Combining both sources ensures that CVE-based VOC scoring reflects reality
rather than only the manually maintained YAML.

**What was rejected:** Feeding BOM CVEs directly into `CVEService` as a secondary lookup would
require mutating a shared service object or adding BOM awareness to `CVEService` itself — coupling
it to the BOM infrastructure. Augmenting the call site list is purely additive and keeps
`CVEService` focused on its existing JSONL/YAML data.

---

## Decision: initial_model_file_path global for Flask server BOM/context auto-discovery

**Choice:** `server.py` adds an `initial_model_file_path: Optional[str]` module-level global,
set in `run_server()` when a model file is successfully loaded. It is passed as `model_file_path`
to every `export_*_logic()` route call, which propagates it through `ThreatModelService` →
`ExportService` → `create_threat_model()` → `ThreatModel._model_file_path`. With `_model_file_path`
set, `ExportService._resolve_gdaf_context()` and `_resolve_bom_directory()` can auto-discover
the model's `context/` and `BOM/` sibling directories.

**Why a global:** The Flask routes are stateless functions with no access to the `run_server()`
scope. The alternative — injecting the path through `ThreatModelService.__init__()` — would
require a new constructor parameter and rebinding of the service on model switch, which is more
invasive. A module-level global is consistent with the existing `initial_markdown_content` and
`initial_project_path` pattern already used by the server.

**Scope:** When the server starts without a model file (empty editor mode), `initial_model_file_path`
stays `None` and exports proceed without BOM/context auto-discovery — matching the previous
behaviour exactly.
