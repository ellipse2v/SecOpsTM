# System Model: LLM / RAG Application

## Description
Enterprise chat assistant built on retrieval-augmented generation (RAG). Users chat through a web front end that calls an API gateway and a RAG orchestrator. The orchestrator screens prompts with a guardrails service, retrieves context from a vector database, and calls an external, third-party LLM provider. The model can request tool calls (customer lookup, ticket creation) that a tool gateway executes against internal services. A document ingestion pipeline parses, chunks and embeds knowledge documents into the vector database. Four trust zones: untrusted clients, the application zone, the internal data and tools zone, and the external LLM provider.

## Context
gdaf_context = context/llm_rag_context.yaml
bom_directory = BOM

## Boundaries
- **Client Zone**: isTrusted=False, type=network-on-prem, color=lightcoral, traversal_difficulty=low, description="Untrusted client side: end-user browsers, administrators on the internet and external attackers", businessValue="Source of all user input, including hostile prompts and untrusted documents"
- **Application Zone**: isTrusted=True, type=network-cloud-provider, color=lightyellow, traversal_difficulty=medium, description="Cloud VPC hosting the API gateway, orchestration, guardrails and tool brokering", businessValue="Enforces authentication, prompt screening and tool authorization"
- **Data and Tools Zone**: isTrusted=True, type=network-cloud-security-group, color=lightblue, traversal_difficulty=high, description="Private network holding the knowledge base, chat history and the internal services reachable by model tool calls", businessValue="Holds proprietary documents and customer records"
- **LLM Provider (External)**: isTrusted=False, type=network-cloud-provider, color=lightgray, line_style=dashed, traversal_difficulty=low, description="Third-party hosted LLM and embedding API outside organisational control", businessValue="Source of model output; also receives every prompt and retrieved passage"

## Actors
- **End User**: boundary="Client Zone", authenticity=externalized, isTrusted=False, description="Authenticated employee or customer chatting with the assistant through a browser"
- **Knowledge Admin**: boundary="Client Zone", authenticity=two-factor, isTrusted=True, description="Content owner who uploads and removes documents in the knowledge base"
- **External Attacker**: boundary="Client Zone", authenticity=none, isTrusted=False, description="Adversary attempting prompt injection, jailbreaks, data extraction, poisoned document uploads and abuse of model spend"

## Servers
- **Chat Front End**:
  boundary="Client Zone",
  type=client-browser,
  machine=saas,
  classification=INTERNAL,
  internet_facing=True,
  description="Single-page chat UI delivered via CDN that renders streamed model output as markdown in the user browser",
  businessValue="Primary user interface; rendering of model output is a script injection surface"
- **API Gateway**:
  boundary="Application Zone",
  type=api-gateway,
  machine=container,
  classification=RESTRICTED,
  internet_facing=True,
  waf=True,
  mfa_enabled=False,
  redundant=True,
  availability=high,
  description="Public entry point terminating TLS, validating tokens and applying per-user rate limits and token budgets; also hosts the document upload endpoints",
  businessValue="Single choke point for all traffic into the assistant"
- **Identity Provider**:
  boundary="Application Zone",
  type=identity-provider,
  machine=saas,
  classification=SECRET,
  mfa_enabled=True,
  auth_protocol=oidc,
  credentials_stored=True,
  confidentiality=critical,
  description="Managed OIDC identity provider issuing short-lived access tokens with MFA",
  businessValue="Root of user identity and of the identity propagated to tools"
- **RAG Orchestrator**:
  boundary="Application Zone",
  type=microservice,
  machine=container,
  classification=SECRET,
  mfa_enabled=False,
  redundant=True,
  integrity=critical,
  description="Builds prompts from the system prompt, chat history and retrieved passages, calls the LLM provider and executes the tool-call loop",
  businessValue="Core business logic; compromise gives control over prompts, retrieval and tool use"
- **Guardrails Service**:
  boundary="Application Zone",
  type=microservice,
  machine=container,
  classification=RESTRICTED,
  integrity=high,
  description="Screens prompts and retrieved passages for injection patterns, redacts PII, moderates model output and enforces a response schema before output reaches the user or the tool gateway",
  businessValue="Defence-in-depth control; a classifier can be evaded and must not be the only barrier"
- **Tool Gateway**:
  boundary="Application Zone",
  type=api-gateway,
  machine=container,
  classification=SECRET,
  mfa_enabled=False,
  integrity=critical,
  description="Brokers model-requested tool calls: allowlisted tools, JSON-schema argument validation, rate limits and per-user authorization for read tools only; write tools such as ticket creation get no per-user authorization and no human approval step",
  businessValue="Limits what a manipulated model can do to internal systems"
- **Secrets Manager**:
  boundary="Application Zone",
  type=secrets_manager,
  machine=saas,
  classification=SECRET,
  encryption=transparent,
  credentials_stored=True,
  confidentiality=critical,
  description="Managed secrets store holding the LLM provider API key, database credentials and tool service tokens",
  businessValue="Compromise exposes the LLM account and internal service access"
- **Audit Log**:
  boundary="Application Zone",
  type=monitoring,
  machine=saas,
  classification=RESTRICTED,
  encryption=transparent,
  detection_level=high,
  description="Central log store for prompts, responses, retrieved document IDs and tool calls, used for investigation and abuse detection",
  businessValue="Forensic evidence; prompt logs also contain user PII"
- **Vector Database**:
  boundary="Data and Tools Zone",
  type=database,
  machine=container,
  classification=RESTRICTED,
  encryption=transparent,
  credentials_stored=True,
  confidentiality=high,
  integrity=critical,
  description="Self-hosted vector store holding document embeddings, text chunks and source metadata with collection-level access keys; queries carry no per-user entitlement filter, so chunks from any document can be returned to any user",
  businessValue="Knowledge base: a leak exposes proprietary text, a write poisons every answer, and missing tenant isolation leaks one user data to another"
- **Document Store**:
  boundary="Data and Tools Zone",
  type=object-storage,
  machine=saas,
  classification=RESTRICTED,
  encryption=transparent,
  confidentiality=high,
  integrity=high,
  description="Object storage with versioning for original uploaded documents before ingestion",
  businessValue="System of record for knowledge content"
- **Ingestion Pipeline**:
  boundary="Data and Tools Zone",
  type=etl-tools,
  machine=container,
  classification=RESTRICTED,
  credentials_stored=True,
  description="Worker service that parses PDF and Office files, chunks the text, calls the embedding API and upserts vectors; processes untrusted file content with no malware or prompt-injection scan before chunks are indexed",
  businessValue="Only path by which documents become retrievable context"
- **Conversation History**:
  boundary="Data and Tools Zone",
  type=database,
  machine=virtual,
  classification=SECRET,
  encryption=transparent,
  credentials_stored=True,
  confidentiality=high,
  description="PostgreSQL database storing per-user chat transcripts and long-term assistant memory",
  businessValue="Contains user PII and sensitive business conversations"
- **Customer Records API**:
  boundary="Data and Tools Zone",
  type=microservice,
  machine=container,
  classification=SECRET,
  confidentiality=critical,
  auth_protocol=oauth,
  description="Internal service returning customer profiles and account data; called as a read-only model tool",
  businessValue="Authoritative customer data subject to privacy regulation"
- **Ticketing Service**:
  boundary="Data and Tools Zone",
  type=microservice,
  machine=container,
  classification=RESTRICTED,
  integrity=high,
  auth_protocol=oauth,
  description="Internal service for creating and updating support tickets; called as a write-capable model tool using one shared service token",
  businessValue="Writes to a business workflow; abuse creates fraudulent or destructive changes"
- **LLM Provider API**:
  boundary="LLM Provider (External)",
  type=default,
  machine=saas,
  classification=RESTRICTED,
  internet_facing=True,
  description="Third-party hosted chat completion and embedding API reached with a static API key; provider retention and training terms are contractual",
  businessValue="Required for every answer; availability, cost and data handling are outside direct control"

## Data
- **User Prompts**: classification=SENSITIVE, isPII=True, credentialsLife=NONE, description="Free-text chat messages that may contain personal or confidential information and hostile instructions"
- **Augmented Prompts**: classification=RESTRICTED, isPII=True, isConfidentialityCritical=True, credentialsLife=NONE, description="Full model input: system prompt, chat history, retrieved passages and user message"
- **Retrieved Context**: classification=RESTRICTED, isIntegrityCritical=True, credentialsLife=NONE, description="Text chunks returned by similarity search and inserted into the prompt as untrusted content"
- **LLM Responses**: classification=INTERNAL, isIntegrityCritical=True, credentialsLife=NONE, description="Model output including answers and requested tool calls; untrusted until validated"
- **Tool Call Requests**: classification=RESTRICTED, isIntegrityCritical=True, credentialsLife=NONE, description="Model-generated function name and arguments sent to the tool gateway"
- **Customer Records**: classification=SECRET, isPII=True, isConfidentialityCritical=True, credentialsLife=NONE, description="Customer profile and account data returned by tools and fed back into the model"
- **Knowledge Documents**: classification=RESTRICTED, isIntegrityCritical=True, credentialsLife=NONE, description="Source documents and extracted text chunks of the knowledge base"
- **Document Embeddings**: classification=RESTRICTED, isConfidentialityCritical=True, isIntegrityCritical=True, credentialsLife=NONE, description="Vectors with chunk text and metadata; embeddings can be inverted to recover most of the source text, and altered vectors change what is retrieved"
- **Conversation History**: classification=SENSITIVE, isPII=True, credentialsLife=NONE, description="Stored chat transcripts and assistant memory"
- **Audit Logs**: classification=SENSITIVE, isPII=True, credentialsLife=NONE, description="Logged prompts, responses and tool calls"
- **Access Tokens**: classification=SECRET, credentialsLife=SHORT, description="OIDC access tokens and the user identity propagated to downstream services"
- **LLM Provider API Key**: classification=SECRET, isPassword=True, credentialsLife=MANUAL, description="Static bearer key authorising spend on the LLM provider account"
- **Service Tokens**: classification=SECRET, credentialsLife=LONG, description="Long-lived service credentials used by the tool gateway and the ingestion pipeline"
- **Database Credentials**: classification=SECRET, isPassword=True, credentialsLife=AUTO, description="Rotated credentials for the vector and conversation databases"

## Dataflows
- **Load Chat UI**: from="End User", to="Chat Front End", protocol=HTTPS, is_encrypted=True, is_authenticated=False, authentication=none, description="Static page and script load before sign-in"
- **User Sign-In**: from="Chat Front End", to="Identity Provider", protocol=HTTPS, is_encrypted=True, is_authenticated=True, authentication=externalized, data="Access Tokens", description="Authorization code flow with PKCE and MFA"
- **Send Chat Message**: from="Chat Front End", to="API Gateway", protocol=HTTPS, is_encrypted=True, is_authenticated=True, authentication=token, authorization=required, data="User Prompts"
- **Upload Knowledge Documents**: from="Knowledge Admin", to="API Gateway", protocol="HTTPS (upload)", is_encrypted=True, is_authenticated=True, authentication=two-factor, authorization=required, data="Knowledge Documents"
- **Attacker Probing**: from="External Attacker", to="API Gateway", protocol="HTTPS (probe)", is_encrypted=True, is_authenticated=False, authentication=none, description="Unauthenticated scanning, credential stuffing and token-spend abuse"
- **Attacker Prompt Injection**: from="External Attacker", to="API Gateway", protocol="HTTPS (chat)", is_encrypted=True, is_authenticated=True, authentication=token, authorization=required, data="User Prompts", description="Jailbreak and injection attempts from a self-registered or stolen account"
- **Attacker Poisoned Upload**: from="External Attacker", to="API Gateway", protocol="HTTPS (upload)", is_encrypted=True, is_authenticated=True, authentication=token, authorization=required, data="Knowledge Documents", description="Document with hidden instructions submitted through a customer attachment path that is indexed"
- **Validate Access Token**: from="API Gateway", to="Identity Provider", protocol=HTTPS, is_encrypted=True, is_authenticated=True, authentication=token, readonly=True, data="Access Tokens"
- **Forward Chat Request**: from="API Gateway", to="RAG Orchestrator", protocol="HTTPS (mTLS)", is_encrypted=True, is_authenticated=True, authentication=client-certificate, authorization=required, data="User Prompts"
- **Stream Response to UI**: from="API Gateway", to="Chat Front End", protocol="HTTPS (SSE)", is_encrypted=True, is_authenticated=True, authentication=token, readonly=True, data="LLM Responses", description="Server-sent events carrying model output that the UI renders as markdown"
- **Route Document Upload**: from="API Gateway", to="Document Store", protocol=HTTPS, is_encrypted=True, is_authenticated=True, authentication=token, authorization=required, data="Knowledge Documents"
- **Screen Prompt and Output**: from="RAG Orchestrator", to="Guardrails Service", protocol="HTTPS (mTLS)", is_encrypted=True, is_authenticated=True, authentication=client-certificate, authorization=required, bidirectional=True, data="Augmented Prompts"
- **Retrieve Context**: from="RAG Orchestrator", to="Vector Database", protocol="gRPC (TLS)", is_encrypted=True, is_authenticated=True, authentication=token, authorization=required, readonly=True, data="Retrieved Context", description="Uses one service key and applies no user entitlement filter to the search"
- **Request Completion**: from="RAG Orchestrator", to="LLM Provider API", protocol=HTTPS, is_encrypted=True, is_authenticated=True, authentication=token, authorization=required, data="Augmented Prompts", description="System prompt, history, retrieved passages and tool results including customer data all leave the organisation on every turn"
- **Embed Query**: from="RAG Orchestrator", to="LLM Provider API", protocol="HTTPS (embeddings)", is_encrypted=True, is_authenticated=True, authentication=token, authorization=required, data="User Prompts"
- **Receive Completion and Tool Calls**: from="LLM Provider API", to="RAG Orchestrator", protocol=HTTPS, is_encrypted=True, is_authenticated=True, authentication=token, readonly=True, data="LLM Responses", description="Model output and requested tool calls, treated as untrusted"
- **Dispatch Tool Call**: from="RAG Orchestrator", to="Tool Gateway", protocol="HTTPS (mTLS)", is_encrypted=True, is_authenticated=True, authentication=client-certificate, authorization=required, data="Tool Call Requests"
- **Tool Customer Lookup**: from="Tool Gateway", to="Customer Records API", protocol=HTTPS, is_encrypted=True, is_authenticated=True, authentication=token, authorization=required, readonly=True, data="Customer Records", description="Read-only call carrying the end-user identity"
- **Tool Create Ticket**: from="Tool Gateway", to="Ticketing Service", protocol=HTTPS, is_encrypted=True, is_authenticated=True, authentication=token, authorization=none, readonly=False, data="Service Tokens", description="Write call using a single shared service token, so the ticketing service cannot tell which user or which model turn caused the action"
- **Load and Save History**: from="RAG Orchestrator", to="Conversation History", protocol="PostgreSQL (TLS)", is_encrypted=True, is_authenticated=True, authentication=credentials, authorization=required, data="Conversation History"
- **Fetch Secrets**: from="RAG Orchestrator", to="Secrets Manager", protocol=HTTPS, is_encrypted=True, is_authenticated=True, authentication=token, authorization=required, readonly=True, data="LLM Provider API Key"
- **Log Prompts and Responses**: from="RAG Orchestrator", to="Audit Log", protocol=HTTPS, is_encrypted=True, is_authenticated=True, authentication=token, data="Audit Logs"
- **Log Tool Calls**: from="Tool Gateway", to="Audit Log", protocol=HTTPS, is_encrypted=True, is_authenticated=True, authentication=token, data="Audit Logs"
- **Read Source Documents**: from="Ingestion Pipeline", to="Document Store", protocol=HTTPS, is_encrypted=True, is_authenticated=True, authentication=token, authorization=required, readonly=True, data="Knowledge Documents"
- **Embed Document Chunks**: from="Ingestion Pipeline", to="LLM Provider API", protocol=HTTPS, is_encrypted=True, is_authenticated=True, authentication=token, authorization=required, data="Knowledge Documents", description="Chunk text is sent to the third-party embedding endpoint"
- **Upsert Embeddings**: from="Ingestion Pipeline", to="Vector Database", protocol="gRPC (TLS)", is_encrypted=True, is_authenticated=True, authentication=token, authorization=required, data="Document Embeddings"

## Protocol Styles
<!-- The diagram keeps one arrow per source, destination and protocol. Flows between the same pair therefore use distinct protocol labels such as HTTPS (upload) or HTTPS (embeddings) so that each one stays visible. Threat generation is not affected. -->
- **HTTPS**: color=darkgreen, line_style=solid
- **HTTPS (chat)**: color=red, line_style=dashed
- **HTTPS (probe)**: color=red, line_style=dotted
- **HTTPS (upload)**: color=darkgreen, line_style=solid
- **HTTPS (embeddings)**: color=darkgreen, line_style=solid
- **HTTPS (SSE)**: color=darkgreen, line_style=solid
- **HTTPS (mTLS)**: color=teal, line_style=solid
- **gRPC (TLS)**: color=blue, line_style=solid
- **PostgreSQL (TLS)**: color=purple, line_style=solid

## Severity Multipliers
- **RAG Orchestrator**: 2.0
- **Tool Gateway**: 1.9
- **Secrets Manager**: 1.9
- **Vector Database**: 1.8
- **Customer Records API**: 1.8
- **Identity Provider**: 1.6
- **Ingestion Pipeline**: 1.8
- **LLM Provider API**: 1.5
- **Ticketing Service**: 1.5
- **API Gateway**: 1.5
- **Guardrails Service**: 1.4

## Custom Mitre Mapping
- **Indirect Prompt Injection via Retrieved Document**: {"tactics": ["Initial Access", "Execution"], "techniques": [{"id": "T1659", "name": "Content Injection"}, {"id": "T1059", "name": "Command and Scripting Interpreter"}]}
- **Model-Driven Tool Abuse (Excessive Agency)**: {"tactics": ["Execution", "Privilege Escalation"], "techniques": [{"id": "T1059", "name": "Command and Scripting Interpreter"}, {"id": "T1548", "name": "Abuse Elevation Control Mechanism"}]}
- **Knowledge Base Poisoning**: {"tactics": ["Impact"], "techniques": [{"id": "T1565.001", "name": "Stored Data Manipulation"}]}
- **Vector Database Data Extraction**: {"tactics": ["Collection", "Exfiltration"], "techniques": [{"id": "T1213", "name": "Data from Information Repositories"}, {"id": "T1530", "name": "Data from Cloud Storage"}]}
- **Sensitive Data Disclosure to LLM Provider**: {"tactics": ["Exfiltration"], "techniques": [{"id": "T1567", "name": "Exfiltration Over Web Service"}]}
- **Cross-User Data Leakage via Retrieval**: {"tactics": ["Collection"], "techniques": [{"id": "T1213", "name": "Data from Information Repositories"}]}
- **Model and Library Supply Chain Compromise**: {"tactics": ["Initial Access"], "techniques": [{"id": "T1195.001", "name": "Compromise Software Dependencies and Development Tools"}]}
- **LLM API Key Theft**: {"tactics": ["Credential Access"], "techniques": [{"id": "T1552", "name": "Unsecured Credentials"}, {"id": "T1528", "name": "Steal Application Access Token"}]}
- **Insecure Output Handling in Chat UI**: {"tactics": ["Execution"], "techniques": [{"id": "T1059.007", "name": "JavaScript"}]}
- **Denial of Wallet**: {"tactics": ["Impact"], "techniques": [{"id": "T1499", "name": "Endpoint Denial of Service"}, {"id": "T1496", "name": "Resource Hijacking"}]}
