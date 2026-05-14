# SecOpsTM — STRIDE Threat Modeling Framework

Automated STRIDE threat analysis with MITRE ATT&CK mapping, AI enrichment (LLM + RAG), and an interactive web editor.

An [OWASP project](https://owasp.org/www-project-secopstm/) · Apache 2.0
· [GitHub](https://github.com/ellipse2v/SecOpsTM)
· [Full documentation](https://github.com/ellipse2v/SecOpsTM/tree/main/docs)

---

## Images

| Tag | Size | Use case |
|---|---|---|
| `ellipse2v/secopstm:core` | ~500 MB | Offline STRIDE analysis — no AI, no API key |
| `ellipse2v/secopstm:ai` | ~2 GB | Full AI enrichment: LLM inference + RAG pipeline |

---

## Quick start

### Core — offline, no API key

```bash
docker run -p 5000:5000 \
  -v $(pwd)/output:/app/output \
  ellipse2v/secopstm:core
```

Open **http://localhost:5000**, paste your threat model and click **Generate**.
Reports land in `$(pwd)/output/<timestamp>/`.

### AI — LLM + RAG

**Step 1 — Download the RAG vector store** (one-time, ~200 MB, stored in a named volume):

```bash
docker run --rm \
  -v secopstm-rag:/app/rag \
  ellipse2v/secopstm:ai --init-rag
```

**Step 2 — Run the server:**

```bash
docker run -p 5000:5000 \
  -e GEMINI_API_KEY=your_key \
  -v secopstm-rag:/app/rag \
  -v $(pwd)/output:/app/output \
  ellipse2v/secopstm:ai
```

The named volume `secopstm-rag` persists across restarts and image upgrades.

---

## API key environment variables

| Provider | Environment variable |
|---|---|
| Google Gemini | `GEMINI_API_KEY` |
| OpenAI | `OPENAI_API_KEY` |
| Mistral | `MISTRAL_API_KEY` |
| NVIDIA NIM | `NVIDIA_API_KEY` |
| Ollama (local, fully offline) | — no key needed — |

---

## Volumes and mounts

| What | Docker flag | Notes |
|---|---|---|
| Output reports | `-v $(pwd)/output:/app/output` | Files land in `output/<timestamp>/` on the host |
| Threat model files | `-v $(pwd)/models:/models` | Then pass `--model-file /models/model.md` |
| AI config | `-v $(pwd)/ai_config.yaml:/app/config/ai_config.yaml:ro` | Change provider or model without rebuilding |
| LLM prompts | `-v $(pwd)/prompts.yaml:/app/config/prompts.yaml:ro` | Override system prompts |
| CVE definitions | `-v $(pwd)/cve_definitions.yml:/app/cve_definitions.yml:ro` | Per-asset CVE list |
| RAG vector store | `-v secopstm-rag:/app/rag` | Named volume — `ai` tag only |

### Full example with all mounts

```bash
docker run -p 5000:5000 \
  -e GEMINI_API_KEY=your_key \
  -v $(pwd)/ai_config.yaml:/app/config/ai_config.yaml:ro \
  -v secopstm-rag:/app/rag \
  -v $(pwd)/models:/models \
  -v $(pwd)/output:/app/output \
  ellipse2v/secopstm:ai
```

---

## Changing the port

Flask always listens on port 5000 inside the container. Use `-p host:5000` to expose it on a different host port:

```bash
docker run -p 8080:5000 ... # accessible on http://localhost:8080
```

---

## CLI / headless mode (no server)

Analyze a model file and get JSON output without starting the web server:

```bash
docker run --rm \
  -v $(pwd)/models:/models \
  -v $(pwd)/output:/app/output \
  ellipse2v/secopstm:core \
  --model-file /models/threat_model.md --output-format json --stdout
```

Pipe directly to `jq` for CI integration:

```bash
docker run --rm \
  -v $(pwd)/models:/models \
  ellipse2v/secopstm:core \
  --model-file /models/threat_model.md --stdout | jq '.threats | length'
```

---

## Output files

| File | Format |
|---|---|
| `report.html` | Interactive HTML threat report with severity filters |
| `report.json` | Versioned JSON (schema v1.0) |
| `diagram.svg` | Architecture diagram with trust boundary colors |
| `diagram.html` | Interactive diagram with severity heat map |
| `attack_navigator.json` | MITRE ATT&CK Navigator layer |
| `stix_report.json` | STIX 2.1 bundle |

---

## More

- [Getting started](https://github.com/ellipse2v/SecOpsTM/blob/main/docs/getting_started.md)
- [Full usage guide](https://github.com/ellipse2v/SecOpsTM/blob/main/docs/usage.md)
- [Threat model templates](https://github.com/ellipse2v/SecOpsTM/tree/main/threatModel_Template)
- [Configuring AI providers](https://github.com/ellipse2v/SecOpsTM/blob/main/docs/usage.md#configuring-ai-providers)
- [GitHub Issues](https://github.com/ellipse2v/SecOpsTM/issues)
