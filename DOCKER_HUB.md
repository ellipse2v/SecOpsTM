# SecOpsTM — STRIDE Threat Modeling Framework

Automated STRIDE threat analysis with MITRE ATT&CK mapping, AI enrichment (LLM + RAG), and an interactive web editor.

An [OWASP project](https://owasp.org/www-project-secopstm/) · Apache 2.0
· [GitHub](https://github.com/ellipse2v/SecOpsTM)
· [Full documentation](https://github.com/ellipse2v/SecOpsTM/tree/main/docs)

---

## Quick start — offline, no API key

```bash
docker run -p 127.0.0.1:5000:5000 \
  -v $(pwd)/output:/app/output \
  ellipse2v/secopstm:latest
```

Open **http://localhost:5000**, paste your system model and click **Generate**.
Reports land in `$(pwd)/output/<timestamp>/`.

> **Security note:** there is no authentication on any route (single-user
> tool by design). `-p 127.0.0.1:5000:5000` binds to localhost only. Only
> use `-p 5000:5000` (all interfaces) on a network you fully trust.

---

## Quick start — with AI enrichment (LLM + RAG)

> **Default provider: NVIDIA NIM** (Llama 3.3 70B). Free API key at
> https://build.nvidia.com/meta/llama-3_3-70b-instruct — no credit card required.

**Step 1 — Download the RAG vector store** (one-time, ~200 MB):

```bash
docker run --rm \
  -v secopstm-rag:/app/rag \
  ellipse2v/secopstm:latest --init-rag
```

**Step 2 — Run the server:**

```bash
docker run -p 127.0.0.1:5000:5000 \
  -e NVIDIA_API_KEY=your_key \
  -v secopstm-rag:/app/rag \
  -v $(pwd)/output:/app/output \
  ellipse2v/secopstm:latest
```

The named volume `secopstm-rag` persists across restarts and image upgrades.

---

## API key environment variables

| Provider | Environment variable | Free tier |
|---|---|---|
| NVIDIA NIM *(default)* | `NVIDIA_API_KEY` | ✅ [build.nvidia.com](https://build.nvidia.com/meta/llama-3_3-70b-instruct) |
| Google Gemini | `GEMINI_API_KEY` | ✅ |
| OpenAI | `OPENAI_API_KEY` | ❌ |
| Mistral | `MISTRAL_API_KEY` | ✅ |
| Ollama (local, fully offline) | — no key needed — | ✅ |

---

## Volumes and mounts

| What | Docker flag | Notes |
|---|---|---|
| Output reports | `-v $(pwd)/output:/app/output` | Files land in `output/<timestamp>/` on the host |
| System model files | `-v $(pwd)/models:/models` | Then pass `--model-file /models/model.md` |
| AI config | `-v $(pwd)/ai_config.yaml:/app/config/ai_config.yaml:ro` | Change provider or model without rebuilding |
| LLM prompts | `-v $(pwd)/prompts.yaml:/app/config/prompts.yaml:ro` | Override system prompts |
| CVE definitions | `-v $(pwd)/cve_definitions.yml:/app/cve_definitions.yml:ro` | Per-asset CVE list |
| RAG vector store | `-v secopstm-rag:/app/rag` | Named volume, required for RAG |

### Full example with all mounts

```bash
docker run -p 127.0.0.1:5000:5000 \
  -e NVIDIA_API_KEY=your_key \
  -v $(pwd)/ai_config.yaml:/app/config/ai_config.yaml:ro \
  -v secopstm-rag:/app/rag \
  -v $(pwd)/models:/models \
  -v $(pwd)/output:/app/output \
  ellipse2v/secopstm:latest
```

---

## Changing the port

```bash
docker run -p 127.0.0.1:8080:5000 ...   # accessible on http://localhost:8080
```

---

## CLI / headless mode (no server)

```bash
docker run --rm \
  -v $(pwd)/models:/models \
  -v $(pwd)/output:/app/output \
  ellipse2v/secopstm:latest \
  --model-file /models/threat_model.md --output-format json --stdout | jq '.threats | length'
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
- [GitHub Issues](https://github.com/ellipse2v/SecOpsTM/issues)
