# Getting Started

## Data layers

SecOpsTM relies on three data layers fetched separately:

| Layer | Content | Size | Command |
|---|---|---|---|
| **Security knowledge base** | MITRE ATT&CK, CAPEC, D3FEND, CIS, NIST, CVE mappings | ~140 MB | `secopstm download-data` |
| **RAG vector store** | Pre-built embeddings for AI threat generation | ~1.8 GB | `secopstm --init-rag` |
| **Fresh CVE data** | Up-to-date CVE→CAPEC database (dev/contributors only) | ~94 MB | clone [Galeax/CVE2CAPEC](https://github.com/Galeax/CVE2CAPEC) |

The **security knowledge base** is required for full STRIDE + MITRE analysis.
The **RAG vector store** is optional and enables AI-powered threat enrichment.
The CVE data bundled in the knowledge base covers 1999–2025 — clone CVE2CAPEC only if you need the absolute latest entries.

---

## Installation options

### Option A — Docker (recommended)

The Docker image already includes the security knowledge base. LLM inference works out of the box with the `latest` tag — just pass your API key. The RAG vector store is the only extra download (optional, ~1.8 GB).

```bash
# Offline threat modeling — no AI key needed
docker pull ghcr.io/ellipse2v/secopstm:latest
docker run -p 5000:5000 -v $(pwd)/output:/app/output \
  ghcr.io/ellipse2v/secopstm:latest

# LLM-enabled — pass any supported API key (NVIDIA NIM, Gemini, OpenAI, Mistral)
# The image already includes litellm — no extra install needed.
docker run -p 5000:5000 \
  -e NVIDIA_NIM_API_KEY=nvapi-... \
  -v $(pwd)/output:/app/output \
  ghcr.io/ellipse2v/secopstm:latest

# To switch provider or model without rebuilding, mount your own ai_config.yaml:
docker run -p 5000:5000 \
  -e GEMINI_API_KEY=your_key \
  -v $(pwd)/config/ai_config.yaml:/app/config/ai_config.yaml \
  -v $(pwd)/output:/app/output \
  ghcr.io/ellipse2v/secopstm:latest

# AI + RAG image — adds pre-built vector store for deeper threat enrichment
docker pull ghcr.io/ellipse2v/secopstm:ai

# One-time: download the RAG vector store into a named volume (~1.8 GB)
docker run --rm \
  -v secopstm-rag:/app/rag \
  ghcr.io/ellipse2v/secopstm:ai \
  --init-rag

# Start the server with LLM + RAG
docker run -p 5000:5000 \
  -e NVIDIA_NIM_API_KEY=nvapi-... \
  -v secopstm-rag:/app/rag \
  -v $(pwd)/output:/app/output \
  ghcr.io/ellipse2v/secopstm:ai
```

| Tag | LLM inference | RAG vector store |
|---|---|---|
| `latest` | ✅ pass any API key via `-e` | ❌ not included |
| `ai` | ✅ | ✅ mount `secopstm-rag:/app/rag` |

Open `http://localhost:5000` in your browser.

### Option B — pip install

```bash
pip install SecOpsTM

# Install Graphviz (required for diagram generation)
#   Windows: https://graphviz.org/download/
#   macOS:   brew install graphviz
#   Linux:   sudo apt-get install graphviz

# Step 1 — Security knowledge base (~140 MB, required for MITRE/CVE mapping)
secopstm download-data

# Step 2 — RAG vector store (~1.8 GB, optional — enables AI threat enrichment)
secopstm --init-rag

# Step 3 — Start
secopstm --server
```

Both `download-data` and `--init-rag` are one-time steps that download from
[GitHub Releases](https://github.com/ellipse2v/SecOpsTM/releases) and work
fully offline afterwards. Re-run with `--force` to update.

### Option C — From source (development)

```bash
git clone https://github.com/ellipse2v/SecOpsTM.git
cd SecOpsTM
pip install -e .
# external_data/ is already in the repo — no download-data step needed
```

To get the **latest CVE entries** (beyond the 1999–2025 snapshot in the repo):

```bash
# Clone the CVE2CAPEC database next to the SecOpsTM directory
git clone https://github.com/Galeax/CVE2CAPEC.git ../CVE2CAPEC
python tooling/copy_cve_data.py
```

**Quick CLI test:**
```bash
secopstm --model-file threatModel_Template/threat_model.md
```

## Using the Web Interface (Server Mode)

The framework includes a web-based interface for interactive threat modeling, accessible from a central menu.

1.  **Launch the server:**
    ```bash
    secopstm --server
    # or equivalently:
    python3 -m threat_analysis --server
    ```

2.  **Open your browser** to the address shown in the console (usually `http://127.0.0.1:5000/`).

3.  **Choose a mode:**
    -   **Simple Mode**: Ideal for quick visualization and editing of threat models written in Markdown. It features a live preview and now supports multi-file projects through a tabbed interface, allowing you to edit a main model and its sub-models together.
    -   **Graphical Editor**: A visual, drag-and-drop canvas for building threat models from scratch without writing Markdown. This mode is under active development.
