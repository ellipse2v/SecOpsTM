# Getting Started

## Installation options

### Option A — Docker (recommended, no setup required)

Graphviz and all runtime dependencies are pre-installed.

```bash
# Core image — Flask server + offline threat modeling
docker pull ghcr.io/ellipse2v/secopstm:latest
docker run -p 5000:5000 -v $(pwd)/output:/app/output ghcr.io/ellipse2v/secopstm:latest

# AI-enabled image — adds LiteLLM + ChromaDB + local embeddings
docker pull ghcr.io/ellipse2v/secopstm:ai
docker run -p 5000:5000 \
  -e GEMINI_API_KEY=your_key \
  -v /path/to/vector_store:/app/threat_analysis/vector_store \
  -v $(pwd)/output:/app/output \
  ghcr.io/ellipse2v/secopstm:ai
```

Open `http://localhost:5000` in your browser.

### Option B — pip install

```bash
pip install SecOpsTM

# Download the offline security knowledge base (~140 MB, required for full analysis)
secopstm download-data

# Install Graphviz separately
#   Windows: https://graphviz.org/download/
#   macOS:   brew install graphviz
#   Linux:   sudo apt-get install graphviz
```

**Quick test:**
```bash
secopstm --server
```

### Option C — From source (development)

```bash
git clone https://github.com/ellipse2v/SecOpsTM.git
cd SecOpsTM
pip install -e .
# external_data/ is already present in the repo — no download step needed
```

**Quick CLI test after installation:**
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
