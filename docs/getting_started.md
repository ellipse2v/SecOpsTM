# Getting Started

## Quick Start / Installation

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/ellipse2v/SecOpsTM.git
    cd SecOpsTM
    ```

2.  **Install Python dependencies:**
    ```bash
    pip install -e .
    ```
    This installs all project dependencies in editable mode and makes the `secopstm` CLI command available in your environment.
    For a standard installation (e.g., for deployment), use `pip install .`

    **Quick CLI test after installation:**
    ```bash
    secopstm --model-file threatModel_Template/threat_model.md
    ```

3.  **Install Graphviz (for diagram generation):**
    -   Windows: [https://graphviz.org/download/](https://graphviz.org/download/)
    -   macOS: `brew install graphviz`
    -   Linux: `sudo apt-get install graphviz`

After installation, restart your terminal or IDE.

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
