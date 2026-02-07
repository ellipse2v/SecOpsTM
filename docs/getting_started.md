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
    This command installs all project dependencies and sets up the project in "editable" mode, which is recommended for development.
    For a standard installation (e.g., for deployment), you can use:
    ```bash
    pip install .
    ```
    **Note on Installation Modes:**
    - `pip install -e .`: Installs the project in "editable" mode. This is recommended for development as any changes you make to the source code in your project directory are immediately reflected without needing to reinstall.
    - `pip install .`: Performs a standard installation, copying the project files into your Python environment. Use this for deployment or when using the package as a dependency.

3.  **Install Graphviz (for diagram generation):**
    -   Windows: [https://graphviz.org/download/](https://graphviz.org/download/)
    -   macOS: `brew install graphviz`
    -   Linux: `sudo apt-get install graphviz`

After installation, restart your terminal or IDE.

## Using the Web Interface (Server Mode)

The framework includes a web-based interface for interactive threat modeling, accessible from a central menu.

1.  **Launch the server:**
    ```bash
    python3 -m threat_analysis --server
    ```

2.  **Open your browser** to the address shown in the console (usually `http://127.0.0.1:5000/`).

3.  **Choose a mode:**
    -   **Simple Mode**: Ideal for quick visualization and editing of threat models written in Markdown. It features a live preview and now supports multi-file projects through a tabbed interface, allowing you to edit a main model and its sub-models together.
    -   **Graphical Editor**: A visual, drag-and-drop canvas for building threat models from scratch without writing Markdown. This mode is under active development.
