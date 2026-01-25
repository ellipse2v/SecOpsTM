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

## Using the Graphical Editor (Under Development)

A web-based graphical editor is included for interactive threat modeling. This feature is currently under active development and may not be fully stable. You can launch it using:

```bash
python3 -m threat_analysis --server
```

Open your browser to `http://127.0.0.1:5000/`.

