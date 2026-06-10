#!/usr/bin/env python3
"""Standalone wrapper for the SecOpsTM threat model validator.

When the threat_analysis package is installed (pip install -e .), delegates
to the package's validate module. Without the package, prints an installation
hint and exits 1.

Preferred usage after package install:
    secopstm validate --model-dir .
"""

import sys

try:
    from threat_analysis.validate import main
    sys.exit(main(sys.argv[1:]))
except ImportError:
    print(
        "Error: threat_analysis package not found.\n"
        "Install it with: pip install -e /path/to/SecOpsTM\n"
        "\nThen run: secopstm validate --model-dir ."
    )
    sys.exit(1)
