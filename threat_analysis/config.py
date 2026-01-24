# Copyright 2025 ellipse2v
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Centralized configuration for the Threat Analysis Framework.
"""
from pathlib import Path
from datetime import datetime

# --- Logging ---
LOG_LEVEL = "INFO"
# --- Model Defaults ---
DEFAULT_MODEL_FILEPATH = Path("threatModel_Template/threat_model.md")
BASE_PROTOCOL_STYLES_FILEPATH = Path("threatModel_Template/base_protocol_styles.md")
DEFAULT_MODEL_NAME = "Enhanced DMZ Security Analysis"
DEFAULT_MODEL_DESCRIPTION = "Advanced DMZ architecture with 8 external flows and command zone"

# --- Output Path Management ---
TIMESTAMP = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
OUTPUT_BASE_DIR = Path("output") / TIMESTAMP
TMP_DIR = Path("output") / "tmp"

# --- Filename Templates ---
# Note: These are templates; the timestamp will be added in the main script.
HTML_REPORT_FILENAME_TPL = "stride_mitre_report_{timestamp}.html"
JSON_REPORT_FILENAME_TPL = "mitre_analysis_{timestamp}.json"
DOT_DIAGRAM_FILENAME_TPL = "tm_diagram_{timestamp}.dot"
SVG_DIAGRAM_FILENAME_TPL = "tm_diagram_{timestamp}.svg"
HTML_DIAGRAM_FILENAME_TPL = "tm_diagram_{timestamp}.html"
JSON_NAVIGATOR_FILENAME_TPL = "attack_navigator_layer_{timestamp}.json"