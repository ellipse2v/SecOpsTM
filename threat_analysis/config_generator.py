#!/usr/bin/env python3
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
Configuration generator module for Threat Model Web UI.
This module generates config.js with all necessary configuration for the web interface.
"""

import json
import datetime
from pathlib import Path
from typing import Dict, Any


# Centralized configuration data - single source of truth
CONFIG_DATA = {
    "ICON_MAPPING": {
        "actor": "/static/resources/icons/actor.svg",
        "web_server": "/static/resources/icons/web-server.svg",
        "database": "/static/resources/icons/database.svg",
        "firewall": "/static/resources/icons/firewall.svg",
        "data": "/static/resources/icons/data.svg",
        "router": "/static/resources/icons/routers.svg",
        "switch": "/static/resources/icons/switch.svg",
        "server": "/static/resources/icons/server.svg",
        "api_gateway": "/static/resources/icons/api-gateway.svg",
        "app_server": "/static/resources/icons/server.svg",
        "central_server": "/static/resources/icons/server.svg",
        "authentication_server": "/static/resources/icons/server.svg",
        "load_balancer": "/static/resources/icons/load_balancer.svg",
        "dmz": "/static/resources/icons/dmz.svg"
    },
    "DEFAULT_PROPERTIES": {
        "BOUNDARY": {
            "name": "New Boundary",
            "description": "",
            "isTrusted": True,
            "lineStyle": "solid",
            "isFilled": True,
            "color": "#f8f9fa"
        },
        "ACTOR": {
            "name": "New Actor",
            "description": "",
            "color": "#E9D5FF"
        },
        "DATA": {
            "name": "New Data",
            "description": "",
            "classification": "public",
            "format": "",
            "credentialsLife": "",
            "confidentiality": "medium",
            "integrity": "medium",
            "availability": "medium",
            "color": "#FFE0B2"
        },
        "SERVER": {
            "name": "New Server",
            "description": "",
            "os": "",
            "color": "#D1FAE5"
        },
        "WEB_SERVER": {
            "name": "Web Server",
            "description": "",
            "os": "",
            "color": "#D1FAE5"
        },
        "DATABASE": {
            "name": "Database",
            "description": "",
            "os": "",
            "color": "#D1FAE5"
        },
        "FIREWALL": {
            "name": "Firewall",
            "description": "",
            "os": "",
            "color": "#FFCDD2"
        },
        "ROUTER": {
            "name": "Router",
            "description": "",
            "os": "",
            "color": "#FFD700"
        },
        "SWITCH": {
            "name": "Switch",
            "description": "",
            "os": "",
            "color": "orange"
        }
    },
    "ELEMENT_DIMENSIONS": {
        "BOUNDARY": {"width": 200, "height": 150},
        "ACTOR": {"width": 80, "height": 80},
        "DATA": {"width": 100, "height": 70},
        "SERVER": {"width": 120, "height": 80},
        "WEB_SERVER": {"width": 120, "height": 80},
        "DATABASE": {"width": 120, "height": 100},
        "FIREWALL": {"width": 120, "height": 100},
        "ROUTER": {"width": 120, "height": 100},
        "SWITCH": {"width": 120, "height": 100}
    },
    "COLOR_SCHEMES": {
        "BOUNDARY": {"fill": "#f8f9fa", "stroke": "#adb5bd", "text": "#495057"},
        "ACTOR": {"fill": "#E9D5FF", "stroke": "#9333EA", "text": "#581C87"},
        "DATA": {"fill": "#FFE0B2", "stroke": "#E65100", "text": "#BF360C"},
        "DEFAULT": {"fill": "#D1FAE5", "stroke": "#065F46", "text": "#064E3B"},
        "FIREWALL": {"fill": "#FFCDD2", "stroke": "#B71C1C", "text": "#B71C1C"},
        "ROUTER": {"fill": "#FFD700", "stroke": "#B8860B", "text": "#8B4513"},
        "SWITCH": {"fill": "orange", "stroke": "#B8860B", "text": "#8B4513"}
    }
}


def generate_config_js(output_path: Path = None) -> bool:
    """
    Generate config.js file with web UI configuration.
    
    Args:
        output_path: Optional path to output file. If None, uses default location.
        
    Returns:
        True if generation succeeded, False otherwise.
    """
    try:
        # Determine output path if not provided
        if output_path is None:
            current_file = Path(__file__)
            output_path = current_file.parent / "server" / "static" / "js" / "config.js"
        
        # Check if file exists and is up to date
        if output_path.exists():
            # Read existing file to check if regeneration is needed
            with open(output_path, 'r') as f:
                existing_content = f.read()
                existing_config = json.loads(existing_content.split('ThreatModelConfig = ')[1].split(';')[0])
                
            # Compare with current configuration
            if existing_config == CONFIG_DATA:
                print(f"Configuration is already up to date: {output_path}")
                return True
        
        # Generate JavaScript code
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        js_code = f"// Threat Model Configuration - Web UI\n"
        js_code += f"// Generated on: {timestamp}\n"
        js_code += f"// This file contains configuration for the threat model web interface\n\n"
        js_code += f"const ThreatModelConfig = {json.dumps(CONFIG_DATA, indent=4)};\n\n"
        js_code += "// Export for use in other modules\n"
        js_code += "if (typeof module !== 'undefined' && module.exports) {\n"
        js_code += "    module.exports = ThreatModelConfig;\n"
        js_code += "}\n"
        
        # Write to file
        output_path.write_text(js_code)
        print(f"Successfully generated configuration: {output_path}")
        return True
        
    except Exception as e:
        print(f"Error generating configuration: {e}")
        return False


def main():
    """Main function for command-line use"""
    success = generate_config_js()
    return 0 if success else 1


if __name__ == "__main__":
    import sys
    sys.exit(main())
