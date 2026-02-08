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

import yaml
import configparser
from pathlib import Path
from typing import Dict, Any, List
import logging
import subprocess
from threat_analysis.utils import _validate_path_within_project

from threat_analysis.iac_plugins import IaCPlugin

class AnsiblePlugin(IaCPlugin):
    """
    IaC Plugin for Ansible configurations that understands inventories.
    """

    @property
    def name(self) -> str:
        return "ansible"

    @property
    def description(self) -> str:
        return "Integrates with Ansible playbooks and inventories to generate threat model components."

    def _parse_inventory(self, inventory_path: Path) -> Dict[str, Any]:
        """Parses an Ansible inventory file (.ini format) manually to extract host variables."""
        if not inventory_path.exists():
            raise FileNotFoundError(f"Inventory file not found: {inventory_path}")

        inventory_data = {"groups": {}, "hosts": {}}
        current_group = None

        with open(inventory_path, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue

                if line.startswith('['):
                    if line.endswith(':children]'):
                        group_name = line[1:-9]
                        inventory_data["groups"].setdefault(group_name, [])
                        # Children are handled implicitly by adding hosts to their groups
                    else:
                        current_group = line[1:-1]
                        inventory_data["groups"].setdefault(current_group, [])
                else:
                    if current_group:
                        parts = line.split()
                        host_name = parts[0]
                        inventory_data["groups"][current_group].append(host_name)
                        
                        host_vars = {"group": current_group}
                        for part in parts[1:]:
                            if '=' in part:
                                key, value = part.split('=', 1)
                                host_vars[key] = value
                        inventory_data["hosts"][host_name] = host_vars
        
        return inventory_data
        
        return inventory_data

    def parse_iac_config(self, config_path: str) -> Dict[str, Any]:
        """
        Parses an Ansible playbook and its corresponding inventory.
        Assumes inventory is named 'hosts.ini' and located in the same directory.
        """
        # Validate config_path
        validated_config_path = _validate_path_within_project(config_path)
        playbook_path = validated_config_path
        inventory_path = playbook_path.parent / 'hosts.ini'

        if not playbook_path.is_file() or playbook_path.suffix not in ['.yml', '.yaml']:
            raise ValueError(f"Unsupported Ansible config path: {playbook_path}. Must be a .yml or .yaml file.")

        inventory = self._parse_inventory(inventory_path)
        
        with open(playbook_path, 'r') as f:
            playbook_content = yaml.safe_load(f)

        threat_model_metadata = {}
        if isinstance(playbook_content, list):
            for play in playbook_content:
                if isinstance(play, dict) and "vars" in play and "threat_model_metadata" in play["vars"]:
                    threat_model_metadata = play["vars"]["threat_model_metadata"]
                    break

        return {
            "inventory": inventory,
            "playbook": playbook_content,
            "threat_model_metadata": threat_model_metadata
        }

    def generate_threat_model_components(self, iac_data: Dict[str, Any]) -> str:
        """Generates Markdown threat model components from parsed Ansible data."""
        metadata = iac_data.get("threat_model_metadata", {})
        markdown = []

        if "boundaries" in metadata:
            markdown.append("## Boundaries")
            for boundary in metadata["boundaries"]:
                props = ", ".join([f"{k}={v}" for k, v in boundary.items() if k not in ["name", "sub_boundaries"]])
                markdown.append(f"- **{boundary['name']}**: {props}")
                if "sub_boundaries" in boundary:
                    for sub_boundary in boundary["sub_boundaries"]:
                        sub_props = ", ".join([f"{k}={v}" for k, v in sub_boundary.items() if k != "name"])
                        markdown.append(f"  - **{sub_boundary['name']}**: {sub_props}")
            markdown.append("")

        if "actors" in metadata:
            markdown.append("## Actors")
            for actor in metadata["actors"]:
                props = ", ".join([f"{k}={v}" for k, v in actor.items() if k != "name"])
                markdown.append(f"- **{actor['name']}**: {props}")
            markdown.append("")

        if "servers" in metadata:
            markdown.append("## Servers")
            for server in metadata["servers"]:
                props_list = [f"{k}={v}" for k, v in server.items() if k != "name"]
                if "ansible_host" in server:
                    props_list.append(f"ip={server['ansible_host']}")
                if "type" in server:
                    props_list.append(f"type={server['type']}")
                props = ", ".join(props_list)
                markdown.append(f"- **{server['name']}**: {props}")
            markdown.append("")

        if "data" in metadata:
            markdown.append("## Data")
            for data_item in metadata["data"]:
                props = ", ".join([f"{k}={v}" for k, v in data_item.items() if k != "name"])
                markdown.append(f"- **{data_item['name']}**: {props}")
            markdown.append("")

        if "data_flows" in metadata:
            markdown.append("## Dataflows")
            for flow in metadata["data_flows"]:
                source_name = flow["source"].replace("actor:", "").replace("server:", "")
                destination_name = flow["destination"].replace("actor:", "").replace("server:", "")

                props_list = [
                    f'from="{source_name}"',
                    f'to="{destination_name}"',
                    f'protocol="{flow["protocol"]}"',
                    f'data="{flow["data"]}"'
                ]
                if "description" in flow:
                    props_list.append(f'description="{flow["description"]}"')
                
                props = ", ".join(props_list)
                markdown.append(f"- **{flow['name']}**: {props}")
            markdown.append("")

        return "\n".join(markdown)