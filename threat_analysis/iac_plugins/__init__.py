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

from abc import ABC, abstractmethod
from typing import Dict, Any, List

class IaCPlugin(ABC):
    """Abstract base class for Infrastructure as Code (IaC) plugins.

    Each plugin must implement methods to parse IaC configurations
    and generate threat model components.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Returns the name of the IaC tool this plugin supports (e.g., 'ansible', 'terraform')."""
        pass

    @property
    @abstractmethod
    def description(self) -> str:
        """Returns a brief description of the plugin's functionality."""
        pass

    @abstractmethod
    def parse_iac_config(self, config_path: str) -> Dict[str, Any]:
        """Parses the IaC configuration and extracts relevant data.

        Args:
            config_path: The path to the root of the IaC configuration (e.g., Ansible playbook directory).

        Returns:
            A dictionary containing parsed IaC data, structured for threat model generation.
        """
        pass

    @abstractmethod
    def generate_threat_model_components(self, iac_data: Dict[str, Any]) -> str:
        """Generates Markdown-formatted threat model components from parsed IaC data.

        Args:
            iac_data: The data extracted by parse_iac_config.

        Returns:
            A string containing Markdown content for threat model elements (e.g., Servers, Dataflows).
        """
        pass

    def generate_bom_files(self, iac_data: Dict[str, Any], output_dir: str) -> List[str]:
        """Generate one BOM YAML file per discovered asset under ``{output_dir}/BOM/``.

        Optional — the default implementation is a no-op.  Plugins that support
        BOM generation override this method.

        Args:
            iac_data: The dict returned by :meth:`parse_iac_config`.
            output_dir: Directory under which a ``BOM/`` sub-directory is created.

        Returns:
            List of absolute paths to the generated BOM files (empty if none).
        """
        return []
