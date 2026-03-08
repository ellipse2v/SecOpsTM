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
Attack Flow prompt helpers — all prompt text lives in config/prompts.yaml.
"""

from typing import Dict
from threat_analysis.ai_engine.prompt_loader import get as _get


def __getattr__(name: str) -> str:
    if name == "ATTACK_FLOW_SYSTEM_PROMPT":
        return _get("attack_flow", "system")
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def build_attack_flow_prompt(threat: Dict, component: Dict, context: Dict) -> str:
    """Builds a STIX 2.1 Attack Flow generation prompt.

    Reads the template from ``config/prompts.yaml``
    (``attack_flow.component_template``) and injects threat + component data.
    """
    mitre_techniques = threat.get("mitre_techniques", [])
    threat_category = threat.get("category", "Unknown")

    return _get(
        "attack_flow",
        "component_template",
        threat_category=threat_category,
        threat_category_lower=threat_category.lower().replace(" ", "-"),
        threat_title=threat.get("title", "Unknown Threat"),
        threat_description=threat.get("description", ""),
        attack_scenario=threat.get("attack_scenario", ""),
        mitre_techniques=", ".join(mitre_techniques) if mitre_techniques else "None identified",
        component_type=component.get("type", "Unknown"),
        component_name=component.get("name", "Unknown"),
        component_description=component.get("description", ""),
        system_context=context.get("system_description", "No additional context provided"),
    )
