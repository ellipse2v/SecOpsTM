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
STRIDE prompt helpers — all prompt text lives in config/prompts.yaml.

This module exposes module-level constants (for backward compatibility) and
the ``build_component_prompt()`` factory used by LiteLLMProvider.
"""

from typing import Dict, Optional
from threat_analysis.ai_engine.prompt_loader import get as _get


# ---------------------------------------------------------------------------
# Module-level constants (lazy-loaded from prompts.yaml on first access)
# ---------------------------------------------------------------------------

def _stride_system() -> str:
    return _get("stride_analysis", "system")


def _dsl_system() -> str:
    return _get("dsl_generation", "system")


# Backward-compatible module attributes evaluated on import
# (wrapped in a lazy property pattern via module __getattr__)
_STRIDE_SYSTEM_PROMPT: Optional[str] = None
_DSL_GENERATION_SYSTEM_PROMPT: Optional[str] = None


def __getattr__(name: str) -> str:
    if name == "STRIDE_SYSTEM_PROMPT":
        return _stride_system()
    if name == "DSL_GENERATION_SYSTEM_PROMPT":
        return _dsl_system()
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


# ---------------------------------------------------------------------------
# Prompt builder
# ---------------------------------------------------------------------------

def build_component_prompt(component: Dict, context: Dict) -> str:
    """Builds a context-rich STRIDE analysis prompt for a single component.

    Reads the template from ``config/prompts.yaml`` (``stride_analysis.component_template``)
    and injects component + system context via ``<<varname>>`` substitution.
    """
    compliance = context.get("compliance_requirements", [])
    integrations = context.get("integrations", [])

    return _get(
        "stride_analysis",
        "component_template",
        comp_type=component.get("type", "Unknown"),
        comp_name=component.get("name", "Unnamed"),
        description=component.get("description", "No description provided"),
        trust_boundary=component.get("trust_boundary", "Unknown"),
        authentication=component.get("authentication", "Unknown"),
        protocol=component.get("protocol", "Unknown"),
        internet_facing=(
            "Yes (directly internet-facing)"
            if component.get("is_public")
            else (
                "No (system has internet-facing components but this one is internal)"
                if context.get("internet_facing")
                else "No"
            )
        ),
        deployment=context.get("deployment_environment", "Unknown"),
        system_desc=context.get("system_description", ""),
        data_sensitivity=context.get("data_sensitivity", "Medium"),
        compliance=", ".join(compliance) if compliance else "None specified",
        user_base=context.get("user_base", "Unknown"),
        integrations=", ".join(integrations) if integrations else "None",
    )
