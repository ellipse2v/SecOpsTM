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

from typing import Dict, List, Optional
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

    sector = context.get("sector", "")
    threat_actors = context.get("threat_actor_profiles", "")
    business_goals = context.get("business_goals_to_protect", "")

    # Build the adversarial context section only when model-specific data is present
    adv_lines: list = []
    if sector:
        adv_lines.append(f"**Sector:** {sector}")
    if threat_actors:
        adv_lines.append(f"**Known Threat Actors:**\n{threat_actors}")
    if business_goals:
        adv_lines.append(f"**Business Goals to Protect:**\n{business_goals}")
    adversarial_context_section = (
        "## Adversarial Context\n" + "\n\n".join(adv_lines) + "\n"
        if adv_lines else ""
    )

    return _get(
        "stride_analysis",
        "component_template",
        comp_type=component.get("type", "Unknown"),
        comp_name=component.get("name", "Unnamed"),
        machine_type=component.get("machine_type", "unknown"),
        technology_tags=component.get("technology_tags", "N/A"),
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
        cia_triad=component.get("cia_triad", "Confidentiality: unknown | Integrity: unknown | Availability: unknown"),
        security_controls=component.get("security_controls", "N/A"),
        business_value=component.get("business_value", "Not specified"),
        extra_properties=component.get("extra_properties", "None"),
        inbound_flows=component.get("inbound_flows", "  None"),
        outbound_flows=component.get("outbound_flows", "  None"),
        deployment=context.get("deployment_environment", "Unknown"),
        system_desc_section=(
            f"## System Context\n    {context['system_description']}\n"
            if context.get("system_description")
            else ""
        ),
        adversarial_context_section=adversarial_context_section,
        data_sensitivity=context.get("data_sensitivity", "Medium"),
        compliance=", ".join(compliance) if compliance else "None specified",
        user_base=context.get("user_base", "Unknown"),
        integrations=", ".join(integrations) if integrations else "None",
    )


def build_batch_prompt(components: List[Dict], context: Dict) -> str:
    """Builds a single STRIDE analysis prompt covering multiple components.

    Each component is rendered as a compact table block.  The LLM is instructed
    to return a JSON array ``[{"component": "<name>", "threats": [...]}, ...]``.

    Args:
        components: List of component_details dicts (same schema as build_component_prompt).
        context:    Shared system context dict.

    Returns:
        Formatted prompt string ready to send to the LLM.
    """
    compliance = context.get("compliance_requirements", [])
    sector = context.get("sector", "")
    threat_actors = context.get("threat_actor_profiles", "")
    business_goals = context.get("business_goals_to_protect", "")

    adv_lines: list = []
    if sector:
        adv_lines.append(f"**Sector:** {sector}")
    if threat_actors:
        adv_lines.append(f"**Known Threat Actors:**\n{threat_actors}")
    if business_goals:
        adv_lines.append(f"**Business Goals to Protect:**\n{business_goals}")
    adversarial_context_section = (
        "## Adversarial Context\n" + "\n\n".join(adv_lines) + "\n"
        if adv_lines else ""
    )

    # Build the per-component blocks
    blocks: List[str] = []
    for i, comp in enumerate(components, 1):
        name = comp.get("name", f"Component{i}")
        internet_facing = (
            "Yes" if comp.get("is_public")
            else (
                "No (internal — system has internet-facing components)"
                if context.get("internet_facing")
                else "No"
            )
        )
        block_lines = [
            f"### Component {i}: {name}",
            "| Field | Value |",
            "|---|---|",
            f"| Type | {comp.get('type', 'Unknown')} |",
            f"| Machine | {comp.get('machine_type', 'unknown')} |",
            f"| Technology Tags | {comp.get('technology_tags', 'N/A')} |",
            f"| Trust Boundary | {comp.get('trust_boundary', 'Unknown')} |",
            f"| Internet-Facing | {internet_facing} |",
            f"| Authentication | {comp.get('authentication', 'Unknown')} |",
            f"| CIA | {comp.get('cia_triad', 'N/A')} |",
            f"| Security Controls | {comp.get('security_controls', 'N/A')} |",
            f"| Business Value | {comp.get('business_value', 'Not specified')} |",
        ]
        if comp.get("description"):
            block_lines.append(f"| Description | {comp['description'][:120]} |")
        block_lines.append("")
        block_lines.append(f"**Inbound:** {comp.get('inbound_flows', '  None')}")
        block_lines.append(f"**Outbound:** {comp.get('outbound_flows', '  None')}")
        block_lines.append("")
        blocks.append("\n".join(block_lines))

    return _get(
        "stride_analysis",
        "batch_template",
        n_components=len(components),
        system_desc_section=(
            f"## System Context\n    {context['system_description']}\n"
            if context.get("system_description")
            else ""
        ),
        adversarial_context_section=adversarial_context_section,
        data_sensitivity=context.get("data_sensitivity", "Medium"),
        compliance=", ".join(compliance) if compliance else "None specified",
        deployment=context.get("deployment_environment", "Unknown"),
        components_block="\n".join(blocks),
    )
