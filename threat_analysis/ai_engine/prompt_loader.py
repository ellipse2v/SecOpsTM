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
Prompt loader — reads all LLM prompts from config/prompts.yaml.

All prompts are defined in one place (config/prompts.yaml) so they can be
tuned by administrators without modifying Python code.

Variable substitution in templates uses <<varname>> syntax, which does not
conflict with JSON curly braces ``{}`` or LangChain's ``{varname}`` placeholders.
"""

import logging
from pathlib import Path
from typing import Any, Dict, Optional

import yaml

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_PROMPTS_PATH = _PROJECT_ROOT / "config" / "prompts.yaml"

_cache: Optional[Dict[str, Any]] = None


def _load() -> Dict[str, Any]:
    """Loads prompts.yaml once and caches the result."""
    global _cache
    if _cache is not None:
        return _cache
    if not _PROMPTS_PATH.exists():
        logging.error(
            f"prompts.yaml not found at {_PROMPTS_PATH}. "
            "Using empty prompt config — outputs will be degraded."
        )
        _cache = {}
        return _cache
    with open(_PROMPTS_PATH, "r", encoding="utf-8") as f:
        _cache = yaml.safe_load(f) or {}
    logging.debug(f"Loaded prompts from {_PROMPTS_PATH}")
    return _cache


def get(section: str, key: str, **variables: str) -> str:
    """Returns a prompt string from prompts.yaml, with optional variable substitution.

    Variables are injected using ``<<varname>>`` placeholders in the YAML template.
    Unknown placeholders are left intact (they may be LangChain or LLM placeholders).

    Args:
        section:   Top-level key in prompts.yaml  (e.g. ``"stride_analysis"``)
        key:       Second-level key               (e.g. ``"system"`` or ``"component_template"``)
        **variables: Mapping of ``varname`` → value to replace ``<<varname>>`` tokens.

    Returns:
        The prompt string with all ``<<varname>>`` replaced.

    Raises:
        KeyError: If ``section`` or ``key`` is missing from prompts.yaml.
    """
    prompts = _load()
    template: str = prompts[section][key]
    for name, value in variables.items():
        template = template.replace(f"<<{name}>>", str(value) if value is not None else "")
    return template


def reload() -> None:
    """Invalidates the cache so the next call to ``get()`` re-reads the YAML file.

    Useful in development / testing when prompts.yaml is edited at runtime.
    """
    global _cache
    _cache = None
    logging.info("prompts.yaml cache cleared — will reload on next access.")
