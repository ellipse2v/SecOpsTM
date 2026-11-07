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

"""Run-level AI settings shared by every LLM caller.

Three call paths reach an LLM (LiteLLMClient, RAGThreatGenerator, ReportGenerator's
provider). They must agree on which provider runs, on how the reasoning toggle is
sent, and on what counts as a failed run, so that logic lives here.
"""

import logging
import os
import threading
from typing import Any, Dict, List, Optional, Tuple

PROFILE_QUALITY = "quality"
PROFILE_PERF = "perf"
AI_PROFILES = (PROFILE_QUALITY, PROFILE_PERF)

# perf also keeps threats with two grounding signals instead of three.
PERF_CONFIDENCE_THRESHOLD = 0.7

# Providers that reject a top-level `enable_thinking` and read it from the model's
# chat template instead.
_CHAT_TEMPLATE_THINKING_PROVIDERS = frozenset({"nvidia_nim"})


def select_provider(
    ai_config: Dict[str, Any], forced_provider: Optional[str] = None
) -> Tuple[Optional[str], Dict[str, Any]]:
    """Return ``(name, config)`` of the provider to use, or ``(None, {})``.

    First ``enabled: true`` wins, unless ``forced_provider`` or
    SECOPSTM_FORCE_PROVIDER names a configured provider, which need not be enabled.
    """
    providers = ai_config.get("ai_providers") or {}
    forced = forced_provider or os.environ.get("SECOPSTM_FORCE_PROVIDER")
    if forced and providers.get(forced):
        logging.warning(
            "Provider selection forced to '%s' via %s "
            "(overrides the enabled: flags in ai_config.yaml)", forced,
            "explicit forced_provider" if forced_provider else "SECOPSTM_FORCE_PROVIDER",
        )
        return forced, providers[forced]
    if forced:
        logging.warning(
            "SECOPSTM_FORCE_PROVIDER='%s' not found or has no configuration in "
            "ai_providers — ignoring", forced
        )
    for name, config in providers.items():
        if config and config.get("enabled", False):
            return name, config
    return None, {}


def resolve_profile(ai_config: Dict[str, Any]) -> str:
    """Return the active generation profile: SECOPSTM_AI_PROFILE, then the config.

    An unknown value falls back to ``quality`` so that a typo cannot loosen the filter.
    """
    value = os.environ.get("SECOPSTM_AI_PROFILE") or (
        (ai_config.get("threat_generation") or {}).get("profile")
    ) or PROFILE_QUALITY
    if value not in AI_PROFILES:
        logging.warning("Unknown AI profile '%s' — using '%s'.", value, PROFILE_QUALITY)
        return PROFILE_QUALITY
    return value


def thinking_params(
    provider_name: str, provider_config: Dict[str, Any], profile: str
) -> Dict[str, Any]:
    """Return the completion kwargs that carry the reasoning toggle for this provider.

    ``perf`` turns reasoning off only where the provider has a toggle: Anthropic, for
    one, rejects an unknown ``enable_thinking`` field, so an absent key sends nothing.
    """
    chat_template = provider_name in _CHAT_TEMPLATE_THINKING_PROVIDERS
    if profile == PROFILE_PERF and (chat_template or "enable_thinking" in provider_config):
        enabled = False
    elif "enable_thinking" in provider_config:
        enabled = bool(provider_config["enable_thinking"])
    else:
        return {}
    if chat_template:
        return {"extra_body": {"chat_template_kwargs": {"enable_thinking": enabled}}}
    return {"enable_thinking": enabled}


class AIRunStats:
    """Process-wide counters, so a failed AI run cannot look like a normal one.

    Long-lived processes (the server) never reset them: callers take a ``mark()`` and
    read ``problems(since=mark)`` to scope the answer to one report.
    """

    _COUNTERS = (
        "calls", "failed_calls", "truncated_calls", "offline_checks",
        "dropped_low_confidence", "dropped_placeholder",
    )

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.reset()

    def reset(self) -> None:
        self.counters: Dict[str, int] = {k: 0 for k in self._COUNTERS}
        self.failed_components: List[str] = []

    def add(self, counter: str, amount: int = 1) -> None:
        with self._lock:
            self.counters[counter] += amount

    def component_failed(self, name: str) -> None:
        with self._lock:
            self.failed_components.append(name)

    def mark(self) -> Dict[str, Any]:
        with self._lock:
            return {"counters": dict(self.counters), "components": len(self.failed_components)}

    def _since(self, mark: Optional[Dict[str, Any]]) -> Tuple[Dict[str, int], List[str]]:
        with self._lock:
            base = (mark or {}).get("counters", {})
            counters = {k: v - base.get(k, 0) for k, v in self.counters.items()}
            return counters, self.failed_components[(mark or {}).get("components", 0):]

    def problems(self, since: Optional[Dict[str, Any]] = None) -> List[str]:
        """Return what went wrong in the AI part of the run; empty means it went fine."""
        counters, components = self._since(since)
        found: List[str] = []
        if counters["offline_checks"]:
            found.append("AI provider unreachable: the output has no new AI threats.")
        elif not counters["calls"]:
            found.append("AI was expected but no LLM call ran.")
        if components:
            found.append(
                f"{len(components)} component(s) got no AI threats: "
                + ", ".join(sorted(set(components)))
            )
        if counters["failed_calls"]:
            found.append(f"{counters['failed_calls']}/{counters['calls']} LLM call(s) failed.")
        return found

    def summary(self, since: Optional[Dict[str, Any]] = None) -> str:
        """One line with the counters, including what the filters removed."""
        counters, _ = self._since(since)
        return (
            f"{counters['calls']} LLM call(s), {counters['failed_calls']} failed, "
            f"{counters['truncated_calls']} truncated; dropped "
            f"{counters['dropped_low_confidence']} low-confidence and "
            f"{counters['dropped_placeholder']} placeholder threat(s)"
        )


run_stats = AIRunStats()
