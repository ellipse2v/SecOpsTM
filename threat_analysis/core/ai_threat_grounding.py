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

"""Grounding check for LLM-generated per-component STRIDE threats.

The debate evaluation (docs/evaluation.md) showed an LLM's self-reported numeric
score does not reproduce and should not be trusted. The same applies to a
generated threat's ``confidence`` field. This module derives a confidence from
what the threat actually gets right about the modelled component, and flags the
claims it cannot have grounded (a CVE in a STRIDE threat — the STRIDE prompt is
never given CVE data; a technology the component's tags contradict).

Pure, offline, no LLM. Consumed by ``AIService._apply_threats_to_element``.
"""

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List

from threat_analysis.core.stride_constants import STRIDE_CATEGORIES

# Confidence is reported on a fixed grid, not a free 0.0–1.0 float.
_CONF_GRID = (0.3, 0.5, 0.7, 0.9)

_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{3,7}\b", re.IGNORECASE)
_CAPEC_RE = re.compile(r"^CAPEC-\d+$", re.IGNORECASE)

# Cross-domain technology keywords. If the component's tags name one stack and the
# threat text is clearly about a different one, that is a grounding violation
# (the STRIDE system prompt explicitly forbids extrapolating stacks).
_TECH_DOMAINS: Dict[str, tuple] = {
    "kubernetes": ("kubernetes", "k8s", "kubectl", "kube-", "helm chart", "kubelet"),
    "docker": ("docker", "dockerfile", "container escape", "container runtime"),
    "aws": ("aws ", "s3 bucket", "iam role", "lambda function", " ec2", "cloudtrail", "sts assume"),
    "azure": (" azure", "entra id", "azure ad", "managed identity"),
    "gcp": ("gcp ", "google cloud", " gke", "gcs bucket"),
    "windows-ad": ("active directory", "kerberos", "ntlm", "domain controller", "group policy"),
}

# protocols the grounding block can name, used for the "real connected protocol" signal
_PROTOCOLS = ("https", "http", "ssh", "sql", "grpc", "amqp", "ldap", "smb", "rdp", "mqtt", "dns", "ftp")


@dataclass
class GroundingResult:
    confidence: float
    flags: List[str] = field(default_factory=list)
    signals: List[str] = field(default_factory=list)


def _snap(value: float) -> float:
    v = max(0.2, min(0.95, value))
    return min(_CONF_GRID, key=lambda g: abs(g - v))


def score_grounding(threat_json: Dict[str, Any], component_details: Dict[str, Any]) -> GroundingResult:
    """Derive a grounded confidence + flags/signals for one generated threat."""
    text = " ".join(
        str(threat_json.get(k, "")) for k in ("title", "description", "attack_scenario")
    ).lower()
    flags: List[str] = []
    signals: List[str] = []

    # ── flags: claims the threat cannot have grounded ────────────────────────
    for cve in sorted({m.upper() for m in _CVE_RE.findall(text)}):
        flags.append(f"cites {cve} — per-component STRIDE analysis is not CVE-grounded")

    tags = str(component_details.get("technology_tags") or "").lower().strip()
    if tags and tags != "n/a":
        # the component declares a specific stack — a threat about a cloud /
        # orchestration domain whose name is nowhere in the tags is extrapolation,
        # which the STRIDE system prompt explicitly forbids
        for d, kws in _TECH_DOMAINS.items():
            if d in tags or any(k.strip() in tags for k in kws):
                continue  # the component genuinely is this
            if any(k in text for k in kws):
                flags.append(f"references {d} but component tech tags are '{tags}'")

    # ── signals: facts about the modelled component the threat gets right ────
    if str(threat_json.get("category", "")) in STRIDE_CATEGORIES:
        signals.append("valid STRIDE category")

    if any(_CAPEC_RE.match(str(c)) for c in (threat_json.get("capec_ids") or [])):
        signals.append("cites a CAPEC id")

    controls = str(component_details.get("security_controls") or "").lower()
    for marker, kw in (("waf: no", "waf"), ("ids: no", "ids"), ("ips: no", "ips"),
                       ("mfa: no", "mfa")):
        if marker in controls and kw in text:
            signals.append(f"targets a real control gap ({kw})")

    flows = (
        str(component_details.get("inbound_flows") or "")
        + " " + str(component_details.get("outbound_flows") or "")
    ).lower()
    if any(p in flows and p in text for p in _PROTOCOLS):
        signals.append("uses a real connected protocol")

    if component_details.get("is_public") and any(
        w in text for w in ("internet", "publicly", "public-facing", "exposed", "unauthenticated")
    ):
        signals.append("consistent with is_public")

    boundary = str(component_details.get("trust_boundary") or "").lower()
    if "untrusted" in boundary and any(w in text for w in ("untrusted", "lateral", "pivot", "boundary")):
        signals.append("consistent with the trust boundary")

    raw = 0.5 + 0.1 * min(len(set(signals)), 4) - 0.2 * len(flags)
    return GroundingResult(
        confidence=_snap(raw),
        flags=flags,
        signals=sorted(set(signals)),
    )
