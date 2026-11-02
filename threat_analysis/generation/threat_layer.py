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

"""Threat layer data for the interactive HTML diagram.

``build_threat_layer()`` attaches every threat of the report to the diagram element it
targets (node, dataflow edge or boundary cluster), keyed by the SVG ``id`` Graphviz gives
that element. The diagram templates turn this into severity badges that can be toggled
from the legend, and a side panel that lists the threats of a clicked element.
"""

import re
from typing import Any, Dict, Iterable, Optional

from threat_analysis.core.stride_constants import STRIDE_CATEGORIES
from threat_analysis.generation.utils import get_enriched_threats

SEVERITY_LEVELS = ("CRITICAL", "HIGH", "MEDIUM", "LOW")
_ORDER = {level: rank for rank, level in enumerate(reversed(SEVERITY_LEVELS), start=1)}
_IMPACT_TO_LEVEL = {5: "CRITICAL", 4: "HIGH", 3: "MEDIUM", 2: "LOW", 1: "LOW"}
_ARROWS = ("→", "->")
# Legend order of the STRIDE filter; anything else (AI free text, empty) is "Other".
STRIDE_ORDER = ("Spoofing", "Tampering", "Repudiation", "Information Disclosure",
                "Denial of Service", "Elevation of Privilege")
OTHER_STRIDE = "Other"
_STRIDE_LOOKUP = {c.lower().replace(" ", ""): c for c in STRIDE_CATEGORIES}
_STRIDE_LOOKUP.update({"informationdisclosure": "Information Disclosure", "disclosure": "Information Disclosure",
                       "dos": "Denial of Service", "elevationofprivileges": "Elevation of Privilege"})
# Per element, the panel lists the worst threats only; the badge still counts them all.
MAX_THREATS_PER_ELEMENT = 25
_MAX_TITLE_LEN = 160


def sanitize_id(name: Any) -> str:
    """Same algorithm as DiagramGenerator._sanitize_name and the report's ``sid`` filter."""
    s = re.sub(r"[^a-zA-Z0-9_]", "_", str(name or ""))
    return (f"_{s}" if s and s[0].isdigit() else s) or "unnamed"


def _name(obj: Any) -> str:
    if obj is None:
        return ""
    if isinstance(obj, dict):
        return str(obj.get("name", ""))
    return str(getattr(obj, "name", "") or "")


def _level_of(threat: Dict[str, Any]) -> str:
    sev = threat.get("severity")
    level = ""
    score = None
    if isinstance(sev, dict):
        level = str(sev.get("level") or "").upper()
        score = sev.get("score")
    elif isinstance(sev, str):
        level = sev.upper()
    if level in _ORDER:
        return level
    if level.startswith("INFO"):
        return "LOW"
    if isinstance(score, (int, float)):
        if score >= 9:
            return "CRITICAL"
        if score >= 7:
            return "HIGH"
        if score >= 4:
            return "MEDIUM"
        return "LOW"
    impact = threat.get("impact")
    if isinstance(impact, (int, float)) and int(impact) in _IMPACT_TO_LEVEL:
        return _IMPACT_TO_LEVEL[int(impact)]
    return ""


def _stride_of(threat: Dict[str, Any]) -> str:
    raw = str(threat.get("stride_category") or "")
    return _STRIDE_LOOKUP.get(re.sub(r"[\s_-]", "", raw).lower(), OTHER_STRIDE)


def _score_of(threat: Dict[str, Any]) -> float:
    sev = threat.get("severity")
    if isinstance(sev, dict) and isinstance(sev.get("score"), (int, float)):
        return float(sev["score"])
    return 0.0


def _element_index(threat_model: Any) -> Dict[str, Dict[str, str]]:
    """Maps a threat ``target`` string to the diagram element that renders it."""
    index: Dict[str, Dict[str, str]] = {}

    # Boundaries are keyed by their lower-cased name (the cluster id uses it); threats
    # name them with the original case.
    for key, info in (getattr(threat_model, "boundaries", {}) or {}).items():
        info = info if isinstance(info, dict) else {}
        display = str(info.get("original_name") or _name(info.get("boundary")) or key)
        entry = {"id": f"cluster_{sanitize_id(key)}", "kind": "boundary", "label": display}
        index[str(key)] = entry
        index[display] = entry

    for collection, kind in (("actors", "actor"), ("servers", "server")):
        for item in getattr(threat_model, collection, []) or []:
            name = _name(item)
            if name:
                index[name] = {"id": sanitize_id(name), "kind": kind, "label": name}

    drawn: Dict[tuple, Dict[str, str]] = {}
    for df in getattr(threat_model, "dataflows", []) or []:
        src, dst = _name(getattr(df, "source", None)), _name(getattr(df, "sink", None))
        if not src or not dst:
            continue
        protocol = getattr(df, "protocol", None)
        reverse = drawn.get((dst, src, protocol))
        if reverse is not None:
            # The diagram merges A→B and B→A of the same protocol into one two-headed
            # arrow that keeps the first flow's id: both flows' threats go on it.
            reverse["label"] = f"{dst} ↔ {src}"
            entry = reverse
        else:
            entry = {
                "id": f"edge_{sanitize_id(src)}_{sanitize_id(dst)}",
                "kind": "dataflow",
                "label": f"{src} → {dst}",
            }
            drawn[(src, dst, protocol)] = entry
        df_name = _name(df)
        # A dataflow name never shadows a node or boundary of the same name.
        if df_name and df_name not in index:
            index[df_name] = entry
        for arrow in _ARROWS:
            index.setdefault(f"{src} {arrow} {dst}", entry)
    return index


def _resolve(target: str, index: Dict[str, Dict[str, str]]) -> Optional[Dict[str, str]]:
    target = target.strip()
    if target in index:
        return index[target]
    for arrow in _ARROWS:
        if arrow in target:
            src, _, dst = target.partition(arrow)
            src, dst = src.strip(), dst.strip()
            key = f"{src} → {dst}"
            if key in index:
                return index[key]
            # Flow between two elements with no drawn edge: pin it on the source node.
            return index.get(src) or index.get(dst)
    return None


def build_threat_layer(threat_model: Any, threats: Optional[Iterable[Dict[str, Any]]] = None) -> Dict[str, Any]:
    """Returns ``{svg_id: element_entry}`` for every diagram element that has threats.

    ``threats`` defaults to :func:`get_enriched_threats`, so the layer shows exactly the
    threats of the report (AI-enriched ones included) when the report was generated first.
    Each entry: ``label``, ``kind``, ``anchor`` (report anchor), ``counts`` per severity,
    ``by_stride`` (``{stride: {severity: n}}``, for the legend's STRIDE filter), ``total``,
    ``max`` (worst severity) and ``threats`` (worst first, capped).
    """
    if threats is None:
        try:
            threats = get_enriched_threats(threat_model)
        except Exception:
            threats = []
    index = _element_index(threat_model)
    layer: Dict[str, Dict[str, Any]] = {}

    for threat in threats or []:
        if not isinstance(threat, dict):
            continue
        target = str(threat.get("target") or "")
        element = _resolve(target, index) if target else None
        level = _level_of(threat)
        if element is None or not level:
            continue
        entry = layer.setdefault(element["id"], {
            "label": element["label"],
            "kind": element["kind"],
            "anchor": f"component-{sanitize_id(target)}",
            "counts": {lvl: 0 for lvl in SEVERITY_LEVELS},
            "by_stride": {},
            "total": 0,
            "max": level,
            "threats": [],
        })
        stride = _stride_of(threat)
        entry["counts"][level] += 1
        per_level = entry["by_stride"].setdefault(stride, {})
        per_level[level] = per_level.get(level, 0) + 1
        entry["total"] += 1
        if _ORDER[level] > _ORDER[entry["max"]]:
            entry["max"] = level
        title = str(threat.get("description") or threat.get("type") or "Threat").strip()
        if len(title) > _MAX_TITLE_LEN:
            title = title[:_MAX_TITLE_LEN - 1].rstrip() + "…"
        entry["threats"].append({
            "id": str(threat.get("id") or ""),
            "title": title,
            "severity": level,
            "score": round(_score_of(threat), 1),
            "stride": stride,
            "source": str(threat.get("source") or ""),
        })

    for entry in layer.values():
        entry["threats"].sort(key=lambda t: (-_ORDER[t["severity"]], -t["score"], t["id"]))
        del entry["threats"][MAX_THREATS_PER_ELEMENT:]
    return layer

