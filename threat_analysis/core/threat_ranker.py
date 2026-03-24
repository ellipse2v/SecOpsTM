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
ThreatRanker — ranks and trims the consolidated threat list.

Ranking is based on a weighted composite of severity, confidence, and
risk-signal coverage.  Trimming caps the total number of threats while
guaranteeing at least one representative per STRIDE category present in
the original list (when ``min_stride_coverage=True``).

All functions are pure and side-effect-free; they return new lists without
mutating the input.
"""

import logging
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

# Threats whose stride_category matches one of these are considered valid
# STRIDE entries when enforcing min_stride_coverage.
_STRIDE_CATEGORIES = frozenset({
    "Spoofing",
    "Tampering",
    "Repudiation",
    "Information Disclosure",
    "Denial of Service",
    "Elevation of Privilege",
})

_DEFAULT_WEIGHTS: Dict[str, float] = {
    "severity": 0.4,
    "confidence": 0.3,
    "risk_signals": 0.3,
}


def _composite_score(threat: Dict, weights: Dict[str, float]) -> float:
    """Computes a 0–1 composite relevance score for a single threat dict.

    Formula::

        score = w_sev * norm_severity
              + w_conf * confidence
              + w_risk * norm_risk_signals

    ``norm_severity``  = severity.score / 10  (capped at 1.0)
    ``confidence``     = threat['confidence'] (already 0–1)
    ``norm_risk_signals`` = (cve_match + cwe_high_risk + network_exposed) / 3
                           minus 0.1 if d3fend mitigations are present
    """
    w_sev  = weights.get("severity",     _DEFAULT_WEIGHTS["severity"])
    w_conf = weights.get("confidence",   _DEFAULT_WEIGHTS["confidence"])
    w_risk = weights.get("risk_signals", _DEFAULT_WEIGHTS["risk_signals"])

    severity_score = (threat.get("severity") or {}).get("score", 5.0)
    norm_severity  = min(float(severity_score) / 10.0, 1.0)

    _conf_raw = threat.get("confidence")
    confidence = float(_conf_raw if _conf_raw is not None else 0.5)
    confidence = max(0.0, min(confidence, 1.0))

    rs = threat.get("risk_signals") or {}
    raw_signals = (
        (1 if rs.get("cve_match")       else 0)
        + (1 if rs.get("cwe_high_risk") else 0)
        + (1 if rs.get("network_exposed") else 0)
    )
    # D3FEND mitigations slightly reduce the risk signal (controls are present)
    d3fend_discount = 0.3 if rs.get("d3fend_mitigations") else 0.0
    norm_risk = max(0.0, (raw_signals / 3.0) - d3fend_discount)

    return w_sev * norm_severity + w_conf * confidence + w_risk * norm_risk


def rank(
    threats: List[Dict],
    weights: Optional[Dict[str, float]] = None,
) -> List[Dict]:
    """Returns a new list sorted by composite relevance score (highest first).

    Each threat dict receives an extra ``_ranking_score`` key (float 0–1) so
    callers can inspect or log the computed value.

    Args:
        threats: List of threat dicts as produced by
                 ``ReportGenerator._get_all_threats_with_mitre_info``.
        weights: Optional override for the three weight keys
                 (``severity``, ``confidence``, ``risk_signals``).
                 Missing keys fall back to the defaults (0.4 / 0.3 / 0.3).

    Returns:
        A new list (original dicts are shallow-copied) sorted descending.
    """
    if not threats:
        return []
    w = {**_DEFAULT_WEIGHTS, **(weights or {})}
    scored: List = []
    for t in threats:
        t_copy = dict(t)
        t_copy["_ranking_score"] = round(_composite_score(t, w), 4)
        scored.append(t_copy)
    scored.sort(key=lambda x: x["_ranking_score"], reverse=True)
    return scored


def trim(
    threats: List[Dict],
    max_total: int,
    min_stride_coverage: bool = True,
) -> List[Dict]:
    """Trims a ranked threat list to at most ``max_total`` entries.

    Algorithm
    ---------
    1. Seed the result with the single highest-ranked threat for each STRIDE
       category that appears in the full list (guarantees coverage).
    2. Fill remaining slots from the ranked list (top-down), skipping items
       already selected in step 1.
    3. Re-sort the final result by ``_ranking_score`` descending.

    Args:
        threats:            Ranked list (output of :func:`rank`).
        max_total:          Maximum number of threats to return.
                            ``0`` or negative = no limit (returns ``threats``
                            unchanged).
        min_stride_coverage: When ``True`` (default) ensures at least one
                            representative per STRIDE category is kept even
                            if it would otherwise be cut.

    Returns:
        A (possibly shorter) list of threat dicts, still sorted descending
        by ``_ranking_score``.
    """
    if max_total <= 0 or len(threats) <= max_total:
        return list(threats)

    if not min_stride_coverage:
        return list(threats[:max_total])

    # --- Step 1: seed with best per-category representative -----------------
    result_set: List[Dict] = []
    seen_indices: set = set()
    covered_cats: set = set()

    all_stride_cats = {
        t.get("stride_category", "")
        for t in threats
        if t.get("stride_category", "") in _STRIDE_CATEGORIES
    }

    for i, t in enumerate(threats):
        cat = t.get("stride_category", "")
        if cat in _STRIDE_CATEGORIES and cat not in covered_cats:
            result_set.append(t)
            seen_indices.add(i)
            covered_cats.add(cat)
            if covered_cats >= all_stride_cats:
                break  # all categories covered, stop seeding

    # --- Step 2: fill remaining slots with top-ranked remaining threats -----
    for i, t in enumerate(threats):
        if len(result_set) >= max_total:
            break
        if i not in seen_indices:
            result_set.append(t)

    # --- Step 3: re-sort by ranking score -----------------------------------
    result_set.sort(key=lambda x: x.get("_ranking_score", 0.0), reverse=True)

    logger.info(
        "ThreatRanker: trimmed %d → %d threats (STRIDE coverage: %s)",
        len(threats),
        len(result_set),
        ", ".join(sorted(covered_cats)) or "none",
    )
    return result_set


def rank_and_trim(
    threats: List[Dict],
    max_total: int = 0,
    min_stride_coverage: bool = True,
    weights: Optional[Dict[str, float]] = None,
) -> List[Dict]:
    """Convenience wrapper: rank then trim in one call.

    Args:
        threats:             Raw (unranked) threat dicts.
        max_total:           Cap on total threats (0 = no limit).
        min_stride_coverage: Preserve one entry per STRIDE category.
        weights:             Composite score weights override.

    Returns:
        Ranked (and optionally trimmed) list with ``_ranking_score`` added.
    """
    ranked = rank(threats, weights=weights)
    return trim(ranked, max_total=max_total, min_stride_coverage=min_stride_coverage)
