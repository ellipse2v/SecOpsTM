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
ThreatConsolidator — merges pytm and AI-generated threat dicts with semantic deduplication.

Deduplication heuristic: two threats are considered duplicates when they share
the same target, the same normalised STRIDE category, and their descriptions
have a Jaccard word-overlap >= 0.3 (or one description is a substring of the
other).  When a duplicate is found the AI version wins (richer description).
Offline-safe: no HTTP calls, no NLP dependencies.
"""

import re
import logging
from typing import Dict, List, Set

logger = logging.getLogger(__name__)

# Variant spellings found in the wild → canonical form
_STRIDE_ALIASES: Dict[str, str] = {
    "elevationofprivilege": "ElevationOfPrivilege",
    "elevation of privilege": "ElevationOfPrivilege",
    "informationdisclosure": "InformationDisclosure",
    "information disclosure": "InformationDisclosure",
    "denialofservice": "DenialOfService",
    "denial of service": "DenialOfService",
    "spoofing": "Spoofing",
    "tampering": "Tampering",
    "repudiation": "Repudiation",
}

_STOP_WORDS: Set[str] = {
    "a", "an", "the", "in", "on", "at", "to", "for", "of", "and", "or",
    "is", "are", "was", "be", "by", "it", "its",
}


def _normalize_category(cat: str) -> str:
    """Return the canonical STRIDE category name for *cat*."""
    key = cat.lower().replace(" ", "")
    return _STRIDE_ALIASES.get(cat.lower(), _STRIDE_ALIASES.get(key, cat))


def _word_set(text: str) -> Set[str]:
    words = re.sub(r"[^a-z0-9\s]", "", text.lower()).split()
    return {w for w in words if w not in _STOP_WORDS and len(w) > 2}


def _jaccard(t1: str, t2: str) -> float:
    s1, s2 = _word_set(t1), _word_set(t2)
    if not s1 or not s2:
        return 0.0
    return len(s1 & s2) / len(s1 | s2)


def _descriptions_similar(d1: str, d2: str) -> bool:
    """Return True when d1 and d2 are semantically close enough to be duplicates."""
    if _jaccard(d1, d2) >= 0.3:
        return True
    d1l, d2l = d1.lower(), d2.lower()
    return d1l in d2l or d2l in d1l


class ThreatConsolidator:
    """
    Merges lists of normalised threat dicts coming from different sources.

    Each dict must contain at least:
        "target"          str   — component name
        "stride_category" str   — STRIDE label (any spelling)
        "description"     str   — human-readable threat description

    Usage::

        merged = ThreatConsolidator.deduplicate(pytm_dicts, ai_dicts)
    """

    @staticmethod
    def deduplicate(
        pytm_threats: List[Dict],
        ai_threats: List[Dict],
    ) -> List[Dict]:
        """
        Return a merged list where pytm threats superseded by an AI threat are
        removed.  The AI version wins on every duplicate.

        Args:
            pytm_threats: threats produced by the pytm rule engine (source="pytm").
            ai_threats:   component-level AI threats (source="AI").

        Returns:
            (unique pytm threats) + (all AI threats), in that order.
        """
        if not ai_threats:
            return list(pytm_threats)

        removed: Set[int] = set()

        for ai in ai_threats:
            ai_target = ai.get("target", "")
            ai_cat = _normalize_category(ai.get("stride_category", ""))
            ai_desc = ai.get("description", "")

            for idx, pytm in enumerate(pytm_threats):
                if idx in removed:
                    continue
                if pytm.get("target", "") != ai_target:
                    continue
                if _normalize_category(pytm.get("stride_category", "")) != ai_cat:
                    continue
                if _descriptions_similar(pytm.get("description", ""), ai_desc):
                    logger.debug(
                        "Dedup: pytm '%s...' superseded by AI '%s...' on target '%s'",
                        pytm.get("description", "")[:60],
                        ai_desc[:60],
                        ai_target,
                    )
                    removed.add(idx)

        unique_pytm = [t for i, t in enumerate(pytm_threats) if i not in removed]
        merged = unique_pytm + ai_threats
        logger.info(
            "ThreatConsolidator: %d pytm + %d AI → %d merged (%d pytm removed as duplicates)",
            len(pytm_threats),
            len(ai_threats),
            len(merged),
            len(removed),
        )
        return merged
