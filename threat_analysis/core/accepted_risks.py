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
AcceptedRiskLoader — loads and matches analyst decisions against threats.

Decisions are stored in ``accepted_risks.yaml`` alongside the threat model.
Auto-discovery: ``{model_dir}/accepted_risks.yaml``.

YAML format
-----------
Two matching styles are supported:

**Key-based** (precise, survives description edits):

    - threat_key: TK-A3F2C891     # shown in the HTML report
      decision: accepted
      rationale: "Mitigated by WAF rule 942100 — verified 2026-01-15"
      reviewer: alice@corp
      expires: 2026-09-01         # optional ISO date

**Pattern-based** (flexible, human-writable without running the tool first):

    - stride_category: Information Disclosure
      target: WebApp
      description_contains: "SQL injection"
      decision: false_positive
      rationale: "Inputs are parameterised, confirmed by dev team"
      reviewer: bob@corp

``decision`` must be one of: ``accepted``, ``false_positive``, ``mitigated``.
Expired entries (``expires`` < today) are silently ignored.
"""

import hashlib
import logging
from datetime import date
from pathlib import Path
from typing import Dict, List, Optional

import yaml

logger = logging.getLogger(__name__)

VALID_DECISIONS = frozenset({"accepted", "false_positive", "mitigated"})


# ---------------------------------------------------------------------------
# Stable content key
# ---------------------------------------------------------------------------

def compute_threat_key(threat: Dict) -> str:
    """Compute a stable 8-char hex key for a threat dict.

    Based on ``(stride_category, target, description[:80])`` — stable across
    re-runs as long as those three fields do not change substantially.

    The key is prefixed ``TK-`` for readability in YAML files and the report.
    """
    cat    = (threat.get("stride_category") or "").strip()
    target = (threat.get("target") or "").strip()
    desc   = (threat.get("description") or "")[:80].strip()
    raw    = f"{cat}\x00{target}\x00{desc}"
    return "TK-" + hashlib.md5(raw.encode("utf-8")).hexdigest()[:8].upper()


# ---------------------------------------------------------------------------
# Loader
# ---------------------------------------------------------------------------

class AcceptedRiskLoader:
    """Loads and applies analyst risk decisions from ``accepted_risks.yaml``.

    Usage::

        loader = AcceptedRiskLoader.from_model_path("/path/to/model.md")
        # or
        loader = AcceptedRiskLoader.from_file("/path/to/accepted_risks.yaml")

        decision = loader.get_decision(threat_dict)
        # returns None if no entry matches, or a dict:
        # {"decision": "accepted", "rationale": "...", "reviewer": "...", ...}
    """

    def __init__(self, entries: List[Dict]):
        self._entries = entries

    # ------------------------------------------------------------------
    # Factories
    # ------------------------------------------------------------------

    @classmethod
    def empty(cls) -> "AcceptedRiskLoader":
        """Returns a no-op loader with zero entries."""
        return cls([])

    @classmethod
    def from_file(cls, path: str) -> "AcceptedRiskLoader":
        """Load from an explicit YAML file path.

        Returns an empty loader if the file does not exist.
        """
        p = Path(path)
        if not p.exists():
            logger.debug("accepted_risks: file not found at %s — skipping.", p)
            return cls.empty()
        try:
            with open(p, "r", encoding="utf-8") as fh:
                raw = yaml.safe_load(fh) or []
            if not isinstance(raw, list):
                logger.warning("accepted_risks: %s must be a YAML list — ignored.", p)
                return cls.empty()
            today = date.today()
            valid: List[Dict] = []
            for entry in raw:
                if not isinstance(entry, dict):
                    continue
                dec = entry.get("decision", "")
                if dec not in VALID_DECISIONS:
                    logger.warning(
                        "accepted_risks: unknown decision %r in %s — skipped.", dec, p
                    )
                    continue
                expires = entry.get("expires")
                if expires:
                    try:
                        exp_date = (
                            expires if isinstance(expires, date)
                            else date.fromisoformat(str(expires))
                        )
                        if exp_date < today:
                            logger.debug(
                                "accepted_risks: entry for %r expired %s — skipped.",
                                entry.get("threat_key") or entry.get("description_contains"),
                                exp_date,
                            )
                            continue
                    except (ValueError, TypeError):
                        logger.warning(
                            "accepted_risks: invalid expires date %r — entry kept.", expires
                        )
                valid.append(entry)
            logger.info("accepted_risks: loaded %d active entries from %s", len(valid), p)
            return cls(valid)
        except Exception as exc:
            logger.error("accepted_risks: failed to load %s: %s", p, exc)
            return cls.empty()

    @classmethod
    def from_model_path(cls, model_file_path: Optional[str]) -> "AcceptedRiskLoader":
        """Auto-discover ``accepted_risks.yaml`` next to the model file.

        Falls back to an empty loader if the model path is None or the file
        does not exist.
        """
        if not model_file_path:
            return cls.empty()
        candidate = Path(model_file_path).parent / "accepted_risks.yaml"
        return cls.from_file(str(candidate))

    # ------------------------------------------------------------------
    # Matching
    # ------------------------------------------------------------------

    def get_decision(self, threat: Dict) -> Optional[Dict]:
        """Return the first matching analyst decision for *threat*, or None.

        Matching order (first match wins):
        1. ``threat_key`` exact match (computed by :func:`compute_threat_key`)
        2. Pattern match: ``stride_category`` AND ``target`` AND
           ``description_contains`` (all must be present in the entry and
           match the threat).
        """
        if not self._entries:
            return None
        key = compute_threat_key(threat)
        threat_cat  = (threat.get("stride_category") or "").lower()
        threat_tgt  = (threat.get("target") or "").lower()
        threat_desc = (threat.get("description") or "").lower()

        for entry in self._entries:
            # --- key-based match ----------------------------------------
            if entry.get("threat_key") and entry["threat_key"] == key:
                return self._to_decision(entry)

            # --- pattern-based match ------------------------------------
            if not entry.get("threat_key"):
                ec  = (entry.get("stride_category") or "").lower()
                et  = (entry.get("target") or "").lower()
                edc = (entry.get("description_contains") or "").lower()
                # All provided fields must match; unset fields are wildcards
                cat_ok  = (not ec)  or (ec  == threat_cat)
                tgt_ok  = (not et)  or (et  == threat_tgt)
                desc_ok = (not edc) or (edc in threat_desc)
                if cat_ok and tgt_ok and desc_ok and (ec or et or edc):
                    return self._to_decision(entry)

        return None

    @staticmethod
    def _to_decision(entry: Dict) -> Dict:
        return {
            "decision":  entry.get("decision", "accepted"),
            "rationale": entry.get("rationale", ""),
            "reviewer":  entry.get("reviewer", ""),
            "expires":   str(entry["expires"]) if entry.get("expires") else None,
        }

    # ------------------------------------------------------------------
    # Convenience
    # ------------------------------------------------------------------

    def __len__(self) -> int:
        return len(self._entries)

    def __bool__(self) -> bool:
        return bool(self._entries)
