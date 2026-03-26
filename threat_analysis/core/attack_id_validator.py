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
AttackIdValidator — validates ATT&CK technique IDs in generated threat reports.

Checks every ``mitre_techniques[].id`` in the threat list against the local
``external_data/enterprise-attack.json`` corpus.  Identifies three classes of
problems:

- **invalid**    — ID not present in the corpus at all (likely an AI hallucination).
- **revoked**    — ID present but marked ``revoked: true`` (superseded by another
                   technique).
- **deprecated** — ID present but marked ``x_mitre_deprecated: true``.

The validator is fully offline: it reads the pre-committed STIX bundle and
never makes network calls.  The JSON is parsed once per process and cached
at class level.
"""

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, FrozenSet, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)

# Path to the enterprise-attack STIX bundle (relative to this file)
_ENTERPRISE_ATTACK_PATH = (
    Path(__file__).resolve().parents[1] / "external_data" / "enterprise-attack.json"
)

# Issue types
INVALID    = "invalid"
REVOKED    = "revoked"
DEPRECATED = "deprecated"

_ISSUE_LABELS = {
    INVALID:    "Invalid ID",
    REVOKED:    "Revoked",
    DEPRECATED: "Deprecated",
}


@dataclass
class IdIssue:
    """A single ATT&CK ID problem found in a threat."""
    technique_id: str        # e.g. "T1234" or "T1234.001"
    issue_type: str          # INVALID | REVOKED | DEPRECATED
    threat_id: str           # e.g. "T-0001"
    threat_name: str         # human-readable name of the threat
    threat_target: str       # target component name

    @property
    def label(self) -> str:
        return _ISSUE_LABELS.get(self.issue_type, self.issue_type)

    @property
    def attack_url(self) -> str:
        """Best-effort ATT&CK URL for a valid/revoked/deprecated ID."""
        tid = self.technique_id
        if "." in tid:
            parts = tid.split(".", 1)
            return f"https://attack.mitre.org/techniques/{parts[0]}/{parts[1]}/"
        return f"https://attack.mitre.org/techniques/{tid}/"


@dataclass
class ValidationReport:
    """Aggregated ATT&CK ID validation results for a full threat list."""
    total_techniques_checked: int
    invalid: List[IdIssue] = field(default_factory=list)
    revoked: List[IdIssue] = field(default_factory=list)
    deprecated: List[IdIssue] = field(default_factory=list)

    @property
    def has_issues(self) -> bool:
        return bool(self.invalid or self.revoked or self.deprecated)

    @property
    def all_issues(self) -> List[IdIssue]:
        return self.invalid + self.revoked + self.deprecated

    @property
    def n_invalid(self) -> int:
        return len(self.invalid)

    @property
    def n_revoked(self) -> int:
        return len(self.revoked)

    @property
    def n_deprecated(self) -> int:
        return len(self.deprecated)


class AttackIdValidator:
    """Validates ATT&CK technique IDs against the local STIX bundle.

    The index is built lazily and cached at class level so it is only
    parsed once per process, even when multiple report generators run.
    """

    # Class-level cache: (valid_ids, revoked_ids, deprecated_ids)
    _index: Optional[Tuple[FrozenSet[str], FrozenSet[str], FrozenSet[str]]] = None

    @classmethod
    def _load_index(cls, stix_path: Path = _ENTERPRISE_ATTACK_PATH) -> Tuple[
        FrozenSet[str], FrozenSet[str], FrozenSet[str]
    ]:
        """Build (or return cached) sets of valid, revoked, and deprecated IDs."""
        if cls._index is not None:
            return cls._index

        if not stix_path.exists():
            logger.warning(
                "AttackIdValidator: enterprise-attack.json not found at %s — "
                "validation disabled.",
                stix_path,
            )
            cls._index = (frozenset(), frozenset(), frozenset())
            return cls._index

        try:
            with open(stix_path, "r", encoding="utf-8") as fh:
                bundle = json.load(fh)
        except (OSError, ValueError) as exc:
            logger.error("AttackIdValidator: failed to load STIX bundle: %s", exc)
            cls._index = (frozenset(), frozenset(), frozenset())
            return cls._index

        valid_ids: Set[str] = set()
        revoked_ids: Set[str] = set()
        deprecated_ids: Set[str] = set()

        for obj in bundle.get("objects", []):
            if obj.get("type") != "attack-pattern":
                continue
            for ref in obj.get("external_references", []):
                if ref.get("source_name") == "mitre-attack":
                    tid = ref.get("external_id", "")
                    if not tid:
                        continue
                    valid_ids.add(tid)
                    if obj.get("revoked"):
                        revoked_ids.add(tid)
                    if obj.get("x_mitre_deprecated"):
                        deprecated_ids.add(tid)

        logger.info(
            "AttackIdValidator: indexed %d techniques (%d revoked, %d deprecated)",
            len(valid_ids),
            len(revoked_ids),
            len(deprecated_ids),
        )
        cls._index = (frozenset(valid_ids), frozenset(revoked_ids), frozenset(deprecated_ids))
        return cls._index

    @classmethod
    def _reset_cache(cls) -> None:
        """Reset class-level cache (for testing)."""
        cls._index = None

    def validate_all(
        self,
        all_threats: List[Dict],
        stix_path: Path = _ENTERPRISE_ATTACK_PATH,
    ) -> ValidationReport:
        """Validate all ATT&CK technique IDs across the full threat list.

        Args:
            all_threats: List of threat dicts as returned by
                         ``ReportGenerator._get_all_threats_with_mitre_info``.
            stix_path:   Override path to the STIX bundle (for tests).

        Returns:
            A :class:`ValidationReport` with per-issue details.
        """
        valid_ids, revoked_ids, deprecated_ids = self._load_index(stix_path)

        # Empty index = corpus not available; skip silently
        if not valid_ids:
            return ValidationReport(total_techniques_checked=0)

        total = 0
        invalid_issues: List[IdIssue] = []
        revoked_issues: List[IdIssue] = []
        deprecated_issues: List[IdIssue] = []

        # Deduplicate per (threat_id, technique_id) to avoid double-counting
        seen: Set[Tuple[str, str]] = set()

        for threat in all_threats:
            threat_id     = threat.get("id", "?")
            threat_name   = threat.get("name") or threat.get("description", "?")
            threat_target = threat.get("target", "?")

            for tech in threat.get("mitre_techniques", []):
                raw_id = (tech.get("id") or "").strip()
                if not raw_id:
                    continue
                total += 1
                key = (threat_id, raw_id)
                if key in seen:
                    continue
                seen.add(key)

                issue = IdIssue(
                    technique_id=raw_id,
                    issue_type="",  # filled below
                    threat_id=threat_id,
                    threat_name=str(threat_name)[:80],
                    threat_target=str(threat_target)[:60],
                )

                if raw_id not in valid_ids:
                    issue.issue_type = INVALID
                    invalid_issues.append(issue)
                elif raw_id in revoked_ids:
                    issue.issue_type = REVOKED
                    revoked_issues.append(issue)
                elif raw_id in deprecated_ids:
                    issue.issue_type = DEPRECATED
                    deprecated_issues.append(issue)

        report = ValidationReport(
            total_techniques_checked=total,
            invalid=invalid_issues,
            revoked=revoked_issues,
            deprecated=deprecated_issues,
        )
        if report.has_issues:
            logger.warning(
                "AttackIdValidator: %d invalid, %d revoked, %d deprecated technique IDs",
                report.n_invalid,
                report.n_revoked,
                report.n_deprecated,
            )
        return report
