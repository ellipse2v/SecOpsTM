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
VEXLoader — loads Vulnerability Exploitability eXchange (VEX) data.

Supported format: CycloneDX 1.x VEX (JSON), the same standard already used
for BOM files so no new parser dependency is required.

VEX state → scoring impact
--------------------------
ACTIVE_STATES  (affected, exploitable, in_triage, under_investigation)
    → CVE is real and active for this component → included in CVE boost scoring

FIXED_STATES   (fixed, resolved, resolved_with_pedigree)
    → Vulnerability has been remediated → excluded from scoring (acts as a
      D3FEND-equivalent mitigation discount)

IGNORED_STATES (not_affected, false_positive, will_not_fix)
    → Not exploitable in this context → excluded from scoring entirely

VEX file resolution order (mirrors _get_bom_loader):
1. DSL ``## Context: vex_file=<path>``      — single-file explicit reference
2. DSL ``## Context: vex_directory=<path>`` — directory of VEX files
3. Auto-discovery: ``{model_parent}/VEX/``  — convention-based directory
4. Auto-discovery: ``{model_parent}/vex.json`` — single-file convention
"""

import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, FrozenSet, List, Optional, Set

logger = logging.getLogger(__name__)

# VEX states that indicate an active, exploitable vulnerability
ACTIVE_STATES: FrozenSet[str] = frozenset({
    "affected",
    "exploitable",
    "in_triage",
    "under_investigation",
})

# VEX states that indicate the vulnerability has been remediated
FIXED_STATES: FrozenSet[str] = frozenset({
    "fixed",
    "resolved",
    "resolved_with_pedigree",
})

# VEX states that mean the component is not impacted — ignored from scoring
IGNORED_STATES: FrozenSet[str] = frozenset({
    "not_affected",
    "false_positive",
    "will_not_fix",
})


def _normalize_key(name: str) -> str:
    """Normalize a component name/ref to a lowercase-underscore key."""
    key = str(name).strip().lower()
    key = re.sub(r"[\s\-]+", "_", key)
    key = re.sub(r"[^a-z0-9_]", "", key)
    return key


@dataclass
class VEXEntry:
    """A single CVE entry extracted from a VEX document."""
    cve_id: str          # e.g. "CVE-2021-44228"
    component_ref: str   # component name or bom-ref (normalized)
    state: str           # ACTIVE / FIXED / IGNORED (normalized to our sets)
    detail: str = ""     # human-readable note from analysis.detail


def _parse_vex_document(data: Dict) -> List[VEXEntry]:
    """
    Parse a CycloneDX VEX JSON document and return a list of VEXEntry objects.

    Handles two common structures:
    - Standalone VEX: top-level ``vulnerabilities`` array
    - Embedded in BOM: same structure, ``bomFormat: CycloneDX``
    """
    entries: List[VEXEntry] = []
    vulns = data.get("vulnerabilities") or []

    for vuln in vulns:
        if not isinstance(vuln, dict):
            continue
        cve_id = str(vuln.get("id") or "").strip().upper()
        if not cve_id:
            continue

        # analysis.state (CycloneDX VEX 1.4+)
        analysis = vuln.get("analysis") or {}
        state_raw = str(analysis.get("state") or "affected").strip().lower()
        detail = str(analysis.get("detail") or "").strip()

        # affects[].ref — list of component bom-refs
        affects = vuln.get("affects") or []
        refs: List[str] = []
        for affect in affects:
            if not isinstance(affect, dict):
                continue
            ref = str(affect.get("ref") or affect.get("versions", [{}])[0].get("ref", "")).strip()
            if ref:
                refs.append(ref)

        # If no refs, the vulnerability applies globally (model-level)
        if not refs:
            refs = ["__global__"]

        for ref in refs:
            entries.append(VEXEntry(
                cve_id=cve_id,
                component_ref=_normalize_key(ref),
                state=state_raw,
                detail=detail,
            ))

    return entries


def _load_vex_file(path: Path) -> List[VEXEntry]:
    """Load and parse a single VEX JSON file. Returns empty list on error."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        if not isinstance(data, dict):
            logger.warning("VEXLoader: %s is not a JSON object, skipping", path)
            return []
        entries = _parse_vex_document(data)
        logger.debug("VEXLoader: loaded %d entries from %s", len(entries), path.name)
        return entries
    except json.JSONDecodeError as exc:
        logger.error("VEXLoader: JSON parse error in %s: %s", path, exc)
        return []
    except Exception as exc:
        logger.error("VEXLoader: failed to load %s: %s", path, exc)
        return []


class VEXLoader:
    """
    Loads VEX data from one or more CycloneDX VEX JSON files and exposes
    per-component CVE lists grouped by their exploitability state.

    Usage::

        loader = VEXLoader.from_file("/path/to/vex.json")
        active  = loader.get_active_cves("WebApp")   # CVEs to boost scoring
        fixed   = loader.get_fixed_cves("WebApp")    # CVEs with mitigations
    """

    def __init__(self) -> None:
        # Maps normalised_component_key → {state → set(cve_id)}
        self._by_component: Dict[str, Dict[str, Set[str]]] = {}
        self._total_entries = 0

    # ------------------------------------------------------------------
    # Factories
    # ------------------------------------------------------------------

    @classmethod
    def empty(cls) -> "VEXLoader":
        """Return an empty VEXLoader (no VEX data available)."""
        return cls()

    @classmethod
    def from_file(cls, path: Path) -> "VEXLoader":
        """Build a VEXLoader from a single VEX file."""
        loader = cls()
        entries = _load_vex_file(path)
        loader._ingest(entries)
        logger.info("VEXLoader: loaded %d VEX entries from %s", loader._total_entries, path)
        return loader

    @classmethod
    def from_directory(cls, directory: Path) -> "VEXLoader":
        """Build a VEXLoader from all *.json VEX files in a directory."""
        loader = cls()
        if not directory.is_dir():
            logger.warning("VEXLoader: directory not found: %s", directory)
            return loader
        for f in sorted(directory.iterdir()):
            if f.suffix.lower() == ".json":
                entries = _load_vex_file(f)
                loader._ingest(entries)
        logger.info(
            "VEXLoader: loaded %d VEX entries from directory %s",
            loader._total_entries,
            directory,
        )
        return loader

    @classmethod
    def from_model_path(cls, model_file_path: str) -> Optional["VEXLoader"]:
        """
        Try to discover and load VEX data relative to a model file path.

        Discovery order:
        1. ``{model_parent}/VEX/`` directory
        2. ``{model_parent}/vex.json`` single file
        Returns None if no VEX data is found.
        """
        parent = Path(model_file_path).resolve().parent

        vex_dir = parent / "VEX"
        if vex_dir.is_dir():
            json_files = list(vex_dir.glob("*.json"))
            if json_files:
                loader = cls.from_directory(vex_dir)
                if loader:
                    return loader

        vex_file = parent / "vex.json"
        if vex_file.is_file():
            return cls.from_file(vex_file)

        return None

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _ingest(self, entries: List[VEXEntry]) -> None:
        """Add a list of VEXEntry objects to the internal index."""
        for entry in entries:
            bucket = self._by_component.setdefault(entry.component_ref, {})
            bucket.setdefault(entry.state, set()).add(entry.cve_id)
            # Also store under global if not already global
            if entry.component_ref != "__global__":
                # We keep a per-component store only; callers query by name
                pass
            self._total_entries += 1

    def _cves_for_component(self, component: str, states: FrozenSet[str]) -> List[str]:
        """
        Return sorted CVE IDs for the given component that match any of the
        given states.  Also includes entries stored under ``__global__``.
        """
        key = _normalize_key(component)
        result: Set[str] = set()
        for target_key in (key, "__global__"):
            bucket = self._by_component.get(target_key, {})
            for state, cves in bucket.items():
                if state in states:
                    result.update(cves)
        return sorted(result)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get_active_cves(self, component: str) -> List[str]:
        """
        Return CVE IDs that are in an active/exploitable state for this
        component.  Use this list as the input to CVE boost scoring.
        """
        return self._cves_for_component(component, ACTIVE_STATES)

    def get_fixed_cves(self, component: str) -> List[str]:
        """
        Return CVE IDs that have been fixed/resolved for this component.
        These indicate a remediation is in place (D3FEND-equivalent signal).
        """
        return self._cves_for_component(component, FIXED_STATES)

    def has_data(self) -> bool:
        """Return True if at least one VEX entry was loaded."""
        return self._total_entries > 0

    def __bool__(self) -> bool:
        return self.has_data()
