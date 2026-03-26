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
BOMLoader — loads per-asset Bill of Materials files from a directory.

Primary format: CycloneDX 1.6 JSON (*.cdx.json or *.json)
Fallback format: custom YAML (*.yaml, *.yml) — legacy support

CycloneDX files are named {asset_name_lowercase_underscores}.cdx.json.
YAML files are named {asset_name_lowercase_underscores}.yaml (legacy).

Extracted fields (same dict structure for both formats):
  os_version:          str   — OS component name + version (e.g. "windows_server_2019")
  software_version:    str   — First non-OS component name + version
  running_services:    list  — services[].name values
  known_cves:          list  — ALL vulnerabilities[].id values (regardless of state)
  active_cves:         list  — CVEs with exploitable state (affected/exploitable/in_triage/
                               under_investigation); None when no analysis.state present
  fixed_cves:          list  — CVEs with fixed/resolved state; None when no state present
  detection_level:     str   — secopstm:detection_level property
  credentials_stored:  bool  — secopstm:credentials_stored property
  patch_level:         str   — secopstm:patch_level property
  notes:               str   — secopstm:notes property

VEX state parsing
-----------------
When vulnerabilities[].analysis.state is present (CycloneDX VEX assertions embedded in
the BOM), known_cves is split into active_cves and fixed_cves automatically.
This eliminates the need for a separate VEX file for scanner outputs that combine
inventory and exploitability data in a single CycloneDX document.
"""

import json
import logging
import re
import yaml
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# Accepted CycloneDX file suffixes (checked in priority order)
_CDX_SUFFIXES = (".cdx.json",)
# Generic JSON fallback (plain .json) — lower priority than .cdx.json
_JSON_SUFFIX = ".json"
# Legacy YAML suffixes
_YAML_SUFFIXES = (".yaml", ".yml")

_SECOPSTM_BOOL_PROPS = {"true", "yes", "1"}

# VEX state sets (mirrors vex_loader, kept local to avoid circular import)
_VEX_ACTIVE_STATES = frozenset({
    "affected", "exploitable", "in_triage", "under_investigation",
})
_VEX_FIXED_STATES = frozenset({
    "fixed", "resolved", "resolved_with_pedigree",
})


def _normalize_asset_key(name: str) -> str:
    """Normalize an asset name to a lowercase-underscore key for dict lookup."""
    key = name.strip().lower()
    key = re.sub(r"[\s\-]+", "_", key)
    key = re.sub(r"[^a-z0-9_]", "", key)
    return key


def _get_secopstm_prop(properties: List[Dict[str, Any]], prop_name: str) -> Optional[str]:
    """Extract a secopstm: property value from a CycloneDX properties list."""
    full_key = f"secopstm:{prop_name}"
    for prop in properties:
        if isinstance(prop, dict) and prop.get("name") == full_key:
            return str(prop["value"]) if prop.get("value") is not None else None
    return None


def _parse_cyclonedx(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Parse a CycloneDX 1.6 JSON dict into the SecOpsTM BOM dict.

    Returns a dict with keys: os_version, software_version, running_services,
    known_cves, detection_level, credentials_stored, patch_level, notes.
    Missing fields default to None / empty list.
    """
    components: List[Dict[str, Any]] = data.get("components") or []
    services_list: List[Dict[str, Any]] = data.get("services") or []
    vulns: List[Dict[str, Any]] = data.get("vulnerabilities") or []
    properties: List[Dict[str, Any]] = data.get("properties") or []

    # --- os_version: first component with type "operating-system" ---
    os_version: Optional[str] = None
    first_non_os_component: Optional[Dict[str, Any]] = None

    for comp in components:
        if not isinstance(comp, dict):
            continue
        comp_type = comp.get("type", "").lower()
        comp_name = comp.get("name", "")
        comp_ver = comp.get("version", "")

        if comp_type == "operating-system" and os_version is None:
            # Build underscore-normalized version string (e.g. "ubuntu_22.04.5")
            parts = [p for p in [comp_name, comp_ver] if p]
            raw = "_".join(parts)
            os_version = re.sub(r"[\s]+", "_", raw)
        elif comp_type != "operating-system" and first_non_os_component is None:
            first_non_os_component = comp

    # --- software_version: first non-OS component ---
    software_version: Optional[str] = None
    if first_non_os_component:
        name_part = first_non_os_component.get("name", "")
        ver_part = first_non_os_component.get("version", "")
        parts = [p for p in [name_part, ver_part] if p]
        software_version = " ".join(parts) if parts else None

    # --- running_services ---
    running_services: List[str] = [
        s["name"] for s in services_list if isinstance(s, dict) and s.get("name")
    ]

    # --- CVE lists with optional VEX state parsing ---
    known_cves: List[str] = []
    active_cves: Optional[List[str]] = None  # set only when analysis.state is present
    fixed_cves: Optional[List[str]] = None   # set only when analysis.state is present
    has_vex_states = False

    for v in vulns:
        if not isinstance(v, dict):
            continue
        cve_id = str(v.get("id") or "").strip()
        if not cve_id:
            continue
        known_cves.append(cve_id)
        state_raw = str((v.get("analysis") or {}).get("state") or "").strip().lower()
        if state_raw:
            has_vex_states = True
            if active_cves is None:
                active_cves = []
                fixed_cves = []
            if state_raw in _VEX_ACTIVE_STATES:
                active_cves.append(cve_id)
            elif state_raw in _VEX_FIXED_STATES:
                fixed_cves.append(cve_id)
            # ignored states (not_affected, false_positive, will_not_fix) are excluded

    # --- secopstm: custom properties ---
    detection_level = _get_secopstm_prop(properties, "detection_level")
    patch_level = _get_secopstm_prop(properties, "patch_level")
    notes = _get_secopstm_prop(properties, "notes")

    credentials_raw = _get_secopstm_prop(properties, "credentials_stored")
    credentials_stored: Optional[bool] = None
    if credentials_raw is not None:
        credentials_stored = credentials_raw.strip().lower() in _SECOPSTM_BOOL_PROPS

    return {
        "os_version": os_version,
        "software_version": software_version,
        "running_services": running_services,
        "known_cves": known_cves,
        "active_cves": active_cves,   # None if no VEX states; list if states present
        "fixed_cves": fixed_cves,     # None if no VEX states; list if states present
        "detection_level": detection_level,
        "credentials_stored": credentials_stored,
        "patch_level": patch_level,
        "notes": notes,
    }


def _load_cyclonedx_file(path: Path) -> Optional[Dict[str, Any]]:
    """Load and parse a CycloneDX JSON file. Returns None on error."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            raw = json.load(fh)
        if not isinstance(raw, dict):
            logger.warning("BOMLoader: %s is not a JSON object, skipping", path)
            return None
        if raw.get("bomFormat") != "CycloneDX":
            logger.warning(
                "BOMLoader: %s does not have bomFormat=CycloneDX, skipping", path
            )
            return None
        return _parse_cyclonedx(raw)
    except json.JSONDecodeError as exc:
        logger.error("BOMLoader: JSON parse error in %s: %s", path, exc)
        return None
    except Exception as exc:
        logger.error("BOMLoader: failed to load %s: %s", path, exc)
        return None


def _load_yaml_file(path: Path) -> Optional[Dict[str, Any]]:
    """Load a legacy YAML BOM file. Returns None on error."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
        if not isinstance(data, dict):
            logger.warning("BOMLoader: %s is not a YAML mapping, skipping", path)
            return None
        return data
    except Exception as exc:
        logger.error("BOMLoader: failed to load %s: %s", path, exc)
        return None


class BOMLoader:
    """
    Loads per-asset BOM files from a directory.

    Primary format: CycloneDX 1.6 JSON (*.cdx.json or *.json with bomFormat=CycloneDX).
    Legacy format: custom YAML (*.yaml, *.yml) — still supported for backward compatibility.

    CycloneDX files take precedence over YAML files when both exist for the same asset.

    Usage::

        loader = BOMLoader("/path/to/BOM")
        data = loader.get("Primary Domain Controller")  # case-insensitive
    """

    def __init__(self, bom_directory: Optional[str]) -> None:
        self._data: Dict[str, Dict[str, Any]] = {}
        if not bom_directory:
            return
        bom_path = Path(bom_directory)
        if not bom_path.exists() or not bom_path.is_dir():
            logger.warning("BOMLoader: directory not found: %s", bom_directory)
            return

        # ---- Pass 1: load legacy YAML files (lowest priority) ----
        for f in sorted(bom_path.iterdir()):
            if f.suffix.lower() in _YAML_SUFFIXES:
                asset_key = _normalize_asset_key(f.stem)
                parsed = _load_yaml_file(f)
                if parsed is not None:
                    self._data[asset_key] = parsed
                    logger.debug("BOMLoader: loaded YAML BOM for '%s' from %s", asset_key, f.name)

        # ---- Pass 2: load CycloneDX JSON files (higher priority, overwrite YAML) ----
        # First collect all candidate JSON files
        json_files = sorted(bom_path.iterdir())

        # Handle .cdx.json (compound suffix) before plain .json
        for f in json_files:
            name_lower = f.name.lower()
            if name_lower.endswith(".cdx.json"):
                # stem for .cdx.json: strip 9 characters (".cdx.json")
                stem = f.name[: -len(".cdx.json")]
                asset_key = _normalize_asset_key(stem)
                parsed = _load_cyclonedx_file(f)
                if parsed is not None:
                    self._data[asset_key] = parsed
                    logger.debug(
                        "BOMLoader: loaded CycloneDX BOM for '%s' from %s", asset_key, f.name
                    )

        # Plain .json (only if not already covered by .cdx.json for this asset)
        for f in json_files:
            name_lower = f.name.lower()
            if name_lower.endswith(".json") and not name_lower.endswith(".cdx.json"):
                asset_key = _normalize_asset_key(f.stem)
                if asset_key in self._data:
                    # Already loaded via .cdx.json — skip to avoid overwriting
                    continue
                parsed = _load_cyclonedx_file(f)
                if parsed is not None:
                    self._data[asset_key] = parsed
                    logger.debug(
                        "BOMLoader: loaded JSON BOM for '%s' from %s", asset_key, f.name
                    )

        logger.info(
            "BOMLoader: loaded %d asset BOMs from %s", len(self._data), bom_directory
        )

    def get(self, asset_name: str) -> Dict[str, Any]:
        """Return BOM data for the given asset name (case-insensitive).

        Returns an empty dict if no BOM file is found for this asset.
        """
        key = _normalize_asset_key(str(asset_name))
        return self._data.get(key, {})

    def __bool__(self) -> bool:
        return bool(self._data)
