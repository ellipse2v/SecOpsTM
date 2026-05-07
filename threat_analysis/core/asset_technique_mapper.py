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
AssetTechniqueMapper — maps asset type and attributes to relevant MITRE ATT&CK techniques.

Loads enterprise-attack.json once (lazy, class-level cache) and builds an index of
{(frozenset_of_platforms, frozenset_of_tactics) → technique_list}.

For a given asset, returns a ranked list of ScoredTechnique dicts based on:
  - Platform match (asset OS/type → MITRE platform)
  - Tactic relevance for this asset type
  - Vulnerability signals (no auth, no encryption, legacy, no MFA)
  - Actor known_ttps boost
"""

import json
import logging
import yaml
from pathlib import Path
from typing import Any, Dict, List, Optional, Set
from dataclasses import dataclass

logger = logging.getLogger(__name__)

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_ASSET_TYPES_PATH = _PROJECT_ROOT / "config" / "asset_types_community.yaml"
_PROTOCOLS_PATH = _PROJECT_ROOT / "config" / "protocols_community.yaml"


@dataclass
class ScoredTechnique:
    id: str
    name: str
    tactics: List[str]
    score: float
    rationale: str
    url: str = ""


class AssetTechniqueMapper:
    """Maps asset characteristics to relevant MITRE ATT&CK techniques."""

    _raw_techniques: Optional[List[Dict]] = None  # class-level cache
    _asset_types: Optional[Dict] = None
    _protocols: Optional[Dict] = None
    _scoring_config: Optional[Dict] = None

    @classmethod
    def _load_scoring_config(cls) -> Dict:
        if cls._scoring_config is not None:
            return cls._scoring_config
        scoring_path = _PROJECT_ROOT / "config" / "scoring_config.yaml"
        try:
            with open(scoring_path, "r", encoding="utf-8") as f:
                cls._scoring_config = yaml.safe_load(f) or {}
            logger.info("AssetTechniqueMapper: loaded scoring config")
        except Exception as exc:
            logger.warning("Cannot load scoring_config.yaml: %s — using defaults", exc)
            cls._scoring_config = {}
        return cls._scoring_config

    @classmethod
    def _get_boosts(cls) -> Dict[str, float]:
        """Return technique scoring boosts from scoring_config.yaml with hardcoded fallbacks."""
        defaults = {
            "platform_match": 0.5,
            "primary_tactic": 0.4,
            "hop_position": 0.3,
            "key_technique": 0.6,
            "actor_known_ttp": 0.5,
            "no_auth": 0.3,
            "no_encryption": 0.2,
            "no_mfa": 0.2,
            "legacy": 0.2,
            "service_match": 0.35,
            "key_tech_service": 0.5,
            "credentials_stored": 0.4,
        }
        from_yaml = cls._load_scoring_config().get("technique_mapper", {}).get("boosts", {})
        return {**defaults, **from_yaml}

    @classmethod
    def _get_minimum_score(cls) -> float:
        """Return the minimum technique score threshold (techniques below this are discarded)."""
        return float(
            cls._load_scoring_config().get("technique_mapper", {}).get("minimum_score", 0.4)
        )

    @classmethod
    def _load_raw(cls) -> List[Dict]:
        if cls._raw_techniques is not None:
            return cls._raw_techniques
        stix_path = Path(__file__).resolve().parents[1] / "external_data" / "enterprise-attack.json"
        try:
            with open(stix_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            cls._raw_techniques = [
                obj for obj in data.get("objects", [])
                if obj.get("type") == "attack-pattern"
                and not obj.get("x_mitre_deprecated", False)
                and not obj.get("revoked", False)
            ]
            logger.info("AssetTechniqueMapper: loaded %d techniques", len(cls._raw_techniques))
        except Exception as exc:
            logger.error("AssetTechniqueMapper: cannot load enterprise-attack.json: %s", exc)
            cls._raw_techniques = []
        return cls._raw_techniques

    @classmethod
    def _load_asset_types(cls) -> Dict:
        if cls._asset_types is not None:
            return cls._asset_types
        try:
            with open(_ASSET_TYPES_PATH, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}
            cls._asset_types = data.get("asset_types", {})
            logger.info("AssetTechniqueMapper: loaded %d asset types", len(cls._asset_types))
        except Exception as exc:
            logger.error("Cannot load asset_types_community.yaml: %s", exc)
            cls._asset_types = {}
        return cls._asset_types

    @classmethod
    def _load_protocols(cls) -> Dict:
        if cls._protocols is not None:
            return cls._protocols
        try:
            with open(_PROTOCOLS_PATH, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}
            cls._protocols = data.get("protocols", {})
            logger.info("AssetTechniqueMapper: loaded %d protocols", len(cls._protocols))
        except Exception as exc:
            logger.error("Cannot load protocols_community.yaml: %s", exc)
            cls._protocols = {}
        return cls._protocols

    def get_techniques(
        self,
        asset_type: str,
        asset_attrs: Dict[str, Any],
        hop_position: str = "intermediate",  # "entry" | "intermediate" | "target"
        actor_known_ttps: Optional[List[str]] = None,
        actor_capable_tactics: Optional[List[str]] = None,
        top_k: int = 5,
        services: Optional[Set[str]] = None,
        credentials_stored: bool = False,
    ) -> List[ScoredTechnique]:
        """
        Return top_k ranked techniques for the given asset.

        hop_position:
          "entry"        → favor initial-access, execution
          "intermediate" → favor lateral-movement, credential-access, privilege-escalation
          "target"       → favor collection, exfiltration, impact
        """
        raw = self._load_raw()
        if not raw:
            return []

        boosts = self._get_boosts()
        min_score = self._get_minimum_score()

        # Resolve asset type to platforms and primary tactics
        resolved_type = self._normalize_type(asset_type)
        asset_types = self._load_asset_types()
        entry = asset_types.get(resolved_type, asset_types.get("default", {}))
        platforms = set(entry.get("platforms", ["Windows", "Linux"]))
        primary_tactics = entry.get("tactics", ["initial-access", "execution", "lateral-movement"])
        key_techniques = set(entry.get("key_techniques", []))

        # Determine which tactics are relevant for this hop position
        hop_tactic_boost = {
            "entry": {"initial-access", "execution"},
            "intermediate": {"lateral-movement", "credential-access", "privilege-escalation", "defense-evasion"},
            "target": {"collection", "exfiltration", "impact", "command-and-control"},
        }.get(hop_position, set())

        # Vulnerability signals
        no_auth = not asset_attrs.get("is_authenticated", False) and asset_attrs.get("authentication", "none") in ("none", "", None)
        no_encryption = not asset_attrs.get("is_encrypted", False)
        no_mfa = not asset_attrs.get("mfa_enabled", True)  # default True (assume MFA unless stated)
        legacy = "windows 7" in str(asset_attrs.get("tags", "")).lower() or "legacy" in str(asset_attrs.get("tags", "")).lower()

        capable_tactic_set = set(actor_capable_tactics) if actor_capable_tactics else None
        known_ttp_set = set(actor_known_ttps) if actor_known_ttps else set()

        scored: List[ScoredTechnique] = []

        if services:
            protocols = self._load_protocols()
        else:
            protocols = {}

        for tech in raw:
            tech_platforms = set(tech.get("x_mitre_platforms", []))
            tech_tactics = {
                p["phase_name"]
                for p in tech.get("kill_chain_phases", [])
                if p.get("kill_chain_name") == "mitre-attack"
            }
            ext_refs = tech.get("external_references", [])
            tech_id = next(
                (r["external_id"] for r in ext_refs if r.get("source_name") == "mitre-attack"), None
            )
            tech_url = next(
                (r.get("url", "") for r in ext_refs if r.get("source_name") == "mitre-attack"), ""
            )
            if not tech_id:
                continue

            # Skip if actor cannot perform this tactic
            if capable_tactic_set and not tech_tactics.intersection(capable_tactic_set):
                continue

            score = 0.0
            reasons = []

            # Platform match
            if tech_platforms.intersection(platforms):
                score += boosts.get("platform_match", 0.5)
                reasons.append("platform match")

            # Primary tactic relevance for this asset type
            if tech_tactics.intersection(set(primary_tactics[:3])):  # top 3 primary tactics
                score += boosts.get("primary_tactic", 0.4)
                reasons.append("primary tactic")

            # Hop position tactic boost
            if tech_tactics.intersection(hop_tactic_boost):
                score += boosts.get("hop_position", 0.3)
                reasons.append("hop position")

            # Key technique for this asset type
            if tech_id in key_techniques:
                score += boosts.get("key_technique", 0.6)
                reasons.append("key technique")

            # Actor known TTP boost
            if tech_id in known_ttp_set:
                score += boosts.get("actor_known_ttp", 0.5)
                reasons.append("actor TTP")

            # Vulnerability signal boosts
            if no_auth and tech_tactics.intersection({"initial-access", "lateral-movement"}):
                score += boosts.get("no_auth", 0.3)
                reasons.append("no-auth asset")
            if no_encryption and tech_tactics.intersection({"credential-access"}):
                score += boosts.get("no_encryption", 0.2)
                reasons.append("cleartext")
            if no_mfa and tech_tactics.intersection({"credential-access", "initial-access"}):
                score += boosts.get("no_mfa", 0.2)
                reasons.append("no-MFA")
            if legacy and tech_tactics.intersection({"initial-access", "execution"}):
                score += boosts.get("legacy", 0.2)
                reasons.append("legacy system")

            # Service-specific boosts (protocols exposed by this asset)
            if services:
                for svc in services:
                    proto_entry = protocols.get(svc, {})
                    tactic_boost = set(proto_entry.get("tactic_boost", []))
                    if tech_tactics.intersection(tactic_boost):
                        score += boosts.get("service_match", 0.35)
                        reasons.append(f"service:{svc}")
                        break  # count each technique once for service match
                    proto_key_techs = set(proto_entry.get("key_techniques", []))
                    if tech_id in proto_key_techs:
                        score += boosts.get("key_tech_service", 0.5)
                        reasons.append(f"key-tech:{svc}")
                        break

            # Credentials stored boost
            if credentials_stored and tech_tactics.intersection({"credential-access"}):
                score += boosts.get("credentials_stored", 0.4)
                reasons.append("credentials-stored")

            if score < min_score:
                continue

            scored.append(ScoredTechnique(
                id=tech_id,
                name=tech.get("name", ""),
                tactics=list(tech_tactics),
                score=round(score, 2),
                rationale=", ".join(reasons),
                url=tech_url,
            ))

        # Sort by score descending, return top_k
        scored.sort(key=lambda t: t.score, reverse=True)
        return scored[:top_k]

    def _normalize_type(self, asset_type: str) -> str:
        if not asset_type:
            return "default"
        t = str(asset_type).lower().strip()
        asset_types = self._load_asset_types()
        # Exact key match takes priority
        if t in asset_types:
            return t
        # Fuzzy substring matching — YAML declaration order determines priority
        for type_key, entry in asset_types.items():
            for pattern in entry.get("fuzzy_matches", []):
                if pattern and pattern in t:
                    return type_key
        return "default"
