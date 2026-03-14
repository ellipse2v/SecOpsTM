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
from pathlib import Path
from typing import Any, Dict, List, Optional, Set
from dataclasses import dataclass

logger = logging.getLogger(__name__)

# Map from DSL asset type string → MITRE platform tags
ASSET_TYPE_TO_PLATFORMS = {
    "firewall": ["Network Devices"],
    "domain-controller": ["Windows"],
    "auth-server": ["Windows", "Linux"],
    "database": ["Windows", "Linux"],
    "web-server": ["Windows", "Linux"],
    "api-gateway": ["Windows", "Linux"],
    "file-server": ["Windows", "Linux"],
    "mail-server": ["Windows", "Linux", "Office Suite"],
    "management-server": ["Windows", "Linux"],
    "workstation": ["Windows"],
    "load-balancer": ["Network Devices", "Linux"],
    "vpn": ["Network Devices"],
    "vpn-gateway": ["Network Devices"],
    "plc": ["Linux"],  # HMI/SCADA Windows, PLC Linux/embedded
    "scada": ["Windows", "Linux"],
    "repository": ["Linux"],
    "cicd": ["Linux"],
    "backup": ["Linux", "Windows"],
    "dns": ["Windows", "Linux"],
    "pki": ["Windows"],
    "siem": ["Linux"],
    "default": ["Windows", "Linux"],
}

# Map from DSL asset type → primary tactics for that asset (ordered by likelihood)
ASSET_TYPE_TO_TACTICS = {
    "firewall": ["initial-access", "defense-evasion", "lateral-movement"],
    "domain-controller": ["credential-access", "privilege-escalation", "persistence", "lateral-movement"],
    "auth-server": ["credential-access", "privilege-escalation", "initial-access"],
    "database": ["credential-access", "collection", "exfiltration"],
    "web-server": ["initial-access", "execution", "persistence"],
    "api-gateway": ["initial-access", "execution"],
    "file-server": ["collection", "lateral-movement", "exfiltration"],
    "mail-server": ["initial-access", "collection"],
    "management-server": ["lateral-movement", "privilege-escalation", "execution"],
    "workstation": ["execution", "persistence", "privilege-escalation", "credential-access"],
    "load-balancer": ["initial-access", "defense-evasion"],
    "vpn": ["initial-access", "credential-access"],
    "vpn-gateway": ["initial-access", "credential-access"],
    "plc": ["impact", "execution"],
    "scada": ["initial-access", "execution", "impact"],
    "repository": ["collection", "exfiltration"],
    "cicd": ["execution", "persistence", "lateral-movement"],
    "backup": ["collection", "exfiltration", "impact"],
    "dns": ["defense-evasion", "lateral-movement", "command-and-control"],
    "pki": ["credential-access", "privilege-escalation"],
    "siem": ["defense-evasion", "collection"],
    "default": ["initial-access", "execution", "lateral-movement"],
}

# High-value techniques to always consider for specific asset types (boosted score)
ASSET_TYPE_KEY_TECHNIQUES = {
    "domain-controller": ["T1550.002", "T1558.003", "T1003.006", "T1558.001", "T1003.001", "T1207"],
    "auth-server": ["T1110", "T1212", "T1528", "T1550"],
    "database": ["T1190", "T1078", "T1048", "T1030"],
    "workstation": ["T1566.001", "T1059.001", "T1059.003", "T1204.002", "T1003.001", "T1055"],
    "file-server": ["T1021.002", "T1039", "T1083", "T1135"],
    "mail-server": ["T1566", "T1114", "T1071.003"],
    "vpn-gateway": ["T1078", "T1133", "T1110"],
    "firewall": ["T1190", "T1600", "T1599"],
    "plc": ["T1565.001", "T1498", "T1489"],
    "scada": ["T1021.001", "T1133", "T1078"],
    "cicd": ["T1195.002", "T1059", "T1525"],
    "management-server": ["T1021.001", "T1078", "T1570"],
}

# Map from lowercase protocol → tactiques MITRE qui s'y appliquent directement
PROTOCOL_TO_TACTIC_BOOST = {
    "ssh":      {"initial-access", "lateral-movement"},
    "rdp":      {"initial-access", "lateral-movement"},
    "smb":      {"lateral-movement", "credential-access"},
    "ldap":     {"credential-access", "discovery"},
    "kerberos": {"credential-access"},
    "http":     {"initial-access"},
    "https":    {"initial-access"},
    "sql":      {"credential-access", "collection", "exfiltration"},
    "winrm":    {"lateral-movement", "execution"},
    "rpc":      {"lateral-movement"},
    "ftp":      {"exfiltration"},
    "smtp":     {"initial-access", "collection"},
    "modbus":   {"execution", "impact"},
    "ipsec":    {"initial-access"},
    "dns":      {"command-and-control", "defense-evasion"},
    "sap":      {"credential-access", "collection"},
    "syslog":   {"collection", "defense-evasion"},
}

# Protocol → specific high-value technique IDs (always boosted when service exposed)
PROTOCOL_KEY_TECHNIQUES = {
    "ssh":      ["T1021.004", "T1098.004"],
    "rdp":      ["T1021.001", "T1078"],
    "smb":      ["T1021.002", "T1570", "T1039"],
    "ldap":     ["T1069.002", "T1087.002"],
    "kerberos": ["T1558.003", "T1558.001"],
    "winrm":    ["T1021.006"],
    "sql":      ["T1190", "T1078", "T1048"],
    "modbus":   ["T1565.001", "T1498"],
    "ftp":      ["T1048.003"],
    "smtp":     ["T1566", "T1114"],
    "dns":      ["T1071.004", "T1568"],
}


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

        # Resolve asset type to platforms and primary tactics
        resolved_type = self._normalize_type(asset_type)
        platforms = set(ASSET_TYPE_TO_PLATFORMS.get(resolved_type, ASSET_TYPE_TO_PLATFORMS["default"]))
        primary_tactics = ASSET_TYPE_TO_TACTICS.get(resolved_type, ASSET_TYPE_TO_TACTICS["default"])
        key_techniques = set(ASSET_TYPE_KEY_TECHNIQUES.get(resolved_type, []))

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
                score += 0.5
                reasons.append("platform match")

            # Primary tactic relevance for this asset type
            if tech_tactics.intersection(set(primary_tactics[:3])):  # top 3 primary tactics
                score += 0.4
                reasons.append("primary tactic")

            # Hop position tactic boost
            if tech_tactics.intersection(hop_tactic_boost):
                score += 0.3
                reasons.append("hop position")

            # Key technique for this asset type
            if tech_id in key_techniques:
                score += 0.6
                reasons.append("key technique")

            # Actor known TTP boost
            if tech_id in known_ttp_set:
                score += 0.5
                reasons.append("actor TTP")

            # Vulnerability signal boosts
            if no_auth and tech_tactics.intersection({"initial-access", "lateral-movement"}):
                score += 0.3
                reasons.append("no-auth asset")
            if no_encryption and tech_tactics.intersection({"credential-access"}):
                score += 0.2
                reasons.append("cleartext")
            if no_mfa and tech_tactics.intersection({"credential-access", "initial-access"}):
                score += 0.2
                reasons.append("no-MFA")
            if legacy and tech_tactics.intersection({"initial-access", "execution"}):
                score += 0.2
                reasons.append("legacy system")

            # Service-specific boosts (protocols exposed by this asset)
            if services:
                for svc in services:
                    tactic_boost = PROTOCOL_TO_TACTIC_BOOST.get(svc, set())
                    if tech_tactics.intersection(tactic_boost):
                        score += 0.35
                        reasons.append(f"service:{svc}")
                        break  # count each technique once for service match
                    proto_key_techs = set(PROTOCOL_KEY_TECHNIQUES.get(svc, []))
                    if tech_id in proto_key_techs:
                        score += 0.5
                        reasons.append(f"key-tech:{svc}")
                        break

            # Credentials stored boost
            if credentials_stored and tech_tactics.intersection({"credential-access"}):
                score += 0.4
                reasons.append("credentials-stored")

            # Skip zero-score techniques
            if score < 0.4:
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
        # Handle common variations
        if "domain" in t or "dc" in t:
            return "domain-controller"
        if "database" in t or "db" in t or "sql" in t:
            return "database"
        if "web" in t and "server" in t:
            return "web-server"
        if "mail" in t:
            return "mail-server"
        if "vpn" in t:
            return "vpn-gateway"
        if "firewall" in t or "fw" in t:
            return "firewall"
        if t == "plc" or t.startswith("plc-") or t.endswith("-plc"):
            return "plc"
        if "scada" in t or "hmi" in t:
            return "scada"
        if "controller" in t:  # generic controller after scada/plc specifics
            return "plc"
        if "workstation" in t or "laptop" in t or "desktop" in t:
            return "workstation"
        if "file" in t:
            return "file-server"
        # pki/certificate must come before "auth" because "certificate-authority" contains "auth"
        if "pki" in t or t == "ca" or "certificate" in t:
            return "pki"
        if "auth" in t:
            return "auth-server"
        if "cicd" in t or "ci_cd" in t or "pipeline" in t or "jenkins" in t:
            return "cicd"
        if "repository" in t or "git" in t:
            return "repository"
        if "backup" in t:
            return "backup"
        if "siem" in t or "log" in t:
            return "siem"
        if "jump" in t or "bastion" in t or "paw" in t:
            return "management-server"
        if "dns" in t:
            return "dns"
        # Return as-is if in our known table, else default
        if t in ASSET_TYPE_TO_PLATFORMS:
            return t
        return "default"
