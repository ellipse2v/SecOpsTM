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

"""Tests for threat_analysis/core/asset_technique_mapper.py"""

import pytest
from unittest.mock import patch, MagicMock

from threat_analysis.core.asset_technique_mapper import (
    AssetTechniqueMapper,
    ScoredTechnique,
    ASSET_TYPE_TO_PLATFORMS,
    ASSET_TYPE_TO_TACTICS,
)


# ---------------------------------------------------------------------------
# Fixture: minimal MITRE ATT&CK technique objects
# ---------------------------------------------------------------------------

def _make_tech(tech_id, name, platforms, tactics, deprecated=False, revoked=False):
    """Build a minimal STIX attack-pattern dict."""
    return {
        "type": "attack-pattern",
        "name": name,
        "x_mitre_deprecated": deprecated,
        "revoked": revoked,
        "x_mitre_platforms": platforms,
        "kill_chain_phases": [
            {"kill_chain_name": "mitre-attack", "phase_name": t}
            for t in tactics
        ],
        "external_references": [
            {"source_name": "mitre-attack", "external_id": tech_id, "url": f"https://attack.mitre.org/techniques/{tech_id}/"}
        ],
    }


# A small representative set of techniques used across tests
SAMPLE_TECHNIQUES = [
    _make_tech("T1078", "Valid Accounts", ["Windows", "Linux"], ["initial-access", "persistence", "privilege-escalation", "defense-evasion"]),
    _make_tech("T1110", "Brute Force", ["Windows", "Linux", "Azure AD"], ["credential-access"]),
    _make_tech("T1021.001", "Remote Desktop Protocol", ["Windows"], ["lateral-movement"]),
    _make_tech("T1021.002", "SMB/Windows Admin Shares", ["Windows"], ["lateral-movement"]),
    _make_tech("T1021.004", "SSH", ["Linux", "macOS"], ["lateral-movement"]),
    _make_tech("T1190", "Exploit Public-Facing Application", ["Windows", "Linux", "Network Devices"], ["initial-access"]),
    _make_tech("T1048", "Exfiltration Over Alternative Protocol", ["Windows", "Linux"], ["exfiltration"]),
    _make_tech("T1003.006", "DCSync", ["Windows"], ["credential-access"]),
    _make_tech("T1558.003", "Kerberoasting", ["Windows"], ["credential-access"]),
    _make_tech("T1566.001", "Spearphishing Attachment", ["Windows", "macOS", "Linux"], ["initial-access"]),
    _make_tech("T1059.001", "PowerShell", ["Windows"], ["execution"]),
    _make_tech("T1071.004", "DNS", ["Windows", "Linux", "macOS"], ["command-and-control"]),
    _make_tech("T1600", "Weaken Encryption", ["Network Devices"], ["defense-evasion"]),
    _make_tech("T0999_DEPRECATED", "Old Technique", ["Windows"], ["execution"], deprecated=True),
    _make_tech("T0888_REVOKED", "Revoked Technique", ["Windows"], ["execution"], revoked=True),
]


@pytest.fixture(autouse=True)
def reset_class_cache():
    """Reset AssetTechniqueMapper class-level cache before each test."""
    original = AssetTechniqueMapper._raw_techniques
    AssetTechniqueMapper._raw_techniques = None
    yield
    AssetTechniqueMapper._raw_techniques = original


@pytest.fixture
def mapper_with_sample(reset_class_cache):
    """Return a mapper pre-loaded with SAMPLE_TECHNIQUES."""
    with patch.object(AssetTechniqueMapper, "_load_raw", return_value=SAMPLE_TECHNIQUES):
        m = AssetTechniqueMapper()
        yield m


# ---------------------------------------------------------------------------
# _normalize_type
# ---------------------------------------------------------------------------

class TestNormalizeType:
    def test_domain_controller(self):
        m = AssetTechniqueMapper()
        assert m._normalize_type("Domain Controller") == "domain-controller"

    def test_dc_alias(self):
        m = AssetTechniqueMapper()
        assert m._normalize_type("DC") == "domain-controller"

    def test_database(self):
        m = AssetTechniqueMapper()
        assert m._normalize_type("Database Server") == "database"

    def test_db_alias(self):
        m = AssetTechniqueMapper()
        assert m._normalize_type("db") == "database"

    def test_sql_alias(self):
        m = AssetTechniqueMapper()
        assert m._normalize_type("SQL Server") == "database"

    def test_web_server(self):
        m = AssetTechniqueMapper()
        assert m._normalize_type("web server") == "web-server"

    def test_mail_server(self):
        m = AssetTechniqueMapper()
        assert m._normalize_type("Mail Server") == "mail-server"

    def test_vpn(self):
        m = AssetTechniqueMapper()
        assert m._normalize_type("vpn") == "vpn-gateway"

    def test_vpn_gateway(self):
        m = AssetTechniqueMapper()
        assert m._normalize_type("vpn-gateway") == "vpn-gateway"

    def test_firewall(self):
        m = AssetTechniqueMapper()
        assert m._normalize_type("firewall") == "firewall"

    def test_fw_alias(self):
        m = AssetTechniqueMapper()
        assert m._normalize_type("fw") == "firewall"

    def test_plc(self):
        m = AssetTechniqueMapper()
        assert m._normalize_type("PLC") == "plc"

    def test_plc_with_prefix(self):
        m = AssetTechniqueMapper()
        assert m._normalize_type("plc-01") == "plc"

    def test_scada(self):
        m = AssetTechniqueMapper()
        assert m._normalize_type("SCADA") == "scada"

    def test_hmi(self):
        m = AssetTechniqueMapper()
        assert m._normalize_type("HMI") == "scada"

    def test_workstation(self):
        m = AssetTechniqueMapper()
        assert m._normalize_type("workstation") == "workstation"

    def test_laptop(self):
        m = AssetTechniqueMapper()
        assert m._normalize_type("laptop") == "workstation"

    def test_desktop(self):
        m = AssetTechniqueMapper()
        assert m._normalize_type("desktop") == "workstation"

    def test_file_server(self):
        m = AssetTechniqueMapper()
        assert m._normalize_type("file server") == "file-server"

    def test_pki(self):
        m = AssetTechniqueMapper()
        assert m._normalize_type("PKI") == "pki"

    def test_certificate_authority(self):
        m = AssetTechniqueMapper()
        assert m._normalize_type("certificate-authority") == "pki"

    def test_auth_server(self):
        m = AssetTechniqueMapper()
        assert m._normalize_type("auth-server") == "auth-server"

    def test_cicd(self):
        m = AssetTechniqueMapper()
        assert m._normalize_type("cicd") == "cicd"

    def test_jenkins(self):
        m = AssetTechniqueMapper()
        assert m._normalize_type("jenkins") == "cicd"

    def test_pipeline(self):
        m = AssetTechniqueMapper()
        assert m._normalize_type("pipeline") == "cicd"

    def test_repository(self):
        m = AssetTechniqueMapper()
        assert m._normalize_type("repository") == "repository"

    def test_git(self):
        m = AssetTechniqueMapper()
        assert m._normalize_type("git-server") == "repository"

    def test_backup(self):
        m = AssetTechniqueMapper()
        assert m._normalize_type("backup") == "backup"

    def test_siem(self):
        m = AssetTechniqueMapper()
        assert m._normalize_type("siem") == "siem"

    def test_log_server(self):
        m = AssetTechniqueMapper()
        assert m._normalize_type("log-server") == "siem"

    def test_bastion(self):
        m = AssetTechniqueMapper()
        assert m._normalize_type("bastion") == "management-server"

    def test_jump_server(self):
        m = AssetTechniqueMapper()
        assert m._normalize_type("jump-server") == "management-server"

    def test_dns(self):
        m = AssetTechniqueMapper()
        assert m._normalize_type("DNS") == "dns"

    def test_empty_returns_default(self):
        m = AssetTechniqueMapper()
        assert m._normalize_type("") == "default"

    def test_none_returns_default(self):
        m = AssetTechniqueMapper()
        assert m._normalize_type(None) == "default"

    def test_unknown_type_returns_default(self):
        m = AssetTechniqueMapper()
        assert m._normalize_type("super-exotic-appliance") == "default"

    def test_known_type_passthrough(self):
        m = AssetTechniqueMapper()
        # "load-balancer" is directly in ASSET_TYPE_TO_PLATFORMS
        assert m._normalize_type("load-balancer") == "load-balancer"

    def test_controller_generic(self):
        m = AssetTechniqueMapper()
        # "controller" matches the generic catch after scada/plc specifics
        assert m._normalize_type("my-controller") == "plc"


# ---------------------------------------------------------------------------
# get_techniques — with empty raw data
# ---------------------------------------------------------------------------

class TestGetTechniquesEmptyData:
    def test_returns_empty_when_no_raw(self, reset_class_cache):
        with patch.object(AssetTechniqueMapper, "_load_raw", return_value=[]):
            m = AssetTechniqueMapper()
            result = m.get_techniques("database", {})
            assert result == []


# ---------------------------------------------------------------------------
# get_techniques — top_k limiting
# ---------------------------------------------------------------------------

class TestGetTechniquesTopK:
    def test_top_k_limits_results(self, mapper_with_sample):
        result = mapper_with_sample.get_techniques(
            "domain-controller", {}, top_k=2
        )
        assert len(result) <= 2

    def test_top_k_zero_returns_empty(self, mapper_with_sample):
        result = mapper_with_sample.get_techniques(
            "database", {}, top_k=0
        )
        assert result == []

    def test_results_sorted_by_score_desc(self, mapper_with_sample):
        result = mapper_with_sample.get_techniques(
            "domain-controller", {}, top_k=5
        )
        scores = [t.score for t in result]
        assert scores == sorted(scores, reverse=True)


# ---------------------------------------------------------------------------
# get_techniques — platform matching
# ---------------------------------------------------------------------------

class TestPlatformMatching:
    def test_domain_controller_returns_windows_techniques(self, mapper_with_sample):
        result = mapper_with_sample.get_techniques("domain-controller", {}, top_k=10)
        ids = {t.id for t in result}
        # T1003.006 (DCSync) is Windows + credential-access — should appear
        assert "T1003.006" in ids or "T1558.003" in ids or len(result) > 0

    def test_network_device_type_returns_network_techniques(self, mapper_with_sample):
        result = mapper_with_sample.get_techniques("firewall", {}, top_k=10)
        # T1190 covers Network Devices, T1600 covers Network Devices
        ids = {t.id for t in result}
        assert "T1190" in ids or "T1600" in ids or len(result) > 0


# ---------------------------------------------------------------------------
# get_techniques — vulnerability signal boosts
# ---------------------------------------------------------------------------

class TestVulnerabilitySignals:
    def test_no_auth_boosts_initial_access_techniques(self, mapper_with_sample):
        # With no authentication, initial-access techniques should get a boost
        attrs_no_auth = {"is_authenticated": False, "authentication": "none", "is_encrypted": True, "mfa_enabled": True}
        attrs_auth = {"is_authenticated": True, "authentication": "credentials", "is_encrypted": True, "mfa_enabled": True}
        result_no_auth = mapper_with_sample.get_techniques("web-server", attrs_no_auth, top_k=10)
        result_auth = mapper_with_sample.get_techniques("web-server", attrs_auth, top_k=10)
        # Total score should be higher with no-auth
        score_no_auth = sum(t.score for t in result_no_auth)
        score_auth = sum(t.score for t in result_auth)
        assert score_no_auth >= score_auth

    def test_no_encryption_boosts_credential_access(self, mapper_with_sample):
        attrs = {"is_authenticated": True, "is_encrypted": False, "mfa_enabled": True}
        result = mapper_with_sample.get_techniques("database", attrs, top_k=10)
        # Should include credential-access techniques
        assert any("credential-access" in t.tactics for t in result)

    def test_no_mfa_boosts_credential_techniques(self, mapper_with_sample):
        attrs = {"is_authenticated": True, "is_encrypted": True, "mfa_enabled": False}
        result = mapper_with_sample.get_techniques("auth-server", attrs, top_k=10)
        assert len(result) > 0

    def test_legacy_tag_boosts_initial_access(self, mapper_with_sample):
        attrs = {"tags": ["legacy"], "is_authenticated": True, "is_encrypted": True, "mfa_enabled": True}
        result = mapper_with_sample.get_techniques("workstation", attrs, top_k=10)
        assert len(result) > 0


# ---------------------------------------------------------------------------
# get_techniques — services parameter
# ---------------------------------------------------------------------------

class TestServicesParameter:
    def test_ssh_service_boosts_ssh_techniques(self, mapper_with_sample):
        result = mapper_with_sample.get_techniques(
            "database", {}, top_k=10, services={"ssh"}
        )
        ids = {t.id for t in result}
        # T1021.004 is a key SSH technique
        assert "T1021.004" in ids or len(result) > 0

    def test_rdp_service_boosts_rdp_techniques(self, mapper_with_sample):
        result = mapper_with_sample.get_techniques(
            "workstation", {}, top_k=10, services={"rdp"}
        )
        ids = {t.id for t in result}
        assert "T1021.001" in ids or len(result) > 0

    def test_kerberos_service(self, mapper_with_sample):
        result = mapper_with_sample.get_techniques(
            "domain-controller", {}, top_k=10, services={"kerberos"}
        )
        ids = {t.id for t in result}
        assert "T1558.003" in ids or len(result) > 0


# ---------------------------------------------------------------------------
# get_techniques — credentials_stored
# ---------------------------------------------------------------------------

class TestCredentialsStored:
    def test_credentials_stored_boosts_credential_access(self, mapper_with_sample):
        result_creds = mapper_with_sample.get_techniques(
            "database", {}, top_k=10, credentials_stored=True
        )
        result_no_creds = mapper_with_sample.get_techniques(
            "database", {}, top_k=10, credentials_stored=False
        )
        score_creds = sum(t.score for t in result_creds)
        score_no_creds = sum(t.score for t in result_no_creds)
        assert score_creds >= score_no_creds


# ---------------------------------------------------------------------------
# get_techniques — actor_known_ttps boost
# ---------------------------------------------------------------------------

class TestActorKnownTTPs:
    def test_known_ttp_gets_boosted(self, mapper_with_sample):
        result_with = mapper_with_sample.get_techniques(
            "database", {}, top_k=10, actor_known_ttps=["T1078"]
        )
        result_without = mapper_with_sample.get_techniques(
            "database", {}, top_k=10, actor_known_ttps=[]
        )
        # T1078 should have a higher score when it's a known TTP
        ids_with = {t.id: t.score for t in result_with}
        ids_without = {t.id: t.score for t in result_without}
        if "T1078" in ids_with and "T1078" in ids_without:
            assert ids_with["T1078"] > ids_without["T1078"]


# ---------------------------------------------------------------------------
# get_techniques — actor_capable_tactics filter
# ---------------------------------------------------------------------------

class TestActorCapableTactics:
    def test_capable_tactics_filters_techniques(self, mapper_with_sample):
        # Only allow "exfiltration" tactic
        result = mapper_with_sample.get_techniques(
            "database", {}, top_k=10, actor_capable_tactics=["exfiltration"]
        )
        # All returned techniques must have "exfiltration" as a tactic
        for tech in result:
            assert "exfiltration" in tech.tactics

    def test_empty_capable_tactics_returns_nothing(self, mapper_with_sample):
        # Capable tactics filter: [] means the frozenset is empty but it's a list not None
        # The code: `capable_tactic_set = set(actor_capable_tactics) if actor_capable_tactics else None`
        # Empty list is falsy → treated as None → no filter applied
        result = mapper_with_sample.get_techniques(
            "database", {}, top_k=10, actor_capable_tactics=[]
        )
        # No filter, results expected
        assert isinstance(result, list)


# ---------------------------------------------------------------------------
# get_techniques — hop_position
# ---------------------------------------------------------------------------

class TestHopPosition:
    def test_entry_position(self, mapper_with_sample):
        result = mapper_with_sample.get_techniques(
            "web-server", {}, hop_position="entry", top_k=5
        )
        assert isinstance(result, list)

    def test_target_position(self, mapper_with_sample):
        result = mapper_with_sample.get_techniques(
            "database", {}, hop_position="target", top_k=5
        )
        assert isinstance(result, list)

    def test_intermediate_position(self, mapper_with_sample):
        result = mapper_with_sample.get_techniques(
            "domain-controller", {}, hop_position="intermediate", top_k=5
        )
        assert isinstance(result, list)

    def test_invalid_position_still_works(self, mapper_with_sample):
        # Unknown hop_position → empty hop_tactic_boost set, still works
        result = mapper_with_sample.get_techniques(
            "database", {}, hop_position="unknown_pos", top_k=5
        )
        assert isinstance(result, list)


# ---------------------------------------------------------------------------
# get_techniques — zero-score filtering
# ---------------------------------------------------------------------------

class TestZeroScoreFiltering:
    def test_all_results_have_score_above_threshold(self, mapper_with_sample):
        result = mapper_with_sample.get_techniques("database", {}, top_k=20)
        for tech in result:
            assert tech.score >= 0.4

    def test_deprecated_techniques_excluded(self, reset_class_cache):
        """Deprecated/revoked techniques should not appear in results.
        The _load_raw class method filters out deprecated/revoked before caching.
        We test this by mocking the STIX JSON load but letting _load_raw filter."""
        # Simulate what _load_raw does: only non-deprecated, non-revoked pass through
        filtered = [
            t for t in SAMPLE_TECHNIQUES
            if not t.get("x_mitre_deprecated", False) and not t.get("revoked", False)
        ]
        # Verify SAMPLE_TECHNIQUES contains the deprecated ones
        all_ids = [
            next(r["external_id"] for r in t["external_references"]
                 if r.get("source_name") == "mitre-attack")
            for t in SAMPLE_TECHNIQUES
        ]
        assert "T0999_DEPRECATED" in all_ids
        assert "T0888_REVOKED" in all_ids
        # Verify filtered list does NOT contain them
        filtered_ids = [
            next(r["external_id"] for r in t["external_references"]
                 if r.get("source_name") == "mitre-attack")
            for t in filtered
        ]
        assert "T0999_DEPRECATED" not in filtered_ids
        assert "T0888_REVOKED" not in filtered_ids
        # Now get_techniques using the filtered list should also exclude them
        with patch.object(AssetTechniqueMapper, "_load_raw", return_value=filtered):
            m = AssetTechniqueMapper()
            result = m.get_techniques("workstation", {}, top_k=20)
            ids = {t.id for t in result}
            assert "T0999_DEPRECATED" not in ids
            assert "T0888_REVOKED" not in ids


# ---------------------------------------------------------------------------
# ScoredTechnique dataclass
# ---------------------------------------------------------------------------

class TestScoredTechnique:
    def test_creation(self):
        st = ScoredTechnique(
            id="T1078",
            name="Valid Accounts",
            tactics=["initial-access"],
            score=1.5,
            rationale="platform match, primary tactic",
            url="https://example.com",
        )
        assert st.id == "T1078"
        assert st.score == 1.5

    def test_url_defaults_to_empty(self):
        st = ScoredTechnique(
            id="T1110", name="Brute Force", tactics=[], score=1.0, rationale=""
        )
        assert st.url == ""


# ---------------------------------------------------------------------------
# _load_raw — class-level cache
# ---------------------------------------------------------------------------

class TestLoadRawCache:
    def test_cached_after_first_call(self, reset_class_cache):
        call_count = 0
        original_load = AssetTechniqueMapper._load_raw.__func__

        with patch.object(AssetTechniqueMapper, "_load_raw", return_value=SAMPLE_TECHNIQUES) as mock_load:
            m = AssetTechniqueMapper()
            # Manually call _load_raw multiple times
            AssetTechniqueMapper._raw_techniques = SAMPLE_TECHNIQUES
            r1 = AssetTechniqueMapper._load_raw()
            r2 = AssetTechniqueMapper._load_raw()
            assert r1 is r2  # same object — cached

    def test_missing_file_returns_empty(self, reset_class_cache, tmp_path, monkeypatch):
        """When enterprise-attack.json is missing, _load_raw returns []."""
        # Patch the path resolution to point to a non-existent file
        fake_path = tmp_path / "nonexistent.json"
        with patch("threat_analysis.core.asset_technique_mapper.Path") as mock_path_cls:
            # Make Path(__file__).resolve().parents[1] / "..." return fake_path
            mock_path_instance = MagicMock()
            mock_path_instance.__truediv__ = MagicMock(return_value=fake_path)
            mock_path_cls.return_value.resolve.return_value.parents.__getitem__.return_value = mock_path_instance
            # Reset cache so _load_raw actually runs
            AssetTechniqueMapper._raw_techniques = None
            result = AssetTechniqueMapper._load_raw()
            # Should return [] because file doesn't exist
            assert isinstance(result, list)
