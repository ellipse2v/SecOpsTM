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

"""Tests for threat_analysis.core.ai_cache.AIThreatCache."""

import json
import tempfile
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from threat_analysis.core.ai_cache import AIThreatCache, _CACHE_FILENAME, _CACHE_VERSION


# ── Fixtures ────────────────────────────────────────────────────────────────

@pytest.fixture
def tmp_model_file(tmp_path):
    """Return a real file path inside a temp directory (model file need not exist)."""
    model = tmp_path / "threat_model.md"
    model.write_text("# dummy")
    return str(model)


@pytest.fixture
def cache(tmp_model_file):
    return AIThreatCache(tmp_model_file)


_SAMPLE_DETAILS = {
    "name": "Backend API",
    "type": "api_server",
    "trust_boundary": "Backend (TRUSTED)",
    "description": "REST API",
    "is_public": False,
    "authentication": "JWT",
    "cia_triad": "Confidentiality: High | Integrity: High | Availability: Medium",
    "security_controls": "WAF: No | IDS: No | IPS: No",
    "machine_type": "unknown",
    "technology_tags": "N/A",
    "business_value": "Not specified",
    "extra_properties": "None",
    "inbound_flows": "  None",
    "outbound_flows": "  None",
    "protocol": None,
}

_SAMPLE_THREATS = [
    {"title": "SQLi", "description": "SQL injection", "category": "Tampering",
     "likelihood": "high", "business_impact": {"severity": "critical"}},
]


# ── compute_hash ────────────────────────────────────────────────────────────

def test_hash_is_20_hex_chars():
    h = AIThreatCache.compute_hash(_SAMPLE_DETAILS)
    assert len(h) == 20
    assert all(c in "0123456789abcdef" for c in h)


def test_hash_deterministic():
    h1 = AIThreatCache.compute_hash(_SAMPLE_DETAILS)
    h2 = AIThreatCache.compute_hash(_SAMPLE_DETAILS)
    assert h1 == h2


def test_hash_order_invariant():
    """Dict insertion order must not affect the hash."""
    d1 = {"a": 1, "b": 2}
    d2 = {"b": 2, "a": 1}
    assert AIThreatCache.compute_hash(d1) == AIThreatCache.compute_hash(d2)


def test_hash_changes_on_attribute_change():
    other = dict(_SAMPLE_DETAILS)
    other["type"] = "database"
    assert AIThreatCache.compute_hash(_SAMPLE_DETAILS) != AIThreatCache.compute_hash(other)


def test_hash_changes_on_name_change():
    other = dict(_SAMPLE_DETAILS)
    other["name"] = "Different Component"
    assert AIThreatCache.compute_hash(_SAMPLE_DETAILS) != AIThreatCache.compute_hash(other)


# ── get / put (in-memory) ───────────────────────────────────────────────────

def test_get_returns_none_on_miss(cache):
    assert cache.get("nonexistent_hash_12345") is None


def test_get_returns_threats_on_hit(cache):
    h = AIThreatCache.compute_hash(_SAMPLE_DETAILS)
    cache.put(h, "Backend API", "LiteLLMProvider", _SAMPLE_THREATS)
    result = cache.get(h)
    assert result == _SAMPLE_THREATS


def test_get_returns_empty_list_on_cached_empty(cache):
    """An empty list is a valid cache value (no threats for this component)."""
    h = "aabbccddeeff00112233"
    cache.put(h, "Actor", "LiteLLMProvider", [])
    assert cache.get(h) == []


def test_put_marks_dirty(cache):
    assert not cache._dirty
    h = AIThreatCache.compute_hash(_SAMPLE_DETAILS)
    cache.put(h, "x", "prov", _SAMPLE_THREATS)
    assert cache._dirty


# ── hit / miss counters ─────────────────────────────────────────────────────

def test_hit_counter_increments(cache):
    h = AIThreatCache.compute_hash(_SAMPLE_DETAILS)
    cache.put(h, "x", "prov", _SAMPLE_THREATS)
    cache.get(h)
    cache.get(h)
    assert cache.hits == 2
    assert cache.misses == 0


def test_miss_counter_increments(cache):
    cache.get("nope_hash_000000000000")
    cache.get("nope_hash_111111111111")
    assert cache.hits == 0
    assert cache.misses == 2


def test_summary_format(cache):
    h = AIThreatCache.compute_hash(_SAMPLE_DETAILS)
    cache.put(h, "x", "prov", _SAMPLE_THREATS)
    cache.get(h)          # hit
    cache.get("miss_h")   # miss
    s = cache.summary()
    assert "1 hit" in s
    assert "1 miss" in s
    assert "50%" in s


def test_summary_all_cached(cache):
    h = AIThreatCache.compute_hash(_SAMPLE_DETAILS)
    cache.put(h, "x", "prov", _SAMPLE_THREATS)
    cache.get(h)
    assert "100%" in cache.summary()


def test_summary_no_calls():
    c = AIThreatCache()
    assert "0%" in c.summary()


# ── persistence ─────────────────────────────────────────────────────────────

def test_save_creates_cache_file(tmp_model_file):
    cache_path = Path(tmp_model_file).parent / _CACHE_FILENAME
    assert not cache_path.exists()

    c = AIThreatCache(tmp_model_file)
    h = AIThreatCache.compute_hash(_SAMPLE_DETAILS)
    c.put(h, "Backend API", "LiteLLMProvider", _SAMPLE_THREATS)
    c.save()

    assert cache_path.exists()


def test_save_writes_valid_json(tmp_model_file):
    c = AIThreatCache(tmp_model_file)
    h = AIThreatCache.compute_hash(_SAMPLE_DETAILS)
    c.put(h, "Backend API", "LiteLLMProvider", _SAMPLE_THREATS)
    c.save()

    cache_path = Path(tmp_model_file).parent / _CACHE_FILENAME
    with cache_path.open() as fh:
        data = json.load(fh)

    assert data["version"] == _CACHE_VERSION
    assert "saved_at" in data
    assert h in data["entries"]
    assert data["entries"][h]["component_name"] == "Backend API"
    assert data["entries"][h]["threats"] == _SAMPLE_THREATS


def test_load_restores_entries(tmp_model_file):
    # Write cache manually.
    cache_path = Path(tmp_model_file).parent / _CACHE_FILENAME
    h = AIThreatCache.compute_hash(_SAMPLE_DETAILS)
    payload = {
        "version": _CACHE_VERSION,
        "saved_at": "2026-01-01T00:00:00+00:00",
        "entries": {
            h: {
                "component_name": "Backend API",
                "generated_at": "2026-01-01T00:00:00+00:00",
                "provider": "LiteLLMProvider",
                "threats": _SAMPLE_THREATS,
            }
        },
    }
    cache_path.write_text(json.dumps(payload))

    # Load via new instance.
    c = AIThreatCache(tmp_model_file)
    assert c.get(h) == _SAMPLE_THREATS


def test_load_discards_wrong_version(tmp_model_file):
    cache_path = Path(tmp_model_file).parent / _CACHE_FILENAME
    h = "aabbccddeeff00112233"
    payload = {
        "version": 99,   # wrong version
        "entries": {h: {"component_name": "x", "generated_at": "", "provider": "", "threats": []}},
    }
    cache_path.write_text(json.dumps(payload))

    c = AIThreatCache(tmp_model_file)
    # Stale entries must NOT be loaded.
    assert c.get(h) is None


def test_save_no_op_when_not_dirty(tmp_model_file):
    c = AIThreatCache(tmp_model_file)
    c.save()  # nothing put → not dirty → no file created
    cache_path = Path(tmp_model_file).parent / _CACHE_FILENAME
    assert not cache_path.exists()


def test_save_no_op_without_model_path():
    """Cache without a model path must not raise even if save() is called."""
    c = AIThreatCache()
    h = "aabbccddeeff00112233"
    c.put(h, "x", "prov", _SAMPLE_THREATS)
    c.save()  # must be a no-op (no cache_path)


def test_round_trip_preserves_threats(tmp_model_file):
    c1 = AIThreatCache(tmp_model_file)
    h = AIThreatCache.compute_hash(_SAMPLE_DETAILS)
    c1.put(h, "Backend API", "LiteLLMProvider", _SAMPLE_THREATS)
    c1.save()

    c2 = AIThreatCache(tmp_model_file)
    assert c2.get(h) == _SAMPLE_THREATS


def test_incremental_save_accumulates_entries(tmp_model_file):
    """Second run adds new entries without losing old ones."""
    details_a = dict(_SAMPLE_DETAILS, name="Component A")
    details_b = dict(_SAMPLE_DETAILS, name="Component B")
    ha = AIThreatCache.compute_hash(details_a)
    hb = AIThreatCache.compute_hash(details_b)

    # First run: cache component A.
    c1 = AIThreatCache(tmp_model_file)
    c1.put(ha, "Component A", "prov", _SAMPLE_THREATS)
    c1.save()

    # Second run: load existing cache, add component B.
    c2 = AIThreatCache(tmp_model_file)
    assert c2.get(ha) == _SAMPLE_THREATS   # A loaded from disk
    c2.put(hb, "Component B", "prov", _SAMPLE_THREATS)
    c2.save()

    # Third run: both A and B should be present.
    c3 = AIThreatCache(tmp_model_file)
    assert c3.get(ha) == _SAMPLE_THREATS
    assert c3.get(hb) == _SAMPLE_THREATS


# ── graceful degradation ────────────────────────────────────────────────────

def test_none_model_path_no_crash():
    c = AIThreatCache(None)
    h = AIThreatCache.compute_hash(_SAMPLE_DETAILS)
    assert c.get(h) is None
    c.put(h, "x", "prov", _SAMPLE_THREATS)
    assert c.get(h) == _SAMPLE_THREATS
    c.save()  # no-op, no error


def test_magicmock_model_path_no_crash():
    """MagicMock passed instead of a path (common in tests) must not raise."""
    c = AIThreatCache(MagicMock())
    assert c.path is None


def test_nonexistent_model_file_falls_back_to_memory(tmp_path):
    c = AIThreatCache(str(tmp_path / "ghost_model.md"))
    assert c.path is None   # file doesn't exist → no cache path


def test_corrupted_cache_file_falls_back_gracefully(tmp_model_file):
    cache_path = Path(tmp_model_file).parent / _CACHE_FILENAME
    cache_path.write_text("{ invalid json !!!")
    # Must not raise.
    c = AIThreatCache(tmp_model_file)
    assert c.size == 0


# ── properties ──────────────────────────────────────────────────────────────

def test_path_property(tmp_model_file):
    c = AIThreatCache(tmp_model_file)
    assert c.path is not None
    assert c.path.name == _CACHE_FILENAME


def test_path_property_none_without_model(cache):
    c = AIThreatCache(None)
    assert c.path is None


def test_size_property(cache):
    assert cache.size == 0
    h = AIThreatCache.compute_hash(_SAMPLE_DETAILS)
    cache.put(h, "x", "prov", _SAMPLE_THREATS)
    assert cache.size == 1
