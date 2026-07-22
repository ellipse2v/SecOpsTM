
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

import pytest
import json
import pandas as pd
from pathlib import Path
from unittest.mock import patch, mock_open, MagicMock
from threat_analysis.core.data_loader import (
    load_attack_techniques,
    load_capec_to_mitre_mapping,
    load_capec_catalog_ids,
    load_stride_to_capec_map,
    load_d3fend_mapping,
    load_nist_mappings,
    load_cis_to_mitre_mapping,
    _clean_string
)

_CACHED_LOADERS = (
    load_attack_techniques,
    load_capec_to_mitre_mapping,
    load_capec_catalog_ids,
    load_stride_to_capec_map,
    load_d3fend_mapping,
    load_nist_mappings,
    load_cis_to_mitre_mapping,
)


@pytest.fixture(autouse=True)
def _clear_data_loader_caches():
    """These loaders are @functools.cache'd for real-world performance (they're
    called from multiple MitreMapping instances / requests). Without clearing
    the cache around each test, the mocked builtins.open/pathlib.Path scenarios
    below would leak into each other within this file, and — since the cache is
    process-global — into any other test module that relies on the real data.
    """
    for loader in _CACHED_LOADERS:
        loader.cache_clear()
    yield
    for loader in _CACHED_LOADERS:
        loader.cache_clear()


@pytest.fixture
def mock_external_data_dir(tmp_path):
    external_data = tmp_path / "threat_analysis" / "external_data"
    external_data.mkdir(parents=True)
    return external_data

def test_load_attack_techniques_file_not_found():
    with patch("builtins.open", side_effect=FileNotFoundError):
        techniques = load_attack_techniques()
        assert techniques == {}

def test_load_attack_techniques_exception():
    with patch("builtins.open", mock_open(read_data="invalid json")):
        techniques = load_attack_techniques()
        assert techniques == {}

def test_load_capec_to_mitre_mapping_file_not_found():
    with patch("builtins.open", side_effect=FileNotFoundError):
        mapping = load_capec_to_mitre_mapping()
        assert mapping == {}

def test_load_capec_to_mitre_mapping_json_error():
    with patch("builtins.open", mock_open(read_data="invalid json")):
        mapping = load_capec_to_mitre_mapping()
        assert mapping == {}

def test_load_capec_to_mitre_mapping_invalid_entry():
    data = [
        {"capec_id": None, "techniques": []},
        {"capec_id": "CAPEC-1", "techniques": [{"taxonomy": "ATT&CK", "id": None}]}
    ]
    with patch("builtins.open", mock_open(read_data=json.dumps(data))):
        mapping = load_capec_to_mitre_mapping()
        assert mapping == {}

def test_load_capec_catalog_ids_file_not_found():
    with patch("builtins.open", side_effect=FileNotFoundError):
        ids = load_capec_catalog_ids()
        assert ids == frozenset()

def test_load_capec_catalog_ids_parses_id_column():
    csv_data = "'ID,Name,Abstraction\n1,Some Pattern,Standard\n66,SQL Injection,Standard\n"
    with patch("builtins.open", mock_open(read_data=csv_data)):
        ids = load_capec_catalog_ids()
        assert ids == frozenset({"CAPEC-1", "CAPEC-66"})

def test_load_capec_catalog_ids_skips_blank_id_rows():
    csv_data = "'ID,Name,Abstraction\n1,Some Pattern,Standard\n,Empty ID Row,Standard\n"
    with patch("builtins.open", mock_open(read_data=csv_data)):
        ids = load_capec_catalog_ids()
        assert ids == frozenset({"CAPEC-1"})

def test_load_capec_catalog_ids_unions_stride_and_mitre_mapping_sources():
    """The CSV (CAPEC_VIEW_ATT&CK_Related_Patterns.csv) is only a narrow
    ATT&CK-linked view of CAPEC, not the master catalog — stride_to_capec.json
    and capec_to_mitre_structured_mapping.json must also contribute IDs, or a
    real, legitimate CAPEC ID that pytm-derived threats reference (but which
    happens to have no ATT&CK mapping) gets wrongly flagged as invalid.
    """
    csv_data = "'ID,Name,Abstraction\n1,Some Pattern,Standard\n"
    stride_json = json.dumps({
        "Tampering": [{"capec_id": "CAPEC-166", "name": "Force the System to Reset Values"}]
    })
    mitre_json = json.dumps([{
        "capec_id": "CAPEC-519",
        "techniques": [{"taxonomy": "ATT&CK", "id": "T1565"}],
    }])

    def _fake_open(path, *args, **kwargs):
        path_str = str(path)
        if "stride_to_capec" in path_str:
            return mock_open(read_data=stride_json)()
        if "capec_to_mitre_structured_mapping" in path_str:
            return mock_open(read_data=mitre_json)()
        return mock_open(read_data=csv_data)()

    with patch("builtins.open", side_effect=_fake_open):
        ids = load_capec_catalog_ids()

    assert ids == frozenset({"CAPEC-1", "CAPEC-166", "CAPEC-519"})

def test_load_stride_to_capec_map_file_not_found():
    with patch("builtins.open", side_effect=FileNotFoundError):
        mapping = load_stride_to_capec_map()
        assert mapping == {}

def test_load_stride_to_capec_map_json_error():
    with patch("builtins.open", mock_open(read_data="invalid json")):
        mapping = load_stride_to_capec_map()
        assert mapping == {}

def test_load_d3fend_mapping_file_not_found():
    with patch("pathlib.Path.exists", return_value=False):
        mapping = load_d3fend_mapping()
        assert mapping == {}

def test_load_d3fend_mapping_empty_file():
    with patch("pathlib.Path.exists", return_value=True), \
         patch("pathlib.Path.stat") as mock_stat:
        mock_stat.return_value.st_size = 0
        mapping = load_d3fend_mapping()
        assert mapping == {}

def test_load_d3fend_mapping_missing_columns():
    df = pd.DataFrame({"Wrong": ["Col"]})
    with patch("pathlib.Path.exists", return_value=True), \
         patch("pathlib.Path.stat") as mock_stat, \
         patch("pandas.read_csv", return_value=df):
        mock_stat.return_value.st_size = 100
        mapping = load_d3fend_mapping()
        assert mapping == {}

def test_load_d3fend_mapping_empty_df():
    df = pd.DataFrame(columns=["ID", "Definition", "D3FEND Technique"])
    with patch("pathlib.Path.exists", return_value=True), \
         patch("pathlib.Path.stat") as mock_stat, \
         patch("pandas.read_csv", return_value=df):
        mock_stat.return_value.st_size = 100
        mapping = load_d3fend_mapping()
        assert mapping == {}

def test_load_d3fend_mapping_unicode_error():
    with patch("pathlib.Path.exists", return_value=True), \
         patch("pathlib.Path.stat") as mock_stat, \
         patch("pandas.read_csv") as mock_read_csv:
        mock_stat.return_value.st_size = 100
        mock_read_csv.side_effect = [UnicodeDecodeError("utf-8", b"", 0, 1, ""), pd.DataFrame({
            "ID": ["D3F-1"], "Definition": ["Def"], "D3FEND Technique": ["Tech"]
        })]
        mapping = load_d3fend_mapping()
        assert "D3F-1" in mapping

def test_load_d3fend_mapping_row_error():
    df = pd.DataFrame({
        "ID": [None, "D3F-2"],
        "Definition": ["Def1", "Def2"],
        "D3FEND Technique": ["Tech1", "Tech2"]
    })
    with patch("pathlib.Path.exists", return_value=True), \
         patch("pathlib.Path.stat") as mock_stat, \
         patch("pandas.read_csv", return_value=df):
        mock_stat.return_value.st_size = 100
        mapping = load_d3fend_mapping()
        assert "D3F-2" in mapping

def test_load_nist_mappings_file_not_found():
    with patch("pathlib.Path.exists", return_value=False):
        mapping = load_nist_mappings()
        assert len(mapping) == 0

def test_load_nist_mappings_missing_columns():
    df = pd.DataFrame({"Wrong": ["Col"]})
    with patch("pathlib.Path.exists", return_value=True), \
         patch("pathlib.Path.stat") as mock_stat, \
         patch("pandas.read_excel", return_value=df):
        mock_stat.return_value.st_size = 100
        mapping = load_nist_mappings()
        assert len(mapping) == 0

def test_load_nist_mappings_exception():
    with patch("pathlib.Path.exists", return_value=True), \
         patch("pathlib.Path.stat") as mock_stat, \
         patch("pandas.read_excel", side_effect=Exception("Excel error")):
        mock_stat.return_value.st_size = 100
        mapping = load_nist_mappings()
        assert len(mapping) == 0

def test_load_cis_to_mitre_mapping_file_not_found():
    with patch("builtins.open", side_effect=FileNotFoundError):
        mapping = load_cis_to_mitre_mapping()
        assert mapping == {}

def test_load_cis_to_mitre_mapping_json_error():
    with patch("builtins.open", mock_open(read_data="invalid json")):
        mapping = load_cis_to_mitre_mapping()
        assert mapping == {}

def test_clean_string():
    assert _clean_string(None) == ""
    assert _clean_string("nan") == ""
    assert _clean_string("  valid  ") == "valid"
    assert _clean_string(123) == "123"
