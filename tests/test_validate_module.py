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

import textwrap
from pathlib import Path

import pytest
import yaml

from threat_analysis.validate import validate_model_dir


MINIMAL_MODEL = textwrap.dedent("""\
    # Threat Model: Test System

    ## Description

    Minimal test system for validation.

    ## Context

    bom_directory = BOM

    ## Boundaries

    - **Internal**: isTrusted=True, type=network-on-prem, line_style=solid,
      description="Internal network"

    ## Actors

    - **User**: boundary=Internal, authenticity=credentials,
      description="Regular user"

    ## Servers

    - **WebApp**: boundary=Internal, type=web-server, machine=virtual,
      classification=INTERNAL, description="Web application"

    ## Data

    - **UserData**: classification=INTERNAL, description="User records"

    ## Dataflows

    - **User to App**: from=User, to=WebApp, protocol=HTTPS,
      isEncrypted=True, isAuthenticated=True
""")


def _write_model(tmp_path: Path, content: str, bom: bool = True) -> Path:
    (tmp_path / "model.md").write_text(content, encoding="utf-8")
    if bom:
        bom_dir = tmp_path / "BOM"
        bom_dir.mkdir()
        (bom_dir / "webapp.yaml").write_text(
            yaml.dump({"asset": "WebApp", "os_version": "Ubuntu 22.04"}),
            encoding="utf-8",
        )
    return tmp_path


def test_valid_minimal_model(tmp_path):
    _write_model(tmp_path, MINIMAL_MODEL)
    failures, _ = validate_model_dir(str(tmp_path))
    assert failures == 0


def test_missing_model_file(tmp_path):
    failures, _ = validate_model_dir(str(tmp_path))
    assert failures >= 1


def test_invalid_server_type(tmp_path):
    bad_model = MINIMAL_MODEL.replace("type=web-server", "type=unknown_type_xyz")
    _write_model(tmp_path, bad_model)
    failures, _ = validate_model_dir(str(tmp_path))
    assert failures >= 1


def test_custom_type_accepted(tmp_path):
    custom_model = MINIMAL_MODEL.replace("type=web-server", "type=uav_aircraft")
    _write_model(tmp_path, custom_model)
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    (config_dir / "asset_types_community.yaml").write_text(
        yaml.dump({
            "asset_types": {
                "uav_aircraft": {
                    "description": "UAV platform",
                    "category": "iot",
                    "platforms": ["Embedded"],
                    "tactics": ["impact"],
                    "key_techniques": ["T1498"],
                    "fuzzy_matches": ["drone"],
                }
            }
        }),
        encoding="utf-8",
    )
    failures, _ = validate_model_dir(str(tmp_path))
    assert failures == 0


def test_broken_boundary_reference(tmp_path):
    bad_model = MINIMAL_MODEL.replace(
        "boundary=Internal, authenticity=credentials",
        "boundary=NonExistent, authenticity=credentials"
    )
    _write_model(tmp_path, bad_model)
    failures, _ = validate_model_dir(str(tmp_path))
    assert failures >= 1


def test_broken_dataflow_reference(tmp_path):
    bad_model = MINIMAL_MODEL.replace("from=User", "from=GhostActor")
    _write_model(tmp_path, bad_model)
    failures, _ = validate_model_dir(str(tmp_path))
    assert failures >= 1


def test_invalid_yaml_in_bom(tmp_path):
    _write_model(tmp_path, MINIMAL_MODEL)
    (tmp_path / "BOM" / "webapp.yaml").write_text("key: [bad yaml\n", encoding="utf-8")
    failures, _ = validate_model_dir(str(tmp_path))
    assert failures >= 1


def test_chinese_in_model_fails(tmp_path):
    chinese_model = MINIMAL_MODEL + "\n<!-- 这是中文 -->\n"
    _write_model(tmp_path, chinese_model)
    failures, _ = validate_model_dir(str(tmp_path))
    assert failures >= 1


def test_bom_multi_word_server_name(tmp_path):
    """BOM normalisation: 'RC Plus Controller' → 'rc_plus_controller.yaml'"""
    model = textwrap.dedent("""\
        # Threat Model: Test System

        ## Description
        Test.

        ## Context
        bom_directory = BOM

        ## Boundaries
        - **Internal**: isTrusted=True, type=network-on-prem, description="Net"

        ## Actors
        - **User**: boundary=Internal, authenticity=credentials, description="User"

        ## Servers
        - **RC Plus Controller**: boundary=Internal, type=workstation, machine=embedded,
          classification=INTERNAL, description="Controller"

        ## Dataflows
        - **User to RC**: from=User, to=RC Plus Controller, protocol=HTTPS,
          isEncrypted=True
    """)
    (tmp_path / "model.md").write_text(model, encoding="utf-8")
    bom_dir = tmp_path / "BOM"
    bom_dir.mkdir()
    # Use the normalised name that _check_bom computes
    (bom_dir / "rc_plus_controller.yaml").write_text(
        yaml.dump({"asset": "RC Plus Controller"}), encoding="utf-8"
    )
    failures, _ = validate_model_dir(str(tmp_path))
    assert failures == 0


def test_missing_bom_file_reported(tmp_path):
    """A server with no corresponding BOM file should produce a failure."""
    (tmp_path / "model.md").write_text(MINIMAL_MODEL, encoding="utf-8")
    bom_dir = tmp_path / "BOM"
    bom_dir.mkdir()
    # Deliberately do NOT create webapp.yaml
    failures, _ = validate_model_dir(str(tmp_path))
    assert failures >= 1
