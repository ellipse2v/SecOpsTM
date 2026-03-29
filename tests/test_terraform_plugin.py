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

"""Tests for threat_analysis/iac_plugins/terraform_plugin.py"""

import json
import os
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

import re
import yaml

from threat_analysis.iac_plugins.terraform_plugin import (
    TerraformPlugin,
    _sanitize_name,
    _provider_of,
    _extract_block_body,
    _parse_tf_text,
    _parse_tfstate,
    _infer_internet_facing,
    _infer_credentials_stored,
    _infer_traversal_difficulty,
    _parse_ingress_rules,
)


# ---------------------------------------------------------------------------
# Helper: write temp files
# ---------------------------------------------------------------------------

def write_tf(tmp_dir: Path, name: str, content: str) -> Path:
    p = tmp_dir / name
    p.write_text(content, encoding="utf-8")
    return p


SIMPLE_TF = """
resource "aws_instance" "web_server" {
  ami           = "ami-12345"
  instance_type = "t3.micro"
  subnet_id     = "aws_subnet.public.id"
}

resource "aws_vpc" "main" {
  cidr_block = "10.0.0.0/16"
}

resource "aws_subnet" "public" {
  vpc_id     = "aws_vpc.main.id"
  cidr_block = "10.0.1.0/24"
}
"""

LAMBDA_TF = """
resource "aws_lambda_function" "processor" {
  function_name = "my-processor"
  runtime       = "python3.11"
}
"""

DB_TF = """
resource "aws_rds_instance" "primary_db" {
  engine         = "postgres"
  instance_class = "db.t3.micro"
}
"""

ACTOR_TF = """
resource "aws_iam_user" "deploy_user" {
  name = "deploy"
}
"""

AZURE_TF = """
resource "azurerm_virtual_machine" "app_vm" {
  name = "appvm"
}

resource "azurerm_virtual_network" "vnet" {
  name = "vnet"
}
"""

GCP_TF = """
resource "google_compute_instance" "gce_vm" {
  name = "gce-vm"
}

resource "google_compute_network" "network" {
  name = "gce-network"
}
"""

MULTI_TF = SIMPLE_TF + LAMBDA_TF + DB_TF + ACTOR_TF


# ---------------------------------------------------------------------------
# _sanitize_name
# ---------------------------------------------------------------------------

class TestSanitizeName:
    def test_underscores_to_spaces(self):
        assert _sanitize_name("web_server") == "Web Server"

    def test_hyphens_to_spaces(self):
        assert _sanitize_name("my-bucket") == "My Bucket"

    def test_mixed(self):
        assert _sanitize_name("primary_db_node") == "Primary Db Node"

    def test_already_clean(self):
        assert _sanitize_name("Server") == "Server"

    def test_empty(self):
        assert _sanitize_name("") == ""


# ---------------------------------------------------------------------------
# _provider_of
# ---------------------------------------------------------------------------

class TestProviderOf:
    def test_aws(self):
        assert _provider_of("aws_instance") == "AWS"

    def test_google(self):
        assert _provider_of("google_compute_instance") == "GCP"

    def test_azurerm(self):
        assert _provider_of("azurerm_virtual_machine") == "Azure"

    def test_unknown(self):
        assert _provider_of("some_custom_resource") == "Cloud"

    def test_partial_prefix_not_matched(self):
        assert _provider_of("aws") == "Cloud"


# ---------------------------------------------------------------------------
# _extract_block_body
# ---------------------------------------------------------------------------

class TestExtractBlockBody:
    def test_simple_block(self):
        hcl = '{ key = "val" }'
        body = _extract_block_body(hcl, 0)
        assert 'key = "val"' in body

    def test_nested_braces(self):
        hcl = '{ outer { inner = 1 } }'
        body = _extract_block_body(hcl, 0)
        assert "inner = 1" in body

    def test_unclosed_brace(self):
        hcl = '{ unclosed'
        body = _extract_block_body(hcl, 0)
        assert "unclosed" in body

    def test_empty_block(self):
        hcl = '{}'
        body = _extract_block_body(hcl, 0)
        assert body == ""


# ---------------------------------------------------------------------------
# _parse_tf_text
# ---------------------------------------------------------------------------

class TestParseTfText:
    def test_parses_aws_instance(self):
        resources = _parse_tf_text(SIMPLE_TF)
        types = [r["resource_type"] for r in resources]
        assert "aws_instance" in types

    def test_parses_multiple_resources(self):
        resources = _parse_tf_text(SIMPLE_TF)
        assert len(resources) == 3

    def test_resource_has_name(self):
        resources = _parse_tf_text(SIMPLE_TF)
        names = [r["name"] for r in resources]
        assert "web_server" in names

    def test_scalar_attribute_extracted(self):
        resources = _parse_tf_text(SIMPLE_TF)
        instance = next(r for r in resources if r["name"] == "web_server")
        assert instance["attributes"].get("instance_type") == "t3.micro"

    def test_empty_text(self):
        assert _parse_tf_text("") == []

    def test_no_resource_blocks(self):
        hcl = 'provider "aws" { region = "us-east-1" }'
        assert _parse_tf_text(hcl) == []

    def test_lambda_resource(self):
        resources = _parse_tf_text(LAMBDA_TF)
        assert resources[0]["resource_type"] == "aws_lambda_function"

    def test_list_attribute(self):
        hcl = '''
resource "aws_security_group" "sg" {
  ingress_rules = ["rule1", "rule2"]
}
'''
        resources = _parse_tf_text(hcl)
        assert resources[0]["attributes"].get("ingress_rules") == ["rule1", "rule2"]

    def test_skips_meta_scalar_attributes(self):
        hcl = '''
resource "aws_instance" "test" {
  count      = 1
  lifecycle  = {}
  ami        = "ami-123"
}
'''
        resources = _parse_tf_text(hcl)
        attrs = resources[0]["attributes"]
        # scalar meta-attributes filtered in scalar parser
        assert "count" not in attrs
        assert "lifecycle" not in attrs
        assert attrs.get("ami") == "ami-123"


# ---------------------------------------------------------------------------
# _parse_tfstate
# ---------------------------------------------------------------------------

class TestParseTfstate:
    def _write_state(self, tmp_path: Path, state: dict) -> Path:
        p = tmp_path / "terraform.tfstate"
        p.write_text(json.dumps(state), encoding="utf-8")
        return p

    def test_parses_managed_resource(self, tmp_path):
        state = {
            "version": 4,
            "resources": [
                {
                    "mode": "managed",
                    "type": "aws_instance",
                    "name": "web",
                    "instances": [{"attributes": {"instance_type": "t3.micro", "ami": "ami-1"}}],
                }
            ],
        }
        p = self._write_state(tmp_path, state)
        resources = _parse_tfstate(p)
        assert len(resources) == 1
        assert resources[0]["resource_type"] == "aws_instance"
        assert resources[0]["attributes"]["instance_type"] == "t3.micro"

    def test_skips_data_resources(self, tmp_path):
        state = {
            "version": 4,
            "resources": [
                {"mode": "data", "type": "aws_ami", "name": "ubuntu", "instances": []},
            ],
        }
        p = self._write_state(tmp_path, state)
        assert _parse_tfstate(p) == []

    def test_skips_empty_instances(self, tmp_path):
        state = {
            "version": 4,
            "resources": [
                {"mode": "managed", "type": "aws_instance", "name": "x", "instances": []},
            ],
        }
        p = self._write_state(tmp_path, state)
        assert _parse_tfstate(p) == []

    def test_handles_old_version(self, tmp_path):
        state = {"version": 3, "resources": []}
        p = self._write_state(tmp_path, state)
        assert _parse_tfstate(p) == []

    def test_handles_missing_file(self, tmp_path):
        assert _parse_tfstate(tmp_path / "nonexistent.tfstate") == []

    def test_handles_invalid_json(self, tmp_path):
        p = tmp_path / "bad.tfstate"
        p.write_text("not json", encoding="utf-8")
        assert _parse_tfstate(p) == []

    def test_flattens_list_attributes(self, tmp_path):
        state = {
            "version": 4,
            "resources": [
                {
                    "mode": "managed",
                    "type": "aws_instance",
                    "name": "web",
                    "instances": [{"attributes": {"tags": ["a", "b"]}}],
                }
            ],
        }
        p = self._write_state(tmp_path, state)
        resources = _parse_tfstate(p)
        assert resources[0]["attributes"]["tags"] == ["a", "b"]

    def test_ignores_nested_dict_attributes(self, tmp_path):
        state = {
            "version": 4,
            "resources": [
                {
                    "mode": "managed",
                    "type": "aws_instance",
                    "name": "web",
                    "instances": [{"attributes": {"nested": {"key": "val"}, "ami": "ami-1"}}],
                }
            ],
        }
        p = self._write_state(tmp_path, state)
        resources = _parse_tfstate(p)
        assert "nested" not in resources[0]["attributes"]
        assert resources[0]["attributes"]["ami"] == "ami-1"


# ---------------------------------------------------------------------------
# TerraformPlugin.parse_iac_config
# ---------------------------------------------------------------------------

class TestParseIacConfig:
    def test_raises_for_missing_path(self, tmp_path):
        plugin = TerraformPlugin()
        with pytest.raises(ValueError, match="does not exist"):
            plugin.parse_iac_config(str(tmp_path / "nonexistent"))

    def test_raises_for_non_tf_file(self, tmp_path):
        p = tmp_path / "config.yaml"
        p.write_text("key: val")
        plugin = TerraformPlugin()
        with pytest.raises(ValueError, match=".tf"):
            plugin.parse_iac_config(str(p))

    def test_single_tf_file(self, tmp_path):
        p = write_tf(tmp_path, "main.tf", SIMPLE_TF)
        plugin = TerraformPlugin()
        result = plugin.parse_iac_config(str(p))
        assert "resources" in result
        assert len(result["resources"]) == 3

    def test_directory_scans_all_tf(self, tmp_path):
        write_tf(tmp_path, "main.tf", SIMPLE_TF)
        write_tf(tmp_path, "lambda.tf", LAMBDA_TF)
        plugin = TerraformPlugin()
        result = plugin.parse_iac_config(str(tmp_path))
        types = [r["resource_type"] for r in result["resources"]]
        assert "aws_instance" in types
        assert "aws_lambda_function" in types

    def test_directory_uses_tfstate_when_present(self, tmp_path):
        write_tf(tmp_path, "main.tf", SIMPLE_TF)
        state = {
            "version": 4,
            "resources": [
                {
                    "mode": "managed",
                    "type": "aws_rds_instance",
                    "name": "db",
                    "instances": [{"attributes": {"engine": "mysql"}}],
                }
            ],
        }
        (tmp_path / "terraform.tfstate").write_text(json.dumps(state))
        plugin = TerraformPlugin()
        result = plugin.parse_iac_config(str(tmp_path))
        # tfstate should take priority — only the rds resource
        types = [r["resource_type"] for r in result["resources"]]
        assert types == ["aws_rds_instance"]

    def test_empty_directory_raises(self, tmp_path):
        plugin = TerraformPlugin()
        with pytest.raises(ValueError, match="No .tf files"):
            plugin.parse_iac_config(str(tmp_path))

    def test_plugin_name(self):
        assert TerraformPlugin().name == "terraform"

    def test_plugin_description(self):
        desc = TerraformPlugin().description
        assert "Terraform" in desc


# ---------------------------------------------------------------------------
# TerraformPlugin.generate_threat_model_components
# ---------------------------------------------------------------------------

class TestGenerateThreatModelComponents:
    def _parse_and_generate(self, tf_text: str) -> str:
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "main.tf"
            p.write_text(tf_text, encoding="utf-8")
            plugin = TerraformPlugin()
            iac_data = plugin.parse_iac_config(str(p))
            return plugin.generate_threat_model_components(iac_data)

    def test_servers_section(self):
        md = self._parse_and_generate(SIMPLE_TF + LAMBDA_TF)
        assert "## Servers" in md
        assert "Web Server" in md

    def test_boundaries_section(self):
        md = self._parse_and_generate(SIMPLE_TF)
        assert "## Boundaries" in md
        assert "Main" in md

    def test_actors_section(self):
        md = self._parse_and_generate(ACTOR_TF)
        assert "## Actors" in md
        assert "Deploy User" in md

    def test_dataflows_section(self):
        # SIMPLE_TF connects a server to a subnet (boundary); since dataflows cannot
        # terminate at boundaries, no ## Dataflows section is generated.
        # A server-to-server ref is required to produce dataflows.
        md = self._parse_and_generate(SIMPLE_TF)
        assert "## Boundaries" in md  # boundaries are still rendered
        assert "## Servers" in md     # servers are still rendered

    def test_azure_resources(self):
        md = self._parse_and_generate(AZURE_TF)
        assert "App Vm" in md
        assert "Vnet" in md

    def test_gcp_resources(self):
        md = self._parse_and_generate(GCP_TF)
        assert "Gce Vm" in md

    def test_empty_resources(self):
        plugin = TerraformPlugin()
        # No resources → no components → empty output (description is skipped too).
        md = plugin.generate_threat_model_components({"resources": []})
        assert md.strip() == ""

    def test_unknown_resource_skipped(self):
        tf = '''
resource "custom_provider_thing" "x" {
  name = "x"
}
'''
        md = self._parse_and_generate(tf)
        assert "## Servers" not in md

    def test_nested_boundaries_rendered(self):
        tf = """
resource "aws_vpc" "main" {
  cidr_block = "10.0.0.0/16"
}
resource "aws_subnet" "pub" {
  vpc_id     = "aws_vpc.main.id"
  cidr_block = "10.0.1.0/24"
}
"""
        md = self._parse_and_generate(tf)
        assert "## Boundaries" in md
        assert "Pub" in md

    def test_no_top_level_boundary_only_nested(self):
        tf = """
resource "aws_subnet" "private" {
  cidr_block = "10.0.2.0/24"
}
"""
        md = self._parse_and_generate(tf)
        assert "## Boundaries" in md
        assert "Private" in md

    def test_database_type(self):
        md = self._parse_and_generate(DB_TF)
        assert "database" in md

    def test_serverless_type(self):
        md = self._parse_and_generate(LAMBDA_TF)
        assert "serverless" in md


# ---------------------------------------------------------------------------
# TerraformPlugin._resolve_ref
# ---------------------------------------------------------------------------

class TestResolveRef:
    def test_three_part_resource_ref(self):
        result = TerraformPlugin._resolve_ref("aws_vpc.main.id")
        assert result == "aws_vpc.main"

    def test_two_part_resource_ref(self):
        result = TerraformPlugin._resolve_ref("aws_vpc.main")
        assert result == "aws_vpc.main"

    def test_interpolation_stripped(self):
        result = TerraformPlugin._resolve_ref("${aws_vpc.main.id}")
        assert result == "aws_vpc.main"

    def test_bare_string_returns_none(self):
        assert TerraformPlugin._resolve_ref("sg-0abc123") is None

    def test_no_underscore_in_type_returns_none(self):
        assert TerraformPlugin._resolve_ref("vpc.main") is None

    def test_single_segment_returns_none(self):
        assert TerraformPlugin._resolve_ref("justvalue") is None


# ---------------------------------------------------------------------------
# TerraformPlugin._derive_dataflows
# ---------------------------------------------------------------------------

class TestDeriveDataflows:
    def test_dataflow_from_subnet_ref(self):
        # Boundary refs (subnet_id → boundary) are now correctly skipped: dataflows
        # cannot terminate at a boundary — they must connect servers or actors.
        plugin = TerraformPlugin()
        servers = [
            {
                "name": "Web Server",
                "_tf_key": "aws_instance.web",
                "_attrs": {"subnet_id": "aws_subnet.pub.id"},
            }
        ]
        boundaries = [
            {
                "name": "Pub",
                "_tf_key": "aws_subnet.pub",
                "_attrs": {},
            }
        ]
        flows = plugin._derive_dataflows(servers, boundaries, [], {"aws_subnet.pub": "Pub"})
        assert flows == []  # boundary refs produce no dataflows

    def test_no_self_loop(self):
        plugin = TerraformPlugin()
        servers = [
            {
                "name": "Same",
                "_tf_key": "aws_instance.same",
                "_attrs": {"vpc_id": "aws_instance.same.id"},
            }
        ]
        boundaries = [{"name": "Same", "_tf_key": "aws_instance.same", "_attrs": {}}]
        flows = plugin._derive_dataflows(servers, boundaries, [], {})
        assert flows == []

    def test_deduplication(self):
        # Both subnet_id and security_groups reference a boundary — both are now
        # skipped (boundary endpoints are invalid). No dataflows produced.
        plugin = TerraformPlugin()
        servers = [
            {
                "name": "App",
                "_tf_key": "aws_instance.app",
                "_attrs": {
                    "subnet_id": "aws_subnet.pub.id",
                    "security_groups": ["aws_subnet.pub.id"],
                },
            }
        ]
        boundaries = [{"name": "Pub", "_tf_key": "aws_subnet.pub", "_attrs": {}}]
        flows = plugin._derive_dataflows(servers, boundaries, [], {"aws_subnet.pub": "Pub"})
        assert flows == []  # boundary refs produce no dataflows (dedup of zero is still zero)

    def test_server_to_server_dataflow(self):
        plugin = TerraformPlugin()
        servers = [
            {
                "name": "Lb",
                "_tf_key": "aws_lb.lb",
                "_attrs": {"subnet_ids": ["aws_instance.app.id"]},
            },
            {
                "name": "App",
                "_tf_key": "aws_instance.app",
                "_attrs": {},
            },
        ]
        flows = plugin._derive_dataflows(servers, [], [], {})
        assert any(f["source"] == "Lb" and f["destination"] == "App" for f in flows)


# ---------------------------------------------------------------------------
# _render_markdown
# ---------------------------------------------------------------------------

class TestRenderMarkdown:
    def test_empty_lists(self):
        plugin = TerraformPlugin()
        assert plugin._render_markdown([], [], [], []) == ""

    def test_only_servers(self):
        plugin = TerraformPlugin()
        md = plugin._render_markdown(
            [],
            [],
            [{"name": "App", "type": "server", "description": "AWS ec2", "_tf_key": "k", "_attrs": {}}],
            [],
        )
        assert "## Servers" in md
        assert "App" in md
        assert "## Boundaries" not in md

    def test_dataflow_format(self):
        plugin = TerraformPlugin()
        md = plugin._render_markdown(
            [],
            [],
            [],
            [{"name": "A To B", "source": "A", "destination": "B", "protocol": "HTTPS", "data": "AppData"}],
        )
        assert "## Dataflows" in md
        assert 'from="A"' in md
        assert 'to="B"' in md

    def test_boundary_trusted_flag(self):
        plugin = TerraformPlugin()
        md = plugin._render_markdown(
            [{"name": "Vpc", "isTrusted": "false", "description": "AWS vpc", "_nested": False, "_tf_key": "k", "_attrs": {}}],
            [], [], [],
        )
        assert "isTrusted=false" in md

    def test_actor_format(self):
        plugin = TerraformPlugin()
        md = plugin._render_markdown(
            [], [{"name": "Admin", "description": "AWS iam user", "_tf_key": "k", "_attrs": {}}], [], []
        )
        assert "## Actors" in md
        assert "Admin" in md


# ---------------------------------------------------------------------------
# DSL syntax validation helpers
# ---------------------------------------------------------------------------

_DSL_LINE_RE = re.compile(r"^- \*\*[^*]+\*\*: .+$")
_VALID_TRAVERSAL = {"low", "medium", "high"}
_VALID_BOOL = {"true", "false"}


def _assert_dsl_syntax(markdown: str) -> None:
    """Assert that every component line in the DSL follows the expected format."""
    in_section = False
    for line in markdown.splitlines():
        if line.startswith("## "):
            in_section = True
            continue
        if not line.strip():
            in_section = False
            continue
        if in_section and line.startswith("-"):
            assert _DSL_LINE_RE.match(line), (
                f"DSL line does not match expected format: {line!r}"
            )
            # Check boolean values are lowercase
            for attr in re.findall(r"(?:internet_facing|credentials_stored|isTrusted)=(\S+?)(?:[,\s]|$)", line):
                attr_clean = attr.rstrip(",")
                assert attr_clean in _VALID_BOOL, (
                    f"Boolean attribute must be 'true' or 'false', got: {attr_clean!r}"
                )
            # Check traversal_difficulty values
            for val in re.findall(r"traversal_difficulty=(\S+?)(?:[,\s]|$)", line):
                val_clean = val.rstrip(",")
                assert val_clean in _VALID_TRAVERSAL, (
                    f"traversal_difficulty must be low/medium/high, got: {val_clean!r}"
                )


# ---------------------------------------------------------------------------
# _infer_internet_facing
# ---------------------------------------------------------------------------

class TestInferInternetFacing:
    def test_associate_public_ip_true(self):
        assert _infer_internet_facing({"associate_public_ip_address": "true"}) is True

    def test_associate_public_ip_false(self):
        assert _infer_internet_facing({"associate_public_ip_address": "false"}) is False

    def test_public_ip_set(self):
        assert _infer_internet_facing({"public_ip": "1.2.3.4"}) is True

    def test_public_ip_empty_string(self):
        assert _infer_internet_facing({"public_ip": ""}) is False

    def test_public_ip_null(self):
        assert _infer_internet_facing({"public_ip": "null"}) is False

    def test_publicly_accessible_rds(self):
        assert _infer_internet_facing({"publicly_accessible": "true"}) is True

    def test_publicly_accessible_false(self):
        assert _infer_internet_facing({"publicly_accessible": "false"}) is False

    def test_no_public_attrs(self):
        assert _infer_internet_facing({"instance_type": "t3.micro"}) is False

    def test_empty_attrs(self):
        assert _infer_internet_facing({}) is False


# ---------------------------------------------------------------------------
# _infer_credentials_stored
# ---------------------------------------------------------------------------

class TestInferCredentialsStored:
    def test_iam_instance_profile(self):
        assert _infer_credentials_stored({"iam_instance_profile": "my-role"}) is True

    def test_iam_instance_profile_arn(self):
        assert _infer_credentials_stored(
            {"iam_instance_profile_arn": "arn:aws:iam::123:instance-profile/role"}
        ) is True

    def test_env_var_password(self):
        assert _infer_credentials_stored(
            {"environment": json.dumps({"DB_PASSWORD": "secret"})}
        ) is True

    def test_env_var_token(self):
        assert _infer_credentials_stored(
            {"environment": json.dumps({"API_TOKEN": "abc"})}
        ) is True

    def test_env_var_no_credential(self):
        assert _infer_credentials_stored(
            {"environment": json.dumps({"APP_NAME": "myapp"})}
        ) is False

    def test_no_sensitive_attrs(self):
        assert _infer_credentials_stored({"instance_type": "t3.micro"}) is False

    def test_empty_attrs(self):
        assert _infer_credentials_stored({}) is False

    def test_env_list_with_password(self):
        env_list = [{"name": "DB_PASSWORD", "value": "s3cr3t"}]
        assert _infer_credentials_stored(
            {"environment": json.dumps(env_list)}
        ) is True


# ---------------------------------------------------------------------------
# _parse_ingress_rules / _infer_traversal_difficulty
# ---------------------------------------------------------------------------

_OPEN_ANY_PORT_SG = [
    {
        "cidr_blocks": ["0.0.0.0/0"],
        "ipv6_cidr_blocks": [],
        "from_port": -1,
        "to_port": -1,
        "protocol": "-1",
    }
]

_OPEN_SPECIFIC_PORT_SG = [
    {
        "cidr_blocks": ["0.0.0.0/0"],
        "ipv6_cidr_blocks": [],
        "from_port": 443,
        "to_port": 443,
        "protocol": "tcp",
    }
]

_RESTRICTED_SG = [
    {
        "cidr_blocks": ["10.0.0.0/8"],
        "ipv6_cidr_blocks": [],
        "from_port": 22,
        "to_port": 22,
        "protocol": "tcp",
    }
]


class TestParseIngressRules:
    def test_json_string_parsed(self):
        rules = _parse_ingress_rules({"ingress": json.dumps(_OPEN_ANY_PORT_SG)})
        assert len(rules) == 1
        assert rules[0]["protocol"] == "-1"

    def test_list_passed_through(self):
        rules = _parse_ingress_rules({"ingress": _OPEN_ANY_PORT_SG})
        assert len(rules) == 1

    def test_empty_returns_empty(self):
        assert _parse_ingress_rules({}) == []

    def test_invalid_json_returns_empty(self):
        assert _parse_ingress_rules({"ingress": "not-json"}) == []


class TestInferTraversalDifficulty:
    def test_open_any_port_is_low(self):
        assert _infer_traversal_difficulty(
            {"ingress": json.dumps(_OPEN_ANY_PORT_SG)}
        ) == "low"

    def test_open_specific_port_is_medium(self):
        assert _infer_traversal_difficulty(
            {"ingress": json.dumps(_OPEN_SPECIFIC_PORT_SG)}
        ) == "medium"

    def test_restricted_sg_is_high(self):
        assert _infer_traversal_difficulty(
            {"ingress": json.dumps(_RESTRICTED_SG)}
        ) == "high"

    def test_no_rules_is_medium(self):
        assert _infer_traversal_difficulty({}) == "medium"

    def test_empty_rules_list_is_medium(self):
        assert _infer_traversal_difficulty({"ingress": json.dumps([])}) == "medium"

    def test_ipv6_open_is_low(self):
        rule = [
            {
                "cidr_blocks": [],
                "ipv6_cidr_blocks": ["::/0"],
                "from_port": -1,
                "to_port": -1,
                "protocol": "-1",
            }
        ]
        assert _infer_traversal_difficulty({"ingress": json.dumps(rule)}) == "low"

    def test_mixed_open_and_restricted_is_low(self):
        mixed = _OPEN_ANY_PORT_SG + _RESTRICTED_SG
        assert _infer_traversal_difficulty({"ingress": json.dumps(mixed)}) == "low"


# ---------------------------------------------------------------------------
# tfstate: list-of-dicts preservation
# ---------------------------------------------------------------------------

class TestTfstateIngressPreservation:
    def _write_state(self, tmp_path: Path, state: dict) -> Path:
        p = tmp_path / "terraform.tfstate"
        p.write_text(json.dumps(state), encoding="utf-8")
        return p

    def test_ingress_rules_preserved_as_json_string(self, tmp_path):
        state = {
            "version": 4,
            "resources": [
                {
                    "mode": "managed",
                    "type": "aws_security_group",
                    "name": "web_sg",
                    "instances": [
                        {
                            "attributes": {
                                "name": "web-sg",
                                "ingress": _OPEN_ANY_PORT_SG,
                            }
                        }
                    ],
                }
            ],
        }
        p = self._write_state(tmp_path, state)
        resources = _parse_tfstate(p)
        assert len(resources) == 1
        ingress_raw = resources[0]["attributes"]["ingress"]
        assert isinstance(ingress_raw, str), "ingress should be JSON-serialised string"
        parsed = json.loads(ingress_raw)
        assert parsed[0]["protocol"] == "-1"

    def test_plain_string_list_still_works(self, tmp_path):
        state = {
            "version": 4,
            "resources": [
                {
                    "mode": "managed",
                    "type": "aws_instance",
                    "name": "web",
                    "instances": [{"attributes": {"tags": ["env=prod", "team=ops"]}}],
                }
            ],
        }
        p = self._write_state(tmp_path, state)
        resources = _parse_tfstate(p)
        assert resources[0]["attributes"]["tags"] == ["env=prod", "team=ops"]


# ---------------------------------------------------------------------------
# DSL enrichment via tfstate end-to-end
# ---------------------------------------------------------------------------

class TestDslEnrichmentFromTfstate:
    def _run_plugin(self, tmp_path: Path, state_dict: dict) -> str:
        state_path = tmp_path / "terraform.tfstate"
        state_path.write_text(json.dumps(state_dict), encoding="utf-8")
        plugin = TerraformPlugin()
        iac_data = plugin.parse_iac_config(str(tmp_path))
        return plugin.generate_threat_model_components(iac_data)

    def test_internet_facing_emitted_in_dsl(self, tmp_path):
        state = {
            "version": 4,
            "resources": [
                {
                    "mode": "managed",
                    "type": "aws_instance",
                    "name": "web",
                    "instances": [
                        {"attributes": {"associate_public_ip_address": "true"}}
                    ],
                }
            ],
        }
        md = self._run_plugin(tmp_path, state)
        assert "internet_facing=true" in md

    def test_internet_facing_not_emitted_when_private(self, tmp_path):
        state = {
            "version": 4,
            "resources": [
                {
                    "mode": "managed",
                    "type": "aws_instance",
                    "name": "db",
                    "instances": [
                        {"attributes": {"associate_public_ip_address": "false"}}
                    ],
                }
            ],
        }
        md = self._run_plugin(tmp_path, state)
        assert "internet_facing" not in md

    def test_credentials_stored_emitted_in_dsl(self, tmp_path):
        state = {
            "version": 4,
            "resources": [
                {
                    "mode": "managed",
                    "type": "aws_instance",
                    "name": "app",
                    "instances": [
                        {"attributes": {"iam_instance_profile": "app-role"}}
                    ],
                }
            ],
        }
        md = self._run_plugin(tmp_path, state)
        assert "credentials_stored=true" in md

    def test_traversal_difficulty_emitted_for_sg(self, tmp_path):
        state = {
            "version": 4,
            "resources": [
                {
                    "mode": "managed",
                    "type": "aws_security_group",
                    "name": "web_sg",
                    "instances": [
                        {"attributes": {"ingress": _OPEN_SPECIFIC_PORT_SG}}
                    ],
                }
            ],
        }
        md = self._run_plugin(tmp_path, state)
        assert "traversal_difficulty=" in md

    def test_dsl_boolean_values_are_lowercase(self, tmp_path):
        state = {
            "version": 4,
            "resources": [
                {
                    "mode": "managed",
                    "type": "aws_instance",
                    "name": "pub",
                    "instances": [
                        {
                            "attributes": {
                                "associate_public_ip_address": "true",
                                "iam_instance_profile": "role",
                            }
                        }
                    ],
                }
            ],
        }
        md = self._run_plugin(tmp_path, state)
        _assert_dsl_syntax(md)
        assert "internet_facing=True" not in md
        assert "credentials_stored=True" not in md

    def test_traversal_difficulty_value_is_valid(self, tmp_path):
        state = {
            "version": 4,
            "resources": [
                {
                    "mode": "managed",
                    "type": "aws_security_group",
                    "name": "tight_sg",
                    "instances": [
                        {"attributes": {"ingress": _RESTRICTED_SG}}
                    ],
                }
            ],
        }
        md = self._run_plugin(tmp_path, state)
        _assert_dsl_syntax(md)
        # Must contain one of the valid values
        assert any(
            f"traversal_difficulty={v}" in md for v in _VALID_TRAVERSAL
        )


# ---------------------------------------------------------------------------
# BOM generation
# ---------------------------------------------------------------------------

class TestBomGeneration:
    def _run_bom(self, tmp_path: Path, state_dict: dict):
        state_path = tmp_path / "terraform.tfstate"
        state_path.write_text(json.dumps(state_dict), encoding="utf-8")
        plugin = TerraformPlugin()
        iac_data = plugin.parse_iac_config(str(tmp_path))
        return plugin.generate_bom_files(iac_data, str(tmp_path))

    def _base_state(self, rtype: str, rname: str, attrs: dict = None) -> dict:
        return {
            "version": 4,
            "resources": [
                {
                    "mode": "managed",
                    "type": rtype,
                    "name": rname,
                    "instances": [{"attributes": attrs or {}}],
                }
            ],
        }

    def test_bom_dir_created(self, tmp_path):
        self._run_bom(tmp_path, self._base_state("aws_instance", "web"))
        assert (tmp_path / "BOM").is_dir()

    def test_one_bom_per_server(self, tmp_path):
        state = {
            "version": 4,
            "resources": [
                {
                    "mode": "managed",
                    "type": "aws_instance",
                    "name": "web",
                    "instances": [{"attributes": {}}],
                },
                {
                    "mode": "managed",
                    "type": "aws_rds_instance",
                    "name": "db",
                    "instances": [{"attributes": {}}],
                },
            ],
        }
        paths = self._run_bom(tmp_path, state)
        assert len(paths) == 2

    def test_bom_yaml_loadable(self, tmp_path):
        paths = self._run_bom(
            tmp_path, self._base_state("aws_instance", "web_server")
        )
        assert paths
        with open(paths[0], encoding="utf-8") as fh:
            bom = yaml.safe_load(fh)
        assert isinstance(bom, dict)

    def test_bom_has_required_keys(self, tmp_path):
        paths = self._run_bom(
            tmp_path, self._base_state("aws_instance", "web_server")
        )
        with open(paths[0], encoding="utf-8") as fh:
            bom = yaml.safe_load(fh)
        required = {
            "asset", "os_version", "patch_level",
            "known_cves", "running_services", "detection_level",
            "credentials_stored",
        }
        assert required.issubset(bom.keys())

    def test_bom_known_cves_is_list(self, tmp_path):
        paths = self._run_bom(
            tmp_path, self._base_state("aws_rds_instance", "primary_db")
        )
        with open(paths[0], encoding="utf-8") as fh:
            bom = yaml.safe_load(fh)
        assert isinstance(bom["known_cves"], list)

    def test_bom_services_inferred_rds(self, tmp_path):
        paths = self._run_bom(
            tmp_path, self._base_state("aws_rds_instance", "primary_db")
        )
        with open(paths[0], encoding="utf-8") as fh:
            bom = yaml.safe_load(fh)
        assert "postgresql" in bom["running_services"]

    def test_bom_services_inferred_lambda(self, tmp_path):
        paths = self._run_bom(
            tmp_path, self._base_state("aws_lambda_function", "handler")
        )
        with open(paths[0], encoding="utf-8") as fh:
            bom = yaml.safe_load(fh)
        assert "https" in bom["running_services"]

    def test_bom_credentials_stored_true_for_iam(self, tmp_path):
        paths = self._run_bom(
            tmp_path,
            self._base_state(
                "aws_instance", "app_server",
                {"iam_instance_profile": "app-role"},
            ),
        )
        with open(paths[0], encoding="utf-8") as fh:
            bom = yaml.safe_load(fh)
        assert bom["credentials_stored"] is True

    def test_no_bom_for_boundary_resources(self, tmp_path):
        paths = self._run_bom(
            tmp_path, self._base_state("aws_vpc", "main")
        )
        assert paths == []

    def test_bom_filename_normalised(self, tmp_path):
        self._run_bom(
            tmp_path, self._base_state("aws_instance", "web_server_01")
        )
        bom_files = list((tmp_path / "BOM").glob("*.yaml"))
        assert bom_files
        # Filename should be lowercase with underscores
        assert bom_files[0].name == bom_files[0].name.lower()
        assert " " not in bom_files[0].name
