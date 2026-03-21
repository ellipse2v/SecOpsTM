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

from threat_analysis.iac_plugins.terraform_plugin import (
    TerraformPlugin,
    _sanitize_name,
    _provider_of,
    _extract_block_body,
    _parse_tf_text,
    _parse_tfstate,
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
        # aws_instance references subnet_id → should generate a dataflow
        md = self._parse_and_generate(SIMPLE_TF)
        assert "## Dataflows" in md

    def test_azure_resources(self):
        md = self._parse_and_generate(AZURE_TF)
        assert "App Vm" in md
        assert "Vnet" in md

    def test_gcp_resources(self):
        md = self._parse_and_generate(GCP_TF)
        assert "Gce Vm" in md

    def test_empty_resources(self):
        plugin = TerraformPlugin()
        md = plugin.generate_threat_model_components({"resources": []})
        assert md == ""

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
        assert len(flows) == 1
        assert flows[0]["source"] == "Web Server"
        assert flows[0]["destination"] == "Pub"
        assert flows[0]["protocol"] == "HTTPS"

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
        # Even though subnet_id and security_groups both reference the same target,
        # dedup should produce only one flow
        assert len(flows) == 1

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
