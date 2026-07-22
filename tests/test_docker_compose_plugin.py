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

import yaml
import pytest

from threat_analysis.iac_plugins.docker_compose_plugin import (
    DockerComposePlugin,
    _image_repo,
    _infer_server_type,
    _infer_protocol,
    _infer_credentials_stored,
    _infer_network_trust,
    _env_to_dict,
)


@pytest.fixture
def project_tmp_path(tmp_path_factory):
    return tmp_path_factory.mktemp("docker_compose_tests", numbered=True)


@pytest.fixture
def plugin():
    return DockerComposePlugin()


SAMPLE_COMPOSE = """
version: "3.8"

networks:
  frontend_net:
  backend_net:

services:
  nginx:
    image: nginx:1.25-alpine
    ports:
      - "443:443"
    networks:
      - frontend_net
    depends_on:
      - webapp

  webapp:
    image: myorg/webapp:latest
    environment:
      - DB_PASSWORD=supersecret
      - DEBUG=false
    networks:
      - frontend_net
      - backend_net
    depends_on:
      - postgres
      - redis

  postgres:
    image: postgres:15
    environment:
      POSTGRES_PASSWORD: dbsecret
    networks:
      - backend_net

  redis:
    image: redis:7-alpine
    networks:
      - backend_net
"""


def _write_compose(project_tmp_path, content=SAMPLE_COMPOSE, filename="docker-compose.yml"):
    p = project_tmp_path / filename
    p.write_text(content, encoding="utf-8")
    return p


class TestPluginMetadata:
    def test_name_and_description(self, plugin):
        assert plugin.name == "docker-compose"
        assert "Docker Compose" in plugin.description


class TestImageRepo:
    def test_strips_tag(self):
        assert _image_repo("postgres:15-alpine") == "postgres"

    def test_strips_registry_and_org(self):
        assert _image_repo("ghcr.io/myorg/myapp:v1") == "myapp"

    def test_strips_digest(self):
        assert _image_repo("redis@sha256:abcdef") == "redis"

    def test_empty_image(self):
        assert _image_repo("") == ""


class TestInferServerType:
    def test_known_database_image(self):
        assert _infer_server_type("postgres:15", published_ports=False) == "database"

    def test_known_cache_image(self):
        assert _infer_server_type("redis:7-alpine", published_ports=False) == "cache"

    def test_unknown_image_with_published_port_is_web_server(self):
        assert _infer_server_type("myorg/webapp:latest", published_ports=True) == "web-server"

    def test_unknown_image_without_published_port_is_microservice(self):
        assert _infer_server_type("myorg/webapp:latest", published_ports=False) == "microservice"


class TestInferProtocol:
    def test_known_database_protocol(self):
        assert _infer_protocol("postgres:15") == "PostgreSQL"

    def test_unknown_image_defaults_to_tcp(self):
        assert _infer_protocol("myorg/webapp:latest") == "TCP"


class TestEnvToDict:
    def test_list_form(self):
        assert _env_to_dict(["KEY=value", "FLAG"]) == {"KEY": "value", "FLAG": ""}

    def test_dict_form(self):
        assert _env_to_dict({"KEY": "value"}) == {"KEY": "value"}

    def test_none(self):
        assert _env_to_dict(None) == {}


class TestInferCredentialsStored:
    def test_password_env_var(self):
        assert _infer_credentials_stored({"environment": ["DB_PASSWORD=x"]}) is True

    def test_secrets_key_present(self):
        assert _infer_credentials_stored({"secrets": ["db_password"]}) is True

    def test_no_credentials(self):
        assert _infer_credentials_stored({"environment": {"DEBUG": "true"}}) is False


class TestInferNetworkTrust:
    def test_dmz_is_untrusted(self):
        assert _infer_network_trust("dmz_net") is False

    def test_backend_is_trusted(self):
        assert _infer_network_trust("backend_net") is True


class TestParseIacConfig:
    def test_parses_services_and_networks(self, plugin, project_tmp_path):
        compose_path = _write_compose(project_tmp_path)
        data = plugin.parse_iac_config(str(compose_path))

        assert set(data["services"].keys()) == {"nginx", "webapp", "postgres", "redis"}
        assert set(data["networks"].keys()) == {"frontend_net", "backend_net"}
        assert data["service_networks"]["nginx"] == {"frontend_net"}
        assert data["service_networks"]["webapp"] == {"frontend_net", "backend_net"}

    def test_directory_path_finds_compose_file(self, plugin, project_tmp_path):
        _write_compose(project_tmp_path)
        data = plugin.parse_iac_config(str(project_tmp_path))
        assert "nginx" in data["services"]

    def test_missing_compose_file_raises(self, plugin, project_tmp_path):
        with pytest.raises(FileNotFoundError):
            plugin.parse_iac_config(str(project_tmp_path))

    def test_unsupported_extension_raises(self, plugin, project_tmp_path):
        bad_path = project_tmp_path / "compose.txt"
        bad_path.write_text("services: {}", encoding="utf-8")
        with pytest.raises(ValueError):
            plugin.parse_iac_config(str(bad_path))


class TestGenerateThreatModelComponents:
    def test_generates_boundaries_servers_and_dataflows(self, plugin, project_tmp_path):
        compose_path = _write_compose(project_tmp_path)
        data = plugin.parse_iac_config(str(compose_path))
        markdown = plugin.generate_threat_model_components(data)

        assert "## Boundaries" in markdown
        assert "## Servers" in markdown
        assert "## Dataflows" in markdown

        # "frontend_net" matches the untrusted-network keyword heuristic
        # ("frontend"); "backend_net" doesn't match any untrusted keyword.
        assert '- **frontend_net**: isTrusted=false' in markdown
        assert '- **backend_net**: isTrusted=true' in markdown

        assert 'nginx' in markdown and 'type=web-server' in markdown
        assert 'internet_facing=true' in markdown
        assert 'type=database' in markdown  # postgres
        assert 'type=cache' in markdown      # redis
        assert 'credentials_stored=true' in markdown

    def test_depends_on_produces_explicit_dataflow(self, plugin, project_tmp_path):
        compose_path = _write_compose(project_tmp_path)
        data = plugin.parse_iac_config(str(compose_path))
        markdown = plugin.generate_threat_model_components(data)

        assert 'from="nginx", to="webapp"' in markdown
        assert 'from="webapp", to="postgres"' in markdown
        assert 'protocol="PostgreSQL"' in markdown

    def test_no_networks_uses_default_network_as_single_boundary(self, plugin, project_tmp_path):
        compose = """
services:
  app:
    image: myapp:latest
  db:
    image: postgres:15
    depends_on:
      - app
"""
        compose_path = _write_compose(project_tmp_path, content=compose)
        data = plugin.parse_iac_config(str(compose_path))
        markdown = plugin.generate_threat_model_components(data)

        # Both services share the implicit default network — exactly one boundary.
        assert markdown.count("## Boundaries") == 1
        boundaries_section = markdown.split("## Servers")[0]
        assert boundaries_section.count("**") == 2  # one boundary name, bolded twice

    def test_untrusted_network_marks_boundary(self, plugin, project_tmp_path):
        compose = """
networks:
  dmz_net:
services:
  edge:
    image: nginx:latest
    networks:
      - dmz_net
"""
        compose_path = _write_compose(project_tmp_path, content=compose)
        data = plugin.parse_iac_config(str(compose_path))
        markdown = plugin.generate_threat_model_components(data)
        assert '- **dmz_net**: isTrusted=false' in markdown

    def test_empty_services_produces_no_servers_section(self, plugin):
        markdown = plugin.generate_threat_model_components(
            {"services": {}, "networks": {}, "service_networks": {}, "default_network": "default"}
        )
        assert "## Servers" not in markdown


class TestBomGeneration:
    def test_generates_one_bom_per_service(self, plugin, project_tmp_path):
        compose_path = _write_compose(project_tmp_path)
        data = plugin.parse_iac_config(str(compose_path))
        output_dir = project_tmp_path / "output"
        output_dir.mkdir()

        written = plugin.generate_bom_files(data, str(output_dir))
        assert len(written) == 4

        bom_dir = output_dir / "BOM"
        postgres_bom = yaml.safe_load((bom_dir / "postgres.yaml").read_text())
        assert postgres_bom["asset"] == "postgres"
        assert postgres_bom["software_version"] == "postgres:15"
        assert postgres_bom["credentials_stored"] is True

    def test_empty_services_produces_no_bom_files(self, plugin):
        assert plugin.generate_bom_files({"services": {}}, "/tmp/unused") == []
