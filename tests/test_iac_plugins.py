import re

import pytest
import yaml
from unittest.mock import patch, mock_open

from threat_analysis.iac_plugins.ansible_plugin import (
    AnsiblePlugin,
    _infer_boundary_trust,
    _infer_internet_facing,
    _infer_credentials_stored,
    _infer_traversal_difficulty,
    _extract_packages_from_tasks,
    _count_firewall_tasks,
)

@pytest.fixture
def project_tmp_path(tmp_path_factory):
    return tmp_path_factory.mktemp("iac_tests", numbered=True)

@pytest.fixture
def ansible_plugin():
    """Fixture for the AnsiblePlugin."""
    return AnsiblePlugin()

# Sample inventory content for tests
SAMPLE_INVENTORY_CONTENT_WITH_VARS = """
[webservers]
web-01 ansible_host=192.168.1.10 custom_var=test_value

[dbservers]
db-01 ansible_host=192.168.1.20

[infra_boundary]
Router_RIE_InfraBoundary
Switch_Main_Fallback
Operator
Admin

[main]
Server_1 ansible_host=10.0.1.11
Frontend_1 ansible_host=10.0.1.1
Server_2 ansible_host=10.0.1.12
Frontend_2 ansible_host=10.0.1.2
Server_3 ansible_host=10.0.1.13
Frontend_3 ansible_host=10.0.1.3
Server_4 ansible_host=10.0.1.14
Frontend_4 ansible_host=10.0.1.4
Server_5 ansible_host=10.0.1.15
Frontend_5 ansible_host=10.0.1.5

[fallback]
Server_1_Fallback ansible_host=10.0.2.11
Frontend_1_Fallback ansible_host=10.0.2.1
Server_2_Fallback ansible_host=10.0.2.12
Frontend_2_Fallback ansible_host=10.0.2.2
Server_3_Fallback ansible_host=10.0.2.13
Frontend_3_Fallback ansible_host=10.0.2.3
Server_4_Fallback ansible_host=10.0.2.14
Frontend_4_Fallback ansible_host=10.0.2.4
Server_5_Fallback ansible_host=10.0.2.15
Frontend_5_Fallback ansible_host=10.0.2.5
"""

# Sample playbook content for tests
SAMPLE_PLAYBOOK_CONTENT = """
- name: Configure web server
  hosts: webservers
  tasks:
    - name: Install nginx
      ansible.builtin.apt:
        name: nginx
        state: present
"""

@pytest.fixture
def ansible_test_env(project_tmp_path):
    """Creates a temporary ansible environment with a playbook and inventory."""
    playbook_path = project_tmp_path / "playbook.yml"
    inventory_path = project_tmp_path / "hosts.ini"

    playbook_path.write_text(SAMPLE_PLAYBOOK_CONTENT)
    inventory_path.write_text(SAMPLE_INVENTORY_CONTENT_WITH_VARS)
    
    return playbook_path

def test_plugin_name_and_description(ansible_plugin):
    """Tests the plugin's name and description."""
    assert ansible_plugin.name == "ansible"
    assert "Ansible playbooks and inventories" in ansible_plugin.description

def test_parse_iac_config_success_with_vars(ansible_plugin, ansible_test_env, project_tmp_path):
    """Tests successful parsing of a playbook and its inventory including host variables."""
    with patch("threat_analysis.iac_plugins.ansible_plugin._validate_path_within_project", return_value=ansible_test_env) as mock_validate:
        parsed_data = ansible_plugin.parse_iac_config(str(ansible_test_env))

    assert "inventory" in parsed_data
    assert "playbook" in parsed_data

    # Check inventory parsing with host variables
    inventory = parsed_data["inventory"]
    assert "web-01" in inventory["hosts"]
    assert inventory["hosts"]["web-01"]["ansible_host"] == "192.168.1.10"
    assert inventory["hosts"]["web-01"]["custom_var"] == "test_value"
    assert "db-01" in inventory["hosts"]
    assert inventory["hosts"]["db-01"]["ansible_host"] == "192.168.1.20"

    # Check playbook parsing
    playbook = parsed_data["playbook"]
    assert playbook[0]["name"] == "Configure web server"

def test_parse_iac_config_inventory_not_found(ansible_plugin, project_tmp_path):
    """Tests that parsing fails if the inventory file is missing."""
    playbook_path = project_tmp_path / "playbook.yml"
    playbook_path.write_text(SAMPLE_PLAYBOOK_CONTENT)
    
    with patch("threat_analysis.iac_plugins.ansible_plugin._validate_path_within_project", return_value=playbook_path) as mock_validate:
        with pytest.raises(FileNotFoundError, match="Inventory file not found"):
            ansible_plugin.parse_iac_config(str(playbook_path))

def test_parse_iac_config_unsupported_file_type(ansible_plugin, project_tmp_path):
    """Tests that parsing fails for unsupported playbook file types."""
    unsupported_file = project_tmp_path / "playbook.txt"
    unsupported_file.write_text("This is not a playbook.")

    with patch("threat_analysis.iac_plugins.ansible_plugin._validate_path_within_project", return_value=unsupported_file) as mock_validate:
        with pytest.raises(ValueError, match="Unsupported Ansible config path"):
            ansible_plugin.parse_iac_config(str(unsupported_file))

def test_generate_threat_model_components(ansible_plugin):
    """Tests the generation of Markdown components from parsed data."""
    iac_data = {
        "threat_model_metadata": {
            "boundaries": [
                {"name": "Public", "type": "External", "isTrusted": False},
                {"name": "DMZ", "type": "DMZ", "isTrusted": True,
                 "sub_boundaries": [
                     {"name": "Web", "type": "Internal", "isTrusted": True}
                 ]}
            ],
            "actors": [
                {"name": "User", "isHuman": True, "boundary": "Public"}
            ],
            "servers": [
                {"name": "WebApp", "stereotype": "Server", "boundary": "DMZ", "ansible_host": "192.168.1.10", "services": ["web"]}
            ],
            "data": [
                {"name": "Web Traffic", "classification": "PUBLIC", "lifetime": "TRANSIENT"}
            ],
            "data_flows": [
                {
                    "name": "User to WebApp",
                    "source": "actor:User",
                    "destination": "server:WebApp",
                    "protocol": "HTTPS",
                    "data": "Web Traffic",
                    "description": "External user accesses web server"
                }
            ]
        }
    }

    generated_markdown = ansible_plugin.generate_threat_model_components(iac_data)

    assert "## Boundaries" in generated_markdown
    assert "- **Public**: type=External, isTrusted=false" in generated_markdown
    assert "- **DMZ**: type=DMZ, isTrusted=true" in generated_markdown
    assert "  - **Web**: type=Internal, isTrusted=true" in generated_markdown
    assert "## Actors" in generated_markdown
    assert "- **User**: isHuman=true, boundary=Public" in generated_markdown
    assert "## Servers" in generated_markdown
    assert "- **WebApp**: stereotype=Server, boundary=DMZ, ansible_host=192.168.1.10, services=['web']" in generated_markdown
    assert "## Data" in generated_markdown
    assert "- **Web Traffic**: classification=PUBLIC, lifetime=TRANSIENT" in generated_markdown
    assert "## Dataflows" in generated_markdown
    assert 'from="User", to="WebApp", protocol="HTTPS", data="Web Traffic", description="External user accesses web server"' in generated_markdown


# ===========================================================================
# DSL syntax helper (mirrors terraform test)
# ===========================================================================

_DSL_LINE_RE = re.compile(r"^- \*\*[^*]+\*\*: .+$")
_VALID_TRAVERSAL = {"low", "medium", "high"}
_VALID_BOOL = {"true", "false"}


def _assert_dsl_syntax(markdown: str) -> None:
    in_section = False
    for line in markdown.splitlines():
        if line.startswith("## ") or line.startswith("  - **"):
            in_section = True
        if not line.strip():
            in_section = False
            continue
        if not in_section:
            continue
        if not (line.startswith("- ") or line.startswith("  - ")):
            continue
        assert _DSL_LINE_RE.match(line.lstrip()), (
            f"DSL line does not match expected format: {line!r}"
        )
        for attr in re.findall(
            r"(?:internet_facing|credentials_stored|isTrusted)=(\S+?)(?:[,\s]|$)", line
        ):
            assert attr.rstrip(",") in _VALID_BOOL, (
                f"Boolean DSL attr must be 'true'/'false', got: {attr!r}"
            )
        for val in re.findall(r"traversal_difficulty=(\S+?)(?:[,\s]|$)", line):
            assert val.rstrip(",") in _VALID_TRAVERSAL, (
                f"traversal_difficulty must be low/medium/high, got: {val!r}"
            )


# ===========================================================================
# Pure inference helpers
# ===========================================================================

class TestInferBoundaryTrust:
    def test_dmz_is_untrusted(self):
        assert _infer_boundary_trust("dmz") is False

    def test_public_is_untrusted(self):
        assert _infer_boundary_trust("public_subnet") is False

    def test_external_is_untrusted(self):
        assert _infer_boundary_trust("external_network") is False

    def test_internal_is_trusted(self):
        assert _infer_boundary_trust("internal") is True

    def test_backend_is_trusted(self):
        assert _infer_boundary_trust("backend_servers") is True

    def test_database_is_trusted(self):
        assert _infer_boundary_trust("database") is True

    def test_unknown_defaults_trusted(self):
        assert _infer_boundary_trust("app_zone") is True

    def test_case_insensitive(self):
        assert _infer_boundary_trust("DMZ") is False
        assert _infer_boundary_trust("INTERNAL") is True


class TestInferInternetFacing:
    def test_dmz_group_is_internet_facing(self):
        assert _infer_internet_facing("dmz", {}) is True

    def test_public_group(self):
        assert _infer_internet_facing("public_servers", {}) is True

    def test_internal_group_not_internet_facing(self):
        assert _infer_internet_facing("internal", {}) is False

    def test_explicit_var_true(self):
        assert _infer_internet_facing("internal", {"internet_facing": True}) is True

    def test_explicit_var_string_true(self):
        assert _infer_internet_facing("internal", {"internet_facing": "true"}) is True

    def test_explicit_var_false_overrides_nothing(self):
        # var=False + group=internal → False
        assert _infer_internet_facing("internal", {"internet_facing": False}) is False

    def test_edge_group(self):
        assert _infer_internet_facing("edge_routers", {}) is True


class TestInferCredentialsStored:
    def test_vault_prefixed_var(self):
        assert _infer_credentials_stored({"vault_db_password": "..."}, False) is True

    def test_become_with_become_pass(self):
        assert _infer_credentials_stored(
            {"ansible_become_pass": "secret"}, True
        ) is True

    def test_become_with_password_file(self):
        assert _infer_credentials_stored(
            {"ansible_become_password_file": "/etc/pass"}, True
        ) is True

    def test_become_without_cred_vars(self):
        assert _infer_credentials_stored({"ansible_host": "1.2.3.4"}, True) is False

    def test_no_credentials(self):
        assert _infer_credentials_stored({}, False) is False

    def test_explicit_credentials_stored_true(self):
        assert _infer_credentials_stored({"credentials_stored": True}, False) is True

    def test_become_with_secret_var(self):
        assert _infer_credentials_stored(
            {"db_secret": "abc"}, True
        ) is True


class TestInferTraversalDifficulty:
    def test_many_firewall_tasks_is_high(self):
        assert _infer_traversal_difficulty("internal", 5) == "high"

    def test_some_firewall_tasks_is_medium(self):
        assert _infer_traversal_difficulty("internal", 1) == "medium"

    def test_no_firewall_internet_facing_is_low(self):
        assert _infer_traversal_difficulty("dmz", 0) == "low"

    def test_no_firewall_internal_is_medium(self):
        assert _infer_traversal_difficulty("internal", 0) == "medium"

    def test_threshold_at_3(self):
        assert _infer_traversal_difficulty("dmz", 3) == "high"
        assert _infer_traversal_difficulty("dmz", 2) == "medium"


# ===========================================================================
# Package/service extraction
# ===========================================================================

class TestExtractPackagesFromTasks:
    def test_apt_single_package(self):
        tasks = [{"ansible.builtin.apt": {"name": "nginx", "state": "present"}}]
        assert "nginx" in _extract_packages_from_tasks(tasks)

    def test_apt_list_of_packages(self):
        tasks = [
            {"ansible.builtin.apt": {"name": ["postgresql", "redis-server"], "state": "present"}}
        ]
        svcs = _extract_packages_from_tasks(tasks)
        assert "postgresql" in svcs
        assert "redis" in svcs

    def test_yum_module(self):
        tasks = [{"ansible.builtin.yum": {"name": "httpd", "state": "present"}}]
        assert "httpd" in _extract_packages_from_tasks(tasks)

    def test_unknown_package_ignored(self):
        tasks = [{"ansible.builtin.apt": {"name": "some-custom-pkg", "state": "present"}}]
        assert _extract_packages_from_tasks(tasks) == []

    def test_no_tasks(self):
        assert _extract_packages_from_tasks([]) == []

    def test_non_install_task_ignored(self):
        tasks = [{"ansible.builtin.template": {"src": "nginx.conf.j2", "dest": "/etc/nginx/nginx.conf"}}]
        assert _extract_packages_from_tasks(tasks) == []


class TestCountFirewallTasks:
    def test_ufw_counted(self):
        tasks = [{"ansible.builtin.ufw": {"rule": "allow", "port": "80"}}]
        assert _count_firewall_tasks(tasks) == 1

    def test_iptables_counted(self):
        tasks = [{"ansible.builtin.iptables": {"chain": "INPUT", "jump": "ACCEPT"}}]
        assert _count_firewall_tasks(tasks) == 1

    def test_firewalld_counted(self):
        tasks = [{"ansible.posix.firewalld": {"port": "443/tcp", "state": "enabled"}}]
        assert _count_firewall_tasks(tasks) == 1

    def test_non_firewall_task_not_counted(self):
        tasks = [{"ansible.builtin.apt": {"name": "nginx"}}]
        assert _count_firewall_tasks(tasks) == 0

    def test_multiple_firewall_tasks(self):
        tasks = [
            {"ansible.builtin.ufw": {"rule": "allow", "port": "80"}},
            {"ansible.builtin.ufw": {"rule": "allow", "port": "443"}},
            {"ansible.builtin.iptables": {"chain": "INPUT", "jump": "DROP"}},
        ]
        assert _count_firewall_tasks(tasks) == 3


# ===========================================================================
# host_vars / group_vars loading
# ===========================================================================

class TestHostVarsParsing:
    def test_single_file_loaded(self, tmp_path):
        plugin = AnsiblePlugin()
        hv_dir = tmp_path / "host_vars"
        hv_dir.mkdir()
        (hv_dir / "web-01.yml").write_text(
            "ansible_distribution: Ubuntu\ncredentials_stored: true\n",
            encoding="utf-8",
        )
        result = plugin._parse_host_vars(tmp_path, "web-01")
        assert result["ansible_distribution"] == "Ubuntu"
        assert result["credentials_stored"] is True

    def test_directory_form_loaded(self, tmp_path):
        plugin = AnsiblePlugin()
        hv_dir = tmp_path / "host_vars" / "db-01"
        hv_dir.mkdir(parents=True)
        (hv_dir / "main.yml").write_text(
            "ansible_distribution: Debian\n", encoding="utf-8"
        )
        result = plugin._parse_host_vars(tmp_path, "db-01")
        assert result["ansible_distribution"] == "Debian"

    def test_missing_host_vars_returns_empty(self, tmp_path):
        plugin = AnsiblePlugin()
        result = plugin._parse_host_vars(tmp_path, "nonexistent-host")
        assert result == {}

    def test_group_vars_single_file(self, tmp_path):
        plugin = AnsiblePlugin()
        gv_dir = tmp_path / "group_vars"
        gv_dir.mkdir()
        (gv_dir / "webservers.yml").write_text(
            "http_port: 8080\n", encoding="utf-8"
        )
        result = plugin._parse_group_vars(tmp_path, "webservers")
        assert result["http_port"] == 8080

    def test_group_vars_directory_form(self, tmp_path):
        plugin = AnsiblePlugin()
        gv_dir = tmp_path / "group_vars" / "dbservers"
        gv_dir.mkdir(parents=True)
        (gv_dir / "main.yml").write_text("db_port: 5432\n", encoding="utf-8")
        result = plugin._parse_group_vars(tmp_path, "dbservers")
        assert result["db_port"] == 5432

    def test_missing_group_vars_returns_empty(self, tmp_path):
        plugin = AnsiblePlugin()
        assert plugin._parse_group_vars(tmp_path, "nonexistent") == {}


# ===========================================================================
# DSL generation — inventory-based (no metadata)
# ===========================================================================

INVENTORY_WITH_DMZ = """
[dmz]
web-01 ansible_host=203.0.113.10
web-02 ansible_host=203.0.113.11

[internal]
app-01 ansible_host=10.0.1.10
db-01 ansible_host=10.0.2.10
"""

PLAYBOOK_WITH_NGINX = """
- name: Setup webservers
  hosts: dmz
  become: yes
  tasks:
    - name: Install nginx
      ansible.builtin.apt:
        name: nginx
        state: present
    - name: Allow HTTP
      ansible.builtin.ufw:
        rule: allow
        port: "80"
        proto: tcp
    - name: Allow HTTPS
      ansible.builtin.ufw:
        rule: allow
        port: "443"
        proto: tcp

- name: Setup app servers
  hosts: internal
  tasks:
    - name: Install postgresql
      ansible.builtin.apt:
        name: postgresql
        state: present
"""


@pytest.fixture
def enriched_ansible_env(tmp_path):
    """Ansible env without metadata: auto-generation from inventory."""
    playbook_path = tmp_path / "site.yml"
    inventory_path = tmp_path / "hosts.ini"
    playbook_path.write_text(PLAYBOOK_WITH_NGINX, encoding="utf-8")
    inventory_path.write_text(INVENTORY_WITH_DMZ, encoding="utf-8")
    return playbook_path


class TestAnsibleInventoryBasedGeneration:
    def _parse_and_generate(self, playbook_path: "Path") -> str:
        plugin = AnsiblePlugin()
        with patch(
            "threat_analysis.iac_plugins.ansible_plugin._validate_path_within_project",
            return_value=playbook_path,
        ):
            iac_data = plugin.parse_iac_config(str(playbook_path))
        return plugin.generate_threat_model_components(iac_data)

    def test_boundaries_from_inventory_groups(self, enriched_ansible_env):
        md = self._parse_and_generate(enriched_ansible_env)
        assert "## Boundaries" in md
        assert "dmz" in md
        assert "internal" in md

    def test_dmz_boundary_untrusted(self, enriched_ansible_env):
        md = self._parse_and_generate(enriched_ansible_env)
        # The dmz boundary line
        dmz_line = next(
            (l for l in md.splitlines() if "dmz" in l.lower() and "isTrusted" in l), ""
        )
        assert "isTrusted=false" in dmz_line

    def test_internal_boundary_trusted(self, enriched_ansible_env):
        md = self._parse_and_generate(enriched_ansible_env)
        internal_line = next(
            (l for l in md.splitlines() if "internal" in l.lower() and "isTrusted" in l), ""
        )
        assert "isTrusted=true" in internal_line

    def test_servers_from_inventory(self, enriched_ansible_env):
        md = self._parse_and_generate(enriched_ansible_env)
        assert "## Servers" in md
        assert "web-01" in md
        assert "db-01" in md

    def test_dmz_servers_marked_internet_facing(self, enriched_ansible_env):
        md = self._parse_and_generate(enriched_ansible_env)
        web01_line = next(
            (l for l in md.splitlines() if "web-01" in l), ""
        )
        assert "internet_facing=true" in web01_line

    def test_internal_servers_not_internet_facing(self, enriched_ansible_env):
        md = self._parse_and_generate(enriched_ansible_env)
        db01_line = next(
            (l for l in md.splitlines() if "db-01" in l), ""
        )
        assert "internet_facing" not in db01_line

    def test_dsl_syntax_valid(self, enriched_ansible_env):
        md = self._parse_and_generate(enriched_ansible_env)
        _assert_dsl_syntax(md)

    def test_traversal_difficulty_on_dmz_boundary(self, enriched_ansible_env):
        md = self._parse_and_generate(enriched_ansible_env)
        dmz_line = next(
            (l for l in md.splitlines() if "dmz" in l.lower() and "traversal_difficulty" in l), ""
        )
        # DMZ has 2 ufw tasks → medium (< 3 threshold)
        assert dmz_line != "", "Expected traversal_difficulty on dmz boundary"
        _assert_dsl_syntax(md)


# ===========================================================================
# DSL generation — metadata-based with enrichment
# ===========================================================================

PLAYBOOK_WITH_METADATA_AND_BECOME = """
- name: Deploy app
  hosts: webservers
  become: yes
  vars:
    threat_model_metadata:
      boundaries:
        - name: DMZ
          isTrusted: False
      servers:
        - name: WebServer
          stereotype: Server
          boundary: DMZ
  tasks:
    - name: Install nginx
      ansible.builtin.apt:
        name: nginx
        state: present

- name: Configure db
  hosts: dbservers
  become: yes
  tasks:
    - name: Install postgresql
      ansible.builtin.apt:
        name: postgresql
        state: present
"""

INVENTORY_METADATA = """
[webservers]
web-app-01 ansible_host=203.0.113.5

[dbservers]
db-01 ansible_host=10.0.2.10
"""


@pytest.fixture
def metadata_ansible_env(tmp_path):
    """Ansible env with metadata block and enrichable hosts."""
    playbook_path = tmp_path / "site.yml"
    inventory_path = tmp_path / "hosts.ini"
    playbook_path.write_text(PLAYBOOK_WITH_METADATA_AND_BECOME, encoding="utf-8")
    inventory_path.write_text(INVENTORY_METADATA, encoding="utf-8")

    # host_vars for web-app-01 with become_pass (credentials indicator)
    hv_dir = tmp_path / "host_vars"
    hv_dir.mkdir()
    (hv_dir / "web-app-01.yml").write_text(
        "ansible_become_pass: s3cr3t\n", encoding="utf-8"
    )
    return playbook_path


class TestAnsibleMetadataEnrichment:
    def _parse_and_generate(self, playbook_path):
        plugin = AnsiblePlugin()
        with patch(
            "threat_analysis.iac_plugins.ansible_plugin._validate_path_within_project",
            return_value=playbook_path,
        ):
            iac_data = plugin.parse_iac_config(str(playbook_path))
        return iac_data, plugin.generate_threat_model_components(iac_data)

    def test_metadata_boundaries_rendered(self, metadata_ansible_env):
        _, md = self._parse_and_generate(metadata_ansible_env)
        assert "## Boundaries" in md
        assert "DMZ" in md

    def test_credentials_stored_injected_from_host_vars(self, metadata_ansible_env):
        _, md = self._parse_and_generate(metadata_ansible_env)
        # WebServer matches web-app-01 (has ansible_become_pass + become: yes)
        server_line = next(
            (l for l in md.splitlines() if "WebServer" in l), ""
        )
        assert "credentials_stored=true" in server_line

    def test_dsl_syntax_valid(self, metadata_ansible_env):
        _, md = self._parse_and_generate(metadata_ansible_env)
        _assert_dsl_syntax(md)


# ===========================================================================
# BOM generation
# ===========================================================================

class TestAnsibleBomGeneration:
    def _get_iac_data(self, playbook_path):
        plugin = AnsiblePlugin()
        with patch(
            "threat_analysis.iac_plugins.ansible_plugin._validate_path_within_project",
            return_value=playbook_path,
        ):
            return plugin, plugin.parse_iac_config(str(playbook_path))

    def test_bom_dir_created(self, enriched_ansible_env, tmp_path):
        plugin, iac_data = self._get_iac_data(enriched_ansible_env)
        plugin.generate_bom_files(iac_data, str(tmp_path))
        assert (tmp_path / "BOM").is_dir()

    def test_one_bom_per_host(self, enriched_ansible_env, tmp_path):
        plugin, iac_data = self._get_iac_data(enriched_ansible_env)
        paths = plugin.generate_bom_files(iac_data, str(tmp_path))
        # 4 hosts: web-01, web-02, app-01, db-01
        assert len(paths) == 4

    def test_bom_yaml_loadable(self, enriched_ansible_env, tmp_path):
        plugin, iac_data = self._get_iac_data(enriched_ansible_env)
        paths = plugin.generate_bom_files(iac_data, str(tmp_path))
        for p in paths:
            with open(p, encoding="utf-8") as fh:
                bom = yaml.safe_load(fh)
            assert isinstance(bom, dict)

    def test_bom_has_required_keys(self, enriched_ansible_env, tmp_path):
        plugin, iac_data = self._get_iac_data(enriched_ansible_env)
        paths = plugin.generate_bom_files(iac_data, str(tmp_path))
        required = {
            "asset", "os_version", "patch_level",
            "known_cves", "running_services", "detection_level",
            "credentials_stored",
        }
        for p in paths:
            with open(p, encoding="utf-8") as fh:
                bom = yaml.safe_load(fh)
            assert required.issubset(bom.keys()), f"Missing keys in {p}"

    def test_bom_services_from_apt_tasks(self, enriched_ansible_env, tmp_path):
        plugin, iac_data = self._get_iac_data(enriched_ansible_env)
        plugin.generate_bom_files(iac_data, str(tmp_path))
        bom_files = list((tmp_path / "BOM").glob("*.yaml"))
        all_services = []
        for p in bom_files:
            with open(p, encoding="utf-8") as fh:
                bom = yaml.safe_load(fh)
            all_services.extend(bom.get("running_services", []))
        # nginx is installed on dmz hosts, postgresql on internal
        assert "nginx" in all_services
        assert "postgresql" in all_services

    def test_bom_known_cves_is_list(self, enriched_ansible_env, tmp_path):
        plugin, iac_data = self._get_iac_data(enriched_ansible_env)
        paths = plugin.generate_bom_files(iac_data, str(tmp_path))
        for p in paths:
            with open(p, encoding="utf-8") as fh:
                bom = yaml.safe_load(fh)
            assert isinstance(bom["known_cves"], list)

    def test_no_bom_when_no_enrichment(self, tmp_path):
        plugin = AnsiblePlugin()
        paths = plugin.generate_bom_files({"host_enrichment": {}}, str(tmp_path))
        assert paths == []

    def test_bom_filename_normalised(self, enriched_ansible_env, tmp_path):
        plugin, iac_data = self._get_iac_data(enriched_ansible_env)
        plugin.generate_bom_files(iac_data, str(tmp_path))
        for bom_file in (tmp_path / "BOM").glob("*.yaml"):
            assert bom_file.name == bom_file.name.lower()
            assert " " not in bom_file.name