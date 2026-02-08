import pytest
from threat_analysis.iac_plugins.ansible_plugin import AnsiblePlugin
from unittest.mock import patch, mock_open

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
    assert "- **Public**: type=External, isTrusted=False" in generated_markdown
    assert "- **DMZ**: type=DMZ, isTrusted=True" in generated_markdown
    assert "  - **Web**: type=Internal, isTrusted=True" in generated_markdown
    assert "## Actors" in generated_markdown
    assert "- **User**: isHuman=True, boundary=Public" in generated_markdown
    assert "## Servers" in generated_markdown
    assert "- **WebApp**: stereotype=Server, boundary=DMZ, ansible_host=192.168.1.10, services=['web']" in generated_markdown
    assert "## Data" in generated_markdown
    assert "- **Web Traffic**: classification=PUBLIC, lifetime=TRANSIENT" in generated_markdown
    assert "## Dataflows" in generated_markdown
    assert 'from="User", to="WebApp", protocol="HTTPS", data="Web Traffic", description="External user accesses web server"' in generated_markdown