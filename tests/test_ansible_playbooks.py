import os
import pytest
import subprocess

def find_playbooks(directory):
    """Find all YAML files in a directory."""
    playbooks = []
    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith((".yml", ".yaml")):
                playbooks.append(os.path.join(root, file))
    return playbooks

@pytest.mark.parametrize("playbook_path", find_playbooks("tests/ansible_playbooks"))
def test_ansible_playbook_syntax(playbook_path):
    """Test the syntax of each Ansible playbook."""
    try:
        subprocess.run(
            ["ansible-playbook", "--syntax-check", playbook_path],
            capture_output=True,
            text=True,
            check=True
        )
    except FileNotFoundError:
        pytest.fail("ansible-playbook command not found. Please ensure Ansible is installed and in your PATH.")
    except subprocess.CalledProcessError as e:
        pytest.fail(f"Syntax check failed for {playbook_path}: {e.stderr}")