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

"""Ansible IaC plugin for SecOpsTM.

Parses an Ansible playbook + inventory (``hosts.ini``) and produces
SecOpsTM Markdown DSL components.

Enrichment sources:
  - ``host_vars/{hostname}.yml`` or ``host_vars/{hostname}/main.yml``
  - ``group_vars/{group}.yml``   or ``group_vars/{group}/main.yml``
  - Playbook tasks: ``apt``/``yum``/``dnf`` module → running services
  - Group names:    ``dmz``/``public``/``external`` → ``isTrusted=false``, ``internet_facing=true``
  - Playbook:       ``become: yes`` + password vars → ``credentials_stored=true``
  - Firewall tasks: ``iptables``/``ufw``/``firewalld`` → ``traversal_difficulty``

Fallback generation:
  When no ``threat_model_metadata`` block is present in the playbook, the
  plugin generates boundaries + servers directly from the inventory groups.

BOM generation:
  :meth:`AnsiblePlugin.generate_bom_files` writes one YAML file per host
  under ``{output_dir}/BOM/``.
"""

import logging
import re
import yaml
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from threat_analysis.utils import _validate_path_within_project
from threat_analysis.iac_plugins import IaCPlugin

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Group-name heuristics
# ---------------------------------------------------------------------------

_UNTRUSTED_GROUP_KEYWORDS: frozenset = frozenset(
    ["dmz", "public", "external", "internet", "perimeter", "edge", "frontend", "web"]
)
_TRUSTED_GROUP_KEYWORDS: frozenset = frozenset(
    ["internal", "backend", "core", "db", "database", "app", "worker",
     "private", "secure", "admin", "management", "infra"]
)

# ---------------------------------------------------------------------------
# Package → service mapping for BOM running_services
# ---------------------------------------------------------------------------

_PACKAGE_SERVICE_MAP: Dict[str, str] = {
    "nginx": "nginx",
    "apache2": "apache2",
    "httpd": "httpd",
    "lighttpd": "http",
    "postgresql": "postgresql",
    "postgresql-server": "postgresql",
    "mysql-server": "mysql",
    "mysql-community-server": "mysql",
    "mariadb-server": "mysql",
    "redis": "redis",
    "redis-server": "redis",
    "memcached": "memcached",
    "openssh-server": "ssh",
    "openssh-client": "ssh",
    "docker": "docker",
    "docker.io": "docker",
    "docker-ce": "docker",
    "haproxy": "haproxy",
    "varnish": "varnish",
    "elasticsearch": "elasticsearch",
    "kibana": "kibana",
    "logstash": "logstash",
    "rabbitmq-server": "rabbitmq",
    "mongodb": "mongodb",
    "mongodb-org": "mongodb",
    "nfs-kernel-server": "nfs",
    "samba": "smb",
    "nodejs": "nodejs",
    "python3": "python3",
    "python": "python",
}

# Ansible package-install module names (FQCN and short forms)
_INSTALL_MODULES: frozenset = frozenset([
    "apt", "ansible.builtin.apt",
    "yum", "ansible.builtin.yum",
    "dnf", "ansible.builtin.dnf",
    "package", "ansible.builtin.package",
    "zypper", "community.general.zypper",
    "apk", "community.general.apk",
])

# Ansible firewall task module names
_FIREWALL_MODULES: frozenset = frozenset([
    "iptables", "ansible.builtin.iptables",
    "ufw", "ansible.builtin.ufw",
    "firewalld", "ansible.posix.firewalld",
])

# Credential-bearing var name fragments (checked against host_vars keys)
_CREDENTIAL_VAR_FRAGMENTS: frozenset = frozenset(
    ["password", "secret", "token", "api_key", "passwd", "credential"]
)


# ---------------------------------------------------------------------------
# Pure inference helpers
# ---------------------------------------------------------------------------

def _infer_boundary_trust(group_name: str) -> bool:
    """Return True (trusted) or False (untrusted) for a group name."""
    lower = group_name.lower()
    for kw in _UNTRUSTED_GROUP_KEYWORDS:
        if kw in lower:
            return False
    return True


def _infer_internet_facing(group_name: str, host_vars: Dict[str, Any]) -> bool:
    """True if the host is in an internet-facing group or explicitly declared."""
    if host_vars.get("internet_facing") in (True, "true", "yes", "1"):
        return True
    lower = group_name.lower()
    for kw in ("dmz", "public", "external", "internet", "edge", "perimeter"):
        if kw in lower:
            return True
    return False


def _infer_credentials_stored(host_vars: Dict[str, Any], play_has_become: bool) -> bool:
    """True if the host stores credentials according to its vars or playbook."""
    if host_vars.get("credentials_stored") in (True, "true", "yes", "1"):
        return True
    # become + any password/vault reference
    if play_has_become:
        for key in host_vars:
            lk = key.lower()
            for frag in _CREDENTIAL_VAR_FRAGMENTS:
                if frag in lk:
                    return True
        # ansible_become_pass or ansible_become_password_file
        if (
            host_vars.get("ansible_become_pass")
            or host_vars.get("ansible_become_password_file")
        ):
            return True
    # Vault-prefixed vars
    for key in host_vars:
        if key.lower().startswith("vault_"):
            return True
    return False


def _infer_traversal_difficulty(group_name: str, firewall_task_count: int) -> str:
    """Infer traversal difficulty.

    High firewall task count → ``high`` (well-guarded zone).
    Low/medium → ``medium``.
    Internet-facing groups with no firewall tasks → ``low``.
    """
    lower = group_name.lower()
    is_internet = any(
        kw in lower for kw in ("dmz", "public", "external", "internet", "edge")
    )
    if firewall_task_count >= 3:
        return "high"
    if firewall_task_count >= 1:
        return "medium"
    if is_internet:
        return "low"
    return "medium"


def _extract_packages_from_tasks(tasks: List[Dict[str, Any]]) -> List[str]:
    """Return service names discovered from package-install tasks."""
    services: List[str] = []
    for task in tasks:
        if not isinstance(task, dict):
            continue
        for module in _INSTALL_MODULES:
            mod_args = task.get(module)
            if mod_args is None:
                continue
            pkg_names: List[str] = []
            if isinstance(mod_args, dict):
                name_val = mod_args.get("name")
                if isinstance(name_val, list):
                    pkg_names = [str(n) for n in name_val]
                elif name_val:
                    pkg_names = [str(name_val)]
            elif isinstance(mod_args, str):
                pkg_names = [mod_args]
            for pkg in pkg_names:
                svc = _PACKAGE_SERVICE_MAP.get(pkg.strip())
                if svc and svc not in services:
                    services.append(svc)
    return services


def _count_firewall_tasks(tasks: List[Dict[str, Any]]) -> int:
    """Count tasks that configure a firewall."""
    count = 0
    for task in tasks:
        if not isinstance(task, dict):
            continue
        for module in _FIREWALL_MODULES:
            if module in task:
                count += 1
                break
    return count


# ---------------------------------------------------------------------------
# Plugin class
# ---------------------------------------------------------------------------

class AnsiblePlugin(IaCPlugin):
    """IaC Plugin for Ansible configurations."""

    @property
    def name(self) -> str:
        return "ansible"

    @property
    def description(self) -> str:
        return (
            "Integrates with Ansible playbooks and inventories to generate "
            "threat model components."
        )

    # ------------------------------------------------------------------
    # IaCPlugin interface
    # ------------------------------------------------------------------

    def parse_iac_config(self, config_path: str) -> Dict[str, Any]:
        """Parse an Ansible playbook + ``hosts.ini`` inventory.

        Returns a dict with keys:
          ``inventory``        — parsed groups and hosts
          ``playbook``         — raw parsed YAML list
          ``threat_model_metadata`` — manual block from playbook vars (may be empty)
          ``host_enrichment``  — per-host inferred enrichment data
          ``group_enrichment`` — per-group inferred enrichment data
        """
        validated_config_path = _validate_path_within_project(config_path)
        playbook_path = validated_config_path
        inventory_path = playbook_path.parent / "hosts.ini"

        if not playbook_path.is_file() or playbook_path.suffix not in (".yml", ".yaml"):
            raise ValueError(
                f"Unsupported Ansible config path: {playbook_path}. "
                "Must be a .yml or .yaml file."
            )

        inventory = self._parse_inventory(inventory_path)

        with open(playbook_path, "r", encoding="utf-8") as fh:
            playbook_content = yaml.safe_load(fh)

        threat_model_metadata: Dict[str, Any] = {}
        if isinstance(playbook_content, list):
            for play in playbook_content:
                if (
                    isinstance(play, dict)
                    and "vars" in play
                    and "threat_model_metadata" in play["vars"]
                ):
                    threat_model_metadata = play["vars"]["threat_model_metadata"]
                    break

        host_enrichment, group_enrichment = self._build_enrichment(
            playbook_path.parent, inventory, playbook_content
        )

        return {
            "inventory": inventory,
            "playbook": playbook_content,
            "threat_model_metadata": threat_model_metadata,
            "host_enrichment": host_enrichment,
            "group_enrichment": group_enrichment,
        }

    def generate_threat_model_components(self, iac_data: Dict[str, Any]) -> str:
        """Generate Markdown DSL components from parsed Ansible data.

        Strategy:
        - If ``threat_model_metadata`` is present → use it as the DSL base
          and enrich each server entry with ``host_enrichment`` data.
        - Otherwise → auto-generate Boundaries + Servers from inventory groups.
        """
        metadata = iac_data.get("threat_model_metadata", {})
        host_enrichment: Dict[str, Any] = iac_data.get("host_enrichment", {})
        group_enrichment: Dict[str, Any] = iac_data.get("group_enrichment", {})
        inventory: Dict[str, Any] = iac_data.get("inventory", {"groups": {}, "hosts": {}})

        if metadata:
            return self._render_from_metadata(metadata, host_enrichment, group_enrichment)
        return self._render_from_inventory(inventory, host_enrichment, group_enrichment)

    def generate_bom_files(self, iac_data: Dict[str, Any], output_dir: str) -> List[str]:
        """Write one BOM YAML file per host under ``{output_dir}/BOM/``."""
        host_enrichment: Dict[str, Any] = iac_data.get("host_enrichment", {})
        if not host_enrichment:
            return []

        bom_dir = Path(output_dir) / "BOM"
        bom_dir.mkdir(parents=True, exist_ok=True)

        written: List[str] = []
        for hostname, info in host_enrichment.items():
            bom_key = re.sub(r"[\s\-]+", "_", hostname.strip().lower())
            bom_key = re.sub(r"[^a-z0-9_]", "", bom_key)

            bom: Dict[str, Any] = {
                "asset": hostname,
                "os_version": info.get("host_vars", {}).get("ansible_distribution", "linux"),
                "software_version": info.get("host_vars", {}).get(
                    "ansible_distribution_version", ""
                ),
                "patch_level": "unknown",
                "known_cves": [],
                "running_services": info.get("services", []),
                "detection_level": "low",
                "credentials_stored": info.get("credentials_stored", False),
                "notes": (
                    f"Auto-generated from Ansible inventory group '{info.get('group', '')}'."
                    " Populate known_cves and patch_level from your scanner."
                ),
            }

            bom_path = bom_dir / f"{bom_key}.yaml"
            with open(bom_path, "w", encoding="utf-8") as fh:
                yaml.dump(bom, fh, default_flow_style=False, allow_unicode=True,
                          sort_keys=False)
            written.append(str(bom_path))
            logger.info("Generated BOM: %s", bom_path)

        return written

    # ------------------------------------------------------------------
    # Inventory parsing
    # ------------------------------------------------------------------

    def _parse_inventory(self, inventory_path: Path) -> Dict[str, Any]:
        """Parse an Ansible INI inventory file."""
        if not inventory_path.exists():
            raise FileNotFoundError(f"Inventory file not found: {inventory_path}")

        inventory_data: Dict[str, Any] = {"groups": {}, "hosts": {}}
        current_group: Optional[str] = None

        with open(inventory_path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue

                if line.startswith("["):
                    if line.endswith(":children]"):
                        group_name = line[1:-9]
                        inventory_data["groups"].setdefault(group_name, [])
                    else:
                        current_group = line[1:-1]
                        inventory_data["groups"].setdefault(current_group, [])
                else:
                    if current_group:
                        parts = line.split()
                        host_name = parts[0]
                        inventory_data["groups"][current_group].append(host_name)

                        host_vars: Dict[str, Any] = {"group": current_group}
                        for part in parts[1:]:
                            if "=" in part:
                                key, value = part.split("=", 1)
                                host_vars[key] = value
                        inventory_data["hosts"][host_name] = host_vars

        return inventory_data

    # ------------------------------------------------------------------
    # host_vars / group_vars loading
    # ------------------------------------------------------------------

    def _load_vars_file(self, path: Path) -> Dict[str, Any]:
        """Load a YAML vars file, returning an empty dict on any error."""
        try:
            raw = yaml.safe_load(path.read_text(encoding="utf-8"))
            return raw if isinstance(raw, dict) else {}
        except Exception as exc:
            logger.debug("Could not load vars file %s: %s", path, exc)
            return {}

    def _parse_host_vars(self, playbook_dir: Path, hostname: str) -> Dict[str, Any]:
        """Load host_vars for a given hostname (single file or directory)."""
        candidates = [
            playbook_dir / "host_vars" / f"{hostname}.yml",
            playbook_dir / "host_vars" / f"{hostname}.yaml",
            playbook_dir / "host_vars" / hostname / "main.yml",
            playbook_dir / "host_vars" / hostname / "vars.yml",
        ]
        for path in candidates:
            if path.is_file():
                return self._load_vars_file(path)
        return {}

    def _parse_group_vars(self, playbook_dir: Path, group_name: str) -> Dict[str, Any]:
        """Load group_vars for a given group name (single file or directory)."""
        candidates = [
            playbook_dir / "group_vars" / f"{group_name}.yml",
            playbook_dir / "group_vars" / f"{group_name}.yaml",
            playbook_dir / "group_vars" / group_name / "main.yml",
            playbook_dir / "group_vars" / group_name / "vars.yml",
        ]
        for path in candidates:
            if path.is_file():
                return self._load_vars_file(path)
        return {}

    # ------------------------------------------------------------------
    # Enrichment builder
    # ------------------------------------------------------------------

    def _collect_play_facts(
        self, playbook_content: Any
    ) -> Dict[str, Tuple[List[str], int, bool]]:
        """Return per-hosts-pattern ``(services, firewall_task_count, has_become)``.

        The key is the play's ``hosts`` value (e.g. ``"webservers"`` or ``"all"``).
        """
        play_facts: Dict[str, Tuple[List[str], int, bool]] = {}
        if not isinstance(playbook_content, list):
            return play_facts

        for play in playbook_content:
            if not isinstance(play, dict):
                continue
            hosts_pattern = str(play.get("hosts", "all"))
            tasks: List[Dict[str, Any]] = list(play.get("tasks", []) or [])
            handlers: List[Dict[str, Any]] = list(play.get("handlers", []) or [])
            all_tasks = tasks + handlers
            services = _extract_packages_from_tasks(all_tasks)
            fw_count = _count_firewall_tasks(all_tasks)
            has_become = bool(play.get("become", False))
            # merge if multiple plays target the same hosts pattern
            if hosts_pattern in play_facts:
                prev_svc, prev_fw, prev_become = play_facts[hosts_pattern]
                merged_svc = list(dict.fromkeys(prev_svc + services))
                play_facts[hosts_pattern] = (
                    merged_svc, prev_fw + fw_count, prev_become or has_become
                )
            else:
                play_facts[hosts_pattern] = (services, fw_count, has_become)

        return play_facts

    def _build_enrichment(
        self,
        playbook_dir: Path,
        inventory: Dict[str, Any],
        playbook_content: Any,
    ) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        """Build host and group enrichment dicts from all available sources."""
        play_facts = self._collect_play_facts(playbook_content)

        # group_enrichment
        group_enrichment: Dict[str, Any] = {}
        for group_name in inventory["groups"]:
            gvars = self._parse_group_vars(playbook_dir, group_name)
            is_trusted = _infer_boundary_trust(group_name)

            # aggregate firewall count from plays targeting this group or 'all'
            fw_count = 0
            for pattern, (_, fw, _) in play_facts.items():
                if pattern == "all" or pattern == group_name:
                    fw_count += fw

            traversal = _infer_traversal_difficulty(group_name, fw_count)
            group_enrichment[group_name] = {
                "group_vars": gvars,
                "isTrusted": is_trusted,
                "traversal_difficulty": traversal,
            }

        # host_enrichment
        host_enrichment: Dict[str, Any] = {}
        for hostname, hinfo in inventory["hosts"].items():
            group = hinfo.get("group", "")
            hvars = self._parse_host_vars(playbook_dir, hostname)
            # merge inventory inline vars (ansible_host, etc.)
            merged_vars = dict(hinfo)
            merged_vars.update(hvars)

            # determine has_become from plays targeting this host's group
            has_become = False
            services: List[str] = []
            for pattern, (svc, _, become) in play_facts.items():
                if pattern == "all" or pattern == group:
                    if become:
                        has_become = True
                    for s in svc:
                        if s not in services:
                            services.append(s)

            host_enrichment[hostname] = {
                "group": group,
                "host_vars": merged_vars,
                "services": services,
                "internet_facing": _infer_internet_facing(group, merged_vars),
                "credentials_stored": _infer_credentials_stored(merged_vars, has_become),
            }

        return host_enrichment, group_enrichment

    # ------------------------------------------------------------------
    # DSL rendering
    # ------------------------------------------------------------------

    @staticmethod
    def _fmt(v: Any) -> str:
        """Format a DSL value: Python booleans → lowercase string."""
        if isinstance(v, bool):
            return str(v).lower()
        return str(v)

    def _render_from_metadata(
        self,
        metadata: Dict[str, Any],
        host_enrichment: Dict[str, Any],
        group_enrichment: Dict[str, Any],
    ) -> str:
        """Render DSL from ``threat_model_metadata`` block, enriched with inferred data."""
        markdown: List[str] = []

        if "boundaries" in metadata:
            markdown.append("## Boundaries")
            for boundary in metadata["boundaries"]:
                bname = boundary["name"]
                props = [
                    f"{k}={self._fmt(v)}"
                    for k, v in boundary.items()
                    if k not in ("name", "sub_boundaries")
                ]
                # Apply group enrichment if group name matches boundary name
                ge = group_enrichment.get(bname, {})
                td = ge.get("traversal_difficulty")
                if td and not any("traversal_difficulty" in p for p in props):
                    props.append(f"traversal_difficulty={td}")
                markdown.append(f"- **{bname}**: {', '.join(props)}")
                if "sub_boundaries" in boundary:
                    for sb in boundary["sub_boundaries"]:
                        sbname = sb["name"]
                        sb_props = [
                            f"{k}={self._fmt(v)}" for k, v in sb.items() if k != "name"
                        ]
                        sge = group_enrichment.get(sbname, {})
                        sb_td = sge.get("traversal_difficulty")
                        if sb_td and not any("traversal_difficulty" in p for p in sb_props):
                            sb_props.append(f"traversal_difficulty={sb_td}")
                        markdown.append(f"  - **{sbname}**: {', '.join(sb_props)}")
            markdown.append("")

        if "actors" in metadata:
            markdown.append("## Actors")
            for actor in metadata["actors"]:
                props = [
                    f"{k}={self._fmt(v)}" for k, v in actor.items() if k != "name"
                ]
                markdown.append(f"- **{actor['name']}**: {', '.join(props)}")
            markdown.append("")

        if "servers" in metadata:
            markdown.append("## Servers")
            for server in metadata["servers"]:
                sname = server["name"]
                props = [
                    f"{k}={self._fmt(v)}" for k, v in server.items() if k != "name"
                ]
                # Look up enrichment by server name (case-insensitive)
                enrichment = self._find_host_enrichment(sname, host_enrichment)
                if enrichment:
                    if enrichment.get("internet_facing") and not any(
                        "internet_facing" in p for p in props
                    ):
                        props.append("internet_facing=true")
                    if enrichment.get("credentials_stored") and not any(
                        "credentials_stored" in p for p in props
                    ):
                        props.append("credentials_stored=true")
                markdown.append(f"- **{sname}**: {', '.join(props)}")
            markdown.append("")

        if "data" in metadata:
            markdown.append("## Data")
            for data_item in metadata["data"]:
                props = [
                    f"{k}={self._fmt(v)}" for k, v in data_item.items() if k != "name"
                ]
                markdown.append(f"- **{data_item['name']}**: {', '.join(props)}")
            markdown.append("")

        if "data_flows" in metadata:
            markdown.append("## Dataflows")
            for flow in metadata["data_flows"]:
                source_name = (
                    flow["source"].replace("actor:", "").replace("server:", "")
                )
                destination_name = (
                    flow["destination"].replace("actor:", "").replace("server:", "")
                )
                props = [
                    f'from="{source_name}"',
                    f'to="{destination_name}"',
                    f'protocol="{flow["protocol"]}"',
                    f'data="{flow["data"]}"',
                ]
                if "description" in flow:
                    props.append(f'description="{flow["description"]}"')
                markdown.append(f"- **{flow['name']}**: {', '.join(props)}")
            markdown.append("")

        return "\n".join(markdown)

    def _render_from_inventory(
        self,
        inventory: Dict[str, Any],
        host_enrichment: Dict[str, Any],
        group_enrichment: Dict[str, Any],
    ) -> str:
        """Auto-generate DSL from inventory groups when no metadata block is present."""
        markdown: List[str] = []

        non_empty_groups = {
            g: hosts
            for g, hosts in inventory["groups"].items()
            if hosts
        }

        if non_empty_groups:
            markdown.append("## Boundaries")
            for group_name in non_empty_groups:
                ge = group_enrichment.get(group_name, {})
                is_trusted = ge.get("isTrusted", True)
                props: List[str] = [f"isTrusted={str(is_trusted).lower()}"]
                td = ge.get("traversal_difficulty")
                if td:
                    props.append(f"traversal_difficulty={td}")
                markdown.append(f"- **{group_name}**: {', '.join(props)}")
            markdown.append("")

        if inventory["hosts"]:
            markdown.append("## Servers")
            for hostname, hinfo in inventory["hosts"].items():
                group = hinfo.get("group", "")
                props = [f'boundary="{group}"'] if group else []
                enrichment = host_enrichment.get(hostname, {})
                if enrichment.get("internet_facing"):
                    props.append("internet_facing=true")
                if enrichment.get("credentials_stored"):
                    props.append("credentials_stored=true")
                markdown.append(f"- **{hostname}**: {', '.join(props)}")
            markdown.append("")

        return "\n".join(markdown)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _find_host_enrichment(
        server_name: str, host_enrichment: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """Find enrichment data for a server by matching hostname patterns.

        Resolution order:
        1. Exact key match
        2. Case-insensitive exact match
        3. Substring containment (normalised to lowercase-hyphens)
        4. Token overlap — split on [-_\\s] and check for shared meaningful tokens
           (e.g. DSL ``WebServer`` shares token ``web`` with host ``web-app-01``)
        """
        lower_name = server_name.lower().replace("_", "-").replace(" ", "-")
        # 1. Exact
        if server_name in host_enrichment:
            return host_enrichment[server_name]
        # 2. Case-insensitive exact
        for hostname, data in host_enrichment.items():
            if hostname.lower() == server_name.lower():
                return data
        # 3. Substring
        for hostname, data in host_enrichment.items():
            hn_lower = hostname.lower().replace("_", "-")
            if lower_name in hn_lower or hn_lower in lower_name:
                return data
        # 4. Token overlap or prefix match (meaningful tokens — length > 2)
        #    Handles e.g. DSL "WebServer" ↔ host "web-app-01" via "web" prefix of "webserver"
        name_tokens = {
            t for t in re.split(r"[-_\s]", lower_name) if len(t) > 2
        }
        for hostname, data in host_enrichment.items():
            hn_tokens = {
                t for t in re.split(r"[-_\s]", hostname.lower()) if len(t) > 2
            }
            # Direct overlap
            if name_tokens & hn_tokens:
                return data
            # Prefix match: a host token is a prefix of a name token or vice-versa
            for nt in name_tokens:
                for ht in hn_tokens:
                    if nt.startswith(ht) or ht.startswith(nt):
                        return data
        return None
