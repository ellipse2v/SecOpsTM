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

"""Terraform IaC plugin for SecOpsTM.

Parses HCL Terraform files (.tf) and tfstate via regex / JSON and converts
discovered resources into SecOpsTM Markdown DSL components.

Enrichment (from tfstate attributes):
  - ``internet_facing``      — public_ip, associate_public_ip_address, publicly_accessible
  - ``credentials_stored``   — iam_instance_profile, env vars with *PASSWORD*/*SECRET*/*TOKEN*
  - ``traversal_difficulty`` — security-group ingress rules (open any-port → low,
                                specific ports → medium, no 0.0.0.0/0 → high)

BOM generation:
  - :meth:`TerraformPlugin.generate_bom_files` writes one YAML file per server
    asset under ``{output_dir}/BOM/``.
"""

import json
import logging
import re
import yaml
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from threat_analysis.iac_plugins import IaCPlugin

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Resource-type → DSL component mapping tables
# ---------------------------------------------------------------------------

_SERVER_RESOURCES: Dict[str, Dict[str, str]] = {
    # Compute / VM
    "aws_instance":                        {"type": "server"},
    "google_compute_instance":             {"type": "server"},
    "azurerm_virtual_machine":             {"type": "server"},
    "azurerm_linux_virtual_machine":       {"type": "server"},
    "azurerm_windows_virtual_machine":     {"type": "server"},
    # Serverless
    "aws_lambda_function":                 {"type": "serverless"},
    "google_cloudfunctions_function":      {"type": "serverless"},
    "google_cloudfunctions2_function":     {"type": "serverless"},
    "azurerm_function_app":                {"type": "serverless"},
    "azurerm_linux_function_app":          {"type": "serverless"},
    # Database
    "aws_rds_instance":                    {"type": "database"},
    "aws_rds_cluster":                     {"type": "database"},
    "aws_dynamodb_table":                  {"type": "database"},
    "aws_elasticache_cluster":             {"type": "database"},
    "google_sql_database_instance":        {"type": "database"},
    "google_bigtable_instance":            {"type": "database"},
    "google_spanner_instance":             {"type": "database"},
    "azurerm_sql_server":                  {"type": "database"},
    "azurerm_cosmosdb_account":            {"type": "database"},
    "azurerm_postgresql_server":           {"type": "database"},
    "azurerm_mysql_server":                {"type": "database"},
    # Storage
    "aws_s3_bucket":                       {"type": "storage"},
    "google_storage_bucket":               {"type": "storage"},
    "azurerm_storage_account":             {"type": "storage"},
    # Load balancers
    "aws_lb":                              {"type": "loadbalancer"},
    "aws_alb":                             {"type": "loadbalancer"},
    "aws_elb":                             {"type": "loadbalancer"},
    "google_compute_forwarding_rule":      {"type": "loadbalancer"},
    "google_compute_global_forwarding_rule": {"type": "loadbalancer"},
    "azurerm_lb":                          {"type": "loadbalancer"},
    "azurerm_application_gateway":         {"type": "loadbalancer"},
    # API Gateway
    "aws_api_gateway_rest_api":            {"type": "api_gateway"},
    "aws_apigatewayv2_api":                {"type": "api_gateway"},
    "google_api_gateway_api":              {"type": "api_gateway"},
    "azurerm_api_management":              {"type": "api_gateway"},
    # Kubernetes / container
    "aws_eks_cluster":                     {"type": "server"},
    "google_container_cluster":            {"type": "server"},
    "azurerm_kubernetes_cluster":          {"type": "server"},
    # Message queues / event buses
    "aws_sqs_queue":                       {"type": "server"},
    "aws_sns_topic":                       {"type": "server"},
    "google_pubsub_topic":                 {"type": "server"},
    "azurerm_servicebus_namespace":        {"type": "server"},
    # Caches
    "aws_elasticache_replication_group":   {"type": "server"},
    "google_memcache_instance":            {"type": "server"},
    "azurerm_redis_cache":                 {"type": "server"},
}

_BOUNDARY_RESOURCES: Dict[str, Dict[str, str]] = {
    "aws_vpc":                       {"isTrusted": "false"},
    "google_compute_network":        {"isTrusted": "false"},
    "azurerm_virtual_network":       {"isTrusted": "false"},
    "aws_subnet":                    {"isTrusted": "true"},
    "google_compute_subnetwork":     {"isTrusted": "true"},
    "azurerm_subnet":                {"isTrusted": "true"},
    "aws_security_group":            {"isTrusted": "true"},
    "google_compute_firewall":       {"isTrusted": "true"},
    "azurerm_network_security_group": {"isTrusted": "true"},
}

_ACTOR_RESOURCES: Dict[str, Dict[str, str]] = {
    "aws_iam_user":                        {},
    "aws_iam_role":                        {},
    "google_service_account":              {},
    "google_project_iam_member":           {},
    "azurerm_user_assigned_identity":      {},
    "azurerm_role_assignment":             {},
}

_CONNECTIVITY_ATTRS: List[str] = [
    "vpc_id",
    "subnet_id",
    "subnet_ids",
    "security_groups",
    "security_group_ids",
    "network_interface_ids",
    "db_subnet_group_name",
    "source_security_group_id",
    "destination_security_group_id",
]

# Resource-type → typical running services (for BOM generation)
_RESOURCE_SERVICES: Dict[str, List[str]] = {
    "aws_instance":                      ["ssh"],
    "google_compute_instance":           ["ssh"],
    "azurerm_virtual_machine":           ["rdp", "ssh"],
    "azurerm_linux_virtual_machine":     ["ssh"],
    "azurerm_windows_virtual_machine":   ["rdp"],
    "aws_rds_instance":                  ["postgresql"],
    "aws_rds_cluster":                   ["postgresql"],
    "aws_dynamodb_table":                ["https"],
    "aws_elasticache_cluster":           ["redis"],
    "aws_elasticache_replication_group": ["redis"],
    "azurerm_redis_cache":               ["redis"],
    "google_sql_database_instance":      ["postgresql", "mysql"],
    "azurerm_sql_server":                ["mssql"],
    "azurerm_postgresql_server":         ["postgresql"],
    "azurerm_mysql_server":              ["mysql"],
    "aws_lambda_function":               ["https"],
    "google_cloudfunctions_function":    ["https"],
    "google_cloudfunctions2_function":   ["https"],
    "azurerm_function_app":              ["https"],
    "azurerm_linux_function_app":        ["https"],
    "aws_eks_cluster":                   ["kubernetes-api", "https"],
    "google_container_cluster":          ["kubernetes-api", "https"],
    "azurerm_kubernetes_cluster":        ["kubernetes-api", "https"],
    "aws_s3_bucket":                     ["https"],
    "google_storage_bucket":             ["https"],
    "azurerm_storage_account":           ["https"],
    "aws_lb":                            ["https"],
    "aws_alb":                           ["https"],
    "aws_elb":                           ["https"],
    "azurerm_lb":                        ["https"],
    "azurerm_application_gateway":       ["https"],
    "aws_api_gateway_rest_api":          ["https"],
    "aws_apigatewayv2_api":              ["https"],
    "azurerm_api_management":            ["https"],
    "aws_sqs_queue":                     ["https"],
    "aws_sns_topic":                     ["https"],
    "google_pubsub_topic":               ["https"],
    "azurerm_servicebus_namespace":      ["amqp", "https"],
}

_CREDENTIAL_KEYWORDS: frozenset = frozenset(
    ["PASSWORD", "SECRET", "KEY", "TOKEN", "CREDENTIAL", "PASSWD", "API_KEY"]
)


# ---------------------------------------------------------------------------
# Enrichment inference helpers (module-level, pure functions)
# ---------------------------------------------------------------------------

def _infer_internet_facing(attrs: Dict[str, Any]) -> bool:
    """True if the resource exposes a public IP or is explicitly public."""
    if attrs.get("associate_public_ip_address") == "true":
        return True
    if attrs.get("publicly_accessible") == "true":
        return True
    public_ip = attrs.get("public_ip", "")
    if isinstance(public_ip, str) and public_ip not in ("", "null", "None", "false"):
        return True
    return False


def _infer_credentials_stored(attrs: Dict[str, Any]) -> bool:
    """True if the resource has an IAM profile or credential-carrying env vars."""
    if attrs.get("iam_instance_profile") or attrs.get("iam_instance_profile_arn"):
        return True
    for attr_key in ("environment", "environment_variables"):
        env_raw = attrs.get(attr_key)
        if not env_raw:
            continue
        if isinstance(env_raw, str):
            try:
                env_obj = json.loads(env_raw)
            except (ValueError, TypeError):
                continue
        else:
            env_obj = env_raw
        if isinstance(env_obj, list):
            env_dict: Dict[str, str] = {
                e.get("name", ""): e.get("value", "")
                for e in env_obj
                if isinstance(e, dict)
            }
        elif isinstance(env_obj, dict):
            env_dict = {str(k): str(v) for k, v in env_obj.items()}
        else:
            continue
        for key in env_dict:
            if any(kw in key.upper() for kw in _CREDENTIAL_KEYWORDS):
                return True
    return False


def _parse_ingress_rules(attrs: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Return the list of ingress rule dicts from a security-group's attributes.

    In tfstate v4 the ``ingress`` attribute is a list of dicts. After parsing
    it is stored as a JSON string (because ``_parse_tfstate`` serialises
    list-of-dicts to preserve them).
    """
    ingress_raw = attrs.get("ingress", "")
    if not ingress_raw:
        return []
    if isinstance(ingress_raw, str):
        try:
            parsed = json.loads(ingress_raw)
            return parsed if isinstance(parsed, list) else []
        except (ValueError, TypeError):
            return []
    if isinstance(ingress_raw, list):
        return ingress_raw
    return []


def _infer_traversal_difficulty(attrs: Dict[str, Any]) -> str:
    """Infer traversal difficulty from security-group ingress rules.

    Returns:
        ``"low"``    — any rule allows all traffic from 0.0.0.0/0 (all ports/protocols)
        ``"medium"`` — open rules exist but only for specific ports, or no rules at all
        ``"high"``   — no rule allows traffic from 0.0.0.0/0 or ::/0
    """
    rules = _parse_ingress_rules(attrs)
    if not rules:
        return "medium"

    open_any_port = False
    open_specific_port = False

    for rule in rules:
        if not isinstance(rule, dict):
            continue
        cidrs: List[str] = []
        for cidr_key in ("cidr_blocks", "ipv6_cidr_blocks"):
            cidr_val = rule.get(cidr_key, [])
            if isinstance(cidr_val, list):
                cidrs.extend(cidr_val)

        if "0.0.0.0/0" not in cidrs and "::/0" not in cidrs:
            continue

        protocol = str(rule.get("protocol", "tcp"))
        try:
            from_port = int(rule.get("from_port", 0) or 0)
            to_port = int(rule.get("to_port", 0) or 0)
        except (ValueError, TypeError):
            from_port = to_port = 0

        if (
            protocol in ("-1", "all")
            or (from_port == 0 and to_port == 0)
            or (from_port == -1 and to_port == -1)
        ):
            open_any_port = True
        else:
            open_specific_port = True

    if open_any_port:
        return "low"
    if open_specific_port:
        return "medium"
    return "high"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _sanitize_name(raw: str) -> str:
    """Convert a raw Terraform resource name to a human-readable DSL name."""
    return raw.replace("_", " ").replace("-", " ").title()


def _provider_of(resource_type: str) -> str:
    """Return the cloud provider prefix from a Terraform resource type."""
    if resource_type.startswith("aws_"):
        return "AWS"
    if resource_type.startswith("google_"):
        return "GCP"
    if resource_type.startswith("azurerm_"):
        return "Azure"
    return "Cloud"


# ---------------------------------------------------------------------------
# HCL-lite regex parser
# ---------------------------------------------------------------------------

_RESOURCE_HEADER_RE = re.compile(
    r'resource\s+"([^"]+)"\s+"([^"]+)"\s*\{',
    re.MULTILINE,
)
_ATTR_SCALAR_RE = re.compile(
    r'^\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*"?([^"\n{}\[\]]+)"?\s*$',
    re.MULTILINE,
)
_ATTR_LIST_RE = re.compile(
    r'([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*\[([^\]]*)\]',
    re.DOTALL,
)


def _extract_block_body(hcl_text: str, open_brace_pos: int) -> str:
    """Return the text inside the outermost braces starting at *open_brace_pos*."""
    depth = 0
    start = open_brace_pos
    for i in range(start, len(hcl_text)):
        ch = hcl_text[i]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return hcl_text[start + 1 : i]
    return hcl_text[start + 1 :]


def _parse_tf_text(hcl_text: str) -> List[Dict[str, Any]]:
    """Parse HCL Terraform source text into a list of resource dicts."""
    resources: List[Dict[str, Any]] = []

    for match in _RESOURCE_HEADER_RE.finditer(hcl_text):
        resource_type = match.group(1)
        resource_name = match.group(2)
        open_pos = match.end() - 1
        body = _extract_block_body(hcl_text, open_pos)

        attributes: Dict[str, Any] = {}

        for attr_match in _ATTR_SCALAR_RE.finditer(body):
            key = attr_match.group(1).strip()
            value = attr_match.group(2).strip()
            if key not in ("for_each", "count", "depends_on", "lifecycle"):
                attributes[key] = value

        for list_match in _ATTR_LIST_RE.finditer(body):
            key = list_match.group(1).strip()
            raw_list = list_match.group(2)
            items = [
                item.strip().strip('"').strip("'")
                for item in raw_list.split(",")
                if item.strip().strip('"').strip("'")
            ]
            if items:
                attributes[key] = items

        resources.append(
            {
                "resource_type": resource_type,
                "name": resource_name,
                "attributes": attributes,
            }
        )
        logger.debug(
            "Parsed resource %s.%s with %d attributes",
            resource_type, resource_name, len(attributes),
        )

    return resources


# ---------------------------------------------------------------------------
# tfstate parser
# ---------------------------------------------------------------------------

def _parse_tfstate(state_path: Path) -> List[Dict[str, Any]]:
    """Extract resources from a ``terraform.tfstate`` JSON file (format v4).

    List-of-dicts attributes (e.g., security-group ``ingress``/``egress``
    rules) are serialised as a JSON string so that downstream inference code
    can parse them without losing information.
    """
    resources: List[Dict[str, Any]] = []
    try:
        with open(state_path, "r", encoding="utf-8") as fh:
            state = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning("Could not read tfstate %s: %s", state_path, exc)
        return resources

    version = state.get("version", 0)
    if version < 4:
        logger.warning(
            "tfstate version %d at %s may not be fully supported (expected 4+)",
            version, state_path,
        )

    for res in state.get("resources", []):
        if res.get("mode") != "managed":
            continue
        resource_type = res.get("type", "")
        instances = res.get("instances", [])
        if not instances:
            continue
        attrs = instances[0].get("attributes", {})

        flat_attrs: Dict[str, Any] = {}
        for k, v in attrs.items():
            if isinstance(v, (str, int, float, bool)):
                flat_attrs[k] = str(v)
            elif isinstance(v, list):
                if v and all(isinstance(i, dict) for i in v):
                    # Preserve list-of-dicts as JSON string (e.g. ingress rules)
                    flat_attrs[k] = json.dumps(v)
                else:
                    flat_attrs[k] = [str(i) for i in v if not isinstance(i, dict)]

        resources.append(
            {
                "resource_type": resource_type,
                "name": res.get("name", "unknown"),
                "attributes": flat_attrs,
            }
        )
    logger.debug("Loaded %d managed resources from tfstate", len(resources))
    return resources


# ---------------------------------------------------------------------------
# Main plugin class
# ---------------------------------------------------------------------------

class TerraformPlugin(IaCPlugin):
    """IaC Plugin for Terraform configurations.

    Accepts a single ``.tf`` file or a directory (recursively scanned for
    ``.tf`` files).  If a ``terraform.tfstate`` file is found in the same
    directory, it is used in preference to the raw HCL sources because the
    state file reflects the *actual* deployed topology rather than the
    intended one.
    """

    @property
    def name(self) -> str:
        return "terraform"

    @property
    def description(self) -> str:
        return (
            "Parses Terraform HCL (.tf) files or tfstate to generate "
            "SecOpsTM threat model components for AWS, Azure, and GCP resources."
        )

    # ------------------------------------------------------------------
    # IaCPlugin interface
    # ------------------------------------------------------------------

    def parse_iac_config(self, config_path: str) -> Dict[str, Any]:
        """Parse Terraform sources at *config_path*."""
        input_path = Path(config_path).resolve()

        if not input_path.exists():
            raise ValueError(f"Terraform path does not exist: {config_path}")

        resources: List[Dict[str, Any]] = []

        if input_path.is_file():
            if input_path.suffix != ".tf":
                raise ValueError(f"Expected a .tf file, got: {input_path.name}")
            logger.info("Parsing single Terraform file: %s", input_path)
            resources = self._load_tf_file(input_path)
        else:
            state_file = input_path / "terraform.tfstate"
            if state_file.is_file():
                logger.info(
                    "Found terraform.tfstate — using state file: %s", state_file
                )
                resources = _parse_tfstate(state_file)
            else:
                logger.info(
                    "No terraform.tfstate found; scanning .tf files in %s", input_path
                )
                tf_files = sorted(input_path.rglob("*.tf"))
                if not tf_files:
                    raise ValueError(f"No .tf files found under directory: {input_path}")
                for tf_file in tf_files:
                    resources.extend(self._load_tf_file(tf_file))

        logger.info("Terraform parse complete: %d resources discovered", len(resources))
        return {"resources": resources}

    def generate_threat_model_components(self, iac_data: Dict[str, Any]) -> str:
        """Generate a SecOpsTM Markdown DSL string from parsed Terraform data."""
        resources: List[Dict[str, Any]] = iac_data.get("resources", [])

        boundaries: List[Dict[str, Any]] = []
        servers: List[Dict[str, Any]] = []
        actors: List[Dict[str, Any]] = []
        name_registry: Dict[str, str] = {}

        for res in resources:
            rtype = res["resource_type"]
            rname = res["name"]
            attrs = res.get("attributes", {})
            dsl_name = _sanitize_name(rname)
            tf_key = f"{rtype}.{rname}"
            name_registry[tf_key] = dsl_name

            if rtype in _SERVER_RESOURCES:
                extra = _SERVER_RESOURCES[rtype]
                servers.append(
                    {
                        "name": dsl_name,
                        "type": extra.get("type", "server"),
                        "description": (
                            f"{_provider_of(rtype)} {rtype.replace('_', ' ')}"
                        ),
                        "internet_facing": _infer_internet_facing(attrs),
                        "credentials_stored": _infer_credentials_stored(attrs),
                        "_tf_key": tf_key,
                        "_resource_type": rtype,
                        "_attrs": attrs,
                    }
                )

            elif rtype in _BOUNDARY_RESOURCES:
                extra = _BOUNDARY_RESOURCES[rtype]
                is_nested = "subnet" in rtype or "security_group" in rtype
                traversal = (
                    _infer_traversal_difficulty(attrs)
                    if "security_group" in rtype or "firewall" in rtype
                    else None
                )
                boundaries.append(
                    {
                        "name": dsl_name,
                        "isTrusted": extra.get("isTrusted", "false"),
                        "description": (
                            f"{_provider_of(rtype)} {rtype.replace('_', ' ')}"
                        ),
                        "traversal_difficulty": traversal,
                        "_nested": is_nested,
                        "_tf_key": tf_key,
                        "_attrs": attrs,
                    }
                )

            elif rtype in _ACTOR_RESOURCES:
                actors.append(
                    {
                        "name": dsl_name,
                        "description": (
                            f"{_provider_of(rtype)} {rtype.replace('_', ' ')}"
                        ),
                        "_tf_key": tf_key,
                        "_attrs": attrs,
                    }
                )
            else:
                logger.debug("Resource type %s not mapped, skipping", rtype)

        dataflows = self._derive_dataflows(servers, boundaries, actors, name_registry)
        return self._render_markdown(boundaries, actors, servers, dataflows)

    def generate_bom_files(self, iac_data: Dict[str, Any], output_dir: str) -> List[str]:
        """Generate one BOM YAML file per server asset under ``{output_dir}/BOM/``.

        The BOM key (filename) is the DSL server name normalised to
        lowercase-underscores, matching :func:`BOMLoader._normalize_asset_key`.
        """
        resources = iac_data.get("resources", [])
        bom_dir = Path(output_dir) / "BOM"
        bom_dir.mkdir(parents=True, exist_ok=True)

        written: List[str] = []
        for res in resources:
            rtype = res["resource_type"]
            if rtype not in _SERVER_RESOURCES:
                continue
            attrs = res.get("attributes", {})
            dsl_name = _sanitize_name(res["name"])
            bom_key = re.sub(r"\s+", "_", dsl_name.lower())

            bom: Dict[str, Any] = {
                "asset": dsl_name,
                "os_version": attrs.get(
                    "ami",
                    attrs.get("engine", attrs.get("runtime", "unknown")),
                ),
                "software_version": attrs.get(
                    "engine_version", attrs.get("runtime", "")
                ),
                "patch_level": "unknown",
                "known_cves": [],
                "running_services": _RESOURCE_SERVICES.get(rtype, []),
                "detection_level": "low",
                "credentials_stored": _infer_credentials_stored(attrs),
                "notes": (
                    f"Auto-generated from Terraform resource {rtype}."
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
    # Private helpers
    # ------------------------------------------------------------------

    def _load_tf_file(self, path: Path) -> List[Dict[str, Any]]:
        try:
            text = path.read_text(encoding="utf-8")
        except OSError as exc:
            logger.warning("Could not read %s: %s", path, exc)
            return []
        return _parse_tf_text(text)

    def _derive_dataflows(
        self,
        servers: List[Dict[str, Any]],
        boundaries: List[Dict[str, Any]],
        actors: List[Dict[str, Any]],
        name_registry: Dict[str, str],
    ) -> List[Dict[str, Any]]:
        """Derive implicit dataflows from connectivity attributes."""
        dataflows: List[Dict[str, Any]] = []
        seen: Set[Tuple[str, str]] = set()

        boundary_names_by_tf_key: Dict[str, str] = {
            b["_tf_key"]: b["name"] for b in boundaries
        }

        all_components = servers + actors

        for comp in all_components:
            attrs = comp.get("_attrs", {})
            src_name = comp["name"]

            for attr_key in _CONNECTIVITY_ATTRS:
                ref_value = attrs.get(attr_key)
                if not ref_value:
                    continue

                refs: List[str] = (
                    ref_value if isinstance(ref_value, list) else [ref_value]
                )

                for ref in refs:
                    tf_key = self._resolve_ref(ref)
                    if not tf_key:
                        continue

                    dst_name = boundary_names_by_tf_key.get(tf_key)
                    if not dst_name:
                        for srv in servers:
                            if srv["_tf_key"] == tf_key:
                                dst_name = srv["name"]
                                break

                    if not dst_name or dst_name == src_name:
                        continue

                    edge = (src_name, dst_name)
                    if edge in seen:
                        continue
                    seen.add(edge)

                    dataflows.append(
                        {
                            "name": f"{src_name} To {dst_name}",
                            "source": src_name,
                            "destination": dst_name,
                            "protocol": "HTTPS",
                            "data": "ApplicationData",
                        }
                    )

        return dataflows

    @staticmethod
    def _resolve_ref(ref_value: str) -> Optional[str]:
        """Convert a Terraform attribute value to a resource tf_key if possible."""
        cleaned = re.sub(r'[${}]', '', ref_value).strip()
        parts = cleaned.split(".")
        if len(parts) >= 2:
            candidate = f"{parts[0]}.{parts[1]}"
            if "_" in parts[0]:
                return candidate
        return None

    # ------------------------------------------------------------------
    # Markdown rendering
    # ------------------------------------------------------------------

    def _render_markdown(
        self,
        boundaries: List[Dict[str, Any]],
        actors: List[Dict[str, Any]],
        servers: List[Dict[str, Any]],
        dataflows: List[Dict[str, Any]],
    ) -> str:
        """Render all components as a SecOpsTM Markdown DSL string."""
        lines: List[str] = []

        if boundaries:
            lines.append("## Boundaries")
            top_level = [b for b in boundaries if not b.get("_nested", False)]
            nested = [b for b in boundaries if b.get("_nested", False)]

            for b in top_level:
                props: List[str] = [
                    f"isTrusted={b['isTrusted']}",
                    f"description=\"{b['description']}\"",
                ]
                if b.get("traversal_difficulty"):
                    props.append(f"traversal_difficulty={b['traversal_difficulty']}")
                lines.append(f"- **{b['name']}**: {', '.join(props)}")
                for nb in nested:
                    nb_props: List[str] = [
                        f"isTrusted={nb['isTrusted']}",
                        f"description=\"{nb['description']}\"",
                    ]
                    if nb.get("traversal_difficulty"):
                        nb_props.append(
                            f"traversal_difficulty={nb['traversal_difficulty']}"
                        )
                    lines.append(f"  - **{nb['name']}**: {', '.join(nb_props)}")
            if not top_level:
                for b in nested:
                    props = [
                        f"isTrusted={b['isTrusted']}",
                        f"description=\"{b['description']}\"",
                    ]
                    if b.get("traversal_difficulty"):
                        props.append(
                            f"traversal_difficulty={b['traversal_difficulty']}"
                        )
                    lines.append(f"- **{b['name']}**: {', '.join(props)}")
            lines.append("")

        if actors:
            lines.append("## Actors")
            for a in actors:
                lines.append(
                    f"- **{a['name']}**: description=\"{a['description']}\""
                )
            lines.append("")

        if servers:
            lines.append("## Servers")
            for s in servers:
                props = [
                    f"type={s['type']}",
                    f"description=\"{s['description']}\"",
                ]
                if s.get("internet_facing"):
                    props.append("internet_facing=true")
                if s.get("credentials_stored"):
                    props.append("credentials_stored=true")
                lines.append(f"- **{s['name']}**: {', '.join(props)}")
            lines.append("")

        if dataflows:
            lines.append("## Dataflows")
            for df in dataflows:
                props = [
                    f'from="{df["source"]}"',
                    f'to="{df["destination"]}"',
                    f'protocol="{df["protocol"]}"',
                    f'data="{df["data"]}"',
                ]
                lines.append(f"- **{df['name']}**: {', '.join(props)}")
            lines.append("")

        return "\n".join(lines)
