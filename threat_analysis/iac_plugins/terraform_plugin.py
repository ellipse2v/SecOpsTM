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

Parses HCL Terraform files (.tf) and optional tfstate via regex (no external
HCL parser dependency) and converts discovered resources into SecOpsTM
Markdown DSL components.
"""

import json
import logging
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from threat_analysis.iac_plugins import IaCPlugin

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Resource-type → DSL component mapping tables
# ---------------------------------------------------------------------------

# Resources that map to a SecOpsTM Server component.
# Value is a dict with optional extra DSL properties.
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

# Resources that map to a SecOpsTM Boundary component.
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

# Resources that map to a SecOpsTM Actor component.
_ACTOR_RESOURCES: Dict[str, Dict[str, str]] = {
    "aws_iam_user":                        {},
    "aws_iam_role":                        {},
    "google_service_account":              {},
    "google_project_iam_member":           {},
    "azurerm_user_assigned_identity":      {},
    "azurerm_role_assignment":             {},
}

# Attribute names that carry references to other resources (used for
# implicit dataflow detection).
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


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _sanitize_name(raw: str) -> str:
    """Convert a raw Terraform resource name to a human-readable DSL name.

    Replaces underscores and hyphens with spaces, title-cases the result.
    """
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

# Matches: resource "TYPE" "NAME" { ... }
# We deliberately use a non-greedy body match; nested braces are handled by
# the brace-counting post-processor below.
_RESOURCE_HEADER_RE = re.compile(
    r'resource\s+"([^"]+)"\s+"([^"]+)"\s*\{',
    re.MULTILINE,
)

# Matches a simple scalar attribute: key = "value" or key = value
_ATTR_SCALAR_RE = re.compile(
    r'^\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*"?([^"\n{}\[\]]+)"?\s*$',
    re.MULTILINE,
)

# Matches a list attribute: key = ["v1", "v2", ...]
_ATTR_LIST_RE = re.compile(
    r'([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*\[([^\]]*)\]',
    re.DOTALL,
)


def _extract_block_body(hcl_text: str, open_brace_pos: int) -> str:
    """Return the text inside the outermost braces starting at *open_brace_pos*.

    The character at *open_brace_pos* must be ``{``.
    """
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
    """Parse HCL Terraform source text into a list of resource dicts.

    Each dict has the shape::

        {
            "resource_type": str,
            "name": str,
            "attributes": Dict[str, Any],   # scalar or list values
        }

    This parser intentionally ignores modules, providers, variables, locals,
    and data sources — only ``resource`` blocks are relevant for the threat
    model.
    """
    resources: List[Dict[str, Any]] = []

    for match in _RESOURCE_HEADER_RE.finditer(hcl_text):
        resource_type = match.group(1)
        resource_name = match.group(2)
        open_pos = match.end() - 1  # position of the opening '{'
        body = _extract_block_body(hcl_text, open_pos)

        attributes: Dict[str, Any] = {}

        # Scalar attributes
        for attr_match in _ATTR_SCALAR_RE.finditer(body):
            key = attr_match.group(1).strip()
            value = attr_match.group(2).strip()
            if key not in ("for_each", "count", "depends_on", "lifecycle"):
                attributes[key] = value

        # List attributes
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
        logger.debug("Parsed resource %s.%s with %d attributes",
                     resource_type, resource_name, len(attributes))

    return resources


# ---------------------------------------------------------------------------
# tfstate parser
# ---------------------------------------------------------------------------

def _parse_tfstate(state_path: Path) -> List[Dict[str, Any]]:
    """Extract resources from a ``terraform.tfstate`` JSON file.

    Returns a list of resource dicts in the same shape as ``_parse_tf_text``.
    tfstate format v4 (Terraform >= 0.13) is assumed; older formats are
    handled gracefully with a warning.
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
        # Use the first instance's attributes as representative
        instances = res.get("instances", [])
        if not instances:
            continue
        attrs = instances[0].get("attributes", {})
        # Flatten only scalar and list values; ignore nested dicts
        flat_attrs: Dict[str, Any] = {}
        for k, v in attrs.items():
            if isinstance(v, (str, int, float, bool)):
                flat_attrs[k] = str(v)
            elif isinstance(v, list):
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
        """Parse Terraform sources at *config_path*.

        Args:
            config_path: Path to a single ``.tf`` file OR a directory.  If a
                directory, all ``.tf`` files are collected recursively.  A
                ``terraform.tfstate`` at the directory root takes priority.

        Returns:
            A dict with key ``"resources"`` containing a list of parsed
            resource dicts (see ``_parse_tf_text`` for the shape).

        Raises:
            ValueError: If the path does not exist or contains no Terraform
                files.
        """
        input_path = Path(config_path).resolve()

        if not input_path.exists():
            raise ValueError(f"Terraform path does not exist: {config_path}")

        resources: List[Dict[str, Any]] = []

        if input_path.is_file():
            if input_path.suffix != ".tf":
                raise ValueError(
                    f"Expected a .tf file, got: {input_path.name}"
                )
            logger.info("Parsing single Terraform file: %s", input_path)
            resources = self._load_tf_file(input_path)
        else:
            # Directory: check for tfstate first
            state_file = input_path / "terraform.tfstate"
            if state_file.is_file():
                logger.info(
                    "Found terraform.tfstate — using state file for higher fidelity: %s",
                    state_file,
                )
                resources = _parse_tfstate(state_file)
            else:
                logger.info(
                    "No terraform.tfstate found; scanning .tf files in %s",
                    input_path,
                )
                tf_files = sorted(input_path.rglob("*.tf"))
                if not tf_files:
                    raise ValueError(
                        f"No .tf files found under directory: {input_path}"
                    )
                for tf_file in tf_files:
                    logger.debug("Parsing %s", tf_file)
                    resources.extend(self._load_tf_file(tf_file))

        logger.info(
            "Terraform parse complete: %d resources discovered", len(resources)
        )
        return {"resources": resources}

    def generate_threat_model_components(self, iac_data: Dict[str, Any]) -> str:
        """Generate a SecOpsTM Markdown DSL string from parsed Terraform data.

        Args:
            iac_data: The dict returned by :meth:`parse_iac_config`.

        Returns:
            A multi-section Markdown string ready to be pasted into the
            SecOpsTM editor or saved as a ``.md`` model file.
        """
        resources: List[Dict[str, Any]] = iac_data.get("resources", [])

        boundaries: List[Dict[str, Any]] = []
        servers: List[Dict[str, Any]] = []
        actors: List[Dict[str, Any]] = []
        dataflows: List[Dict[str, Any]] = []

        # Track canonical DSL names for dataflow source/destination resolution
        name_registry: Dict[str, str] = {}  # tf_key → dsl_name

        # ---- classify resources ----
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
                        "_tf_key": tf_key,
                        "_attrs": attrs,
                    }
                )

            elif rtype in _BOUNDARY_RESOURCES:
                extra = _BOUNDARY_RESOURCES[rtype]
                is_nested = "subnet" in rtype or "security_group" in rtype
                boundaries.append(
                    {
                        "name": dsl_name,
                        "isTrusted": extra.get("isTrusted", "false"),
                        "description": (
                            f"{_provider_of(rtype)} {rtype.replace('_', ' ')}"
                        ),
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

        # ---- implicit dataflows from connectivity attributes ----
        dataflows = self._derive_dataflows(servers, boundaries, actors, name_registry)

        # ---- render Markdown ----
        return self._render_markdown(boundaries, actors, servers, dataflows)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _load_tf_file(self, path: Path) -> List[Dict[str, Any]]:
        """Read and parse a single .tf file."""
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
        """Derive implicit dataflows from connectivity attributes.

        For each server/actor that references a VPC, subnet, or security
        group, we create a logical dataflow from that component to the
        boundary.  This is a best-effort approximation: no protocol is known
        at parse time so we default to ``HTTPS``.
        """
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

                # Normalise to list
                refs: List[str] = (
                    ref_value if isinstance(ref_value, list) else [ref_value]
                )

                for ref in refs:
                    # Try to resolve the ref as a Terraform resource reference
                    # (e.g. "aws_vpc.main.id" → "aws_vpc.main")
                    tf_key = self._resolve_ref(ref)
                    if not tf_key:
                        continue

                    dst_name = boundary_names_by_tf_key.get(tf_key)
                    if not dst_name:
                        # Also search servers (e.g. alb → instance)
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

                    flow_name = f"{src_name} To {dst_name}"
                    dataflows.append(
                        {
                            "name": flow_name,
                            "source": src_name,
                            "destination": dst_name,
                            "protocol": "HTTPS",
                            "data": "ApplicationData",
                        }
                    )
                    logger.debug(
                        "Derived dataflow: %s → %s (via %s)",
                        src_name, dst_name, attr_key,
                    )

        return dataflows

    @staticmethod
    def _resolve_ref(ref_value: str) -> Optional[str]:
        """Convert a Terraform attribute value to a resource tf_key if possible.

        Examples that are resolved::

            "aws_vpc.main.id"   → "aws_vpc.main"
            "aws_vpc.main"      → "aws_vpc.main"
            "${aws_vpc.main.id}" → "aws_vpc.main"

        Bare string values like ``"sg-0abc123"`` cannot be resolved and
        return ``None``.
        """
        # Strip interpolation syntax
        cleaned = re.sub(r'[${}]', '', ref_value).strip()
        # Drop attribute suffix (last segment after the second dot)
        parts = cleaned.split(".")
        if len(parts) >= 2:
            candidate = f"{parts[0]}.{parts[1]}"
            # Only trust it if the prefix looks like a known resource type
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

        # ---- Boundaries ----
        if boundaries:
            lines.append("## Boundaries")
            # Top-level boundaries first (VPCs / VNets), then nested (subnets, SGs)
            top_level = [b for b in boundaries if not b.get("_nested", False)]
            nested = [b for b in boundaries if b.get("_nested", False)]

            for b in top_level:
                lines.append(
                    f"- **{b['name']}**: isTrusted={b['isTrusted']}, "
                    f"description=\"{b['description']}\""
                )
                # Attach nested boundaries as sub-boundaries
                for nb in nested:
                    lines.append(
                        f"  - **{nb['name']}**: isTrusted={nb['isTrusted']}, "
                        f"description=\"{nb['description']}\""
                    )
            # Nested boundaries without a top-level parent
            if not top_level:
                for b in nested:
                    lines.append(
                        f"- **{b['name']}**: isTrusted={b['isTrusted']}, "
                        f"description=\"{b['description']}\""
                    )
            lines.append("")

        # ---- Actors ----
        if actors:
            lines.append("## Actors")
            for a in actors:
                lines.append(
                    f"- **{a['name']}**: description=\"{a['description']}\""
                )
            lines.append("")

        # ---- Servers ----
        if servers:
            lines.append("## Servers")
            for s in servers:
                props = [
                    f"type={s['type']}",
                    f"description=\"{s['description']}\"",
                ]
                lines.append(f"- **{s['name']}**: {', '.join(props)}")
            lines.append("")

        # ---- Dataflows ----
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
