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

"""Docker Compose IaC plugin for SecOpsTM.

Parses a ``docker-compose.yml``/``docker-compose.yaml`` file (Compose spec
v2/v3) and produces SecOpsTM Markdown DSL components.

Mapping:
  - Each top-level ``networks:`` entry (or the implicit default network when
    none is declared)                     -> Boundary
  - Each ``services.<name>``              -> Server (``type=`` inferred from
    the image, see ``_IMAGE_TYPE_MAP``)
  - ``ports:`` publishing a host port     -> ``internet_facing=true``
  - ``environment``/``secrets``/``configs`` containing credential-like keys
    or any use of ``secrets:``/``configs:`` -> ``credentials_stored=true``
  - ``depends_on``                        -> explicit Dataflow
  - Two services sharing a custom network -> inferred Dataflow (protocol from
    the "server" side's image type, see ``_IMAGE_PROTOCOL_MAP``)

BOM generation:
  :meth:`DockerComposePlugin.generate_bom_files` writes one YAML file per
  service under ``{output_dir}/BOM/``, using the image name:tag as the
  software version.
"""

import logging
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import yaml

from threat_analysis.utils import _validate_path_within_project
from threat_analysis.iac_plugins import IaCPlugin

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Image name -> Server.type / protocol heuristics
# ---------------------------------------------------------------------------
# Keys are substrings matched against the image repository name (the part
# before ':' and before the last '/'), longest-match-first so e.g. "mongo-express"
# doesn't shadow "mongo".

_IMAGE_TYPE_MAP: Dict[str, str] = {
    # Databases
    "postgres": "database", "postgresql": "database", "mysql": "database",
    "mariadb": "database", "mongo": "database", "cockroachdb": "database",
    "cassandra": "database", "couchdb": "database", "influxdb": "database",
    "timescaledb": "database", "mssql": "database", "oracle": "database",
    "cockroach": "database",
    # Cache
    "redis": "cache", "memcached": "cache", "keydb": "cache",
    # Web / reverse-proxy / ingress
    "nginx": "web-server", "httpd": "web-server", "apache": "web-server",
    "caddy": "web-server", "lighttpd": "web-server",
    "traefik": "ingress", "envoy": "ingress",
    "haproxy": "load-balancer",
    # Message brokers
    "rabbitmq": "message_broker", "kafka": "message_broker",
    "activemq": "message_broker", "nats": "message_broker",
    "zookeeper": "message_broker",
    # Auth / identity
    "keycloak": "auth-server", "openldap": "auth-server", "freeipa": "domain-controller",
    "authelia": "auth-server", "authentik": "auth-server",
    # Secrets management
    "vault": "secrets_manager",
    # Monitoring / observability
    "prometheus": "monitoring", "grafana": "monitoring", "jaeger": "monitoring",
    "zipkin": "monitoring", "loki": "monitoring", "alertmanager": "monitoring",
    # CI/CD
    "jenkins": "cicd", "gitlab-runner": "cicd", "drone": "cicd", "gitea": "repository",
    # Container registry
    "registry": "container_registry",
    # DNS
    "coredns": "dns", "bind9": "dns", "powerdns": "dns",
    # API gateway
    "kong": "api-gateway", "tyk": "api-gateway",
    # Backup
    "restic": "backup", "duplicati": "backup",
}

# Protocol used for an inferred (network-adjacency) dataflow whose destination
# runs this image type — falls back to "TCP" when the type isn't listed.
_IMAGE_PROTOCOL_MAP: Dict[str, str] = {
    "postgres": "PostgreSQL", "postgresql": "PostgreSQL",
    "mysql": "MySQL", "mariadb": "MySQL",
    "mongo": "MongoDB",
    "redis": "Redis", "keydb": "Redis", "memcached": "Memcached",
    "nginx": "HTTPS", "httpd": "HTTPS", "apache": "HTTPS", "caddy": "HTTPS",
    "traefik": "HTTPS", "envoy": "HTTPS", "haproxy": "HTTPS",
    "rabbitmq": "AMQP", "kafka": "Kafka", "activemq": "AMQP", "nats": "NATS",
    "vault": "HTTPS", "keycloak": "HTTPS", "kong": "HTTPS", "tyk": "HTTPS",
}

_UNTRUSTED_NETWORK_KEYWORDS: frozenset = frozenset(
    ["dmz", "public", "external", "internet", "frontend", "edge"]
)

_CREDENTIAL_KEY_FRAGMENTS: frozenset = frozenset(
    ["password", "secret", "token", "api_key", "apikey", "passwd", "credential", "pwd"]
)

_DEFAULT_NETWORK_NAME = "default"


def _image_repo(image: str) -> str:
    """Strips the tag/digest from an image reference, e.g.
    'postgres:15-alpine' -> 'postgres', 'ghcr.io/org/myapp:v1' -> 'myapp'."""
    if not image:
        return ""
    without_digest = image.split("@")[0]
    without_tag = without_digest.rsplit(":", 1)[0]
    return without_tag.rsplit("/", 1)[-1].lower()


def _infer_server_type(image: str, published_ports: bool) -> str:
    repo = _image_repo(image)
    for key, server_type in _IMAGE_TYPE_MAP.items():
        if key in repo:
            return server_type
    # Unknown/custom image: a published port suggests a user-facing service.
    return "web-server" if published_ports else "microservice"


def _infer_protocol(image: str) -> str:
    repo = _image_repo(image)
    for key, protocol in _IMAGE_PROTOCOL_MAP.items():
        if key in repo:
            return protocol
    return "TCP"


def _has_published_port(ports: List[Any]) -> bool:
    """True if at least one entry in a service's `ports:` list publishes to
    the host (as opposed to only being exposed to other containers)."""
    return bool(ports)


def _env_to_dict(environment: Any) -> Dict[str, str]:
    """Normalises `environment:` (list of "KEY=value" or dict form) to a dict."""
    if isinstance(environment, dict):
        return {str(k): str(v) for k, v in environment.items()}
    if isinstance(environment, list):
        result = {}
        for item in environment:
            if isinstance(item, str) and "=" in item:
                k, v = item.split("=", 1)
                result[k] = v
            elif isinstance(item, str):
                result[item] = ""
        return result
    return {}


def _infer_credentials_stored(service: Dict[str, Any]) -> bool:
    if service.get("secrets") or service.get("configs"):
        return True
    env = _env_to_dict(service.get("environment"))
    for key in env:
        lk = key.lower()
        if any(frag in lk for frag in _CREDENTIAL_KEY_FRAGMENTS):
            return True
    return bool(service.get("env_file"))


def _infer_network_trust(network_name: str) -> bool:
    lower = network_name.lower()
    return not any(kw in lower for kw in _UNTRUSTED_NETWORK_KEYWORDS)


def _service_networks(service: Dict[str, Any], default_network: str) -> Set[str]:
    nets = service.get("networks")
    if not nets:
        return {default_network}
    if isinstance(nets, dict):
        return set(nets.keys()) or {default_network}
    if isinstance(nets, list):
        return {str(n) for n in nets} or {default_network}
    return {default_network}


class DockerComposePlugin(IaCPlugin):
    """IaC Plugin for Docker Compose configurations."""

    @property
    def name(self) -> str:
        return "docker-compose"

    @property
    def description(self) -> str:
        return (
            "Integrates with Docker Compose files (v2/v3) to generate "
            "threat model components from services, networks and dependencies."
        )

    # ------------------------------------------------------------------
    # IaCPlugin interface
    # ------------------------------------------------------------------

    def parse_iac_config(self, config_path: str) -> Dict[str, Any]:
        """Parse a docker-compose.yml/yaml file.

        Accepts either a direct path to the compose file, or a directory
        containing one (tries docker-compose.yml, docker-compose.yaml,
        compose.yml, compose.yaml, in that order).

        Returns a dict with keys ``services`` (raw), ``networks`` (raw),
        ``service_networks`` (name -> set of joined network names) and
        ``default_network`` (the implicit network name when none is declared).
        """
        validated_path = _validate_path_within_project(config_path)

        compose_path = validated_path
        if validated_path.is_dir():
            for candidate in ("docker-compose.yml", "docker-compose.yaml",
                               "compose.yml", "compose.yaml"):
                p = validated_path / candidate
                if p.is_file():
                    compose_path = p
                    break
            else:
                raise FileNotFoundError(
                    f"No docker-compose.yml/yaml found in {validated_path}"
                )

        if not compose_path.is_file() or compose_path.suffix not in (".yml", ".yaml"):
            raise ValueError(
                f"Unsupported Docker Compose path: {compose_path}. "
                "Must be a .yml or .yaml file."
            )

        with open(compose_path, "r", encoding="utf-8") as fh:
            compose = yaml.safe_load(fh) or {}

        services: Dict[str, Any] = compose.get("services") or {}
        networks: Dict[str, Any] = compose.get("networks") or {}

        # Compose project name (directory name) used to build the implicit
        # default network name, mirroring `docker compose`'s own convention —
        # cosmetic only, never referenced outside this plugin.
        default_network = f"{compose_path.parent.name}_{_DEFAULT_NETWORK_NAME}"

        service_networks: Dict[str, Set[str]] = {
            svc_name: _service_networks(svc or {}, default_network)
            for svc_name, svc in services.items()
        }

        return {
            "services": services,
            "networks": networks,
            "service_networks": service_networks,
            "default_network": default_network,
        }

    def generate_threat_model_components(self, iac_data: Dict[str, Any]) -> str:
        """Generate Markdown DSL components from parsed Compose data."""
        services: Dict[str, Any] = iac_data.get("services", {})
        networks: Dict[str, Any] = iac_data.get("networks", {})
        service_networks: Dict[str, Set[str]] = iac_data.get("service_networks", {})
        default_network: str = iac_data.get("default_network", _DEFAULT_NETWORK_NAME)

        all_network_names: Set[str] = set(networks.keys())
        for nets in service_networks.values():
            all_network_names.update(nets)

        markdown: List[str] = []

        # --- Boundaries: one per compose network ---------------------------
        if all_network_names:
            markdown.append("## Boundaries")
            for net_name in sorted(all_network_names):
                is_trusted = _infer_network_trust(net_name)
                markdown.append(
                    f"- **{net_name}**: isTrusted={str(is_trusted).lower()}"
                )
            markdown.append("")

        # --- Servers: one per service ---------------------------------------
        service_types: Dict[str, str] = {}
        if services:
            markdown.append("## Servers")
            for svc_name, svc in services.items():
                svc = svc or {}
                image = str(svc.get("image", ""))
                ports = svc.get("ports") or []
                published = _has_published_port(ports)
                server_type = _infer_server_type(image, published)
                service_types[svc_name] = server_type

                nets = service_networks.get(svc_name, {default_network})
                # DSL servers belong to exactly one boundary — pick the first
                # network deterministically (sorted) when a service joins several.
                boundary = sorted(nets)[0]

                props = [f'boundary="{boundary}"', f"type={server_type}"]
                if published:
                    props.append("internet_facing=true")
                if _infer_credentials_stored(svc):
                    props.append("credentials_stored=true")

                markdown.append(f"- **{svc_name}**: {', '.join(props)}")
            markdown.append("")

        # --- Dataflows: depends_on (explicit) + shared-network (inferred) ---
        flows: List[Tuple[str, str, str, str]] = []  # (name, source, dest, protocol)
        seen_pairs: Set[Tuple[str, str]] = set()

        for svc_name, svc in services.items():
            svc = svc or {}
            depends_on = svc.get("depends_on")
            if not depends_on:
                continue
            dep_names = list(depends_on.keys()) if isinstance(depends_on, dict) else list(depends_on)
            for dep in dep_names:
                if dep not in services or (svc_name, dep) in seen_pairs:
                    continue
                seen_pairs.add((svc_name, dep))
                protocol = _infer_protocol(str(services[dep].get("image", "")))
                flows.append((f"{svc_name}_to_{dep}", svc_name, dep, protocol))

        # Shared-network inference: only for pairs not already connected via
        # depends_on, and only within custom (non-default) networks — every
        # service normally shares the implicit default network, which would
        # otherwise connect every pair to every other pair.
        custom_networks = all_network_names - {default_network}
        for net_name in sorted(custom_networks):
            members = sorted(
                s for s, nets in service_networks.items() if net_name in nets
            )
            for i, source in enumerate(members):
                for dest in members[i + 1:]:
                    if (source, dest) in seen_pairs or (dest, source) in seen_pairs:
                        continue
                    seen_pairs.add((source, dest))
                    protocol = _infer_protocol(str(services.get(dest, {}).get("image", "")))
                    flows.append((f"{source}_to_{dest}", source, dest, protocol))

        if flows:
            markdown.append("## Dataflows")
            for flow_name, source, dest, protocol in flows:
                markdown.append(
                    f'- **{flow_name}**: from="{source}", to="{dest}", '
                    f'protocol="{protocol}"'
                )
            markdown.append("")

        return "\n".join(markdown)

    def generate_bom_files(self, iac_data: Dict[str, Any], output_dir: str) -> List[str]:
        """Write one BOM YAML file per service under ``{output_dir}/BOM/``."""
        services: Dict[str, Any] = iac_data.get("services", {})
        if not services:
            return []

        bom_dir = Path(output_dir) / "BOM"
        bom_dir.mkdir(parents=True, exist_ok=True)

        written: List[str] = []
        for svc_name, svc in services.items():
            svc = svc or {}
            image = str(svc.get("image", ""))
            repo = _image_repo(image)
            tag = ""
            if ":" in image.split("@")[0]:
                tag = image.split("@")[0].rsplit(":", 1)[-1]

            bom_key = re.sub(r"[^a-z0-9_]", "", re.sub(r"[\s\-]+", "_", svc_name.strip().lower()))

            bom: Dict[str, Any] = {
                "asset": svc_name,
                "os_version": "container",
                "software_version": f"{repo}:{tag}" if tag else repo,
                "patch_level": "unknown",
                "known_cves": [],
                "running_services": [repo] if repo else [],
                "detection_level": "low",
                "credentials_stored": _infer_credentials_stored(svc),
                "notes": (
                    f"Auto-generated from Docker Compose service '{svc_name}' "
                    f"(image: {image or 'unknown'})."
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
