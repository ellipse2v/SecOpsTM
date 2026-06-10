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

"""Canonical DSL enum definitions for SecOpsTM.

Single source of truth for all valid field values in the Markdown DSL.
Import DSL_ENUMS from here rather than duplicating the dict in external tools.
"""

from typing import Any, Dict, List

DSL_ENUMS: Dict[str, List[Any]] = {
    # Boundary attributes
    "Boundary.isTrusted": [True, False],
    "Boundary.isFilled": [True, False],
    "Boundary.type": [
        "network-on-prem",
        "network-cloud-provider",
        "network-cloud-security-group",
        "execution-environment",
        "container-runtime",
    ],
    "Boundary.line_style": ["solid", "dashed", "dotted"],
    "Boundary.traversal_difficulty": ["low", "medium", "high"],

    # Actor attributes
    "Actor.authenticity": [
        "none", "credentials", "two-factor", "client-certificate", "externalized",
    ],
    "Actor.providesAuthentication": [True, False],

    # Server attributes — type (built-in + modern architecture types)
    "Server.type": [
        # Core pytm types (hyphen-style)
        "firewall", "domain-controller", "auth-server", "database", "web-server",
        "api-gateway", "file-server", "mail-server", "management-server", "workstation",
        "load-balancer", "vpn", "vpn-gateway", "plc", "scada", "repository", "cicd",
        "backup", "dns", "pki", "siem", "default",
        # Modern architecture types (underscore-style)
        "api_server", "microservice", "secrets_manager", "monitoring", "message_broker",
        "cache", "ingress", "service_mesh", "container_registry",
    ],
    "Server.classification": ["PUBLIC", "INTERNAL", "RESTRICTED", "SECRET"],
    "Server.machine": [
        "physical", "virtual", "container", "embedded", "saas", "serverless",
    ],
    "Server.onAWS": [True, False],
    "Server.onAzure": [True, False],
    "Server.onGCP": [True, False],
    "Server.isHardened": [True, False],
    "Server.internet_facing": [True, False],
    "Server.credentials_stored": [True, False],
    # CIA triad
    "Server.confidentiality": ["low", "medium", "high", "critical"],
    "Server.integrity": ["low", "medium", "high", "critical"],
    "Server.availability": ["low", "medium", "high", "critical"],
    # Encryption
    "Server.encryption": [
        "none",
        "transparent",
        "data-with-symmetric-shared-key",
        "data-with-asymmetric-shared-key",
        "data-with-enduser-individual-key",
    ],
    # Security features
    "Server.redundant": [True, False],
    "Server.mfa_enabled": [True, False],
    # Authentication protocol
    "Server.auth_protocol": [
        "none", "ldap", "kerberos", "saml", "oauth", "oidc", "radius",
    ],
    # Firewall-specific (validated only when type=firewall)
    "Server.waf": [True, False],
    "Server.ids": [True, False],
    "Server.ips": [True, False],

    # Data attributes
    "Data.classification": [
        "UNKNOWN", "PUBLIC", "RESTRICTED", "SECRET", "TOP_SECRET",
        "SENSITIVE", "INTERNAL", "CONFIDENTIAL",
    ],
    "Data.credentialsLife": [
        "NONE", "UNKNOWN", "SHORT", "LONG", "AUTO", "MANUAL", "HARDCODED",
    ],
    "Data.isPII": [True, False],
    "Data.isPassword": [True, False],
    "Data.isCryptographicKey": [True, False],
    "Data.isConfidentialityCritical": [True, False],
    "Data.isIntegrityCritical": [True, False],

    # Dataflow attributes
    "Dataflow.authentication": [
        "none", "credentials", "session-id", "token", "client-certificate",
        "two-factor", "externalized", "kerberos",
    ],
    "Dataflow.isEncrypted": [True, False],
    "Dataflow.isAuthenticated": [True, False],
    "Dataflow.bidirectional": [True, False],
    "Dataflow.authorization": ["none", "required", "mutual"],
    "Dataflow.vpn": [True, False],
    "Dataflow.ipFiltered": [True, False],
    "Dataflow.readOnly": [True, False],
    "Dataflow.usage": ["business", "devops", "management"],
}

# Valid attributes for Protocol Style entries
PROTOCOL_STYLE_ATTRS: frozenset = frozenset({"color", "line_style", "width"})

# Valid range for severity multiplier values
SEVERITY_MULTIPLIER_MIN: float = 0.0
SEVERITY_MULTIPLIER_MAX: float = 5.0
