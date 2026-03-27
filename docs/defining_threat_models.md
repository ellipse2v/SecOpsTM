# SecOpsTM DSL Reference

This document is the authoritative reference for the SecOpsTM Markdown Domain-Specific Language
(DSL). It covers every section, every attribute, and every accepted value. After reading this, you
can write any threat model from scratch without consulting the source code.

**Target audience:** DevOps engineers, security architects, threat modelers.

---

## Overview

A SecOpsTM threat model is a Markdown file. The file is parsed in three passes:

1. **Pass 0** — `## Context` (standalone key-value block, model-level settings)
2. **First pass** — `## Boundaries`, `## Actors`, `## Servers`, `## Data` (element definitions)
3. **Second pass** — `## Dataflows`, `## Protocol Styles`, `## Severity Multipliers`,
   `## Custom Mitre Mapping` (relationships and overrides, which reference elements by name)

This order matters: dataflows can only reference elements that were defined in the first pass.

**List item format.** Every element is defined as a Markdown list item:

```markdown
- **Element Name**: key=value, key=value, key="quoted value", key=[list, of, values]
```

- Names are **case-sensitive** for display but matched **case-insensitively** when referenced
  elsewhere (e.g., `boundary=Internet` matches a boundary named `Internet` or `INTERNET`).
- Multi-line definitions are supported: indent continuation lines further than the `- **Name**:`
  line.
- Comments: `// text to end of line` is stripped before parsing. Use them freely.

---

## File Structure

```markdown
# Threat Model: My System Name

## Description
Free-form text describing the system under analysis.

## Context
gdaf_context = context/my_context.yaml
bom_directory = BOM

## Boundaries
- **Zone Name**: isTrusted=True, type=network-on-prem, color=lightgreen

## Actors
- **User Name**: boundary="Zone Name", authenticity=credentials, isTrusted=True

## Servers
- **Server Name**: boundary="Zone Name", type=web-server, confidentiality=high

## Data
- **Data Object Name**: classification=SECRET, description="Sensitive payload"

## Dataflows
- **Flow Name**: from="Actor Name", to="Server Name", protocol=HTTPS, is_encrypted=True

## Protocol Styles
- **HTTPS**: color=darkgreen, line_style=solid

## Severity Multipliers
- **Server Name**: 2.0

## Custom Mitre Mapping
- **Attack Name**: {"tactics": ["Lateral Movement"], "techniques": [{"id": "T1021.002", "name": "SMB/Windows Admin Shares"}]}
```

The title (`# Threat Model: ...`) is used as the model name in reports and diagrams. Everything
else is controlled by the sections described below.

---

## Section: Description

```markdown
## Description
Free-form text. No special formatting required. This text appears in the generated HTML report
header and in diagram tooltips.
```

This section is pure prose. It is not parsed for key-value pairs. Write as many paragraphs as
needed to explain the system scope, deployment context, and relevant regulatory requirements.

---

## Section: Context

The `## Context` section configures model-level options. It is parsed before elements are created.
Each line takes the form `key = value` or `- key = value` or `- key: value`.

```markdown
## Context
gdaf_context = context/my_context.yaml
bom_directory = BOM
gdaf_min_technique_score = 0.75
```

### Context Attributes

| Attribute | Type | Default | Description |
|---|---|---|---|
| `gdaf_context` | string (path) | `None` | Path to the GDAF context YAML file. Relative to the model file directory. See [Project Directory Structure](#project-directory-structure). |
| `bom_directory` | string (path) | `None` | Path to the BOM directory. Relative to the model file directory. |
| `vex_file` | string (path) | `None` | Path to a standalone CycloneDX VEX file. Takes priority over BOM `known_cves` for CVE scoring. Relative to the model file directory. |
| `vex_directory` | string (path) | `None` | Path to a directory of CycloneDX VEX files (one per component or a single global file). |
| `gdaf_min_technique_score` | float 0.0–3.0 | `0.8` | Minimum `ScoredTechnique.score` required to render a technique as an OR-branch in `.afb` Attack Flow files. |

**Context path resolution** (in order of priority):
1. Value specified in `## Context` section
2. `{model_dir}/context/*.yaml` — auto-discovered if the directory exists
3. `config/context.yaml` in the SecOpsTM installation (global default)

**BOM directory resolution** (in order of priority):
1. Value specified in `## Context` section
2. `{model_dir}/BOM/` — auto-discovered if the directory exists
3. Disabled (no BOM enrichment)

**CVE source resolution** — single priority chain, first match wins:
1. `vex_file` / `vex_directory` in `## Context` (or auto-discovered `VEX/` dir / `vex.json`)
2. BOM file with `vulnerabilities[].analysis.state` (CycloneDX VEX assertions embedded in BOM)
3. BOM file `known_cves` without state (all CVEs treated as active — legacy)
4. `cve_definitions.yml` at project root (global fallback)

> **Tip:** Most scanner tools (Qualys, Tenable, Grype) can export CycloneDX JSON that includes
> both component inventory and vulnerability exploitability assertions in one file. Place these
> files in `BOM/` — SecOpsTM reads `analysis.state` automatically. No separate `VEX/` directory
> is needed unless your scanner emits standalone VEX documents.

---

## Section: Boundaries

Boundaries represent trust zones, network segments, or logical execution environments. They are
rendered as labelled clusters in diagrams. Trust level controls diagram colors and GDAF entry-point
detection.

```markdown
## Boundaries
- **Internet**:
  isTrusted=False,
  type=network-on-prem,
  color=red,
  traversal_difficulty=low,
  businessValue="Public internet — untrusted perimeter"
- **Internal Network**:
  isTrusted=True,
  type=network-on-prem,
  color=lightgreen,
  traversal_difficulty=low
- **Finance Zone**:
  isTrusted=True,
  type=execution-environment,
  color=lightyellow,
  traversal_difficulty=high,
  businessValue="Hosts ERP system and financial data"
```

### Nested Boundaries

Boundaries can be nested by indenting the child boundary further than the parent:

```markdown
## Boundaries
- **Corporate Network**:
  isTrusted=True,
  type=network-on-prem,
  color=lightblue
  - **Finance Zone**:
    isTrusted=True,
    type=execution-environment,
    color=lightyellow
```

### Boundary Attributes

| Attribute | Type | Default | STRIDE Impact | GDAF Impact | Description |
|---|---|---|---|---|---|
| `isTrusted` | bool | `False` | Trust boundary threats | Entry point detection | Whether this zone is trusted. Trusted = green solid border; Untrusted = red dashed border in diagrams. |
| `type` | string | `""` | None | Context for path scoring | Zone type. See accepted values below. |
| `color` | string | `"lightgray"` | None | None | CSS color name or hex (`#2e7d32`) for the boundary cluster fill in diagrams. |
| `traversal_difficulty` | string | `"low"` | None | `hop_weight` bonus | How difficult it is for an attacker to cross into this boundary. See table below. |
| `businessValue` | string | `None` | None | None | Free-text description shown in diagram tooltips. |

### Accepted Values for `type`

| Value | Meaning |
|---|---|
| `network-on-prem` | On-premises network segment |
| `network-cloud-provider` | Cloud provider network (AWS VPC, Azure VNet, etc.) |
| `network-cloud-security-group` | Cloud security group or firewall rule boundary |
| `execution-environment` | Logical execution zone (data center zone, server room, container namespace) |
| `container-runtime` | Container orchestration boundary (Kubernetes namespace, Docker network) |

### `traversal_difficulty` Values

| Value | `hop_weight` Bonus | Meaning | Example |
|---|---|---|---|
| `low` | +0.3 | Easily traversable (few controls) | Public DMZ, open internal segment |
| `medium` | +0.1 | Moderate controls (firewall, VLAN segmentation) | Standard internal network |
| `high` | +0.0 | Strong controls (micro-segmentation, strict firewall rules) | Finance zone, OT/SCADA zone |

Higher `hop_weight` means a higher GDAF path score through that boundary (more attractive to
attackers because it is easier to traverse). Use `high` for segments you have hardened with strong
network controls.

---

## Section: Actors

Actors represent people, external systems, or roles that interact with your system. They appear as
external entities in diagrams (rectangles without servers).

```markdown
## Actors
- **External Attacker**:
  boundary=Internet,
  authenticity=none,
  isTrusted=False
- **Corporate Employee**:
  boundary="Internal Network",
  authenticity=credentials,
  isTrusted=True,
  businessValue="Internal user with domain account"
- **Remote Employee**:
  boundary=Internet,
  authenticity=two-factor,
  isTrusted=False,
  color=orange
```

### Actor Attributes

| Attribute | Type | Default | Description |
|---|---|---|---|
| `boundary` | string | `None` | Name of the boundary this actor belongs to. Must match a boundary defined in `## Boundaries`. |
| `authenticity` | string | `"none"` | Authentication method this actor uses. See accepted values below. |
| `isTrusted` | bool | `False` | Whether this actor is trusted. Actors in untrusted boundaries with `isTrusted=False` are GDAF entry points for external attackers. |
| `color` | string | `None` | Node fill color in diagrams. CSS color name or hex. |
| `businessValue` | string | `None` | Free-text description shown in tooltips. |

### Accepted Values for `authenticity`

| Value | Description |
|---|---|
| `none` | No authentication |
| `credentials` | Username and password |
| `two-factor` | Multi-factor authentication |
| `client-certificate` | TLS/mTLS client certificate |
| `externalized` | Authentication delegated to external IdP (SSO, SAML, OAuth) |

---

## Section: Servers

Servers represent components of your system: web servers, databases, firewalls, domain controllers,
PLCs, and any other asset that processes or stores data. This is the richest section in terms of
attributes because servers carry most of the GDAF scoring signals.

```markdown
## Servers
- **Primary Domain Controller**:
  boundary="IT Infrastructure Zone",
  type=domain-controller,
  machine=physical,
  auth_protocol=kerberos,
  mfa_enabled=False,
  credentials_stored=True,
  confidentiality=critical,
  integrity=critical,
  availability=critical,
  tags=[windows-server-2019, active-directory],
  businessValue="Forest root — controls all access"
- **Web Application Firewall**:
  boundary=DMZ,
  type=firewall,
  machine=virtual,
  waf=True,
  internet_facing=True,
  confidentiality=medium,
  integrity=high,
  availability=high,
  tags=[modsecurity, waf]
- **Application Backend**:
  boundary="App Zone",
  type=web-server,
  machine=container,
  confidentiality=high,
  integrity=high,
  availability=high,
  submodel=./backend/model.md
```

### Server Attributes

| Attribute | Type | Default | STRIDE Impact | GDAF Impact | Description |
|---|---|---|---|---|---|
| `boundary` | string | `None` | Trust boundary threats | Group membership, `boundary_trusted` flag | Boundary this server belongs to. |
| `type` | string | `"default"` | None | Platform/tactic selection, key technique boosts | Asset type. See full list below. |
| `machine` | string | `None` | DoS threat variants | None | Deployment form. Accepted: `physical`, `virtual`, `container`, `serverless`. |
| `confidentiality` | string | `"low"` | Data-at-rest threats | CIA score (path scoring) | Data confidentiality level: `low`, `medium`, `high`, `critical`. |
| `integrity` | string | `"low"` | Tampering threats | CIA score (path scoring) | Data integrity level: `low`, `medium`, `high`, `critical`. |
| `availability` | string | `"low"` | DoS threat severity | CIA score (path scoring) | Availability requirement: `low`, `medium`, `high`, `critical`. |
| `encryption` | string | `""` | Data-at-rest STRIDE rules | None | Encryption of stored data. See accepted values below. |
| `redundant` | bool | `False` | DoS threat likelihood | None | Whether this server has redundant capacity. Reduces DoS threat likelihood. |
| `mfa_enabled` | bool | `True` | None | +0.2 on credential-access/initial-access if `False` | Whether MFA is required. Default is `True` (MFA assumed unless explicitly set to `False`). |
| `auth_protocol` | string | `None` | Kerberos/LDAP-specific threats | None | Authentication protocol in use: `none`, `ldap`, `kerberos`, `saml`, `oauth`, `oidc`, `radius`. |
| `internet_facing` | bool | `False` | None | GDAF entry point (even in trusted boundary) | Whether this server is directly reachable from the internet. |
| `credentials_stored` | bool | `False` | Credential theft threats | +0.4 on credential-access techniques | Whether this server stores credentials (password hashes, service accounts, API keys). |
| `waf` | bool | `False` | None (firewall type only) | None | Whether a Web Application Firewall is enabled. Only meaningful for `type=firewall`. |
| `ids` | bool | `False` | None (firewall type only) | None | Whether an Intrusion Detection System is active. |
| `ips` | bool | `False` | None (firewall type only) | None | Whether an Intrusion Prevention System is active. |
| `tags` | list | `[]` | None | Legacy signal, service hints | Arbitrary string tags. `legacy` or `windows 7` in tags triggers legacy signal (+0.2 on initial-access/execution techniques). |
| `submodel` | string (path) | `None` | None | Sub-model bridging edges in GDAF graph | Relative path to a child model file. The server becomes a hyperlink in the diagram. See [Project Directory Structure](#project-directory-structure). |
| `businessValue` | string | `None` | None | None | Free-text tooltip shown in diagrams and reports. |
| `color` | string | `None` | None | None | Node fill color. CSS color name or hex. |

### Accepted Values for `type`

The `type` attribute controls which MITRE ATT&CK platform tags, primary tactics, and key technique
IDs are used when GDAF scores this asset. The fuzzy matching in `_normalize_type()` means common
variations (e.g., `"web server"`, `"webserver"`, `"web-server"`) all resolve to the same canonical
type.

| `type` Value | MITRE Platforms | Primary Tactics | Key Techniques (boosted) |
|---|---|---|---|
| `firewall` | Network Devices | initial-access, defense-evasion, lateral-movement | T1190, T1600, T1599 |
| `domain-controller` | Windows | credential-access, privilege-escalation, persistence, lateral-movement | T1550.002, T1558.003, T1003.006, T1558.001, T1003.001, T1207 |
| `auth-server` | Windows, Linux | credential-access, privilege-escalation, initial-access | T1110, T1212, T1528, T1550 |
| `database` | Windows, Linux | credential-access, collection, exfiltration | T1190, T1078, T1048, T1030 |
| `web-server` | Windows, Linux | initial-access, execution, persistence | — |
| `api-gateway` | Windows, Linux | initial-access, execution | — |
| `file-server` | Windows, Linux | collection, lateral-movement, exfiltration | T1021.002, T1039, T1083, T1135 |
| `mail-server` | Windows, Linux, Office Suite | initial-access, collection | T1566, T1114, T1071.003 |
| `management-server` | Windows, Linux | lateral-movement, privilege-escalation, execution | T1021.001, T1078, T1570 |
| `workstation` | Windows | execution, persistence, privilege-escalation, credential-access | T1566.001, T1059.001, T1059.003, T1204.002, T1003.001, T1055 |
| `load-balancer` | Network Devices, Linux | initial-access, defense-evasion | — |
| `vpn` | Network Devices | initial-access, credential-access | — |
| `vpn-gateway` | Network Devices | initial-access, credential-access | T1078, T1133, T1110 |
| `plc` | Linux | impact, execution | T1565.001, T1498, T1489 |
| `scada` | Windows, Linux | initial-access, execution, impact | T1021.001, T1133, T1078 |
| `repository` | Linux | collection, exfiltration | — |
| `cicd` | Linux | execution, persistence, lateral-movement | T1195.002, T1059, T1525 |
| `backup` | Linux, Windows | collection, exfiltration, impact | — |
| `dns` | Windows, Linux | defense-evasion, lateral-movement, command-and-control | — |
| `pki` | Windows | credential-access, privilege-escalation | — |
| `siem` | Linux | defense-evasion, collection | — |
| `default` | Windows, Linux | initial-access, execution, lateral-movement | — |

If no `type` is specified, or the value does not match any of the above (including fuzzy matching),
the `default` profile is used.

**Fuzzy matching examples:**

| DSL value | Resolved type |
|---|---|
| `"web server"`, `"webserver"`, `web-server` | `web-server` |
| `"Domain Controller"`, `dc`, `"Active Directory"` | `domain-controller` |
| `"MySQL"`, `"PostgreSQL"`, `sql`, `db` | `database` |
| `"jenkins"`, `"ci_cd"`, `pipeline` | `cicd` |
| `"bastion"`, `"jump server"`, `paw` | `management-server` |
| `"Certificate Authority"`, `ca`, `pki` | `pki` |
| `"SCADA"`, `hmi` | `scada` |
| `"siemens-plc"`, `plc-controller` | `plc` |

### Accepted Values for `encryption`

Used by pytm STRIDE rules to generate data-at-rest threats.

| Value | Description |
|---|---|
| `none` | No encryption of stored data |
| `transparent` | Transparent disk encryption (e.g., BitLocker) |
| `data-with-symmetric-shared-key` | Data encrypted with a shared symmetric key |
| `data-with-asymmetric-shared-key` | Data encrypted with asymmetric keys (PKI) |
| `data-with-enduser-individual-key` | End-to-end encryption with per-user keys |

### CIA Score and GDAF

The `confidentiality`, `integrity`, and `availability` attributes feed directly into GDAF's CIA
score for each node, which adds up to +0.5 bonus on the path score when the target node has high
CIA values. This makes high-CIA assets more attractive targets in GDAF scenarios.

| CIA Level | Numeric Score |
|---|---|
| `low` | 0 |
| `medium` | 1 |
| `high` | 2 |
| `critical` | 3 |

The combined CIA formula: `(confidentiality × 3 + integrity × 2 + availability) / 18`, normalized
to 0.0–1.0.

---

## Section: Data

The `## Data` section defines named data objects that can be referenced by dataflows. Data
classification affects both STRIDE threat generation and GDAF path scoring (higher classification
= higher `data_value` weight on edges carrying that data).

> **Important:** The section header is `## Data`, not `## Data Objects`. Using any other header
> name will cause the section to be silently ignored.

```markdown
## Data
- **Admin Credentials**:
  description="Privileged administrative credentials for domain and servers",
  classification=TOP_SECRET,
  credentialsLife=HARDCODED
- **Financial Record**:
  description="Highly sensitive financial records and transactions",
  classification=TOP_SECRET
- **VPN Auth Token**:
  description="IPSec VPN authentication credentials",
  classification=SECRET,
  credentialsLife=SHORT
- **Web Request**:
  description="HTTP/S requests from the internet",
  classification=PUBLIC
```

### Data Attributes

| Attribute | Type | Default | STRIDE Impact | GDAF Impact | Description |
|---|---|---|---|---|---|
| `classification` | string | `UNKNOWN` | Data handling threats, sensitivity level | `data_value` on edges (0.0–1.0) | Sensitivity classification. Case-insensitive. See values below. |
| `credentialsLife` | string | `UNKNOWN` | Credential handling threats | None | Credential lifetime/storage type. See values below. |
| `description` | string | `""` | None | None | Free-text description of the data object. |

### Accepted Values for `classification`

| Value | GDAF `data_value` | Description |
|---|---|---|
| `PUBLIC` | 0.0 | Non-sensitive, publicly available data |
| `UNKNOWN` | 0.1 | Classification unknown |
| `RESTRICTED` | 0.4 | Internal use only, not public |
| `SECRET` | 0.7 | Sensitive — requires access controls |
| `TOP_SECRET` | 1.0 | Highly sensitive — maximum protection required |

### Accepted Values for `credentialsLife`

| Value | STRIDE Impact | Description |
|---|---|---|
| `NONE` | No credential threats | No credentials |
| `UNKNOWN` | Low signal | Credential lifetime unknown |
| `SHORT` | Low risk | Short-lived tokens or session credentials |
| `LONG` | Medium risk | Long-lived credentials (service accounts) |
| `AUTO` | Low risk | Automatically rotated credentials |
| `MANUAL` | Medium risk | Manually managed credentials (rotation risk) |
| `HARDCODED` | High risk | Hardcoded credentials — triggers hardcoded credential threat in pytm rules |

`HARDCODED` and `LONG` credential lifetimes act as credential persistence signals and generate
additional pytm STRIDE threats related to credential theft and replay attacks.

---

## Section: Dataflows

Dataflows define communication channels between actors and servers (or between servers). Each
dataflow is a directed edge in the system graph. Dataflows are the primary unit for STRIDE threat
generation: most pytm rules fire based on dataflow properties (encrypted, authenticated, protocol).

```markdown
## Dataflows
- **WorkstationToAD**:
  from="Employee Workstation",
  to="Primary Domain Controller",
  protocol=LDAP,
  authentication=credentials,
  is_encrypted=False
  // LDAP in cleartext — credential interception vector
- **DevToGitLab**:
  from=Developer,
  to="Source Code Repository",
  protocol=SSH,
  authentication=two-factor,
  is_encrypted=True,
  data="Source Code"
- **ADToJump**:
  from="Primary Domain Controller",
  to="Jump Server",
  protocol=WinRM,
  data="Admin Credentials",
  authentication=credentials,
  is_encrypted=True
  // Lateral movement vector: attacker with DC admin can push GPO via WinRM
```

### Dataflow Attributes

| Attribute | Type | Default | Required | STRIDE Impact | GDAF Impact | Description |
|---|---|---|---|---|---|---|
| `from` | string | — | Yes | Determines source element | Source node in the graph | Name of the source element (actor or server). Must match exactly (case-insensitive). |
| `to` | string | — | Yes | Determines sink element | Sink node in the graph | Name of the destination element (actor or server). |
| `protocol` | string | `None` | No | Protocol-specific STRIDE rules | `services` set on both nodes, tactic boosts | Protocol name. Any string; common values: HTTPS, HTTP, SSH, RDP, SMB, LDAP, Kerberos, SQL, WinRM, RPC, SMTP, IPSEC, Modbus, DNS, FTP, SAP, TCP, UDP. |
| `is_encrypted` | bool | `False` | No | Cleartext data threats | +0.3 on `hop_weight` when `False` | Whether the channel is encrypted. |
| `is_authenticated` | bool | `False` | No | Unauthenticated access threats | +0.4 on `hop_weight` when `False` | Whether the channel requires authentication. |
| `authentication` | string | `"none"` | No | Authentication-specific STRIDE rules | Edge `authentication` attribute | Authentication method on this flow. See values below. |
| `authorization` | string | `"none"` | No | Authorization threats | None | Authorization model. See values below. |
| `vpn` | bool | `False` | No | VPN-related threat variants | None | Whether this flow travels through a VPN tunnel. |
| `bidirectional` | bool | `False` | No | None | Reverse edge added to GDAF graph | When `True`, GDAF can traverse this edge in both directions, enabling reverse attack paths. |
| `data` | string | `None` | No | Data classification threats | `data_value` on edge (0.0–1.0 from classification) | Name of a `## Data` object transported by this flow. Must match a defined data object. |
| `ip_filtered` | bool | `False` | No | IP filtering threat variants | None | Whether this flow is IP-filtered. |
| `readonly` | bool | `False` | No | Write-access threats | None | Whether this flow is read-only. |
| `usage` | string | `None` | No | None | None | Usage category: `business`, `devops`, `management`. |
| `color` | string | `None` | No | None | None | Arrow color in diagrams. Overrides protocol style color if set. CSS name or hex. |

### Accepted Values for `authentication`

| Value | Description |
|---|---|
| `none` | No authentication |
| `credentials` | Username and password |
| `session-id` | Session token (cookie) |
| `token` | API token or bearer token |
| `client-certificate` | Mutual TLS (mTLS) |
| `two-factor` | Multi-factor authentication |
| `externalized` | External IdP (SAML, OAuth) |
| `kerberos` | Kerberos ticket |

### Accepted Values for `authorization`

| Value | Description |
|---|---|
| `none` | No authorization |
| `technical-user` | Fixed service account authorization |
| `enduser-identity-propagation` | User identity forwarded to backend (e.g., impersonation, JWT) |

### GDAF Edge Scoring

GDAF computes `hop_weight` for each edge to score how exploitable the path segment is:

| Condition | `hop_weight` Bonus |
|---|---|
| `is_authenticated=False` | +0.4 |
| `is_encrypted=False` | +0.3 |
| `mfa_enabled=False` on sink node | +0.2 |
| CIA score of sink node | +0 to +0.1 |
| Data value from `data` classification | +0 to +0.3 |
| `traversal_difficulty=low` on sink boundary | +0.3 |
| `traversal_difficulty=medium` on sink boundary | +0.1 |
| `traversal_difficulty=high` on sink boundary | +0.0 |

The final hop score is `avg_technique_score × hop_weight`. Path score is the average hop score
across the path, plus a CIA bonus from the target node.

### Comments in Dataflows

Any text following `//` on a line is treated as a comment and ignored by the parser:

```markdown
- **ADToJump**:
  from="Primary Domain Controller",
  to="Jump Server",
  protocol=WinRM,
  is_encrypted=True
  // This path enables GPO-based lateral movement after domain compromise
```

---

## Section: Protocol Styles

Protocol Styles define rendering properties for dataflow arrows grouped by protocol name. When a
dataflow has `protocol=HTTPS`, it inherits the `HTTPS` style. Styles are applied to all flows
using that protocol unless the flow has its own `color` attribute (which takes precedence).

```markdown
## Protocol Styles
- **HTTPS**: color=darkgreen, line_style=solid
- **HTTP**: color=red, line_style=solid
- **SSH**: color=blue, line_style=dashed
- **LDAP**: color=purple, line_style=solid
- **SMB**: color=orange
- **RDP**: color=steelblue, line_style=dashed
- **SQL**: color=purple
- **Modbus**: color=crimson, line_style=solid
- **SYSLOG**: color=gray, line_style=dotted
```

### Protocol Style Attributes

| Attribute | Type | Description |
|---|---|---|
| `color` | string | CSS color name or hex. Applied to all dataflow arrows using this protocol. |
| `line_style` | string | Arrow line style: `solid`, `dashed`, `dotted`. |
| `width` | number | Line width (thickness). |
| `arrow_style` | string | Arrow head style (Graphviz arrow type). |

Protocol style names are matched exactly against the `protocol` attribute of dataflows. The match
is case-sensitive (define `HTTPS` for flows using `protocol=HTTPS`).

---

## Section: Severity Multipliers

Severity Multipliers adjust the base severity score of all threats targeting a specific element.
Use them to reflect the business criticality of crown-jewel assets that should always appear at
the top of the threat report.

```markdown
## Severity Multipliers
- **Primary Domain Controller**: 3.0
- **Financial ERP System**: 2.5
- **Core Database Cluster**: 2.5
- **SCADA HMI**: 2.0
- **PKI Certificate Authority**: 2.0
```

The value is a floating-point multiplier applied to the computed severity score. A multiplier of
`2.0` doubles the score; `3.0` triples it. There is no upper bound. Use values between 1.0 and 5.0
in practice.

The name must match an element name exactly (case-insensitive lookup).

---

## Section: Custom Mitre Mapping

Custom MITRE Mappings let you pin specific ATT&CK tactics and technique IDs to named attack
patterns that are relevant to your environment. These appear in the threat report alongside the
automatically-mapped techniques from the STRIDE→CAPEC→ATT&CK chain.

```markdown
## Custom Mitre Mapping
- **Pass-the-Hash**: {"tactics": ["Lateral Movement"], "techniques": [{"id": "T1550.002", "name": "Use Alternate Authentication Material: Pass the Hash"}]}
- **Kerberoasting**: {"tactics": ["Credential Access"], "techniques": [{"id": "T1558.003", "name": "Steal or Forge Kerberos Tickets: Kerberoasting"}]}
- **Golden Ticket**: {"tactics": ["Persistence", "Privilege Escalation"], "techniques": [{"id": "T1558.001", "name": "Steal or Forge Kerberos Tickets: Golden Ticket"}]}
- **Modbus Command Injection**: {"tactics": ["Impact"], "techniques": [{"id": "T1565.001", "name": "Data Manipulation: Stored Data Manipulation"}]}
```

The value must be a valid Python dict literal (uses `ast.literal_eval` internally). The format is:

```
{"tactics": [<list of tactic names>], "techniques": [{"id": "<ATT&CK ID>", "name": "<technique name>"}, ...]}
```

Tactic names should match the ATT&CK tactic display names (e.g., `"Lateral Movement"`,
`"Credential Access"`, `"Initial Access"`, `"Impact"`).

Technique IDs follow the ATT&CK format: `T1234` or `T1234.001` for sub-techniques.

---

## Project Directory Structure

The recommended structure for a project-mode model (with GDAF context, BOM, and sub-models):

```
My_System/
  model.md                       # Main threat model DSL file
  context/                       # GDAF context YAML (auto-discovered)
    context.yaml
  BOM/                           # Per-asset Bill of Materials (auto-discovered)
    primary_domain_controller.yaml
    web_application_firewall.yaml
    financial_erp_system.yaml
    ...
  output/                        # Generated reports (add to .gitignore)
  Backend_Service/               # Sub-model for a server defined in model.md
    model.md
    BOM/
      app_server.yaml
```

**Invocation:**

```bash
secopstm --model-file My_System/model.md
```

SecOpsTM automatically discovers `context/*.yaml` and `BOM/*.cdx.json` (or legacy `BOM/*.yaml`)
relative to the model file directory. No `## Context` section is required if you follow the
convention.

**Sub-model drill-down.** A server in the main model can reference a child model using the
`submodel` attribute:

```markdown
## Servers
- **Application Backend**:
  boundary="App Zone",
  type=web-server,
  submodel=./Backend_Service/model.md
```

The server node in the parent diagram becomes a hyperlink to the child diagram. The child diagram
shows ghost nodes for all external actors and servers that communicate with the parent server,
providing full context without duplicating definitions.

In GDAF, bridging edges are automatically added: attacker paths can traverse from the parent
server into the child model's internal topology, and back out through the parent's exit dataflows.

### Ghost node mechanism — how child diagrams show parent connections

The child model does **not** declare anything about its parent. Ghost nodes are built entirely
from the parent's `## Dataflows` section at render time.

**Algorithm:**

1. `_collect_parent_connections(parent_tm, server_name)` scans every dataflow in the parent
   and collects stubs where `source` or `sink` matches the sub-model server name (case-insensitive).
   Each stub records the peer name, direction (`incoming` / `outgoing`), protocol, and
   encryption/auth flags.

2. Inside the child diagram, the generator identifies which child server receives external traffic
   using the following priority:

   - **Explicit entry point** (preferred): any server with `entry_point=True` in `## Servers`.
     All ghost nodes are wired to/from that server. If multiple servers share `entry_point=True`
     (HA pair, active-active firewalls), all of them receive ghost edges.
   - **Topology heuristic** (fallback, when no `entry_point=True` is declared):
     - **root servers** — servers that receive no inbound dataflow within the child → used for
       incoming ghost edges.
     - **leaf servers** — servers that send no outbound dataflow within the child → used for
       outgoing ghost edges.

3. Ghost nodes are placed:
   - `incoming` stub → ghost node in the green **"External connections in"** cluster, wired
     to the entry point / root servers.
   - `outgoing` stub → ghost node in the orange **"External connections out"** cluster, wired
     from the entry point / leaf servers.
   - **Same peer in both directions** (reverse proxy pattern) → single ghost node in the
     purple **"External connections bidirectional"** cluster, with arrows in both directions.

**Declaring an explicit entry point (recommended):**

```markdown
## Servers
- **EdgeFirewall**:
  boundary="DMZ",
  type=firewall,
  entry_point=True        ← ghost nodes will connect to/from this server
- **CoreSwitch**:
  boundary="Internal",
  type=router
- **AppServer**:
  boundary="Internal",
  type=application-server
```

Use `entry_point=True` on the first component in the sub-model that receives traffic from the
parent — typically a firewall, load balancer, or reverse proxy. Without this attribute the
generator falls back to the topology heuristic, which may pick the wrong server in complex
topologies.

> **Note on asymmetric pipelines:** for one-way data flows (e.g., log ingestion) where ingress
> and egress go through *different* servers, a future `exit_point=True` attribute is planned.
> For now, mark the ingress server with `entry_point=True`; the outgoing ghost will also be
> wired to it, which is the conservative-safe default.

**What must match:** the server name used in the parent's `## Dataflows` must equal the `submodel=`
server name after `.lower().strip()`. The child model declares nothing else about its parent.

### Reverse proxy pattern

When a reverse proxy sits in front of a backend and routes all traffic:

```markdown
# parent/main.md
## Servers
- **ReverseProxy**: boundary=DMZ, type=web-server
- **BackendCluster**: boundary="App Zone", submodel=./backend/model.md

## Dataflows
- **ProxyToBackend**: from=ReverseProxy, to=BackendCluster, protocol=HTTP
- **BackendToProxy**: from=BackendCluster, to=ReverseProxy, protocol=HTTP
```

In the child diagram (`backend/model.md`), `ReverseProxy` appears **once** in a single purple
bidirectional ghost cluster with arrows in both directions — not duplicated across the green/orange
clusters. The ghost is wired to the child's root servers (incoming) and from the child's leaf
servers (outgoing), reflecting the actual traffic path.

---

## BOM Files (Bill of Materials)

BOM files provide per-asset operational metadata that GDAF uses to refine technique scoring and
detection coverage estimates. BOM files are optional — assets without a BOM file use the
attributes defined in the DSL.

The primary BOM format is **CycloneDX 1.6 JSON** (OWASP standard). Legacy custom YAML files are
still supported for backward compatibility.

### File Naming

Name the file after the asset, normalized to lowercase with spaces replaced by underscores, and
add the `.cdx.json` extension:

| Asset name (in DSL) | CycloneDX BOM filename |
|---|---|
| `Primary Domain Controller` | `primary_domain_controller.cdx.json` |
| `Financial ERP System` | `financial_erp_system.cdx.json` |
| `Web Application Firewall` | `web_application_firewall.cdx.json` |

The BOMLoader normalizes filenames (lowercase, spaces/hyphens → underscores) and matches
case-insensitively. CycloneDX `.cdx.json` files take precedence over YAML files when both
exist for the same asset.

### CycloneDX 1.6 JSON Schema

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "version": 1,
  "metadata": {
    "component": {
      "type": "device",
      "name": "Primary Domain Controller",
      "version": "Windows Server 2019 Build 17763.2628"
    }
  },
  "components": [
    {
      "type": "operating-system",
      "name": "Windows Server 2019",
      "version": "10.0.17763.2628",
      "purl": "pkg:generic/microsoft/windows-server@10.0.17763.2628"
    },
    {
      "type": "application",
      "name": "Active Directory Domain Services",
      "version": "10.0.17763"
    }
  ],
  "services": [
    {"name": "LDAP", "endpoints": ["tcp://0.0.0.0:389"]},
    {"name": "Kerberos", "endpoints": ["udp://0.0.0.0:88"]},
    {"name": "DNS", "endpoints": ["udp://0.0.0.0:53"]},
    {"name": "RPC", "endpoints": ["tcp://0.0.0.0:135"]},
    {"name": "WinRM", "endpoints": ["tcp://0.0.0.0:5985"]}
  ],
  "vulnerabilities": [
    {
      "id": "CVE-2020-1472",
      "description": "Zerologon — elevation of privilege",
      "ratings": [{"severity": "critical", "score": 10.0, "method": "CVSSv3"}],
      "affects": [{"ref": "Primary Domain Controller"}]
    },
    {
      "id": "CVE-2021-42278",
      "description": "sAMAccountName spoofing — privilege escalation to domain admin",
      "ratings": [{"severity": "high", "score": 7.5, "method": "CVSSv3"}],
      "affects": [{"ref": "Primary Domain Controller"}]
    }
  ],
  "properties": [
    {"name": "secopstm:patch_level", "value": "outdated"},
    {"name": "secopstm:detection_level", "value": "medium"},
    {"name": "secopstm:credentials_stored", "value": "true"},
    {"name": "secopstm:notes", "value": "Zerologon patched but noPac still exploitable. No EDR. MFA disabled."}
  ]
}
```

### Required Fields

| Field | Required | Description |
|---|---|---|
| `bomFormat` | Yes | Must be `"CycloneDX"` — used to identify the file as a valid CycloneDX BOM. |
| `specVersion` | Yes | Should be `"1.6"`. |
| `metadata.component` | Yes | Describes the asset. `name` is used as the display name. |
| `components` | No | List of software/OS components installed on the asset. |
| `services` | No | Network services actively listening on the asset. |
| `vulnerabilities` | No | Known CVEs present on the asset. |
| `properties` | No | SecOpsTM-specific metadata (see below). |

### How Services Are Detected

The `services[]` array lists network services listening on the asset. Each entry needs only a
`name` field — the `endpoints` array is optional (informational):

```json
"services": [
  {"name": "LDAP", "endpoints": ["tcp://0.0.0.0:389"]},
  {"name": "Kerberos", "endpoints": ["udp://0.0.0.0:88"]}
]
```

Service names are merged with protocols derived from DSL dataflows to build the node's full
`services` set for GDAF technique scoring.

### How CVEs Are Listed

Each entry in `vulnerabilities[]` must have an `id` field with the CVE identifier:

```json
"vulnerabilities": [
  {
    "id": "CVE-2020-1472",
    "description": "Zerologon — elevation of privilege",
    "ratings": [{"severity": "critical", "score": 10.0, "method": "CVSSv3"}]
  }
]
```

CVE IDs are cross-referenced against `external_data/cve2capec/` JSONL files to extract CWE
classes and CAPEC patterns, which feed into the STRIDE severity scoring pipeline.

### SecOpsTM Custom Properties (`secopstm:` prefix)

Operational metadata specific to SecOpsTM is stored in the `properties[]` array using the
`secopstm:` prefix:

| Property name | Type | Values | GDAF Effect |
|---|---|---|---|
| `secopstm:patch_level` | string | `current`, `outdated`, `critical` | Informational — displayed in reports. |
| `secopstm:detection_level` | string | `none`, `low`, `medium`, `high` | Maps to detection_coverage float: 0.0, 0.2, 0.5, 0.8. |
| `secopstm:credentials_stored` | bool string | `"true"` / `"false"` | +0.4 on all credential-access technique scores if `"true"`. Overrides DSL value. |
| `secopstm:notes` | string | Free text | Included verbatim in reports and GDAF summaries. |

```json
"properties": [
  {"name": "secopstm:patch_level", "value": "outdated"},
  {"name": "secopstm:detection_level", "value": "medium"},
  {"name": "secopstm:credentials_stored", "value": "true"},
  {"name": "secopstm:notes", "value": "No EDR deployed. noPac still exploitable."}
]
```

### Backward Compatibility — YAML Files

Legacy YAML BOM files (`.yaml` / `.yml`) are still loaded automatically. CycloneDX files take
precedence when both exist for the same asset. Example of a legacy YAML file (still valid):

```yaml
asset: "Primary Domain Controller"
os_version: "windows_server_2019"
software_version: "Windows Server 2019 Build 17763.2628"
patch_level: outdated
known_cves:
  - CVE-2020-1472
  - CVE-2021-42278
running_services:
  - LDAP
  - Kerberos
detection_level: medium
credentials_stored: true
notes: "Zerologon mitigated by patch. No EDR deployed."
```

### BOM Field Reference

The following fields are available in both CycloneDX JSON and legacy YAML, and are passed to
GDAF after loading:

| Field | Source in CycloneDX | Type | Default | GDAF Effect |
|---|---|---|---|---|
| `os_version` | First `components[]` with `type=operating-system` (name + version, underscores) | string | `None` | Informational — stored in node metadata. |
| `software_version` | First non-OS `components[]` entry (name + version) | string | `None` | Informational — stored in node metadata. |
| `running_services` | `services[].name` values | list | `[]` | Merged with DSL dataflow protocols → tactic/technique boosts. |
| `known_cves` | `vulnerabilities[].id` values | list | `[]` | CVE match signal in STRIDE scoring (+0.5 per hit). When `analysis.state` is present on a vulnerability, only CVEs in active states (`affected`, `exploitable`, `in_triage`, `under_investigation`) contribute to scoring; `fixed`/`resolved` CVEs are treated as a remediation signal (discount). |
| `active_cves` | derived from `vulnerabilities[].analysis.state` | list | (auto) | Auto-derived from `known_cves` when `analysis.state` is present. Only these CVEs boost severity. |
| `fixed_cves` | derived from `vulnerabilities[].analysis.state` | list | (auto) | Auto-derived. CVEs marked `fixed` or `resolved` act as a D3FEND-equivalent mitigation signal. |
| `detection_level` | `secopstm:detection_level` property | string | `"none"` | detection_coverage float: none=0.0, low=0.2, medium=0.5, high=0.8. |
| `credentials_stored` | `secopstm:credentials_stored` property | bool | — | +0.4 on credential-access techniques. Overrides DSL value. |
| `patch_level` | `secopstm:patch_level` property | string | `None` | Informational. |
| `notes` | `secopstm:notes` property | string | `None` | Included in reports. |

### How GDAF Uses BOM Data

1. `credentials_stored=true` → +0.4 on all credential-access technique scores at this node.
2. `detection_level` → mapped to `detection_coverage` float. The scenario-level detection
   coverage is the average across all hop nodes, displayed in Attack Flow reports.
3. `running_services` → merged with protocols from dataflows into the node's `services` set.
   Services trigger protocol-specific tactic boosts and key technique matches.

---

## Complete Example

The following is the complete `On-Prem_Enterprise_Network.md` template, which covers all DSL
features. It models a large enterprise with 9 security zones, Active Directory, ERP, CI/CD, and
OT/SCADA.

```markdown
# Threat Model: On-Prem Enterprise Network

## Description
Large multinational manufacturing enterprise with on-premises Active Directory infrastructure,
financial ERP system, CI/CD pipeline, and legacy OT/SCADA environment. Approximately 2,000
employees. Compliance: ISO 27001, IEC 62443, SOX, GDPR.

## Context
gdaf_context = context/enterprise_onprem_context.yaml
bom_directory = BOM
gdaf_min_technique_score = 0.75

## Boundaries
- **Internet**: type=network-on-prem, isTrusted=False, color=red, traversal_difficulty=low
- **DMZ**: type=network-on-prem, isTrusted=False, color=orange, traversal_difficulty=low
- **VPN Perimeter**: type=network-on-prem, isTrusted=False, color=orangered, traversal_difficulty=low
- **Internal Network**: type=network-on-prem, isTrusted=True, color=lightgreen, traversal_difficulty=low
- **IT Infrastructure Zone**: type=execution-environment, isTrusted=True, color=lightblue, traversal_difficulty=medium
- **Finance Zone**: type=execution-environment, isTrusted=True, color=lightyellow, traversal_difficulty=high
- **Development Zone**: type=execution-environment, isTrusted=True, color=lightcyan, traversal_difficulty=medium
- **Restricted Data Zone**: type=execution-environment, isTrusted=True, color=lavender, traversal_difficulty=high
- **OT SCADA Zone**: type=execution-environment, isTrusted=True, color=mistyrose, traversal_difficulty=high

## Actors
- **External Attacker**: boundary=Internet, authenticity=none, isTrusted=False
- **Remote Employee**: boundary=Internet, authenticity=two-factor, isTrusted=False
- **Corporate Employee**: boundary="Internal Network", authenticity=credentials, isTrusted=True
- **Finance Employee**: boundary="Finance Zone", authenticity=credentials, isTrusted=True
- **IT Administrator**: boundary="IT Infrastructure Zone", authenticity=two-factor, isTrusted=True
- **Developer**: boundary="Development Zone", authenticity=two-factor, isTrusted=True
- **SCADA Operator**: boundary="OT SCADA Zone", authenticity=credentials, isTrusted=True

## Servers
- **Edge Router**:
  boundary=DMZ, type=firewall, machine=physical, ids=True, ips=True,
  internet_facing=True, confidentiality=high, integrity=high, availability=critical,
  tags=[cisco-ios, edge, perimeter]
- **Primary Domain Controller**:
  boundary="IT Infrastructure Zone", type=domain-controller, machine=physical,
  auth_protocol=kerberos, mfa_enabled=False, credentials_stored=True,
  confidentiality=critical, integrity=critical, availability=critical,
  tags=[windows-server-2019, active-directory]
- **Financial ERP System**:
  boundary="Finance Zone", type=database, machine=physical, encryption=none,
  mfa_enabled=False, credentials_stored=True,
  confidentiality=critical, integrity=critical, availability=critical,
  tags=[sap, erp, mainframe]
- **SCADA HMI**:
  boundary="OT SCADA Zone", type=scada, machine=physical, mfa_enabled=False,
  encryption=none, confidentiality=critical, integrity=critical, availability=critical,
  tags=[windows-7, legacy, hmi, scada]
- **PLC Controller**:
  boundary="OT SCADA Zone", type=plc, machine=physical,
  confidentiality=medium, integrity=critical, availability=critical,
  tags=[siemens, plc, ot, modbus]

## Data
- **Admin Credentials**: description="Privileged administrative credentials", classification=TOP_SECRET
- **Financial Record**: description="Highly sensitive financial records", classification=TOP_SECRET
- **SCADA Command**: description="Operational control commands for industrial systems", classification=SECRET
- **Kerberos Ticket**: description="Active Directory Kerberos authentication ticket", classification=SECRET

## Dataflows
- **ExternalToRouter**: from="External Attacker", to="Edge Router", protocol=TCP, authentication=none, is_encrypted=False
- **WorkstationToAD**: from="Employee Workstation", to="Primary Domain Controller", protocol=LDAP, authentication=credentials, is_encrypted=False
- **ADToJump**:
  from="Primary Domain Controller", to="Jump Server", protocol=WinRM,
  data="Admin Credentials", authentication=credentials, is_encrypted=True
  // Lateral movement: DC admin can push GPO/scripts to jump server
- **HMIToPLC**: from="SCADA HMI", to="PLC Controller", protocol=Modbus, authentication=none, is_encrypted=False

## Protocol Styles
- **HTTPS**: color=darkgreen, line_style=solid
- **HTTP**: color=red, line_style=solid
- **SSH**: color=blue, line_style=dashed
- **LDAP**: color=purple, line_style=solid
- **SMB**: color=orange
- **RDP**: color=steelblue, line_style=dashed
- **Modbus**: color=crimson, line_style=solid

## Severity Multipliers
- **Primary Domain Controller**: 3.0
- **Financial ERP System**: 2.5
- **Core Database Cluster**: 2.5
- **SCADA HMI**: 2.0
- **PKI Certificate Authority**: 2.0

## Custom Mitre Mapping
- **Pass-the-Hash**: {"tactics": ["Lateral Movement"], "techniques": [{"id": "T1550.002", "name": "Use Alternate Authentication Material: Pass the Hash"}]}
- **Kerberoasting**: {"tactics": ["Credential Access"], "techniques": [{"id": "T1558.003", "name": "Steal or Forge Kerberos Tickets: Kerberoasting"}]}
- **DCSync**: {"tactics": ["Credential Access"], "techniques": [{"id": "T1003.006", "name": "OS Credential Dumping: DCSync"}]}
- **Golden Ticket**: {"tactics": ["Persistence", "Privilege Escalation"], "techniques": [{"id": "T1558.001", "name": "Steal or Forge Kerberos Tickets: Golden Ticket"}]}
- **Modbus Command Injection**: {"tactics": ["Impact"], "techniques": [{"id": "T1565.001", "name": "Data Manipulation: Stored Data Manipulation"}]}
```

The complete version of this template (with all 22 servers, 30 dataflows, and 10 data objects) is
available at `threatModel_Template/On-Prem_Enterprise_Network.md`.

---

## Quick Reference Table

Every attribute across all sections. "Required" means the model cannot function without it.

| Attribute | Section | Type | Default | Required | STRIDE Impact | GDAF Impact |
|---|---|---|---|---|---|---|
| `gdaf_context` | Context | string (path) | None | No | None | Loads attack objectives and actor profiles |
| `bom_directory` | Context | string (path) | None | No | None | Enriches nodes with operational metadata |
| `vex_file` | Context | string (path) | None | No | CVE scoring (priority 1) | Standalone VEX document — overrides BOM CVEs |
| `vex_directory` | Context | string (path) | None | No | CVE scoring (priority 1) | Directory of VEX files — overrides BOM CVEs |
| `gdaf_min_technique_score` | Context | float | 0.8 | No | None | Filters .afb OR-branch rendering |
| `isTrusted` | Boundaries | bool | False | No | Trust boundary threats | Entry point detection |
| `type` (boundary) | Boundaries | string | "" | No | None | Zone classification |
| `color` (boundary) | Boundaries | string | lightgray | No | None | Diagram cluster fill color |
| `traversal_difficulty` | Boundaries | string | low | No | None | `hop_weight` bonus |
| `businessValue` | Boundaries, Actors, Servers | string | None | No | None | Tooltip text |
| `boundary` | Actors, Servers | string | None | No | Trust zone assignment | Group membership, `boundary_trusted` |
| `authenticity` | Actors | string | none | No | Auth-specific threats | None |
| `isTrusted` (actor) | Actors | bool | False | No | None | Insider vs. external entry point |
| `color` (actor/server) | Actors, Servers | string | None | No | None | Node fill color |
| `type` (server) | Servers | string | default | No | None | Platform/tactic/technique selection |
| `machine` | Servers | string | None | No | DoS variants | None |
| `confidentiality` | Servers | string | low | No | Data-at-rest threats | CIA score |
| `integrity` | Servers | string | low | No | Tampering threats | CIA score |
| `availability` | Servers | string | low | No | DoS severity | CIA score |
| `encryption` | Servers | string | "" | No | Data-at-rest STRIDE rules | None |
| `redundant` | Servers | bool | False | No | DoS likelihood | None |
| `mfa_enabled` | Servers | bool | True | No | None | +0.2 on cred-access if False |
| `auth_protocol` | Servers | string | None | No | Protocol threats | None |
| `internet_facing` | Servers | bool | False | No | None | GDAF entry point |
| `credentials_stored` | Servers | bool | False | No | Credential theft | +0.4 on cred-access techniques |
| `waf` | Servers | bool | False | No | None (firewall only) | None |
| `ids` | Servers | bool | False | No | None (firewall only) | None |
| `ips` | Servers | bool | False | No | None (firewall only) | None |
| `tags` | Servers | list | [] | No | None | Legacy signal, service hints |
| `submodel` | Servers | string (path) | None | No | None | Sub-model bridging edges |
| `entry_point` | Servers | bool | False | No | None | Ghost wiring in child diagrams — marks the server that receives external (parent) traffic; see [Ghost node mechanism](#ghost-node-mechanism--how-child-diagrams-show-parent-connections) |
| `classification` | Data | string | UNKNOWN | No | Data sensitivity threats | `data_value` on edges |
| `credentialsLife` | Data | string | UNKNOWN | No | Credential threats | None |
| `description` (data) | Data | string | "" | No | None | None |
| `from` | Dataflows | string | — | **Yes** | Source element | Source node |
| `to` | Dataflows | string | — | **Yes** | Sink element | Sink node |
| `protocol` | Dataflows | string | None | No | Protocol threats | Service boosts |
| `is_encrypted` | Dataflows | bool | False | No | Cleartext threats | +0.3 `hop_weight` if False |
| `is_authenticated` | Dataflows | bool | False | No | Auth threats | +0.4 `hop_weight` if False |
| `authentication` | Dataflows | string | none | No | Auth-specific threats | Edge auth attribute |
| `authorization` | Dataflows | string | none | No | Authz threats | None |
| `vpn` | Dataflows | bool | False | No | VPN variants | None |
| `bidirectional` | Dataflows | bool | False | No | None | Reverse edge in GDAF graph |
| `data` | Dataflows | string | None | No | Data classification threats | `data_value` on edge |
| `ip_filtered` | Dataflows | bool | False | No | IP filter threats | None |
| `readonly` | Dataflows | bool | False | No | Write-access threats | None |
| `usage` | Dataflows | string | None | No | None | None |
| `color` (dataflow) | Dataflows | string | None | No | None | Arrow color (overrides protocol style) |
| `color` (protocol) | Protocol Styles | string | None | No | None | Arrow color for all flows with this protocol |
| `line_style` | Protocol Styles | string | solid | No | None | Arrow line style |
| `width` | Protocol Styles | number | None | No | None | Arrow line width |
| multiplier value | Severity Multipliers | float | — | No | Severity scaling | None |
| `tactics` | Custom Mitre Mapping | list | — | No | MITRE tactic assignment | None |
| `techniques` | Custom Mitre Mapping | list | — | No | MITRE technique assignment | None |
| `asset` | BOM (YAML legacy) | string | None | No | None | None (cosmetic — not used for file matching) |
| `os_version` | BOM | string | None | No | None | Informational (CDX: first operating-system component) |
| `software_version` | BOM | string | None | No | None | Informational (CDX: first non-OS component) |
| `patch_level` | BOM | string | None | No | None | Informational (CDX: `secopstm:patch_level` property) |
| `known_cves` | BOM | list | [] | No | CVE-CAPEC scoring (+0.5) | None (CDX: `vulnerabilities[].id`) — when `analysis.state` present, only active-state CVEs score |
| `active_cves` | BOM (auto) | list | (derived) | No | CVE scoring input | None — auto-derived from `known_cves` + `analysis.state` |
| `fixed_cves` | BOM (auto) | list | (derived) | No | Mitigation discount | None — auto-derived; acts as remediation signal |
| `running_services` | BOM | list | [] | No | None | Service boosts (CDX: `services[].name`) |
| `detection_level` | BOM | string | none | No | None | `detection_coverage` float (CDX: `secopstm:detection_level`) |
| `credentials_stored` (BOM) | BOM | bool | — | No | Credential threats | Overrides DSL value (CDX: `secopstm:credentials_stored`) |
| `notes` | BOM | string | None | No | None | None (CDX: `secopstm:notes` property) |

---

## Related Documentation

- [Enriching AI Threats](enriching_ai_threats.md) — which DSL attributes, BOM fields, and context files
  improve AI-generated threats, and exactly how each one affects the LLM prompt
- [GDAF Reference](gdaf.md) — Goal-Driven Attack Flow Engine: context YAML format, actor profiles,
  attack objectives, risk criteria
- [Usage](usage.md) — CLI flags, project mode invocation, export formats
- [Examples](examples.md) — Ready-to-use templates for common architectures
- [Extensibility](extensibility.md) — Adding custom STRIDE rules and IaC plugins
