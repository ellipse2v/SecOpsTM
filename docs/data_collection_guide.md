# Data Collection Guide for Threat Modeling

This guide tells you exactly what information to gather before building a SecOpsTM threat model.
It is written for security architects and DevOps engineers who are conducting or commissioning a
threat modeling session. You can hand this document to a system owner and expect to receive back
everything the tool needs.

A well-filled threat model produces: a STRIDE threat report with MITRE ATT&CK mappings, a
severity-colored architecture diagram, goal-driven attack scenarios (GDAF), and exports to STIX
2.1 and ATT&CK Navigator.

**Time to collect:** One to two hours of architecture walkthrough with the system owner.
**Format:** Return filled-in Markdown following the examples in each section, or a completed
questionnaire that the threat modeler will translate.

---

## Introduction

SecOpsTM models a system by describing:
1. **Who** interacts with it (actors)
2. **Where** they are (boundaries / trust zones)
3. **What** processes and stores data (servers/components)
4. **What data** flows between components
5. **What sensitive data assets** exist
6. **What the system inventory looks like** (BOM)
7. **What attackers want** and **who they are** (GDAF context)

Each piece of information maps directly to a section in the threat model file. Missing information
produces lower-quality threat coverage — for example, a server without CIA ratings gets no GDAF
path scoring, and a dataflow without `is_encrypted` gets a default of `False` which adds threat
noise.

---

## Point 1: System Overview

**Why it matters:** Sets the scope of the model. The tool embeds the description in every
generated report. It also informs AI-powered threat generation, which uses the description as
context for prompt building.

**What to collect:**

| Question | Example answer |
|---|---|
| What does this system do? | "Financial transaction processing platform serving 500 internal users" |
| What technology stack? | "Java microservices on Kubernetes, PostgreSQL, Kafka, Azure AD" |
| What is the deployment environment? | On-premises / cloud (AWS, Azure, GCP) / hybrid |
| What industry / regulatory requirements apply? | ISO 27001, PCI-DSS, GDPR, SOX, IEC 62443 |
| Approximate number of users | 500 internal, 10,000 external |
| Is the system internet-facing? | Yes / No / Partially (only the API gateway) |

**Maps to:** `## Description` section and `config/context.yaml` system description.

**Example DSL output:**

```markdown
## Description
Financial transaction processing platform serving 500 internal users and 10,000 external
customers. Java microservices on Kubernetes (AKS), PostgreSQL, Apache Kafka. Deployed in
Azure with on-premises Active Directory federation. Compliance: PCI-DSS, GDPR, ISO 27001.
```

---

## Point 2: Network Segmentation (Boundaries)

**Why it matters:** Boundaries are the trust zones that STRIDE threat rules fire on. A dataflow
crossing from an untrusted boundary to a trusted boundary is the primary trigger for spoofing,
tampering, and information disclosure threats. GDAF uses boundary trust and traversal difficulty
to score how exploitable each network segment is.

**What to collect:**

| Question | Example answer |
|---|---|
| List all network segments / security zones | Internet perimeter, DMZ, Internal LAN, Finance VLAN, OT network |
| For each zone: is it trusted or untrusted? | DMZ = untrusted, Internal LAN = trusted |
| For each zone: type (network, execution environment, container) | DMZ = network, Finance VLAN = execution environment |
| For each zone: how hard is it to get in? (low / medium / high controls) | Finance VLAN = high (firewall + NAC + VLAN isolation) |
| Are any zones nested inside others? | Finance VLAN is inside Internal Network |

**Traversal difficulty guidance:**

| Control posture | Value to use |
|---|---|
| Open segment, no controls, few firewall rules | `low` |
| Standard VLAN + firewall rules, no micro-segmentation | `medium` |
| Micro-segmented, strict allow-list firewall, NAC, jump server required | `high` |

**Maps to:** `## Boundaries` section.

**Example DSL output:**

```markdown
## Boundaries
- **Internet**: isTrusted=False, type=network-on-prem, color=red, traversal_difficulty=low
- **DMZ**: isTrusted=False, type=network-on-prem, color=orange, traversal_difficulty=low
- **Internal Network**: isTrusted=True, type=network-on-prem, color=lightgreen, traversal_difficulty=low
- **Finance Zone**:
  isTrusted=True,
  type=execution-environment,
  color=lightyellow,
  traversal_difficulty=high,
  businessValue="Hosts ERP and all financial records"
```

---

## Point 3: Users and External Systems (Actors)

**Why it matters:** Actors are the entities that initiate dataflows. Without actors, there are no
attack entry points for GDAF, and no source for dataflows that cross trust boundaries. External
attackers placed in untrusted boundaries are how GDAF computes paths to target assets.

**What to collect:**

| Question | Example answer |
|---|---|
| List all user roles / personas | End User, Administrator, Finance Analyst, SCADA Operator |
| List all external systems (APIs, partners, suppliers) | Payment gateway, external SSO provider |
| List adversarial actors for modeling purposes | External Attacker, Insider Threat |
| For each actor: which zone are they in? | Finance Analyst → Finance Zone; External Attacker → Internet |
| For each actor: how do they authenticate? | Two-factor, credentials, none (attacker) |
| For each actor: are they trusted? | Employees = trusted; External Attacker = untrusted |

**Maps to:** `## Actors` section.

**Example DSL output:**

```markdown
## Actors
- **External Attacker**: boundary=Internet, authenticity=none, isTrusted=False
- **End User**: boundary=Internet, authenticity=credentials, isTrusted=False
- **Finance Analyst**: boundary="Finance Zone", authenticity=two-factor, isTrusted=True
- **IT Administrator**: boundary="Internal Network", authenticity=two-factor, isTrusted=True
```

---

## Point 4: Components and Servers

**Why it matters:** Servers are the nodes in the attack graph. Their attributes feed into GDAF
technique selection (asset type → relevant MITRE techniques), CIA scoring (path attractiveness),
and STRIDE rule filtering. A domain controller without `type=domain-controller` will not receive
Kerberoasting or Pass-the-Hash technique scoring.

**What to collect for each server/component:**

| Attribute | Question | Example |
|---|---|---|
| Name | What is the component called? | "Primary Domain Controller" |
| Zone / boundary | Which network segment is it in? | IT Infrastructure Zone |
| Asset type | What category of asset is it? | `domain-controller` (see full list below) |
| Machine type | Physical, virtual, container, or serverless? | `physical` |
| Is it internet-facing? | Is it directly reachable from the internet? | `False` (behind DMZ) |
| Stores credentials? | Does it store password hashes, API keys, service account passwords? | `True` |
| MFA enabled? | Is MFA required to access this system? | `False` |
| Authentication protocol | LDAP, Kerberos, SAML, OAuth, RADIUS, none | `kerberos` |
| Encryption at rest | None, transparent disk, per-file encryption | `none` |
| Confidentiality rating | How sensitive is the data it holds? (low/medium/high/critical) | `critical` |
| Integrity rating | How serious would tampering be? (low/medium/high/critical) | `critical` |
| Availability rating | How serious would downtime be? (low/medium/high/critical) | `critical` |
| Technology tags | OS version, product name, relevant identifiers | `windows-server-2019, active-directory` |
| Firewall-specific | WAF enabled? IDS? IPS? | `ids=True, ips=True` |

**Full list of asset types:**

| Type | Examples |
|---|---|
| `firewall` | Edge router, WAF, NGFW, security appliance |
| `domain-controller` | Active Directory DC, LDAP server |
| `auth-server` | RADIUS, TACACS+, Okta, Keycloak |
| `database` | SQL Server, PostgreSQL, Oracle, MongoDB, SAP HANA |
| `web-server` | Apache, NGINX, IIS, Node.js app server |
| `api-gateway` | Kong, AWS API Gateway, Azure API Management |
| `file-server` | Windows File Server, NAS, SharePoint |
| `mail-server` | Exchange, Postfix, sendmail |
| `management-server` | Jump server, bastion host, PAM solution, RMM |
| `workstation` | Desktop PC, laptop, thin client |
| `load-balancer` | HAProxy, F5, AWS ALB |
| `vpn` | Client VPN concentrator |
| `vpn-gateway` | Site-to-site VPN gateway, Cisco ASA |
| `plc` | Programmable Logic Controller, RTU, embedded controller |
| `scada` | HMI workstation, SCADA server, historian |
| `repository` | GitLab, GitHub Enterprise, Bitbucket |
| `cicd` | Jenkins, GitHub Actions runner, GitLab CI |
| `backup` | Backup server, Veeam, Commvault |
| `dns` | DNS resolver, authoritative DNS server |
| `pki` | Certificate Authority, OCSP responder |
| `siem` | Splunk, Elastic SIEM, Microsoft Sentinel |

If none fits, omit `type` and the default platform profile is used.

**Maps to:** `## Servers` section.

**Example DSL output:**

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
  businessValue="Forest root — controls all network access"
- **Payment API Gateway**:
  boundary=DMZ,
  type=api-gateway,
  machine=container,
  internet_facing=True,
  confidentiality=high,
  integrity=critical,
  availability=critical,
  tags=[kong, pci-scope]
```

---

## Point 5: Communication Flows (Dataflows)

**Why it matters:** Dataflows are the primary source of STRIDE threats. Every unauthenticated or
unencrypted flow generates threats. GDAF uses dataflows as directed graph edges to find attack
paths — without dataflows, there is no graph and no path analysis. Missing dataflows = missing
attack paths.

**For each communication channel between two components:**

| Attribute | Question | Example |
|---|---|---|
| Source → Destination | What connects to what? | Employee Workstation → Active Directory |
| Protocol | What protocol is used? | LDAP |
| Encrypted? | Is the channel encrypted (TLS, IPSec)? | No |
| Authenticated? | Is mutual authentication required? | Credentials (one-way) |
| Authentication method | Credentials, token, certificate, Kerberos, 2FA, none | `credentials` |
| VPN? | Does this flow travel over a VPN tunnel? | No |
| Bidirectional? | Does data flow both ways meaningfully? | Yes (DC replication) |
| Data carried | What named data object does this carry? | Kerberos Ticket, Admin Credentials |

**Prioritize flows involving:**
- Trust boundary crossings (internet → DMZ, DMZ → internal)
- Administrative protocols (RDP, SSH, WinRM, LDAP, Kerberos)
- Database connections
- OT/SCADA protocols (Modbus, DNP3, OPC-UA)
- Service-to-service API calls

**Maps to:** `## Dataflows` section.

**Example DSL output:**

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
- **HMIToPLC**:
  from="SCADA HMI",
  to="PLC Controller",
  protocol=Modbus,
  authentication=none,
  is_encrypted=False
```

---

## Point 6: Sensitive Data Assets

**Why it matters:** Data classification drives STRIDE data handling threats and GDAF path scoring.
A `TOP_SECRET` data object carried on a dataflow adds +0.3 to the path score for that edge,
making it more attractive to attackers in GDAF scenarios. `HARDCODED` credentials on a data object
trigger dedicated pytm credential theft rules.

**What to collect:**

| Question | Example |
|---|---|
| List all distinct sensitive data types handled by the system | Admin credentials, financial records, PII, source code, SCADA commands |
| For each data type: sensitivity level | TOP_SECRET, SECRET, RESTRICTED, PUBLIC |
| For each data type: is it credential material? | Yes / No |
| For credentials: are they long-lived, auto-rotated, or hardcoded? | LONG (service accounts) / HARDCODED (embedded API keys) |
| Which dataflows carry which data types? | DB backup flow carries "Database Backup" (TOP_SECRET) |

**Classification guidance:**

| Level | Use when |
|---|---|
| `PUBLIC` | Data is publicly available, no harm if disclosed |
| `RESTRICTED` | Internal use only; disclosure causes moderate harm |
| `SECRET` | Sensitive; disclosure causes significant harm (PII, credentials) |
| `TOP_SECRET` | Maximum sensitivity; disclosure causes severe harm (financial records, admin credentials) |

**Credential lifetime guidance:**

| Situation | Value |
|---|---|
| Session tokens, JWT with short expiry | `SHORT` |
| Service account passwords, API keys changed annually | `LONG` |
| Hardcoded passwords or API keys in code / config | `HARDCODED` |
| Automatically rotated by a secrets manager | `AUTO` |

**Maps to:** `## Data` section.

**Example DSL output:**

```markdown
## Data
- **Admin Credentials**:
  description="Domain administrator and service account credentials",
  classification=TOP_SECRET,
  credentialsLife=LONG
- **Financial Record**:
  description="Transaction history and SAP ERP records",
  classification=TOP_SECRET
- **PII**:
  description="Employee and customer personally identifiable information",
  classification=SECRET
- **Embedded API Key**:
  description="Hardcoded API key in legacy integration",
  classification=SECRET,
  credentialsLife=HARDCODED
```

---

## Point 7: Asset Inventory / BOM

**Why it matters:** The Bill of Materials (BOM) enriches GDAF's graph with operational
ground-truth: actual CVEs present, real services listening, detection capability, and patch
status. Without BOM files, GDAF scores techniques based only on the asset type. With BOM files,
it can boost techniques for known CVEs (e.g., Zerologon on a domain controller), flag legacy
software, and compute detection coverage gaps.

**For each server, provide a BOM YAML file. Collect:**

| Attribute | Question | Example |
|---|---|---|
| OS version | What OS and version is running? | `windows_server_2019`, `ubuntu_22.04`, `cisco_ios_15.7` |
| Software version | What is the main application version? | `MSSQL_2008_R2`, `GitLab_15.11` |
| Patch level | Is it up to date? | `current`, `outdated`, `critical` |
| Known CVEs | Are there known unpatched vulnerabilities? | CVE-2020-1472 (Zerologon) |
| Running services | What is actually listening on the network? | LDAP, Kerberos, RPC, WinRM, DNS |
| Detection level | What security monitoring is in place on this asset? | `none`, `low`, `medium`, `high` |
| Stores credentials? | Does it store credential material? | `true` |
| Notes | Any relevant operational context | "Last patched 18 months ago. No EDR deployed." |

**Detection level guidance:**

| Level | Meaning | Example |
|---|---|---|
| `none` | No monitoring | Legacy system, no agent, no syslog |
| `low` | Basic logging only, no alerting | Syslog to SIEM but no alert rules |
| `medium` | Active monitoring with some alert coverage | EDR installed, some SIEM alert rules |
| `high` | Comprehensive detection with tuned alerts | Full EDR, UEBA, custom SIEM rules, 24/7 SOC |

**BOM file naming convention:** `{asset_name_lowercase_underscores}.yaml`

Example: for an asset named `Primary Domain Controller`, the BOM file is
`primary_domain_controller.yaml`.

**Example BOM file (`primary_domain_controller.yaml`):**

```yaml
asset: "Primary Domain Controller"
os_version: "windows_server_2019"
software_version: "Windows Server 2019 Build 17763.2628"
patch_level: outdated
known_cves:
  - CVE-2020-1472    # Zerologon
  - CVE-2021-42278   # sAMAccount name spoofing
  - CVE-2021-42287
running_services:
  - LDAP
  - Kerberos
  - RPC
  - DNS
  - WinRM
detection_level: medium
credentials_stored: true
notes: "Zerologon mitigated by patch but sAMAccount spoofing still present. No EDR deployed. AD Recycle Bin enabled."
```

**Maps to:** `BOM/*.yaml` directory (auto-discovered by SecOpsTM).

---

## Point 8: Attack Scenarios and Threat Actors

**Why it matters:** The GDAF engine requires explicit attack objectives and threat actor profiles
to generate goal-driven attack scenarios. Without this information, GDAF produces no output and
you get only the STRIDE-based threat table. With a well-defined context file, GDAF produces ranked
multi-hop attack paths with MITRE technique assignments for each step.

**What to collect:**

### Attack Objectives

For each business-critical outcome an attacker could achieve:

| Question | Example |
|---|---|
| What is the attacker's goal? | "Steal financial records" |
| Which specific systems are the targets? | Financial ERP System, Core Database Cluster |
| What is the business impact? | "SOX violation, regulatory fines, competitive damage" |
| What MITRE ATT&CK tactic represents the end-goal? | `exfiltration`, `impact`, `privilege-escalation` |
| Minimum severity score to flag as unacceptable? | 5.0 (scale: 1.0–10.0) |

### Threat Actor Profiles

For each threat actor type relevant to your organization:

| Question | Example |
|---|---|
| Actor name and type | "Financially Motivated Cybercriminal Group" |
| Sophistication level | `low`, `medium`, `high`, `nation-state` |
| Which objectives do they pursue? | Financial exfiltration, ransomware |
| Entry preference | `internet-facing` (external), `insider` |
| Known TTPs (if specific group) | T1566.001 (spearphishing), T1078 (valid accounts) |
| Which ATT&CK tactics are they capable of? | initial-access, lateral-movement, exfiltration |

### Risk Parameters

| Question | Example |
|---|---|
| Maximum attack hops to model | 7 (default) |
| Maximum paths per objective | 3 (default) |
| Acceptable risk score threshold | 5.0 — paths scoring above this are flagged |

**Maps to:** `context/context.yaml` (GDAF context file).

**Minimal GDAF context example:**

```yaml
attack_objectives:
  - id: "OBJ-DATA-EXFIL"
    name: "Customer Data Exfiltration"
    description: "Steal customer PII and financial data"
    target_asset_names:
      - "Core Database"
    target_types: ["database"]
    business_impact: "GDPR fines, reputational damage"
    mitre_final_tactic: "exfiltration"
    min_severity_score: 5.0

threat_actors:
  - id: "TA-EXTERNAL"
    name: "External Cybercriminal"
    sophistication: "medium"
    objectives: ["OBJ-DATA-EXFIL"]
    entry_preference: "internet-facing"
    known_ttps:
      - "T1190"    # Exploit Public-Facing Application
      - "T1078"    # Valid Accounts
    capable_tactics:
      - "initial-access"
      - "credential-access"
      - "lateral-movement"
      - "exfiltration"

risk_criteria:
  acceptable_risk_score: 5.0
  max_hops: 7
  max_paths_per_objective: 3
```

---

## Point 9: Existing Security Controls

**Why it matters:** Security controls reduce threat likelihood and affect GDAF scoring. Documenting
them ensures the model reflects the current security posture rather than a worst-case baseline.
Controls without corresponding attributes in the DSL can be noted in `businessValue` fields or
BOM `notes` for context.

**What to collect:**

| Control type | DSL attribute / Location | Example |
|---|---|---|
| Network encryption (TLS, IPSec) | `is_encrypted=True` on dataflows | All internal API calls use mTLS |
| Authentication on channels | `is_authenticated=True`, `authentication=two-factor` on dataflows | VPN requires 2FA |
| MFA on servers | `mfa_enabled=True` on servers | Jump server requires MFA |
| Web Application Firewall | `waf=True` on firewall type server | WAF in front of public API |
| IDS/IPS | `ids=True`, `ips=True` on firewall servers | Edge router has IPS |
| Detection and response (EDR, SIEM) | `detection_level` in BOM files | Domain controller: medium |
| Data encryption at rest | `encryption=transparent` on servers | DB uses TDE |
| Network segmentation strength | `traversal_difficulty=high` on boundaries | Finance zone: high |
| Redundancy | `redundant=True` on servers | Load balancer is redundant |
| Credentials in secrets manager | `credentialsLife=AUTO` on data objects | API keys auto-rotated |

**Note:** The tool automatically maps D3FEND defensive techniques to threats. If your controls are
reflected accurately in DSL attributes, the STRIDE report will include D3FEND countermeasures in
the threat details — no extra action needed.

---

## Point 10: Custom MITRE ATT&CK Mappings (Advanced)

**Why it matters:** SecOpsTM automatically maps STRIDE threats to ATT&CK techniques via the
STRIDE→CAPEC→ATT&CK chain. However, some attack patterns are environment-specific and not captured
by this automatic chain. Custom mappings let you pin specific techniques to named attack patterns
that you know are relevant to your environment.

**When to use custom mappings:**

- You know specific attacks are relevant to your technology stack (e.g., Kerberoasting on a
  Windows AD environment, Zerologon, SAP-specific techniques)
- You want to ensure specific ATT&CK IDs appear in Navigator exports for red team planning
- Your compliance framework requires explicit mapping of specific techniques

**What to collect:**

| Question | Example |
|---|---|
| Name of the attack pattern | "Kerberoasting" |
| Which MITRE ATT&CK tactics apply? | "Credential Access" |
| Which specific ATT&CK technique IDs? | T1558.003 |
| Technique full name (for readability) | "Steal or Forge Kerberos Tickets: Kerberoasting" |

**Maps to:** `## Custom Mitre Mapping` section.

**Example DSL output:**

```markdown
## Custom Mitre Mapping
- **Kerberoasting**: {"tactics": ["Credential Access"], "techniques": [{"id": "T1558.003", "name": "Steal or Forge Kerberos Tickets: Kerberoasting"}]}
- **Pass-the-Hash**: {"tactics": ["Lateral Movement"], "techniques": [{"id": "T1550.002", "name": "Use Alternate Authentication Material: Pass the Hash"}]}
- **Golden Ticket**: {"tactics": ["Persistence", "Privilege Escalation"], "techniques": [{"id": "T1558.001", "name": "Steal or Forge Kerberos Tickets: Golden Ticket"}]}
```

You can look up ATT&CK technique IDs at [attack.mitre.org](https://attack.mitre.org) or browse
the ATT&CK Navigator export generated by SecOpsTM.

---

## Delivery Format

The easiest way to hand off collected information is a partially-filled `model.md` file using
the template below. Alternatively, fill in the questionnaire above and the threat modeler will
build the DSL file.

**Minimal viable model template to fill in:**

```markdown
# Threat Model: [SYSTEM NAME]

## Description
[2–5 sentences describing the system, its purpose, user count, deployment, compliance scope]

## Context
gdaf_context = context/context.yaml
bom_directory = BOM

## Boundaries
- **[ZONE 1 NAME]**: isTrusted=[True/False], type=[network-on-prem/execution-environment], traversal_difficulty=[low/medium/high]
- **[ZONE 2 NAME]**: isTrusted=[True/False], type=[...], traversal_difficulty=[...]
[add more zones]

## Actors
- **[ACTOR NAME]**: boundary=[ZONE], authenticity=[none/credentials/two-factor], isTrusted=[True/False]
[add more actors, include an "External Attacker" in an untrusted zone for GDAF]

## Servers
- **[SERVER NAME]**:
  boundary=[ZONE],
  type=[see list above],
  confidentiality=[low/medium/high/critical],
  integrity=[low/medium/high/critical],
  availability=[low/medium/high/critical],
  internet_facing=[True/False],
  credentials_stored=[True/False],
  mfa_enabled=[True/False]
[add all servers]

## Data
- **[DATA NAME]**: description="[what is it]", classification=[PUBLIC/RESTRICTED/SECRET/TOP_SECRET]
[add sensitive data types]

## Dataflows
- **[FLOW NAME]**: from=[SOURCE], to=[DESTINATION], protocol=[PROTOCOL], is_encrypted=[True/False], is_authenticated=[True/False]
[add all communication flows]
```

**Checklist before delivery:**

- [ ] All network zones / segments listed with trust level and difficulty
- [ ] All user roles and external systems listed as actors, placed in correct zones
- [ ] All servers listed with asset type, CIA ratings, and zone
- [ ] Internet-facing servers marked `internet_facing=True`
- [ ] Servers storing credentials marked `credentials_stored=True`
- [ ] Servers without MFA explicitly marked `mfa_enabled=False`
- [ ] All communication channels listed as dataflows with protocol and encryption status
- [ ] Sensitive data types listed in `## Data` with classification
- [ ] Data objects referenced in dataflows where relevant
- [ ] One `External Attacker` actor placed in an untrusted boundary (for GDAF entry points)
- [ ] BOM YAML files created for at least the 5–10 most critical assets
- [ ] GDAF context YAML created with at least one attack objective and one threat actor

---

## Worked Example

A small e-commerce application with a public API, an internal database, and an admin panel.

**Architecture description:**
- Public API (Node.js) in the DMZ, internet-facing
- PostgreSQL database in an internal zone, not internet-facing
- Admin panel in an internal zone, accessible only to IT staff via VPN
- External customers access the API over HTTPS
- An attacker on the internet is in scope

**Resulting model.md:**

```markdown
# Threat Model: E-Commerce Platform

## Description
Customer-facing e-commerce API built on Node.js and PostgreSQL. Approximately 50,000 customers
access the platform daily via HTTPS. The admin panel is accessible only to 5 IT staff members
via VPN. Compliance: GDPR, PCI-DSS.

## Context
gdaf_context = context/context.yaml
bom_directory = BOM

## Boundaries
- **Internet**: isTrusted=False, type=network-on-prem, color=red, traversal_difficulty=low
- **DMZ**: isTrusted=False, type=network-on-prem, color=orange, traversal_difficulty=low
- **Internal Zone**: isTrusted=True, type=execution-environment, color=lightblue, traversal_difficulty=medium

## Actors
- **External Attacker**: boundary=Internet, authenticity=none, isTrusted=False
- **Customer**: boundary=Internet, authenticity=credentials, isTrusted=False
- **IT Staff**: boundary="Internal Zone", authenticity=two-factor, isTrusted=True

## Servers
- **Public API**:
  boundary=DMZ,
  type=web-server,
  machine=container,
  internet_facing=True,
  confidentiality=medium,
  integrity=high,
  availability=critical,
  tags=[nodejs, express]
- **PostgreSQL Database**:
  boundary="Internal Zone",
  type=database,
  machine=virtual,
  confidentiality=critical,
  integrity=critical,
  availability=high,
  credentials_stored=True,
  tags=[postgresql-15]
- **Admin Panel**:
  boundary="Internal Zone",
  type=management-server,
  machine=virtual,
  mfa_enabled=True,
  confidentiality=high,
  integrity=high,
  availability=medium,
  tags=[nginx, admin]

## Data
- **Customer PII**: description="Customer name, email, address", classification=SECRET
- **Payment Card Data**: description="Card numbers — PCI scope", classification=TOP_SECRET
- **Admin Credentials**: description="Admin panel access credentials", classification=SECRET

## Dataflows
- **CustomerToAPI**: from=Customer, to="Public API", protocol=HTTPS, is_encrypted=True, is_authenticated=True
- **AttackerToAPI**: from="External Attacker", to="Public API", protocol=HTTPS, is_encrypted=True, is_authenticated=False
- **APIToDatabase**:
  from="Public API",
  to="PostgreSQL Database",
  protocol=SQL,
  is_encrypted=False,
  is_authenticated=True,
  data="Customer PII"
- **ITToAdmin**: from="IT Staff", to="Admin Panel", protocol=HTTPS, is_encrypted=True, is_authenticated=True, authentication=two-factor
- **AdminToDatabase**: from="Admin Panel", to="PostgreSQL Database", protocol=SQL, is_encrypted=True, is_authenticated=True, data="Admin Credentials"

## Severity Multipliers
- **PostgreSQL Database**: 2.5
- **Admin Panel**: 1.5
```

This compact model will produce:

- STRIDE threat report covering spoofing (unauthenticated API access), tampering (SQL injection),
  information disclosure (unencrypted API-to-DB channel), DoS, and elevation of privilege
- MITRE ATT&CK technique mapping for each threat category
- GDAF attack scenarios from the External Attacker to the PostgreSQL Database
- ATT&CK Navigator export and STIX 2.1 bundle
