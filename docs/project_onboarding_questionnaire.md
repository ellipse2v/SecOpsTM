# SecOpsTM — Project Onboarding Questionnaire

**How to use this form:** Fill in one section per system you want to threat-model.
Send the completed form to your security team. They will use it to build the SecOpsTM
DSL model file. For full parameter details, see `docs/defining_threat_models.md`.

A completed example for an e-commerce platform is available at:
`threatModel_Template/projects/example_3/`

---

## Section 1 — System Overview

| Question | Your Answer |
|---|---|
| **System name** | |
| **One-sentence description** | |
| **Business function** (what does it do for users?) | |
| **Deployment environment** | Cloud / On-Premises / Hybrid |
| **Number of end users (approx.)** | |
| **Peak concurrent users** | |
| **Sector / industry** | |
| **Compliance requirements** | PCI-DSS / GDPR / HIPAA / SOX / ISO 27001 / Other |
| **Is the system internet-facing?** | Yes / No |
| **Key third-party integrations** (payment, email, IdP, etc.) | |

---

## Section 2 — Security Zones (Boundaries)

List each network segment or logical zone. For each zone, answer:

| Zone Name | Trusted? (Y/N) | Zone Type | How hard to cross? | Description |
|---|---|---|---|---|
| e.g. Internet | No | Network segment | Easy | All external users |
| e.g. DMZ | No | Network segment | Easy | Firewalls, API gateway |
| e.g. App Zone | Yes | Execution env. | Medium | Internal microservices |
| e.g. DB Zone | Yes | Execution env. | Hard | Database servers only |
| | | | | |
| | | | | |

**Zone Type options:** Network segment (on-prem) / Cloud VPC/VNet / Cloud security group / Execution environment / Container namespace

**"How hard to cross?" options:**
- **Easy (low):** Few controls, open segment
- **Medium:** Firewall + VLAN, standard internal network
- **Hard (high):** Micro-segmented, strict whitelist, dedicated hardware

---

## Section 3 — Users and External Systems (Actors)

List every type of user or external system that interacts with your system:

| Actor Name | In which zone? | How do they authenticate? | Trusted? |
|---|---|---|---|
| e.g. Customer | Internet | Username + password | No |
| e.g. Admin | Internal | Password + MFA token | Yes |
| e.g. Payment Gateway | Internet | Client TLS certificate | No |
| e.g. External Attacker | Internet | None | No |
| | | | |
| | | | |

**Authentication options:** None / Password / Password + MFA / Client certificate / External SSO (SAML/OIDC)

---

## Section 4 — Components and Servers

List every significant component (APIs, databases, firewalls, load balancers, queues, CI/CD, etc.):

| Component Name | Zone | Type | Internet-facing? | Confidentiality | Integrity | Availability |
|---|---|---|---|---|---|---|
| e.g. WebServer | DMZ | Web server | Yes | Low | High | Critical |
| e.g. AuthService | App Zone | App server | No | Critical | Critical | Critical |
| e.g. PaymentDB | DB Zone | Database | No | Critical | Critical | High |
| | | | | | | |

**Type options:** Web server / App server / Database / Firewall / Load balancer / Message queue / API gateway / Switch / Domain controller / Other (describe)

**Confidentiality / Integrity / Availability:** Low / Medium / High / Critical

For each component, also answer (Y/N):

| Component Name | MFA enabled? | WAF? | IDS? | Credentials stored? | Redundant? |
|---|---|---|---|---|---|
| | | | | | |
| | | | | | |

---

## Section 5 — Communication Flows (Dataflows)

List every connection between components:

| Flow Name | From | To | Protocol | Port | Authenticated? | Encrypted? |
|---|---|---|---|---|---|---|
| e.g. UserLogin | Customer | WebServer | HTTPS | 443 | Yes (credentials) | Yes (TLS) |
| e.g. APIToDatabase | WebAPI | PostgreSQL | TCP | 5432 | Yes (password) | Yes (TLS) |
| e.g. LegacySync | LegacyApp | CoreDB | HTTP | 80 | No | No |
| | | | | | | |
| | | | | | | |

**Protocol examples:** HTTP, HTTPS, gRPC, TCP, UDP, SSH, LDAP, Kerberos, AMQP, SMTP, SFTP, NFS, RDP

**Authentication options:** None / Username+password / MFA / Client certificate

**Is the flow bidirectional?** (client also receives responses that carry sensitive data) — mark if yes

---

## Section 6 — Sensitive Data Assets

List the data types your system stores or processes:

| Data Name | Sensitivity | Where is it stored? | PII? | Regulatory scope | Encrypted at rest? | Encrypted in transit? |
|---|---|---|---|---|---|---|
| e.g. Customer Record | Secret | UserDB, BackupDB | Yes | GDPR | Yes | Yes |
| e.g. Payment Token | Secret | PaymentDB | No | PCI-DSS | Yes | Yes |
| e.g. Audit Logs | Restricted | LoggingServer | No | SOX | No | Yes |
| | | | | | | |

**Sensitivity levels:** Public / Restricted / Confidential / Secret / Top Secret

---

## Section 7 — Asset Inventory (for BOM enrichment)

For each component listed in Section 4, provide:

| Component | OS / Platform | Software + Version | Patch Status | Known CVEs | Detection Level |
|---|---|---|---|---|---|
| e.g. WebServer | Ubuntu 22.04 | nginx 1.24.0 | Current | CVE-2023-44487 | High |
| e.g. AuthService | Ubuntu 22.04 | Keycloak 22.0.5 | Outdated | CVE-2023-6134 | Medium |
| e.g. PrimaryDB | Ubuntu 22.04 | PostgreSQL 15.4 | Current | — | High |
| | | | | | |

**Patch status:** Current / Outdated / Critical (actively exploited CVE unpatched)
**Detection level:** Low (no monitoring) / Medium (logs only) / High (EDR + SIEM alerts)

Also note for each component:
- Running services / daemons (e.g., LDAP, SSH, RDP, WinRM)
- Are credentials or API keys stored on this host? (Y/N)
- Any known security notes (unpatched known issue, missing control, exception)

---

## Section 8 — Attack Scenarios (for GDAF Analysis)

What is an attacker most likely to target? List the 2-5 most critical attack objectives:

| Objective | What the attacker wants | Which components are targeted? | Business impact if achieved |
|---|---|---|---|
| e.g. Payment card theft | Steal card data or tokens | PaymentService, PaymentDB | PCI-DSS fine, card fraud liability |
| e.g. Account takeover | Compromise customer accounts | AuthService, WebAPI | Customer trust, chargebacks |
| e.g. Ransomware | Encrypt all data for ransom | All databases | Full business disruption |
| | | | |

For each objective, also describe the most likely attacker type:

| Attacker Type | Sophistication | Entry method | Known tactics |
|---|---|---|---|
| e.g. Cybercriminal | Medium | Phishing / exploiting public app | Credential theft, lateral movement |
| e.g. Nation-state APT | High | Supply chain / zero-day | All tactics |
| e.g. Insider | Low | Legitimate access | Data exfiltration |
| | | | |

---

## Section 9 — Existing Security Controls

Check all controls currently in place:

**Network controls:**
- [ ] Perimeter firewall
- [ ] WAF (Web Application Firewall)
- [ ] IDS/IPS
- [ ] Network segmentation (VLANs, micro-segmentation)
- [ ] VPN for remote access
- [ ] DDoS protection (CDN, scrubbing)

**Identity and access:**
- [ ] MFA enforced for admins
- [ ] MFA enforced for all users
- [ ] Privileged access management (PAM)
- [ ] Role-based access control (RBAC)
- [ ] Certificate-based authentication for services

**Data protection:**
- [ ] Encryption at rest (specify which databases/volumes)
- [ ] Encryption in transit (TLS everywhere, or list exceptions)
- [ ] Data Loss Prevention (DLP)
- [ ] Secrets management (Vault, AWS Secrets Manager, etc.)

**Detection and response:**
- [ ] SIEM
- [ ] EDR on servers
- [ ] Log aggregation (centralized logging)
- [ ] Alerting on authentication failures
- [ ] Incident response plan

**Development security:**
- [ ] SAST / DAST in CI/CD
- [ ] SCA (dependency vulnerability scanning)
- [ ] Container image scanning
- [ ] Secrets scanning in git

---

## Section 10 — Sub-model Drill-down (for multi-model projects)

If your architecture has subsystems that merit their own detailed models:

| Parent component | Sub-model name | What it contains |
|---|---|---|
| e.g. BackendServices | backend/model.md | Auth, Order, DB services |
| e.g. OrderService | order_service/model.md | Queue, payment, shipping microservices |
| | | |

Each sub-model will appear as a clickable drill-down link in the parent diagram.

---

## Handoff Checklist

Before handing this to the security team, confirm:

- [ ] All significant components listed (nothing missing from the architecture)
- [ ] All data flows listed (including internal service-to-service calls)
- [ ] All sensitive data assets identified with classification
- [ ] Patch status and CVEs checked with the operations team
- [ ] Attack objectives approved by business/risk owner
- [ ] Compliance requirements confirmed with legal/compliance team

---

*SecOpsTM — Threat Model as Code. For questions, see `docs/getting_started.md` or open an issue.*
