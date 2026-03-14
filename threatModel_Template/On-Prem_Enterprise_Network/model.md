# Threat Model: On-Prem Enterprise Network

## Description
This model describes a complex on-premises enterprise network for a large multinational manufacturing organization. It covers 9 security zones ranging from an untrusted internet perimeter to a highly restricted OT/SCADA environment. The architecture includes Active Directory infrastructure, a financial ERP system, a CI/CD development pipeline, and legacy industrial control systems. This model highlights threats related to lateral movement, credential theft, legacy protocols, and OT network security.

## Context
- gdaf_context = context/enterprise_onprem_context.yaml
- bom_directory = BOM
- gdaf_min_technique_score = 0.75

## Boundaries
- **Internet**:
  type=network-on-prem,
  isTrusted=False,
  color=red,
  traversal_difficulty=low
- **DMZ**:
  type=network-on-prem,
  isTrusted=False,
  color=orange,
  traversal_difficulty=low
- **VPN Perimeter**:
  type=network-on-prem,
  isTrusted=False,
  color=orangered,
  traversal_difficulty=low
- **Internal Network**:
  type=network-on-prem,
  isTrusted=True,
  color=lightgreen,
  traversal_difficulty=low
- **IT Infrastructure Zone**:
  type=execution-environment,
  isTrusted=True,
  color=lightblue,
  traversal_difficulty=medium
- **Finance Zone**:
  type=execution-environment,
  isTrusted=True,
  color=lightyellow,
  traversal_difficulty=high
- **Development Zone**:
  type=execution-environment,
  isTrusted=True,
  color=lightcyan,
  traversal_difficulty=medium
- **Restricted Data Zone**:
  type=execution-environment,
  isTrusted=True,
  color=lavender,
  traversal_difficulty=high
- **OT SCADA Zone**:
  type=execution-environment,
  isTrusted=True,
  color=mistyrose,
  traversal_difficulty=high

## Actors
- **External Attacker**:
  boundary=Internet,
  authenticity=none,
  isTrusted=False
- **Remote Employee**:
  boundary=Internet,
  authenticity=two-factor,
  isTrusted=False
- **Corporate Employee**:
  boundary="Internal Network",
  authenticity=credentials,
  isTrusted=True
- **Finance Employee**:
  boundary="Finance Zone",
  authenticity=credentials,
  isTrusted=True
- **IT Administrator**:
  boundary="IT Infrastructure Zone",
  authenticity=two-factor,
  isTrusted=True
- **Developer**:
  boundary="Development Zone",
  authenticity=two-factor,
  isTrusted=True
- **SCADA Operator**:
  boundary="OT SCADA Zone",
  authenticity=credentials,
  isTrusted=True

## Servers
- **Edge Router**:
  boundary=DMZ,
  type=firewall,
  machine=physical,
  ids=True,
  ips=True,
  internet_facing=True,
  confidentiality=high,
  integrity=high,
  availability=critical,
  tags=[cisco-ios, edge, perimeter]
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
- **Reverse Proxy**:
  boundary=DMZ,
  type=web-server,
  machine=virtual,
  internet_facing=True,
  confidentiality=low,
  integrity=medium,
  availability=high,
  tags=[nginx, proxy]
- **Mail Gateway**:
  boundary=DMZ,
  type=mail-server,
  machine=virtual,
  internet_facing=True,
  confidentiality=medium,
  integrity=medium,
  availability=high,
  tags=[postfix, smtp]
- **Corporate VPN Gateway**:
  boundary="VPN Perimeter",
  type=vpn-gateway,
  machine=physical,
  internet_facing=True,
  confidentiality=high,
  integrity=critical,
  availability=critical,
  tags=[cisco-asa, ipsec]
- **Internal Firewall**:
  boundary="Internal Network",
  type=firewall,
  machine=physical,
  ids=True,
  ips=True,
  confidentiality=high,
  integrity=high,
  availability=critical,
  tags=[fortinet]
- **Internal DNS Server**:
  boundary="Internal Network",
  type=dns,
  machine=virtual,
  confidentiality=medium,
  integrity=high,
  availability=high,
  tags=[windows, dns]
- **Employee Workstation**:
  boundary="Internal Network",
  type=workstation,
  machine=virtual,
  confidentiality=medium,
  integrity=medium,
  availability=medium,
  encryption=none,
  tags=[windows-10, endpoint]
- **File Server**:
  boundary="Internal Network",
  type=file-server,
  machine=virtual,
  confidentiality=high,
  integrity=high,
  availability=high,
  tags=[windows, smb]
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
  tags=[windows-server-2019, active-directory]
- **Backup Domain Controller**:
  boundary="IT Infrastructure Zone",
  type=domain-controller,
  machine=virtual,
  auth_protocol=kerberos,
  mfa_enabled=False,
  credentials_stored=True,
  confidentiality=critical,
  integrity=critical,
  availability=high,
  tags=[windows-server-2019, active-directory]
- **PKI Certificate Authority**:
  boundary="IT Infrastructure Zone",
  type=pki,
  machine=virtual,
  credentials_stored=True,
  confidentiality=critical,
  integrity=critical,
  availability=high,
  tags=[windows, pki, ca]
- **SIEM Server**:
  boundary="IT Infrastructure Zone",
  type=siem,
  machine=virtual,
  confidentiality=high,
  integrity=critical,
  availability=high,
  tags=[linux, elastic-stack, siem]
- **Jump Server**:
  boundary="IT Infrastructure Zone",
  type=management-server,
  machine=virtual,
  mfa_enabled=True,
  confidentiality=high,
  integrity=high,
  availability=high,
  tags=[windows, rdp, bastion]
- **Financial ERP System**:
  boundary="Finance Zone",
  type=database,
  machine=physical,
  encryption=none,
  mfa_enabled=False,
  credentials_stored=True,
  confidentiality=critical,
  integrity=critical,
  availability=critical,
  tags=[sap, erp, mainframe]
- **Finance Workstation**:
  boundary="Finance Zone",
  type=workstation,
  machine=virtual,
  confidentiality=high,
  integrity=medium,
  availability=medium,
  tags=[windows-10, endpoint]
- **Source Code Repository**:
  boundary="Development Zone",
  type=repository,
  machine=virtual,
  confidentiality=high,
  integrity=critical,
  availability=high,
  tags=[linux, gitlab, git]
- **CI CD Pipeline**:
  boundary="Development Zone",
  type=cicd,
  machine=virtual,
  confidentiality=medium,
  integrity=critical,
  availability=high,
  tags=[linux, jenkins, cicd]
- **Core Database Cluster**:
  boundary="Restricted Data Zone",
  type=database,
  machine=physical,
  credentials_stored=True,
  confidentiality=critical,
  integrity=critical,
  availability=critical,
  tags=[sql-server-2019, windows, cluster]
- **Backup Server**:
  boundary="Restricted Data Zone",
  type=backup,
  machine=virtual,
  confidentiality=critical,
  integrity=high,
  availability=high,
  tags=[linux, veeam, backup]
- **SCADA HMI**:
  boundary="OT SCADA Zone",
  type=scada,
  machine=physical,
  mfa_enabled=False,
  encryption=none,
  confidentiality=critical,
  integrity=critical,
  availability=critical,
  tags=[windows-7, legacy, hmi, scada]
- **PLC Controller**:
  boundary="OT SCADA Zone",
  type=plc,
  machine=physical,
  confidentiality=medium,
  integrity=critical,
  availability=critical,
  tags=[siemens, plc, ot, modbus]

## Data
- **Web Request**:
  description="HTTP/S requests from the internet",
  classification=PUBLIC
- **VPN Auth Token**:
  description="IPSec VPN authentication credentials",
  classification=SECRET
- **Kerberos Ticket**:
  description="Active Directory Kerberos authentication ticket",
  classification=SECRET
- **Employee PII**:
  description="Employee personal identifiable information",
  classification=SECRET
- **Financial Record**:
  description="Highly sensitive financial records and transactions",
  classification=TOP_SECRET
- **Source Code**:
  description="Proprietary source code and deployment artifacts",
  classification=RESTRICTED
- **SCADA Command**:
  description="Operational control commands for industrial systems",
  classification=SECRET
- **Database Backup**:
  description="Full database backup containing all sensitive records",
  classification=TOP_SECRET
- **Email Message**:
  description="Corporate email including potentially sensitive attachments",
  classification=RESTRICTED
- **Admin Credentials**:
  description="Privileged administrative credentials for domain and servers",
  classification=TOP_SECRET

## Dataflows
- **ExternalToRouter**:
  from="External Attacker",
  to="Edge Router",
  protocol=TCP,
  authentication=none,
  is_encrypted=False
- **RemoteToVPN**:
  from="Remote Employee",
  to="Corporate VPN Gateway",
  protocol=IPSEC,
  authentication=two-factor,
  is_encrypted=True,
  vpn=True
- **ExternalToMail**:
  from="External Attacker",
  to="Mail Gateway",
  protocol=SMTP,
  authentication=none,
  is_encrypted=False
- **RouterToWAF**:
  from="Edge Router",
  to="Web Application Firewall",
  protocol=HTTP,
  authentication=none,
  is_encrypted=False
- **WAFToProxy**:
  from="Web Application Firewall",
  to="Reverse Proxy",
  protocol=HTTP,
  authentication=none,
  is_encrypted=False
- **ProxyToInternalFW**:
  from="Reverse Proxy",
  to="Internal Firewall",
  protocol=HTTP,
  authentication=none,
  is_encrypted=False
- **MailToWorkstation**:
  from="Mail Gateway",
  to="Employee Workstation",
  protocol=SMTP,
  authentication=none,
  is_encrypted=False
- **VPNToInternalFW**:
  from="Corporate VPN Gateway",
  to="Internal Firewall",
  protocol=IPSEC,
  is_encrypted=True
- **InternalFWToWorkstation**:
  from="Internal Firewall",
  to="Employee Workstation",
  protocol=TCP,
  authentication=none,
  is_encrypted=False
- **EmployeeToWorkstation**:
  from="Corporate Employee",
  to="Employee Workstation",
  protocol=RDP,
  authentication=credentials,
  is_encrypted=False
- **WorkstationToAD**:
  from="Employee Workstation",
  to="Primary Domain Controller",
  protocol=LDAP,
  authentication=credentials,
  is_encrypted=False
- **WorkstationToFile**:
  from="Employee Workstation",
  to="File Server",
  protocol=SMB,
  authentication=credentials,
  is_encrypted=False
- **WorkstationToSIEM**:
  from="Employee Workstation",
  to="SIEM Server",
  protocol=SYSLOG,
  authentication=none,
  is_encrypted=False
- **ADToBackupAD**:
  from="Primary Domain Controller",
  to="Backup Domain Controller",
  protocol=RPC,
  authentication=credentials,
  is_encrypted=False
- **ADToPKI**:
  from="Primary Domain Controller",
  to="PKI Certificate Authority",
  protocol=RPC,
  authentication=credentials,
  is_encrypted=True
- **SIEMToAD**:
  from="SIEM Server",
  to="Primary Domain Controller",
  protocol=LDAP,
  authentication=credentials,
  is_encrypted=False
- **ITAdminToJump**:
  from="IT Administrator",
  to="Jump Server",
  protocol=RDP,
  authentication=two-factor,
  is_encrypted=True
- **JumpToAD**:
  from="Jump Server",
  to="Primary Domain Controller",
  protocol=WinRM,
  authentication=credentials,
  is_encrypted=True
- **ADToJump**:
  from="Primary Domain Controller",
  to="Jump Server",
  protocol=WinRM,
  data="Admin Credentials",
  authentication=credentials,
  is_encrypted=True
  // Lateral movement vector: attacker with DC admin (DCSync/Golden Ticket) can push
  // GPO/scripts to jump server or reuse domain admin credentials via WinRM
- **JumpToSCADA**:
  from="Jump Server",
  to="SCADA HMI",
  protocol=RDP,
  authentication=credentials,
  is_encrypted=False
- **JumpToERP**:
  from="Jump Server",
  to="Financial ERP System",
  protocol=SAP,
  authentication=credentials,
  is_encrypted=False
- **FinanceEmpToERP**:
  from="Finance Employee",
  to="Financial ERP System",
  protocol=TCP,
  authentication=credentials,
  is_encrypted=False
- **ERPToCoreDB**:
  from="Financial ERP System",
  to="Core Database Cluster",
  protocol=SQL,
  authentication=credentials,
  is_encrypted=False
- **DevToGitLab**:
  from="Developer",
  to="Source Code Repository",
  protocol=SSH,
  authentication=two-factor,
  is_encrypted=True
- **DevToCICD**:
  from="Developer",
  to="CI CD Pipeline",
  protocol=HTTPS,
  authentication=credentials,
  is_encrypted=True
- **GitLabToCICD**:
  from="Source Code Repository",
  to="CI CD Pipeline",
  protocol=HTTPS,
  authentication=token,
  is_encrypted=True
- **CICDToCoreDB**:
  from="CI CD Pipeline",
  to="Core Database Cluster",
  protocol=SQL,
  authentication=credentials,
  is_encrypted=False
- **CoreDBToBackup**:
  from="Core Database Cluster",
  to="Backup Server",
  protocol=TCP,
  authentication=credentials,
  is_encrypted=False
- **SCADAOpToHMI**:
  from="SCADA Operator",
  to="SCADA HMI",
  protocol=RDP,
  authentication=credentials,
  is_encrypted=False
- **HMIToPLC**:
  from="SCADA HMI",
  to="PLC Controller",
  protocol=Modbus,
  authentication=none,
  is_encrypted=False
- **InternalDNSToAD**:
  from="Internal DNS Server",
  to="Primary Domain Controller",
  protocol=DNS,
  authentication=none,
  is_encrypted=False

## Protocol Styles
- **HTTPS**: color=darkgreen, line_style=solid
- **HTTP**: color=red, line_style=solid
- **SSH**: color=blue, line_style=dashed
- **LDAP**: color=purple, line_style=solid
- **Kerberos**: color=teal
- **SMB**: color=orange
- **RDP**: color=steelblue, line_style=dashed
- **SQL**: color=purple
- **SMTP**: color=gray
- **IPSEC**: color=darkblue, line_style=dashed
- **Modbus**: color=crimson, line_style=solid
- **WinRM**: color=steelblue
- **RPC**: color=darkorange
- **SYSLOG**: color=gray, line_style=dotted
- **TCP**: color=gray
- **DNS**: color=teal
- **SAP**: color=orange

## Severity Multipliers
- **Primary Domain Controller**: 3.0
- **Financial ERP System**: 2.5
- **Core Database Cluster**: 2.5
- **SCADA HMI**: 2.0
- **PLC Controller**: 2.0
- **PKI Certificate Authority**: 2.0

## Custom Mitre Mapping
- **Pass-the-Hash**: {"tactics": ["Lateral Movement"], "techniques": [{"id": "T1550.002", "name": "Use Alternate Authentication Material: Pass the Hash"}]}
- **Kerberoasting**: {"tactics": ["Credential Access"], "techniques": [{"id": "T1558.003", "name": "Steal or Forge Kerberos Tickets: Kerberoasting"}]}
- **DCSync**: {"tactics": ["Credential Access"], "techniques": [{"id": "T1003.006", "name": "OS Credential Dumping: DCSync"}]}
- **Golden Ticket**: {"tactics": ["Persistence", "Privilege Escalation"], "techniques": [{"id": "T1558.001", "name": "Steal or Forge Kerberos Tickets: Golden Ticket"}]}
- **LSASS Memory Dump**: {"tactics": ["Credential Access"], "techniques": [{"id": "T1003.001", "name": "OS Credential Dumping: LSASS Memory"}]}
- **NTLM Relay**: {"tactics": ["Credential Access", "Lateral Movement"], "techniques": [{"id": "T1557.001", "name": "Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay"}]}
- **Modbus Command Injection**: {"tactics": ["Impact"], "techniques": [{"id": "T1565.001", "name": "Data Manipulation: Stored Data Manipulation"}]}
