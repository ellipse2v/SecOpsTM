# Threat Model: Traditional Enterprise Network

## Description
Traditional enterprise with Active Directory, DMZ, file servers, and application servers.

## Context
gdaf_context = context/enterprise_network_context.yaml
bom_directory = BOM

## Boundaries
- **Internal Network**: isTrusted=True, color=green
- **DMZ (Demilitarized Zone)**: isTrusted=False, color=orange
- **Internet**: isTrusted=False, color=red

## Actors
- **Employee**: boundary="Internal Network"
- **System Administrator**: boundary="Internal Network"
- **External Attacker**: boundary="Internet"

## Servers
- **DomainController**: boundary="Internal Network", type="domain_controller"
- **File Server**: boundary="Internal Network", type="file_server"
- **Application Server**: boundary="Internal Network", type="app_server"
- **DMZWebServer**: boundary="DMZ (Demilitarized Zone)", type="web_server"
- **Firewall**: type="firewall"

## Dataflows
- **User Authentication**: from="Employee", to="DomainController", protocol="Kerberos/LDAP"
- **File Access**: from="Employee", to="File Server", protocol="SMB"
- **Internal App Access**: from="Employee", to="Application Server", protocol="HTTPS"
- **External Web Request**: from="External Attacker", to="Firewall", protocol="HTTPS"
- **Internal Web Request**: from="Firewall", to="DMZWebServer", protocol="HTTPS"
- **AD Replication**: from="DomainController", to="DomainController", protocol="RPC/LDAP"
- **Admin Management**: from="System Administrator", to="DomainController", protocol="RPC/SMB"

## Protocol Styles
- **Kerberos/LDAP**: color=purple, line_style=solid
- **SMB**: color=blue, line_style=dashed
- **HTTPS**: color=darkgreen, line_style=solid
- **RPC/LDAP**: color=gray, line_style=dashed
- **RPC/SMB**: color=gray, line_style=dashed

## Severity Multipliers
- **DomainController**: 3.0
- **Application Server**: 1.8
- **File Server**: 1.5
- **DMZWebServer**: 1.6
