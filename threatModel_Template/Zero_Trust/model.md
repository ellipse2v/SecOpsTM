<!--
Copyright 2024 ellipse2v — Apache License, Version 2.0
https://www.apache.org/licenses/LICENSE-2.0
-->

# Threat Model: Zero Trust Architecture

## Description
This threat model describes a zero trust network architecture with identity-based access control.

## Context
gdaf_context = context/zero_trust_context.yaml
bom_directory = BOM

## Boundaries
- **Untrusted Network**: isTrusted=False, color=red
- **Trusted Network**: isTrusted=True, color=green
- **Identity Provider (IdP)**: isTrusted=True, color=purple
- **Policy Enforcement Point (PEP)**: isTrusted=True, color=blue
- **Workload**: isTrusted=True, color=lightblue

## Actors
- **User**: boundary="Untrusted Network"
- **Administrator**: boundary="Trusted Network"

## Servers
- **Authentication Service**: boundary="Identity Provider (IdP)", type="authentication_service"
- **Authorization Service**: boundary="Identity Provider (IdP)", type="authorization_service"
- **Policy Engine**: boundary="Policy Enforcement Point (PEP)", type="policy_engine"
- **Microservice A**: boundary="Workload", type="microservice"
- **Microservice B**: boundary="Workload", type="microservice"

## Dataflows
- **Auth Request**: from="User", to="Authentication Service", protocol="HTTPS"
- **Auth Response**: from="Authentication Service", to="User", protocol="HTTPS"
- **Access Request**: from="User", to="Policy Engine", protocol="HTTPS"
- **Policy Eval**: from="Policy Engine", to="Authorization Service", protocol="Internal API"
- **Authz Decision**: from="Authorization Service", to="Policy Engine", protocol="Internal API"
- **Authorized Access**: from="Policy Engine", to="Microservice A", protocol="Encrypted TLS"
- **Inter-service**: from="Microservice A", to="Microservice B", protocol="Encrypted TLS"
- **Admin Management**: from="Administrator", to="Policy Engine", protocol="HTTPS"

## Protocol Styles
- **HTTPS**: color=darkgreen, line_style=solid
- **Encrypted TLS**: color=blue, line_style=solid
- **Internal API**: color=gray, line_style=dashed

## Severity Multipliers
- **Authentication Service**: 2.5
- **Policy Engine**: 2.0
- **Authorization Service**: 2.0
