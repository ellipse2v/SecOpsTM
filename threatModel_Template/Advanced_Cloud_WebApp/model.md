<!--
Copyright 2024 ellipse2v — Apache License, Version 2.0
https://www.apache.org/licenses/LICENSE-2.0
-->

# Threat Model: Advanced Cloud Web Application

## Description
Advanced cloud web app with CDN, API gateway, auth service, product microservice, and managed database.

## Context
gdaf_context = context/advanced_cloud_context.yaml
bom_directory = BOM

## Boundaries
- **Public Cloud Zone**: type=network-cloud-provider, isTrusted=False
- **Private App Zone**: type=network-cloud-security-group, isTrusted=True
- **Secure Data Zone**: type=network-cloud-security-group, isTrusted=True

## Actors
- **End User**: boundary="Public Cloud Zone", authenticity=credentials, isTrusted=False
- **DevOps Engineer**: boundary="Public Cloud Zone", authenticity=two-factor, isTrusted=True

## Servers
- **CDN Load Balancer**: boundary="Public Cloud Zone", type=load-balancer, health_check_enabled=True
- **API Gateway**: boundary="Public Cloud Zone", type=api-gateway, machine=serverless, redundant=True
- **Auth Service**: boundary="Private App Zone", type=auth-server, machine=container, auth_protocol=oidc, mfa_enabled=True
- **Product Microservice**: boundary="Private App Zone", machine=container, redundant=True
- **Product Database**: boundary="Secure Data Zone", type=database, machine=virtual, database_type=sql, encryption=data-with-symmetric-shared-key, backup_frequency=daily, redundant=True
- **CI/CD Server**: boundary="Private App Zone", type=management-server, machine=virtual

## Dataflows
- **UserToGateway**: from="End User", to="API Gateway", protocol=HTTPS, authentication=token, is_encrypted=True
- **GatewayToAuth**: from="API Gateway", to="Auth Service", protocol=HTTPS, authentication=token, is_encrypted=True
- **GatewayToProductSvc**: from="API Gateway", to="Product Microservice", protocol=HTTPS, authentication=token, is_encrypted=True
- **ProductSvcToDB**: from="Product Microservice", to="Product Database", protocol=TCP, authentication=credentials, is_encrypted=False
- **DevOpsToCICD**: from="DevOps Engineer", to="CI/CD Server", protocol=SSH, authentication=two-factor, vpn=True, ip_filtered=True, is_encrypted=True
- **CICDToProductSvc**: from="CI/CD Server", to="Product Microservice", protocol=SSH, authentication=credentials, is_encrypted=True

## Protocol Styles
- **HTTPS**: color=darkgreen, line_style=solid
- **TCP**: color=red, line_style=dashed
- **SSH**: color=blue, line_style=dashed

## Severity Multipliers
- **Product Database**: 2.0
- **Auth Service**: 2.5
- **Product Microservice**: 1.8
- **CI/CD Server**: 1.7
