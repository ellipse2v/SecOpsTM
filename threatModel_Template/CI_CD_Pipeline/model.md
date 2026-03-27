<!--
Copyright 2024 ellipse2v — Apache License, Version 2.0
https://www.apache.org/licenses/LICENSE-2.0
-->

# Threat Model: CI/CD Pipeline (Continuous Integration and Deployment)

## Description
This threat model focuses on a CI/CD pipeline, covering the development, integration, testing, and deployment stages.

## Context
gdaf_context = context/cicd_context.yaml
bom_directory = BOM

## Boundaries
- **Development Environment**: color=lightblue, isTrusted=True
- **Code Repository**: color=gray, isTrusted=True
- **Build Server**: color=orange, isTrusted=True
- **Artifact Registry**: color=purple, isTrusted=True
- **Production Environment**: color=green, isTrusted=False

## Actors
- **Developer**: boundary="Development Environment"
- **CI/CD System**: boundary="Build Server"

## Servers
- **Git Repository**: boundary="Code Repository", type="git_repo"
- **CIServer**: boundary="Build Server", type="ci_cd_server"
- **ArtifactRegistry**: boundary="Artifact Registry", type="docker_registry"
- **KubeCluster**: boundary="Production Environment", type="kubernetes_cluster"

## Dataflows
- **Push Code**: from="Developer", to="Git Repository", protocol="HTTPS/SSH", color=darkgreen
- **Webhook Trigger**: from="Git Repository", to="CIServer", protocol="HTTPS"
- **Fetch Code**: from="CIServer", to="Git Repository", protocol="HTTPS/SSH"
- **Build Application**: from="CIServer", to="ArtifactRegistry", protocol="HTTPS"
- **Pull Artifact**: from="KubeCluster", to="ArtifactRegistry", protocol="HTTPS"
- **Deploy Application**: from="CIServer", to="KubeCluster", protocol="API/SSH"

## Protocol Styles
- **HTTPS**: color=darkgreen, line_style=solid
- **HTTP**: color=red, line_style=solid
- **SSH**: color=blue, line_style=dashed
- **API**: color=black, line_style=dotted

## Severity Multipliers
- **CIServer**: 2.0
- **Git Repository**: 1.8
- **KubeCluster**: 2.0
- **ArtifactRegistry**: 1.5
