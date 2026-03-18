<!--
Copyright 2024 ellipse2v — Apache License, Version 2.0
https://www.apache.org/licenses/LICENSE-2.0
-->

# Threat Model: Cloud-Native Architecture

## Description
This threat model addresses cloud-native architectures, focusing on serverless functions, API gateways, managed databases, and object storage.

## Context
gdaf_context = context/cloud_native_context.yaml
bom_directory = BOM

## Boundaries
- **Client (Browser/Mobile)**: color=lightblue, isTrusted=False
- **API Gateway**: color=orange, isTrusted=False
- **FaaS Function (Lambda/Cloud Functions)**: color=green, isTrusted=True
- **NoSQL Database (DynamoDB/Firestore)**: color=purple, isTrusted=True
- **Object Storage (S3/Cloud Storage)**: color=blue, isTrusted=True

## Actors
- **End User**: boundary="Client (Browser/Mobile)"
- **Developer/Cloud Operator**: color=gray
- **Attacker**: color=red

## Servers
- **CDNEdge**: type="cdn"
- **APIGateway**: boundary="API Gateway", type="api_gateway"
- **LambdaFunction**: boundary="FaaS Function (Lambda/Cloud Functions)", type="faas"
- **NoSQLDatabase**: boundary="NoSQL Database (DynamoDB/Firestore)", type="database"
- **ObjectStorage**: boundary="Object Storage (S3/Cloud Storage)", type="object_storage"

## Dataflows
- **Client Request**: from="End User", to="CDNEdge", protocol="HTTPS"
- **API Request**: from="CDNEdge", to="APIGateway", protocol="HTTPS"
- **Function Invocation**: from="APIGateway", to="LambdaFunction", protocol="Internal API"
- **Database Access**: from="LambdaFunction", to="NoSQLDatabase", protocol="Internal API"
- **Object Storage Access**: from="LambdaFunction", to="ObjectStorage", protocol="Internal API"
- **Function Compromise**: from="Attacker", to="LambdaFunction", protocol="API"
- **Misconfigured Storage**: from="Attacker", to="ObjectStorage", protocol="HTTPS"
- **Developer Access**: from="Developer/Cloud Operator", to="APIGateway", protocol="API"

## Protocol Styles
- **HTTPS**: color=darkgreen, line_style=solid
- **Internal API**: color=blue, line_style=dashed

## Severity Multipliers
- **NoSQLDatabase**: 2.0
- **LambdaFunction**: 1.8
- **ObjectStorage**: 1.5
