<!--
Copyright 2024 ellipse2v — Apache License, Version 2.0
https://www.apache.org/licenses/LICENSE-2.0
-->

# Threat Model: Microservices Architecture

## Description
This threat model covers a microservices-based application with an API gateway, service mesh, message broker, and shared database.

## Context
gdaf_context = context/microservices_context.yaml
bom_directory = BOM

## Boundaries
- **Client (Browser/Mobile)**: color=lightblue, isTrusted=False
- **API Gateway**: color=orange, isTrusted=False
- **Microservice A**: color=green, isTrusted=True
- **Microservice B**: color=blue, isTrusted=True
- **Shared/Dedicated Database**: color=purple, isTrusted=True

## Actors
- **End User**: boundary="Client (Browser/Mobile)"
- **Developer/Operator**: color=gray
- **Attacker**: color=red

## Servers
- **Load Balancer**: type="load_balancer"
- **APIGateway**: boundary="API Gateway", type="api_gateway"
- **UserService**: boundary="Microservice A", type="microservice"
- **ProductService**: boundary="Microservice B", type="microservice"
- **ServiceDiscovery**: type="service_discovery"
- **MessageBroker**: type="message_broker"
- **AppDatabase**: boundary="Shared/Dedicated Database", type="database"

## Dataflows
- **Client Request**: from="End User", to="Load Balancer", protocol="HTTPS"
- **API Request**: from="Load Balancer", to="APIGateway", protocol="HTTPS"
- **Sync Request**: from="APIGateway", to="UserService", protocol="HTTP/gRPC"
- **Async Event**: from="UserService", to="MessageBroker", protocol="AMQP/Kafka"
- **Message Consume**: from="MessageBroker", to="ProductService", protocol="AMQP/Kafka"
- **DB Access**: from="UserService", to="AppDatabase", protocol="JDBC/API"
- **Gateway Attack**: from="Attacker", to="APIGateway", protocol="HTTPS"
- **Service Compromise**: from="Attacker", to="UserService", protocol="HTTP/gRPC"

## Protocol Styles
- **HTTPS**: color=darkgreen, line_style=solid
- **HTTP/gRPC**: color=blue, line_style=solid
- **AMQP/Kafka**: color=purple, line_style=dashed
- **JDBC/API**: color=orange, line_style=dashed

## Severity Multipliers
- **AppDatabase**: 2.0
- **APIGateway**: 1.8
- **MessageBroker**: 1.6
- **UserService**: 1.5
