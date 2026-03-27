<!--
Copyright 2024 ellipse2v — Apache License, Version 2.0
https://www.apache.org/licenses/LICENSE-2.0
-->

# Threat Model: Three-Tier Architecture

## Description
Classic three-tier web architecture: presentation, business logic, and data.

## Context
gdaf_context = context/three_tier_context.yaml
bom_directory = BOM

## Boundaries
- **Client (Web Browser)**: color=lightblue, isTrusted=False
- **Web Server (Presentation Tier)**: color=orange, isTrusted=False
- **Application Server (Business Logic Tier)**: color=green, isTrusted=True
- **Database (Data Tier)**: color=purple, isTrusted=True

## Actors
- **End User**: boundary="Client (Web Browser)"

## Servers
- **Client Web Browser**: boundary="Client (Web Browser)", type="client_browser", businessValue=Low
- **Load Balancer**: color=gray, type="load_balancer", businessValue=Medium
- **WebServer**: boundary="Web Server (Presentation Tier)", type="web_server", businessValue=Critical
- **AppServer**: boundary="Application Server (Business Logic Tier)", type="app_server", businessValue=Medium
- **DatabaseServer**: boundary="Database (Data Tier)", type="database", businessValue=Critical

## Dataflows
- **HTTP/S Request**: from="End User", to="Load Balancer", protocol="HTTPS"
- **Web Request**: from="Load Balancer", to="WebServer", protocol="HTTP/S"
- **API Request**: from="WebServer", to="AppServer", protocol="HTTP/S"
- **SQL Request**: from="AppServer", to="DatabaseServer", protocol="JDBC/ODBC"
- **SQL Response**: from="DatabaseServer", to="AppServer", protocol="JDBC/ODBC"

## Protocol Styles
- **HTTPS**: color=darkgreen, line_style=solid
- **HTTP/S**: color=orange, line_style=solid
- **JDBC/ODBC**: color=purple, line_style=dashed

## Severity Multipliers
- **DatabaseServer**: 2.0
- **AppServer**: 1.8
- **WebServer**: 1.5
