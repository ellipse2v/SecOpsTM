# Threat Model: Simple Monolithic Web Application

## Description
A monolithic web application with a single application server handling all business logic.

## Context
gdaf_context = context/monolithic_context.yaml
bom_directory = BOM

## Boundaries
- **Client (Web Browser)**: color=lightblue, isTrusted=False
- **Monolithic Web Server**: color=orange, isTrusted=False
- **Database**: color=purple, isTrusted=True

## Actors
- **End User**: boundary="Client (Web Browser)"
- **Administrator**: color=gray

## Servers
- **LoadBalancer**: type="load_balancer"
- **MonolithicApp**: boundary="Monolithic Web Server", type="web_server"
- **DatabaseServer**: boundary="Database", type="database"

## Dataflows
- **HTTP/S Request**: from="End User", to="LoadBalancer", protocol="HTTPS"
- **Web Request**: from="LoadBalancer", to="MonolithicApp", protocol="HTTP/S"
- **Database Request**: from="MonolithicApp", to="DatabaseServer", protocol="JDBC/ODBC/API"
- **Database Response**: from="DatabaseServer", to="MonolithicApp", protocol="JDBC/ODBC/API"
- **Web Response**: from="MonolithicApp", to="LoadBalancer", protocol="HTTP/S"
- **HTTP/S Response**: from="LoadBalancer", to="End User", protocol="HTTPS"

## Protocol Styles
- **HTTPS**: color=darkgreen, line_style=solid
- **HTTP/S**: color=orange
- **JDBC/ODBC/API**: color=purple, line_style=dashed

## Severity Multipliers
- **DatabaseServer**: 2.0
- **MonolithicApp**: 1.8
