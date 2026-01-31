# Threat Model: Three-Tier Architecture

## Description
This threat model describes a classic three-tier web architecture: presentation, business logic, and data. It examines the interactions between the client, application server, and database, identifying potential vulnerabilities at each tier and at integration points.

## Boundaries
- **Client (Web Browser)**: color=lightblue, isTrusted=False
- **Web Server (Presentation Tier)**: color=orange, isTrusted=False
- **Application Server (Business Logic Tier)**: color=green, isTrusted=True
- **Database (Data Tier)**: color=purple, isTrusted=True

## Actors
- **End User**: boundary="Client (Web Browser)"
- **Attacker**: color=red

## Servers
- **Client Web Browser**: boundary="Client (Web Browser)", type="client_browser", businessValue=Low
- **Load Balancer**: color=gray, type="load_balancer", businessValue=Medium
- **Web Server (Nginx/Apache)**: boundary="Web Server (Presentation Tier)", type="web_server", businessValue=Critical
- **Application Server (Tomcat/Node.js/Django)**: boundary="Application Server (Business Logic Tier)", type="app_server", businessValue=Medium
- **Database Server (MySQL/PostgreSQL)**: boundary="Database (Data Tier)", type="database", businessValue=Critical

## Dataflows
- **HTTP/S Request**: from="End User", to="Load Balancer", protocol="HTTPS", color=darkgreen
- **Web Request**: from="Load Balancer", to="Web Server (Nginx/Apache)", protocol="HTTP/S", color=darkgreen
- **API Request**: from="Web Server (Nginx/Apache)", to="Application Server (Tomcat/Node.js/Django)", protocol="HTTP/S", color=darkgreen
- **SQL Request**: from="Application Server (Tomcat/Node.js/Django)", to="Database Server (MySQL/PostgreSQL)", protocol="JDBC/ODBC", color=purple
- **SQL Response**: from="Database Server (MySQL/PostgreSQL)", to="Application Server (Tomcat/Node.js/Django)", protocol="JDBC/ODBC", color=purple
- **API Response**: from="Application Server (Tomcat/Node.js/Django)", to="Web Server (Nginx/Apache)", protocol="HTTP/S", color=darkgreen
- **Web Response**: from="Web Server (Nginx/Apache)", to="Load Balancer", protocol="HTTP/S", color=darkgreen
- **HTTP/S Response**: from="Load Balancer", to="End User", protocol="HTTPS", color=darkgreen
- **SQL Injection**: from="Attacker", to="Application Server (Tomcat/Node.js/Django)", protocol="HTTP/S", color=red
- **XSS**: from="Attacker", to="Client Web Browser", protocol="HTTP/S", color=red

## Protocol Styles
- **HTTPS**: color=darkgreen, line_style=solid
- **HTTP**: color=red, line_style=solid
- **SSH**: color=blue, line_style=dashed
- **SQL**: color=purple
- **LDAPS**: color=teal
- **MQTT**: color=teal, line_style=dashed
- **JDBC/ODBC**: color=purple

## Severity Multipliers
# Example:
# - **Database Server (Data Tier)**: 1.9 (contains sensitive user data)
# - **Application Server (Business Logic Tier)**: 1.7 (business logic and data access)

## Custom Mitre Mapping
# Example:
# - **SQL Injection**: tactics=["Initial Access"], techniques=[{"id": "T1190", "name": "Exploit Public-Facing Application"}]
# - **Cross-Site Scripting (XSS)**: tactics=["Impact"], techniques=[{"id": "T1059", "name": "Command and Scripting Interpreter"}]