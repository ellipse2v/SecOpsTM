# Threat Model: Mobile Application

## Description
Mobile application with backend API, third-party identity provider, and payment gateway integration.

## Context
gdaf_context = context/mobile_app_context.yaml
bom_directory = BOM

## Boundaries
- **Mobile Device (Client)**: isTrusted=False, color=lightblue
- **Backend API**: isTrusted=True, color=green
- **Third-Party Services (Authentication, Payment)**: isTrusted=False, color=orange

## Actors
- **Mobile User**: boundary="Mobile Device (Client)"
- **Attacker**: color=red

## Servers
- **Mobile Application**: boundary="Mobile Device (Client)", type="mobile_application"
- **APIGateway**: boundary="Backend API", type="api_gateway"
- **BackendServer**: boundary="Backend API", type="app_server"
- **BackendDatabase**: boundary="Backend API", type="database"
- **IdentityProvider**: boundary="Third-Party Services (Authentication, Payment)", type="identity_provider"
- **Payment Gateway**: boundary="Third-Party Services (Authentication, Payment)", type="payment_gateway"

## Dataflows
- **Auth Request**: from="Mobile Application", to="IdentityProvider", protocol="HTTPS"
- **Auth Token**: from="IdentityProvider", to="Mobile Application", protocol="HTTPS"
- **API Data Request**: from="Mobile Application", to="APIGateway", protocol="HTTPS"
- **Backend Request**: from="APIGateway", to="BackendServer", protocol="HTTPS"
- **DB Request**: from="BackendServer", to="BackendDatabase", protocol="JDBC/ODBC"
- **DB Response**: from="BackendDatabase", to="BackendServer", protocol="JDBC/ODBC"
- **Backend Response**: from="BackendServer", to="APIGateway", protocol="HTTPS"
- **API Response**: from="APIGateway", to="Mobile Application", protocol="HTTPS"
- **Payment Request**: from="Mobile Application", to="Payment Gateway", protocol="HTTPS"
- **Reverse Engineering**: from="Attacker", to="Mobile Application", protocol="Offline"
- **Communication Interception**: from="Attacker", to="APIGateway", protocol="Network"

## Protocol Styles
- **HTTPS**: color=darkgreen, line_style=solid
- **JDBC/ODBC**: color=purple, line_style=dashed
- **Offline**: color=red, line_style=dotted
- **Network**: color=orange, line_style=dashed

## Severity Multipliers
- **BackendDatabase**: 2.0
- **IdentityProvider**: 2.5
- **Payment Gateway**: 2.5
- **BackendServer**: 1.8
- **APIGateway**: 1.5
