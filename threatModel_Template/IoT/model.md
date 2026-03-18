# Threat Model: IoT Architecture

## Description
IoT system with sensors, gateway, cloud platform, analytics, and device management.

## Context
gdaf_context = context/iot_context.yaml
bom_directory = BOM

## Boundaries
- **Physical Environment**: isTrusted=False, color=red
- **IoT Device**: isTrusted=False, color=orange
- **IoT Gateway**: isTrusted=False, color=yellow
- **Cloud Platform**: isTrusted=True, color=lightblue
- **Mobile Application**: isTrusted=False, color=lightgreen

## Actors
- **Sensor**: boundary="IoT Device"
- **Actuator**: boundary="IoT Device"
- **Device Administrator**: boundary="Mobile Application"
- **Cloud Administrator**: boundary="Cloud Platform"

## Servers
- **IoT Gateway Server**: boundary="IoT Gateway", type="iot_gateway"
- **IoT Hub**: boundary="Cloud Platform", type="iot_hub"
- **Data Storage**: boundary="Cloud Platform", type="data_storage"
- **Analytics Engine**: boundary="Cloud Platform", type="analytics_engine"
- **Device Management Service**: boundary="Cloud Platform", type="device_management_service"

## Dataflows
- **Sensor Data**: from="Sensor", to="IoT Gateway Server", protocol="MQTT/CoAP"
- **Gateway to Cloud**: from="IoT Gateway Server", to="IoT Hub", protocol="HTTPS/MQTT"
- **Cloud to Storage**: from="IoT Hub", to="Data Storage", protocol="Internal API"
- **Storage to Analytics**: from="Data Storage", to="Analytics Engine", protocol="Internal API"
- **Command to Gateway**: from="Device Management Service", to="IoT Gateway Server", protocol="MQTT/CoAP"
- **Gateway to Actuator**: from="IoT Gateway Server", to="Actuator", protocol="MQTT/CoAP"
- **Admin to Device Mgmt**: from="Device Administrator", to="Device Management Service", protocol="HTTPS"

## Protocol Styles
- **MQTT/CoAP**: color=teal, line_style=dashed
- **HTTPS/MQTT**: color=darkgreen, line_style=solid
- **HTTPS**: color=darkgreen, line_style=solid
- **Internal API**: color=blue, line_style=dashed

## Severity Multipliers
- **IoT Hub**: 2.0
- **Device Management Service**: 2.0
- **IoT Gateway Server**: 1.8
- **Data Storage**: 1.5
