# Threat Model: IoT (Internet of Things) Architecture

## Description
This threat model describes a typical IoT architecture, including devices, gateways, cloud platforms, and user interfaces. It focuses on the data flow from sensors to the cloud and back to actuators, considering the unique security challenges of resource-constrained devices and distributed environments.

## Boundaries
<!-- ERROR - Boundary 'Physical Environment' is defined but not used by any actor or server. 注掉下面这一行就不会报这个错了-->
<!-- - **Physical Environment**: color=lightgray, isTrusted=False -->
- **IoT Device**: color=lightblue, isTrusted=False
- **IoT Gateway**: color=lightgreen, isTrusted=False
- **Cloud Platform**: color=orange, isTrusted=True
- **Mobile Application**: color=purple, isTrusted=False

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
- **Sensor Data**: from="Sensor", to="IoT Gateway Server", protocol="MQTT/CoAP", color=teal
- **Gateway to Cloud**: from="IoT Gateway Server", to="IoT Hub", protocol="HTTPS/MQTT", color=darkgreen
- **Cloud to Data Storage**: from="IoT Hub", to="Data Storage", protocol="Internal API"
- **Cloud to Analytics**: from="Data Storage", to="Analytics Engine", protocol="Internal API"
- **Command to Actuator**: from="Device Management Service", to="IoT Gateway Server", protocol="MQTT/CoAP", color=teal
- **Gateway to Actuator**: from="IoT Gateway Server", to="Actuator", protocol="MQTT/CoAP", color=teal
- **Admin to Device Management**: from="Device Administrator", to="Device Management Service", protocol="HTTPS", color=darkgreen

## Protocol Styles
- **HTTPS**: color=darkgreen, line_style=solid
- **HTTP**: color=red, line_style=solid
- **SSH**: color=blue, line_style=dashed
- **SQL**: color=purple
- **LDAPS**: color=teal
- **MQTT**: color=teal, line_style=dashed
- **MQTT/CoAP**: color=teal
- **HTTPS/MQTT**: color=darkgreen
- **Internal API**: color=grey, line_style=dotted

## Severity Multipliers
# Example:
# - **IoT Device**: 1.8 (due to physical access and limited update capabilities)
# - **IoT Gateway**: 1.5 (due to bridging physical and cloud environments)

## Custom Mitre Mapping
# Example:
# - **Unauthorized Device Access**: tactics=["Initial Access"], techniques=[{"id": "T1190", "name": "Exploit Public-Facing Application"}]
# - **Firmware Tampering**: tactics=["Persistence", "Defense Evasion"], techniques=[{"id": "T1542", "name": "Pre-OS Boot"}]