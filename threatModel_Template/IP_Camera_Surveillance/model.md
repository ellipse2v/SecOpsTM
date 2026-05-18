# Threat Model: IP Camera Surveillance System

## Description
IP-based video surveillance system for a commercial building: fixed and PTZ cameras,
thermal perimeter detection, NVR, Video Management System, RTSP relay, mobile viewer
app, and cloud archive. Models the full attack surface from unauthenticated RTSP streams
to VMS admin takeover and NVR footage destruction.

## Context
gdaf_context = context/camera_context.yaml
bom_directory = BOM

## Boundaries
- **Physical Perimeter**: isTrusted=False, traversal_difficulty=low
- **Camera Network**: isTrusted=False, traversal_difficulty=medium
- **Management Network**: isTrusted=True, traversal_difficulty=high
- **Mobile Access**: isTrusted=False, traversal_difficulty=low
- **Cloud Storage**: isTrusted=True, traversal_difficulty=medium

## Actors
- **External Attacker**: boundary="Physical Perimeter"
- **Security Operator**: boundary="Management Network"
- **Mobile Viewer**: boundary="Mobile Access"

## Servers
- **Cam-Entrance-01**: type="ip-camera", boundary="Camera Network", internet_facing=False, credentials_stored=True
- **Cam-Parking-PTZ**: type="ptz-camera", boundary="Camera Network", internet_facing=False, credentials_stored=True
- **Cam-Server-Room**: type="ip-camera", boundary="Camera Network", internet_facing=False, credentials_stored=True
- **Cam-Thermal-Perimeter**: type="thermal-camera", boundary="Physical Perimeter", internet_facing=True, credentials_stored=True
- **NVR-Main**: type="nvr", boundary="Camera Network", credentials_stored=True
- **VMS-Server**: type="vms", boundary="Management Network", credentials_stored=True
- **RTSP-Relay**: type="rtsp-server", boundary="Camera Network"
- **Cloud-Archive**: type="backup", boundary="Cloud Storage"
- **Mobile-App-Server**: type="api-gateway", boundary="Mobile Access"

## Dataflows
- **Cam-to-NVR-01**: from="Cam-Entrance-01", to="NVR-Main", protocol="RTSP", encrypted=False, authenticated=False
- **Cam-to-NVR-PTZ**: from="Cam-Parking-PTZ", to="NVR-Main", protocol="RTSP", encrypted=False, authenticated=False
- **Cam-to-NVR-Server**: from="Cam-Server-Room", to="NVR-Main", protocol="RTSP", encrypted=False, authenticated=False
- **Thermal-to-NVR**: from="Cam-Thermal-Perimeter", to="NVR-Main", protocol="RTSP", encrypted=False, authenticated=True
- **NVR-to-VMS**: from="NVR-Main", to="VMS-Server", protocol="HTTPS", encrypted=True, authenticated=True
- **NVR-to-RTSP**: from="NVR-Main", to="RTSP-Relay", protocol="RTSP", encrypted=False, authenticated=False
- **VMS-to-Cloud**: from="VMS-Server", to="Cloud-Archive", protocol="HTTPS", encrypted=True, authenticated=True
- **VMS-to-PTZ-Control**: from="VMS-Server", to="Cam-Parking-PTZ", protocol="ONVIF", encrypted=False, authenticated=True
- **Operator-to-VMS**: from="Security Operator", to="VMS-Server", protocol="HTTPS", encrypted=True, authenticated=True
- **Mobile-to-API**: from="Mobile Viewer", to="Mobile-App-Server", protocol="HTTPS", encrypted=True, authenticated=True
- **API-to-RTSP**: from="Mobile-App-Server", to="RTSP-Relay", protocol="RTSP", encrypted=False, authenticated=False
- **Attacker-to-Thermal**: from="External Attacker", to="Cam-Thermal-Perimeter", protocol="RTSP", encrypted=False, authenticated=False

## Protocol Styles
- **RTSP**: color=orange, line_style=dashed
- **ONVIF**: color=darkorange, line_style=dashed
- **HTTPS**: color=darkgreen, line_style=solid

## Severity Multipliers
- **NVR-Main**: 2.5
- **VMS-Server**: 2.0
- **Cam-Server-Room**: 2.0
- **RTSP-Relay**: 1.8
- **Cam-Thermal-Perimeter**: 1.5
- **Cam-Parking-PTZ**: 1.3
