# System Model: DJI Power Inspection Drone System

## Description

The DJI Power Inspection Drone System is an integrated unmanned aerial vehicle (UAV) solution designed for electrical infrastructure inspection, including power lines, substations, and transmission towers. The system comprises aircraft platforms (Matrice 350 RTK, M30T, M400, Mavic 3 Enterprise), ground control systems (RC Plus controller, mobile devices with DJI Pilot 2), backend analysis workstations (DJI Terra), and optional cloud services (FlightHub 2, DJI Account servers, RTK services).

The system supports three network security modes: Standard Mode (full connectivity), Restricted Network Mode (maps/RTK/cloud services only, no DJI account), and Local Data Mode (LDM) which provides complete network isolation. This threat model focuses on a deployment scenario for critical power infrastructure inspection with high-security requirements.

## Context

gdaf_context = context/dji-power-inspection_context.yaml
bom_directory = BOM

## Boundaries

- **Airborne**:
  isTrusted=False, type=execution-environment, color=#e3f2fd, line_style=dashed, traversal_difficulty=medium,
  description="Physical and logical boundary encompassing the aircraft and all onboard systems including flight controller, avionics, gimbal payloads, and O3 Enterprise transmission system.",
  businessValue="Contains critical flight control systems and sensitive inspection data collection capabilities"

- **Ground Station**:
  isTrusted=True, type=execution-environment, color=#fff3e0, line_style=solid, traversal_difficulty=low,
  description="Temporary field deployment boundary for flight operations including RC Plus controller, mobile devices running DJI Pilot 2, and optional Cellular Dongle 2.",
  businessValue="Primary security control point where Local Data Mode and encryption settings are configured"

- **Office Backend**:
  isTrusted=True, type=network-on-prem, color=#e8f5e9, line_style=solid, traversal_difficulty=low,
  description="Permanent office infrastructure for data analysis and storage including analysis workstations running DJI Terra, local file servers, and corporate network infrastructure.",
  businessValue="Central repository for processed inspection data and analysis reports"

- **Cloud External**:
  isTrusted=False, type=network-cloud-provider, color=#fce4ec, line_style=dashed, traversal_difficulty=medium,
  description="External cloud services and third-party systems including DJI FlightHub 2, DJI Account servers, Network RTK services, and third-party livestream platforms.",
  businessValue="Optional services for fleet management, data synchronization, and live video distribution"

- **Supply Chain**:
  isTrusted=False, type=execution-environment, color=#f3e5f5, line_style=dotted, traversal_difficulty=high,
  description="DJI manufacturing, distribution, and firmware development including Shenzhen headquarters, manufacturing facilities, firmware development teams, and component suppliers.",
  businessValue="Source of all system components and firmware updates"

## Actors

- **Drone Pilot**:
  boundary=Ground Station, authenticity=credentials, isTrusted=True, providesAuthentication=False,
  description="Trained operator controlling the aircraft via RC Plus controller and DJI Pilot 2 application.",
  businessValue="Primary system operator responsible for safe flight operations and data collection"

- **Data Analyst**:
  boundary=Office Backend, authenticity=credentials, isTrusted=True, providesAuthentication=False,
  description="Personnel responsible for processing and analyzing inspection data using DJI Terra and other analysis tools.",
  businessValue="Produces actionable insights from collected inspection data"

- **Fleet Manager**:
  boundary=Office Backend, authenticity=two-factor, isTrusted=True, providesAuthentication=True,
  description="Administrator managing drone fleet operations, user accounts, and security policies via FlightHub 2.",
  businessValue="Oversees operational security and compliance for the entire drone program"

- **Nation State Actor**:
  boundary=Cloud External, authenticity=none, isTrusted=False, providesAuthentication=False,
  description="Advanced persistent threat actors with interest in critical infrastructure intelligence and potential sabotage capabilities.",
  businessValue="Primary external threat actor for high-security deployments"

- **Criminal Organization**:
  boundary=Cloud External, authenticity=none, isTrusted=False, providesAuthentication=False,
  description="Organized crime groups targeting equipment theft, ransomware attacks, or sensitive data for financial gain.",
  businessValue="Threat actor motivated by financial gain through equipment theft or data ransom"

- **Negligent Operator**:
  boundary=Ground Station, authenticity=credentials, isTrusted=True, providesAuthentication=False,
  description="Well-meaning but careless operator who may misconfigure security settings, lose equipment, or accidentally expose data.",
  businessValue="Internal threat source due to accidental security lapses"

- **DJI Manufacturer**:
  boundary=Supply Chain, authenticity=externalized, isTrusted=False, providesAuthentication=False,
  description="DJI as the system manufacturer with firmware development capabilities and cloud service access (trust level contested due to geopolitical concerns).",
  businessValue="System originator with deep technical knowledge and potential remote capabilities"

## Servers

- **Aircraft Flight Controller**:
  boundary=Airborne, type=uav_aircraft, classification=RESTRICTED, machine=embedded,
  confidentiality=critical, integrity=critical, availability=critical, encryption=none,
  redundant=False, mfa_enabled=False, internet_facing=False, credentials_stored=False,
  description="Custom DJI embedded flight computer responsible for flight control, navigation, sensor fusion, and aircraft stability.",
  businessValue="Critical asset - loss of control means aircraft loss"

- **Aircraft Payload System**:
  boundary=Airborne, type=gimbal_payload, classification=RESTRICTED, machine=embedded,
  confidentiality=high, integrity=high, availability=high, encryption=none,
  redundant=False, mfa_enabled=False, internet_facing=False, credentials_stored=False,
  description="Multi-sensor inspection payload (Zenmuse H30T/H20T/L2) providing RGB, thermal, zoom, and LiDAR capabilities.",
  businessValue="Primary sensor suite for infrastructure inspection data collection"

- **Aircraft Onboard Storage**:
  boundary=Airborne, type=file-server, classification=RESTRICTED, machine=embedded,
  confidentiality=high, integrity=medium, availability=medium, encryption=transparent,
  redundant=False, mfa_enabled=False, internet_facing=False, credentials_stored=False,
  description="SD card storage for flight logs, inspection media, and mission data with AES-256-XTS encryption when security code enabled.",
  businessValue="Local storage for sensitive inspection data and operational logs"

- **RC Plus Controller**:
  boundary=Ground Station, type=ground_controller, classification=RESTRICTED, machine=embedded,
  confidentiality=high, integrity=high, availability=high, encryption=transparent,
  redundant=False, mfa_enabled=False, internet_facing=False, credentials_stored=True,
  description="Android-based rugged tablet controller with integrated display running DJI Pilot 2 application.",
  businessValue="Primary ground control interface and security configuration point"

- **Mobile Device**:
  boundary=Ground Station, type=workstation, classification=INTERNAL, machine=physical,
  confidentiality=medium, integrity=medium, availability=medium, encryption=transparent,
  redundant=False, mfa_enabled=True, internet_facing=False, credentials_stored=True,
  description="Commercial Android or iOS device optionally used with DJI Pilot 2 for extended control capabilities.",
  businessValue="Secondary control interface with consumer-grade security"

- **Analysis Workstation**:
  boundary=Office Backend, type=workstation, classification=RESTRICTED, machine=physical,
  confidentiality=high, integrity=high, availability=medium, encryption=transparent,
  redundant=False, mfa_enabled=True, internet_facing=False, credentials_stored=True,
  description="Windows desktop or laptop running DJI Terra for 3D modeling, data processing, and analysis report generation.",
  businessValue="Primary data processing and analysis platform"

- **DJI FlightHub 2**:
  boundary=Cloud External, type=cloud_fleet_management, classification=INTERNAL, machine=saas,
  confidentiality=medium, integrity=medium, availability=medium, encryption=transparent,
  redundant=True, mfa_enabled=True, internet_facing=True, credentials_stored=True,
  description="Cloud-based fleet management platform for live streaming, data storage, and multi-aircraft coordination.",
  businessValue="Optional cloud service for fleet management and remote monitoring"

- **DJI Account Servers**:
  boundary=Cloud External, type=auth-server, classification=INTERNAL, machine=saas,
  confidentiality=high, integrity=high, availability=medium, encryption=transparent,
  redundant=True, mfa_enabled=True, internet_facing=True, credentials_stored=True,
  description="User authentication and device registration servers (US-based for non-China users, China-based for China users).",
  businessValue="Identity management for DJI ecosystem access"

- **RTK Service**:
  boundary=Cloud External, type=api_server, classification=PUBLIC, machine=saas,
  confidentiality=low, integrity=medium, availability=medium, encryption=transparent,
  redundant=True, mfa_enabled=False, internet_facing=True, credentials_stored=False,
  description="Network RTK correction service providing centimeter-level positioning accuracy via NTRIP protocol.",
  businessValue="Enhanced positioning for precision flight operations"

- **Livestream Servers**:
  boundary=Cloud External, type=api-gateway, classification=PUBLIC, machine=saas,
  confidentiality=low, integrity=low, availability=low, encryption=transparent,
  redundant=True, mfa_enabled=False, internet_facing=True, credentials_stored=False,
  description="Third-party streaming platforms (YouTube, Vimeo, custom RTMP servers) for live video distribution.",
  businessValue="Optional live video distribution for remote stakeholders"

## Data

- **Infrastructure Coordinates**:
  classification=SECRET, dataState=at-rest,
  description="GIS coordinates, waypoints, and 3D models of power line infrastructure locations."

- **Inspection Imagery**:
  classification=RESTRICTED, dataState=in-transit,
  description="High-resolution RGB photos, 4K video, and thermal images of power line equipment and structures."

- **LiDAR Point Clouds**:
  classification=RESTRICTED, dataState=at-rest,
  description="Precise 3D point cloud data with vertical 3cm and horizontal 4cm accuracy."

- **Flight Telemetry**:
  classification=INTERNAL, dataState=in-transit,
  description="Real-time aircraft status, position, battery level, and sensor data."

- **Flight Control Commands**:
  classification=RESTRICTED, dataState=in-transit,
  description="Real-time pilot control inputs for aircraft navigation and operation."

- **User Credentials**:
  classification=SECRET, dataState=at-rest,
  description="DJI account credentials, security codes, and network passwords."

- **Device Information**:
  classification=INTERNAL, dataState=in-transit,
  description="Serial numbers, firmware versions, and device status information."

- **Mission Plans**:
  classification=INTERNAL, dataState=at-rest,
  description="Waypoint missions and automated flight paths for inspection operations."

## Dataflows

- **Flight Control Uplink**:
  from=RC Plus Controller, to=Aircraft Flight Controller, protocol=o3-enterprise,
  data=Flight Control Commands, bidirectional=False,
  description="Real-time flight control signals transmitted via O3 Enterprise with AES-256 encryption."

- **Telemetry Downlink**:
  from=Aircraft Flight Controller, to=RC Plus Controller, protocol=o3-enterprise,
  data=Flight Telemetry, bidirectional=False,
  description="Continuous aircraft status and sensor data transmission to ground station."

- **Live Video Feed**:
  from=Aircraft Payload System, to=RC Plus Controller, protocol=o3-enterprise,
  data=Inspection Imagery, bidirectional=False,
  description="Real-time 1080p video feed from payload cameras to ground display."

- **Media Storage Onboard**:
  from=Aircraft Payload System, to=Aircraft Onboard Storage, protocol=internal-bus,
  data=Inspection Imagery, bidirectional=False,
  description="Photos and videos saved to aircraft SD card with optional AES-256-XTS encryption."

- **Media Transfer to RC**:
  from=Aircraft Onboard Storage, to=RC Plus Controller, protocol=o3-enterprise,
  data=Inspection Imagery, bidirectional=False,
  description="Thumbnail and full-resolution media transfer from aircraft to ground controller."

- **Mission Plan Upload**:
  from=RC Plus Controller, to=Aircraft Flight Controller, protocol=o3-enterprise,
  data=Mission Plans, bidirectional=False,
  description="Waypoint mission upload from DJI Pilot 2 to aircraft flight controller."

- **RTK Correction Data**:
  from=RTK Service, to=Aircraft Flight Controller, protocol=ntrip,
  data=Infrastructure Coordinates, bidirectional=False,
  description="Real-time kinematic correction data for centimeter-level positioning accuracy."

- **Cloud Data Sync**:
  from=RC Plus Controller, to=DJI FlightHub 2, protocol=https,
  data=Flight Telemetry, bidirectional=False,
  description="Optional synchronization of flight logs, device info, and thumbnails to DJI cloud."

- **Firmware Update OTA**:
  from=DJI Account Servers, to=Aircraft Flight Controller, protocol=https,
  data=Device Information, bidirectional=False,
  description="Over-the-air firmware updates downloaded via RC and distributed to aircraft."

- **Firmware Update Offline**:
  from=Analysis Workstation, to=Aircraft Flight Controller, protocol=physical-media,
  data=Device Information, bidirectional=False,
  description="Offline firmware update via SD card for air-gapped deployments."

- **Livestream Distribution**:
  from=RC Plus Controller, to=Livestream Servers, protocol=rtmp,
  data=Inspection Imagery, bidirectional=False,
  description="Real-time video streaming to third-party platforms via 4G/Internet."

- **Data Transfer to Workstation**:
  from=RC Plus Controller, to=Analysis Workstation, protocol=usb,
  data=Inspection Imagery, bidirectional=True,
  description="Post-mission data transfer from SD cards to analysis workstation via USB."

- **Map Data Download**:
  from=DJI Account Servers, to=RC Plus Controller, protocol=https,
  data=Infrastructure Coordinates, bidirectional=False,
  description="Base map and satellite imagery download for mission planning."

- **Account Authentication**:
  from=RC Plus Controller, to=DJI Account Servers, protocol=https,
  data=User Credentials, bidirectional=True,
  description="DJI account login and authentication for cloud feature access."

- **GEO Zone Update**:
  from=DJI Account Servers, to=Aircraft Flight Controller, protocol=https,
  data=Infrastructure Coordinates, bidirectional=False,
  description="No-fly zone and restricted area database updates."

## Protocol Styles

- **o3-enterprise**:
  description="DJI O3 Enterprise proprietary transmission protocol with AES-256 encryption for video and data.",
  lineStyle=solid, color=#1976d2, labelColor=#ffffff

- **https**:
  description="Standard HTTPS protocol with TLS encryption for cloud communications.",
  lineStyle=solid, color=#388e3c, labelColor=#ffffff

- **usb**:
  description="USB mass storage protocol for physical data transfer.",
  lineStyle=dashed, color=#f57c00, labelColor=#ffffff

- **physical-media**:
  description="SD card physical transfer for offline firmware updates.",
  lineStyle=dashed, color=#7b1fa2, labelColor=#ffffff

- **ntrip**:
  description="NTRIP protocol over cellular network for RTK correction data.",
  lineStyle=dotted, color=#0097a7, labelColor=#ffffff

- **rtmp**:
  description="RTMP/RTSP protocol for live video streaming to third-party platforms.",
  lineStyle=dotted, color=#d32f2f, labelColor=#ffffff

- **internal-bus**:
  description="Internal hardware bus for onboard data storage.",
  lineStyle=solid, color=#5d4037, labelColor=#ffffff

## Severity Multipliers

// Context-specific multipliers for critical infrastructure inspection scenario

- **Critical Infrastructure Multiplier**:
  factor=2.0,
  description="Power grid is critical national infrastructure requiring enhanced security assessment."

- **EMI Environment Multiplier**:
  factor=1.5,
  description="Power lines create high-EMI environment affecting aircraft electronics and navigation."

- **LDM Enabled Multiplier**:
  factor=0.5,
  description="Local Data Mode significantly reduces cloud-related attack surface when properly configured."

- **Cloud Sync Enabled Multiplier**:
  factor=1.3,
  description="Cloud connectivity increases attack surface through additional network exposure."

- **Media Encryption Enabled Multiplier**:
  factor=0.7,
  description="AES-256-XTS encryption reduces data breach impact from physical theft."

- **Operator Training Multiplier**:
  factor=0.8,
  description="Trained operators reduce accidental security lapses and misconfigurations."

- **Remote Operations Multiplier**:
  factor=1.2,
  description="Remote inspection locations increase physical security risks for equipment."

- **Fleet Operations Multiplier**:
  factor=1.3,
  description="Multiple aircraft operations increase system complexity and management overhead."

## Custom Mitre Mapping

// Custom MITRE ATT&CK mappings for UAV-specific attack scenarios
// Format: technique=ID, name="Name", description="Description", platforms="Platform"
