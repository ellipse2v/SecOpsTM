# Threat Model: Satellite Ground Segment (Thales Demo Scenario)

## Description
Low Earth Orbit satellite system modelling the attack surface demonstrated by Thales
at DEF CON 2023 and documented in the SPARTA/PWNSAT attack flow. Three independent
attack paths are modelled: (1) RF attacker replays unauthenticated CCSDS uplink
commands, pivots OBC → ADCS/Payload; (2) RF attacker passively intercepts unencrypted
CCSDS downlink telemetry via a rogue TLM receiver; (3) RF attacker spoofs GNSS signals
to feed false orbit data to the ADCS GPS receiver; (4) cyber attacker pivots through
internet-facing ground station to Mission Control Server; (5) supply chain attacker
implants malicious firmware on OBC during AIT phase via EGSE.

## Context
gdaf_context = context/satellite_context.yaml
bom_directory = BOM

## Boundaries
- **Space Segment**: isTrusted=False, traversal_difficulty=high
- **Ground Segment**: isTrusted=False, traversal_difficulty=medium
- **TT&C Channel**: isTrusted=False, traversal_difficulty=low
- **Mission Network**: isTrusted=True, traversal_difficulty=high
- **Integration Network**: isTrusted=True, traversal_difficulty=high

## Actors
- **RF Attacker**: boundary="TT&C Channel"
- **Cyber Attacker**: boundary="Ground Segment"
- **Mission Operator**: boundary="Mission Network"
- **Supply Chain Attacker**: boundary="Integration Network"

## Servers
- **Ground-Station**: type="ground-station", boundary="Ground Segment", internet_facing=True, credentials_stored=True
- **TTC-Frontend**: type="ttc-link", boundary="TT&C Channel", internet_facing=True
- **TLM-Receiver**: type="ttc-link", boundary="TT&C Channel", internet_facing=True
- **OBC**: type="onboard-computer", boundary="Space Segment", credentials_stored=True
- **GPS-Receiver**: type="onboard-computer", boundary="Space Segment"
- **ADCS**: type="onboard-computer", boundary="Space Segment"
- **Mission-Payload**: type="leo-satellite", boundary="Space Segment"
- **Mission-Control-Server**: type="server", boundary="Mission Network", credentials_stored=True
- **EGSE**: type="server", boundary="Integration Network", credentials_stored=True

## Dataflows
- **Operator-to-GS**: from="Mission Operator", to="Ground-Station", protocol="HTTPS", encrypted=True, authenticated=True
- **GS-to-TTC**: from="Ground-Station", to="TTC-Frontend", protocol="SLE", encrypted=False, authenticated=False
- **RF-Uplink**: from="TTC-Frontend", to="OBC", protocol="CCSDS", encrypted=False, authenticated=False
- **RF-Downlink**: from="OBC", to="TLM-Receiver", protocol="CCSDS", encrypted=False, authenticated=False
- **TLM-to-GS**: from="TLM-Receiver", to="Ground-Station", protocol="SLE", encrypted=False, authenticated=False
- **GPS-Signal**: from="GPS-Receiver", to="ADCS", protocol="NMEA", encrypted=False, authenticated=False
- **OBC-to-ADCS**: from="OBC", to="ADCS", protocol="MIL-STD-1553", encrypted=False, authenticated=False
- **OBC-to-Payload**: from="OBC", to="Mission-Payload", protocol="SpaceWire", encrypted=False, authenticated=False
- **Attacker-RF-Uplink**: from="RF Attacker", to="TTC-Frontend", protocol="RF", encrypted=False, authenticated=False
- **Attacker-RF-Downlink**: from="RF Attacker", to="TLM-Receiver", protocol="RF", encrypted=False, authenticated=False
- **Attacker-GNSS-Spoof**: from="RF Attacker", to="GPS-Receiver", protocol="GNSS", encrypted=False, authenticated=False
- **Attacker-GS-Exploit**: from="Cyber Attacker", to="Ground-Station", protocol="HTTPS", encrypted=False, authenticated=False
- **GS-to-MCS**: from="Ground-Station", to="Mission-Control-Server", protocol="HTTPS", encrypted=True, authenticated=True
- **Supply-Chain-EGSE**: from="Supply Chain Attacker", to="EGSE", protocol="USB", encrypted=False, authenticated=False
- **EGSE-to-OBC**: from="EGSE", to="OBC", protocol="JTAG", encrypted=False, authenticated=False

## Data
- **Telecommands**: format="CCSDS", classification="sensitive"
- **Telemetry**: format="CCSDS", classification="internal"
- **Payload-Data**: format="raw", classification="confidential"
- **GPS-Signal**: format="NMEA", classification="public"
- **Firmware-Image**: format="binary", classification="confidential"

## Protocol Styles
- **CCSDS**: color=purple, line_style=dashed
- **SpaceWire**: color=darkorchid, line_style=dashed
- **MIL-STD-1553**: color=darkviolet, line_style=dashed
- **SLE**: color=slateblue, line_style=dashed
- **RF**: color=crimson, line_style=dotted
- **GNSS**: color=goldenrod, line_style=dotted
- **NMEA**: color=gold, line_style=dashed
- **JTAG**: color=chocolate, line_style=dashed
- **USB**: color=darkorange, line_style=solid
- **HTTPS**: color=darkgreen, line_style=solid

## Severity Multipliers
- **OBC**: 3.0
- **Mission-Payload**: 3.0
- **ADCS**: 2.5
- **TTC-Frontend**: 2.0
- **TLM-Receiver**: 1.8
- **GPS-Receiver**: 2.0
- **Ground-Station**: 2.0
- **Mission-Control-Server**: 1.8
- **EGSE**: 2.5
