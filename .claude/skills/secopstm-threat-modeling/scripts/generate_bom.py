#!/usr/bin/env python3
"""
BOM YAML generator

Parses Servers from model.md and generates corresponding BOM YAML files.

Usage:
    python generate_bom.py --model path/to/model.md --output BOM/

Output:
    - One BOM YAML file per Server
    - Filename: lowercase + underscore (e.g. web_server.yaml)
    - Format: compliant with SecOpsTM BOMLoader spec
"""

import argparse
import re
import ast
import yaml
from pathlib import Path
from typing import Dict, List, Any


def parse_key_value_params(params_str: str) -> Dict[str, Any]:
    """
    Parse key=value parameters (multi-line, comments, quoted strings, lists).
    """
    params = {}
    
    # Strip // comments
    cleaned_params_str = re.sub(r'//.*', '', params_str)
    # Normalise newlines to commas
    normalized_params_str = cleaned_params_str.replace('\n', ',').replace('\r', ',')

    # Match key=value where value is "quoted", [list], or unquoted
    param_pattern = re.compile(
        r'([\w_]+)\s*=\s*'  # key=
        r'('
            r'"[^"]*"'  # "quoted value"
            r'|'
            r'\[[^\]]*\]'  # [list value]
            r'|'
            r'[^,]+'  # unquoted value
        r')'
    )

    for key, value_str in param_pattern.findall(normalized_params_str):
        key = key.strip()
        value_str = value_str.strip()
        
        # Process value
        if value_str.startswith('"') and value_str.endswith('"'):
            value = value_str[1:-1]
        elif value_str.startswith('[') and value_str.endswith(']'):
            # List value
            value = [item.strip().strip('"').strip("'") for item in value_str[1:-1].split(',') if item.strip()]
        else:
            # Boolean, number, or string
            if value_str.lower() == 'true':
                value = True
            elif value_str.lower() == 'false':
                value = False
            else:
                try:
                    value = ast.literal_eval(value_str)
                except (ValueError, SyntaxError):
                    value = value_str

        # Normalise key names
        if key.lower() in ['istrusted', 'is_trusted']:
            key = 'isTrusted'
        elif key.lower() in ['isfilled', 'is_filled']:
            key = 'isFilled'
        elif key.lower() in ['businessvalue', 'business_value']:
            key = 'businessValue'

        params[key] = value
        
    return params


def normalize_asset_key(name: str) -> str:
    """Normalise asset name to lowercase + underscore format (mirrors bom_loader._normalize_asset_key)."""
    key = name.strip().lower()
    key = re.sub(r"[\s\-]+", "_", key)
    key = re.sub(r"[^a-z0-9_]", "", key)
    return key


def parse_model_md(model_path: str) -> Dict:
    """Parse model.md and extract Server information"""
    with open(model_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    result = {
        'servers': [],
        'project_name': Path(model_path).parent.name
    }
    
    # Parse Servers section
    servers_match = re.search(r'## Servers\s*(.*?)(?=## |\Z)', content, re.DOTALL)
    if servers_match:
        servers_content = servers_match.group(1)
        # Match each Server definition: - **Name**: params (multi-line support)
        pattern = r'^\s*-\s*\*\*([^*\:]+)\*\*\s*:\s*(.*?)(?=^\s*-\s*\*\*|\Z)'
        for match in re.finditer(pattern, servers_content, re.MULTILINE | re.DOTALL):
            server_name = match.group(1).strip()
            params_str = match.group(2).strip()
            params = parse_key_value_params(params_str)
            
            server_data = {
                'name': server_name,
                'properties': params
            }
            result['servers'].append(server_data)
    
    return result


def map_server_type_to_services(server_type: str, props: Dict) -> List[str]:
    """Infer running services from Server type"""
    services = []
    
    # Common service/port mappings
    type_services = {
        'web-server': ['HTTP (80)', 'HTTPS (443)'],
        'api-gateway': ['HTTP (80)', 'HTTPS (443)', 'API Gateway'],
        'api_server': ['HTTP (80)', 'HTTPS (443)', 'REST API'],
        'database': ['Database Service'],
        'load-balancer': ['HTTP (80)', 'HTTPS (443)', 'Load Balancer'],
        'firewall': ['Firewall Service'],
        'dns': ['DNS (53)'],
        'mail-server': ['SMTP (25)', 'IMAP (143)', 'POP3 (110)'],
        'vpn': ['VPN Service'],
        'vpn-gateway': ['VPN Gateway'],
        'domain-controller': ['Active Directory', 'LDAP (389)', 'Kerberos (88)'],
        'auth-server': ['Authentication Service', 'OAuth/OIDC'],
        'pki': ['Certificate Authority'],
        'siem': ['SIEM Service', 'Log Collection'],
        'backup': ['Backup Service'],
        'repository': ['Git Repository'],
        'cicd': ['CI/CD Pipeline', 'Build Service'],
        'cache': ['Redis (6379)', 'Memcached (11211)'],
        'message_broker': ['Kafka (9092)', 'RabbitMQ (5672)'],
        'secrets_manager': ['Secrets Management Service'],
        'monitoring': ['Prometheus (9090)', 'Grafana (3000)'],
        'microservice': ['Microservice API'],
        'ingress': ['Ingress Controller'],
        'service_mesh': ['Service Mesh Proxy'],
        'container_registry': ['Container Registry (5000)'],
        'plc': ['PLC Control Service'],
        'scada': ['SCADA HMI'],
    }
    
    # Add default service
    if server_type in type_services:
        services.extend(type_services[server_type])
    else:
        services.append('Default Service')
    
    # Mark as internet-accessible if internet_facing is set
    if props.get('internet_facing'):
        services.append('Internet-facing')
    
    # Mark as credential-storing if credentials_stored is set
    if props.get('credentials_stored'):
        services.append('Credentials Storage')
    
    return services


def infer_patch_level(props: Dict) -> str:
    """Infer patch level (user should verify)"""
    # Default to unknown; prompt user to verify
    return 'unknown'


def generate_bom(server_data: Dict, project_name: str) -> Dict:
    """Generate BOM data structure for a single Server (all 25 fields, BOMLoader-compliant)."""
    props = server_data.get('properties', {})
    server_name = server_data['name']
    server_type = props.get('type', 'default')

    # Build BOM data structure with all Server fields
    bom = {
        # Required fields
        'asset': server_name,
        'asset_type': server_type,
        'os_version': '[Organization-specific]',
        'software_version': '[Organization-specific]',
        'patch_level': infer_patch_level(props),  # current/outdated/unknown

        # CVE list — user must fill from actual scan results
        'known_cves': [],
        'running_services': map_server_type_to_services(server_type, props),

        # Security attributes (extracted from model.md)
        'detection_level': 'unknown',  # none/low/medium/high
        'credentials_stored': props.get('credentials_stored', False),
        
        # CIA triad
        'confidentiality': props.get('confidentiality', 'low'),  # low/medium/high/critical
        'integrity': props.get('integrity', 'low'),  # low/medium/high/critical
        'availability': props.get('availability', 'low'),  # low/medium/high/critical
        
        # Encryption configuration
        'encryption': props.get('encryption', 'none'),  # none/transparent/...
        
        # Security features
        'redundant': props.get('redundant', False),
        'mfa_enabled': props.get('mfa_enabled', True),
        'auth_protocol': props.get('auth_protocol', 'none'),
        
        # Firewall-specific features (only when type=firewall)
        'waf': props.get('waf', False) if server_type == 'firewall' else None,
        'ids': props.get('ids', False) if server_type == 'firewall' else None,
        'ips': props.get('ips', False) if server_type == 'firewall' else None,
        
        # Cloud platform flags
        'onAWS': props.get('onAWS', False),
        'onAzure': props.get('onAzure', False),
        'onGCP': props.get('onGCP', False),
        'isHardened': props.get('isHardened', False),
        
        # Additional fields
        'tags': props.get('tags', []),
        'submodel': props.get('submodel', None),
        'businessValue': props.get('businessValue', None),
        'color': props.get('color', None),
        'description': props.get('description', ''),
        
        # Legacy fields (retained)
        'notes': generate_notes(server_name, props),
    }
    
    return bom


def generate_notes(server_name: str, props: Dict) -> str:
    """Generate BOM notes field (template text — user should complete)"""
    notes_parts = []
    
    # Add type information
    server_type = props.get('type', 'default')
    notes_parts.append(f"Server type: {server_type}")
    
    notes_parts.append(f"Asset type: {server_type} (may be custom - check config/asset_types_community.yaml)")

    machine = props.get('machine', 'physical')
    notes_parts.append(f"Machine type: {machine}")

    boundary = props.get('boundary', 'unknown')
    notes_parts.append(f"Boundary: {boundary}")

    classification = props.get('classification', 'UNKNOWN')
    notes_parts.append(f"Classification: {classification}")

    # Security configuration summary
    cia = f"CIA: C={props.get('confidentiality', 'low')}, I={props.get('integrity', 'low')}, A={props.get('availability', 'low')}"
    notes_parts.append(cia)

    encryption = props.get('encryption', 'none')
    if encryption != 'none':
        notes_parts.append(f"Encryption: {encryption}")

    auth_protocol = props.get('auth_protocol', 'none')
    if auth_protocol != 'none':
        notes_parts.append(f"Auth Protocol: {auth_protocol}")

    security_features = []
    if props.get('redundant'):
        security_features.append('redundant')
    if props.get('mfa_enabled', True):
        security_features.append('MFA enabled')
    if props.get('internet_facing'):
        security_features.append('internet-facing')
    if props.get('isHardened'):
        security_features.append('hardened')
    if security_features:
        notes_parts.append(f"Security: {', '.join(security_features)}")

    # Firewall features (only when type=firewall)
    if server_type == 'firewall':
        fw_features = []
        if props.get('waf'):
            fw_features.append('WAF')
        if props.get('ids'):
            fw_features.append('IDS')
        if props.get('ips'):
            fw_features.append('IPS')
        if fw_features:
            notes_parts.append(f"Firewall: {', '.join(fw_features)}")

    # Cloud platforms
    cloud_platforms = []
    if props.get('onAWS'):
        cloud_platforms.append('AWS')
    if props.get('onAzure'):
        cloud_platforms.append('Azure')
    if props.get('onGCP'):
        cloud_platforms.append('GCP')
    if cloud_platforms:
        notes_parts.append(f"Cloud: {', '.join(cloud_platforms)}")

    # Alerts
    if props.get('internet_facing'):
        notes_parts.append("⚠️ Internet-facing - requires enhanced security controls")
    
    if props.get('credentials_stored'):
        notes_parts.append("⚠️ Stores credentials - ensure encryption at rest")
    
    if encryption == 'none':
        notes_parts.append("⚠️ No encryption at rest configured")

    standard_types = ['firewall', 'domain-controller', 'auth-server', 'database', 'web-server',
                      'api-gateway', 'file-server', 'mail-server', 'management-server',
                      'workstation', 'load-balancer', 'vpn', 'vpn-gateway', 'plc', 'scada',
                      'repository', 'cicd', 'backup', 'dns', 'pki', 'siem', 'default']
    if server_type not in standard_types:
        notes_parts.append(f"⚠️ Custom asset type '{server_type}' - ensure defined in config/asset_types_community.yaml")

    notes_parts.append("\n[Organization-specific]: Please update with actual values")
    notes_parts.append("Patch level should be verified against vendor security advisories")
    notes_parts.append("CVE list should be populated from vulnerability scanner output")
    
    return "; ".join(notes_parts)


def main():
    parser = argparse.ArgumentParser(description='Generate BOM YAML files')
    parser.add_argument('--model', required=True, help='Path to model.md')
    parser.add_argument('--output', required=True, help='Output directory (e.g. BOM/)')
    parser.add_argument('--dry-run', action='store_true', help='Show what would be generated without writing')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    print(f"Parsing model.md: {args.model}")
    model_data = parse_model_md(args.model)

    if not model_data['servers']:
        print("No Servers found in model")
        return 1

    print(f"  {len(model_data['servers'])} servers found")

    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    generated_files = []
    skipped_servers = []

    for server in model_data['servers']:
        asset_key = normalize_asset_key(server['name'])
        bom_filename = f"{asset_key}.yaml"
        bom_path = output_dir / bom_filename

        bom_data = generate_bom(server, model_data['project_name'])
        
        if args.dry_run:
            print(f"  would generate: {bom_path}")
            if args.verbose:
                print(f"    Asset: {bom_data['asset']}")
                print(f"    Type: {server['properties'].get('type', 'unknown')}")
                print(f"    Credentials: {bom_data['credentials_stored']}")
        else:
            try:
                with open(bom_path, 'w', encoding='utf-8') as f:
                    f.write(f"# BOM: {server['name']}\n")
                    f.write(f"# Generated from model.md - please review and update\n")
                    f.write(f"# Fields marked [Organization-specific] need manual input\n\n")
                    yaml.dump(bom_data, f, allow_unicode=True, sort_keys=False, 
                             default_flow_style=None, width=120)
                print(f"  generated: {bom_path}")
                generated_files.append(bom_path)
            except Exception as e:
                print(f"  error generating {bom_path}: {e}")
                skipped_servers.append(server['name'])
    
    print("\n" + "=" * 60)
    if args.dry_run:
        print(f"  Dry run: {len(model_data['servers'])} BOM files would be generated")
    else:
        print(f"  Done: {len(generated_files)} BOM files generated")
        if skipped_servers:
            print(f"  Warning: {len(skipped_servers)} servers skipped: {', '.join(skipped_servers)}")

    print("\nNext steps:")
    print("1. Update os_version and software_version fields")
    print("2. Populate known_cves list from vulnerability scanner output")
    print("3. Confirm patch_level (current/outdated/unknown)")
    print("4. Set detection_level (none/low/medium/high)")
    print("5. Complete security configuration notes")
    
    return 0 if not skipped_servers else 1


if __name__ == '__main__':
    exit(main())
