#!/usr/bin/env python3
# Copyright 2025 ellipse2v
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""
GDAF Context YAML generator

Parses model.md system information and generates a GDAF attack scenario context file.

Usage:
    python generate_context.py --model path/to/model.md --output context/

Output:
    - Generates {project-name}_context.yaml file
    - Compliant with GDAF specification format
"""

import argparse
import re
import ast
import yaml
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime


def parse_key_value_params(params_str: str) -> Dict[str, Any]:
    """Parse key=value parameters (multi-line, comments, quoted strings, lists)"""
    params = {}
    cleaned_params_str = re.sub(r'//.*', '', params_str)
    normalized_params_str = cleaned_params_str.replace('\n', ',').replace('\r', ',')

    param_pattern = re.compile(
        r'([\w_]+)\s*=\s*'
        r'('
            r'"[^"]*"'
            r'|'
            r'\[[^\]]*\]'
            r'|'
            r'[^,]+'
        r')'
    )

    for key, value_str in param_pattern.findall(normalized_params_str):
        key = key.strip()
        value_str = value_str.strip()
        
        if value_str.startswith('"') and value_str.endswith('"'):
            value = value_str[1:-1]
        elif value_str.startswith('[') and value_str.endswith(']'):
            value = [item.strip().strip('"').strip("'") for item in value_str[1:-1].split(',') if item.strip()]
        else:
            if value_str.lower() == 'true':
                value = True
            elif value_str.lower() == 'false':
                value = False
            else:
                try:
                    value = ast.literal_eval(value_str)
                except (ValueError, SyntaxError):
                    value = value_str

        if key.lower() in ['istrusted', 'is_trusted']:
            key = 'isTrusted'
        elif key.lower() in ['isfilled', 'is_filled']:
            key = 'isFilled'
        elif key.lower() in ['businessvalue', 'business_value']:
            key = 'businessValue'

        params[key] = value
        
    return params


def parse_model_md(model_path: str) -> Dict:
    """Parse model.md and extract system information (all attributes)"""
    with open(model_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    result = {
        'project_name': Path(model_path).parent.name,
        'description': '',
        'servers': [],
        'actors': [],
        'data': [],
        'boundaries': [],  # full boundary list including all attributes
        'dataflows': [],
        'context': {}
    }
    
    # Extract Description
    desc_match = re.search(r'## Description\s*\n\n(.+?)(?=## |\Z)', content, re.DOTALL)
    if desc_match:
        result['description'] = desc_match.group(1).strip()
    
    # Extract Servers
    servers_match = re.search(r'## Servers\s*(.*?)(?=## |\Z)', content, re.DOTALL)
    if servers_match:
        servers_content = servers_match.group(1)
        pattern = r'^\s*-\s*\*\*([^*\:]+)\*\*\s*:\s*(.*?)(?=^\s*-\s*\*\*|\Z)'
        for match in re.finditer(pattern, servers_content, re.MULTILINE | re.DOTALL):
            server_name = match.group(1).strip()
            params_str = match.group(2).strip()
            params = parse_key_value_params(params_str)
            result['servers'].append({
                'name': server_name,
                'properties': params
            })
    
    # Extract Actors
    actors_match = re.search(r'## Actors\s*(.*?)(?=## |\Z)', content, re.DOTALL)
    if actors_match:
        actors_content = actors_match.group(1)
        pattern = r'^\s*-\s*\*\*([^*\:]+)\*\*\s*:\s*(.*?)(?=^\s*-\s*\*\*|\Z)'
        for match in re.finditer(pattern, actors_content, re.MULTILINE | re.DOTALL):
            actor_name = match.group(1).strip()
            params_str = match.group(2).strip()
            params = parse_key_value_params(params_str)
            result['actors'].append({
                'name': actor_name,
                'properties': params
            })
    
    # Extract Data
    data_match = re.search(r'## Data\s*(.*?)(?=## |\Z)', content, re.DOTALL)
    if data_match:
        data_content = data_match.group(1)
        pattern = r'^\s*-\s*\*\*([^*\:]+)\*\*\s*:\s*(.*?)(?=^\s*-\s*\*\*|\Z)'
        for match in re.finditer(pattern, data_content, re.MULTILINE | re.DOTALL):
            data_name = match.group(1).strip()
            params_str = match.group(2).strip()
            params = parse_key_value_params(params_str)
            result['data'].append({
                'name': data_name,
                'properties': params
            })
    
    # Extract Boundaries (full attributes)
    boundaries_match = re.search(r'## Boundaries\s*(.*?)(?=## |\Z)', content, re.DOTALL)
    if boundaries_match:
        boundaries_content = boundaries_match.group(1)
        pattern = r'^\s*-\s*\*\*([^*\:]+)\*\*\s*:\s*(.*?)(?=^\s*-\s*\*\*|\Z)'
        for match in re.finditer(pattern, boundaries_content, re.MULTILINE | re.DOTALL):
            boundary_name = match.group(1).strip()
            params_str = match.group(2).strip()
            params = parse_key_value_params(params_str)
            result['boundaries'].append({
                'name': boundary_name,
                'properties': params
            })
    
    # Extract Dataflows
    dataflows_match = re.search(r'## Dataflows\s*(.*?)(?=## |\Z)', content, re.DOTALL)
    if dataflows_match:
        dataflows_content = dataflows_match.group(1)
        pattern = r'^\s*-\s*\*\*([^*\:]+)\*\*\s*:\s*(.*?)(?=^\s*-\s*\*\*|\Z)'
        for match in re.finditer(pattern, dataflows_content, re.MULTILINE | re.DOTALL):
            df_name = match.group(1).strip()
            params_str = match.group(2).strip()
            params = parse_key_value_params(params_str)
            result['dataflows'].append({
                'name': df_name,
                'properties': params
            })
    
    # Extract Context
    context_match = re.search(r'## Context\s*(.*?)(?=## |\Z)', content, re.DOTALL)
    if context_match:
        context_content = context_match.group(1)
        # Match key = value or key: value
        pattern = r'^-?\s*([A-Za-z_][A-Za-z0-9_]*)[\s=:]+\s*(.+)$'
        for match in re.finditer(pattern, context_content, re.MULTILINE):
            key = match.group(1).strip()
            value = match.group(2).strip().strip('"').strip("'")
            
            # Type coercion
            if value.lower() == 'true':
                value = True
            elif value.lower() == 'false':
                value = False
            else:
                try:
                    value = int(value)
                except ValueError:
                    try:
                        value = float(value)
                    except ValueError:
                        pass  # Keep as string
            
            result['context'][key] = value
    
    return result


def generate_attack_objectives(servers: List[Dict], data: List[Dict], 
                               boundaries: List[Dict], dataflows: List[Dict]) -> List[Dict]:
    """
    Dynamically generate attack objectives from model data.
    Based on: critical servers (availability=critical),
    sensitive data (Data.classification), and internet-facing assets.
    """
    objectives = []
    obj_counter = 1
    
    # 1. Identify critical assets
    critical_servers = []  # availability=critical
    high_value_servers = []  # database, auth-server, etc.
    internet_facing = []  # internet_facing=True or boundary=Internet
    credential_servers = []  # credentials_stored=True
    
    # Build boundary-name to properties map
    boundary_map = {b['name'].lower(): b['properties'] for b in boundaries}
    
    for server in servers:
        props = server.get('properties', {})
        server_type = props.get('type', 'default')
        name = server['name']
        
        # Check availability requirement
        availability = props.get('availability', 'low')
        if availability == 'critical':
            critical_servers.append(name)
        
        # Check high-value server types
        if server_type in ['database', 'auth-server', 'pki', 'domain-controller', 
                           'secrets_manager', 'siem']:
            high_value_servers.append(name)
        
        # Check internet-facing status
        if props.get('internet_facing'):
            internet_facing.append(name)
        else:
            # Check if boundary is internet-facing
            boundary_name = props.get('boundary', '').lower()
            if 'internet' in boundary_name or 'dmz' in boundary_name:
                internet_facing.append(name)
        
        # Check credential storage
        if props.get('credentials_stored'):
            credential_servers.append(name)
    
    # 2. Identify sensitive data
    sensitive_data = []  # classification=SECRET/TOP_SECRET
    confidential_data = []  # classification=RESTRICTED/SENSITIVE
    
    for d in data:
        props = d.get('properties', {})
        classification = props.get('classification', 'UNKNOWN')
        
        if classification in ['SECRET', 'TOP_SECRET']:
            sensitive_data.append(d['name'])
        elif classification in ['RESTRICTED', 'SENSITIVE']:
            confidential_data.append(d['name'])
    
    # 3. Generate attack objectives
    
    # OBJ-001: Data Theft
    if sensitive_data or confidential_data or credential_servers:
        targets = sensitive_data[:3] if sensitive_data else (confidential_data[:3] if confidential_data else credential_servers[:3])
        target_types = []
        if sensitive_data:
            target_types.extend(['sensitive_data', 'secret_data'])
        if credential_servers:
            target_types.append('credentials')
        
        objectives.append({
            'id': f'OBJ-{obj_counter:03d}',
            'name': 'Data Theft',
            'description': 'Steal sensitive data or credentials from the system',
            'target_asset_names': targets,
            'target_types': target_types if target_types else ['data'],
            'attacker_intent': 'Exfiltrate sensitive information for financial gain, espionage, or blackmail',
            'business_impact': 'Data breach, regulatory compliance violation (GDPR, HIPAA, etc.), reputational damage, financial loss',
            'mitre_final_tactic': 'exfiltration',
            'min_severity_score': 8.5 if sensitive_data else 7.5
        })
        obj_counter += 1
    
    # OBJ-002: Critical Infrastructure Compromise
    if critical_servers or high_value_servers:
        targets = critical_servers[:3] if critical_servers else high_value_servers[:3]
        target_types = []
        if critical_servers:
            target_types.extend(['critical_infrastructure'])
        if high_value_servers:
            target_types.extend(['database', 'auth-server', 'pki', 'domain-controller'])
        
        objectives.append({
            'id': f'OBJ-{obj_counter:03d}',
            'name': 'Critical Infrastructure Compromise',
            'description': 'Compromise critical infrastructure components to disrupt operations or gain elevated access',
            'target_asset_names': targets,
            'target_types': target_types if target_types else ['server'],
            'attacker_intent': 'Gain control over critical systems for sabotage, ransom, or strategic advantage',
            'business_impact': 'Service disruption, operational downtime, potential safety incidents, financial loss',
            'mitre_final_tactic': 'impact',
            'min_severity_score': 9.0 if critical_servers else 8.0
        })
        obj_counter += 1
    
    # OBJ-003: Persistent Access Establishment
    if internet_facing:
        objectives.append({
            'id': f'OBJ-{obj_counter:03d}',
            'name': 'Persistent Access Establishment',
            'description': 'Establish persistent access through internet-facing assets for long-term operations',
            'target_asset_names': internet_facing[:2],
            'target_types': ['internet_facing_asset'],
            'attacker_intent': 'Maintain long-term access for future operations, data theft, or lateral movement',
            'business_impact': 'Long-term compromise, ongoing data theft, potential lateral movement to internal systems',
            'mitre_final_tactic': 'persistence',
            'min_severity_score': 8.5
        })
        obj_counter += 1
    
    # OBJ-004: Lateral Movement — if multiple boundaries
    if len(boundaries) > 2:
        # Identify servers in internal boundaries
        internal_servers = []
        for server in servers:
            props = server.get('properties', {})
            boundary_name = props.get('boundary', '').lower()
            if 'internal' in boundary_name or 'corporate' in boundary_name:
                internal_servers.append(server['name'])
        
        if internal_servers:
            objectives.append({
                'id': f'OBJ-{obj_counter:03d}',
                'name': 'Lateral Movement',
                'description': 'Move laterally from initial access point to internal critical assets',
                'target_asset_names': internal_servers[:3],
                'target_types': ['internal_server'],
                'attacker_intent': 'Escalate access from perimeter to internal critical systems',
                'business_impact': 'Full system compromise, access to all internal data and systems',
                'mitre_final_tactic': 'lateral-movement',
                'min_severity_score': 8.0
            })
            obj_counter += 1
    
    # Fallback: add default objective if none generated
    if not objectives:
        objectives.append({
            'id': 'OBJ-001',
            'name': 'System Compromise',
            'description': 'Gain unauthorized access to system assets',
            'target_asset_names': [s['name'] for s in servers[:2]] if servers else ['*'],
            'target_types': ['server'],
            'attacker_intent': 'Initial compromise for unknown purposes',
            'business_impact': 'Potential data breach and service disruption',
            'mitre_final_tactic': 'initial-access',
            'min_severity_score': 7.0
        })
    
    return objectives


def generate_threat_actors(boundaries: List[Dict], actors: List[Dict], 
                           dataflows: List[Dict]) -> List[Dict]:
    """
    Dynamically generate threat actors from model data.
    Based on: Boundary configuration (isTrusted), authentication mechanisms, and Actor boundary assignments.
    """
    threat_actors = []
    ta_counter = 1
    
    # 1. Analyse boundary configuration
    untrusted_boundaries = []  # isTrusted=False
    trusted_boundaries = []  # isTrusted=True
    has_internet = False
    has_external_auth = False
    
    for boundary in boundaries:
        props = boundary.get('properties', {})
        name = boundary['name']
        
        if not props.get('isTrusted', False):
            untrusted_boundaries.append(name)
            if 'internet' in name.lower() or 'dmz' in name.lower():
                has_internet = True
        else:
            trusted_boundaries.append(name)
    
    # 2. Analyse authentication mechanisms
    auth_levels = set()
    for actor in actors:
        props = actor.get('properties', {})
        authenticity = props.get('authenticity', 'none')
        auth_levels.add(authenticity)
        
        # Check for external authentication
        if authenticity == 'externalized':
            has_external_auth = True
    
    # Check dataflow authentication
    for df in dataflows:
        props = df.get('properties', {})
        auth = props.get('authentication', 'none')
        auth_levels.add(auth)
        if auth == 'externalized':
            has_external_auth = True
    
    # 3. Generate threat actors
    
    # TA-001: External Attacker
    if has_internet:
        sophistication = 'high' if has_external_auth else 'medium'
        threat_actors.append({
            'id': f'TA-{ta_counter:03d}',
            'name': 'External Attacker',
            'sophistication': sophistication,
            'objectives': [],  # filled in step 4
            'entry_preference': 'internet-facing',
            'entry_points': [b for b in untrusted_boundaries if 'internet' in b.lower() or 'dmz' in b.lower()],
            'description': 'External threat actors attempting to compromise the system remotely via internet-facing assets',
            'known_ttps': ['T1190', 'T1040', 'T1563', 'T1566', 'T1133'],
            'capable_tactics': ['initial-access', 'collection', 'exfiltration', 'defense-evasion']
        })
        ta_counter += 1
    else:
        # No internet boundary, but external attackers still possible
        threat_actors.append({
            'id': f'TA-{ta_counter:03d}',
            'name': 'External Attacker',
            'sophistication': 'medium',
            'objectives': [],
            'entry_preference': 'external',
            'entry_points': untrusted_boundaries[:2],
            'description': 'External threat actors attempting to compromise the system from outside the trust boundary',
            'known_ttps': ['T1190', 'T1566', 'T1078'],
            'capable_tactics': ['initial-access', 'collection', 'exfiltration']
        })
        ta_counter += 1
    
    # TA-002: Insider Threat
    if trusted_boundaries:
        # Check internal authentication level
        insider_sophistication = 'high' if 'two-factor' in auth_levels or 'client-certificate' in auth_levels else 'medium'
        
        threat_actors.append({
            'id': f'TA-{ta_counter:03d}',
            'name': 'Insider Threat',
            'sophistication': insider_sophistication,
            'objectives': [],
            'entry_preference': 'insider',
            'entry_points': trusted_boundaries[:2],
            'description': 'Malicious or negligent insiders with legitimate access to trusted systems',
            'known_ttps': ['T1003', 'T1078', 'T1567', 'T1070'],
            'capable_tactics': ['credential-access', 'exfiltration', 'persistence', 'privilege-escalation']
        })
        ta_counter += 1
    
    # TA-003: Nation-State Actor — only when internet boundary + high-value targets
    if has_internet and len(untrusted_boundaries) > 1:
        threat_actors.append({
            'id': f'TA-{ta_counter:03d}',
            'name': 'Nation-State Actor',
            'sophistication': 'very-high',
            'objectives': [],
            'entry_preference': 'supply-chain',
            'entry_points': ['supply-chain', 'zero-day-exploits'],
            'description': 'State-sponsored threat actor with advanced capabilities and resources',
            'known_ttps': ['T1195', 'T1542', 'T1595', 'T1189', 'T1190'],
            'capable_tactics': ['initial-access', 'persistence', 'evasion', 'lateral-movement']
        })
        ta_counter += 1
    
    # TA-004: Automated Attacker — if weak authentication present
    if 'none' in auth_levels or 'credentials' in auth_levels:
        threat_actors.append({
            'id': f'TA-{ta_counter:03d}',
            'name': 'Automated Attacker',
            'sophistication': 'low',
            'objectives': [],
            'entry_preference': 'internet-facing',
            'entry_points': [b for b in untrusted_boundaries if 'internet' in b.lower()] if has_internet else [],
            'description': 'Automated bots and scripts attempting credential stuffing, brute force, or vulnerability scanning',
            'known_ttps': ['T1110', 'T1190', 'T1592'],
            'capable_tactics': ['initial-access', 'credential-access', 'discovery']
        })
        ta_counter += 1
    
    # 4. Assign objectives to each threat actor
    # Assign relevant objectives based on actor characteristics
    for actor in threat_actors:
        if actor['id'] == 'TA-001':  # External Attacker
            actor['objectives'] = [f'OBJ-{i:03d}' for i in range(1, 4)]  # OBJ-001, OBJ-002, OBJ-003
        elif actor['id'] == 'TA-002':  # Insider Threat
            actor['objectives'] = [f'OBJ-{i:03d}' for i in range(1, 3)]  # OBJ-001, OBJ-002
        elif actor['id'] == 'TA-003':  # Nation-State
            actor['objectives'] = [f'OBJ-{i:03d}' for i in range(2, 4)]  # OBJ-002, OBJ-003
        elif actor['id'] == 'TA-004':  # Automated
            actor['objectives'] = ['OBJ-001']  # Only data theft
    
    return threat_actors


def generate_risk_criteria(gdaf_min_technique_score: float = 0.75) -> Dict:
    """
    Generate risk acceptance criteria.
    Includes the 4 fields required by GDAF engine (defaults exist, but explicit values are better).
    """
    return {
        # Required GDAF engine fields (see gdaf_engine.py:515-518)
        'acceptable_risk_score': 5.0,
        'max_hops': 6,
        'max_paths_per_objective': 3,
        'gdaf_min_technique_score': gdaf_min_technique_score,
        
        # Optional but recommended fields (human-readable context)
        'likelihood_scale': {
            'Very Low (1)': 'Requires nation-state resources and zero-day exploits',
            'Low (2)': 'Requires advanced skills and specialized equipment',
            'Medium (3)': 'Requires moderate skills, known vulnerabilities',
            'High (4)': 'Requires basic skills, publicly available tools',
            'Very High (5)': 'Simple execution, no special skills required'
        },
        'impact_scale': {
            'Negligible (1)': 'Minor operational delay, no data exposure',
            'Minor (2)': 'Temporary service disruption, limited data exposure',
            'Moderate (3)': 'Significant operational impact, sensitive data exposure',
            'Major (4)': 'Extended service outage, critical data breach',
            'Catastrophic (5)': 'Critical infrastructure damage or casualties'
        },
        'risk_acceptance_threshold': {
            'Critical': 'Immediate remediation required',
            'High': 'Remediation within 30 days',
            'Medium': 'Remediation within 90 days',
            'Low': 'Remediation within 180 days'
        }
    }


def generate_context(project_name: str, model_data: Dict) -> Dict:
    """
    Generate the full Context data structure.
    Dynamically generates all fields from actual model data.
    """
    
    description = model_data.get('description', '')
    if not description:
        description = f"Threat model for {project_name}"
    
    servers = model_data.get('servers', [])
    server_types = [s.get('properties', {}).get('type', '') for s in servers]
    
    # Infer sector from server types
    sector = '[Organization-specific]'
    if any(t in ['plc', 'scada'] for t in server_types):
        sector = 'Industrial IoT / OT'
    elif any(t in ['database', 'web-server', 'api-gateway'] for t in server_types):
        sector = 'Web Application / SaaS'
    elif any(t in ['kubernetes', 'container', 'microservice'] for t in server_types):
        sector = 'Cloud Native / Container'
    elif any(t in ['api_server', 'message_broker', 'cache'] for t in server_types):
        sector = 'Microservices / Distributed System'
    elif any(t in ['domain-controller', 'auth-server'] for t in server_types):
        sector = 'Enterprise IT / Active Directory'
    
    # Infer data sensitivity from Data classification
    data_sensitivity = 'CONFIDENTIAL'
    for d in model_data.get('data', []):
        classification = d.get('properties', {}).get('classification', 'UNKNOWN')
        if classification in ['TOP_SECRET', 'SECRET']:
            data_sensitivity = 'SECRET'
            break
        elif classification in ['SENSITIVE', 'RESTRICTED']:
            data_sensitivity = 'CONFIDENTIAL'
    
    # Check internet-facing status
    internet_facing = False
    for server in servers:
        if server.get('properties', {}).get('internet_facing'):
            internet_facing = True
            break
        boundary_name = server.get('properties', {}).get('boundary', '').lower()
        if 'internet' in boundary_name or 'dmz' in boundary_name:
            internet_facing = True
            break
    
    # Generate attack objectives from model data
    attack_objectives = generate_attack_objectives(
        model_data.get('servers', []),
        model_data.get('data', []),
        model_data.get('boundaries', []),
        model_data.get('dataflows', [])
    )
    
    # Generate threat actors from model data
    threat_actors = generate_threat_actors(
        model_data.get('boundaries', []),
        model_data.get('actors', []),
        model_data.get('dataflows', [])
    )
    
    # Extract config from ## Context section if present
    context_config = model_data.get('context', {})
    gdaf_min_technique_score = context_config.get('gdaf_min_technique_score', 0.75)
    
    context = {
        'system_description': description,
        'sector': sector,
        'data_sensitivity': data_sensitivity,
        'internet_facing': internet_facing,
        'compliance_requirements': context_config.get('compliance_requirements', ['[Organization-specific]']),
        'attack_objectives': attack_objectives,
        'threat_actors': threat_actors,
        'risk_criteria': generate_risk_criteria(gdaf_min_technique_score),
        'assumptions': [
            'Default security configurations are enabled',
            'Regular security updates are applied',
            'Network segmentation follows best practices'
        ],
        'limitations': [
            'Threat model based on available documentation',
            'Some technical details may require verification',
            'Third-party dependencies not fully assessed'
        ]
    }
    
    return context


def main():
    parser = argparse.ArgumentParser(description='Generate GDAF Context YAML file')
    parser.add_argument('--model', required=True, help='Path to model.md')
    parser.add_argument('--output', required=True, help='Output directory (e.g. context/)')
    parser.add_argument('--dry-run', action='store_true', help='Show what would be generated without writing')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    print(f"Parsing model.md: {args.model}")
    model_data = parse_model_md(args.model)
    
    project_name = model_data['project_name']
    print(f"  project name: {project_name}")
    print(f"  description: {model_data.get('description', 'N/A')[:80]}...")
    print(f"  {len(model_data.get('servers', []))} servers found")
    print(f"  {len(model_data.get('actors', []))} actors found")
    print(f"  {len(model_data.get('data', []))} data items found")
    print(f"  {len(model_data.get('boundaries', []))} boundaries found")
    print(f"  {len(model_data.get('dataflows', []))} dataflows found")
    
    print("\nGenerating context data...")
    print("  - generating attack objectives (from critical assets and sensitive data)")
    print("  - generating threat actors (from boundary config and auth mechanisms)")
    context_data = generate_context(project_name, model_data)
    
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    context_filename = f"{project_name}_context.yaml"
    context_path = output_dir / context_filename
    
    if args.dry_run:
        print(f"\n  would generate: {context_path}")
        if args.verbose:
            print(f"\n  attack objectives: {len(context_data['attack_objectives'])}")
            print(f"  threat actors: {len(context_data['threat_actors'])}")
    else:
        try:
            with open(context_path, 'w', encoding='utf-8') as f:
                f.write(f"# GDAF Attack Scenario Context\n")
                f.write(f"# {project_name} Threat Model Context\n")
                f.write(f"# Generated: {datetime.now().isoformat()}\n")
                f.write(f"# \n")
                f.write(f"# IMPORTANT: Review and customize:\n")
                f.write(f"# - sector, compliance_requirements, attack_objectives, threat_actors\n")
                f.write(f"\n")
                yaml.dump(context_data, f, allow_unicode=True, sort_keys=False, 
                         default_flow_style=None, width=120)
            print(f"\n  generated: {context_path}")
        except Exception as e:
            print(f"  error: {e}")
            return 1
    
    print(f"\nDone.")
    print(f"\nSummary:")
    print(f"  attack objectives: {len(context_data['attack_objectives'])}")
    print(f"  threat actors: {len(context_data['threat_actors'])}")
    print(f"  sector: {context_data['sector']}")
    print(f"  data sensitivity: {context_data['data_sensitivity']}")
    
    print("\nNext steps:")
    print("1. Update sector field (currently auto-inferred)")
    print("2. Add applicable compliance_requirements")
    print("3. Review target assets in attack_objectives")
    print("4. Adjust threat_actors sophistication and TTPs")
    print("5. Add to model.md ## Context: gdaf_context = context/{filename}")
    
    return 0


if __name__ == '__main__':
    exit(main())
