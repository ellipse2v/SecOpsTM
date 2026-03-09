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

import pytest
from threat_analysis.ai_engine.prompts.stride_prompts import build_component_prompt, STRIDE_SYSTEM_PROMPT
from threat_analysis.ai_engine.prompts.attack_flow_prompts import build_attack_flow_prompt, ATTACK_FLOW_SYSTEM_PROMPT

def test_stride_prompts():
    component = {
        'type': 'Web Server',
        'name': 'Frontend',
        'description': 'Main user interface',
        'trust_boundary': 'Internet',
        'authentication': 'OAuth2',
        'protocol': 'HTTPS',
        'is_public': True,
    }
    context = {
        'system_description': 'A simple web application',
        'data_sensitivity': 'High',
        'compliance_requirements': ['GDPR', 'PCI-DSS'],
        'deployment_environment': 'AWS',
        'integrations': ['Auth0', 'Stripe'],
        'user_base': 'Public users',
        'internet_facing': True
    }
    
    prompt = build_component_prompt(component, context)
    
    assert "Web Server" in prompt
    assert "Frontend" in prompt
    assert "Main user interface" in prompt
    assert "Internet" in prompt
    assert "OAuth2" in prompt
    assert "HTTPS" in prompt
    assert "Yes" in prompt  # Internet facing
    assert "AWS" in prompt
    assert "A simple web application" in prompt
    assert "High" in prompt
    assert "GDPR, PCI-DSS" in prompt
    assert "Public users" in prompt
    assert "Auth0, Stripe" in prompt
    assert STRIDE_SYSTEM_PROMPT is not None

def test_stride_prompts_defaults():
    component = {}
    context = {}
    
    prompt = build_component_prompt(component, context)
    
    assert "Unknown" in prompt
    assert "Unnamed" in prompt
    assert "No description" in prompt
    assert "No" in prompt  # Internet facing default False
    assert "None specified" in prompt
    assert "None" in prompt # Integrations

def test_attack_flow_prompts():
    threat = {
        'title': 'SQL Injection',
        'category': 'Information Disclosure',
        'description': 'Attacker injects SQL code',
        'attack_scenario': """1. Find input field
2. Inject code
3. Dump DB""",
        'mitre_techniques': ['T1190']
    }
    component = {
        'type': 'Database',
        'name': 'UserDB',
        'description': 'Stores user data'
    }
    context = {
        'system_description': 'Backend system'
    }
    
    prompt = build_attack_flow_prompt(threat, component, context)
    
    assert "SQL Injection" in prompt
    assert "Information Disclosure" in prompt
    assert "Attacker injects SQL code" in prompt
    assert "Find input field" in prompt
    assert "T1190" in prompt
    assert "Database" in prompt
    assert "UserDB" in prompt
    assert "Stores user data" in prompt
    assert "Backend system" in prompt
    assert ATTACK_FLOW_SYSTEM_PROMPT is not None

def test_attack_flow_prompts_defaults():
    threat = {}
    component = {}
    context = {}
    
    prompt = build_attack_flow_prompt(threat, component, context)
    
    assert "Unknown" in prompt
    assert "No additional context" in prompt
    assert "None" in prompt # mitre_techniques.join
