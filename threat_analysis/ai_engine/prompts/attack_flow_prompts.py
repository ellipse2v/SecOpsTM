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

from typing import Dict

ATTACK_FLOW_SYSTEM_PROMPT = """You are an expert in cyber attack chain analysis and MITRE ATT&CK framework. You specialize in creating detailed Attack Flow diagrams following the MITRE Attack Flow v3.0 specification (STIX 2.1 format).

Your expertise includes:
- Kill chain methodology (Lockheed Martin, MITRE ATT&CK)
- Attack graph theory and path analysis
- STIX 2.1 objects and relationships
- Detection engineering and defensive opportunities

You create comprehensive, realistic attack flows that show:
1. Initial access vectors
2. Privilege escalation paths
3. Lateral movement opportunities
4. Data exfiltration methods
5. Defensive detection points
6. Alternative paths (if primary blocked)"""

def build_attack_flow_prompt(threat: Dict, component: Dict, context: Dict) -> str:
    """Generates a prompt to create a STIX 2.1 Attack Flow."""
    
    threat_title = threat.get('title', 'Unknown')
    threat_category = threat.get('category', 'Unknown')
    threat_description = threat.get('description', '')
    attack_scenario = threat.get('attack_scenario', '')
    mitre_techniques = threat.get('mitre_techniques', [])
    
    prompt = f"""# Attack Flow Generation Request

## Threat to Analyze
- **Category**: {threat_category}
- **Title**: {threat_title}
- **Description**: {threat_description}
- **Basic Scenario**: {attack_scenario}
- **Known MITRE Techniques**: {', '.join(mitre_techniques)}

## Target Component
- **Type**: {component.get('type')}
- **Name**: {component.get('name')}
- **Context**: {component.get('description', '')}

## System Context
{context.get('system_description', 'No additional context')}

## Your Task
Create a detailed Attack Flow in MITRE Attack Flow v3.0 format (STIX 2.1 based).

The flow should include:
1. **Initial Access**: How attacker gains entry
2. **Execution**: Code execution or command running
3. **Persistence** (if applicable): How attacker maintains access
4. **Privilege Escalation**: Moving to higher privileges
5. **Defense Evasion**: Bypassing security controls
6. **Credential Access**: Obtaining credentials
7. **Discovery**: Network/system reconnaissance
8. **Lateral Movement** (if applicable): Moving to other systems
9. **Collection**: Gathering target data
10. **Exfiltration**: Data exfiltration method

For each action, include:
- MITRE ATT&CK Tactic ID and name
- MITRE ATT&CK Technique ID and name
- Sub-technique (if applicable)
- Description of the action
- Success path (next action)
- Failure path (if blocked)
- Detection opportunities

Include conditions (prerequisites) and assets (targeted resources).

## Output Format
Return ONLY valid JSON following this STIX 2.1 structure:

```json
{{
  "type": "attack-flow",
  "spec_version": "3.0.0",
  "id": "attack-flow--{threat_category.lower()}-{uuid}",
  "created": "{{current_timestamp}}",
  "modified": "{{current_timestamp}}",
  "name": "{threat_title}",
  "description": "Attack flow for {threat_title}",
  "scope": "incident",
  "start_refs": ["action--1"],
  
  "actions": [
    {{
      "type": "action",
      "id": "action--1",
      "name": "Action Name",
      "tactic": {{
        "id": "TA0001",
        "name": "Initial Access"
      }},
      "technique": {{
        "id": "T1078",
        "name": "Valid Accounts",
        "subtechnique": {{
          "id": "T1078.004",
          "name": "Cloud Accounts"
        }}
      }},
      "description": "Detailed action description",
      "confidence": 85,
      "success_refs": ["action--2"],
      "failure_refs": ["action--detection-1"]
    }}
  ],
  
  "conditions": [
    {{
      "type": "condition",
      "id": "condition--1",
      "description": "Prerequisite condition",
      "pattern": "Observable pattern or requirement"
    }}
  ],
  
  "assets": [
    {{
      "type": "asset",
      "id": "asset--1",
      "name": "Asset name",
      "description": "Asset description"
    }}
  ],
  
  "detection_points": [
    {{
      "type": "detection",
      "id": "detection--1",
      "name": "Detection method",
      "description": "How to detect this action",
      "data_sources": ["Log source 1", "Log source 2"],
      "blocks_action": "action--X"
    }}
  ]
}}
```

Create a realistic, detailed attack flow with 5-7 main actions."""

    return prompt
