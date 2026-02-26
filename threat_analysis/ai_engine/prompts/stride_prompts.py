from typing import Dict

STRIDE_SYSTEM_PROMPT = """You are an elite cybersecurity expert specializing in threat modeling using the STRIDE methodology. You have deep knowledge of:
- STRIDE framework (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege)
- MITRE ATT&CK framework (techniques, sub-techniques, tactics)
- Real-world attack patterns and CVEs
- Cloud security (AWS, Azure, GCP, Kubernetes)
- Application security (OWASP Top 10, API security)
- Compliance frameworks (HIPAA, GDPR, PCI-DSS, SOC2)

Your task is to analyze system components and identify realistic, actionable security threats with business context.

Critical requirements:
1. Provide DETAILED, SPECIFIC threats (not generic)
2. Include multi-step attack scenarios
3. Map to MITRE ATT&CK techniques with TIDs
4. Assess business impact (financial, regulatory, reputational)
5. Reference real-world precedents (CVEs, breaches) when applicable
6. Suggest detection opportunities
7. Calculate confidence score (0.0-1.0) based on likelihood and attack surface"""

def build_component_prompt(component: Dict, context: Dict) -> str:
    """Builds a context-rich prompt for optimal zero-shot performance."""
    
    # Extract component details
    comp_type = component.get('type', 'Unknown')
    comp_name = component.get('name', 'Unnamed')
    description = component.get('description', 'No description')
    trust_boundary = component.get('trust_boundary', 'Unknown')
    authentication = component.get('authentication', 'Unknown')
    protocol = component.get('protocol', 'Unknown')
    
    # System context
    system_desc = context.get('system_description', '')
    data_sensitivity = context.get('data_sensitivity', 'Medium')
    internet_facing = context.get('internet_facing', False)
    compliance = context.get('compliance_requirements', [])
    deployment = context.get('deployment_environment', 'Unknown')
    integrations = context.get('integrations', [])
    user_base = context.get('user_base', 'Unknown')
    
    prompt = f"""# Threat Modeling Analysis Request

## Component Details
- **Type**: {comp_type}
- **Name**: {comp_name}
- **Description**: {description}
- **Trust Boundary**: {trust_boundary}
- **Authentication Method**: {authentication}
- **Protocol**: {protocol}
- **Internet Facing**: {"Yes" if internet_facing else "No"}
- **Deployment**: {deployment}

## System Context
{system_desc}

## Security Context
- **Data Sensitivity**: {data_sensitivity}
- **Compliance Requirements**: {', '.join(compliance) if compliance else 'None specified'}
- **User Base**: {user_base}
- **Integrations**: {', '.join(integrations) if integrations else 'None'}

## Your Task
Analyze this component for STRIDE threats. For each identified threat, provide:

1. **Category**: One of [Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege]
2. **Title**: Concise, specific threat title (not generic)
3. **Description**: Detailed technical explanation
4. **Attack Scenario**: Step-by-step attack chain (minimum 3 steps)
5. **Prerequisites**: What an attacker needs (access, tools, knowledge)
6. **Business Impact**: 
   - Severity (Critical/High/Medium/Low)
   - Financial impact
   - Regulatory impact (if compliance applies)
   - Reputational impact
   - Operational impact
7. **Likelihood**: Low/Medium/High with rationale
8. **MITRE ATT&CK Techniques**: Array of technique IDs (e.g., ["T1078.004", "T1552.007"])
9. **Real-world Precedents**: CVEs or known breaches (if applicable)
10. **Detection Opportunities**: How defenders can detect this attack
11. **Confidence**: Score 0.0-1.0 indicating your confidence in this threat

## Output Format
Return ONLY valid JSON (no markdown, no preamble) with this exact structure:

```json
{{
  "threats": [
    {{
      "category": "Information Disclosure",
      "title": "Specific Threat Title",
      "description": "Detailed description...",
      "attack_scenario": "1. Step one\\n2. Step two\\n3. Step three",
      "prerequisites": ["Prerequisite 1", "Prerequisite 2"],
      "business_impact": {{
        "severity": "Critical",
        "financial": "Description of financial impact",
        "regulatory": "Description of regulatory impact",
        "reputational": "Description of reputational impact",
        "operational": "Description of operational impact"
      }},
      "likelihood": "Medium",
      "likelihood_rationale": "Explanation...",
      "mitre_techniques": ["T1234.001", "T1234.002"],
      "real_world_precedents": ["CVE-2021-12345", "Company Breach 2022"],
      "detection_opportunities": ["Detection method 1", "Detection method 2"],
      "confidence": 0.85
    }}
  ]
}}
```

Focus on threats that are:
- Specific to this component and context (not generic)
- Realistic and exploitable
- Actionable for security teams
- Considering the compliance and business context"""
    
    return prompt
