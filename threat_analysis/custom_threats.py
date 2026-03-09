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

from .threat_rules import THREAT_RULES
from typing import Dict
import logging

class RuleBasedThreatGenerator:
    """
    A class to generate threats for a given threat model based on a set of expressive rules.
    The engine can handle nested property checks (e.g., 'source.boundary.isTrusted').
    """
    def __init__(self, threat_model):
        self.threat_model = threat_model
        self.threats = []
        self.id_counter = 1
        # P3: pre-split universal rules (conditions={}) from conditional rules so the
        # inner loop never calls _matches() for the always-true case.
        self._rules_universal: Dict[str, list] = {}
        self._rules_conditional: Dict[str, list] = {}
        for key, rule_list in THREAT_RULES.items():
            universal = [r for r in rule_list if not r.get("conditions")]
            conditional = [r for r in rule_list if r.get("conditions")]
            self._rules_universal[key] = universal
            self._rules_conditional[key] = conditional

    def _add_threat(self, component_name, description, stride_category, impact, likelihood, mitigations=None, capec_ids=None):
        threat = {
            "id": self.id_counter,
            "component": component_name,
            "description": description,
            "stride_category": stride_category,
            "impact": impact,
            "likelihood": likelihood,
            "mitigations": mitigations or [],
            "capec_ids": capec_ids or []
        }
        self.threats.append(threat)
        self.id_counter += 1

    def _get_property(self, component, key):
        """Gets a property from a component, handling dot notation for nested objects."""
        value = component
        try:
            for part in key.split('.'):
                if isinstance(value, dict):
                    value = value.get(part)
                else:
                    value = getattr(value, part, None)
                if value is None:
                    return None
        except AttributeError:
            return None
        return value

    def _matches(self, component, conditions):
        """
        Checks if a component's properties match the given conditions, supporting dot notation
        and special computed conditions.
        """
        if not conditions:
            return True

        for key, expected_value in conditions.items():
            # Handle special computed conditions first
            if key == 'crosses_trust_boundary':
                source_boundary = self._get_property(component, 'source.inBoundary')
                sink_boundary = self._get_property(component, 'sink.inBoundary')
                if not source_boundary or not sink_boundary:
                    return False # Cannot determine if boundaries are crossed
                
                is_crossing = source_boundary.isTrusted != sink_boundary.isTrusted
                if is_crossing != expected_value:
                    return False
                continue # Move to the next condition

            if key == 'contains_sensitive_data':
                data_list = self._get_property(component, 'data')
                if not isinstance(data_list, list):
                    return False # Data is not in the expected list format
                
                has_sensitive = any(
                    self._get_property(d, 'classification.name').lower() in ['secret', 'top_secret', 'sensitive'] 
                    for d in data_list
                )
                if has_sensitive != expected_value:
                    return False
                continue # Move to the next condition

            # Handle direct property lookups
            prop_value = self._get_property(component, key)
            
            if hasattr(prop_value, 'name'):
                prop_value = prop_value.name.lower()

            if isinstance(prop_value, str) and isinstance(expected_value, str):
                if prop_value.lower() != expected_value.lower():
                    return False
            elif prop_value != expected_value:
                return False
        return True

    def _apply_rules(self, component, key: str, fmt_kwargs: dict, component_name: str) -> None:
        """Applies all matching rules (universal + conditional) for one component."""
        for rule in self._rules_universal[key]:
            for tpl in rule["threats"]:
                desc = tpl["description"].format(**fmt_kwargs)
                self._add_threat(component_name, desc, **{k: v for k, v in tpl.items() if k != 'description'})
        for rule in self._rules_conditional[key]:
            if self._matches(component, rule["conditions"]):
                for tpl in rule["threats"]:
                    desc = tpl["description"].format(**fmt_kwargs)
                    self._add_threat(component_name, desc, **{k: v for k, v in tpl.items() if k != 'description'})

    def generate_threats(self):
        """
        Generates all threats for the threat model by applying rules to each component.
        """
        for server_info in self.threat_model.servers:
            self._apply_rules(server_info, "servers", {"name": server_info['name']}, server_info['name'])

        for flow in self.threat_model.dataflows:
            self._apply_rules(
                flow, "dataflows",
                {"source": flow.source, "sink": flow.sink},
                f"Flow from {flow.source.name} to {flow.sink.name}",
            )

        for actor_info in self.threat_model.actors:
            self._apply_rules(actor_info, "actors", {"name": actor_info['name']}, actor_info['name'])

        return self.threats

def get_custom_threats(threat_model):
    """
    Generates a list of threats based on the components in the threat model.
    """
    generator = RuleBasedThreatGenerator(threat_model)
    return generator.generate_threats()
