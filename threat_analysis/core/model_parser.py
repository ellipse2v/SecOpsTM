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
# 
# # In threat_analysis/model_parser.py

import re
import logging
from typing import List, Dict, Any, Callable, Optional, Tuple, Set
from .models_module import ThreatModel, CustomThreat
from .mitre_mapping_module import MitreMapping
from pytm import Classification, Lifetime
import ast

class ModelParser:
    """
    Parses a threat model defined in Markdown and constructs a ThreatModel object.
    """
    def __init__(self, threat_model: ThreatModel, mitre_mapping: MitreMapping):
        self.threat_model = threat_model
        self.mitre_mapping = mitre_mapping
        self.current_section = None
        self.section_parsers: Dict[str, Callable[[str], None]] = {
            "## Boundaries": self._parse_boundary,
            "## Actors": self._parse_actor,
            "## Servers": self._parse_server,
            "## Data": self._parse_data,             
            "## Dataflows": self._parse_dataflow,
            "## Protocol Styles": self._parse_protocol_style,
            "## Severity Multipliers": self._parse_severity_multiplier,
            "## Custom Mitre Mapping": self._parse_custom_mitre
        }
                # Mappings of string literals to PyTM enums
        self.classification_map = {
            "UNKNOWN": Classification.UNKNOWN,
            "PUBLIC": Classification.PUBLIC,
            "SECRET": Classification.SECRET,
            "TOP_SECRET": Classification.TOP_SECRET,
            "RESTRICTED": Classification.RESTRICTED,
            "SENSITIVE": Classification.SENSITIVE,
            # Common aliases
            "CONFIDENTIAL": Classification.SENSITIVE,  # CONFIDENTIAL ≈ SENSITIVE in pytm
            "INTERNAL": Classification.RESTRICTED,
        }

        self.lifetime_map = {
            "NONE": Lifetime.NONE,
            "UNKNOWN": Lifetime.UNKNOWN,
            "SHORT": Lifetime.SHORT,
            "LONG": Lifetime.LONG,
            "AUTO": Lifetime.AUTO,
            "MANUAL": Lifetime.MANUAL,
            "HARDCODED": Lifetime.HARDCODED,
        }

    def parse_markdown(self, markdown_content: str):
        """
        Parses Markdown content in two passes: first for elements, then for relationships.
        """
        lines = markdown_content.splitlines()
        
        # Pass 0: Parse ## Context (standalone key=value block, no list items)
        self._parse_context_section(lines)

        # First Pass: Parse Boundaries, Actors, Servers, and Data
        element_sections = {
            "## Boundaries": self._parse_boundary,
            "## Actors": self._parse_actor,
            "## Servers": self._parse_server,
            "## Data": self._parse_data,
        }
        self._process_sections(lines, element_sections)

        # Second Pass: Parse Dataflows, Protocol Styles, Severity Multipliers, Custom Mitre Mapping
        # These sections rely on elements defined in the first pass.
        relationship_sections = {
            "## Dataflows": self._parse_dataflow,
            "## Protocol Styles": self._parse_protocol_style,
            "## Severity Multipliers": self._parse_severity_multiplier,
            "## Custom Mitre Mapping": self._parse_custom_mitre,
        }
        self._process_sections(lines, relationship_sections)

    def _process_sections(self, lines: List[str], parsers: Dict[str, Callable]):
        """
        Helper method to process specific sections of the Markdown content, supporting multi-line definitions.
        """
        current_section = None # Reset current_section for each pass of _process_sections
        boundary_stack: List[Tuple[str, int]] = []

        logging.debug(f"Starting _process_sections pass with parsers: {list(parsers.keys())}")

        i = 0
        while i < len(lines):
            line = lines[i]
            logging.debug(f"Processing line {i}: '{line.strip()}' (current_section: {current_section})")
            if not line.strip():
                i += 1
                continue

            if line.strip().startswith("## ") or line.strip().startswith("### "):
                section_title = line.strip()
                logging.debug(f"Found potential section header: '{section_title}'")
                if section_title in parsers:
                    current_section = section_title
                    logging.info(f"⏳ Loading section: {current_section}")
                    boundary_stack = []
                else:
                    current_section = None # Header not relevant for this pass
                i += 1
                continue

            # Check if it's a list item under a known section
            if line.strip().startswith("- "):
                if current_section and current_section in parsers:
                    logging.debug(f"Attempting to parse list item under section: {current_section}")
                    match = re.match(r'^\s*- \*\*(?P<name>[^\*:]+)\*\*:\s*(?P<params>.*)', line)
                    if match:
                        name = match.group('name').strip()
                        params_str = match.group('params').strip()
                        logging.debug(f"Matched element: name='{name}', params='{params_str}'")
                        
                        current_indentation = len(line) - len(line.lstrip())
                        j = i + 1
                        while j < len(lines):
                            next_line = lines[j]
                            next_indentation = len(next_line) - len(next_line.lstrip())
                            
                            if next_line.strip() and (next_indentation > current_indentation or (not next_line.strip().startswith("- ") and not next_line.strip().startswith("## ") and not next_line.strip().startswith("### "))):
                                params_str += "\n" + next_line.strip()
                                j += 1
                            else:
                                break
                        i = j

                        if current_section == "## Boundaries":
                            parsers[current_section](name, params_str, current_indentation, boundary_stack)
                        else:
                            parsers[current_section](name, params_str)
                        continue # Successfully parsed a list item
                    else:
                        logging.debug(f"Line '{line.strip()}' started with '-' but did not match element regex.")
                # If it's a list item but no relevant section, or no match,
                # we still need to increment i.
                i += 1
                continue

            # If it's neither a header nor a list item, reset current_section
            current_section = None
            logging.debug(f"Skipping line '{line.strip()}'. Not a header or relevant list item. Resetting current_section.")
            i += 1

    def _parse_boundary(self, name: str, params_str: str, indentation: int, boundary_stack: List[Tuple[str, int]]):
        """Parses a boundary from a name and a multi-line param string, handling nesting."""
        logging.debug(f"Parsing boundary '{name}' with params: {params_str}")
        boundary_kwargs = self._parse_key_value_params(params_str)
        
        logging.debug(f"Parsed boundary kwargs for '{name}': {boundary_kwargs}")
        if 'color' not in boundary_kwargs:
            boundary_kwargs['color'] = 'lightgray'
            logging.debug(f"Color not found for '{name}', defaulting to lightgray.")
        
        business_value = boundary_kwargs.pop('businessValue', None)

        parent_obj = None
        while boundary_stack and boundary_stack[-1][1] >= indentation:
            boundary_stack.pop()
        if boundary_stack:
            parent_name = boundary_stack[-1][0].lower() # Parent name should be looked up in lowercase
            parent_obj = self.threat_model.boundaries.get(parent_name, {}).get('boundary')
        
        self.threat_model.add_boundary(name, parent_boundary_obj=parent_obj, business_value=business_value, **boundary_kwargs)
        boundary_stack.append((name, indentation))

    def _parse_actor(self, name: str, params_str: str):
        """Parses an actor from a name and a parameter string (can be multi-line)."""
        logging.debug(f"Parsing actor '{name}' with params: {params_str}")
        actor_kwargs = self._parse_key_value_params(params_str)
        
        boundary_name = actor_kwargs.pop('boundary', None)
        business_value = actor_kwargs.pop('businessValue', None)

        self.threat_model.add_actor(name, boundary_name=boundary_name, business_value=business_value, **actor_kwargs)

    def _parse_server(self, name: str, params_str: str):
        """Parses a server from a name and a parameter string (can be multi-line)."""
        logging.debug(f"Parsing server '{name}' with params: {params_str}")
        server_kwargs = self._parse_key_value_params(params_str)
        boundary_name = server_kwargs.pop('boundary', None)
        business_value = server_kwargs.pop('businessValue', None)

        self.threat_model.add_server(name, boundary_name=boundary_name, business_value=business_value, **server_kwargs)
        logging.debug(f"   - Added Server: {name} (Boundary: {boundary_name}, Props: {server_kwargs}, Business Value: {business_value})")
            
    def _parse_key_value_params(self, params_str: str) -> Dict[str, Any]:
        """
        Parses a key=value parameter string (single or multi-line) and returns a dictionary.
        Handles comments, quoted strings, booleans, numbers, hex colors, lists, and unquoted strings.
        """
        logging.debug(f"Parsing params: '{params_str}'")
        params = {}
        
        # Remove comments (// to end of line) and then replace newlines with commas
        cleaned_params_str = re.sub(r'//.*', '', params_str)
        normalized_params_str = cleaned_params_str.replace('\n', ',').replace('\r', ',')

        # This regex is more advanced to handle lists and avoid splitting inside them.
        # It matches: key=value pairs where value can be "quoted", [a list], or unquoted.
        param_pattern = re.compile(
            r'([\w_]+)\s*=\s*'  # key= (allow underscore in key)
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
            
            # Process the value
            if value_str.startswith('"') and value_str.endswith('"'):
                value = value_str[1:-1]
            elif value_str.startswith('[') and value_str.endswith(']'):
                # It's a list, split by comma and strip items
                value = [item.strip() for item in value_str[1:-1].split(',')]
            else:
                # It's a boolean, number, or unquoted string
                if value_str.lower() == 'true':
                    value = True
                elif value_str.lower() == 'false':
                    value = False
                else:
                    try:
                        # Use ast.literal_eval for safe evaluation of numbers, etc.
                        value = ast.literal_eval(value_str)
                    except (ValueError, SyntaxError):
                        value = value_str # Keep as string if it fails

            # Normalize keys to handle case variations
            if key.lower() in ['istrusted', 'is_trusted']:
                key = 'isTrusted'
            elif key.lower() in ['isfilled', 'is_filled']:
                key = 'isFilled'
            elif key.lower() in ['businessvalue', 'business_value']:
                key = 'businessValue'

            params[key] = value
            
        logging.debug(f"Parsed params: {params}")
        return params

    def _parse_data(self, name: str, params_str: str):
        """Parses a Data object from a name and a parameter string (can be multi-line)."""
        logging.debug(f"Parsing data '{name}' with params: {params_str}")
        data_kwargs = self._parse_key_value_params(params_str)

        # Convert strings to PyTM enum objects
        if "classification" in data_kwargs and isinstance(data_kwargs["classification"], str):
            enum_str = data_kwargs["classification"].upper()
            data_kwargs["classification"] = self.classification_map.get(enum_str, Classification.UNKNOWN)
            if enum_str not in self.classification_map:
                logging.warning(f"⚠️ Warning: Classification '{enum_str}' not recognized for Data '{name}'. Set to UNKNOWN.")

        if "credentialsLife" in data_kwargs:
            raw_cl = data_kwargs["credentialsLife"]
            if isinstance(raw_cl, Lifetime):
                pass  # already the right type
            elif isinstance(raw_cl, str):
                enum_str = raw_cl.upper()
                data_kwargs["credentialsLife"] = self.lifetime_map.get(enum_str, Lifetime.UNKNOWN)
                if enum_str not in self.lifetime_map:
                    logging.warning(f"⚠️ Warning: Lifetime '{raw_cl}' not recognized for Data '{name}'. Set to UNKNOWN.")
            else:
                # integer or other non-string — discard to avoid pytm TypeError
                logging.warning(
                    f"⚠️ Warning: credentialsLife for Data '{name}' has a non-string value ({raw_cl!r}). "
                    "Use a Lifetime keyword (NONE, SHORT, LONG, AUTO, MANUAL, HARDCODED). Defaulting to NONE."
                )
                data_kwargs["credentialsLife"] = Lifetime.NONE
            
        self.threat_model.add_data(name, **data_kwargs)
        
        params_display = [f"{key}: {value.name if hasattr(value, 'name') else value}" for key, value in data_kwargs.items()]
        logging.debug(f"   - Added Data: {name} ({', '.join(params_display)})")

    def _parse_dataflow(self, name: str, params_str: str):
        """Parses a dataflow from a name and a parameter string (can be multi-line)."""
        logging.debug(f"Parsing dataflow '{name}' with params: {params_str}")
        params = self._parse_key_value_params(params_str)

        from_name_raw = params.pop("from", None)
        to_name_raw = params.pop("to", None)

        if not all([from_name_raw, to_name_raw]):
            logging.warning(f"⚠️ Warning: Dataflow '{name}' is missing mandatory parameters (from, to).")
            return

        # Using an inner function for DRY code
        def find_element(name_raw: str):
            if not isinstance(name_raw, str): # Ensure name_raw is a string before calling lower()
                logging.warning(f"⚠️ Invalid element name for dataflow '{name}': {name_raw} is not a string.")
                return None
            return self.threat_model.get_element_by_name(name_raw)

        from_elem = find_element(from_name_raw)
        to_elem = find_element(to_name_raw)

        if from_elem and to_elem:
            self.threat_model.add_dataflow(from_elem, to_elem, name, **params)
            logging.debug(f"   - Added Dataflow: {name} ({from_name_raw} -> {to_name_raw}, Props: {params})")
        else:
            logging.warning(f"⚠️ Warning: Elements for dataflow '{name}' not found. From: '{from_name_raw}', To: '{to_name_raw}'.")
            
    def _parse_protocol_style(self, name: str, params_str: str):
        """Parses a protocol style from a name and a parameter string (can be multi-line)."""
        logging.debug(f"Parsing protocol style '{name}' with params: {params_str}")
        style_kwargs = self._parse_key_value_params(params_str)
        
        self.threat_model.add_protocol_style(name, **style_kwargs)
        
        params_display = [f"{key}: {value}" for key, value in style_kwargs.items()]
        logging.debug(f"   - Added Protocol Style: {name} ({', '.join(params_display)})")

    def _parse_severity_multiplier(self, name: str, params_str: str):
        """Parses a severity multiplier from a name and a value string."""
        logging.debug(f"Parsing severity multiplier '{name}' with value: {params_str}")
        try:
            multiplier = float(params_str)
            self.threat_model.add_severity_multiplier(name, multiplier)
            logging.debug(f"   - Added Severity Multiplier: {name} = {multiplier}")
        except (ValueError, TypeError):
            logging.warning(f"⚠️ Warning: Malformed severity multiplier value for '{name}': {params_str}")

    # Keys whose comma-separated values are parsed as lists rather than strings.
    _LIST_CONTEXT_KEYS = frozenset({
        "compliance_requirements",
        "integrations",
        "threat_actor_profiles",
        "business_goals_to_protect",
    })

    def _parse_context_section(self, lines: List[str]) -> None:
        """Pass 0: parse the ## Context section into threat_model.context_config.

        Accepts two syntaxes per line (after the section header):
          key = value
          - key = value
          - key: value

        Values are coerced: "true"/"false" → bool, numeric strings → float/int,
        keys in _LIST_CONTEXT_KEYS → comma-separated list of strings,
        everything else stays a string.

        AI-context keys (accepted directly in ## Context):
          system_description, sector, deployment_environment, data_sensitivity,
          internet_facing, user_base, compliance_requirements, integrations
        """
        in_context = False
        kv_re = re.compile(r'^-?\s*([A-Za-z_][A-Za-z0-9_]*)[\s=:]+(.+)$')
        for line in lines:
            stripped = line.strip()
            if stripped == "## Context":
                in_context = True
                continue
            if in_context:
                if stripped.startswith("## "):
                    break  # next section
                if not stripped or stripped.startswith("#"):
                    continue
                m = kv_re.match(stripped)
                if m:
                    key, raw = m.group(1).strip(), m.group(2).strip().strip('"').strip("'")
                    if key in self._LIST_CONTEXT_KEYS:
                        val: Any = [item.strip() for item in raw.split(",") if item.strip()]
                    elif raw.lower() == "true":
                        val = True
                    elif raw.lower() == "false":
                        val = False
                    else:
                        try:
                            val = int(raw)
                        except ValueError:
                            try:
                                val = float(raw)
                            except ValueError:
                                val = raw
                    self.threat_model.context_config[key] = val
                    logging.info("Context: %s = %r", key, val)

    def _parse_custom_mitre(self, name: str, params_str: str):
        """Parses a custom MITRE mapping from a name and a parameter string."""
        logging.debug(f"Parsing custom MITRE mapping '{name}' with params: {params_str}")
        try:
            # The params_str should be a string representation of a dictionary literal
            mapping_dict = ast.literal_eval(params_str)
            tactics = mapping_dict.get('tactics', [])
            techniques = mapping_dict.get('techniques', [])
            self.threat_model.add_custom_mitre_mapping(name, tactics, techniques)
            logging.debug("Custom MITRE mapping added: %s (tactics: %d, techniques: %d)", name, len(tactics), len(techniques))
        except (SyntaxError, ValueError, AttributeError) as e: # Added AttributeError for safety
            logging.error(f"Error evaluating custom MITRE mapping for '{name}': {e}")