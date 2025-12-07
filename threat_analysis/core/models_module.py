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
Threat Model Definition Module with MITRE ATT&CK Integration
"""
from pytm import TM, Boundary, Actor, Server, Dataflow, Data, Classification, Lifetime
from collections import defaultdict
from typing import List, Dict, Any, Optional, Tuple
import logging
from enum import Enum
from pathlib import Path

# Patch pytm.Boundary to ensure it has all necessary custom attributes
if not hasattr(Boundary, 'isTrusted'):
    original_boundary_init = Boundary.__init__
    def new_boundary_init(self, *args, **kwargs):
        original_boundary_init(self, *args, **kwargs)
        self.protocol = ""
        self.port = "" # Initialize port
        self.data = [] # Initialize data as a list
        self.isTrusted = False # Default value
    Boundary.__init__ = new_boundary_init

from .mitre_mapping_module import MitreMapping
from threat_analysis.severity_calculator_module import SeverityCalculator
from .model_validator import ModelValidator
from threat_analysis.custom_threats import get_custom_threats
from .cve_service import CVEService

class CustomThreat:
    """A simple class to represent a custom threat."""
    def __init__(self, name, description, stride_category, impact, likelihood, target, capec_ids=None):
        self.name = name
        self.description = description
        self.stride_category = stride_category
        self.impact = impact
        self.likelihood = likelihood
        self.target = target
        self.capec_ids = capec_ids or []
        self.severity_info = None # To store calculated severity

    def __str__(self):
        return self.name


class ThreatModel:
    """Main class for managing the threat model with MITRE ATT&CK integration"""

    def __init__(self, name: str, description: str = "", cve_service: CVEService = None):
        self.tm = TM(name)
        self.tm.description = description
        self.boundaries = {}  # Stores Boundary objects and their properties (e.g., color)
        self.actors = []
        self.servers = []
        self.dataflows = []
        self.severity_multipliers: Dict[str, float] = {}
        self.custom_mitre_mappings: Dict[str, Any] = {}
        self.protocol_styles: Dict[str, Dict[str, Any]] = {}  # New: Store protocol styles
        self.threats_raw = []
        self.grouped_threats = defaultdict(list)
        self.data_objects = {}
        # Adding a dictionary for quick access to elements by their name
        self._elements_by_name: Dict[str, Any] = {}
        self._component_collections: Dict[type, list] = {
            Actor: self.actors,
            Server: self.servers
            # Other types like Datastore can be added here
        }
        
        # MITRE ATT&CK Integration
        self.mitre_mapper = MitreMapping(threat_model=self)
        self.mitre_analysis_results = {}
        self.threat_mitre_mapping = {}
        self.severity_calculator = SeverityCalculator() # Instantiate SeverityCalculator

        # CVE Service
        if not cve_service:
            raise ValueError("A CVEService instance must be provided to ThreatModel.")
        self.cve_service = cve_service

    def add_boundary(self, name: str, color: str = "lightgray", parent_boundary_obj: Optional[Boundary] = None, **kwargs) -> Boundary:
        """Adds a boundary to the model with additional properties, including an optional parent.

        Args:
            name (str): The name of the boundary.
            color (str, optional): The color of the boundary. Defaults to "lightgray".
            parent_boundary_obj (Optional[Boundary], optional): The parent Boundary object. Defaults to None.
            **kwargs: Additional properties for the boundary.

        Returns:
            Boundary: The created Boundary object.
        """
        boundary = Boundary(name)

        # Explicitly set isTrusted on the pytm.Boundary object if provided in kwargs
        if 'isTrusted' in kwargs:
            boundary.isTrusted = kwargs['isTrusted']

        # HACK: Add dummy attributes to Boundary objects to allow them to be
        # used as sources/sinks in Dataflows. The underlying pytm library
        # expects these attributes to exist on dataflow endpoints, which
        # this patch provides.
        boundary.protocol = ""
        boundary.port = None
        boundary.data = None

        if parent_boundary_obj:
            boundary.inBoundary = parent_boundary_obj

        # Store boundary with all properties including color and any additional kwargs
        boundary_props = {"boundary": boundary, "color": color}
        boundary_props.update(kwargs)  # Add any additional properties like isTrusted, isFilled

        self.boundaries[name.lower()] = boundary_props
        self._elements_by_name[name.lower()] = boundary
        return boundary

    def add_actor(self, name: str, boundary_name: Optional[str] = None, **kwargs) -> Actor:
        """Adds an actor to the model"""
        actor = Actor(name)
        boundary_obj = None
        if boundary_name and boundary_name.lower() in self.boundaries:
            boundary_obj = self.boundaries[boundary_name.lower()]["boundary"]
        if boundary_obj:
            actor.inBoundary = boundary_obj
        actor_props = {'name': name, 'object': actor, 'boundary': boundary_obj}
        actor_props.update(kwargs)
        self.actors.append(actor_props)
        self._elements_by_name[name.lower()] = actor
        return actor

    def add_server(self, name: str, boundary_name: Optional[str] = None, **kwargs) -> Server:
        """Adds a server to the model with optional color and is_filled attributes."""
        boundary_obj = None
        if boundary_name and boundary_name.lower() in self.boundaries:
            boundary_obj = self.boundaries[boundary_name.lower()]["boundary"]
        
        server = Server(name)
        if boundary_obj:
            server.inBoundary = boundary_obj
        server_props = {'name': name, 'object': server, 'boundary': boundary_obj}
        server_props.update(kwargs)
        self.servers.append(server_props)
        self._elements_by_name[name.lower()] = server
        return server

    def add_data(self, name: str, **kwargs) -> Data:
        """Adds a Data object to the model with additional properties.
        Properties are passed as keyword arguments and are transmitted
        directly to the pytm.Data constructor.
        """
        data_obj = Data(name, **kwargs)  # Passes **kwargs to the Data constructor
        self.data_objects[name.lower()] = data_obj
        logging.info(f"   - Added Data: {name} (Props: {kwargs})")  # Debugging
        logging.debug(f"DEBUG: Data object added with name: '{name}'") # New debug log
        return data_obj

    def add_dataflow(self, from_element: Any, to_element: Any, name :str,
            protocol: str, data_name: Optional[str] = None,
            is_authenticated: bool = False,
            is_encrypted: bool = False) -> Dataflow:
        """Adds a dataflow to the model"""
        data_objects = []
        if data_name:
            data_object = self.data_objects.get(data_name.lower())
            if data_object:
                data_objects.append(data_object)
            else:
                logging.warning(f"⚠️ Warning: Data object '{data_name}' not found for dataflow '{name}'.")

        dataflow = Dataflow(
            from_element,
            to_element,
            name,
            protocol=protocol,
            data=data_objects,  # Always pass a list
            is_authenticated=is_authenticated,
            is_encrypted=is_encrypted
        )
        self.dataflows.append(dataflow)
        self._elements_by_name[name.lower()] = dataflow # Add dataflow to elements by name
        return dataflow

    def add_protocol_style(self, protocol_name: str, **style_kwargs):
        """
        Adds styling information for a specific protocol.
        
        Args:
            protocol_name (str): Name of the protocol (e.g., "HTTPS", "TCP", "UDP")
            **style_kwargs: Style properties like:
                - color (str): Color for the protocol lines
                - line_style (str): Style of the line (solid, dashed, dotted, etc.)
                - width (int/float): Line width
                - arrow_style (str): Arrow style for dataflows
                - etc.
        
        Example:
            add_protocol_style("HTTPS", color="green", line_style="solid", width=2)
            add_protocol_style("HTTP", color="red", line_style="dashed", width=1)
        """
        self.protocol_styles[protocol_name] = style_kwargs
        logging.info(f"✅ Protocol style added for {protocol_name}: {style_kwargs}")

    def get_protocol_style(self, protocol_name: str) -> Optional[Dict[str, Any]]:
        """
        Retrieves the style configuration for a given protocol.
        
        Args:
            protocol_name (str): Name of the protocol
            
        Returns:
            Dict[str, Any]: Style configuration dictionary or None if not found
        """
        return self.protocol_styles.get(protocol_name)

    def get_all_protocol_styles(self) -> Dict[str, Dict[str, Any]]:
        """
        Returns all protocol styles defined in the model.
        
        Returns:
            Dict[str, Dict[str, Any]]: All protocol styles
        """
        return self.protocol_styles.copy()

    def get_element_by_name(self, name: str) -> Optional[Any]:
        """Retrieves an element (Actor, Server, Boundary) by its name."""
        element = self._elements_by_name.get(name.lower())
        if element:
            return element
        # Also check boundaries
        boundary_info = self.boundaries.get(name.lower())
        if boundary_info:
            return boundary_info.get('boundary')
        return self.data_objects.get(name.lower())

    def process_threats(self) -> Dict[str, List[Tuple[Any, Any]]]:
        """Executes PyTM threat analysis, filters, and groups the results with MITRE mapping."""
        
        # --- Model Validation ---
        validator = ModelValidator(self)
        errors = validator.validate()
        if errors:
            for error in errors:
                logging.error(f"❌ Model Validation Error: {error}")
            # Stop processing if validation fails
            return {}

        self.tm.process()

        pytm_raw_threats = []
        try:
            pytm_raw_threats = self.tm._threats
        except AttributeError:
            logging.warning("⚠️ Could not retrieve PyTM threats from tm._threats.")

        # --- Post-processing: expand class targets to all instances ---
        expanded_pytm_threats = self._expand_class_targets(pytm_raw_threats)

        # --- Generate and add custom threats ---
        custom_threats_tuples = self._apply_custom_threats()

        # Combine filtered PyTM threats with custom threats
        self.threats_raw = expanded_pytm_threats + custom_threats_tuples

        # Normalization and grouping of threats
        self.grouped_threats = self._group_threats()

        # MITRE ATT&CK Analysis
        self._perform_mitre_analysis()

        return self.grouped_threats

    def _apply_custom_threats(self) -> List[Tuple[CustomThreat, Any]]:
        """
        Applies custom threats to the threat model and returns them.
        """
        
        custom_threats_list = get_custom_threats(self)
        
        generated_custom_threats = []

        for threat_dict in custom_threats_list:
            target_name = threat_dict.get('component')
            target_obj = self.get_element_by_name(target_name)
            if target_obj:
                custom_threat = CustomThreat(
                    name=threat_dict['description'],
                    description=threat_dict['description'],
                    stride_category=threat_dict['stride_category'],
                    impact=threat_dict['impact'],
                    likelihood=threat_dict['likelihood'],
                    target=target_obj,
                    capec_ids=threat_dict.get('capec_ids')
                )
                
                # Calculate and store severity for custom threats
                threat_type = custom_threat.stride_category
                target_name_for_severity = getattr(target_obj, 'name', 'Unknown')
                protocol = getattr(target_obj, 'protocol', None) if isinstance(target_obj, Dataflow) else None
                classification = None
                if isinstance(target_obj, Dataflow) and hasattr(target_obj, 'data') and target_obj.data:
                    # Assuming dataflows carry a single data object for simplicity in this context
                    data_obj = next(iter(custom_threat.target.data)) # Get the first data object from the DataSet
                    if hasattr(data_obj, 'classification'):
                        classification = data_obj.classification.name # Get string representation of enum

                custom_threat.severity_info = self.severity_calculator.get_severity_info(
                    threat_type=threat_type,
                    target_name=target_name_for_severity,
                    protocol=protocol,
                    classification=classification,
                    impact=custom_threat.impact,
                    likelihood=custom_threat.likelihood
                )

                generated_custom_threats.append((custom_threat, target_obj))
        
        return generated_custom_threats

    def _expand_class_targets(self, threats: List[Any]) -> List[Tuple[Any, Any]]:
        """
        Expands threats that target a class (e.g., Server, Actor) into separate threats
        for each instance of that class in the model.
        This method is now generic and uses the _component_collections registry.
        """
        expanded_threats = []
        for threat in threats:
            target = getattr(threat, 'target', None)

            if isinstance(target, type) and target in self._component_collections:
                collection = self._component_collections[target]
                for item_info in collection:
                    instance = item_info['object']
                    new_threat = threat.__class__(**threat.__dict__)
                    new_threat.target = instance
                    expanded_threats.append((new_threat, instance))
            else:
                expanded_threats.append((threat, target))
        
        return expanded_threats

    def _group_threats(self) -> Dict[str, List[Tuple[Any, Any]]]:
        """Groups threats by type, skipping threats with unresolved targets."""
        grouped = defaultdict(list)

        for t in self.threats_raw:
            # threats_raw should now consistently contain (threat, target) tuples
            threat, target = t

            # Filter out threats with unresolved targets if necessary (e.g., target is None)
            if target is None or (isinstance(target, tuple) and any(x is None for x in target)):
                continue

            # Use the stride_category from the threat object if available, otherwise infer from class name
            stride_category = getattr(threat, 'stride_category', str(threat.__class__.__name__))
            grouped[stride_category].append((threat, target))

        return grouped
    
    def _perform_mitre_analysis(self):
        """Performs MITRE ATT&CK analysis on all detected threats"""
        
        
        # Analyze threats using the MITRE mapper
        self.mitre_analysis_results = self.mitre_mapper.analyze_pytm_threats_list(self.threats_raw)
        
        # Create individual mappings for each threat
        for processed_threat in self.mitre_analysis_results["processed_threats"]:
            # Ensure target is a string for the key, handling tuples and None
            if processed_threat['target'] is None:
                target_str = "Unspecified"
            elif isinstance(processed_threat['target'], tuple):
                # Handle tuples (e.g., dataflow targets or single element wrapped in tuple)
                if len(processed_threat['target']) >= 2:
                    source_obj = processed_threat['target'][0]
                    dest_obj = processed_threat['target'][1]
                    source_name = getattr(source_obj, 'name', "Unspecified") if source_obj else "Unspecified"
                    dest_name = getattr(dest_obj, 'name', "Unspecified") if dest_obj else "Unspecified"
                    target_str = f"{source_name} → {dest_name}"
                elif len(processed_threat['target']) == 1:
                    # If it's a tuple with a single element, treat it as a single target
                    single_obj = processed_threat['target'][0]
                    target_str = getattr(single_obj, 'name', "Unspecified") if single_obj else "Unspecified"
                else:
                    # Empty tuple or other unexpected case
                    target_str = "Unspecified"
            else:
                # Handle single objects with a 'name' attribute
                target_str = getattr(processed_threat['target'], 'name', "Unspecified")
            threat_key = f"{processed_threat['threat_name']}_{target_str}"
            self.threat_mitre_mapping[threat_key] = {
                "stride_category": processed_threat["stride_category"],
                "mitre_tactics": processed_threat["mitre_tactics"],
                "mitre_techniques": processed_threat["mitre_techniques"],
                "severity_info": processed_threat.get("severity_info") # Add severity info to mapping
            }

    def get_statistics(self) -> Dict[str, int]:
        """Returns the model statistics"""
        return {
            "total_threats": len(self.threats_raw),
            "threat_types": len(self.grouped_threats),
            "actors": len(self.actors),
            "servers": len(self.servers),
            "dataflows": len(self.dataflows),
            "boundaries": len(self.boundaries),
            "protocol_styles": len(self.protocol_styles),
            "mitre_techniques_count": self.mitre_analysis_results.get("mitre_techniques_count", 0)
        }

    def add_severity_multiplier(self, element_name: str, multiplier: float):
        """Adds a severity multiplier for a given element."""
        self.severity_multipliers[element_name] = multiplier
        


    def add_custom_mitre_mapping(self, attack_name: str, tactics: List[str], techniques: List[Dict[str, str]]):
        """
        Adds a custom MITRE mapping.
        tactics: A list of MITRE ATT&CK tactic names.
        techniques: A list of dictionaries, each with 'id' and 'name' for techniques.
        """
        self.custom_mitre_mappings[attack_name] = {
            "tactics": tactics,
            "techniques": techniques
        }

    def get_all_threats_details(self) -> List[Dict[str, Any]]:
        """
        Returns a detailed list of all threats from the latest analysis results.
        """
        if not self.mitre_analysis_results:
            self.process_threats()

        # The processed_threats list already contains what we need.
        # We just need to rename some keys to match what AttackNavigatorGenerator expects.
        
        detailed_threats = []
        for threat_data in self.mitre_analysis_results.get("processed_threats", []):
            # The target can be an object or a tuple of objects. We need a string representation.
            target = threat_data.get('target')
            if target is None:
                target_str = "Unspecified"
            elif isinstance(target, tuple):
                if len(target) >= 2:
                    source_name = getattr(target[0], 'name', "Unknown")
                    dest_name = getattr(target[1], 'name', "Unknown")
                    # Explicitly cast to str() to handle pytm.varString objects
                    target_str = f"{str(source_name)} -> {str(dest_name)}"
                elif len(target) == 1:
                     # Explicitly cast to str()
                     target_str = str(getattr(target[0], 'name', "Unknown"))
                else:
                    target_str = "Unknown"
            else:
                # Explicitly cast to str()
                target_str = str(getattr(target, 'name', 'Unknown'))

            detailed_threats.append({
                "description": threat_data.get("threat_name"),
                "target": target_str,
                "stride_category": threat_data.get("stride_category"),
                "mitre_techniques": threat_data.get("mitre_techniques", []),
                "severity": threat_data.get("severity_info", {}),
            })
            
        return detailed_threats