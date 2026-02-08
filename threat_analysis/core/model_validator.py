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

from __future__ import annotations
from typing import List, Dict, Any, Set, TYPE_CHECKING

from pytm import Boundary

if TYPE_CHECKING:
    from threat_analysis.core.models_module import ThreatModel

class ModelValidator:
    """
    Validates a ThreatModel object for consistency and correctness.
    """

    def __init__(self, threat_model: ThreatModel):
        self.threat_model = threat_model
        self.errors: List[str] = []
        self.element_names: Set[str] = set()

    def validate(self) -> List[str]:
        """
        Runs all validation checks and returns a list of errors.
        """
        self.errors = []
        self.element_names = set()

        self._validate_unique_names()
        self._validate_unique_dataflow_names()
        self._validate_dataflow_references()
        self._validate_element_boundaries()
        self._validate_dataflow_endpoints()
        self._validate_unused_boundaries()

        return self.errors

    def _add_error(self, message: str):
        """Adds an error message to the list of errors."""
        self.errors.append(message)

    def _validate_unique_names(self):
        """
        Validates that all elements (actors, servers, boundaries, data) have unique names.
        """
        # Check actors
        for actor_info in self.threat_model.actors:
            name = actor_info.get('name')
            if name in self.element_names:
                self._add_error(f"Duplicate element name: '{name}' is already used.")
            self.element_names.add(name)

        # Check servers
        for server_info in self.threat_model.servers:
            name = server_info.get('name')
            if name in self.element_names:
                self._add_error(f"Duplicate element name: '{name}' is already used.")
            self.element_names.add(name)

        # Check boundaries
        for boundary_name in self.threat_model.boundaries:
            if boundary_name in self.element_names:
                self._add_error(f"Duplicate element name: '{boundary_name}' is already used.")
            self.element_names.add(boundary_name)

        # Check data
        for data_name in self.threat_model.data_objects:
            if data_name in self.element_names:
                self._add_error(f"Duplicate element name: '{data_name}' is already used.")
            self.element_names.add(name)


    def _validate_unique_dataflow_names(self):
        """
        Validates that all dataflows have unique names amongst themselves.
        """
        dataflow_names: Set[str] = set()
        for dataflow in self.threat_model.dataflows:
            name = dataflow.name
            if name in dataflow_names:
                self._add_error(f"Duplicate dataflow name: '{name}' is already used.")
            dataflow_names.add(name)


    def _validate_dataflow_references(self):
        """
        Validates that dataflows refer to existing elements and data.
        """
        all_element_names = {actor_info['name'].lower() for actor_info in self.threat_model.actors}
        all_element_names.update({server_info['name'].lower() for server_info in self.threat_model.servers})
        all_element_names.update({b.lower() for b in self.threat_model.boundaries})

        for dataflow in self.threat_model.dataflows:
            from_name = dataflow.source.name.lower()
            to_name = dataflow.sink.name.lower()

            if from_name not in all_element_names:
                self._add_error(f"Dataflow '{dataflow.name}' refers to a non-existent 'from' element: '{dataflow.source.name}'.")
            
            if to_name not in all_element_names:
                self._add_error(f"Dataflow '{dataflow.name}' refers to a non-existent 'to' element: '{dataflow.sink.name}'.")

            if dataflow.data:
                for data_item in dataflow.data:
                    if data_item.name.lower() not in self.threat_model.data_objects:
                        self._add_error(f"Dataflow '{dataflow.name}' refers to non-existent data: '{data_item.name}'.")

    def _validate_element_boundaries(self):
        """
        Validates that actors and servers refer to existing boundaries.
        """
        boundary_names = {b.lower() for b in self.threat_model.boundaries}

        for element_info in self.threat_model.actors:
            if hasattr(element_info, 'zone'):
                boundary_name = element_info.zone
                element_name = element_info.name
            else:
                boundary_val = element_info.get('boundary')
                if isinstance(boundary_val, str):
                    boundary_name = boundary_val
                elif isinstance(boundary_val, Boundary):
                    boundary_name = boundary_val.name
                else:
                    boundary_name = element_info.get('boundary_name')
                
                element_name = element_info['name']

            if boundary_name and boundary_name.lower() not in boundary_names:
                self._add_error(f"Actor '{element_name}' refers to a non-existent boundary: '{boundary_name}'.")

        for element_info in self.threat_model.servers:
            if hasattr(element_info, 'zone'):
                boundary_name = element_info.zone
                element_name = element_info.name
            else:
                boundary_val = element_info.get('boundary')
                if isinstance(boundary_val, str):
                    boundary_name = boundary_val
                elif isinstance(boundary_val, Boundary):
                    boundary_name = boundary_val.name
                else:
                    boundary_name = element_info.get('boundary_name')
                
                element_name = element_info['name']

            if boundary_name and boundary_name.lower() not in boundary_names:
                self._add_error(f"Server '{element_name}' refers to a non-existent boundary: '{boundary_name}'.")

    def _validate_dataflow_endpoints(self):
        """
        Validates that dataflows do not connect directly to boundaries.
        """
        for dataflow in self.threat_model.dataflows:
            if isinstance(dataflow.source, Boundary):
                self._add_error(f"Dataflow '{dataflow.name}' cannot originate directly from a boundary. The source must be an actor or a server.")
            if isinstance(dataflow.sink, Boundary):
                self._add_error(f"Dataflow '{dataflow.name}' cannot terminate directly at a boundary. The destination must be an actor or a server.")

    def _validate_unused_boundaries(self):
        """
        Validates that all boundaries are used by at least one element.
        """
        used_boundaries = set()
        for element_info in self.threat_model.actors:
            if hasattr(element_info, 'zone'):
                boundary_name = element_info.zone
            else:
                boundary_val = element_info.get('boundary')
                if isinstance(boundary_val, str):
                    boundary_name = boundary_val
                elif isinstance(boundary_val, Boundary):
                    boundary_name = boundary_val.name
                else:
                    boundary_name = element_info.get('boundary_name')

            if boundary_name:
                used_boundaries.add(boundary_name.lower())
        
        for element_info in self.threat_model.servers:
            if hasattr(element_info, 'zone'):
                boundary_name = element_info.zone
            else:
                boundary_val = element_info.get('boundary')
                if isinstance(boundary_val, str):
                    boundary_name = boundary_val
                elif isinstance(boundary_val, Boundary):
                    boundary_name = boundary_val.name
                else:
                    boundary_name = element_info.get('boundary_name')

            if boundary_name:
                used_boundaries.add(boundary_name.lower())

        defined_boundaries_map = {
            b_lower: self.threat_model.boundaries[b_lower].get("original_name", b_lower)
            for b_lower in self.threat_model.boundaries
        }

        unused_lower_names = defined_boundaries_map.keys() - used_boundaries

        for boundary_lower_name in unused_lower_names:
            # Explicitly ignore the default 'boundary' if it was not explicitly defined by the user
            if boundary_lower_name == "boundary":
                continue
            original_name = defined_boundaries_map[boundary_lower_name]
            self._add_error(f"Boundary '{original_name}' is defined but not used by any actor or server.")