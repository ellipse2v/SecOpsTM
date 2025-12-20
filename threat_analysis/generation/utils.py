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
Utility functions for threat analysis generation modules
"""
from typing import Any, Union


def extract_name_from_object(obj: Any) -> str:
    """
    Extracts a name from an object in a robust way, handling various object types.
    
    Args:
        obj: The object from which to extract the name
        
    Returns:
        str: The extracted name, or "Unspecified" if no name can be determined
        
    Handles:
        - Objects with a 'name' attribute
        - String objects
        - Tuple objects (unwraps single-element tuples)
        - None values
    """
    if isinstance(obj, tuple) and len(obj) == 1:
        obj = obj[0]
    
    if obj is None:
        return "Unspecified"
    
    try:
        # Try to get the name attribute and convert to string
        return str(obj.name)
    except AttributeError:
        # If no name attribute, check if it's a string
        if isinstance(obj, str):
            return obj
        return "Unspecified"


def get_target_name(target: Any) -> str:
    """
    Determines the target name, handling different target types including dataflows.
    
    Args:
        target: The target object (can be a single object, tuple of objects, or dataflow)
        
    Returns:
        str: A string representation of the target name
        
    Handles:
        - Single objects: returns their name
        - Tuples of 2 objects: returns "source → destination" format
        - Dataflow objects with source/sink attributes
        - None values
    """
    if isinstance(target, tuple):
        if len(target) == 2:
            source, sink = target
            
            # Handle dataflow objects that have source/sink attributes
            if hasattr(source, 'source') and hasattr(source, 'sink'):
                source_name = extract_name_from_object(source.source)
            else:
                source_name = extract_name_from_object(source)
                
            if hasattr(sink, 'source') and hasattr(sink, 'sink'):
                dest_name = extract_name_from_object(sink.sink)
            else:
                dest_name = extract_name_from_object(sink)
                
            return f"{source_name} → {dest_name}"
        elif len(target) == 1:
            # Handle single-element tuples (e.g., dataflow objects wrapped in tuple)
            single_obj = target[0]
            if hasattr(single_obj, 'source') and hasattr(single_obj, 'sink'):
                # This is a dataflow object
                source_name = extract_name_from_object(single_obj.source)
                dest_name = extract_name_from_object(single_obj.sink)
                return f"{source_name} → {dest_name}"
    
    # For single objects or other cases
    return extract_name_from_object(target)