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
Centralized factory for creating and validating ThreatModel objects.
"""
import logging
from typing import Optional

from threat_analysis.core.models_module import ThreatModel
from threat_analysis.core.model_parser import ModelParser
from threat_analysis.core.model_validator import ModelValidator
from threat_analysis.core.mitre_mapping_module import MitreMapping
from threat_analysis.core.cve_service import CVEService


def create_threat_model(
    markdown_content: str,
    model_name: str,
    model_description: str,
    cve_service: CVEService,
    validate: bool = True,
) -> Optional[ThreatModel]:
    """
    Creates, parses, and optionally validates a ThreatModel from Markdown content.

    Args:
        markdown_content: The Markdown content of the threat model.
        model_name: The name of the threat model.
        model_description: The description of the threat model.
        cve_service: An instance of the CVEService.
        validate: Whether to validate the model after parsing.

    Returns:
        A ThreatModel object if successful, otherwise None.
    """
    try:
        threat_model = ThreatModel(
            model_name,
            model_description,
            cve_service=cve_service
        )
        # The MitreMapping object is now created inside ThreatModel, so we get it from there
        parser = ModelParser(threat_model, threat_model.mitre_mapper)
        parser.parse_markdown(markdown_content)
        logging.info(f"✅ Model '{model_name}' loaded successfully.")

        if validate:
            logging.info("🛡️ Validating model...")
            validator = ModelValidator(threat_model)
            errors = validator.validate()
            if errors:
                logging.error("❌ Model validation failed.")
                for error in errors:
                    logging.error(f"  - {error}")
                return None
            logging.info("✅ Model validation successful.")

        return threat_model

    except Exception as e:
        logging.error(f"❌ Error creating threat model: {e}")
        return None
