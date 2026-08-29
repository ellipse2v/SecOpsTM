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
import threading
from contextlib import contextmanager
from typing import Optional

from threat_analysis.core.models_module import ThreatModel
from threat_analysis.core.model_parser import ModelParser
from threat_analysis.core.model_validator import ModelValidator
from threat_analysis.core.mitre_mapping_module import MitreMapping
from threat_analysis.core.cve_service import CVEService

# pytm >= 1.4.0 keeps TM's element/flow registries in a class-level ClassVar
# shared across the whole process (see the TM.reset() comment in
# core/models_module.py). Two concurrent requests each building a ThreatModel
# would otherwise race: one's TM.reset() can wipe the other's parsed state
# before it gets to call process_threats(). This lock serializes the
# create_threat_model() + process_threats() pair across every caller.
#
# RLock, not Lock: defensive against a future call site nesting (an outer
# method delegating to an inner one that also acquires this lock on the same
# thread) — a plain Lock would deadlock the moment that happens. No current
# call site actually nests (every acquisition wraps a single create+process
# pair with nothing else lock-acquiring in between), but RLock costs nothing
# extra and removes an entire class of future deadlock bugs.
_pytm_build_lock = threading.RLock()
_PYTM_LOCK_TIMEOUT_S = 30  # avoid hanging forever if something holds it too long


@contextmanager
def pytm_build_lock():
    """Serializes pytm model construction/processing across threads — see the
    module-level comment above `_pytm_build_lock` for why this exists. Wrap
    every `create_threat_model(...)` call (and any `process_threats()` call on
    its result) in `with pytm_build_lock():`.

    Raises TimeoutError if the lock can't be acquired within
    `_PYTM_LOCK_TIMEOUT_S` seconds (another request is taking unusually long).
    """
    acquired = _pytm_build_lock.acquire(timeout=_PYTM_LOCK_TIMEOUT_S)
    if not acquired:
        raise TimeoutError(
            "Another analysis is currently in progress — please retry in a few seconds."
        )
    try:
        yield
    finally:
        _pytm_build_lock.release()


def create_threat_model(
    markdown_content: str,
    model_name: str,
    model_description: str,
    cve_service: CVEService,
    validate: bool = True,
    model_file_path: Optional[str] = None,
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
        if model_file_path:
            threat_model._model_file_path = model_file_path
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
