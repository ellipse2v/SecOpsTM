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

import os
import re
import json
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# Define project root
PROJECT_ROOT = Path(__file__).resolve().parents[2]

def extract_json_from_llm_response(text: str) -> Optional[str]:
    """Extracts a JSON object or array from an LLM response that may be wrapped
    in markdown code fences or contain surrounding prose.

    Handles both ``{...}`` objects and ``[...]`` arrays.
    Returns the extracted JSON string, or None if no valid JSON is found.
    """
    # 1. Prefer JSON inside markdown code fences (```json ... ``` or ``` ... ```)
    match = re.search(r"```(?:json)?\s*([\s\S]*?)\s*```", text, re.DOTALL)
    if match:
        candidate = match.group(1).strip()
        try:
            json.loads(candidate)
            return candidate
        except json.JSONDecodeError:
            pass  # fence content wasn't valid JSON, fall through

    # 2. Fallback: find the outermost [...] or {...} in the raw text.
    # Arrays take priority because most AI threat outputs are lists.
    start_bracket = text.find("[")
    start_brace = text.find("{")

    if start_bracket == -1 and start_brace == -1:
        return None

    if start_bracket != -1 and (start_brace == -1 or start_bracket < start_brace):
        start_index, end_char = start_bracket, "]"
    else:
        start_index, end_char = start_brace, "}"

    end_index = text.rfind(end_char)
    if end_index <= start_index:
        return None

    candidate = text[start_index: end_index + 1]
    try:
        json.loads(candidate)
        return candidate
    except (json.JSONDecodeError, TypeError):
        return None


def resolve_path(
    path: str,
    base_dir: Path,
    default_filename: str
) -> Tuple[Path, bool]:
    """
    Resolves a file path.
    If the path is explicitly provided, it resolves it.
    Otherwise, it returns the default path.
    Returns the resolved path and a boolean indicating if the path was explicit.
    """
    is_explicit = path is not None
    if is_explicit:
        return Path(path), True
    return base_dir / default_filename, False

def compare_threat_reports(old: dict, new: dict) -> dict:
    """Compare two versioned JSON threat reports.

    Threats are keyed by ``(target, stride_category, name)``.

    Returns a dict with keys:
    - ``added``:   list of threat dicts present in *new* but not in *old*
    - ``resolved``: list of threat dicts present in *old* but not in *new*
    - ``changed``: list of dicts ``{"old": ..., "new": ...}`` where severity changed
    - ``summary``: ``{"added": N, "resolved": N, "changed": N}``
    """

    def _key(t: dict) -> tuple:
        return (
            t.get("target", ""),
            t.get("stride_category", ""),
            t.get("name", ""),
        )

    old_threats: Dict[tuple, dict] = {_key(t): t for t in old.get("threats", [])}
    new_threats: Dict[tuple, dict] = {_key(t): t for t in new.get("threats", [])}

    added: List[dict] = [t for k, t in new_threats.items() if k not in old_threats]
    resolved: List[dict] = [t for k, t in old_threats.items() if k not in new_threats]
    changed: List[dict] = [
        {"old": old_threats[k], "new": new_threats[k]}
        for k in old_threats
        if k in new_threats and old_threats[k].get("severity") != new_threats[k].get("severity")
    ]

    return {
        "added": added,
        "resolved": resolved,
        "changed": changed,
        "summary": {
            "added": len(added),
            "resolved": len(resolved),
            "changed": len(changed),
        },
    }


def _validate_path_within_project(input_path: str, base_dir: Path = PROJECT_ROOT) -> Path:
    """
    Validates if an input path is within the specified base directory (project root by default).
    Raises ValueError if the path is outside the base directory or does not exist.
    """
    path_obj = Path(input_path)
    if not path_obj.exists():
        listing = []
        for root, dirs, files in os.walk(base_dir):
            level = str(Path(root).relative_to(base_dir)).count(os.sep) if Path(root) != base_dir else 0
            indent = ' ' * 4 * level
            listing.append(f'{indent}{os.path.basename(root)}/')
            subindent = ' ' * 4 * (level + 1)
            for f in files:
                listing.append(f'{subindent}{f}')
        dir_listing = "\n".join(listing)
        raise ValueError(f"Path does not exist: {input_path}. Project directory structure:\n{dir_listing}")

    resolved_path = path_obj.resolve()
    base_dir_resolved = base_dir.resolve()
    if not resolved_path.is_relative_to(base_dir_resolved):
        raise ValueError(f"Path is outside the allowed project directory: {input_path} (Base: {base_dir_resolved})")

    return path_obj


def resolve_gdaf_context(threat_model) -> Optional[str]:
    """Resolve the GDAF context file path for a given threat model.
    
    Priority order:
    1. `gdaf_context` key in the model's ## Context DSL section
    2. `{model_parent}/context/` directory (first .yaml/.yml found)
    
    Returns the resolved path as a string, or None if no context file is found.
    """
    import logging
    
    ctx_cfg = getattr(threat_model, "context_config", {})
    dsl_path = ctx_cfg.get("gdaf_context")
    model_path = getattr(threat_model, "_model_file_path", None)
    
    if dsl_path:
        # Resolve relative to model file directory first
        if model_path:
            p = Path(model_path).parent / dsl_path
            if p.exists():
                logging.info("GDAF: using context from DSL ## Context: %s", p)
                return str(p)
        p = Path(dsl_path)
        if p.exists():
            logging.info("GDAF: using context from DSL ## Context: %s", p)
            return str(p)
        logging.warning("GDAF: gdaf_context '%s' declared in ## Context but file not found", dsl_path)
    
    # Check model parent context/ subdirectory
    if model_path:
        context_dir = Path(model_path).parent / "context"
        if context_dir.exists():
            yaml_files = list(context_dir.glob("*.yaml")) + list(context_dir.glob("*.yml"))
            if yaml_files:
                logging.info("GDAF: using context from model context/ dir: %s", yaml_files[0])
                return str(yaml_files[0])
    
    return None


def resolve_bom_directory(threat_model) -> Optional[str]:
    """Resolve BOM directory: DSL ## Context bom_directory → {model_parent}/BOM/ → None."""
    import logging
    
    ctx_cfg = getattr(threat_model, "context_config", {})
    dsl_path = ctx_cfg.get("bom_directory")
    model_path = getattr(threat_model, "_model_file_path", None)
    
    if dsl_path:
        # Resolve relative to model file directory first
        if model_path:
            p = Path(model_path).parent / dsl_path
            if p.exists():
                logging.info("BOM: using context from DSL ## Context: %s", p)
                return str(p)
        p = Path(dsl_path)
        if p.exists():
            logging.info("BOM: using context from DSL ## Context: %s", p)
            return str(p)
        logging.warning("BOM: bom_directory '%s' declared in ## Context but not found", dsl_path)
    
    # Auto-discover from model file parent
    if model_path:
        bom_dir = Path(model_path).parent / "BOM"
        if bom_dir.exists() and bom_dir.is_dir():
            n_files = len(list(bom_dir.glob("*.json")) + list(bom_dir.glob("*.yaml")) + list(bom_dir.glob("*.yml")))
            logging.info("BOM: auto-discovered %s (%d asset file(s))", bom_dir, n_files)
            return str(bom_dir)
    return None


def run_gdaf_engine(threat_model, export_path=None, progress_callback=None):
    """Run GDAF engine on a threat model and attach scenarios.
    
    This is a common function used by:
    - SecOpsTMFramework.generate_reports() (CLI --model-file mode)
    - ExportService.export_single_file_logic() (Server mode)
    - ReportGenerator.generate_project_reports() (Project mode)
    
    Args:
        threat_model: ThreatModel instance
        export_path: Optional path to save Attack Flow files (Path or str)
        progress_callback: Optional callback function(progress_percent, message) 
                          called after confirming context file exists
    
    Returns:
        List of AttackScenario objects, or empty list if none generated
    """
    import logging
    try:
        from threat_analysis.core.gdaf_engine import GDAFEngine
        from threat_analysis.generation.attack_flow_builder import AttackFlowBuilder
        
        _context_path = resolve_gdaf_context(threat_model)
        if not _context_path:
            logging.debug("GDAF: no context file found, skipping.")
            return []
        
        if progress_callback:
            progress_callback(94, "Running GDAF cross-model analysis...")
        
        _bom_dir = resolve_bom_directory(threat_model)
        _extra = getattr(threat_model, "sub_models", [])
        
        _gdaf = GDAFEngine(threat_model, _context_path, extra_models=_extra, bom_directory=_bom_dir)
        _scenarios = _gdaf.run()
        
        if _scenarios:
            threat_model.gdaf_scenarios = _scenarios
            
            # Generate Attack Flow files if export_path provided
            if export_path:
                _builder = AttackFlowBuilder(_scenarios, model_name=str(threat_model.tm.name))
                _builder.generate_and_save(str(export_path))
            
            logging.info("GDAF: generated %d attack scenarios", len(_scenarios))
        else:
            logging.info("GDAF: no scenarios produced (check context attack_objectives/threat_actors)")
        
        return _scenarios
    
    except Exception as e:
        logging.warning("GDAF generation skipped (non-fatal): %s", e)
        return []
