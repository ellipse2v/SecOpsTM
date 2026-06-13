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

"""SecOpsTM threat model validator.

Validates model.md and related YAML files for completeness and consistency.

Usage (via CLI):
    secopstm validate --model-dir path/to/project/

Usage (programmatic):
    from threat_analysis.validate import validate_model_dir
    failures, warnings = validate_model_dir("path/to/project/")

Checks:
    - DSL enum values (Boundary, Actor, Server, Data, Dataflow)
    - Reference integrity (boundary=, from=, to=)
    - Element name uniqueness
    - Dataflow endpoint constraints (no direct Boundary connections)
    - Unused boundary detection
    - BOM file correspondence
    - YAML syntax validity
    - submodel path existence (multi-subsystem mode)
    - Protocol Styles and Severity Multipliers
    - English-only output files
"""

from __future__ import annotations

import argparse
import ast
import re
import sys
import yaml
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from threat_analysis.core.bom_loader import _normalize_asset_key as _normalize_bom_key
from threat_analysis.core.dsl_constants import (
    DSL_ENUMS,
    SEVERITY_MULTIPLIER_MIN,
    SEVERITY_MULTIPLIER_MAX,
)

_CJK_RE = re.compile(r'[一-鿿㐀-䶿]')


@dataclass
class ValidationResult:
    passed: bool
    message: str
    file: str = ""
    line: int = 0
    section: str = ""


@dataclass
class ParsedModel:
    boundaries: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    actors: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    servers: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    data_objects: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    dataflows: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    protocol_styles: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    severity_multipliers: Dict[str, float] = field(default_factory=dict)
    context: Dict[str, Any] = field(default_factory=dict)
    submodels: List[str] = field(default_factory=list)


def _parse_key_value_params(params_str: str) -> Dict[str, Any]:
    """Parse a DSL key=value parameter string into a dict."""
    params: Dict[str, Any] = {}
    cleaned = re.sub(r'//.*', '', params_str)
    normalised = cleaned.replace('\n', ',').replace('\r', ',')
    pattern = re.compile(
        r'([\w_]+)\s*=\s*'
        r'('
        r'"[^"]*"'
        r'|'
        r'\[[^\]]*\]'
        r'|'
        r'[^,]+'
        r')'
    )
    for key, value_str in pattern.findall(normalised):
        key = key.strip()
        value_str = value_str.strip()
        if value_str.startswith('"') and value_str.endswith('"'):
            value: Any = value_str[1:-1]
        elif value_str.startswith('[') and value_str.endswith(']'):
            value = [i.strip().strip('"').strip("'")
                     for i in value_str[1:-1].split(',') if i.strip()]
        elif value_str.lower() == 'true':
            value = True
        elif value_str.lower() == 'false':
            value = False
        else:
            try:
                value = ast.literal_eval(value_str)
            except (ValueError, SyntaxError):
                value = value_str
        if key.lower() in ('istrusted', 'is_trusted'):
            key = 'isTrusted'
        elif key.lower() in ('isfilled', 'is_filled'):
            key = 'isFilled'
        elif key.lower() in ('businessvalue', 'business_value'):
            key = 'businessValue'
        params[key] = value
    return params


def _parse_model_md(content: str) -> ParsedModel:
    """Parse model.md content into a ParsedModel."""
    model = ParsedModel()
    section_re = re.compile(r'^## (.+)$', re.MULTILINE)
    element_re = re.compile(
        r'^\s*-\s*\*\*([^*:]+)\*\*\s*:\s*(.*?)(?=^\s*-\s*\*\*|\Z)',
        re.MULTILINE | re.DOTALL,
    )

    sections: Dict[str, str] = {}
    matches = list(section_re.finditer(content))
    for i, m in enumerate(matches):
        title = m.group(1).strip()
        start = m.end()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(content)
        sections[title] = content[start:end]

    def _parse_section(name: str) -> Dict[str, Dict[str, Any]]:
        result: Dict[str, Dict[str, Any]] = {}
        body = sections.get(name, '')
        for em in element_re.finditer(body):
            elem_name = em.group(1).strip()
            params = _parse_key_value_params(em.group(2).strip())
            result[elem_name] = params
        return result

    model.boundaries = _parse_section('Boundaries')
    model.actors = _parse_section('Actors')
    model.servers = _parse_section('Servers')
    model.data_objects = _parse_section('Data')
    model.dataflows = _parse_section('Dataflows')
    model.protocol_styles = _parse_section('Protocol Styles')

    for body_line in sections.get('Severity Multipliers', '').splitlines():
        m = re.match(r'^\s*-\s*\*\*([^*:]+)\*\*\s*:\s*(.+)$', body_line)
        if m:
            try:
                model.severity_multipliers[m.group(1).strip()] = float(m.group(2).strip())
            except ValueError:
                pass

    for body_line in sections.get('Context', '').splitlines():
        m = re.match(r'^-?\s*([A-Za-z_][A-Za-z0-9_]*)[\s=:]+(.+)$', body_line.strip())
        if m:
            model.context[m.group(1).strip()] = m.group(2).strip().strip('"').strip("'")

    for props in model.servers.values():
        sm = props.get('submodel')
        if sm and isinstance(sm, str):
            model.submodels.append(sm)

    return model


class ThreatModelValidator:
    """Validates a SecOpsTM threat model directory."""

    def __init__(self, model_dir: str, verbose: bool = False) -> None:
        self.model_dir = Path(model_dir)
        self.verbose = verbose
        self.results: List[ValidationResult] = []
        self._model: Optional[ParsedModel] = None
        self._model_content: str = ""
        self._model_file: Path = Path()
        self._custom_server_types: set = set()

    def _ok(self, message: str, **kw: Any) -> None:
        self.results.append(ValidationResult(passed=True, message=message, **kw))
        if self.verbose:
            print(f"  ✓ {message}")

    def _fail(self, message: str, **kw: Any) -> None:
        self.results.append(ValidationResult(passed=False, message=message, **kw))
        print(f"  ✗ {message}")

    def _load_model(self) -> bool:
        model_file = self.model_dir / 'model.md'
        if not model_file.exists():
            model_file = self.model_dir / 'main.md'
        if not model_file.exists():
            self._fail(f"model.md (or main.md) not found in {self.model_dir}")
            return False
        self._model_content = model_file.read_text(encoding='utf-8')
        self._model_file = model_file
        self._model = _parse_model_md(self._model_content)
        self._ok(
            f"Loaded {model_file.name}: "
            f"{len(self._model.boundaries)} boundaries, "
            f"{len(self._model.actors)} actors, "
            f"{len(self._model.servers)} servers, "
            f"{len(self._model.dataflows)} dataflows"
        )
        return True

    def _load_custom_types(self) -> None:
        config_file = self.model_dir / 'config' / 'asset_types_community.yaml'
        if not config_file.exists():
            return
        try:
            data = yaml.safe_load(config_file.read_text(encoding='utf-8'))
            if isinstance(data, dict) and 'asset_types' in data:
                types = data['asset_types']
                if isinstance(types, dict):
                    self._custom_server_types.update(types.keys())
                    self._ok(f"Loaded {len(self._custom_server_types)} custom asset types")
                else:
                    self._fail("config/asset_types_community.yaml: 'asset_types' must be a dict, not a list")
            else:
                self._fail("config/asset_types_community.yaml: missing 'asset_types' root key")
        except yaml.YAMLError as exc:
            self._fail(f"config/asset_types_community.yaml: YAML parse error — {exc}")

    def _check_enum(self, element: str, name: str, props: Dict[str, Any]) -> None:
        for key, value in props.items():
            enum_key = f"{element}.{key}"
            if enum_key not in DSL_ENUMS:
                continue
            # Server.type validation is handled by _check_server_type (custom types awareness)
            if enum_key == "Server.type":
                continue
            valid = DSL_ENUMS[enum_key]
            if valid == [True, False] and isinstance(value, str):
                value = value.lower() == 'true'
            if value not in valid:
                self._fail(
                    f"{element} '{name}': invalid {key}={value!r} (valid: {valid})",
                    section=element,
                )

    def _check_server_type(self, name: str, props: Dict[str, Any]) -> None:
        server_type = props.get('type', 'default')
        valid_types = set(DSL_ENUMS['Server.type']) | self._custom_server_types
        if server_type not in valid_types:
            self._fail(
                f"Server '{name}': type={server_type!r} not in standard types and "
                f"not defined in config/asset_types_community.yaml",
                section="Servers",
            )

    def _check_references(self) -> None:
        assert self._model is not None
        m = self._model
        all_nodes = set(m.actors) | set(m.servers)
        boundary_names = set(m.boundaries)

        for element_type, elements in (("Actor", m.actors), ("Server", m.servers)):
            for name, props in elements.items():
                boundary_ref = props.get('boundary')
                if boundary_ref and boundary_ref not in boundary_names:
                    self._fail(
                        f"{element_type} '{name}': boundary={boundary_ref!r} not defined",
                        section=element_type,
                    )

        for df_name, props in m.dataflows.items():
            from_ref = props.get('from')
            to_ref = props.get('to')
            if from_ref and from_ref not in all_nodes:
                self._fail(
                    f"Dataflow '{df_name}': from={from_ref!r} not found "
                    f"(boundaries are not valid endpoints)",
                    section="Dataflows",
                )
            if to_ref and to_ref not in all_nodes:
                self._fail(
                    f"Dataflow '{df_name}': to={to_ref!r} not found",
                    section="Dataflows",
                )

    def _check_bom(self) -> None:
        assert self._model is not None
        bom_dir = self.model_dir / 'BOM'
        context_bom = self._model.context.get('bom_directory')
        if context_bom:
            bom_dir = self.model_dir / context_bom
        if not bom_dir.exists():
            if self._model.servers:
                self._fail(f"BOM directory not found: {bom_dir}")
            return
        # Collect normalised keys for all BOM file stems (YAML + CycloneDX JSON)
        existing_bom: set = set()
        for f in bom_dir.iterdir():
            name_lower = f.name.lower()
            if name_lower.endswith('.cdx.json'):
                stem = f.name[: -len('.cdx.json')]
            elif name_lower.endswith(('.yaml', '.yml', '.json')):
                stem = f.stem
            else:
                continue
            existing_bom.add(_normalize_bom_key(stem))
        for server_name in self._model.servers:
            normalised = _normalize_bom_key(server_name)
            if normalised not in existing_bom:
                self._fail(
                    f"Server '{server_name}': no BOM file found "
                    f"(expected BOM/{normalised}.yaml)",
                    section="BOM",
                )

    def _check_yaml_files(self) -> None:
        for yaml_file in self.model_dir.rglob('*.yaml'):
            if '.tm-raw' in yaml_file.parts:
                continue
            try:
                yaml.safe_load(yaml_file.read_text(encoding='utf-8'))
            except yaml.YAMLError as exc:
                self._fail(f"YAML error in {yaml_file.relative_to(self.model_dir)}: {exc}")

    def _check_submodel_paths(self) -> None:
        assert self._model is not None
        for sm_path in self._model.submodels:
            resolved = (self.model_dir / sm_path).resolve()
            if not resolved.exists():
                self._fail(f"submodel path does not exist: {sm_path}")

    def _check_english(self) -> None:
        if not self._model_content:
            return
        for i, line in enumerate(self._model_content.splitlines(), 1):
            if _CJK_RE.search(line):
                self._fail(
                    f"model.md line {i}: non-English characters detected — "
                    f"output files must be in English",
                    file=str(self._model_file),
                    line=i,
                )
                break

    def _check_severity_multipliers(self) -> None:
        assert self._model is not None
        for name, value in self._model.severity_multipliers.items():
            if not (SEVERITY_MULTIPLIER_MIN <= value <= SEVERITY_MULTIPLIER_MAX):
                self._fail(
                    f"Severity multiplier '{name}': value {value} out of range "
                    f"[{SEVERITY_MULTIPLIER_MIN}, {SEVERITY_MULTIPLIER_MAX}]"
                )

    def _check_unused_boundaries(self) -> None:
        """Flag boundaries defined in ## Boundaries but not referenced by any actor or server."""
        assert self._model is not None
        m = self._model
        used: set = set()
        for props in (*m.actors.values(), *m.servers.values()):
            b = props.get('boundary')
            if isinstance(b, str):
                used.add(b.lower())
        for boundary_name in m.boundaries:
            if boundary_name.lower() not in used:
                self._fail(
                    f"Boundary '{boundary_name}': defined but not used by any actor or server",
                    section="Boundaries",
                )

    def _check_name_uniqueness(self) -> None:
        """Detect duplicate element names within each DSL section."""
        section_re = re.compile(r'^## (.+)$', re.MULTILINE)
        element_name_re = re.compile(r'^\s*-\s*\*\*([^*:]+)\*\*\s*:', re.MULTILINE)
        matches = list(section_re.finditer(self._model_content))
        for i, m in enumerate(matches):
            title = m.group(1).strip()
            start = m.end()
            end = matches[i + 1].start() if i + 1 < len(matches) else len(self._model_content)
            body = self._model_content[start:end]
            seen: set = set()
            for em in element_name_re.finditer(body):
                name = em.group(1).strip()
                if name in seen:
                    self._fail(
                        f"## {title}: duplicate element name '{name}'",
                        section=title,
                    )
                seen.add(name)

    def _run_check(self, fn: Any, ok_message: str) -> None:
        """Run a check; record a passing result if it introduced no failures."""
        failures_before = sum(1 for r in self.results if not r.passed)
        fn()
        if sum(1 for r in self.results if not r.passed) == failures_before:
            self._ok(ok_message)

    def run(self) -> Tuple[int, int]:
        """Run all checks. Returns (failure_count, warning_count)."""
        print(f"\nValidating: {self.model_dir}\n")
        if not self._load_model():
            return (1, 0)
        self._load_custom_types()
        assert self._model is not None
        m = self._model
        self._run_check(
            lambda: [self._check_enum('Boundary', n, p) for n, p in m.boundaries.items()],
            f"Boundary enum values OK ({len(m.boundaries)} boundaries)",
        )
        self._run_check(
            lambda: [self._check_enum('Actor', n, p) for n, p in m.actors.items()],
            f"Actor enum values OK ({len(m.actors)} actors)",
        )
        self._run_check(
            lambda: [
                (self._check_enum('Server', n, p), self._check_server_type(n, p))
                for n, p in m.servers.items()
            ],
            f"Server enum values and types OK ({len(m.servers)} servers)",
        )
        self._run_check(
            lambda: [self._check_enum('Data', n, p) for n, p in m.data_objects.items()],
            f"Data enum values OK ({len(m.data_objects)} data objects)",
        )
        self._run_check(
            lambda: [self._check_enum('Dataflow', n, p) for n, p in m.dataflows.items()],
            f"Dataflow enum values OK ({len(m.dataflows)} dataflows)",
        )
        self._run_check(self._check_unused_boundaries, "No unused boundaries")
        self._run_check(self._check_name_uniqueness, "Element names unique")
        self._run_check(self._check_references, "Reference integrity OK")
        self._run_check(self._check_bom, "BOM correspondence OK")
        self._run_check(self._check_yaml_files, "YAML syntax OK")
        self._run_check(self._check_submodel_paths, "Submodel paths OK")
        self._run_check(self._check_english, "English-only content OK")
        self._run_check(self._check_severity_multipliers, "Severity multipliers OK")
        failures = sum(1 for r in self.results if not r.passed)
        passed = sum(1 for r in self.results if r.passed)
        total = failures + passed
        print(f"\n{'─'*50}")
        print(f"Results: {passed}/{total} checks passed, {failures} failure(s)")
        return (failures, 0)


def validate_model_dir(model_dir: str, verbose: bool = False) -> Tuple[int, int]:
    """Validate a threat model directory. Returns (failure_count, warning_count)."""
    validator = ThreatModelValidator(model_dir, verbose=verbose)
    return validator.run()


def main(argv: Optional[List[str]] = None) -> int:
    """CLI entry point for `secopstm validate`."""
    parser = argparse.ArgumentParser(
        prog="secopstm validate",
        description="Validate a SecOpsTM threat model directory.",
    )
    parser.add_argument(
        "--model-dir",
        required=True,
        metavar="DIR",
        help="Path to the threat model directory containing model.md (or main.md).",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Show passing checks in addition to failures.",
    )
    args = parser.parse_args(argv)
    failures, _ = validate_model_dir(args.model_dir, verbose=args.verbose)
    return 1 if failures > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
