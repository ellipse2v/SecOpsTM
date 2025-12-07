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
from pathlib import Path
from typing import Tuple

# Define project root
PROJECT_ROOT = Path(__file__).resolve().parents[2]

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

def _validate_path_within_project(input_path: str, base_dir: Path = PROJECT_ROOT) -> Path:
    """
    Validates if an input path is within the specified base directory (project root by default).
    Raises ValueError if the path is outside the base directory or does not exist.
    """
    path_obj = Path(input_path)
    if not path_obj.exists():
        raise ValueError(f"Path does not exist: {input_path}")

    resolved_path = path_obj.resolve()
    if not resolved_path.is_relative_to(base_dir):
        raise ValueError(f"Path is outside the allowed project directory: {input_path}")

    return resolved_path
