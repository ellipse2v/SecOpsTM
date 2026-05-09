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
STRIDE Threat Analysis Library with MITRE ATT&CK Integration
"""

try:
    from importlib.metadata import version as _pkg_version
    __version__ = _pkg_version("SecOpsTM")
except Exception:
    __version__ = "unknown"

__author__ = "ellipse2v"

__all__ = [
    'ThreatModel',
    'MitreMapping',
    'SeverityCalculator',
    'ReportGenerator',
    'DiagramGenerator',
    'ModelParser',
    'data_loader',
]

_lazy_map = {
    'ThreatModel':          ('.core.models_module',          'ThreatModel'),
    'MitreMapping':         ('.core.mitre_mapping_module',   'MitreMapping'),
    'SeverityCalculator':   ('.severity_calculator_module',  'SeverityCalculator'),
    'ReportGenerator':      ('.generation.report_generator', 'ReportGenerator'),
    'DiagramGenerator':     ('.generation.diagram_generator','DiagramGenerator'),
    'ModelParser':          ('.core.model_parser',           'ModelParser'),
    'data_loader':          ('.core.data_loader',             None),
}


def __getattr__(name: str):
    if name not in _lazy_map:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    import importlib
    mod_path, attr = _lazy_map[name]
    mod = importlib.import_module(mod_path, package=__name__)
    obj = mod if attr is None else getattr(mod, attr)
    globals()[name] = obj
    return obj