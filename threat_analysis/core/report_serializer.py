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
ReportSerializer — produces a schema_version:"1.0" compliant dict from a
ThreatModel instance and the list of normalised threat dicts returned by
ReportGenerator._get_all_threats_with_mitre_info().

The output validates against:
  threat_analysis/schemas/v1/threat_model_report.schema.json
"""

from datetime import datetime
from typing import Any, Dict, List


class ReportSerializer:
    SCHEMA_VERSION = "1.0"

    @staticmethod
    def serialize(threat_model: Any, all_detailed_threats: List[Dict]) -> Dict:
        """
        Build and return the canonical report dict.

        Args:
            threat_model:         ThreatModel instance (after process_threats()).
            all_detailed_threats: Output of ReportGenerator._get_all_threats_with_mitre_info().

        Returns:
            A dict that validates against schemas/v1/threat_model_report.schema.json.
        """
        return {
            "schema_version": ReportSerializer.SCHEMA_VERSION,
            "generated_at": datetime.now().isoformat(),
            "model": ReportSerializer._serialize_model(threat_model),
            "threats": [
                ReportSerializer._serialize_threat(t, i)
                for i, t in enumerate(all_detailed_threats)
            ],
            "statistics": ReportSerializer._statistics(all_detailed_threats),
        }

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _serialize_model(threat_model: Any) -> Dict:
        actors = [
            {
                "name": d.get("name", ""),
                "boundary": ReportSerializer._boundary_name(d.get("object")),
                "business_value": d.get("business_value"),
            }
            for d in threat_model.actors
        ]
        servers = [
            {
                "name": d.get("name", ""),
                "boundary": ReportSerializer._boundary_name(d.get("object")),
                "business_value": d.get("business_value"),
            }
            for d in threat_model.servers
        ]
        dataflows = [
            {
                "name": str(getattr(df, "name", "")),
                "from": ReportSerializer._element_name(getattr(df, "source", None)),
                "to": ReportSerializer._element_name(getattr(df, "sink", None)),
                "protocol": str(getattr(df, "protocol", "") or "") or None,
            }
            for df in threat_model.dataflows
        ]
        boundaries = [
            {"name": str(name), "color": info.get("color")}
            for name, info in threat_model.boundaries.items()
        ]
        return {
            "name": str(threat_model.tm.name),
            "description": str(threat_model.tm.description or ""),
            "components": {
                "actors": actors,
                "servers": servers,
                "dataflows": dataflows,
                "boundaries": boundaries,
            },
        }

    @staticmethod
    def _serialize_threat(t: Dict, index: int) -> Dict:
        severity = t.get("severity") or {}
        return {
            "id": f"T-{index + 1:04d}",
            "description": str(t.get("description", "")),
            "source": t.get("source", "pytm"),
            "stride_category": t.get("stride_category", ""),
            "target": str(t.get("target", "")),
            "severity": {
                "score": severity.get("score"),
                "level": severity.get("level"),
                "formatted_score": severity.get("formatted_score"),
            },
            "confidence": t.get("confidence"),
            "mitre_techniques": t.get("mitre_techniques", []),
            "capecs": t.get("capecs", []),
            "cve": t.get("cve", []),
            "business_value": t.get("business_value"),
        }

    @staticmethod
    def _statistics(threats: List[Dict]) -> Dict:
        by_source: Dict[str, int] = {}
        by_stride: Dict[str, int] = {}
        by_severity: Dict[str, int] = {}
        for t in threats:
            src = t.get("source", "unknown")
            by_source[src] = by_source.get(src, 0) + 1
            cat = t.get("stride_category", "unknown")
            by_stride[cat] = by_stride.get(cat, 0) + 1
            level = (t.get("severity") or {}).get("level", "UNKNOWN")
            by_severity[level] = by_severity.get(level, 0) + 1
        return {
            "total": len(threats),
            "by_source": by_source,
            "by_stride_category": by_stride,
            "by_severity_level": by_severity,
        }

    @staticmethod
    def _boundary_name(element: Any) -> Any:
        """Return the boundary name of a pytm element, or None."""
        boundary = getattr(element, "inBoundary", None)
        if boundary is None:
            return None
        return str(getattr(boundary, "name", ""))

    @staticmethod
    def _element_name(element: Any) -> Any:
        if element is None:
            return None
        return str(getattr(element, "name", ""))
