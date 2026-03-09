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
Attack chain analysis — correlates threats across components via dataflows.

For each dataflow (source → sink), pairs the highest-severity threat on the source
with the highest-severity threat on the sink to model a pivot chain: an attacker
compromises the source component and uses the dataflow as a lateral-movement vector
to reach and exploit the sink.
"""

import logging
from typing import Any, Dict, List

logger = logging.getLogger(__name__)


class AttackChainAnalyzer:
    """Correlates per-component threats into multi-hop attack chains via dataflows."""

    def analyze(self, all_threats: List[Dict], dataflows: List[Any]) -> List[Dict]:
        """Return a list of attack-chain dicts, one per dataflow with threats on both ends.

        Each chain dict contains:
            source_name   – name of the entry-point component
            sink_name     – name of the pivot target component
            dataflow_name – label for the dataflow edge
            protocol      – transport protocol (may be empty string)
            entry_threat  – highest-severity threat dict on the source
            pivot_threat  – highest-severity threat dict on the sink
            chain_score   – average severity score of the two threats
            chain_label   – CRITICAL / HIGH / MEDIUM / LOW derived from chain_score
        """
        if not all_threats or not dataflows:
            return []

        # Index threats by target component name, sorted by severity score descending
        _EXCLUDE = frozenset({"Unspecified →", "Unspecified", "→", ""})
        comp_threats: Dict[str, List[Dict]] = {}
        for threat in all_threats:
            target = threat.get("target", "") or ""
            if target in _EXCLUDE:
                continue
            comp_threats.setdefault(target, []).append(threat)

        for name in comp_threats:
            comp_threats[name].sort(
                key=lambda t: t.get("severity", {}).get("score", 0.0),
                reverse=True,
            )

        chains: List[Dict] = []
        seen_pairs: set = set()

        for df in dataflows:
            raw_src = getattr(df, "source", None)
            raw_snk = getattr(df, "sink", None)
            if raw_src is None or raw_snk is None:
                continue

            source_name = raw_src.name if hasattr(raw_src, "name") else str(raw_src)
            sink_name = raw_snk.name if hasattr(raw_snk, "name") else str(raw_snk)

            pair = (source_name, sink_name)
            if pair in seen_pairs:
                continue
            seen_pairs.add(pair)

            src_threats = comp_threats.get(source_name, [])
            snk_threats = comp_threats.get(sink_name, [])
            if not src_threats or not snk_threats:
                continue

            entry = src_threats[0]
            pivot = snk_threats[0]

            entry_score = entry.get("severity", {}).get("score", 0.0)
            pivot_score = pivot.get("severity", {}).get("score", 0.0)
            chain_score = (entry_score + pivot_score) / 2.0

            if chain_score >= 4.0:
                chain_label = "CRITICAL"
            elif chain_score >= 3.0:
                chain_label = "HIGH"
            elif chain_score >= 2.0:
                chain_label = "MEDIUM"
            else:
                chain_label = "LOW"

            df_name = getattr(df, "name", None) or f"{source_name} → {sink_name}"
            protocol = getattr(df, "protocol", "") or ""

            chains.append(
                {
                    "source_name": source_name,
                    "sink_name": sink_name,
                    "dataflow_name": df_name,
                    "protocol": protocol,
                    "entry_threat": entry,
                    "pivot_threat": pivot,
                    "chain_score": chain_score,
                    "chain_label": chain_label,
                }
            )

        chains.sort(key=lambda c: c["chain_score"], reverse=True)
        logger.debug("AttackChainAnalyzer: found %d chains.", len(chains))
        return chains
