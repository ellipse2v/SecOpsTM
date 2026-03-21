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
GDAFEngine — Goal-Driven Attack Flow Engine.

Reads attack objectives and threat actor profiles from a YAML context file,
builds a directed graph from ThreatModel dataflows, finds all paths from
entry points to target assets, assigns MITRE techniques per hop, and returns
a ranked list of AttackScenario objects.

All processing is offline — only disk reads, no network calls.
"""

import logging
import uuid
import yaml
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from threat_analysis.core.asset_technique_mapper import AssetTechniqueMapper, ScoredTechnique
from threat_analysis.core.bom_loader import BOMLoader

logger = logging.getLogger(__name__)

# Classification → data sensitivity score (0.0–1.0)
_CLASSIFICATION_SCORE = {
    "top_secret": 1.0,
    "secret": 0.7,
    "restricted": 0.4,
    "public": 0.0,
    "unknown": 0.1,
}

# traversal_difficulty → hop_weight bonus (easy path = easier for attacker = higher risk)
_TRAVERSAL_BONUS = {"low": 0.3, "medium": 0.1, "high": 0.0}

# detection_level → detection_coverage float
_DETECTION_COVERAGE = {"none": 0.0, "low": 0.2, "medium": 0.5, "high": 0.8}


@dataclass
class AttackHop:
    asset_name: str
    asset_type: str
    techniques: List[ScoredTechnique]
    dataflow_name: str
    protocol: str
    is_encrypted: bool
    is_authenticated: bool
    hop_score: float  # sum of top technique scores × vulnerability weight
    hop_position: str  # "entry" | "intermediate" | "target"


@dataclass
class AttackScenario:
    scenario_id: str
    objective_id: str
    objective_name: str
    objective_description: str
    objective_business_impact: str
    objective_mitre_final_tactic: str
    actor_id: str
    actor_name: str
    actor_sophistication: str
    entry_point: str
    target_asset: str
    hops: List[AttackHop]
    path_score: float
    risk_level: str  # CRITICAL | HIGH | MEDIUM | LOW
    detection_coverage: float  # 0.0 (no detection controls mapped)
    unacceptable_risk: bool
    min_technique_score: float = 0.8  # threshold for OR-branch rendering in .afb


class GDAFEngine:
    """Builds goal-driven attack scenarios from ThreatModel + context YAML.

    In project mode, pass ``extra_models`` to include assets and dataflows from
    sub-models in the attack graph — enabling cross-boundary paths that span
    multiple markdown files.
    """

    def __init__(
        self,
        threat_model: Any,
        context_path: Optional[str] = None,
        extra_models: Optional[List[Any]] = None,
        bom_directory: Optional[str] = None,
    ):
        self.threat_model = threat_model
        # All models whose nodes/edges should be merged into the unified graph
        self._all_models: List[Any] = [threat_model] + (extra_models or [])
        ctx = self._load_context(context_path)
        if ctx and ("attack_objectives" in ctx or "threat_actors" in ctx):
            # Context explicitly declares GDAF sections (even if empty lists) — use as-is.
            self.context = ctx
        else:
            # Context file exists but has no GDAF sections (only system metadata),
            # OR no context file at all — generate objectives/actors automatically.
            auto = self._auto_context(threat_model)
            if ctx:
                # Merge non-GDAF metadata from ctx into the auto-generated context
                # so that extra keys (project description, custom fields) are preserved.
                merged = dict(auto)
                for k, v in ctx.items():
                    if k not in ("attack_objectives", "threat_actors", "risk_criteria"):
                        merged[k] = v
                self.context = merged
            else:
                self.context = auto
        self.mapper = AssetTechniqueMapper()
        self._bom = BOMLoader(bom_directory)
        self._graph: Optional[Dict] = None  # built lazily

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run(self) -> List[AttackScenario]:
        """Run the engine and return all discovered attack scenarios."""
        objectives = self.context.get("attack_objectives", [])
        actors = self.context.get("threat_actors", [])
        risk_criteria = self.context.get("risk_criteria", {})

        if not objectives or not actors:
            logger.info("GDAF: no attack_objectives or threat_actors in context — skipping")
            return []

        graph = self._build_graph()
        max_hops = risk_criteria.get("max_hops", 7)
        max_paths = risk_criteria.get("max_paths_per_objective", 3)
        acceptable_risk = risk_criteria.get("acceptable_risk_score", 5.0)
        self._min_technique_score = float(risk_criteria.get("gdaf_min_technique_score", 0.8))

        scenarios: List[AttackScenario] = []

        for objective in objectives:
            target_names = set(n.lower() for n in objective.get("target_asset_names", []))
            target_types = set(t.lower() for t in objective.get("target_types", []))

            # Identify target assets
            target_nodes = [
                name for name, node in graph.items()
                if name.lower() in target_names
                or self.mapper._normalize_type(node.get("type", "")) in target_types
            ]
            if not target_nodes:
                logger.debug("GDAF: no target nodes for objective %s", objective["id"])
                continue

            for actor in actors:
                if objective["id"] not in actor.get("objectives", []):
                    continue

                entry_nodes = self._find_entry_points(graph, actor)
                if not entry_nodes:
                    logger.debug("GDAF: no entry points for actor %s", actor["id"])
                    continue

                for target in target_nodes:
                    actor_scenarios = []
                    for entry in entry_nodes:
                        if entry == target:
                            continue
                        # Collect enough raw paths across all entry points
                        paths = self._bfs_paths(graph, entry, target, max_hops)
                        for path in paths:
                            scenario = self._build_scenario(
                                path, objective, actor, graph, acceptable_risk
                            )
                            if scenario:
                                actor_scenarios.append(scenario)
                            if len(actor_scenarios) >= max_paths * len(entry_nodes):
                                break

                    # Keep top max_paths by score for this (actor, target)
                    actor_scenarios.sort(key=lambda s: s.path_score, reverse=True)
                    scenarios.extend(actor_scenarios[:max_paths])

        logger.info("GDAF: produced %d attack scenarios", len(scenarios))
        return scenarios

    # ------------------------------------------------------------------
    # Graph construction
    # ------------------------------------------------------------------

    def _build_graph(self) -> Dict:
        if self._graph is not None:
            return self._graph

        graph: Dict[str, Dict] = {}

        # Iterate over all models (main + sub-models in project mode)
        for model in self._all_models:
            # Add actors as nodes (skip duplicates — first definition wins)
            for actor_props in model.actors:
                name = actor_props.get("name", "")
                if not name or name in graph:
                    continue
                boundary_obj = actor_props.get("boundary")
                boundary_trusted = True
                if boundary_obj:
                    b_info = self._boundary_info_for_model(model, boundary_obj)
                    boundary_trusted = b_info.get("isTrusted", True)
                graph[name] = {
                    "kind": "actor",
                    "type": "actor",
                    "boundary_trusted": boundary_trusted,
                    "is_trusted": actor_props.get("isTrusted", boundary_trusted),
                    "attrs": actor_props,
                    "edges": [],
                    "services": set(),
                    "detection_coverage": 0.0,
                    "credentials_stored": False,
                    "internet_facing": False,
                }

            # Add servers as nodes (skip duplicates)
            for server_props in model.servers:
                name = server_props.get("name", "")
                if not name or name in graph:
                    continue
                boundary_obj = server_props.get("boundary")
                boundary_trusted = True
                traversal_difficulty = "low"
                if boundary_obj:
                    b_info = self._boundary_info_for_model(model, boundary_obj)
                    boundary_trusted = b_info.get("isTrusted", True)
                    traversal_difficulty = b_info.get("traversal_difficulty", "low")
                internet_facing = bool(server_props.get("internet_facing", False))
                credentials_stored = bool(server_props.get("credentials_stored", False))
                graph[name] = {
                    "kind": "server",
                    "type": server_props.get("type", "default"),
                    "boundary_trusted": boundary_trusted,
                    "is_trusted": boundary_trusted,
                    "confidentiality": server_props.get("confidentiality", "low"),
                    "integrity": server_props.get("integrity", "low"),
                    "availability": server_props.get("availability", "low"),
                    "mfa_enabled": server_props.get("mfa_enabled", True),
                    "encryption": server_props.get("encryption", ""),
                    "tags": server_props.get("tags", []),
                    "attrs": server_props,
                    "edges": [],
                    "services": set(),
                    "internet_facing": internet_facing,
                    "credentials_stored": credentials_stored,
                    "traversal_difficulty": traversal_difficulty,
                    "detection_coverage": 0.0,
                }

            # Add directed edges from dataflows
            for df in model.dataflows:
                src_obj = getattr(df, "source", None)
                snk_obj = getattr(df, "sink", None)
                if src_obj is None or snk_obj is None:
                    continue
                src_name = src_obj.name if hasattr(src_obj, "name") else str(src_obj)
                snk_name = snk_obj.name if hasattr(snk_obj, "name") else str(snk_obj)
                if src_name not in graph or snk_name not in graph:
                    continue

                # Compute data_value from Data objects on the flow
                data_value = 0.0
                df_data = getattr(df, "data", None)
                if df_data:
                    data_items = df_data if isinstance(df_data, (list, tuple)) else [df_data]
                    for d in data_items:
                        cls_str = str(getattr(d, "classification", "unknown")).lower().replace(" ", "_")
                        cls_val = _CLASSIFICATION_SCORE.get(cls_str, 0.1)
                        if cls_val > data_value:
                            data_value = cls_val

                # Traversal difficulty from sink node's boundary
                snk_traversal = graph[snk_name].get("traversal_difficulty", "low")

                protocol = (getattr(df, "protocol", "") or "").lower()
                bidirectional = bool(getattr(df, "bidirectional", False))
                edge = {
                    "target": snk_name,
                    "dataflow_name": getattr(df, "name", ""),
                    "protocol": protocol,
                    "is_encrypted": bool(getattr(df, "is_encrypted", False)),
                    "is_authenticated": bool(getattr(df, "is_authenticated", False)),
                    "authentication": getattr(df, "authentication", "none") or "none",
                    "data_value": data_value,
                    "traversal_difficulty": snk_traversal,
                    "bidirectional": bidirectional,
                }
                graph[src_name]["edges"].append(edge)

                # Add protocol to services set for both src and snk nodes
                if protocol:
                    graph[src_name]["services"].add(protocol)
                    graph[snk_name]["services"].add(protocol)

                # Add reverse edge for bidirectional dataflows
                if bidirectional:
                    src_traversal = graph[src_name].get("traversal_difficulty", "low")
                    reverse_edge = {
                        "target": src_name,
                        "dataflow_name": getattr(df, "name", "") + " (reverse)",
                        "protocol": protocol,
                        "is_encrypted": bool(getattr(df, "is_encrypted", False)),
                        "is_authenticated": bool(getattr(df, "is_authenticated", False)),
                        "authentication": getattr(df, "authentication", "none") or "none",
                        "data_value": data_value,
                        "traversal_difficulty": src_traversal,
                        "bidirectional": True,
                        "bidirectional_reverse": True,
                    }
                    graph[snk_name]["edges"].append(reverse_edge)

        # Merge BOM data into each node
        if self._bom:
            for node_name, node in graph.items():
                bom = self._bom.get(node_name)
                if not bom:
                    continue
                # credentials_stored: BOM overrides DSL value
                if "credentials_stored" in bom:
                    node["credentials_stored"] = bool(bom["credentials_stored"])
                # detection_level → detection_coverage
                if "detection_level" in bom:
                    node["detection_coverage"] = _DETECTION_COVERAGE.get(
                        str(bom["detection_level"]).lower(), 0.0
                    )
                # running_services → additional protocols in services set
                if "running_services" in bom:
                    for svc in (bom["running_services"] or []):
                        node["services"].add(str(svc).lower())
                # Store BOM metadata for reference
                node["bom"] = bom

        # Second pass: add bridging edges for servers that have a sub-model reference.
        # server_props['_submodel_tm'] is set by _recursively_generate_reports when
        # a sub-model is pre-created.  Bridging means:
        #   parent_server → sub_root_servers   (internal access after compromise)
        #   sub_leaf_servers → original_targets (exit paths inherit parent's outgoing edges)
        for model in self._all_models:
            for server_props in model.servers:
                sub_tm = server_props.get("_submodel_tm") if isinstance(server_props, dict) else None
                if sub_tm is None:
                    continue
                parent_name = server_props.get("name", "") if isinstance(server_props, dict) else ""
                if not parent_name or parent_name not in graph:
                    continue

                # Collect sub-model server names present in the graph
                sub_names = {
                    sp.get("name", "") for sp in sub_tm.servers
                    if isinstance(sp, dict) and sp.get("name", "") in graph
                }
                if not sub_names:
                    continue

                # Root servers: not the sink of any sub-model dataflow
                sub_sinks: set = set()
                for df in sub_tm.dataflows:
                    snk = getattr(df, "sink", None)
                    snk_n = snk.name if hasattr(snk, "name") else str(snk)
                    if snk_n in sub_names:
                        sub_sinks.add(snk_n)
                sub_roots = sub_names - sub_sinks or sub_names

                # Leaf servers: not the source of any sub-model dataflow
                sub_srcs: set = set()
                for df in sub_tm.dataflows:
                    src = getattr(df, "source", None)
                    src_n = src.name if hasattr(src, "name") else str(src)
                    if src_n in sub_names:
                        sub_srcs.add(src_n)
                sub_leaves = sub_names - sub_srcs or sub_names

                # Bridging edge: parent → each sub-model root
                for root_name in sub_roots:
                    graph[parent_name]["edges"].append({
                        "target": root_name,
                        "dataflow_name": f"internal:{parent_name}→{root_name}",
                        "protocol": "internal",
                        "is_encrypted": False,
                        "is_authenticated": False,
                        "authentication": "none",
                    })
                    logger.debug("GDAF: bridge %s → %s (sub-model root)", parent_name, root_name)

                # Exit bridging: sub-model leaves inherit parent's outgoing edges
                parent_outgoing = list(graph[parent_name]["edges"])
                for leaf_name in sub_leaves:
                    for edge in parent_outgoing:
                        if edge["target"] in sub_names:
                            continue  # internal — already wired
                        graph[leaf_name]["edges"].append(dict(edge))
                        logger.debug("GDAF: bridge %s → %s (sub-model leaf exit)", leaf_name, edge["target"])

        self._graph = graph
        logger.debug("GDAF: graph built with %d nodes from %d model(s)", len(graph), len(self._all_models))
        return graph

    def _boundary_info_for_model(self, model: Any, boundary_obj) -> Dict:
        """Look up boundary properties by matching the object within a specific model."""
        for _key, binfo in model.boundaries.items():
            if binfo.get("boundary") is boundary_obj:
                return binfo
        return {}

    # ------------------------------------------------------------------
    # Entry point detection
    # ------------------------------------------------------------------

    def _find_entry_points(self, graph: Dict, actor: Dict) -> List[str]:
        entry_pref = actor.get("entry_preference", "internet-facing")
        entries = []

        if entry_pref == "insider":
            # Insider: any actor with isTrusted=True that has edges
            for name, node in graph.items():
                if node["kind"] == "actor" and node.get("is_trusted", False):
                    if node["edges"]:
                        entries.append(name)
        else:
            # External: actors in untrusted boundaries, or first reachable servers
            for name, node in graph.items():
                if node["kind"] == "actor" and not node.get("is_trusted", True):
                    if node["edges"]:
                        entries.append(name)
            if not entries:
                # Fallback: untrusted servers (VPN gateway, edge router etc.)
                for name, node in graph.items():
                    if node["kind"] == "server" and not node.get("boundary_trusted", True):
                        if node["edges"]:
                            entries.append(name)
                # Also add internet-facing servers regardless of boundary trust
                for name, node in graph.items():
                    if node["kind"] == "server" and node.get("internet_facing", False):
                        if node["edges"] and name not in entries:
                            entries.append(name)

        return entries

    # ------------------------------------------------------------------
    # BFS path finding
    # ------------------------------------------------------------------

    def _bfs_paths(
        self, graph: Dict, start: str, end: str, max_hops: int
    ) -> List[List[Tuple[str, Dict]]]:
        """
        BFS from start to end. Returns list of paths.
        Each path = list of (node_name, edge_dict) tuples, ending with (end, {}).
        """
        # Each queue item: (current_node, path_so_far)
        # path_so_far = list of (node_name, edge_used_to_reach_this_node)
        queue = deque()
        queue.append((start, [(start, {})]))
        paths = []

        while queue:
            current, path = queue.popleft()
            if len(path) > max_hops + 1:
                continue
            if current == end:
                paths.append(path)
                if len(paths) >= 20:  # collect at most 20 raw paths
                    break
                continue
            visited_in_path = {n for n, _ in path}
            for edge in graph.get(current, {}).get("edges", []):
                neighbor = edge["target"]
                if neighbor in visited_in_path:
                    continue
                new_path = path + [(neighbor, edge)]
                queue.append((neighbor, new_path))

        return paths

    # ------------------------------------------------------------------
    # Scenario construction
    # ------------------------------------------------------------------

    def _build_scenario(
        self,
        path: List[Tuple[str, Dict]],
        objective: Dict,
        actor: Dict,
        graph: Dict,
        acceptable_risk: float,
    ) -> Optional[AttackScenario]:
        if len(path) < 2:
            return None

        known_ttps = actor.get("known_ttps", [])
        capable_tactics = actor.get("capable_tactics", None)
        hops: List[AttackHop] = []
        hop_detection_coverages: List[float] = []

        for i, (node_name, edge) in enumerate(path):
            # Skip the very first entry (that's the attacker actor, not a hop target)
            if i == 0:
                continue

            node = graph.get(node_name, {})
            asset_type = node.get("type", "default")

            # Determine hop position
            if i == 1:
                hop_pos = "entry"
            elif i == len(path) - 1:
                hop_pos = "target"
            else:
                hop_pos = "intermediate"

            # Build asset attrs for the mapper (combining node info + edge info)
            asset_attrs = {
                "type": asset_type,
                "is_authenticated": edge.get("is_authenticated", False),
                "authentication": edge.get("authentication", "none"),
                "is_encrypted": edge.get("is_encrypted", False),
                "mfa_enabled": node.get("mfa_enabled", True),
                "encryption": node.get("encryption", ""),
                "tags": node.get("tags", []),
            }

            node_services = node.get("services", set())
            node_credentials = node.get("credentials_stored", False)

            techniques = self.mapper.get_techniques(
                asset_type=asset_type,
                asset_attrs=asset_attrs,
                hop_position=hop_pos,
                actor_known_ttps=known_ttps,
                actor_capable_tactics=capable_tactics,
                top_k=3,
                services=node_services,
                credentials_stored=node_credentials,
            )

            # Compute hop risk weight from vulnerability signals
            hop_weight = 1.0
            if not edge.get("is_authenticated", False):
                hop_weight += 0.4
            if not edge.get("is_encrypted", False):
                hop_weight += 0.3
            if not node.get("mfa_enabled", True):
                hop_weight += 0.2
            cia_score = self._cia_score(node)
            hop_weight += cia_score * 0.1

            # Data value bonus: high-classification data makes this edge more attractive
            hop_weight += edge.get("data_value", 0.0) * 0.3

            # Traversal difficulty bonus: easier segments are higher risk for the attacker
            hop_weight += _TRAVERSAL_BONUS.get(edge.get("traversal_difficulty", "low"), 0.1)

            # Track detection coverage for scenario-level average
            hop_detection_coverages.append(node.get("detection_coverage", 0.0))

            # Use average technique score (not sum) to avoid score inflation with top_k
            avg_tech_score = (sum(t.score for t in techniques) / len(techniques)) if techniques else 0.5
            hop_score = avg_tech_score * hop_weight
            hops.append(AttackHop(
                asset_name=node_name,
                asset_type=asset_type,
                techniques=techniques,
                dataflow_name=edge.get("dataflow_name", ""),
                protocol=edge.get("protocol", ""),
                is_encrypted=edge.get("is_encrypted", False),
                is_authenticated=edge.get("is_authenticated", False),
                hop_score=round(hop_score, 2),
                hop_position=hop_pos,
            ))

        if not hops:
            return None

        path_score = round(sum(h.hop_score for h in hops) / max(len(hops), 1), 2)

        # Add a CIA bonus (+0–0.5) from the target asset's criticality.
        # Additive to keep independent from the path difficulty score.
        target_node = graph.get(path[-1][0], {})
        target_cia = self._cia_score(target_node)
        path_score = round(path_score + target_cia * 0.5, 2)

        # Compute scenario-level detection coverage (average of all hop nodes)
        avg_detection = (
            sum(hop_detection_coverages) / len(hop_detection_coverages)
            if hop_detection_coverages else 0.0
        )

        # Thresholds calibrated for avg_tech_score × hop_weight scoring:
        # hop_weight ~ 1.0–2.0, avg_tech_score ~ 1.0–2.5 → hop_score ~ 1.0–5.0
        # path_score (average) ~ 1.0–5.0 + CIA bonus 0–0.5
        risk_level = (
            "CRITICAL" if path_score >= 4.0 else
            "HIGH"     if path_score >= 2.8 else
            "MEDIUM"   if path_score >= 1.8 else
            "LOW"
        )

        target_name = path[-1][0]

        return AttackScenario(
            scenario_id=f"GDAF-{str(uuid.uuid4())[:8].upper()}",
            objective_id=objective["id"],
            objective_name=objective["name"],
            objective_description=objective.get("description", ""),
            objective_business_impact=objective.get("business_impact", ""),
            objective_mitre_final_tactic=objective.get("mitre_final_tactic", ""),
            actor_id=actor["id"],
            actor_name=actor["name"],
            actor_sophistication=actor.get("sophistication", "medium"),
            entry_point=path[0][0],  # the attacker actor
            target_asset=target_name,
            hops=hops,
            path_score=path_score,
            risk_level=risk_level,
            detection_coverage=round(avg_detection, 2),
            unacceptable_risk=path_score >= acceptable_risk,
            min_technique_score=getattr(self, "_min_technique_score", 0.8),
        )

    def _cia_score(self, node: Dict) -> float:
        """Compute normalized CIA score 0.0–1.0 from node attributes."""
        LEVEL = {"critical": 3, "high": 2, "medium": 1, "low": 0}
        c = LEVEL.get(str(node.get("confidentiality", "low")).lower(), 0)
        i = LEVEL.get(str(node.get("integrity", "low")).lower(), 0)
        a = LEVEL.get(str(node.get("availability", "low")).lower(), 0)
        return min((c * 3 + i * 2 + a) / 18.0, 1.0)  # max = 18 → 1.0

    # ------------------------------------------------------------------
    # Context loading
    # ------------------------------------------------------------------

    @staticmethod
    def _load_context(context_path: Optional[str]) -> Dict:
        if not context_path:
            return {}
        p = Path(context_path)
        if not p.exists():
            logger.warning("GDAF: context file not found: %s", context_path)
            return {}
        try:
            with open(p, "r", encoding="utf-8") as f:
                return yaml.safe_load(f) or {}
        except Exception as exc:
            logger.error("GDAF: failed to load context %s: %s", context_path, exc)
            return {}

    @staticmethod
    def _auto_context(threat_model: Any) -> Dict:
        """Generate a minimal GDAF context from the ThreatModel when no YAML is provided.

        Targets the servers with the highest combined CIA score; uses a single generic
        adversary so that attack paths are always evaluated even without a hand-crafted
        context file.
        """
        logger.info("GDAF: no context file — auto-generating minimal context from ThreatModel")

        # Score servers by CIA values to identify crown-jewel targets
        _LEVEL = {"critical": 3, "high": 2, "medium": 1, "low": 0}
        scored = []
        for s in threat_model.servers:
            props = s if isinstance(s, dict) else vars(s) if hasattr(s, "__dict__") else {}
            name = props.get("name") or getattr(s, "name", "")
            if not name:
                continue
            c = _LEVEL.get(str(props.get("confidentiality", "low")).lower(), 0)
            i = _LEVEL.get(str(props.get("integrity", "low")).lower(), 0)
            a = _LEVEL.get(str(props.get("availability", "low")).lower(), 0)
            scored.append((c + i + a, name))

        scored.sort(reverse=True)
        top_targets = [name for _, name in scored[:3]] or ["*"]

        objectives = [
            {
                "id": "OBJ-AUTO-001",
                "name": "Compromise high-value assets",
                "description": "Auto-generated objective: reach the highest-CIA servers",
                "target_asset_names": top_targets,
                "target_types": ["database", "server"],
                "mitre_final_tactic": "impact",
                "business_impact": "Data breach / service disruption",
            }
        ]
        actors = [
            {
                "id": "ACT-AUTO-001",
                "name": "Generic External Adversary",
                "sophistication": "medium",
                "objectives": ["OBJ-AUTO-001"],
                "initial_access": "internet",
                "assumed_breach": False,
            }
        ]
        risk_criteria = {"max_hops": 7, "max_paths_per_objective": 3, "acceptable_risk_score": 5.0}
        return {
            "attack_objectives": objectives,
            "threat_actors": actors,
            "risk_criteria": risk_criteria,
        }
