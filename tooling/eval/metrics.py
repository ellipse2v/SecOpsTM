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

"""Pure ranking / dispersion metrics for the debate evaluation harness.

An "order" is a list of scenario-id strings, best-ranked first, and every pair
of orders passed to the same function is a permutation of the same id set
(except the top-k helpers, which tolerate small membership differences in the
tail). No imports from ``threat_analysis`` — this module is a leaf.
"""

import statistics
from typing import Dict, List

from scipy.stats import kendalltau, spearmanr


def _rank_vectors(order_a: List[str], order_b: List[str]) -> tuple[List[int], List[int]]:
    """Map the shared id set to paired rank vectors under each ordering.

    Ids missing from one side are appended at the end (rank = len) so the
    vectors stay the same length.
    """
    ids = list(dict.fromkeys(list(order_a) + list(order_b)))
    pos_a = {sid: i for i, sid in enumerate(order_a)}
    pos_b = {sid: i for i, sid in enumerate(order_b)}
    ra = [pos_a.get(sid, len(order_a)) for sid in ids]
    rb = [pos_b.get(sid, len(order_b)) for sid in ids]
    return ra, rb


def kendall_tau(order_a: List[str], order_b: List[str]) -> float:
    """Kendall tau-b between two orderings. 1.0 identical, -1.0 reversed."""
    ra, rb = _rank_vectors(order_a, order_b)
    if len(ra) < 2:
        return 1.0
    tau = kendalltau(ra, rb).statistic
    return 0.0 if tau != tau else float(tau)  # NaN guard (all-tied input)


def kendall_tau_values(vals_a: List[float], vals_b: List[float]) -> float:
    """Kendall tau-b between two equal-length numeric vectors (ties allowed).

    Used for band-aware ranking comparisons: pass each ordering mapped through a
    scenario -> band-index lookup, so two orderings that differ only by a
    within-band permutation compare as identical.
    """
    if len(vals_a) != len(vals_b) or len(vals_a) < 2:
        return 1.0
    tau = kendalltau(vals_a, vals_b).statistic
    return 0.0 if tau != tau else float(tau)  # NaN guard (a vector with no variation)


def spearman_rho(order_a: List[str], order_b: List[str]) -> float:
    """Spearman rho between two orderings. 1.0 identical, -1.0 reversed."""
    ra, rb = _rank_vectors(order_a, order_b)
    if len(ra) < 2:
        return 1.0
    rho = spearmanr(ra, rb).statistic
    return 0.0 if rho != rho else float(rho)


def top_k_jaccard(order_a: List[str], order_b: List[str], k: int) -> float:
    """Jaccard overlap of the top-k id sets. 1.0 identical set, 0.0 disjoint."""
    a = set(order_a[:k])
    b = set(order_b[:k])
    if not a and not b:
        return 1.0
    return len(a & b) / len(a | b)


def max_displacement(order_a: List[str], order_b: List[str], k: int) -> int:
    """Largest rank change among order_a's top-k items.

    An item absent from order_b is treated as ranked at position len(order_b).
    """
    pos_b = {sid: i for i, sid in enumerate(order_b)}
    worst = 0
    for rank_a, sid in enumerate(order_a[:k]):
        rank_b = pos_b.get(sid, len(order_b))
        worst = max(worst, abs(rank_b - rank_a))
    return worst


def coeff_variation(values: List[float]) -> float:
    """Population coefficient of variation (stdev / mean). 0.0 when mean is 0
    or fewer than two values are given."""
    if len(values) < 2:
        return 0.0
    mean = statistics.fmean(values)
    if mean == 0:
        return 0.0
    return statistics.pstdev(values) / abs(mean)


def majority(values: List[bool]) -> bool:
    """True iff strictly more than half the values are True."""
    if not values:
        return False
    return sum(1 for v in values if v) * 2 > len(values)


def bucket_change_count(before: Dict[str, str], after: Dict[str, str]) -> int:
    """Number of ids whose risk-level bucket differs. Ids absent from `after`
    are ignored; ids absent from `before` are ignored."""
    changed = 0
    for sid, level in before.items():
        if sid in after and after[sid] != level:
            changed += 1
    return changed
