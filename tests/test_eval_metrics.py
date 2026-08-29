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

import math

import pytest

from tooling.eval.metrics import (
    kendall_tau,
    spearman_rho,
    top_k_jaccard,
    max_displacement,
    coeff_variation,
    majority,
    bucket_change_count,
)


def test_kendall_tau_identical_order_is_one():
    assert kendall_tau(["a", "b", "c", "d"], ["a", "b", "c", "d"]) == pytest.approx(1.0)


def test_kendall_tau_reversed_order_is_minus_one():
    assert kendall_tau(["a", "b", "c", "d"], ["d", "c", "b", "a"]) == pytest.approx(-1.0)


def test_kendall_tau_single_adjacent_swap():
    # one discordant pair out of C(4,2)=6 -> tau = (6-2)/6 wait: swap of b,c ->
    # discordant pairs: (b,c). concordant: 5. tau = (5-1)/6 = 0.6666...
    assert kendall_tau(["a", "b", "c", "d"], ["a", "c", "b", "d"]) == pytest.approx(2 / 3)


def test_kendall_tau_ignores_element_order_of_args_only_ranking_matters():
    # same ranking expressed with a different id set order in order_b's construction
    assert kendall_tau(["x", "y", "z"], ["x", "y", "z"]) == pytest.approx(1.0)


def test_spearman_rho_identical_is_one():
    assert spearman_rho(["a", "b", "c", "d"], ["a", "b", "c", "d"]) == pytest.approx(1.0)


def test_spearman_rho_known_value():
    # order_a ranks: a=0 b=1 c=2 d=3 ; order_b ["a","c","b","d"] ranks a=0 c=1 b=2 d=3
    # rho over (0,1,2,3) vs (0,2,1,3) = 0.8
    assert spearman_rho(["a", "b", "c", "d"], ["a", "c", "b", "d"]) == pytest.approx(0.8)


def test_top_k_jaccard_identical():
    assert top_k_jaccard(["a", "b", "c", "d"], ["a", "b", "c", "e"], k=3) == pytest.approx(1.0)


def test_top_k_jaccard_disjoint():
    assert top_k_jaccard(["a", "b"], ["c", "d"], k=2) == pytest.approx(0.0)


def test_top_k_jaccard_half_overlap():
    # top-2 of a = {a,b} ; top-2 of b = {b,c} ; intersection 1, union 3
    assert top_k_jaccard(["a", "b", "c"], ["b", "c", "a"], k=2) == pytest.approx(1 / 3)


def test_top_k_jaccard_k_larger_than_list_uses_whole_list():
    assert top_k_jaccard(["a", "b"], ["a", "b"], k=10) == pytest.approx(1.0)


def test_max_displacement_no_change():
    assert max_displacement(["a", "b", "c", "d"], ["a", "b", "c", "d"], k=4) == 0


def test_max_displacement_item_moved_three_places():
    # 'a' is rank 0 in order_a, rank 3 in order_b -> displacement 3
    assert max_displacement(["a", "b", "c", "d"], ["b", "c", "d", "a"], k=4) == 3


def test_max_displacement_only_considers_top_k_of_order_a():
    # only 'a' (top-1) is checked; it stays at 0. 'd' moving is ignored.
    assert max_displacement(["a", "b", "c", "d"], ["a", "d", "b", "c"], k=1) == 0


def test_max_displacement_item_dropped_out_of_ranking_uses_end_position():
    # order_b missing 'c' entirely -> treated as ranked last (index = len(order_b))
    assert max_displacement(["c", "a"], ["a"], k=1) == 1


def test_coeff_variation_constant_input_is_zero():
    assert coeff_variation([0.7, 0.7, 0.7]) == pytest.approx(0.0)


def test_coeff_variation_known_value():
    # mean 2.0, population stdev 0.816496..., cv = 0.408248...
    assert coeff_variation([1.0, 2.0, 3.0]) == pytest.approx(0.40824829, abs=1e-6)


def test_coeff_variation_zero_mean_returns_zero_not_nan():
    result = coeff_variation([-1.0, 0.0, 1.0])
    assert result == 0.0
    assert not math.isnan(result)


def test_coeff_variation_single_value_is_zero():
    assert coeff_variation([1.5]) == pytest.approx(0.0)


def test_coeff_variation_empty_is_zero():
    assert coeff_variation([]) == pytest.approx(0.0)


def test_majority_true():
    assert majority([True, True, False]) is True


def test_majority_false():
    assert majority([False, False, True]) is False


def test_majority_tie_breaks_false():
    # even count, 50/50 -> not a majority for True -> False
    assert majority([True, False]) is False


def test_majority_empty_is_false():
    assert majority([]) is False


def test_bucket_change_count_keyed_by_id_not_position():
    before = {"s1": "HIGH", "s2": "MEDIUM", "s3": "LOW"}
    after = {"s1": "HIGH", "s2": "CRITICAL", "s3": "LOW"}
    assert bucket_change_count(before, after) == 1


def test_bucket_change_count_ignores_ids_absent_from_after():
    before = {"s1": "HIGH", "s2": "LOW"}
    after = {"s1": "MEDIUM"}
    assert bucket_change_count(before, after) == 1


def test_bucket_change_count_no_changes():
    before = {"s1": "HIGH", "s2": "LOW"}
    after = {"s1": "HIGH", "s2": "LOW"}
    assert bucket_change_count(before, after) == 0
