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

"""Tests for threat_analysis/core/stride_constants.py

Used throughout the pipeline (threat grouping, summary stats, report filtering) as
the single source of truth for the 6 canonical STRIDE categories — a regression here
(e.g. a typo introduced while editing) would silently drop threats from every report.
"""

from threat_analysis.core.stride_constants import STRIDE_CATEGORIES


def test_stride_categories_is_a_frozenset():
    assert isinstance(STRIDE_CATEGORIES, frozenset)


def test_stride_categories_has_exactly_six_entries():
    assert len(STRIDE_CATEGORIES) == 6


def test_stride_categories_content():
    assert STRIDE_CATEGORIES == frozenset({
        "Spoofing",
        "Tampering",
        "Repudiation",
        "Information Disclosure",
        "Denial of Service",
        "Elevation of Privilege",
    })


def test_stride_categories_immutable():
    """frozenset has no in-place mutation methods — any accidental `.add(...)` call
    elsewhere in the codebase must fail loudly instead of silently corrupting this
    shared constant.
    """
    assert not hasattr(STRIDE_CATEGORIES, "add")
    assert not hasattr(STRIDE_CATEGORIES, "remove")
