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

"""Tests for threat_analysis/generation/utils.py"""

import pytest
from threat_analysis.generation.utils import extract_name_from_object, get_target_name


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class _Named:
    """Simple object with a name attribute."""
    def __init__(self, name):
        self.name = name


class _Dataflow:
    """Minimal dataflow-like object with source and sink."""
    def __init__(self, src_name, snk_name):
        self.source = _Named(src_name)
        self.sink = _Named(snk_name)


# ---------------------------------------------------------------------------
# extract_name_from_object
# ---------------------------------------------------------------------------

class TestExtractNameFromObject:
    def test_named_object(self):
        obj = _Named("WebServer")
        assert extract_name_from_object(obj) == "WebServer"

    def test_string_object(self):
        assert extract_name_from_object("plain string") == "plain string"

    def test_none_returns_unspecified(self):
        assert extract_name_from_object(None) == "Unspecified"

    def test_single_element_tuple_with_named(self):
        obj = _Named("ActorA")
        assert extract_name_from_object((obj,)) == "ActorA"

    def test_single_element_tuple_with_string(self):
        assert extract_name_from_object(("hello",)) == "hello"

    def test_single_element_tuple_with_none(self):
        assert extract_name_from_object((None,)) == "Unspecified"

    def test_integer_returns_unspecified(self):
        # int has no .name attribute and is not a string
        assert extract_name_from_object(42) == "Unspecified"

    def test_object_name_is_converted_to_str(self):
        class NumericName:
            name = 123
        assert extract_name_from_object(NumericName()) == "123"

    def test_multi_element_tuple_falls_through_to_name(self):
        # A multi-element tuple has no .name attr and is not a string → "Unspecified"
        obj = _Named("X")
        result = extract_name_from_object((obj, obj))
        assert result == "Unspecified"

    def test_empty_string(self):
        assert extract_name_from_object("") == ""


# ---------------------------------------------------------------------------
# get_target_name
# ---------------------------------------------------------------------------

class TestGetTargetName:
    def test_single_named_object(self):
        assert get_target_name(_Named("DB")) == "DB"

    def test_none(self):
        assert get_target_name(None) == "Unspecified"

    def test_string(self):
        assert get_target_name("Target") == "Target"

    def test_two_element_tuple_plain_objects(self):
        src = _Named("A")
        snk = _Named("B")
        result = get_target_name((src, snk))
        assert result == "A → B"

    def test_two_element_tuple_dataflow_objects(self):
        # Both elements are dataflow-like (have source/sink attributes)
        df1 = _Dataflow("X", "Y")
        df2 = _Dataflow("P", "Q")
        result = get_target_name((df1, df2))
        # source element: df1.source.name == "X", sink element: df2.sink.name == "Q"
        assert result == "X → Q"

    def test_two_element_tuple_mixed(self):
        # source is plain named, sink is dataflow-like
        src = _Named("Alpha")
        snk = _Dataflow("ignored", "Beta")
        result = get_target_name((src, snk))
        assert result == "Alpha → Beta"

    def test_single_element_tuple_with_named(self):
        obj = _Named("Single")
        # Single-element tuple → extract_name_from_object(obj) == "Single"
        assert get_target_name((obj,)) == "Single"

    def test_single_element_tuple_with_dataflow(self):
        df = _Dataflow("Src", "Snk")
        result = get_target_name((df,))
        assert result == "Src → Snk"

    def test_single_element_tuple_with_non_dataflow(self):
        # Not a dataflow (no source/sink), not a string, no name → "Unspecified"
        result = get_target_name((42,))
        assert result == "Unspecified"

    def test_two_element_tuple_strings(self):
        result = get_target_name(("Hello", "World"))
        assert result == "Hello → World"

    def test_empty_tuple(self):
        # Empty tuple: not 1 or 2 elements → falls through to extract_name_from_object(())
        # () is not None, not string, has no .name → "Unspecified"
        result = get_target_name(())
        assert result == "Unspecified"
