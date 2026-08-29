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

"""Regression test for the pytm class-level-state race between concurrent
create_threat_model()+process_threats() calls — see
docs/superpowers/specs/2026-07-23-lightweight-multi-user-workspaces-design.md
section 2 for the full explanation.

This is a best-effort concurrency demonstration, not a fully deterministic
repro: it forces both threads to start at the same instant (threading.Barrier)
and repeats many times to make the interleaving likely, but exact reproduction
without the fix depends on the interpreter's thread-scheduling. What IS
deterministic: with pytm_build_lock() held for the whole create+process pair,
this must pass every single run, on every repetition.
"""

import sys
import threading
from unittest.mock import patch

import pytest

from threat_analysis.core.cve_service import CVEService
from threat_analysis.core.model_factory import create_threat_model, pytm_build_lock
from threat_analysis.utils import PROJECT_ROOT

MODEL_A = """# System Model: Model A

## Boundaries
- **ZoneA**: isTrusted=true

## Actors
- **UserA**: boundary=ZoneA

## Servers
- **ServerA**: boundary=ZoneA

## Dataflows
- **FlowA**: from="UserA", to="ServerA", protocol="HTTPS"
"""

MODEL_B = """# System Model: Model B

## Boundaries
- **ZoneB**: isTrusted=true

## Actors
- **UserB**: boundary=ZoneB

## Servers
- **ServerB**: boundary=ZoneB

## Dataflows
- **FlowB**: from="UserB", to="ServerB", protocol="HTTPS"
"""


@pytest.fixture
def cve_service(tmp_path):
    return CVEService(PROJECT_ROOT, tmp_path / "cve_definitions.yml")


def _build_and_process(markdown, model_name, cve_service, barrier, use_lock, out, key):
    barrier.wait()
    if use_lock:
        with pytm_build_lock():
            tm = create_threat_model(markdown, model_name, "desc", cve_service, validate=False)
            grouped = tm.process_threats()
    else:
        tm = create_threat_model(markdown, model_name, "desc", cve_service, validate=False)
        grouped = tm.process_threats()

    own_component_names = {s["name"] for s in tm.servers} | {a["name"] for a in tm.actors}
    foreign_targets = []
    for threats in grouped.values():
        for threat, target in threats:
            target_names = (
                {getattr(t, "name", "") for t in target}
                if isinstance(target, tuple)
                else {getattr(target, "name", "")}
            )
            foreign_targets.extend(n for n in target_names if n and n not in own_component_names)

    out[key] = {
        "grouped_threats_nonempty": bool(grouped),
        "foreign_targets": foreign_targets,
    }


def _run_concurrent_pair(cve_service, use_lock: bool) -> tuple[dict, dict]:
    barrier = threading.Barrier(2)
    out = {}
    with patch.object(sys, 'argv', ['pytest']):
        t1 = threading.Thread(target=_build_and_process,
                              args=(MODEL_A, "ModelA", cve_service, barrier, use_lock, out, "a"))
        t2 = threading.Thread(target=_build_and_process,
                              args=(MODEL_B, "ModelB", cve_service, barrier, use_lock, out, "b"))
        t1.start()
        t2.start()
        t1.join(timeout=30)
        t2.join(timeout=30)
    return out["a"], out["b"]


class TestPytmConcurrency:
    def test_concurrent_builds_with_lock_never_cross_contaminate(self, cve_service):
        """The real regression guard: with pytm_build_lock() held for the whole
        create+process pair, repeated concurrent runs must NEVER show a threat
        whose target belongs to the other thread's model."""
        for _ in range(20):
            result_a, result_b = _run_concurrent_pair(cve_service, use_lock=True)
            assert result_a["grouped_threats_nonempty"]
            assert result_b["grouped_threats_nonempty"]
            assert result_a["foreign_targets"] == []
            assert result_b["foreign_targets"] == []
