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

import json

import pytest

from threat_analysis.core.asset_technique_mapper import ScoredTechnique
from threat_analysis.core.gdaf_engine import AttackHop, AttackScenario
from tooling.eval._common import freeze, thaw, scenario_order, risk_levels


def _scenario(sid: str, score: float, level: str = "HIGH") -> AttackScenario:
    hop = AttackHop(
        asset_name="web-01",
        asset_type="Server",
        techniques=[ScoredTechnique(id="T1190", name="Exploit Public-Facing App",
                                    tactics=["initial-access"], score=0.9, rationale="r", url="u")],
        dataflow_name="user->web",
        protocol="HTTPS",
        is_encrypted=True,
        is_authenticated=False,
        hop_score=0.9,
        hop_position="entry",
    )
    return AttackScenario(
        scenario_id=sid,
        objective_id="obj1",
        objective_name="Exfiltrate data",
        objective_description="d",
        objective_business_impact="b",
        objective_mitre_final_tactic="exfiltration",
        actor_id="act1",
        actor_name="Ransomware crew",
        actor_sophistication="high",
        entry_point="internet",
        target_asset="db-01",
        hops=[hop],
        path_score=score,
        risk_level=level,
        detection_coverage=0.2,
        unacceptable_risk=True,
    )


def test_freeze_produces_json_serialisable_records():
    records = freeze([_scenario("S1", 3.4)])
    json.dumps(records)  # must not raise


def test_thaw_round_trips_read_fields():
    original = [_scenario("S1", 3.4, "HIGH"), _scenario("S2", 1.1, "LOW")]
    restored = thaw(freeze(original))
    assert [s.scenario_id for s in restored] == ["S1", "S2"]
    assert restored[0].path_score == pytest.approx(3.4)
    assert restored[0].risk_level == "HIGH"
    assert restored[0].detection_coverage == pytest.approx(0.2)
    assert restored[0].hops[0].asset_name == "web-01"
    assert restored[0].hops[0].hop_position == "entry"
    assert restored[0].hops[0].protocol == "HTTPS"
    assert restored[0].hops[0].is_authenticated is False
    assert restored[0].hops[0].is_encrypted is True
    assert restored[0].hops[0].techniques[0].id == "T1190"


def test_thawed_scenario_is_accepted_by_debate_engine_grounding():
    # RedBlueDebateEngine._build_grounding reads hop.techniques[i].id, hop.protocol,
    # hop.is_authenticated, hop.is_encrypted, hop.asset_name, hop.hop_position
    from threat_analysis.core.debate_engine import RedBlueDebateEngine
    restored = thaw(freeze([_scenario("S1", 3.4)]))
    engine = RedBlueDebateEngine(provider=None, config={})
    grounding = engine._build_grounding(restored[0])
    assert "web-01" in grounding
    assert "T1190" in grounding


def test_scenario_order_sorts_by_path_score_desc():
    scenarios = [_scenario("S1", 1.0), _scenario("S2", 5.0), _scenario("S3", 3.0)]
    assert scenario_order(scenarios) == ["S2", "S3", "S1"]


def test_scenario_order_breaks_ties_by_id():
    scenarios = [_scenario("Sb", 2.0), _scenario("Sa", 2.0)]
    assert scenario_order(scenarios) == ["Sa", "Sb"]


def test_risk_levels_maps_id_to_level():
    scenarios = [_scenario("S1", 3.0, "HIGH"), _scenario("S2", 1.0, "LOW")]
    assert risk_levels(scenarios) == {"S1": "HIGH", "S2": "LOW"}


def test_run_debate_mutates_copies_not_originals():
    from tooling.eval._common import run_debate

    class StubProvider:
        async def generate_debate_turn(self, prompt, system_prompt, temperature=None):
            return {"viability_score": 0.9, "techniques_blocked": [], "techniques_attempted": ["T1190"],
                    "failed_alternatives": [], "detection_gaps": [], "evidence": [], "rationale": "stub"}

    originals = [_scenario("S1", 3.0), _scenario("S2", 2.0)]
    original_scores = [s.path_score for s in originals]
    mutated, results = run_debate(
        originals, provider=StubProvider(),
        config={"top_n": 5, "min_viability_threshold": 0.0, "max_rounds": 1},
        sleep_s=0.0,
    )
    assert [s.path_score for s in originals] == original_scores  # originals untouched
    assert any(s.path_score_pre_debate is not None for s in mutated)
    assert all(r.scenario_id for r in results)


def test_run_debate_returns_debate_results_with_viability():
    from tooling.eval._common import run_debate

    class StubProvider:
        async def generate_debate_turn(self, prompt, system_prompt, temperature=None):
            return {"viability_score": 0.7, "techniques_blocked": [], "techniques_attempted": [],
                    "failed_alternatives": [], "detection_gaps": [], "evidence": [], "rationale": "s"}

    _, results = run_debate(
        [_scenario("S1", 4.0)], provider=StubProvider(),
        config={"top_n": 5, "min_viability_threshold": 0.0, "max_rounds": 1}, sleep_s=0.0,
    )
    assert len(results) == 1
    assert 0.0 <= results[0].final_viability <= 1.0


def test_run_debate_sleeps_after_every_turn_not_just_per_scenario():
    # 1 scenario, 1 round -> 2 turns (Red + Blue) -> 2 sleeps, not 1.
    import time
    from tooling.eval._common import run_debate

    class StubProvider:
        async def generate_debate_turn(self, prompt, system_prompt, temperature=None):
            return {"viability_score": 0.6, "techniques_blocked": [], "techniques_attempted": [],
                    "failed_alternatives": [], "detection_gaps": [], "evidence": [], "rationale": "s"}

    sleep_s = 0.05
    start = time.monotonic()
    run_debate(
        [_scenario("S1", 4.0)], provider=StubProvider(),
        config={"top_n": 5, "min_viability_threshold": 0.0, "max_rounds": 1},
        sleep_s=sleep_s,
    )
    elapsed = time.monotonic() - start
    # a per-scenario throttle would sleep once (>= 0.05); per-turn sleeps twice.
    assert elapsed >= 2 * sleep_s


def test_make_provider_sets_force_env(monkeypatch):
    import os
    from tooling.eval._common import make_provider
    # monkeypatch.setenv records the pre-test state and restores (here: unsets) it
    # on teardown, so the var never leaks into the rest of the pytest process
    monkeypatch.setenv("SECOPSTM_FORCE_PROVIDER", "placeholder")
    make_provider("groq")
    assert os.environ["SECOPSTM_FORCE_PROVIDER"] == "groq"


def test_determinism_aggregate_one_provider_stubbed(tmp_path, monkeypatch):
    """The aggregation math runs end to end with run_debate stubbed — no LLM."""
    import json
    from tooling.eval import determinism
    from tooling.eval._common import thaw

    fixture = tmp_path / "Toy.scenarios.json"
    from tooling.eval._common import freeze
    fixture.write_text(json.dumps(freeze([_scenario("S1", 3.0), _scenario("S2", 2.0)])))

    calls = {"n": 0}

    def fake_run_debate(scenarios, *, provider, config, sleep_s=0.0):
        calls["n"] += 1
        s = thaw(freeze(scenarios))
        for sc in s:
            sc.path_score_pre_debate = sc.path_score
            sc.path_score = sc.path_score * (1.0 + 0.01 * calls["n"])
            sc.debate_factor = 1.0 + 0.01 * calls["n"]

        class R:
            def __init__(self, sid):
                self.scenario_id = sid
                self.final_viability = 0.6
                self.residual_path_viable = True
                self.debate_factor = 1.0 + 0.01 * calls["n"]
                self.rounds = []
        return s, [R(sc.scenario_id) for sc in s]

    monkeypatch.setattr(determinism, "run_debate", fake_run_debate)
    monkeypatch.setattr(determinism, "make_provider", lambda name: object())

    out = tmp_path / "result.json"
    rc = determinism.main([
        "--fixtures-dir", str(tmp_path),
        "--fixtures", "Toy",
        "--providers", "groq",
        "--runs", "3", "--top-n", "5", "--max-rounds", "1", "--sleep", "0",
        "--out", str(out),
    ])
    assert rc == 0
    data = json.loads(out.read_text())
    assert data["step"] == "determinism"
    assert data["fixtures"]["Toy"]["scenario_count"] == 2
    prov = data["fixtures"]["Toy"]["by_provider"]["groq"]
    assert prov["runs_ok"] == 3
    # both S1 and S2 are debated by the stub -> the debated subset is the full set
    assert prov["debated_count"] == 2
    # factor vector per scenario is [1.01, 1.02, 1.03] across the 3 runs.
    # population CV = pstdev / mean = 0.00816497 / 1.02 = 0.008005 -> round(4) = 0.008
    assert prov["factor_cv_median"] == pytest.approx(0.008)
    assert prov["factor_cv_max"] == pytest.approx(0.008)
    # final_viability is a constant 0.6 every run -> CV 0
    assert prov["final_viability_cv_median"] == pytest.approx(0.0)
    # scaling both scenarios by the same factor keeps the ordering -> tau 1.0
    assert prov["rank_stability"] == pytest.approx(1.0)
    assert prov["rank_stability_debated"] == pytest.approx(1.0)
    assert prov["risk_level_flip_rate"] == pytest.approx(0.0)
    assert prov["direction_flip_rate"] == pytest.approx(0.0)


def test_determinism_cross_provider_block_with_bands(tmp_path, monkeypatch):
    """Two providers -> the cross-provider block runs and does not choke on the
    internal `_bands` / `_orders` record keys."""
    import json
    from tooling.eval import determinism
    from tooling.eval._common import freeze, thaw

    fixture = tmp_path / "Toy.scenarios.json"
    fixture.write_text(json.dumps(freeze([_scenario("S1", 3.0), _scenario("S2", 2.0)])))

    def fake_run_debate(scenarios, *, provider, config, sleep_s=0.0):
        s = thaw(freeze(scenarios))
        for sc in s:
            sc.path_score_pre_debate = sc.path_score
            sc.debate_factor = 1.05

        class R:
            def __init__(self, sid):
                self.scenario_id = sid
                self.final_viability = 0.6
                self.residual_path_viable = True
                self.rounds = []
        return s, [R(sc.scenario_id) for sc in s]

    monkeypatch.setattr(determinism, "run_debate", fake_run_debate)
    monkeypatch.setattr(determinism, "make_provider", lambda name: object())

    out = tmp_path / "r.json"
    rc = determinism.main([
        "--fixtures-dir", str(tmp_path), "--fixtures", "Toy",
        "--providers", "groq", "mistral",
        "--runs", "2", "--top-n", "5", "--max-rounds", "1", "--sleep", "0", "--out", str(out),
    ])
    assert rc == 0
    cross = json.loads(out.read_text())["fixtures"]["Toy"]["cross_provider"]
    assert cross["direction_agreement"] == pytest.approx(1.0)
    assert "factor_delta_mean" in cross


def test_determinism_metrics_use_debated_subset_only(tmp_path, monkeypatch):
    """Regression guard for the dilution bug: a fixture where the debate touches
    only 2 of 4 scenarios must report debated_count == 2 and compute dispersion
    over just those 2 — the 2 never-debated scenarios (constant debate_factor 1.0)
    must not drag every metric to zero."""
    import json
    from tooling.eval import determinism
    from tooling.eval._common import freeze, thaw

    fixture = tmp_path / "Toy.scenarios.json"
    fixture.write_text(json.dumps(freeze([
        _scenario("S1", 5.0), _scenario("S2", 4.0), _scenario("S3", 3.0), _scenario("S4", 2.0),
    ])))

    calls = {"n": 0}

    def fake_run_debate(scenarios, *, provider, config, sleep_s=0.0):
        calls["n"] += 1
        s = thaw(freeze(scenarios))
        for sc in s:
            sc.path_score_pre_debate = sc.path_score
        # debate only S1 and S2; give them a genuinely varying factor run to run
        debated = {"S1": 0.8 + 0.1 * calls["n"], "S2": 1.2 - 0.1 * calls["n"]}
        for sc in s:
            sc.debate_factor = debated.get(sc.scenario_id, 1.0)
            sc.path_score = sc.path_score * sc.debate_factor

        class R:
            def __init__(self, sid):
                self.scenario_id = sid
                self.final_viability = 0.6
                self.residual_path_viable = True
                self.rounds = []
        return s, [R("S1"), R("S2")]  # results for the debated subset only

    monkeypatch.setattr(determinism, "run_debate", fake_run_debate)
    monkeypatch.setattr(determinism, "make_provider", lambda name: object())

    out = tmp_path / "r.json"
    rc = determinism.main([
        "--fixtures-dir", str(tmp_path), "--fixtures", "Toy", "--providers", "groq",
        "--runs", "3", "--top-n", "2", "--max-rounds", "1", "--sleep", "0", "--out", str(out),
    ])
    assert rc == 0
    prov = json.loads(out.read_text())["fixtures"]["Toy"]["by_provider"]["groq"]
    assert prov["debated_count"] == 2
    # S1 factor is [0.9, 1.0, 1.1], S2 is [1.1, 1.0, 0.9] — both have real dispersion.
    # If the 2 undebated scenarios were included, the median CV would be ~0.
    assert prov["factor_cv_median"] > 0.02


def test_ablation_aggregate_stubbed(tmp_path, monkeypatch):
    import json
    from tooling.eval import ablation
    from tooling.eval._common import freeze, thaw

    fx = tmp_path / "Toy.scenarios.json"
    fx.write_text(json.dumps(freeze([
        _scenario("S1", 5.0), _scenario("S2", 4.0), _scenario("S3", 3.0),
        _scenario("S4", 2.0), _scenario("S5", 1.0), _scenario("S6", 0.5),
    ])))

    def fake_run_debate(scenarios, *, provider, config, sleep_s=0.0):
        s = thaw(freeze(scenarios))
        # push the lowest-scored debated scenario to the top
        for sc in s:
            sc.path_score_pre_debate = sc.path_score
        s_sorted = sorted(s, key=lambda x: x.path_score)
        s_sorted[0].path_score = 99.0
        s_sorted[0].debate_factor = 1.5

        class R:
            def __init__(self, sid):
                self.scenario_id = sid
                self.final_viability = 0.8
                self.residual_path_viable = True
                self.rounds = []
        return s, [R(sc.scenario_id) for sc in s]

    monkeypatch.setattr(ablation, "run_debate", fake_run_debate)
    monkeypatch.setattr(ablation, "make_provider", lambda name: object())

    out = tmp_path / "abl.json"
    rc = ablation.main([
        "--fixtures-dir", str(tmp_path), "--fixtures", "Toy",
        "--provider", "groq", "--top-n", "5", "--max-rounds", "1", "--sleep", "0",
        "--out", str(out),
    ])
    assert rc == 0
    data = json.loads(out.read_text())
    assert data["step"] == "ablation"
    tf = data["fixtures"]["Toy"]
    assert tf["scenario_count"] == 6
    # the stub pushes S6 (lowest pre-debate) to the top:
    # pre  = [S1, S2, S3, S4, S5, S6]  post = [S6, S1, S2, S3, S4, S5]
    assert tf["top5_unchanged"] is False
    assert tf["top5_jaccard"] == pytest.approx(0.6667)      # {S1..S4} / {S1..S6}
    assert tf["top5_max_displacement"] == 1                  # every top-5 item shifts by 1
    assert tf["kendall_tau"] == pytest.approx(0.3333)        # 5 discordant of 15 pairs
    assert tf["kendall_tau"] < 1.0
    assert data["aggregate"]["fixtures_ok"] == 1
    assert data["aggregate"]["fixtures_excluded_lt2"] == 0
    assert data["aggregate"]["kendall_tau_median"] == pytest.approx(0.3333)


# ---------------------------------------------------------------------------
# Multi-provider dispatch (fallback / parallel_merge)
# ---------------------------------------------------------------------------

def test_run_fallback_attempts_tries_next_provider_on_failure():
    from tooling.eval._common import run_fallback_attempts

    def attempt(prov, i):
        if prov == "a":
            raise RuntimeError("a is rate-limited")
        return f"{prov}-{i}"

    successes, failed = run_fallback_attempts(["a", "b"], 3, attempt)
    assert failed == 0
    assert [s for _, s in successes] == ["b-0", "b-1", "b-2"]
    assert {p for p, _ in successes} == {"b"}


def test_run_fallback_attempts_counts_a_slot_failed_only_when_every_provider_fails():
    from tooling.eval._common import run_fallback_attempts

    def attempt(prov, i):
        raise RuntimeError("down")

    successes, failed = run_fallback_attempts(["a", "b"], 2, attempt)
    assert successes == []
    assert failed == 2  # 2 slots, each exhausts both providers


def test_run_parallel_merge_attempts_pools_every_provider_full_runs():
    from tooling.eval._common import run_parallel_merge_attempts

    def attempt(prov, i):
        return f"{prov}-{i}"

    successes, failed = run_parallel_merge_attempts(["a", "b"], 3, attempt)
    assert failed == 0
    # both providers run their own full 3 attempts -> 6 pooled samples
    assert sorted(s for _, s in successes) == ["a-0", "a-1", "a-2", "b-0", "b-1", "b-2"]


def test_run_parallel_merge_attempts_pools_partial_success_when_one_provider_fails():
    from tooling.eval._common import run_parallel_merge_attempts

    def attempt(prov, i):
        if prov == "a":
            raise RuntimeError("a is down")
        return f"{prov}-{i}"

    successes, failed = run_parallel_merge_attempts(["a", "b"], 2, attempt)
    assert failed == 2  # both of a's attempts
    assert sorted(s for _, s in successes) == ["b-0", "b-1"]


def test_run_multi_provider_dispatches_by_mode():
    from tooling.eval._common import run_multi_provider

    def attempt(prov, i):
        return f"{prov}-{i}"

    fb, _ = run_multi_provider(["a", "b"], 1, "fallback", attempt)
    assert [s for _, s in fb] == ["a-0"]  # "a" never fails -> fallback never reaches "b"

    pm, _ = run_multi_provider(["a", "b"], 1, "parallel_merge", attempt)
    assert sorted(s for _, s in pm) == ["a-0", "b-0"]

    with pytest.raises(ValueError):
        run_multi_provider(["a"], 1, "bogus", attempt)


def test_determinism_with_no_providers_flag_errors_when_config_disabled(tmp_path, monkeypatch):
    from tooling.eval import determinism

    monkeypatch.setattr(
        determinism, "load_eval_multi_provider_config",
        lambda: {"enabled": False, "mode": "fallback", "providers": []},
    )
    out = tmp_path / "result.json"
    with pytest.raises(SystemExit):
        determinism.main([
            "--fixtures-dir", str(tmp_path), "--fixtures", "Toy", "--out", str(out),
        ])


def test_determinism_config_fallback_pools_into_one_entry(tmp_path, monkeypatch):
    """eval_multi_provider enabled with mode: fallback (from config, no --providers
    on the CLI): one pooled entry, no by_provider/cross_provider, and the failing
    provider contributes nothing to served_by."""
    import json
    from tooling.eval import determinism
    from tooling.eval._common import freeze, thaw

    fixture = tmp_path / "Toy.scenarios.json"
    fixture.write_text(json.dumps(freeze([_scenario("S1", 3.0), _scenario("S2", 2.0)])))

    def fake_run_debate(scenarios, *, provider, config, sleep_s=0.0):
        if provider == "down":
            raise RuntimeError("down is rate-limited")
        s = thaw(freeze(scenarios))

        class R:
            def __init__(self, sid):
                self.scenario_id = sid
                self.final_viability = 0.6
                self.residual_path_viable = True
                self.debate_factor = 1.0
                self.rounds = []
        return s, [R(sc.scenario_id) for sc in s]

    monkeypatch.setattr(determinism, "run_debate", fake_run_debate)
    # make_provider's return value stands in for the provider identity fake_run_debate checks
    monkeypatch.setattr(determinism, "make_provider", lambda name: name)
    monkeypatch.setattr(
        determinism, "load_eval_multi_provider_config",
        lambda: {"enabled": True, "mode": "fallback", "providers": ["down", "up"]},
    )

    out = tmp_path / "result.json"
    rc = determinism.main([
        "--fixtures-dir", str(tmp_path), "--fixtures", "Toy",
        "--runs", "3", "--top-n", "5", "--max-rounds", "1", "--sleep", "0",
        "--out", str(out),
    ])
    assert rc == 0
    data = json.loads(out.read_text())
    assert data["params"]["providers"] == ["down", "up"]
    assert data["params"]["multi_provider_mode"] == "fallback"
    entry = data["fixtures"]["Toy"]
    assert "by_provider" not in entry
    assert "cross_provider" not in entry
    assert entry["served_by"] == {"up": 3}  # "down" always fails -> fallback always reaches "up"
    assert entry["runs_ok"] == 3
    assert entry["debated_count"] == 2


def test_determinism_config_parallel_merge_pools_both_providers(tmp_path, monkeypatch):
    import json
    from tooling.eval import determinism
    from tooling.eval._common import freeze, thaw

    fixture = tmp_path / "Toy.scenarios.json"
    fixture.write_text(json.dumps(freeze([_scenario("S1", 3.0), _scenario("S2", 2.0)])))

    def fake_run_debate(scenarios, *, provider, config, sleep_s=0.0):
        s = thaw(freeze(scenarios))

        class R:
            def __init__(self, sid):
                self.scenario_id = sid
                self.final_viability = 0.6
                self.residual_path_viable = True
                self.debate_factor = 1.0
                self.rounds = []
        return s, [R(sc.scenario_id) for sc in s]

    monkeypatch.setattr(determinism, "run_debate", fake_run_debate)
    monkeypatch.setattr(determinism, "make_provider", lambda name: name)
    monkeypatch.setattr(
        determinism, "load_eval_multi_provider_config",
        lambda: {"enabled": True, "mode": "parallel_merge", "providers": ["a", "b"]},
    )

    out = tmp_path / "result.json"
    rc = determinism.main([
        "--fixtures-dir", str(tmp_path), "--fixtures", "Toy",
        "--runs", "2", "--top-n", "5", "--max-rounds", "1", "--sleep", "0",
        "--out", str(out),
    ])
    assert rc == 0
    entry = json.loads(out.read_text())["fixtures"]["Toy"]
    # both providers run their own 2 attempts -> 4 pooled samples total
    assert entry["served_by"] == {"a": 2, "b": 2}
    assert entry["runs_ok"] == 4


def test_determinism_explicit_providers_cli_overrides_config_and_uses_legacy_path(tmp_path, monkeypatch):
    """Passing --providers on the CLI always wins over config/ai_config.yaml and
    keeps the legacy per-provider-separate reporting, even if config is enabled."""
    import json
    from tooling.eval import determinism
    from tooling.eval._common import freeze, thaw

    fixture = tmp_path / "Toy.scenarios.json"
    fixture.write_text(json.dumps(freeze([_scenario("S1", 3.0), _scenario("S2", 2.0)])))

    def fake_run_debate(scenarios, *, provider, config, sleep_s=0.0):
        s = thaw(freeze(scenarios))

        class R:
            def __init__(self, sid):
                self.scenario_id = sid
                self.final_viability = 0.6
                self.residual_path_viable = True
                self.debate_factor = 1.0
                self.rounds = []
        return s, [R(sc.scenario_id) for sc in s]

    monkeypatch.setattr(determinism, "run_debate", fake_run_debate)
    monkeypatch.setattr(determinism, "make_provider", lambda name: object())
    # config says "parallel_merge" — the explicit CLI --providers below must ignore it
    monkeypatch.setattr(
        determinism, "load_eval_multi_provider_config",
        lambda: (_ for _ in ()).throw(AssertionError("config should not be consulted")),
    )

    out = tmp_path / "result.json"
    rc = determinism.main([
        "--fixtures-dir", str(tmp_path), "--fixtures", "Toy",
        "--providers", "groq",
        "--runs", "2", "--top-n", "5", "--max-rounds", "1", "--sleep", "0",
        "--out", str(out),
    ])
    assert rc == 0
    entry = json.loads(out.read_text())["fixtures"]["Toy"]
    assert "by_provider" in entry
    assert "groq" in entry["by_provider"]


def test_ablation_providers_falls_back_on_failure(tmp_path, monkeypatch):
    """--providers A B: A fails outright, B serves the fixture."""
    import json
    from tooling.eval import ablation
    from tooling.eval._common import freeze, thaw

    fx = tmp_path / "Toy.scenarios.json"
    fx.write_text(json.dumps(freeze([_scenario("S1", 5.0), _scenario("S2", 4.0)])))

    def fake_run_debate(scenarios, *, provider, config, sleep_s=0.0):
        if provider == "down":
            raise RuntimeError("down is rate-limited")
        s = thaw(freeze(scenarios))

        class R:
            def __init__(self, sid):
                self.scenario_id = sid
                self.final_viability = 0.8
                self.residual_path_viable = True
                self.rounds = []
        return s, [R(sc.scenario_id) for sc in s]

    monkeypatch.setattr(ablation, "run_debate", fake_run_debate)
    monkeypatch.setattr(ablation, "make_provider", lambda name: name)

    out = tmp_path / "abl.json"
    rc = ablation.main([
        "--fixtures-dir", str(tmp_path), "--fixtures", "Toy",
        "--providers", "down", "up", "--top-n", "5", "--max-rounds", "1", "--sleep", "0",
        "--out", str(out),
    ])
    assert rc == 0
    data = json.loads(out.read_text())
    assert data["params"]["providers"] == ["down", "up"]
    assert "kendall_tau" in data["fixtures"]["Toy"]  # succeeded via fallback to "up"


def test_ablation_rejects_both_provider_and_providers(tmp_path):
    from tooling.eval import ablation

    out = tmp_path / "abl.json"
    with pytest.raises(SystemExit):
        ablation.main([
            "--fixtures-dir", str(tmp_path), "--fixtures", "Toy",
            "--provider", "groq", "--providers", "groq", "xai",
            "--out", str(out),
        ])


def test_ablation_with_no_provider_flag_errors_when_config_disabled(tmp_path, monkeypatch):
    """Neither --provider nor --providers, and eval_multi_provider disabled/empty
    in config -> a clear error, not a silent fallback to nothing."""
    from tooling.eval import ablation

    monkeypatch.setattr(
        ablation, "load_eval_multi_provider_config",
        lambda: {"enabled": False, "mode": "fallback", "providers": []},
    )
    out = tmp_path / "abl.json"
    with pytest.raises(SystemExit):
        ablation.main([
            "--fixtures-dir", str(tmp_path), "--fixtures", "Toy",
            "--out", str(out),
        ])


def test_ablation_with_no_provider_flag_uses_config(tmp_path, monkeypatch):
    """Neither --provider nor --providers -> providers come from
    config/ai_config.yaml's eval_multi_provider section."""
    import json
    from tooling.eval import ablation
    from tooling.eval._common import freeze, thaw

    fx = tmp_path / "Toy.scenarios.json"
    fx.write_text(json.dumps(freeze([_scenario("S1", 5.0), _scenario("S2", 4.0)])))

    def fake_run_debate(scenarios, *, provider, config, sleep_s=0.0):
        s = thaw(freeze(scenarios))

        class R:
            def __init__(self, sid):
                self.scenario_id = sid
                self.final_viability = 0.8
                self.residual_path_viable = True
                self.rounds = []
        return s, [R(sc.scenario_id) for sc in s]

    monkeypatch.setattr(ablation, "run_debate", fake_run_debate)
    monkeypatch.setattr(ablation, "make_provider", lambda name: name)
    monkeypatch.setattr(
        ablation, "load_eval_multi_provider_config",
        lambda: {"enabled": True, "mode": "fallback", "providers": ["from-config"]},
    )

    out = tmp_path / "abl.json"
    rc = ablation.main([
        "--fixtures-dir", str(tmp_path), "--fixtures", "Toy",
        "--top-n", "5", "--max-rounds", "1", "--sleep", "0",
        "--out", str(out),
    ])
    assert rc == 0
    data = json.loads(out.read_text())
    assert data["params"]["providers"] == ["from-config"]
    assert "kendall_tau" in data["fixtures"]["Toy"]
