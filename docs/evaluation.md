# Evaluating the Red/Blue Debate Re-Scoring

## What is measured

The HTML report contains **two separate ranked lists**, and they are not the same thing:

| | STRIDE threat table | GDAF attack scenarios |
|---|---|---|
| Unit | one `ExtendedThreat` (pytm / AI / LLM) | one `AttackScenario` (a path through the architecture) |
| Score | VOC severity — STRIDE base score adjusted by target, protocol, data classification, then `RiskContext` deltas (CVE match +0.5, high-risk CWE +0.3, network-exposed +0.7, D3FEND mitigation −0.5) | `path_score` — sum of per-hop `technique_score × vulnerability_weight`, plus boundary `traversal_difficulty` and data-value bonuses |
| Changed by the Red/Blue debate? | **No. Never.** | **Yes** — `path_score` is multiplied by a `debate_factor` between 0.5 and 1.5, and the risk level is recomputed |

The debate re-scores **GDAF scenarios only**. It does not touch threat severity.
So the question "does the debate prioritise better than the base score?" is only
meaningful for the GDAF scenario list, compared against **GDAF's own pre-debate
`path_score` ordering**. That is the baseline here.

GDAF itself is deterministic and offline — a graph traversal with MITRE technique
scoring, no LLM. Only the debate pass calls a model.

## Method

- **Frozen fixtures.** `tooling/eval/freeze_scenarios.py` runs GDAF once per
  bundled template and writes the scenarios to
  `tooling/eval/fixtures/<template>.scenarios.json`, committed. Every run below
  reads the same frozen input.
- **Provider forcing.** `SECOPSTM_FORCE_PROVIDER=<key>` pins provider selection
  regardless of the `enabled:` flags in `config/ai_config.yaml`.
- **Step 1 — determinism.** Debate the same fixture N times per provider. Measure
  how far the re-score moves run to run.
- **Step 2 — ablation.** Compare the pre-debate ordering to the post-debate
  ordering, per fixture.
- Metric definitions are in `tooling/eval/metrics.py` with unit tests in
  `tests/test_eval_metrics.py`.

### Metrics

| Name | Meaning |
|---|---|
| `factor_cv` | coefficient of variation (stdev / mean) of `debate_factor` for one scenario across the runs. 0 = identical every run. |
| `risk_level_flip_rate` | fraction of scenarios whose CRITICAL/HIGH/MEDIUM/LOW bucket is not the same in every run |
| `rank_stability` | mean pairwise Kendall τ between the scenario orderings of the runs |
| `direction_flip_rate` | fraction of scenarios where `residual_path_viable` (the debate's viable / not-viable verdict) is not constant across runs |
| `direction_agreement` | fraction of scenarios where two providers reach the same viable / not-viable majority verdict |
| `kendall_tau`, `spearman_rho` | pre-debate ordering vs post-debate ordering |
| `top5_jaccard` | set overlap of the two top-5s |
| `top5_max_displacement` | largest rank change among the pre-debate top-5 |

## Step 1 — Determinism

> **NOT YET RUN.** Fill this section from
> `tooling/eval/results/determinism-<date>.json` (produced by the command in
> *Reproduce* below).

| Fixture | Provider | runs ok | factor_cv median | factor_cv max | risk flip rate | rank stability | direction flip rate |
|---|---|---|---|---|---|---|---|
| _pending_ | | | | | | | |

Cross-provider (Groq vs Grok):

| Fixture | direction_agreement | factor_delta_mean |
|---|---|---|
| _pending_ | | |

**Verdict rule.** `factor_cv` median ≤ 0.05 across fixtures → the re-score is
**stable**, Step 2 and a later Step 3 (human-labelled benchmark) are worth doing.
≥ 0.30 on any fixture → the re-score is **noise**: keep the debate as an
explanation generator (the detection-gap list and the Red/Blue narrative have
value on their own), but stop treating `debate_factor` as a prioritisation input,
or make it opt-in and labelled experimental. Between the two → **caveated**;
report the instability and read Step 2 with it in mind.

**Verdict:** _pending_

## Step 2 — Ablation

> **NOT YET RUN.** Fill from `tooling/eval/results/ablation-<date>.json`.

| Fixture | scenarios | kendall τ | spearman ρ | top-5 Jaccard | top-5 max move | bucket changes |
|---|---|---|---|---|---|---|
| _pending_ | | | | | | |

- top-5 set unchanged in **_N / M_** fixtures
- median Kendall τ: **_pending_**

**Worked example:** _pending_ — the fixture + scenario with the largest top-5
displacement, with the one-line reason from the debate rounds.

**Reading it.** top-5 essentially never moves → the debate is expensive for
prioritisation; recommend opt-in + experimental, or cut. top-5 moves in a
meaningful share of fixtures → the worked example is the evidence it adds signal;
keep it, and a human-labelled Step 3 becomes worth the effort.

**Verdict:** _pending_

## Limitations

- Small n — about four fixtures for Step 1, up to eighteen for Step 2.
- One model per provider. Not a claim about "LLMs" in general.
- LLM output is non-deterministic by construction; this is what Step 1 quantifies.
- No human ground-truth ranking yet. Step 3 (a labelled benchmark scored with
  NDCG@5 / Kendall τ against an analyst ranking) is a separate future spec.
- Step 1 lowers `--top-n` and `--max-rounds` for the token budget, so its numbers
  are a floor on stability, not the production debate config.
- GDAF's own `path_score` has ~0.02-0.15 run-to-run variation from set-iteration order (seen on the On-Prem fixture), and `scenario_id` is randomised per generation. The frozen fixtures are a fixed snapshot so this does not affect a single eval run, but regenerating them produces a different file — hence the pinned commit SHA below.

## Reproduce

```bash
export GROQ_API_KEY=gsk_...
export XAI_API_KEY=xai-...        # optional; enables the cross-provider check

# 1. Freeze the GDAF scenarios (offline, no key needed)
python -m tooling.eval.freeze_scenarios --all

# 2. Step 1 — determinism (~15-30 min, spends tokens)
python -m tooling.eval.determinism \
    --fixtures GDAF_Debate_Smoke_Test Kubernetes_Helm_Cluster On-Prem_Enterprise_Network \
    --providers groq xai --runs 3 --top-n 3 --max-rounds 2 --sleep 8 \
    --out tooling/eval/results/determinism-$(date +%F).json

# 3. Step 2 — ablation (~30-60 min)
python -m tooling.eval.ablation --all --provider groq \
    --top-n 5 --max-rounds 3 --sleep 8 \
    --out tooling/eval/results/ablation-$(date +%F).json
```

Fixtures were generated at commit `9e46110` — regenerate them if `GDAFEngine`,
`AssetTechniqueMapper`, or a template changes.

## Next

Step 3 — a human-labelled benchmark: an analyst ranks the top ~15 threats of
8-10 models by "fix first", then base VOC / debate-adjusted / GDAF rankings are
scored against that with NDCG@5 and Kendall τ. Its own spec when Step 1 clears.
