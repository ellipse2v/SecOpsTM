# Evaluating the Red/Blue Debate Re-Scoring

## What is measured

The HTML report contains **two separate ranked lists**, and they are not the same thing:

| | STRIDE threat table | GDAF attack scenarios |
|---|---|---|
| Unit | one `ExtendedThreat` (pytm / AI / LLM) | one `AttackScenario` (a path through the architecture) |
| Score | VOC severity — STRIDE base score adjusted by target, protocol, data classification, then `RiskContext` deltas (CVE match +0.5, high-risk CWE +0.3, network-exposed +0.7, D3FEND mitigation −0.5) | `path_score` — sum of per-hop `technique_score × vulnerability_weight`, plus boundary `traversal_difficulty` and data-value bonuses |
| Changed by the Red/Blue debate? | **No. Never.** | **Yes** — when the debate converged, `path_score` is multiplied by a `debate_factor` between 0.8 and 1.2 and the risk level is recomputed |

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
| `factor_cv` | coefficient of variation (population stdev / mean) of `debate_factor` for one scenario across the runs. 0 = identical every run. |
| `final_viability_cv_median` | same, over `DebateResult.final_viability` per scenario |
| `debated_count` | distinct scenarios actually debated in ≥1 OK run — all Step-1 dispersion metrics are computed over this subset only, never the never-debated tail (which keeps `debate_factor == 1.0` by default and would pin every metric to 0) |
| `risk_level_flip_rate` | fraction of *debated* scenarios whose CRITICAL/HIGH/MEDIUM/LOW bucket is not the same in every run |
| `rank_stability` | mean pairwise Kendall τ between the full scenario orderings of the runs |
| `rank_stability_debated` | same, but each run's ordering is first filtered to the debated subset (`null` if fewer than 2 scenarios were debated) |
| `rank_stability_banded` | same as `_debated` but scenarios in the same pre-debate confidence band are treated as tied — a within-band reshuffle (scores that were never distinguishable) does not count as instability. `band_count` reports how many bands the fixture split into. |
| `rank_stability_random_baseline` | mean pairwise τ over random shuffles of the debated ids at this k — the value `rank_stability_debated` would take if the debate were pure noise (≈ 0 for k ≥ ~4). |
| `top1_recurrence` | fraction of runs whose #1 debated scenario matches the modal #1 — decision stability, not score stability |
| `topk_set_recurrence` | same, for the top-3 debated *set* |
| `direction_flip_rate` | fraction of *debated* scenarios where `residual_path_viable` (the debate's viable / not-viable verdict) is not constant across runs |
| `direction_agreement` | fraction of scenarios where two providers reach the same viable / not-viable majority verdict |
| `kendall_tau`, `spearman_rho` | pre-debate ordering vs post-debate ordering |
| `kendall_tau_banded` | `kendall_tau` with same-band scenarios tied (ablation) |
| `top5_jaccard` | set overlap of the two top-5s |
| `top5_max_displacement` | largest rank change among the pre-debate top-5 |

## Improvements applied after the first run (2026-08-31)

The first run below fed the ranking with a free 0.0–1.0 `viability_score` float at
the provider's default temperature. Changes since:

- **`debate.temperature: 0.0`** (greedy) is now the default (`config/ai_config.yaml`).
- **Discrete viability** — Red and Blue must return one of `0.0 / 0.25 / 0.5 /
  0.75 / 1.0`; the engine snaps to that grid and the round outcome is
  `min(red, blue)` (the old `− 0.15 × len(techniques_blocked)` term, a raw count
  of an LLM-generated list, is gone).
- **The factor is only applied when the debate converged.** An unconverged debate
  (rounds didn't agree) keeps the GDAF score and contributes only its narrative.
- **Narrower band** — `debate_factor` range `0.5–1.5` → `0.8–1.2`. The debate
  nudges a score, it does not halve or 1.5× it.
- **GDAF is now deterministic** — technique selection sorts with an id tie-break,
  the services set is iterated sorted, and `scenario_id` is a hash of the path
  signature (was `uuid4`). Two GDAF runs are now byte-identical; the committed
  fixtures were regenerated.
- **Confidence bands** — the harness groups scenarios whose `path_score`s are
  within 5 % into a band and reports `rank_stability_banded` / `kendall_tau_banded`
  alongside the raw values, so a within-band reshuffle (scores that were never
  distinguishable) is not counted against the debate.
- The report section is **"Adversarial Review"** with a qualitative verdict, not a
  precise adjusted score.

### Results after the improvements

Re-run 2026-08-31 against the regenerated fixtures, full current build
(`determinism-2026-08-31d.json` / `ablation-2026-08-31d.json`, mistral). The
cross-provider numbers are from an earlier mistral + groq pass on the same build,
before Groq's daily token cap.

**Step 1 — determinism** (Mistral, 3 runs, `--top-n 3 --max-rounds 2`, temp 0):

| Fixture | debated | bands | factor_cv | rank_stability_debated | rank_stability_banded | top1_recurrence | direction_flip |
|---|---|---|---|---|---|---|---|
| GDAF_Debate_Smoke_Test | 1 | 1 | 0.0 | n/a | n/a | 1.0 | 0.0 |
| Kubernetes_Helm_Cluster | 3 | 1 | **0.0** | **1.0** | **1.0** | 1.0 | 0.0 |
| On-Prem_Enterprise_Network | 3 | 3 | **0.0** | **1.0** | **1.0** | 1.0 | 0.0 |

Baseline for comparison: `rank_stability_debated` was 0.11 (Groq) / 0.56 (Mistral)
on Kubernetes and 0.11 on On-Prem; `factor_cv` was 0.03–0.53. Every dispersion
metric is now zero and every reproducibility metric is 1.0. The random-shuffle
baseline for `rank_stability_debated` at k = 3 is −0.33, so 1.0 is not a chance
result. (`final_viability_cv` is still ~0.18 — the raw viability estimate wobbles
between rounds, but the snapped grid + `min()` + converged-gate absorb it before
it reaches the factor. One earlier run scored On-Prem at `rank_stability_debated`
0.56, so Mistral at temp 0 is *nearly* but not perfectly deterministic — n = 3 is
too few to pin the exact value.)

Cross-provider (Mistral vs Groq): `direction_agreement` **1.0** on both Smoke and
Kubernetes — the two models agree on every viable / not-viable verdict.
`factor_delta_mean` 0.07 (Smoke) / 0.10 (Kubernetes).

**Step 2 — ablation** (Mistral, `--top-n 5 --max-rounds 3`, `ablation-2026-08-31d.json`):

| Fixture | bands | kendall τ | kendall τ (banded) | top-5 changed? |
|---|---|---|---|---|
| Kubernetes_Helm_Cluster | 1 | 1.00 | 1.00 | no |
| On-Prem_Enterprise_Network | 3 | 0.996 | 1.00 | no |
| Serverless_AWS_Lambda | 1 | 0.78 | **1.00** | no (all movement within one band) |

`kendall_tau_banded` is **1.00 on every fixture** — the debate makes no cross-band
reordering. The one worked example (On-Prem `GDAF-C5C6AA55`, pre-rank #4 → #2,
Blue cited no detection for the DCSync / credential-dumping path) is a small,
band-neutral move.

### Reading the post-improvement result

The trade the four changes made: the debate re-score went from an **active but
non-reproducible** re-ranker to a **reproducible but timid** one. It is now stable
run to run (factor_cv 0, rank_stability 1.0) and the two providers agree on
direction — but with the narrow `0.8–1.2` band, the converged-gate, and the
discrete grid, it no longer moves any scenario across a confidence band. The
number is trustworthy now; it is also close to a no-op for prioritisation.

**So:** keep the Adversarial Review for its narrative and detection-gap output
(the "Red tried X and could not, Blue has no rule for Y" list is the value), and
treat `debate_factor` as a minor, reproducible tie-break within a band — not a
signal that reorders the risk list. A larger run (`--top-n` ≥ 8, more runs, a
second provider on every fixture) would confirm whether the debate ever earns a
cross-band move on a fixture with more spread.

## Step 1 — Determinism (pre-improvement baseline)

Two providers, 3 runs per fixture, `--top-n 3 --max-rounds 2`. Sources:
`tooling/eval/results/determinism-2026-08-30.json` (groq, `openai/gpt-oss-120b`,
`--sleep 22`) and `determinism-mistral-2026-08-31.json` (mistral,
`mistral-small-latest`, `--sleep 3`). Runs 3/3 OK on both, no failed turns.

| Fixture | provider | debated | factor_cv med | risk flip rate | **rank stability (debated)** | direction flip rate |
|---|---|---|---|---|---|---|
| GDAF_Debate_Smoke_Test | groq | 1 | 0.038 | 0.0 | n/a (1 scenario) | 0.0 |
| GDAF_Debate_Smoke_Test | mistral | 1 | **0.530** | **1.0** | n/a | **1.0** |
| Kubernetes_Helm_Cluster | groq | 3 | 0.076 | **1.0** | **0.11** | 0.0 |
| Kubernetes_Helm_Cluster | mistral | 3 | 0.018 | 0.0 | **0.56** | 0.0 |
| On-Prem_Enterprise_Network | groq | 3 | 0.033 | 0.0 | **0.11** | 0.0 |
| On-Prem_Enterprise_Network | mistral | 3 | 0.065 | 0.0 | **0.11** | 0.0 |

Cross-provider direction-agreement (the automatic Groq-vs-X block) was not
produced: Groq's daily quota was spent, so the two providers ran on different
days and can't be compared in one invocation. Gemini is geo-blocked from the run
location; no xAI key was available.

**Verdict rule.** Headline metric is `rank_stability (debated)` — Kendall τ
between runs over the scenarios the debate actually re-scored. ≥ 0.8 →
**reproducible**. ≤ 0.4 → **noise**: keep the debate as an explanation generator
(the detection-gap list and the Red/Blue narrative have value on their own), stop
treating `debate_factor` as a prioritisation input, or make it opt-in and
labelled experimental. Between → **caveated**. (`factor_cv` — the adjustment
*magnitude* — is secondary; the run showed it can be steady while the ranking
is not.)

**Reading the numbers.**

- **`rank_stability (debated)`** is the recurring signal: **0.11** in three of the
  four multi-scenario cells (both providers on On-Prem, Groq on Kubernetes), 0.56
  in the fourth (Mistral on Kubernetes). 0.11 is near the random baseline —
  re-running the same debate on the same input reshuffles the relative order of
  the three debated scenarios. **Resolution caveat:** with only 3 debated
  scenarios, a pairwise Kendall τ can only be −1, −⅓, ⅓ or 1, so these are coarse
  estimates from a handful of values; a proper reading needs `--top-n` ≥ 8 and
  more runs.
- **`factor_cv` disagrees between providers.** On the 1-scenario Smoke fixture,
  Groq is tight (0.038) and Mistral is chaotic (0.530, with `final_viability_cv`
  1.41 and both flip rates at 1.0). On Kubernetes the order reverses — Mistral
  0.018, Groq 0.076 with every risk bucket flipping. There is no provider-
  independent statement to make about adjustment-magnitude stability.
- **`direction_flip_rate`** (the viable / not-viable verdict) is 0.0 for every
  multi-scenario cell on both providers — the binary call is stable — but 1.0 for
  Mistral on the single Smoke scenario.

**Verdict: caveated, leaning negative for prioritisation.** The one metric that
holds across providers and fixtures says the debated-scenario ordering does not
reproduce (`rank_stability (debated)` ≈ 0.11 in 3 of 4 cells). Adjustment
magnitude is model-dependent and sometimes chaotic. The binary viable/not verdict
is stable. n is small (3 runs, 3 debated scenarios), and k = 3 makes the headline
τ coarse — this is a signal, not proof — but it points away from trusting
`debate_factor` as a ranking input.

## Step 2 — Ablation (pre-improvement baseline)

Provider `mistral` (`mistral-small-latest`), `--all --top-n 5 --max-rounds 3
--sleep 3`, clean run (no failed turns). Source:
`tooling/eval/results/ablation-mistral-2026-08-31.json`. (The 2026-08-30 Groq run
is discarded — it hit the daily token cap and most debate turns errored out,
making its `kendall_tau = 1.0` indistinguishable from "no change".)

| Fixture | scenarios | kendall τ | top-5 Jaccard | top-5 max move | bucket changes | top-5 changed? |
|---|---|---|---|---|---|---|
| Kubernetes_Helm_Cluster | 9 | **0.44** | **0.43** | **5** | 4 | **yes** |
| On-Prem_Enterprise_Network | 43 | 1.00 | 1.00 | 1 | 0 | no |
| Serverless_AWS_Lambda | 10 | **0.33** | 0.67 | **9** | 3 | **yes** |
| GDAF_Debate_Smoke_Test | 1 | — | — | — | — | excluded (<2 scenarios) |

top-5 set unchanged in **1 of 3** fixtures; median Kendall τ **0.44**.

**Worked example** (`Serverless_AWS_Lambda`, scenario `GDAF-B5BC145A`): pre-debate
rank **#1 → post-debate rank #10**. The debate demoted the top GDAF path because,
under adversarial challenge, Red could not advance it — "S3 bucket is explicitly
unauthenticated per grounding facts" (no credentials to abuse) and "no exploitable
CVEs listed in grounding facts" — and Blue cited no detection as needed. So the
raw-`path_score` favourite turned out to be a dead end. That is a *sensible*
demotion.

**Verdict: the debate is an active re-ranker, not an inert one.** It substantially
reordered two of three fixtures — including moving a #1 path to #10 for a
defensible reason — and left the largest fixture untouched. Combined with Step 1:
the debate makes large, plausible-looking ranking changes that **do not reproduce
run to run**. It is finding something real (the Lambda dead-end) but not
reliably.

## Overall

Two stages: a **pre-improvement baseline** (free-float viability, provider
default temperature — the tables further down) and a **post-improvement re-run**
(the "Results after the improvements" section above).

- **Before:** the debate was an active re-ranker (`kendall_tau` 0.33–0.44 on two
  ablation fixtures, a #1 → #10 demotion) whose re-score did **not** reproduce
  (`rank_stability_debated` ≈ 0.11).
- **After** temp 0 + discrete viability + converged-gate + narrow `0.8–1.2` band:
  the re-score is **fully reproducible** (`factor_cv` 0, `rank_stability_debated`
  and `_banded` 1.0, `top1_recurrence` 1.0, cross-provider `direction_agreement`
  1.0) and, as a direct consequence, **timid** — `kendall_tau_banded` is 1.0 on
  every ablation fixture, i.e. it never moves a scenario across a confidence band.

The `debate_factor` is now a small, trustworthy, within-band tie-break rather than
a coin-flip that reorders the risk list. The part worth relying on is still the
Red/Blue narrative and the detection-gap list, not the number.

**Still to do:** a larger run (`--top-n` ≥ 8, `--runs` ≥ 15, a second provider on
every fixture — needs a paid tier or a local model) to see whether the debate
ever earns a cross-band move on a fixture with more score spread, and per-run
instrumentation (`round_count`, degraded-turn flag) to attribute any residual
noise.

## Limitations

- Small n — 3 fixtures × 3 runs for Step 1, 3 scored fixtures for Step 2.
- `--top-n 3` for Step 1 means only 3 scenarios per fixture are ordered, so the
  headline Kendall τ is a coarse estimate (pairwise τ over 3 items is one of
  −1, −⅓, ⅓, 1). Raise `--top-n` and `--runs` for a real reading.
- Two models tested (`openai/gpt-oss-120b`, `mistral-small-latest`). Not a claim
  about "LLMs" in general — and the two disagree on adjustment-magnitude stability.
- Cross-provider `direction_agreement` is available for Smoke and Kubernetes only
  (1.0 for both); Groq's daily token cap knocked it out on the largest fixture.
- No human ground-truth ranking yet. Step 3 (a labelled benchmark scored with
  NDCG@5 / Kendall τ against an analyst ranking) is a separate future spec —
  Step 1's reproducibility result makes it lower priority.
- Groq's free tier caps tokens-per-minute (8,000) *and* tokens-per-day (200,000);
  the per-turn `--sleep` handles the minute cap but one Step 1 run exhausts the
  day cap. Mistral's free tier had no binding limit for these run sizes. A local
  Ollama model removes both constraints and is the right target for a larger
  Step 1.
- `RedBlueDebateEngine._select_scenarios` only debates the top-N by `path_score`
  that also clear `min_viability_threshold`. With `--top-n 5`, a fixture with more
  than 5 scenarios leaves its tail at the pre-debate score, which mechanically
  caps how far Kendall τ and the top-5 metrics can move. Each fixture's scenario
  count and `debated_count` are reported next to the metrics so this is visible.
  For the same reason, Step 1's dispersion metrics are computed over the debated
  subset only — the never-debated tail is constant by construction and would
  otherwise dilute every number toward zero.
- GDAF's own `path_score` has ~0.02-0.15 run-to-run variation from set-iteration
  order (seen on the On-Prem fixture), and `scenario_id` is randomised per
  generation. The frozen fixtures are a fixed snapshot so this does not affect a
  single eval run, but regenerating them produces a different file — hence the
  pinned commit SHA below.

## Reproduce

```bash
export GROQ_API_KEY=gsk_...           # 8000 TPM + 200k TPD free-tier caps
export MISTRAL_API_KEY=...            # no binding free-tier cap for these sizes
# a second working provider name also enables the cross-provider check

# 1. Freeze the GDAF scenarios (offline, no key needed)
python -m tooling.eval.freeze_scenarios --all

# 2. Step 1 — determinism
#    Groq needs --sleep 22 (per-minute cap) and one full run spends the day cap.
#    Mistral runs at --sleep 3 in ~10 min.
python -m tooling.eval.determinism \
    --fixtures GDAF_Debate_Smoke_Test Kubernetes_Helm_Cluster On-Prem_Enterprise_Network \
    --providers mistral --runs 3 --top-n 3 --max-rounds 2 --sleep 3 \
    --out tooling/eval/results/determinism-$(date +%F).json

# 3. Step 2 — ablation
python -m tooling.eval.ablation --all --provider mistral \
    --top-n 5 --max-rounds 3 --sleep 3 \
    --out tooling/eval/results/ablation-$(date +%F).json
```

Fixtures were regenerated 2026-08-31 after the GDAF-determinism fix — they are
now byte-reproducible. Regenerate if `GDAFEngine`,
`AssetTechniqueMapper`, or a template changes.

## Next

Step 3 — a human-labelled benchmark: an analyst ranks the top ~15 threats of
8-10 models by "fix first", then base VOC / debate-adjusted / GDAF rankings are
scored against that with NDCG@5 and Kendall τ. Its own spec when Step 1 clears.
