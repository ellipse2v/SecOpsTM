# Customizing Scoring — SecOpsTM

SecOpsTM scoring is driven by `config/scoring_config.yaml`.  All values have
hardcoded fallbacks in the source code, so the file is **optional** — deleting
it or leaving a field blank restores the built-in default.

---

## File location

```
config/scoring_config.yaml
```

The file is loaded **lazily** on first use and cached for the lifetime of the
process.  Restart the server (or CLI) after editing.

---

## Schema reference

### `stride.base_scores`

Starting score for each STRIDE category, on a 1.0–10.0 scale.  Higher = more
severe by default.

```yaml
stride:
  base_scores:
    ElevationOfPrivilege: 9.0   # range 1.0–10.0
    Tampering: 8.0
    InformationDisclosure: 7.5
    Spoofing: 7.0
    DenialOfService: 6.0
    Repudiation: 5.0
```

---

### `stride.severity_thresholds`

Bands that map numeric scores to severity labels.  Must be non-overlapping and
cover the full 1.0–10.0 range to avoid `INFORMATIONAL` fallback for gaps.

```yaml
stride:
  severity_thresholds:
    CRITICAL:      [9.0, 10.0]   # [min_inclusive, max_inclusive]
    HIGH:          [7.5,  8.9]
    MEDIUM:        [6.0,  7.4]
    LOW:           [4.0,  5.9]
    INFORMATIONAL: [1.0,  3.9]
```

---

### `stride.protocol_adjustments`

Additive delta applied when a dataflow uses the specified protocol.  Positive =
more risky, negative = more secure.

```yaml
stride:
  protocol_adjustments:
    SSH:   0.5    # allowed range: -3.0 to +3.0
    HTTPS: -0.3
    HTTP:  0.2
```

Add any protocol name here; only protocols listed receive an adjustment.

---

### `stride.classification_multipliers`

Multiplier applied after the base score and protocol adjustment.  `PUBLIC` (1.0)
is the neutral baseline.

```yaml
stride:
  classification_multipliers:
    PUBLIC:     1.0    # multiplier >= 1.0 recommended
    RESTRICTED: 1.2
    SECRET:     1.5
    TOP_SECRET: 2.0
```

---

### `stride.voc_deltas`

Additive deltas applied when contextual risk signals are present.  Negative
values reduce the score (mitigating signal).

```yaml
stride:
  voc_deltas:
    cve_match:          0.5   # known CVE matches target and STRIDE category
    cwe_high_risk:      0.3   # matched CVE has a high-risk CWE class
    network_exposed:    0.7   # target reachable without auth or encryption
    d3fend_mitigations: -0.5  # D3FEND defensive technique counters the threat
```

---

### `high_risk_cwes`

CWE IDs (as numeric strings) treated as high-exploitability signals for
`voc_deltas.cwe_high_risk`.  Add CWEs relevant to your technology stack.

```yaml
high_risk_cwes:
  - "89"    # SQL Injection
  - "78"    # OS Command Injection
  - "502"   # Deserialization
  # ... add more as needed
```

Full MITRE CWE catalogue: https://cwe.mitre.org/data/definitions/

---

### `deduplication.jaccard_threshold`

When `ThreatConsolidator` merges pytm and AI threats, two threats for the same
target + STRIDE category are treated as duplicates if their Jaccard word-overlap
meets this threshold (AI wins on duplicate).

```yaml
deduplication:
  jaccard_threshold: 0.3   # range 0.0–1.0; lower = more aggressive merging
```

Lower values → more pytm threats replaced by AI equivalents.
Higher values → more pytm threats kept alongside AI threats.

---

### `technique_mapper.minimum_score`

Techniques with a composite score below this threshold are discarded before
returning the `top_k` list.

```yaml
technique_mapper:
  minimum_score: 0.4   # range 0.0–1.0
```

---

### `technique_mapper.boosts`

Additive boosts applied in `AssetTechniqueMapper.get_techniques()`.

```yaml
technique_mapper:
  boosts:
    platform_match:    0.5   # technique platform matches asset platform
    primary_tactic:    0.4   # technique tactic is primary for this asset type
    hop_position:      0.3   # technique tactic matches the GDAF hop position
    key_technique:     0.6   # technique is in asset type's key_techniques list
    actor_known_ttp:   0.5   # technique is in the actor's known TTPs
    no_auth:           0.3   # asset has no authentication
    no_encryption:     0.2   # asset has no encryption (credential-access)
    no_mfa:            0.2   # asset has no MFA
    legacy:            0.2   # asset is tagged as legacy
    service_match:     0.35  # technique tactic matches a protocol tactic boost
    key_tech_service:  0.5   # technique is a key_technique for an exposed protocol
    credentials_stored: 0.4  # asset stores credentials (credential-access)
```

---

### `gdaf.classification_scores`

Sensitivity weight (0.0–1.0) assigned to each data classification level when computing
`data_value` on dataflow edges.  Higher = more attractive target for an attacker.

```yaml
gdaf:
  classification_scores:
    top_secret: 1.0   # range 0.0–1.0
    secret: 0.7
    restricted: 0.4
    public: 0.0
    unknown: 0.1
```

---

### `gdaf.traversal_bonus`

Additive bonus to `hop_weight` based on how easy a boundary is to cross
(`traversal_difficulty` attribute on boundaries).  Easier = higher attacker probability.

```yaml
gdaf:
  traversal_bonus:
    low: 0.3    # easy to cross — more attractive hop
    medium: 0.1
    high: 0.0   # hard to cross — attacker still evaluated, lower probability
```

---

### `gdaf.detection_coverage`

Maps BOM `detection_level` values to a float coverage score used in the
scenario-level detection average.

```yaml
gdaf:
  detection_coverage:
    none: 0.0
    low: 0.2
    medium: 0.5
    high: 0.8
```

---

### `gdaf.hop_weights`

Additive and multiplicative weights applied when computing `hop_weight` for each
hop in `_build_scenario()`.  `hop_weight` starts at 1.0 and each signal adds to it.

```yaml
gdaf:
  hop_weights:
    no_auth: 0.4           # edge has no authentication
    no_encryption: 0.3     # edge has no encryption
    no_mfa: 0.2            # node has no MFA
    cia_contribution: 0.1  # multiplied by node CIA score (0–1)
    data_value_factor: 0.3 # multiplied by edge data_value (0–1)
    cve_per_cve: 0.15      # per unpatched CVE on the node
    cve_cap: 0.5           # maximum total CVE bonus regardless of count
```

---

### `gdaf.target_cia_bonus`

Additive bonus applied to `path_score` from the target asset's CIA criticality score.
Keeps target importance independent from the path difficulty score.

```yaml
gdaf:
  target_cia_bonus: 0.5   # range 0.0–1.0
```

---

### `gdaf.risk_thresholds`

`path_score` cutoffs that map to risk labels.  Scores are calibrated for the default
`hop_weight` range (1.0–2.0) × average technique score (1.0–2.5).

```yaml
gdaf:
  risk_thresholds:
    CRITICAL: 4.0   # path_score >= 4.0
    HIGH: 2.8       # path_score >= 2.8
    MEDIUM: 1.8     # path_score >= 1.8
                    # below MEDIUM → LOW
```

---

### `gdaf.defaults`

Fallback values used when no `risk_criteria` block is present in the GDAF context YAML
and no auto-generated context is available.

> **Note:** When GDAF runs without a hand-crafted context file (`_auto_context()` is used),
> `max_hops`, `max_paths_per_objective`, and `acceptable_risk_score` are taken from the
> auto-generated `risk_criteria` dict (same hardcoded values) rather than from this section.
> These defaults only apply when a context YAML exists but omits the `risk_criteria` key.

```yaml
gdaf:
  defaults:
    max_hops: 7                    # maximum path depth in BFS traversal
    max_paths_per_objective: 3     # top N paths kept per objective × actor pair
    acceptable_risk_score: 5.0     # path_score above this → unacceptable_risk=True
    gdaf_min_technique_score: 0.8  # minimum AssetTechniqueMapper score for OR-branch rendering
```

---

## Ranking weights

The composite threat ranking weights (severity / confidence / risk_signals) are
configured in `config/ai_config.yaml` under `threat_generation.ranking_weights`:

```yaml
# config/ai_config.yaml — SECTION 2
threat_generation:
  ranking_weights:
    severity: 0.4      # must sum to 1.0
    confidence: 0.3
    risk_signals: 0.3
```

---

## Example: hardening for OT/ICS environments

```yaml
# config/scoring_config.yaml — OT/ICS profile example
stride:
  base_scores:
    ElevationOfPrivilege: 9.5
    Tampering: 9.0

  voc_deltas:
    network_exposed: 1.2   # higher penalty — OT systems should never be internet-facing
    d3fend_mitigations: -0.3  # fewer OT-specific mitigations available

deduplication:
  jaccard_threshold: 0.4   # keep more distinct threats in OT environments

technique_mapper:
  minimum_score: 0.3       # cast a wider net for OT-specific techniques
```

---

## Related documentation

- `docs/customizing_prompts.md` — customize LLM prompt templates
- `CONTRIBUTING_ASSET_TYPES.md` — add new asset types to the community registry
- `config/asset_types_community.yaml` — asset type to MITRE platform/tactic mapping
- `config/protocols_community.yaml` — protocol to tactic boost mapping
