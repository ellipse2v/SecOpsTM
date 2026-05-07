# Contributing Asset Types and Protocols

SecOpsTM uses two YAML files as the single source of truth for MITRE ATT&CK mappings:

- `config/asset_types_community.yaml` — asset type → platforms, tactics, key techniques
- `config/protocols_community.yaml` — protocol → tactic boosts, key techniques

## Adding a New Asset Type

Add an entry to `config/asset_types_community.yaml` under the `asset_types:` key:

```yaml
  my-custom-type:
    description: "Brief human-readable description"
    category: endpoint          # endpoint | network | server | ot | iot | cloud | identity
    platforms: [Windows, Linux] # MITRE ATT&CK platform names — see valid values below
    tactics: [initial-access]   # kebab-case tactic IDs — see valid values below
    key_techniques: [T1190]     # optional; technique IDs scored highly for this type
    fuzzy_matches: [mytype, mt] # lowercase substrings for loose type name matching
    icon_url: ""                # reserved for future use — leave empty
```

### Valid `platforms` values (exact case required)

`Windows`, `Linux`, `macOS`, `Network Devices`, `Embedded`, `Office Suite`, `IaaS`, `Containers`

### Valid `tactics` values (kebab-case)

`initial-access`, `execution`, `persistence`, `privilege-escalation`, `defense-evasion`,
`credential-access`, `discovery`, `lateral-movement`, `collection`, `command-and-control`,
`exfiltration`, `impact`

### Fuzzy matching and ordering

`_normalize_type()` iterates YAML entries in declaration order. If two entries have overlapping
`fuzzy_matches` patterns, place the more specific entry earlier in the file.

**Example:** `pki` is declared before `auth-server` because `"certificate-authority"` contains
`"auth"` — without this ordering, it would wrongly resolve to `auth-server`.

**Known short-pattern false positives (inherited from original Python source):**
- `dc` matches `domain-controller` but also matches strings like `load-balancer-dc1`
- `log` matches `siem` but also matches strings like `analog-device`
- `git` matches `repository` but also matches strings like `digital-twin`

These are pre-existing trade-offs. When adding new `fuzzy_matches`, prefer longer, more specific
patterns to avoid similar false positives.

## Adding a New Protocol

Add an entry to `config/protocols_community.yaml` under the `protocols:` key:

```yaml
  my-protocol:
    tactic_boost: [lateral-movement]  # tactics boosted when this protocol is exposed
    key_techniques: [T1021.001]       # technique IDs always boosted for this protocol
```

## Submitting a PR

1. Add your entry to the appropriate YAML file.
2. Run the test suite: `python -m pytest tests/test_asset_technique_mapper.py -v`
3. Open a PR with:
   - A brief description of the asset type or protocol
   - At least one MITRE ATT&CK reference justifying your tactic/technique choices
   - The domain/industry context (OT, IoT, medical, cloud, etc.)

## Future Work

- `icon_url`: PNG icons (64×64) will be added in a future sprint. Leave this field empty for now.
- Formal YAML schema validation (MITRE platform names, tactic ID format) is planned.
