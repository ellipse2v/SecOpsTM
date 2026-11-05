# System Model: GDAF Debate Smoke Test

## Description
Minimal two-node system used to smoke-test GDAF attack path generation and the
Red/Blue debate feature with the smallest possible token footprint. Not a
realistic architecture — just enough for one attack path.

## Context
gdaf_context = context/gdaf_test_context.yaml

## Boundaries
- **Internet**: isTrusted=False, type=network-on-prem, traversal_difficulty=low, description="Untrusted public internet — attacker entry point."
- **Internal Network**: isTrusted=True, type=network-on-prem, traversal_difficulty=medium, description="Trusted internal network hosting the target server."

## Actors
- **External Attacker**: boundary=Internet, authenticity=none, isTrusted=False, description="Unauthenticated external attacker with no prior access."

## Servers
- **Target Server**: boundary="Internal Network", type=web-server, machine=virtual, internet_facing=True, mfa_enabled=False, credentials_stored=True, confidentiality=high, integrity=high, availability=medium, description="Single target asset exposed to the attacker for GDAF path testing."

## Dataflows
- **AttackerToServer**: from="External Attacker", to="Target Server", protocol=HTTPS, is_encrypted=True, is_authenticated=False, description="Direct unauthenticated path from the attacker to the target."
