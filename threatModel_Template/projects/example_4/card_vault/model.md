# Threat Model: PayFlow — Card Data Vault

## Description
The card data vault is the most sensitive component in the PayFlow architecture. A TokenProxy
service is the only allowed entry point to the HSM and VaultDB — it enforces strict IP
whitelist and mutual TLS authentication. The HSM performs all cryptographic operations
(FIPS 140-2 Level 3). The VaultDB stores tokenized PAN data with AES-256 encryption at rest.
The vault zone has no direct internet path.

**Ghost node pattern:** PaymentAPI (parent model) sends tokenization requests IN (PaymentToVault)
and receives tokens OUT (VaultToPayment) — it appears as a SINGLE bidirectional ghost node in
this diagram's purple "External connections bidirectional" cluster.

## Context
bom_directory = BOM

## Boundaries
- **HSM Zone**:
  isTrusted=True,
  type=execution-environment,
  color=lavender,
  traversal_difficulty=high,
  businessValue="Hardware Security Module zone — cryptographic operations, FIPS 140-2 Level 3"
- **Vault Data Zone**:
  isTrusted=True,
  type=execution-environment,
  color=lightpurple,
  traversal_difficulty=high,
  businessValue="Encrypted card data storage — PCI-DSS CDE, zero internet path"

## Servers
- **TokenProxy**:
  boundary="HSM Zone",
  type=application-server,
  machine=physical,
  confidentiality=critical,
  integrity=critical,
  availability=high,
  mfa_enabled=True,
  auth_protocol=client-certificate,
  encryption=AES-256,
  credentials_stored=True,
  tags=[tokenization, detokenization, pci-dss, fips, whitelist],
  businessValue="Tokenization proxy — sole entry into vault, IP whitelist + mTLS enforced",
  entry_point=True
- **HSM**:
  boundary="HSM Zone",
  type=application-server,
  machine=physical,
  confidentiality=critical,
  integrity=critical,
  availability=critical,
  mfa_enabled=True,
  auth_protocol=client-certificate,
  encryption=AES-256,
  tags=[hsm, pkcs11, fips-140-2, pci-dss, key-management],
  businessValue="Thales Luna HSM — key generation, AES-256 encryption/decryption, PKCS11"
- **VaultDB**:
  boundary="Vault Data Zone",
  type=database,
  machine=physical,
  confidentiality=critical,
  integrity=critical,
  availability=high,
  redundant=True,
  mfa_enabled=True,
  auth_protocol=credentials,
  encryption=AES-256,
  credentials_stored=True,
  tags=[postgresql, tde, pgaudit, pci-dss, pan-storage],
  businessValue="PostgreSQL with Transparent Data Encryption — stores tokenized PAN data"

## Data
- **TokenizeRequest**:
  description="PAN + expiry submitted for HSM tokenization — PCI-DSS in-scope",
  classification=SECRET,
  encrypted_in_transit=True,
  pii=True,
  dpia=True
- **VaultToken**:
  description="PCI-DSS format-preserving token replacing PAN — safe for merchant storage",
  classification=CONFIDENTIAL,
  encrypted_in_transit=True

## Dataflows
- **ProxyToHSM**:
  from=TokenProxy,
  to=HSM,
  protocol=PKCS11,
  port=2223,
  authentication=client-certificate,
  encryption=TLS,
  data="TokenizeRequest"
- **ProxyToVaultDB**:
  from=TokenProxy,
  to=VaultDB,
  protocol=PostgreSQL,
  port=5432,
  authentication=credentials,
  encryption=TLS,
  data="VaultToken"

## Protocol Styles
- **PKCS11**: color=darkpurple, line_style=solid
- **PostgreSQL**: color=blue, line_style=solid

## Severity Multipliers
- **HSM**: 3.0
- **VaultDB**: 3.0
- **TokenProxy**: 2.5
