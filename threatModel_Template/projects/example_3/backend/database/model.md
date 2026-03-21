# Threat Model: EcoShop — Database Cluster

## Description
The database cluster consists of a primary PostgreSQL instance and a streaming replica.
All data at rest is encrypted with AES-256. Replication uses TLS-encrypted streaming
replication over port 5432. The primary handles all writes; the replica serves read-heavy
analytics queries. Backup snapshots are encrypted and stored to an off-site S3-compatible
object store.

Both instances are located in the Protected DB Zone and are reachable only from the DB
firewall whitelist (DB firewall sub-model is in the parent backend model).

## Context
bom_directory = BOM

## Boundaries
- **Protected DB Zone**:
  isTrusted=True,
  type=execution-environment,
  color=lavender,
  traversal_difficulty=high,
  businessValue="Isolated database zone — strictly whitelisted access"

## Servers
- **PrimaryDB**:
  boundary="Protected DB Zone",
  type=database,
  machine=virtual,
  confidentiality=critical,
  integrity=critical,
  availability=high,
  redundant=True,
  mfa_enabled=True,
  auth_protocol=credentials,
  encryption=AES-256,
  credentials_stored=True,
  ids=False,
  tags=[postgresql-15, primary, read-write, pci-dss, gdpr, encrypted-at-rest],
  businessValue="PostgreSQL primary — all writes, PII and payment tokenization data",
  entry_point=True
- **ReplicaDB**:
  boundary="Protected DB Zone",
  type=database,
  machine=virtual,
  confidentiality=critical,
  integrity=high,
  availability=medium,
  redundant=True,
  mfa_enabled=True,
  auth_protocol=credentials,
  encryption=AES-256,
  credentials_stored=False,
  ids=False,
  tags=[postgresql-15, replica, read-only, streaming-replication],
  businessValue="PostgreSQL streaming replica — read-only queries and failover target"

## Data
- **PaymentToken**:
  description="Tokenized payment data — PAN replaced by token (PCI-DSS scope)",
  classification=SECRET,
  storage_location=[PrimaryDB],
  pii=False,
  dpia=False,
  encrypted_at_rest=True,
  encrypted_in_transit=True,
  credentialsLife=NONE
- **CustomerRecord**:
  description="Customer profile — name, email, address, order history (GDPR scope)",
  classification=SECRET,
  storage_location=[PrimaryDB, ReplicaDB],
  pii=True,
  dpia=True,
  encrypted_at_rest=True,
  encrypted_in_transit=True
- **ReplicationStream**:
  description="PostgreSQL streaming replication WAL data",
  classification=SECRET,
  encrypted_in_transit=True

## Dataflows
- **PrimaryToReplica**:
  from=PrimaryDB,
  to=ReplicaDB,
  protocol=PostgreSQL-Replication,
  port=5432,
  authentication=client-certificate,
  encryption=TLS,
  data="ReplicationStream",
  bidirectional=False

## Protocol Styles
- **PostgreSQL-Replication**: color=purple, line_style=solid

## Severity Multipliers
- **PrimaryDB**: 3.0
- **ReplicaDB**: 2.0
