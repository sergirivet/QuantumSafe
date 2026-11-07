# ADR 0003: Relational cryptographic inventory

- Status: Accepted
- Date: 2026-11-05

## Context

Discovery produces observations that must remain queryable over time. A JSON-only store would make ownership, relationships, deduplication and historical comparison difficult. The inventory needs to preserve scan snapshots while allowing assets, services, certificates and algorithms to be reused across scans.

## Decision

Use PostgreSQL with `pgx/v5` and a relational schema:

- `scans` stores immutable scan metadata and snapshot boundaries;
- `assets` identifies a canonical target;
- `scan_addresses` preserves addresses observed by a scan;
- `services` stores the stable asset/IP/port/protocol identity;
- `scan_services` records which services were observed in a scan;
- `certificates` deduplicates certificates by the SHA-256 digest of the DER bytes;
- `service_certificates` records certificate observations per scan;
- `algorithms` deduplicates algorithm names by category;
- `crypto_usages` records algorithm use, scan, service, timestamp and structured evidence.

The raw TLS observation is stored as JSONB only in `crypto_usages.evidence`, because it is evidence attached to a normalized cryptographic usage rather than the primary data model.

Saving a report is one transaction. Reading a scan reconstructs the asset, services, certificates and algorithms from relational queries.

Persistence is enabled with `QS_DATABASE_URL`. Local scans without that variable remain functional and do not require PostgreSQL.

## Consequences

### Positive

- Historical scan evidence is preserved.
- Assets, services, certificates and algorithms can be queried and deduplicated.
- Foreign keys and constraints protect inventory integrity.
- The storage contract is explicit and can later support API and workers.
- The discovery package remains independent of PostgreSQL.

### Negative

- PostgreSQL becomes an operational dependency when persistence is enabled.
- Schema migrations and compatibility must be managed as the product evolves.
- The current CLI does not yet expose a retrieval command; retrieval is available through the repository contract for the upcoming API layer.

## Migration

The initial schema is in `migrations/001_initial_inventory.sql`. Migrations are applied explicitly; the application does not mutate schema automatically at startup.
