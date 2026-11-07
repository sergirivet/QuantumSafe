# QuantumSafe

QuantumSafe is a Go-based platform for cryptographic discovery and post-quantum readiness.

The product is intended to help organizations answer four operational questions:

1. Where is cryptography used?
2. Which assets, services and data are exposed to cryptographic risk?
3. What should be migrated first, and why?
4. How can a migration be validated with evidence?

## Current status

This repository is in the PQC readiness phase. It currently provides:

- a Go module;
- a CLI with `help`, `version` and JSON discovery output for `scan`;
- environment-based configuration;
- structured logging with `log/slog`;
- a version package;
- PostgreSQL-backed cryptographic inventory;
- REST API with versioned endpoints and pagination;
- deterministic, explainable risk assessments;
- NIST-sourced PQC readiness classification;
- deterministic migration plans with validation checks;
- baseline/current migration validation;
- certificate public-key algorithm evidence for migration analysis;
- unit tests for configuration, version metadata, CLI behavior and discovery safety.

## Run

From the repository root:

```bash
go run ./cmd/quantumsafe
go run ./cmd/quantumsafe help
go run ./cmd/quantumsafe version
go run ./cmd/quantumsafe scan example.com
go run ./cmd/quantumsafe serve
go test ./...
go build ./...
```

`scan` performs bounded discovery of public targets: DNS resolution, TCP probes on ports 80 and 443, HTTP metadata and TLS metadata. It rejects IP literals, private addresses and URL-shaped targets.

Use it only against systems for which you have explicit authorization:

```bash
go run ./cmd/quantumsafe scan example.com
```

The log level can be selected with `QS_LOG_LEVEL`:

```bash
QS_LOG_LEVEL=debug go run ./cmd/quantumsafe
```

Supported values are `debug`, `info`, `warn` and `error`. Unknown values are rejected at startup.

Discovery limits can be configured with bounded environment variables:

```bash
QS_SCAN_TIMEOUT=10s
QS_SCAN_MAX_CONCURRENCY=4
QS_SCAN_MAX_ADDRESSES=16
```

The accepted ranges are validated at startup. Invalid values stop the process instead of silently changing scan behavior.

## PostgreSQL inventory

Persistence is optional for local discovery. To enable it, create a PostgreSQL database, apply the schema explicitly and set `QS_DATABASE_URL`:

```bash
export QS_DATABASE_URL="postgres://user:password@localhost:5432/quantumsafe?sslmode=disable"
psql "$QS_DATABASE_URL" -f migrations/001_initial_inventory.sql
go run ./cmd/quantumsafe scan example.com
```

When persistence is enabled, the scan output includes `inventory_scan_id`. The repository can retrieve the complete snapshot with its asset, services, certificates and algorithms. The application does not modify the database schema automatically at startup.

## Project structure

```text
cmd/quantumsafe/       process entry point
internal/app/          application composition and startup
internal/config/       process configuration
internal/version/      build version metadata
internal/discovery/    bounded DNS, TCP, HTTP and TLS discovery
internal/inventory/    relational inventory repository and models
internal/api/          versioned REST API and HTTP error contract
internal/risk/         versioned deterministic risk policy
internal/pqc/          NIST-sourced PQC readiness catalog
internal/migration/    explainable migration planning
migrations/            explicit PostgreSQL schema migrations
exercises/             small Go learning exercises
docs/adr/              architecture decision records
docs/api.md            REST API examples and operational constraints
roadmap.md             staged product and engineering roadmap
```

Packages under `internal/` are private to this module. This keeps the public API surface small while the domain model is still evolving.

Scan reports include a schema version, UTC timestamp, elapsed duration, resolved addresses, truncation status and observed services. Addresses and services are sorted deterministically so future inventory comparisons do not depend on goroutine completion order.

The REST API is intentionally bound to `127.0.0.1:8080` by default and requires PostgreSQL. Authentication and authorization are not implemented yet, so the server must remain behind a trusted boundary. See [docs/api.md](docs/api.md) for the endpoint contract.

## Product direction

QuantumSafe is not intended to be only a port scanner or a certificate dashboard. Its differentiating goal is an evidence-backed cryptographic control loop:

```text
Discover -> Inventory -> Explain risk -> Prioritize migration -> Validate change
```

Enterprise capabilities such as ownership, evidence provenance, policy evaluation, auditability, multi-environment operation and autonomous recurring checks will be introduced only when the underlying domain model can support them reliably.

## Security posture

Discovery must be performed only against systems for which the operator has authorization. Future network functionality must enforce bounded concurrency, timeouts, cancellation, target validation and SSRF protections.

QuantumSafe will use established cryptographic libraries and standards. It will not implement cryptographic primitives from scratch.
