# QuantumSafe

QuantumSafe is a Go-based platform for cryptographic discovery and post-quantum readiness.

The product is intended to help organizations answer four operational questions:

1. Where is cryptography used?
2. Which assets, services and data are exposed to cryptographic risk?
3. What should be migrated first, and why?
4. How can a migration be validated with evidence?

## Current status

This repository is in the initial CLI phase. It currently provides:

- a Go module;
- a CLI with `help`, `version` and a JSON placeholder for `scan`;
- environment-based configuration;
- structured logging with `log/slog`;
- a version package;
- unit tests for configuration, version metadata and CLI behavior.
## Run

From the repository root:

```bash
go run ./cmd/quantumsafe
go run ./cmd/quantumsafe help
go run ./cmd/quantumsafe version
go run ./cmd/quantumsafe scan example.com
go test ./...
go build ./...
```

`scan` is intentionally only a command contract at this stage. It does not perform network discovery yet.

The log level can be selected with `QS_LOG_LEVEL`:

```bash
QS_LOG_LEVEL=debug go run ./cmd/quantumsafe
```

Supported values are `debug`, `info`, `warn` and `error`. Unknown values currently fall back to `info`.

## Project structure

```text
cmd/quantumsafe/       process entry point
internal/app/          application composition and startup
internal/config/       process configuration
internal/version/      build version metadata
exercises/             small Go learning exercises
docs/adr/              architecture decision records
roadmap.md             staged product and engineering roadmap
```

Packages under `internal/` are private to this module. This keeps the public API surface small while the domain model is still evolving.

## Product direction

QuantumSafe is not intended to be only a port scanner or a certificate dashboard. Its differentiating goal is an evidence-backed cryptographic control loop:

```text
Discover -> Inventory -> Explain risk -> Prioritize migration -> Validate change
```

Enterprise capabilities such as ownership, evidence provenance, policy evaluation, auditability, multi-environment operation and autonomous recurring checks will be introduced only when the underlying domain model can support them reliably.

## Security posture

Discovery must be performed only against systems for which the operator has authorization. Future network functionality must enforce bounded concurrency, timeouts, cancellation, target validation and SSRF protections.

QuantumSafe will use established cryptographic libraries and standards. It will not implement cryptographic primitives from scratch.
