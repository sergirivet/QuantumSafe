# ADR 0001: Initial modular monolith architecture

- Status: Accepted
- Date: 2026-10-25

## Context

QuantumSafe is starting as a cryptographic discovery and post-quantum readiness product. The domain is expected to grow across discovery, inventory, risk, migration planning and validation, but there is not yet enough behavior to justify distributed services or infrastructure-heavy abstractions.

The first implementation should be easy to run locally, easy to test and able to evolve toward persistent storage, an API, workers and cloud deployment without committing to those systems prematurely.

## Decision

We will build QuantumSafe as a modular monolith in Go.

The initial structure is:

```text
cmd/quantumsafe/       process entry point
internal/app/          startup and application composition
internal/config/       process configuration
internal/version/      version metadata
docs/adr/              architecture decisions
```

The product executable is named `quantumsafe`.

We will initially use the Go standard library, including `log/slog`, `context`, `testing` and networking packages. External dependencies will be added only when they solve a demonstrated problem better than the standard library or an established, audited implementation is required.

Application code is private under `internal/`. We will not create a public `pkg/` API until a stable, externally reusable contract exists.

Configuration starts with defaults and environment variables. The initial supported setting is `QS_LOG_LEVEL`.

The process entry point remains thin. Application startup, configuration loading and logging composition belong in `internal/app`.

## Consequences

### Positive

- One deployable process and one simple local development workflow.
- Clear package ownership without prematurely designing service boundaries.
- Low dependency and operational overhead.
- A future REST API, worker runner or storage adapter can be added behind existing application boundaries.
- Tests can focus on behavior without requiring cloud services.

### Negative

- The monolith will require discipline as bounded contexts are added.
- Some future extraction work may be needed if an independently scalable component emerges.
- The initial CLI is not yet a multi-user enterprise control plane.

## Explicit non-decisions

We are not introducing PostgreSQL, REST, cloud SDKs, Kubernetes, Helm, an operator, a KMS or a custom cryptographic implementation in this phase.

Those decisions require a concrete use case, a tested domain contract and an operational reason.

## Product quality constraints

Future capabilities must preserve these properties:

- findings include evidence provenance and timestamps;
- risk decisions are explainable and policy-versioned;
- discovery is authorization-aware and bounded;
- sensitive material is not logged or persisted accidentally;
- migrations can be validated rather than merely planned;
- autonomous actions require explicit policy, audit records and safe defaults.
