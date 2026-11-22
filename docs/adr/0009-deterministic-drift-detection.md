# ADR 0009: Deterministic drift detection before scheduling

- Status: Accepted
- Date: 2026-11-07

## Context

QuantumSafe needs continuous observation, but scheduling scans before defining reliable change semantics would create noisy or unsafe automation. A baseline and current snapshot must be comparable before workers can decide what deserves attention.

## Decision

Implement drift detection as a pure comparison of two persisted snapshots.

It reports:

- added services;
- removed services;
- added algorithms;
- removed algorithms;
- certificate fingerprint changes.

Events are deterministic and sorted by service and event type. Empty snapshots, target mismatches and missing evidence produce an inconclusive report rather than a false change or false stability result.

The initial API is:

```text
GET /api/v1/drift?baseline_scan_id={id}&current_scan_id={id}
```

Recurring scheduling, distributed workers and automatic remediation are deliberately deferred until scan quality, retention and authorization policies are defined.

## Consequences

- Drift semantics are testable before automation is introduced.
- Operators can inspect changes on demand.
- Later workers can reuse the same pure comparison contract.
- An operational scheduler still needs durable schedules, leases, retries, backoff and tenant limits.
