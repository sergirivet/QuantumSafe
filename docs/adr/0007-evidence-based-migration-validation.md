# ADR 0007: Evidence-based migration validation

- Status: Accepted
- Date: 2026-11-06

## Context

A migration plan is not proof that a system changed. QuantumSafe needs to compare a baseline observation with a later observation and distinguish a successful change from missing evidence.

## Decision

Implement validation as a pure comparison of two persisted inventory snapshots.

The validator checks:

- target identity;
- removal of classified quantum-vulnerable public-key algorithms;
- service coverage;
- comparable certificate evidence.

It returns `passed`, `failed` or `inconclusive`:

- `passed` means all applicable checks passed;
- `failed` means the target mismatched or a vulnerable algorithm remained;
- `inconclusive` means evidence was insufficient, such as a service absent from the current scan.

A missing service is not treated as a successful migration because it may represent an incomplete scan or an outage. The validator does not change inventory, execute remediation or claim compliance.

The API endpoint is:

```text
GET /api/v1/migration/validation?baseline_scan_id={id}&current_scan_id={id}
```

## Consequences

- Migration outcomes are tied to immutable evidence snapshots.
- False positives from incomplete scans are reduced.
- Follow-up work can add scan quality signals, approvals and richer certificate/key-exchange comparison.
- Validation remains independent of cryptographic implementation code.
