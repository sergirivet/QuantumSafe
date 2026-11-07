# ADR 0004: Explainable deterministic risk policy

- Status: Accepted
- Date: 2026-11-06

## Context

QuantumSafe needs to prioritize cryptographic findings, but no single universal score can represent an organization's business criticality, data sensitivity, dependencies and migration constraints. Presenting an invented score as a standard would be misleading.

## Decision

Implement a small deterministic policy in `internal/risk`.

The policy:

- is explicitly versioned as `quantumsafe-risk-v1`;
- scores each factor from 0 to 5;
- uses a transparent sum with a declared maximum;
- classifies the result into LOW, MEDIUM, HIGH or CRITICAL using thresholds owned by QuantumSafe;
- returns every factor, score, rationale and evidence;
- reports missing organization context separately;
- applies a neutral score of 3 to unknown business context so incomplete data is visible and does not silently become zero risk;
- does not claim to be CVSS, NIST or a regulatory score.

The initial factors are algorithm risk, internet exposure, business criticality, data sensitivity, dependency impact, migration complexity and crypto agility.

Algorithm classifications in this phase are deliberately conservative heuristics for triage. They must be reviewed against current authoritative standards before being used for compliance decisions or automated remediation.

## Consequences

### Positive

- Analysts can explain why a service was prioritized.
- Policy changes can be versioned and compared.
- Missing data becomes an actionable output rather than hidden uncertainty.
- The engine is pure and deterministic, so it is easy to test and run in API or worker processes.

### Negative

- The first policy is not a universal security measurement.
- Business context must be supplied by an organization before results become highly specific.
- Algorithm classification will need authoritative source mapping in the PQC readiness phase.

## Follow-up

PQC classifications and migration priority rules require an explicit source review using current NIST and other applicable official publications. They must not be added as unverified labels to this policy.
