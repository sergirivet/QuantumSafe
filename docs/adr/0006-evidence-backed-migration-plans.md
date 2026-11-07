# ADR 0006: Evidence-backed migration plans

- Status: Accepted
- Date: 2026-11-06

## Context

Risk and PQC readiness identify what deserves attention, but an organization needs an actionable migration plan with dependencies and validation criteria. Automatically inventing owners, deadlines or replacement algorithms would create false certainty and could trigger unsafe changes.

## Decision

Generate deterministic migration plan items from one persisted scan snapshot.

Each item includes:

- stable identifier;
- service and current algorithm;
- PQC classification and reference;
- risk level and priority;
- proposed action;
- dependencies;
- validation checks;
- reasons and evidence gaps;
- status, initially `proposed`.

Owners and deadlines remain empty until an organization assigns them. The plan does not execute changes and does not select a concrete replacement without function, dependency and interoperability evidence.

Plans are exposed through:

```text
GET /api/v1/migration/plans?scan_id={id}
```

## Consequences

### Positive

- Migration work is traceable to a specific evidence snapshot.
- Priorities and validation are visible before execution.
- The system can later support approvals, ownership and workflow state without pretending those exist now.
- Plan generation is deterministic and testable.

### Negative

- The first plan is not a project-management system.
- Dependency discovery and ownership still require organization input.
- Migration validation will need a later comparison model between baseline and follow-up scans.
