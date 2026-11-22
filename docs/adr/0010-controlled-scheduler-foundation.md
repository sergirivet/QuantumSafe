# ADR 0010: Controlled scheduler foundation

- Status: Accepted
- Date: 2026-11-07

## Context

QuantumSafe must eventually discover recurring changes and detect drift, but autonomous execution introduces duplicate runs, tenant starvation, retries, stale schedules and authorization concerns.

## Decision

Introduce a small scheduler contract in `internal/automation` that:

- validates tenant, target, interval and next run;
- accepts intervals from one minute to thirty days;
- selects only enabled due schedules;
- orders due work deterministically;
- limits concurrent executions;
- propagates cancellation;
- returns per-schedule results.

The current scheduler has a PostgreSQL schedule-store contract with leases and owner-checked completion, plus an in-process execution foundation. It does not yet expose schedule CRUD, run a permanent daemon, retry failed work or mutate migration plans.

## Consequences

- Worker behavior is testable before introducing a distributed runtime.
- Unsafe schedule intervals and disabled work are rejected or skipped.
- Production autonomy still requires schedule CRUD, a supervised worker process, retries, backoff, tenant quotas, audit events and idempotency keys.
