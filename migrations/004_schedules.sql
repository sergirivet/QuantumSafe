BEGIN;

CREATE TABLE IF NOT EXISTS schedules (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    target TEXT NOT NULL,
    interval_seconds BIGINT NOT NULL CHECK (interval_seconds BETWEEN 60 AND 2592000),
    next_run TIMESTAMPTZ NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    lease_owner TEXT NOT NULL DEFAULT '',
    lease_until TIMESTAMPTZ,
    last_run TIMESTAMPTZ,
    last_error TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_schedules_due ON schedules (enabled, next_run);
CREATE INDEX IF NOT EXISTS idx_schedules_tenant ON schedules (tenant_id);

COMMIT;
