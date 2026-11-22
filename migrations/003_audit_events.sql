BEGIN;

CREATE TABLE IF NOT EXISTS audit_events (
    id BIGSERIAL PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    subject TEXT NOT NULL,
    action TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id TEXT NOT NULL DEFAULT '',
    outcome TEXT NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL,
    metadata JSONB NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_audit_events_tenant_time ON audit_events (tenant_id, occurred_at DESC);

COMMIT;
