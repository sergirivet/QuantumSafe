BEGIN;

CREATE TABLE IF NOT EXISTS scans (
    id BIGSERIAL PRIMARY KEY,
    target TEXT NOT NULL CHECK (length(target) > 0),
    schema_version INTEGER NOT NULL,
    scanned_at TIMESTAMPTZ NOT NULL,
    duration_ms BIGINT NOT NULL CHECK (duration_ms >= 0),
    addresses_truncated BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS assets (
    id BIGSERIAL PRIMARY KEY,
    canonical_name TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS scan_addresses (
    scan_id BIGINT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    ip INET NOT NULL,
    PRIMARY KEY (scan_id, ip)
);

CREATE TABLE IF NOT EXISTS services (
    id BIGSERIAL PRIMARY KEY,
    asset_id BIGINT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    ip INET NOT NULL,
    port INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
    protocol TEXT NOT NULL CHECK (length(protocol) > 0),
    first_seen_at TIMESTAMPTZ NOT NULL,
    last_seen_at TIMESTAMPTZ NOT NULL,
    UNIQUE (asset_id, ip, port, protocol)
);

CREATE TABLE IF NOT EXISTS scan_services (
    scan_id BIGINT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    service_id BIGINT NOT NULL REFERENCES services(id) ON DELETE CASCADE,
    PRIMARY KEY (scan_id, service_id)
);

CREATE TABLE IF NOT EXISTS certificates (
    id BIGSERIAL PRIMARY KEY,
    fingerprint_sha256 TEXT NOT NULL UNIQUE CHECK (length(fingerprint_sha256) = 64),
    public_key_algorithm TEXT NOT NULL DEFAULT '',
    subject TEXT NOT NULL,
    issuer TEXT NOT NULL,
    dns_names TEXT[] NOT NULL DEFAULT '{}',
    not_before TIMESTAMPTZ NOT NULL,
    not_after TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS service_certificates (
    scan_id BIGINT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    service_id BIGINT NOT NULL REFERENCES services(id) ON DELETE CASCADE,
    certificate_id BIGINT NOT NULL REFERENCES certificates(id) ON DELETE RESTRICT,
    PRIMARY KEY (scan_id, service_id, certificate_id)
);

CREATE TABLE IF NOT EXISTS algorithms (
    id BIGSERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    category TEXT NOT NULL CHECK (length(category) > 0),
    UNIQUE (name, category)
);

CREATE TABLE IF NOT EXISTS crypto_usages (
    id BIGSERIAL PRIMARY KEY,
    scan_id BIGINT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    service_id BIGINT NOT NULL REFERENCES services(id) ON DELETE CASCADE,
    algorithm_id BIGINT NOT NULL REFERENCES algorithms(id) ON DELETE RESTRICT,
    evidence JSONB NOT NULL,
    observed_at TIMESTAMPTZ NOT NULL,
    UNIQUE (scan_id, service_id, algorithm_id)
);

CREATE INDEX IF NOT EXISTS idx_scans_target_scanned_at ON scans (target, scanned_at DESC);
CREATE INDEX IF NOT EXISTS idx_services_asset ON services (asset_id);
CREATE INDEX IF NOT EXISTS idx_scan_services_service ON scan_services (service_id);
CREATE INDEX IF NOT EXISTS idx_service_certificates_certificate ON service_certificates (certificate_id);
CREATE INDEX IF NOT EXISTS idx_crypto_usages_algorithm ON crypto_usages (algorithm_id);
CREATE INDEX IF NOT EXISTS idx_crypto_usages_service ON crypto_usages (service_id);

COMMIT;
