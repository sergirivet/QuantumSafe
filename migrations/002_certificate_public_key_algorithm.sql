BEGIN;

ALTER TABLE certificates
    ADD COLUMN IF NOT EXISTS public_key_algorithm TEXT NOT NULL DEFAULT '';

COMMIT;
