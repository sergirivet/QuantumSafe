# QuantumSafe API

The API is served by:

```bash
QS_DATABASE_URL="postgres://user:password@localhost:5432/quantumsafe?sslmode=disable" \
  go run ./cmd/quantumsafe serve
```

The default bind address is `127.0.0.1:8080`. Change it with `QS_HTTP_ADDR` only when the deployment boundary and authentication model are ready for a wider bind.

## Create a scan

```http
POST /api/v1/scans
Content-Type: application/json

{"target":"example.com"}
```

A successful response is `201 Created`:

```json
{
  "scan_id": 42,
  "report": {
    "schema_version": 1,
    "target": "example.com",
    "addresses": [],
    "services": []
  }
}
```

The real report contains the observed addresses and services. Discovery remains restricted to authorized targets and bounded by configured timeouts and concurrency.

## Read a scan

```bash
curl http://127.0.0.1:8080/api/v1/scans/42
curl http://127.0.0.1:8080/api/v1/scans/42/risk
```

The risk endpoint returns the versioned deterministic policy assessment for each observed algorithm. Missing organization context is returned explicitly in `missing_context`; it is never guessed.

## List resources

All collection endpoints support `page` and `page_size` query parameters. `page_size` is limited to 100.

```bash
curl 'http://127.0.0.1:8080/api/v1/assets?page=1&page_size=50'
curl 'http://127.0.0.1:8080/api/v1/services?page=1&page_size=50'
curl 'http://127.0.0.1:8080/api/v1/certificates?page=1&page_size=50'
curl 'http://127.0.0.1:8080/api/v1/algorithms?page=1&page_size=50'
curl 'http://127.0.0.1:8080/api/v1/pqc/readiness?scan_id=42'
curl 'http://127.0.0.1:8080/api/v1/migration/plans?scan_id=42'
curl 'http://127.0.0.1:8080/api/v1/migration/validation?baseline_scan_id=42&current_scan_id=57'
```

Get one asset:

```bash
curl http://127.0.0.1:8080/api/v1/assets/1
```

Collection responses use this envelope:

```json
{
  "items": [],
  "page": 1,
  "page_size": 50,
  "total": 0
}
```

## Errors

Errors have a stable public shape and do not expose SQL, network or stack-trace details:

```json
{
  "error": {
    "code": "invalid_pagination",
    "message": "page must be positive and page_size must be between 1 and 100"
  }
}
```

Authentication and authorization are intentionally not implemented yet. Do not expose this server beyond a trusted local boundary until that layer exists.

## PQC readiness

`GET /api/v1/pqc/readiness?scan_id=42` classifies the cryptographic observations attached to one scan. It reports:

- finalized NIST standards: ML-KEM, ML-DSA and SLH-DSA;
- public-key algorithms in migration scope, such as RSA and ECDSA;
- algorithms in ongoing NIST standardization work, such as Falcon and HQC;
- protocol metadata that is insufficient by itself to establish PQC readiness;
- gaps and migration recommendations.

The catalog cites the official sources in every report. Current sources are NIST FIPS 203, FIPS 204, FIPS 205 and the NIST PQC project page.

## Migration plans

`GET /api/v1/migration/plans?scan_id=42` creates a deterministic, proposed plan from the scan evidence. Each item includes its current algorithm, classification, risk level, priority, dependencies, validation checks and gaps.

Plans do not invent owners or deadlines. Items start as `proposed` and require organization governance before becoming an execution task.

## Migration validation

`GET /api/v1/migration/validation?baseline_scan_id=42&current_scan_id=57` compares two persisted snapshots. It checks target identity, vulnerable algorithms, service coverage and certificate evidence.

The result is one of:

- `passed`: all applicable checks passed;
- `failed`: a target mismatch or vulnerable algorithm remains;
- `inconclusive`: required evidence is missing, for example when a service disappeared from the current scan.
