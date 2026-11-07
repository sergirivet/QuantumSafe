# ADR 0005: NIST-sourced PQC readiness catalog

- Status: Accepted
- Date: 2026-11-06

## Sources

The initial catalog is based on official NIST publications:

- FIPS 203, Module-Lattice-Based Key-Encapsulation Mechanism Standard (ML-KEM): https://csrc.nist.gov/pubs/fips/203/final
- FIPS 204, Module-Lattice-Based Digital Signature Standard (ML-DSA): https://csrc.nist.gov/pubs/fips/204/final
- FIPS 205, Stateless Hash-Based Digital Signature Standard (SLH-DSA): https://csrc.nist.gov/pubs/fips/205/final
- NIST Post-Quantum Cryptography project: https://csrc.nist.gov/projects/post-quantum-cryptography

NIST's project page states that the first three standards provide the foundation for most PQC deployments and separately describes ongoing standardization work, including Falcon and HQC. The catalog records that distinction.

## Decision

Implement a versioned catalog in `internal/pqc` with these classifications:

- `pqc_standardized`: ML-KEM, ML-DSA and SLH-DSA with their FIPS references;
- `quantum_vulnerable`: observed public-key families such as RSA and ECDSA that require migration analysis;
- `ongoing_standardization`: families such as Falcon and HQC that must not be presented as finalized FIPS deployment standards;
- `protocol_metadata`: TLS versions and cipher suites that do not identify the complete public-key migration surface;
- `classical`: symmetric or hash observations requiring separate key-size and usage context;
- `unknown`: observations that cannot be classified safely.

The report includes source URLs, function, classification, migration priority, reasons and gaps. It does not claim that a service is PQC-ready merely because it uses TLS 1.3, a modern cipher suite or a cataloged algorithm. Readiness requires deployment, interoperability, dependency and policy evidence that is not available in the current inventory.

The endpoint is:

```text
GET /api/v1/pqc/readiness?scan_id={id}
```

## Consequences

- PQC findings are traceable to official sources.
- Standardized algorithms and ongoing candidates are not conflated.
- The catalog can be updated independently and versioned when standards or project status change.
- Current discovery must capture certificate public-key algorithms to improve readiness coverage.
- Full migration planning, hybrid protocol analysis and implementation validation remain future work.
