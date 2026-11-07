# ADR 0002: Bounded and authorized network discovery

- Status: Accepted
- Date: 2026-11-05

## Context

QuantumSafe must observe cryptographic properties of authorized public services without becoming an unrestricted port scanner or an SSRF primitive. DNS can return multiple addresses, addresses can change between resolution and connection, and HTTP can redirect to a different host.

Discovery results will later become evidence for inventory and risk decisions, so silent limits and nondeterministic output would make comparisons and audits unreliable.

## Decision

The first discovery engine will:

- accept hostnames, not IP literals or URL-shaped inputs;
- resolve DNS before connecting;
- reject private, loopback, link-local, multicast, unspecified and shared IPv4 ranges;
- connect to the resolved IP address rather than resolving the hostname again at dial time;
- limit the number of addresses, concurrent probes and per-probe duration;
- use context cancellation for the entire operation;
- probe only the explicitly configured ports, initially 80 and 443;
- disable HTTP redirects;
- return structured JSON with a schema version, timestamp, duration, addresses and observed services;
- sort addresses and services deterministically;
- keep configuration bounded and reject invalid values instead of silently changing behavior.

TLS observations are collected for inventory purposes. They are not a statement that the certificate or endpoint satisfies an organization policy. Trust evaluation and risk scoring are separate future concerns.

## Consequences

### Positive

- Lower risk of accidental access to internal network ranges.
- Stable scan output suitable for later persistence and comparison.
- Explicit operational limits protect the scanner and the target.
- Discovery can run autonomously later under policy control.
- The network layer remains testable without Internet access through narrow resolver and dialer seams.

### Negative

- Some legitimate private enterprise targets cannot be scanned by this first public-target mode.
- The scanner may miss services on ports not in the configured set.
- DNS and network observations are time-sensitive and require later evidence provenance.
- A reachable service may still produce incomplete HTTP or TLS metadata.

## Follow-up decisions

Future support for private targets, cloud accounts, authenticated discovery, broader port sets or automatic remediation requires an explicit authorization model, threat model and audit design before implementation.
