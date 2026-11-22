# ADR 0008: Governance, authentication and audit foundation

- Status: Accepted
- Date: 2026-11-07

## Context

QuantumSafe now exposes scans, inventory, risk, PQC readiness and migration workflows. An enterprise product must establish who is acting, which tenant owns the data and which permissions are required before adding autonomous workflows.

## Decision

Introduce a private governance package with:

- principals containing subject, tenant and role;
- explicit permissions;
- viewer, analyst and admin roles;
- Bearer authentication through a constant-time compared static token adapter;
- an audit sink contract;
- PostgreSQL audit event persistence without secrets.

The operational `serve` command requires `QS_API_TOKEN`, `QS_API_TENANT_ID`, `QS_API_SUBJECT` and `QS_API_ROLE`. The default bind remains localhost.

The current token adapter is intentionally a bounded transitional mechanism for local or controlled deployments. It is not a replacement for an OIDC/SAML identity provider, token rotation service, tenant directory or external policy engine.

## Authorization

- viewers can read inventory, risk and migration data;
- analysts can also create scans;
- admins can perform all current actions.

Future mutation endpoints must define a specific permission before exposure.

## Audit

Authenticated requests generate audit events containing tenant, subject, action, resource type, outcome and timestamp. Tokens, request bodies and cryptographic material are never included in the event.

## Consequences

- The API no longer needs to be exposed as an unauthenticated operational service.
- Tenant and subject identity exist in the domain before workflows and approvals are added.
- Replacing the token adapter with an enterprise identity provider is isolated behind `governance.Authenticator`.
- Audit persistence is queryable and can later support compliance workflows.
- The current implementation is not yet a complete enterprise identity platform.
