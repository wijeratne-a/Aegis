# Catenar Documentation

## Component Tiers

- **Core runtime:** proxy, verifier, dashboard, sdks, policies — required for the data and control plane
- **Dev tools:** dev/cli (debug watch), tools/catenar-verify (chain verify) — used by `make debug` and `make verify`
- **Optional utilities:** core/crypto (key generation), schemas/ (SCHEMA_DIR), dev/scripts/windows/ — not in the main runtime path

## Architecture & Design

- [ARCHITECTURE.md](ARCHITECTURE.md) — High-level system design: data plane, control plane, SDKs

## Security

- [proxy_mitm_ca_trust.md](proxy_mitm_ca_trust.md) — Proxy TLS MITM and CA trust setup
- [security/trust-model.md](security/trust-model.md) — Lineage trust, VERIFIER_API_KEY, production auth

## Frontend & Standards

- [web/security_protocol.md](web/security_protocol.md) — Authentication and API security

## Operations

- [runbooks/](runbooks/) — Operational playbooks for common incidents

## Demo

- [demo/getting-started.md](demo/getting-started.md) — Quick start and demo script
