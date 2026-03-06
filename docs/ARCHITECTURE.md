# Aegis Architecture

## Overview

Aegis is a Zero Trust Network Access (ZTNA) layer for AI agents. It sits between agents and external tools/databases, inspecting traffic, enforcing policy, and producing cryptographically verifiable Proof-of-Task (PoT) receipts.

## Components

### Data Plane

- **Proxy** (`core/proxy`): Rust forward proxy with TLS MITM. Decrypts HTTPS, evaluates Rego policies on request and response payloads, blocks violations, and forwards allowed traffic. Emits trace WAL entries for audit.
- **Verifier** (`core/verifier`): Rust API that validates execution traces, signs PoT receipts (Ed25519), and persists policy commitments. Fires webhooks to the control plane on violations.

### Control Plane

- **Dashboard** (`dashboard`): Next.js application for policy registration, receipt viewing, alerts, and incident drill-down. Consumes webhook data from the verifier.

### SDKs

- **Python SDK** (`sdks/python`): `@aegis.trace` decorator, policy registration, trace emission. Used by Python agents.
- **Node.js SDK** (`sdks/nodejs`): Equivalent for Node.js agents.

### Crypto Utilities

- **core/crypto**: Standalone CLI for Ed25519 key generation and BLAKE3 manifest signing. Dev/onboarding utility; not part of the runtime data path.

## Data Flow

1. Agent registers policy with verifier → gets commitment hash.
2. Agent makes outbound HTTP via proxy (HTTP_PROXY/HTTPS_PROXY).
3. Proxy decrypts, parses payload, evaluates `policies/payload.rego`.
4. On block: returns semantic JSON error; optionally forwards to verifier for receipt.
5. On allow: forwards request; buffers response; evaluates `policies/response.rego` (bidirectional defense).
6. Verifier signs receipt (BLAKE3 chain + Ed25519); webhook notifies dashboard.

## Deployment

- **Docker Compose**: Single-command local stack (verifier, proxy, dashboard, Prometheus, Grafana, OTel collector).
- **Helm** (`deploy/helm/`): Kubernetes deployment with ConfigMaps, secrets, and optional Fluent Bit.
- **Observability**: Proxy exports Prometheus metrics; OTel collector can forward to Datadog, Splunk, or Loki.

## Policy as Code

Rego policies live in `policies/` (payload.rego, response.rego, default.rego). Helm mounts them via ConfigMap. For GitOps, policies are managed in version control and deployed via CI/CD.
