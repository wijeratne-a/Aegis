# Catenar Deployment

## Open Core Chart

The base Helm chart at `helm/catenar/` deploys the Catenar proxy and verifier with Open Core capabilities:

- **Verifier**: Uses `KEY_PROVIDER=env` with `CATENAR_SIGNING_KEY_HEX` (or `local` with `CATENAR_DEV_ALLOW_EPHEMERAL_KEY=1` for development only)
- **Proxy**: TLS MITM, Rego policy evaluation, BLAKE3 trace chaining
- **Observability**: Prometheus metrics, OTLP export (when configured)

## Catenar Enterprise

For Redis, SIEM integrations (Datadog, Splunk), and AWS KMS or HashiCorp Vault signing, see **Catenar Enterprise**. Contact for licensing.
