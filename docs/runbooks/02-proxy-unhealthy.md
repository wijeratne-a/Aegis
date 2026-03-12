# Runbook: Proxy Unhealthy

## Symptom
- Proxy pods not ready or CrashLoopBackOff
- Health check `/healthz` returns non-200

## Checks

1. **Pod status**:
   ```bash
   kubectl get pods -l app=catenar-proxy
   kubectl describe pod <proxy-pod>
   kubectl logs <proxy-pod> --tail=100
   ```

2. **Verifier connectivity**: Proxy must reach verifier. Verify:
   - `VERIFIER_URL` is correct
   - NetworkPolicy allows proxy → verifier egress
   - Verifier is running and healthy

3. **Policy load**: Invalid policy.json or Rego can cause startup failure. If Rego fails to load (e.g. missing file or syntax error), the proxy starts with no payload/response engine and **allows requests** (fail-open). Check logs for "failed to load policy" or "failed to compile payload Rego policy". Check ConfigMap `configmap-policy` or mounted policy volume.

4. **WAL / trace log**: If the WAL partition is full or unwritable, the proxy logs a warning and continues; the affected request is not recorded in the trace. Ensure the WAL volume has sufficient space and is not read-only.

5. **Resource limits**: OOMKilled? Increase memory limits in values.yaml.

## Resolution

- **Verifier down**: Restart verifier, ensure `VERIFIER_URL` is resolvable.
- **Policy error**: Fix policy JSON/Rego, redeploy.
- **TLS/mTLS**: If verifier.tls.enabled, ensure client cert secret is mounted correctly.
