let validated = false;

function hasMinLength(value: string | undefined, min: number): boolean {
  return Boolean(value && value.trim().length >= min);
}

export function validateStartupSecrets(): void {
  const errors: string[] = [];
  const jwtSecret = process.env.JWT_SECRET;
  const nextAuthSecret = process.env.NEXTAUTH_SECRET;
  const ingestToken = process.env.SIDECAR_INGEST_TOKEN;

  if (!hasMinLength(jwtSecret, 32)) {
    errors.push("JWT_SECRET must be set and at least 32 characters");
  }
  if (ingestToken && !hasMinLength(ingestToken, 32)) {
    errors.push("SIDECAR_INGEST_TOKEN must be at least 32 characters when set");
  }

  const allowDemo = process.env.ALLOW_DEMO_LOGIN === "dangerous_insecure_demo_mode";
  if (allowDemo && !hasMinLength(process.env.DEMO_PASSWORD, 16)) {
    errors.push(
      "DEMO_PASSWORD must be set and at least 16 characters when ALLOW_DEMO_LOGIN=dangerous_insecure_demo_mode"
    );
  }

  const oidcConfigured = Boolean(
    process.env.OIDC_ISSUER || process.env.OIDC_CLIENT_ID || process.env.OIDC_CLIENT_SECRET
  );
  if (oidcConfigured) {
    if (!process.env.OIDC_ISSUER) errors.push("OIDC_ISSUER is required when OIDC is enabled");
    if (!process.env.OIDC_CLIENT_ID) errors.push("OIDC_CLIENT_ID is required when OIDC is enabled");
    if (!process.env.OIDC_CLIENT_SECRET) errors.push("OIDC_CLIENT_SECRET is required when OIDC is enabled");
    if (!hasMinLength(nextAuthSecret, 32)) {
      errors.push("NEXTAUTH_SECRET must be set and at least 32 characters when OIDC is enabled");
    }
  }

  if (errors.length > 0) {
    throw new Error(`[startup] configuration validation failed: ${errors.join("; ")}`);
  }
}

export function ensureStartupValidation(): void {
  if (validated) return;
  validateStartupSecrets();
  validated = true;
}
