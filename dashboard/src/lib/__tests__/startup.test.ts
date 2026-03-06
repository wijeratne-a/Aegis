import test from "node:test";
import assert from "node:assert/strict";
import { validateStartupSecrets } from "@/lib/startup";

function withEnv(patch: Record<string, string | undefined>, fn: () => void) {
  const previous = new Map<string, string | undefined>();
  for (const [key, value] of Object.entries(patch)) {
    previous.set(key, process.env[key]);
    if (value === undefined) {
      delete process.env[key];
    } else {
      process.env[key] = value;
    }
  }
  try {
    fn();
  } finally {
    for (const [key, value] of previous.entries()) {
      if (value === undefined) {
        delete process.env[key];
      } else {
        process.env[key] = value;
      }
    }
  }
}

test("accepts valid baseline startup configuration", () => {
  withEnv(
    {
      JWT_SECRET: "a".repeat(32),
      OIDC_ISSUER: undefined,
      OIDC_CLIENT_ID: undefined,
      OIDC_CLIENT_SECRET: undefined,
      NEXTAUTH_SECRET: undefined,
    },
    () => {
      assert.doesNotThrow(() => validateStartupSecrets());
    }
  );
});

test("requires OIDC secrets when OIDC enabled", () => {
  withEnv(
    {
      JWT_SECRET: "a".repeat(32),
      OIDC_ISSUER: "https://issuer.example.com",
      OIDC_CLIENT_ID: "client",
      OIDC_CLIENT_SECRET: "secret",
      NEXTAUTH_SECRET: "short",
    },
    () => {
      assert.throws(() => validateStartupSecrets(), /NEXTAUTH_SECRET/);
    }
  );
});
