import test from "node:test";
import assert from "node:assert/strict";
import { resolveIdentityFromOidcClaims } from "@/lib/auth-claims";

test("maps admin role and org from OIDC claims", () => {
  const prevRoleClaim = process.env.OIDC_ROLE_CLAIM;
  const prevOrgClaim = process.env.OIDC_ORG_CLAIM;
  const prevAdminRoles = process.env.OIDC_ADMIN_ROLES;
  try {
    process.env.OIDC_ROLE_CLAIM = "roles";
    process.env.OIDC_ORG_CLAIM = "org";
    process.env.OIDC_ADMIN_ROLES = "admin,platform-admin";

    const identity = resolveIdentityFromOidcClaims({
      preferred_username: "alice",
      roles: ["platform-admin"],
      org: "acme",
    });

    assert.equal(identity.username, "alice");
    assert.equal(identity.role, "admin");
    assert.equal(identity.orgId, "acme");
  } finally {
    process.env.OIDC_ROLE_CLAIM = prevRoleClaim;
    process.env.OIDC_ORG_CLAIM = prevOrgClaim;
    process.env.OIDC_ADMIN_ROLES = prevAdminRoles;
  }
});

test("falls back to username mapping when claims missing", () => {
  const prevUserMap = process.env.USER_ORG_MAP;
  try {
    process.env.USER_ORG_MAP = "bob:org-b";
    const identity = resolveIdentityFromOidcClaims({ preferred_username: "bob" });
    assert.equal(identity.role, "auditor");
    assert.equal(identity.orgId, "org-b");
  } finally {
    process.env.USER_ORG_MAP = prevUserMap;
  }
});
