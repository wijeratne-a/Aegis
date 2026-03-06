import type { UserRole } from "./auth";

type ClaimValue = string | string[] | undefined;

function parseCsvEnv(value: string | undefined, fallback: string[]): string[] {
  if (!value) return fallback;
  return value
    .split(",")
    .map((v) => v.trim().toLowerCase())
    .filter(Boolean);
}

function parseUserOrgMap(raw: string | undefined): Map<string, string> {
  const map = new Map<string, string>();
  if (!raw) return map;
  for (const pair of raw.split(",")) {
    const [user, org] = pair.split(":").map((v) => v?.trim());
    if (user && org) {
      map.set(user.toLowerCase(), org);
    }
  }
  return map;
}

function claimToString(value: ClaimValue): string | undefined {
  if (typeof value === "string") return value;
  if (Array.isArray(value) && value.length > 0 && typeof value[0] === "string") {
    return value[0];
  }
  return undefined;
}

function claimToList(value: ClaimValue): string[] {
  if (typeof value === "string") {
    return value
      .split(",")
      .map((v) => v.trim().toLowerCase())
      .filter(Boolean);
  }
  if (Array.isArray(value)) {
    return value
      .filter((v): v is string => typeof v === "string")
      .map((v) => v.trim().toLowerCase())
      .filter(Boolean);
  }
  return [];
}

export interface OidcClaimsInput {
  preferred_username?: string;
  email?: string;
  sub?: string;
  role?: string | string[];
  roles?: string | string[];
  org_id?: string | string[];
  organization?: string | string[];
  [key: string]: unknown;
}

export function resolveRoleFromUsername(username: string): UserRole {
  const adminUsers = parseCsvEnv(process.env.ADMIN_USERS, ["admin"]);
  return adminUsers.includes(username.toLowerCase()) ? "admin" : "auditor";
}

export function resolveOrgFromUsername(username: string): string {
  const map = parseUserOrgMap(process.env.USER_ORG_MAP);
  const mapped = map.get(username.toLowerCase());
  if (mapped) return mapped;
  return process.env.DEFAULT_ORG_ID?.trim() || "default";
}

export function resolveIdentityFromOidcClaims(claims: OidcClaimsInput): {
  username: string;
  role: UserRole;
  orgId: string;
} {
  const username =
    claims.preferred_username ??
    claims.email ??
    claims.sub ??
    "unknown-user";

  const roleClaim = process.env.OIDC_ROLE_CLAIM?.trim() || "roles";
  const roleValue = claims[roleClaim] as ClaimValue;
  const resolvedRoleValue = claimToList(roleValue).length > 0
    ? roleValue
    : ((claims.roles ?? claims.role) as ClaimValue);
  const roles = claimToList(resolvedRoleValue);

  const adminRoles = parseCsvEnv(process.env.OIDC_ADMIN_ROLES, ["admin"]);
  const auditorRoles = parseCsvEnv(process.env.OIDC_AUDITOR_ROLES, ["auditor", "viewer", "read-only"]);

  let role: UserRole = resolveRoleFromUsername(username);
  if (roles.some((r) => adminRoles.includes(r))) {
    role = "admin";
  } else if (roles.some((r) => auditorRoles.includes(r))) {
    role = "auditor";
  }

  const orgClaimName = process.env.OIDC_ORG_CLAIM?.trim() || "org_id";
  const orgClaim = claims[orgClaimName] as ClaimValue;
  const orgFromClaim = claimToString(orgClaim) ?? claimToString((claims.organization ?? claims.org_id) as ClaimValue);
  const orgId = orgFromClaim?.trim() || resolveOrgFromUsername(username);

  return {
    username,
    role,
    orgId,
  };
}
