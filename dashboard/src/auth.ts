import NextAuth from "next-auth";
import type { JWT } from "next-auth/jwt";
import { resolveIdentityFromOidcClaims } from "@/lib/auth-claims";

const issuer = process.env.OIDC_ISSUER;
const clientId = process.env.OIDC_CLIENT_ID;
const clientSecret = process.env.OIDC_CLIENT_SECRET;

const hasOidcConfig = Boolean(issuer && clientId && clientSecret);

function mapTokenIdentity(token: JWT, profile: Record<string, unknown>) {
  const identity = resolveIdentityFromOidcClaims(profile);
  token.username = identity.username;
  token.role = identity.role;
  token.org_id = identity.orgId;
}

export const { handlers, auth } = NextAuth({
  trustHost: true,
  providers: hasOidcConfig
    ? [
        {
          id: "oidc",
          name: "Enterprise SSO",
          type: "oidc",
          issuer,
          clientId,
          clientSecret,
          checks: ["pkce", "state"],
        },
      ]
    : [],
  session: { strategy: "jwt" },
  callbacks: {
    async jwt({ token, profile, user }) {
      if (profile && typeof profile === "object") {
        mapTokenIdentity(token, profile as Record<string, unknown>);
      }
      if (user?.email && !token.username) {
        token.username = user.email;
      }
      if (!token.role) {
        token.role = "auditor";
      }
      if (!token.org_id) {
        token.org_id = process.env.DEFAULT_ORG_ID?.trim() || "default";
      }
      return token;
    },
    async session({ session, token }) {
      const username = typeof token.username === "string" ? token.username : session.user?.email ?? "unknown-user";
      const role = token.role === "admin" ? "admin" : "auditor";
      const orgId = typeof token.org_id === "string" ? token.org_id : process.env.DEFAULT_ORG_ID?.trim() || "default";

      session.user = {
        ...session.user,
        name: username,
        email: session.user?.email ?? null,
      };
      (session as unknown as Record<string, unknown>).username = username;
      (session as unknown as Record<string, unknown>).role = role;
      (session as unknown as Record<string, unknown>).org_id = orgId;
      return session;
    },
  },
});

export const isOidcConfigured = hasOidcConfig;
