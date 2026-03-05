import { timingSafeEqual } from "crypto";
import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { createSession, getSessionCookieConfig, resolveOrgId, resolveRole } from "@/lib/auth";
import { checkLoginLimit, getTrustedIdentifier } from "@/lib/rate-limit";
import { ensureStartupValidation } from "@/lib/startup";

const loginSchema = z.object({
  username: z.string().min(1),
  password: z.string().min(1),
});

function getLoginRateLimitKey(request: NextRequest): string {
  return getTrustedIdentifier(request, "login");
}

export async function POST(request: NextRequest) {
  ensureStartupValidation();

  const rateKey = getLoginRateLimitKey(request);
  const { allowed } = checkLoginLimit(rateKey);
  if (!allowed) {
    return NextResponse.json(
      { error: "Too many login attempts. Try again later." },
      { status: 429 }
    );
  }

  const body = await request.json().catch(() => ({}));
  const parsed = loginSchema.safeParse(body);
  if (!parsed.success) {
    return NextResponse.json(
      { error: "Invalid request. username and password required." },
      { status: 400 }
    );
  }

  const { username, password } = parsed.data;

  const oidcConfigured = Boolean(
    process.env.OIDC_ISSUER && process.env.OIDC_CLIENT_ID && process.env.OIDC_CLIENT_SECRET
  );
  const allowDemo = process.env.ALLOW_DEMO_LOGIN === "dangerous_insecure_demo_mode";
  if (allowDemo && process.env.NODE_ENV === "production") {
    return NextResponse.json(
      { error: "Demo login cannot be enabled in production" },
      { status: 503 }
    );
  }
  if (!allowDemo && oidcConfigured) {
    return NextResponse.json(
      {
        error: "Demo login disabled. Use enterprise SSO.",
        oidc_login_url: "/api/auth/signin/oidc?callbackUrl=/dashboard",
      },
      { status: 401 }
    );
  }
  if (!allowDemo) {
    return NextResponse.json(
      {
        error:
          "Configure real auth. Production must use IdP or credential store. Set ALLOW_DEMO_LOGIN=dangerous_insecure_demo_mode only for local development.",
      },
      { status: 401 }
    );
  }
  console.warn("[auth] ALLOW_DEMO_LOGIN is enabled; use only for local/demo.");

  const demoPassword = process.env.DEMO_PASSWORD;
  if (!demoPassword || demoPassword.length < 16) {
    return NextResponse.json(
      { error: "DEMO_PASSWORD not configured (min 16 chars)" },
      { status: 503 }
    );
  }

  const a = Buffer.from(demoPassword, "utf8");
  const b = Buffer.from(password, "utf8");
  if (a.length !== b.length) {
    return NextResponse.json(
      { error: "Invalid credentials" },
      { status: 401 }
    );
  }
  try {
    if (!timingSafeEqual(a, b)) {
      return NextResponse.json(
        { error: "Invalid credentials" },
        { status: 401 }
      );
    }
  } catch {
    return NextResponse.json(
      { error: "Invalid credentials" },
      { status: 401 }
    );
  }

  const role = resolveRole(username);
  const org_id = resolveOrgId(username);
  const token = await createSession(username, role, org_id);
  const { name, options } = getSessionCookieConfig();

  const response = NextResponse.json({ ok: true, username, role, org_id });
  response.cookies.set(name, token, options);
  return response;
}
