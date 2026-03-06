import { NextResponse } from "next/server";
import { getSessionCookieConfig } from "@/lib/auth";

export async function POST() {
  const { name, options } = getSessionCookieConfig();
  const response = NextResponse.json({ ok: true });
  response.cookies.set(name, "", { ...options, maxAge: 0 });
  for (const cookieName of [
    "next-auth.session-token",
    "__Secure-next-auth.session-token",
    "authjs.session-token",
    "__Secure-authjs.session-token",
  ]) {
    response.cookies.set(cookieName, "", { ...options, maxAge: 0 });
  }
  return response;
}
