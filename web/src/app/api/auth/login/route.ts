import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { createSession, getSessionCookieConfig } from "@/lib/auth";

const loginSchema = z.object({
  username: z.string().min(1),
  password: z.string().min(1),
});

export async function POST(request: NextRequest) {
  const body = await request.json().catch(() => ({}));
  const parsed = loginSchema.safeParse(body);
  if (!parsed.success) {
    return NextResponse.json(
      { error: "Invalid request. username and password required." },
      { status: 400 }
    );
  }

  const { username, password } = parsed.data;

  // Simulated auth: accept any non-empty credentials for demo
  if (!username || !password) {
    return NextResponse.json(
      { error: "Invalid credentials" },
      { status: 401 }
    );
  }

  const token = await createSession(username);
  const { name, options } = getSessionCookieConfig();

  const response = NextResponse.json({ ok: true, username });
  response.cookies.set(name, token, options);
  return response;
}
