import { NextResponse } from "next/server";
import { getSession } from "@/lib/auth";

export async function GET() {
  const session = await getSession();
  if (!session) {
    return NextResponse.json({ user: null }, { status: 401 });
  }
  return NextResponse.json({
    user: {
      username: session.username,
      role: session.role ?? "auditor",
      org_id: session.org_id,
      auth_source: session.auth_source ?? "demo",
    },
  });
}
