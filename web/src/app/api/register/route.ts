import { NextRequest, NextResponse } from "next/server";
import { registerPolicySchema } from "@/lib/schemas";
import { getSession } from "@/lib/auth";

const MAX_PAYLOAD_BYTES = 1024 * 1024; // 1MB

export async function POST(request: NextRequest) {
  const session = await getSession();
  if (!session) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const raw = await request.text();
  if (Buffer.byteLength(raw, "utf8") > MAX_PAYLOAD_BYTES) {
    return NextResponse.json(
      { error: "Payload too large (max 1MB)" },
      { status: 413 }
    );
  }

  let body: unknown;
  try {
    body = JSON.parse(raw);
  } catch {
    return NextResponse.json({ error: "Invalid JSON" }, { status: 400 });
  }

  const parsed = registerPolicySchema.safeParse(body);
  if (!parsed.success) {
    return NextResponse.json(
      { error: "Invalid request" },
      { status: 400 }
    );
  }

  const baseUrl = process.env.VERIFIER_API_URL ?? "http://127.0.0.1:3000";
  const url = `${baseUrl.replace(/\/$/, "")}/v1/register`;

  try {
    const res = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(parsed.data),
    });
    const data = await res.json();

    if (!res.ok) {
      return NextResponse.json(
        data ?? { error: "Verifier error" },
        { status: res.status }
      );
    }

    return NextResponse.json(data);
  } catch (err) {
    console.error("[api/register] proxy error:", err);
    return NextResponse.json(
      { error: "Failed to reach verifier" },
      { status: 502 }
    );
  }
}
