import { NextRequest, NextResponse } from "next/server";
import { getSession } from "@/lib/auth";
import { getAlertByIncidentId } from "@/lib/alert-store";
import { classifyViolation } from "@/lib/severity";
import { ensureStartupValidation } from "@/lib/startup";

export async function GET(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  ensureStartupValidation();

  const session = await getSession();
  if (!session) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const { id: incidentId } = await params;
  if (!incidentId) {
    return NextResponse.json({ error: "Missing incident ID" }, { status: 400 });
  }

  const alert = getAlertByIncidentId(incidentId);
  if (!alert) {
    return NextResponse.json({ error: "Incident not found" }, { status: 404 });
  }

  return NextResponse.json({
    ...alert,
    severity: classifyViolation(alert.reason).toString(),
  });
}
