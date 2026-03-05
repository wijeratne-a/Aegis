"use client";

import { Download } from "lucide-react";
import { useSession } from "@/lib/api";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";

function ExportButton({ format, label }: { format: "json" | "csv"; label: string }) {
  const href = `/api/audit/export?format=${format}`;
  return (
    <a href={href} target="_blank" rel="noreferrer">
      <Button variant="outline" className="w-full justify-start sm:w-auto">
        <Download className="mr-2 h-4 w-4" />
        {label}
      </Button>
    </a>
  );
}

export default function CompliancePage() {
  const sessionQuery = useSession();
  const orgId = sessionQuery.data?.org_id ?? "default";

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold">Compliance Dashboard</h1>
        <p className="mt-2 text-muted-foreground">
          Export proof receipt audit trails scoped to your organization.
        </p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Audit Export</CardTitle>
          <CardDescription>
            Current scope: <code className="font-mono">{orgId}</code>
          </CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-3 sm:flex-row">
          <ExportButton format="json" label="Download JSON export" />
          <ExportButton format="csv" label="Download CSV export" />
        </CardContent>
      </Card>
    </div>
  );
}
