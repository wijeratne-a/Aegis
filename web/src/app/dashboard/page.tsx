import Link from "next/link";
import { Shield, FileCode, Terminal } from "lucide-react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";

const quickLinks = [
  { href: "/dashboard/policy", label: "Policy Builder", icon: Shield, desc: "Register policies and get policy commitments" },
  { href: "/dashboard/verify", label: "Verification Playground", icon: FileCode, desc: "Submit traces and view PoT receipts" },
  { href: "/dashboard/sdk", label: "SDK Sandbox", icon: Terminal, desc: "Copy Python SDK snippets for your project" },
];

export default function DashboardPage() {
  return (
    <div>
      <h1 className="text-2xl font-bold">Dashboard</h1>
      <p className="mt-2 text-muted-foreground">
        Welcome to the Aegis Playground. Choose a tool to get started.
      </p>
      <div className="mt-8 grid gap-4 md:grid-cols-3">
        {quickLinks.map(({ href, label, icon: Icon, desc }) => (
          <Link key={href} href={href}>
            <Card className="transition-colors hover:bg-accent/50">
              <CardHeader>
                <Icon className="h-8 w-8 text-primary" />
                <CardTitle>{label}</CardTitle>
                <CardDescription>{desc}</CardDescription>
              </CardHeader>
            </Card>
          </Link>
        ))}
      </div>
    </div>
  );
}
