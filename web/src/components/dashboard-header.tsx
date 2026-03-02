"use client";

import { useRouter } from "next/navigation";
import { useQuery } from "@tanstack/react-query";
import { LogOut, User } from "lucide-react";
import { Button } from "@/components/ui/button";

async function fetchMe() {
  const res = await fetch("/api/auth/me");
  if (!res.ok) throw new Error("Unauthorized");
  const data = await res.json();
  return data.user;
}

export function DashboardHeader() {
  const router = useRouter();
  const { data: user, isLoading } = useQuery({
    queryKey: ["me"],
    queryFn: fetchMe,
    retry: false,
  });

  async function handleLogout() {
    await fetch("/api/auth/logout", { method: "POST" });
    router.push("/login");
    router.refresh();
  }

  return (
    <header className="flex h-14 items-center justify-between border-b border-border/40 px-4">
      <div />
      <div className="flex items-center gap-4">
        {isLoading ? (
          <span className="text-sm text-muted-foreground">Loading...</span>
        ) : user ? (
          <span className="flex items-center gap-2 text-sm">
            <User className="h-4 w-4" />
            {user.username}
          </span>
        ) : null}
        <Button variant="ghost" size="sm" onClick={handleLogout}>
          <LogOut className="mr-2 h-4 w-4" />
          Log out
        </Button>
      </div>
    </header>
  );
}
