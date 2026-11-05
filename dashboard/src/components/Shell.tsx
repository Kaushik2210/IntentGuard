"use client";

import { LayoutDashboard, ScrollText, ShieldCheck } from "lucide-react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { Stats, usePoll } from "@/lib/api";

const NAV = [
  { href: "/", label: "Overview", icon: LayoutDashboard },
  { href: "/approvals", label: "Approvals", icon: ShieldCheck },
  { href: "/audit", label: "Audit log", icon: ScrollText },
];

export default function Shell({ children }: { children: React.ReactNode }) {
  const path = usePathname();
  const { data, error } = usePoll<Stats>("/stats", 3000);
  return (
    <div className="flex min-h-screen flex-col md:flex-row">
      <aside className="flex shrink-0 items-center gap-1 border-b border-line bg-panel px-3 py-2 md:w-56 md:flex-col md:items-stretch md:border-b-0 md:border-r md:px-3 md:py-4">
        <div className="mr-3 flex items-center gap-2 px-2 md:mb-4">
          <span className="grid h-7 w-7 place-items-center rounded-lg bg-accent text-black">
            <ShieldCheck size={16} />
          </span>
          <span className="font-semibold tracking-tight">IntentGuard</span>
        </div>
        <nav className="flex gap-1 md:flex-col">
          {NAV.map(({ href, label, icon: Icon }) => {
            const on = path === href;
            return (
              <Link
                key={href}
                href={href}
                aria-current={on ? "page" : undefined}
                className={`flex min-h-9 items-center gap-2 rounded-lg px-2.5 text-[13px] ${on ? "bg-panel2 text-fg" : "text-muted hover:text-fg"}`}
              >
                <Icon size={15} />
                {label}
                {href === "/approvals" && !error && !!data?.pending && (
                  <span className="ml-auto rounded-full bg-review px-1.5 font-mono text-[11px] text-black">{data.pending}</span>
                )}
              </Link>
            );
          })}
        </nav>
        <p className="mt-auto hidden px-2 text-[11px] leading-snug text-muted md:block">
          Prototype. Synthetic data only. Not a guarantee of protection.
        </p>
      </aside>
      <main className="min-w-0 flex-1 p-4 md:p-6">{children}</main>
    </div>
  );
}
