"use client";

import { usePathname } from "next/navigation";
import { SignInPanel } from "./SignInPanel";
import { useConnection } from "@/lib/connection";

/**
 * Pages a tab may open before it is signed in: the product's own explanation
 * (overview, CLI guide, coverage) and sign-in itself. Everything that reads or
 * writes workspace data is behind the gate. `Nav` and `FooterLinks` read this.
 */
export const PUBLIC_PATHS: ReadonlySet<string> = new Set(["/", "/cli", "/coverage", "/login"]);

/**
 * Every page outside `PUBLIC_PATHS` needs an accepted session or API key.
 *
 * The session token lives in this tab's sessionStorage, so the server render
 * cannot see it and the check is made here. Nothing of the page renders until
 * the probe settles: the static HTML carries no page content, and a page's own
 * reads never fire unauthenticated. The sign-in form takes the page's place
 * rather than redirecting, so the URL (and any draft the page keeps) survives
 * and signing in shows the page that was asked for.
 */
export function AuthGate({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const { ready, status, authenticated } = useConnection();

  if (PUBLIC_PATHS.has(pathname)) return <>{children}</>;
  if (authenticated) return <>{children}</>;
  if (!ready || status === "checking") {
    return <div className="wrap auth-wait" aria-busy="true" />;
  }
  return <SignInPanel />;
}
