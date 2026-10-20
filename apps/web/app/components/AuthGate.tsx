"use client";

import { usePathname } from "next/navigation";
import { SignInPanel } from "./SignInPanel";
import { Skel } from "./ui";
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
 * cannot see it and the check is made here. The page itself stays unmounted
 * until the probe settles — the static HTML shows a session check, and a
 * page's own reads never fire unauthenticated. The sign-in form takes the
 * page's place rather than redirecting, so the URL (and any draft the page
 * keeps) survives and signing in shows the page that was asked for.
 */
export function AuthGate({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const { ready, status, authenticated } = useConnection();

  if (PUBLIC_PATHS.has(pathname)) return <>{children}</>;
  if (authenticated) return <>{children}</>;
  if (!ready || status === "checking") {
    return (
      <div className="wrap auth">
        <section className="auth-card auth-skeleton" aria-busy="true" aria-labelledby="session-check-title">
          <h1 id="session-check-title" className="auth-wait-title">Checking your session…</h1>
          <p className="auth-wait-lead">This page opens once sign-in is confirmed.</p>
          <div className="auth-skel" aria-hidden="true">
            <Skel w="32%" h={13} />
            <Skel h={40} />
            <Skel w="32%" h={13} />
            <Skel h={40} />
            <Skel h={42} />
          </div>
        </section>
      </div>
    );
  }
  return <SignInPanel />;
}
