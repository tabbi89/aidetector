"use client";

import { useRouter } from "next/navigation";
import { useEffect } from "react";
import { APP_HOME } from "@/app/components/AppHome";
import { SignInPanel } from "@/app/components/SignInPanel";
import { useConnection } from "@/lib/connection";

/**
 * Where to go after signing in: `?next=` when it is a path on this site, else
 * the scans list. Anything else (`//host`, `https://…`) is an open redirect.
 */
function nextPath(): string {
  const raw = new URLSearchParams(window.location.search).get("next") ?? "";
  return raw.startsWith("/") && !raw.startsWith("//") ? raw : APP_HOME;
}

/** The one page a tab may open before it is signed in. */
export default function LoginPage() {
  const router = useRouter();
  const { authenticated } = useConnection();

  // Already signed in (or signed in just now): this page has nothing to do.
  useEffect(() => {
    if (authenticated) router.replace(nextPath());
  }, [authenticated, router]);

  return <SignInPanel />;
}
