"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useEffect } from "react";
import { useConnection } from "@/lib/connection";

/** Where a signed-in tab lives: the overview is for visitors, the work is here. */
export const APP_HOME = "/scans";

/** The header logo: the overview for a visitor, the scans list once signed in. */
export function BrandLink() {
  const { authenticated } = useConnection();
  return (
    <Link href={authenticated ? APP_HOME : "/"} className="brand"
      // A flex link splits its name at the dot ("runpentests ."); say it whole.
      aria-label="runpentests."
    >
      runpentests<span className="dot">.</span>
    </Link>
  );
}

/**
 * Sends a signed-in tab from the overview to the app. The overview stays a
 * static page for visitors, so this only acts once the session check says so.
 */
export function SignedInRedirect() {
  const router = useRouter();
  const { authenticated } = useConnection();

  useEffect(() => {
    if (authenticated) router.replace(APP_HOME);
  }, [authenticated, router]);

  return null;
}
