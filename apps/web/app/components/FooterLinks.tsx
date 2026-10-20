"use client";

import Link from "next/link";
import { useConnection } from "@/lib/connection";

/** Footer shortcuts; the app pages appear once the tab is signed in. */
export function FooterLinks() {
  const { authenticated, ready } = useConnection();
  // The links that depend on the session wait for the first check.
  return (
    <nav className="foot-links" aria-label="Footer">
      {ready && authenticated && <Link href="/scans">Scans</Link>}
      <Link href="/coverage">Coverage</Link>
      <Link href="/cli">CLI guide</Link>
      {ready && (authenticated ? <Link href="/scans/new">New scan</Link> : <Link href="/login">Sign in</Link>)}
    </nav>
  );
}
