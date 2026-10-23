"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useEffect, useRef, useState } from "react";
import { useConnection } from "@/lib/connection";

/** Signed in, the header is the app: the work, nothing else. Workspace and
 *  the API docs live in the account menu; the guides in the footer. */
const APP_LINKS = [
  { href: "/scans", label: "Scans" },
  { href: "/scans/new", label: "New scan" },
];

/** Signed out, the header is the product's public pages. */
const PUBLIC_LINKS = [
  { href: "/", label: "Overview" },
  { href: "/coverage", label: "Coverage" },
  { href: "/cli", label: "CLI" },
];

/**
 * The link for the section a page belongs to: a scan's page is under Scans and
 * "New scan" keeps its own entry.
 */
function isCurrent(pathname: string, href: string): boolean {
  if (pathname === href) return true;
  if (href === "/" || !pathname.startsWith(`${href}/`)) return false;
  return !(href === "/scans" && pathname.startsWith("/scans/new"));
}

export function Nav() {
  const pathname = usePathname();
  // Subscribed so the docs link follows a server chosen after this render;
  // the value is the same one `getServerUrl()` returns.
  const { serverUrl, authenticated, ready } = useConnection();
  // Below 900px the links fold into a menu button instead of a clipped strip.
  const [open, setOpen] = useState(false);
  const toggle = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    setOpen(false);
  }, [pathname]);

  useEffect(() => {
    if (!open) return;
    function onKey(event: KeyboardEvent) {
      if (event.key === "Escape") {
        setOpen(false);
        toggle.current?.focus();
      }
    }
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [open]);

  // Until the first check answers, which set applies is unknown: render
  // neither, rather than flash the signed-out links at a signed-in tab.
  if (!ready) return <nav className="nav" aria-label="Primary" />;

  const links = authenticated ? APP_LINKS : PUBLIC_LINKS;

  return (
    <nav className="nav" aria-label="Primary">
      <button
        ref={toggle}
        type="button"
        className="nav-toggle"
        aria-expanded={open}
        aria-controls="primary-links"
        onClick={() => setOpen((value) => !value)}
      >
        <span aria-hidden="true">{open ? "✕" : "☰"}</span> Menu
      </button>
      <div id="primary-links" className={open ? "nav-links open" : "nav-links"}>
        {links.map((l) => (
          <Link
            key={l.href}
            href={l.href}
            aria-current={isCurrent(pathname, l.href) ? "page" : undefined}
          >
            {l.label}
          </Link>
        ))}
        {!authenticated && (
          <>
            <span className="sep" aria-hidden="true" />
            <a href={`${serverUrl}/docs`} target="_blank" rel="noreferrer">
              API docs ↗
            </a>
          </>
        )}
      </div>
    </nav>
  );
}
