"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useEffect, useId, useRef, useState } from "react";
import { useConnection } from "@/lib/connection";

/**
 * The signed-in member in the topbar: one avatar button that opens who you
 * are, your role, workspace settings, the API docs and sign-out. Signed out, a plain
 * "Sign in" link. Keeps the primary links from sharing a row with an email
 * address, which is what made them wrap.
 */
export function AccountMenu() {
  const { user, role, tenant, authenticated, ready, signOut, serverUrl } = useConnection();
  const pathname = usePathname();
  const [open, setOpen] = useState(false);
  const root = useRef<HTMLDivElement>(null);
  const button = useRef<HTMLButtonElement>(null);
  const menuId = useId();

  useEffect(() => setOpen(false), [pathname]);

  useEffect(() => {
    if (!open) return;
    function onPointer(event: PointerEvent) {
      if (!root.current?.contains(event.target as Node)) setOpen(false);
    }
    function onKey(event: KeyboardEvent) {
      if (event.key === "Escape") {
        setOpen(false);
        button.current?.focus();
      }
    }
    document.addEventListener("pointerdown", onPointer);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("pointerdown", onPointer);
      document.removeEventListener("keydown", onKey);
    };
  }, [open]);

  // Hold the avatar's place until the first check answers: no "Sign in"
  // button flashes at a signed-in tab, and the topbar does not shift.
  if (!ready) return <span className="account-placeholder" aria-hidden="true" />;

  if (!authenticated) {
    return pathname === "/login" ? null : (
      <Link className="btn quiet sm account-signin" href="/login">
        Sign in
      </Link>
    );
  }

  // An operator API key has no member behind it; say so rather than guess.
  const name = user?.display_name || user?.email || "Operator key";
  const initial = (user?.display_name || user?.email || "?").trim().charAt(0).toUpperCase();

  return (
    <div className="account" ref={root}>
      <button
        ref={button}
        type="button"
        className="account-button"
        aria-haspopup="true"
        aria-expanded={open}
        aria-controls={menuId}
        aria-label={`Account: ${name}`}
        onClick={() => setOpen((v) => !v)}
      >
        <span className="account-avatar" aria-hidden="true">{initial}</span>
      </button>
      {open && (
        <div id={menuId} className="account-pop">
          <div className="account-who">
            <span className="account-avatar lg" aria-hidden="true">{initial}</span>
            <span className="account-id">
              <strong>{name}</strong>
              {user?.email && user.email !== name && <span>{user.email}</span>}
            </span>
          </div>
          <p className="account-meta">
            {role && <span className="account-role">{role}</span>}
            {tenant && <span>workspace · {tenant}</span>}
          </p>
          <div className="account-actions">
            <Link href="/workspace" onClick={() => setOpen(false)}>
              Workspace settings
            </Link>
            <a href={`${serverUrl}/docs`} target="_blank" rel="noreferrer">
              API docs ↗
            </a>
            <button type="button" onClick={() => void signOut()}>
              Sign out
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
