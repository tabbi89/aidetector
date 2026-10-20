"use client";

import { useEffect, useState } from "react";

export type Theme = "light" | "dark";

const KEY = "aidetector-theme";

/**
 * Light/dark switch. Light is the product default — the system preference is
 * intentionally not consulted, so dark only ever comes from a stored choice
 * (see the boot script in layout.tsx, which applies it before first paint).
 */
export function ThemeToggle() {
  const [theme, setTheme] = useState<Theme>("light");
  const [ready, setReady] = useState(false);

  useEffect(() => {
    const attr = document.documentElement.dataset.theme;
    setTheme(attr === "dark" ? "dark" : "light");
    setReady(true);
  }, []);

  function toggle() {
    const next: Theme = theme === "dark" ? "light" : "dark";
    setTheme(next);
    document.documentElement.dataset.theme = next;
    try {
      localStorage.setItem(KEY, next);
    } catch {
      /* private mode — the choice just doesn't persist */
    }
  }

  const dark = theme === "dark";

  return (
    <button
      type="button"
      className="theme-toggle"
      onClick={toggle}
      aria-pressed={ready ? dark : undefined}
      title={dark ? "Switch to light" : "Switch to dark"}
    >
      <span className="ico" aria-hidden="true">
        {dark ? (
          <svg viewBox="0 0 20 20" width="15" height="15" fill="none" stroke="currentColor" strokeWidth="1.6">
            <path d="M16.5 11.6A7 7 0 0 1 8.4 3.5a7 7 0 1 0 8.1 8.1z" strokeLinejoin="round" />
          </svg>
        ) : (
          <svg viewBox="0 0 20 20" width="15" height="15" fill="none" stroke="currentColor" strokeWidth="1.6">
            <circle cx="10" cy="10" r="3.6" />
            <path d="M10 1.6v2M10 16.4v2M1.6 10h2M16.4 10h2M4.1 4.1l1.4 1.4M14.5 14.5l1.4 1.4M15.9 4.1l-1.4 1.4M5.5 14.5l-1.4 1.4" strokeLinecap="round" />
          </svg>
        )}
      </span>
      <span className="visually-hidden">
        {dark ? "Switch to light theme" : "Switch to dark theme"}
      </span>
    </button>
  );
}
