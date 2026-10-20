"use client";

import Link from "next/link";
import {
  useCallback,
  useEffect,
  useId,
  useRef,
  useState,
  type KeyboardEvent as ReactKeyboardEvent,
} from "react";
import { api } from "@/lib/api";
import { useCapabilities } from "./useCapabilities";

type ExportKey = "json" | "pdf" | "html" | "sarif" | "pentest";

interface ExportItem {
  key: ExportKey;
  label: string;
  hint: string;
  run: (id: string) => Promise<void>;
}

const ITEMS: ExportItem[] = [
  {
    key: "json",
    label: "JSON",
    hint: "Machine-readable findings",
    run: (id) => api.downloadExport(id),
  },
  {
    key: "pdf",
    label: "PDF report",
    hint: "Human-readable report",
    run: (id) => api.downloadPdf(id),
  },
  {
    key: "html",
    label: "HTML report",
    hint: "Saved file, not opened on this origin",
    run: (id) => api.openHtmlReport(id),
  },
  {
    key: "sarif",
    label: "SARIF",
    hint: "Findings as SARIF 2.1.0 for code-scanning dashboards",
    run: (id) => api.downloadSarif(id),
  },
  {
    key: "pentest",
    label: "Pentest report",
    hint: "Markdown report — attack paths, impact and remediation",
    run: (id) => api.downloadPentestReport(id),
  },
];

/**
 * One export control for every report format.
 *
 * The downloads carry the API key on a header, so they go through `api` rather
 * than an <a href> (which would arrive unauthenticated). Premium is advisory:
 * when the API reports the tier unavailable the item is disabled and says so;
 * when entitlement is unknown it is offered and the API's 402 is the truth.
 */
export function ExportMenu({ id }: { id: string }) {
  const { premium } = useCapabilities();
  const premiumLocked = premium?.available === false;
  const menuId = useId();
  const [open, setOpen] = useState(false);
  const [activeIndex, setActiveIndex] = useState(0);
  const [busy, setBusy] = useState<ExportKey | null>(null);
  const [error, setError] = useState<string | null>(null);
  const root = useRef<HTMLDivElement | null>(null);
  const trigger = useRef<HTMLButtonElement | null>(null);

  const enabled = ITEMS.filter((item) => !(item.key === "pentest" && premiumLocked));
  // The upgrade link is the last navigable item when the tier is unavailable.
  const navigable = enabled.length + (premiumLocked ? 1 : 0);

  const close = useCallback((returnFocus = false) => {
    setOpen(false);
    if (returnFocus) trigger.current?.focus();
  }, []);

  // Click outside closes; a hidden tab keeps no menu open.
  useEffect(() => {
    if (!open) return;
    function onPointer(event: PointerEvent) {
      if (root.current && !root.current.contains(event.target as Node)) close();
    }
    document.addEventListener("pointerdown", onPointer);
    return () => document.removeEventListener("pointerdown", onPointer);
  }, [open, close]);

  // Move focus to the first (or last, for ArrowUp) item when the menu opens.
  useEffect(() => {
    if (!open) return;
    const rows = root.current?.querySelectorAll<HTMLElement>(
      '[role="menuitem"]:not([disabled])',
    );
    rows?.[activeIndex]?.focus();
  }, [open, activeIndex]);

  async function run(item: ExportItem) {
    setBusy(item.key);
    setError(null);
    try {
      await item.run(id);
      close(true);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      // A successful download must leave the menu usable: the next export is a
      // normal action, not a one-shot.
      setBusy(null);
    }
  }

  function openMenu(index = 0) {
    setActiveIndex(index);
    setOpen(true);
  }

  function onTriggerKeyDown(event: ReactKeyboardEvent<HTMLButtonElement>) {
    if (event.key === "Enter" || event.key === " " || event.key === "ArrowDown") {
      event.preventDefault();
      openMenu(0);
    } else if (event.key === "ArrowUp") {
      event.preventDefault();
      openMenu(Math.max(navigable - 1, 0));
    }
  }

  function onMenuKeyDown(event: ReactKeyboardEvent<HTMLDivElement>) {
    if (event.key === "Escape") {
      event.preventDefault();
      close(true);
      return;
    }
    if (event.key === "ArrowDown" || event.key === "ArrowUp") {
      event.preventDefault();
      if (navigable === 0) return;
      const step = event.key === "ArrowDown" ? 1 : -1;
      setActiveIndex((current) => (current + step + navigable) % navigable);
      return;
    }
    if (event.key === "Home" || event.key === "End") {
      event.preventDefault();
      if (navigable === 0) return;
      setActiveIndex(event.key === "Home" ? 0 : navigable - 1);
    }
  }

  return (
    <div className="export-menu" ref={root}>
      <button
        ref={trigger}
        type="button"
        className="btn quiet sm export-trigger"
        aria-haspopup="menu"
        aria-expanded={open}
        aria-controls={menuId}
        onClick={() => (open ? close() : openMenu(0))}
        onKeyDown={onTriggerKeyDown}
        disabled={busy !== null}
      >
        ⤓ Export
      </button>

      {open && (
        <div
          id={menuId}
          role="menu"
          aria-label="Export scan"
          className="export-list"
          onKeyDown={onMenuKeyDown}
        >
          {ITEMS.map((item) => {
            const locked = item.key === "pentest" && premiumLocked;
            if (locked) {
              return (
                <button
                  key={item.key}
                  type="button"
                  role="menuitem"
                  className="export-item"
                  disabled
                  aria-disabled="true"
                  title={premium?.reason ?? "Premium plan required"}
                >
                  <span className="export-label">{item.label}</span>
                  <span className="export-badge">Premium plan</span>
                </button>
              );
            }
            return (
              <button
                key={item.key}
                type="button"
                role="menuitem"
                className="export-item"
                disabled={busy !== null}
                onClick={() => run(item)}
                title={item.hint}
              >
                <span className="export-label">
                  {busy === item.key ? `${item.label}…` : item.label}
                </span>
              </button>
            );
          })}
          {premiumLocked && (
            <Link
              role="menuitem"
              className="export-item export-upgrade"
              href="/coverage#premium-tier"
              title="See what the premium tier adds"
            >
              See Premium plan
            </Link>
          )}
        </div>
      )}

      {error && (
        <p className="err export-menu-err" role="alert">
          Could not export: {error}
        </p>
      )}
    </div>
  );
}