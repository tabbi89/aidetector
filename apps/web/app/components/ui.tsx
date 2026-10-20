"use client";

import { useEffect, useState } from "react";

/** Shimmer placeholder. Sizes are inline so callers stay declarative. */
export function Skel({ w, h = 14, r }: { w?: number | string; h?: number; r?: number }) {
  return (
    <span
      className="skel"
      aria-hidden="true"
      style={{
        display: "block",
        width: w ?? "100%",
        height: h,
        borderRadius: r,
      }}
    />
  );
}

const UNITS: [number, Intl.RelativeTimeFormatUnit][] = [
  [60, "second"],
  [3600, "minute"],
  [86400, "hour"],
  [604800, "day"],
];

function relative(iso: string) {
  const then = new Date(iso).getTime();
  if (Number.isNaN(then)) return "";
  const diff = (then - Date.now()) / 1000;
  const abs = Math.abs(diff);
  if (abs < 45) return "just now";
  const fmt = new Intl.RelativeTimeFormat(undefined, { numeric: "auto" });
  for (const [limit, unit] of UNITS) {
    if (abs < limit) {
      const div = limit === 60 ? 1 : limit === 3600 ? 60 : limit === 86400 ? 3600 : 86400;
      return fmt.format(Math.round(diff / div), unit);
    }
  }
  return new Date(iso).toLocaleDateString();
}

/**
 * "3 minutes ago", refreshed every 30s. Renders nothing until mounted so the
 * server and client markup agree.
 */
export function Ago({ iso }: { iso: string }) {
  const [text, setText] = useState("");

  useEffect(() => {
    const update = () => setText(relative(iso));
    update();
    const t = setInterval(update, 30_000);
    return () => clearInterval(t);
  }, [iso]);

  return (
    <time dateTime={iso} title={new Date(iso).toLocaleString()} suppressHydrationWarning>
      {text}
    </time>
  );
}

/** Copies `value`, then confirms for a beat. */
export function CopyButton({ value, label = "Copy" }: { value: string; label?: string }) {
  const [done, setDone] = useState(false);

  async function copy() {
    try {
      await navigator.clipboard.writeText(value);
      setDone(true);
      setTimeout(() => setDone(false), 1400);
    } catch {
      /* clipboard blocked — nothing useful to say */
    }
  }

  return (
    <button className="copybtn" onClick={copy} aria-label={`${label} ${value}`} type="button">
      {done ? "✓ copied" : "⧉ copy"}
    </button>
  );
}

/** Dismissible error strip. */
export function ErrorBanner({ message, onClose }: { message: string; onClose?: () => void }) {
  return (
    <div className="banner error" role="alert">
      <span aria-hidden="true">⚠</span>
      <span>{message}</span>
      {onClose && (
        <button className="x" onClick={onClose} aria-label="Dismiss error" type="button">
          ✕
        </button>
      )}
    </div>
  );
}
