"use client";

import { useEffect } from "react";

/**
 * Sets the tab title to match the root metadata template (`%s · aidetector`).
 * Client pages cannot export `metadata`; call this once the label is known.
 * Pass null while the label is still loading so a route layout title can stand.
 */
export function usePageTitle(label: string | null | undefined) {
  useEffect(() => {
    if (!label) return;
    document.title = `${label} · aidetector`;
  }, [label]);
}
