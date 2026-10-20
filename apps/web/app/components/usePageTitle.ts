"use client";

import { useEffect } from "react";
import { TITLE_SUFFIX } from "./title";

// Mounted holders, oldest first. Only the newest keeps the title, so two
// holders can never take turns overwriting each other.
const holders: object[] = [];

/**
 * Sets the tab title in the root metadata template's shape (`<label> · aidetector`).
 * Client pages cannot export `metadata`; call this once the label is known.
 * Pass null while the label is still loading so the route layout's title stands.
 *
 * Next.js can publish a route title after this effect has run (metadata
 * streams separately from the page), so the label is held until the component
 * unmounts or the label changes. Then the latest route title is put back.
 */
export function usePageTitle(label: string | null | undefined) {
  useEffect(() => {
    if (!label) return;
    const wanted = `${label}${TITLE_SUFFIX}`;
    const me = {};
    holders.push(me);
    let routeTitle = document.title;

    const hold = () => {
      if (holders[holders.length - 1] !== me || document.title === wanted) return;
      routeTitle = document.title;
      document.title = wanted;
    };
    hold();
    const observer = new MutationObserver(hold);
    observer.observe(document.head, { subtree: true, childList: true, characterData: true });

    return () => {
      observer.disconnect();
      holders.splice(holders.indexOf(me), 1);
      if (document.title === wanted) document.title = routeTitle;
    };
  }, [label]);
}
