"use client";

import { useEffect, useRef, useState } from "react";

type Section = { id: string; label: string };

/** The current section follows document position; scrolling never rewrites history. */
export function GuideNav({
  label,
  sections,
}: {
  label: string;
  sections: Section[];
}) {
  const nav = useRef<HTMLElement>(null);
  const [active, setActive] = useState("");

  useEffect(() => {
    let frame = 0;
    const update = () => {
      frame = 0;
      const headerBottom =
        document.querySelector(".topbar")?.getBoundingClientRect().bottom ?? 0;
      const sticky =
        nav.current && getComputedStyle(nav.current).position === "sticky";
      document.documentElement.style.setProperty(
        "--guide-nav-h",
        sticky ? `${nav.current!.offsetHeight}px` : "0px",
      );
      const line =
        Math.max(
          headerBottom,
          sticky ? nav.current!.getBoundingClientRect().bottom : 0,
        ) + 36;
      let current = "";
      for (const section of sections) {
        const target = document.getElementById(section.id);
        if (target && target.getBoundingClientRect().top <= line)
          current = section.id;
      }
      // A short last section may never reach the activation line before the page ends.
      if (
        window.scrollY > 0 &&
        window.innerHeight + window.scrollY >=
          document.documentElement.scrollHeight - 2
      ) {
        current = sections[sections.length - 1]?.id ?? current;
      }
      setActive(current);
    };
    const schedule = () => {
      if (!frame) frame = requestAnimationFrame(update);
    };
    const resize = new ResizeObserver(schedule);
    resize.observe(document.body);
    if (nav.current) resize.observe(nav.current);
    window.addEventListener("scroll", schedule, { passive: true });
    window.addEventListener("resize", schedule);
    window.addEventListener("hashchange", schedule);
    schedule();
    return () => {
      cancelAnimationFrame(frame);
      resize.disconnect();
      document.documentElement.style.removeProperty("--guide-nav-h");
      window.removeEventListener("scroll", schedule);
      window.removeEventListener("resize", schedule);
      window.removeEventListener("hashchange", schedule);
    };
  }, [sections]);

  return (
    <nav ref={nav} className="guide-nav" aria-label={label}>
      <div className="wrap">
        {sections.map((section) => (
          <a
            key={section.id}
            href={`#${section.id}`}
            aria-current={active === section.id ? "location" : undefined}
          >
            {section.label}
          </a>
        ))}
      </div>
    </nav>
  );
}
