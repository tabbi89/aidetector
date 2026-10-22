"use client";

import { type ReactNode, useEffect, useState } from "react";
import { PlanBadge } from "./PlanBadge";

export interface WorkspaceSection {
  id: string;
  label: string;
  meta: string;
  content: ReactNode;
  premium?: boolean;
}

export function SidebarWorkspace({
  id, title, eyebrow, description, sections, collapsible = false, defaultSection,
  active: controlledActive, onActiveChange,
}: {
  id: string;
  title: string;
  eyebrow: string;
  description: string;
  sections: WorkspaceSection[];
  collapsible?: boolean;
  /**
   * Section to open first. Defaults to the first one; pass this when the leading
   * section is a caveat rather than the answer the user came for.
   */
  defaultSection?: string;
  /**
   * Controlled section. Omit it and the workspace owns the choice; provide it
   * and the caller does (a URL, usually). `onActiveChange` reports the new id
   * either way, so a caller can observe a still-uncontrolled workspace.
   */
  active?: string;
  onActiveChange?: (id: string) => void;
}) {
  const [uncontrolledActive, setUncontrolledActive] = useState(() => {
    const preferred = sections.find((section) => section.id === defaultSection);
    return preferred?.id ?? sections[0]?.id;
  });
  const active = controlledActive ?? uncontrolledActive;

  function selectSection(next: string) {
    if (controlledActive === undefined) setUncontrolledActive(next);
    onActiveChange?.(next);
  }
  const [horizontal, setHorizontal] = useState(false);
  const [expanded, setExpanded] = useState(true);
  const [expandedLoaded, setExpandedLoaded] = useState(!collapsible);

  useEffect(() => {
    if (!collapsible) return;

    const storageKey = "aidetector-workspace-" + id + "-expanded";
    try {
      const saved = window.localStorage.getItem(storageKey);
      if (saved === "true" || saved === "false") {
        setExpanded(saved === "true");
      }
    } catch {
      // Storage can be unavailable in privacy-restricted browser contexts.
    } finally {
      setExpandedLoaded(true);
    }
  }, [collapsible, id]);

  useEffect(() => {
    if (!collapsible || !expandedLoaded) return;

    try {
      window.localStorage.setItem(
        "aidetector-workspace-" + id + "-expanded",
        String(expanded),
      );
    } catch {
      // Storage can be unavailable in privacy-restricted browser contexts.
    }
  }, [collapsible, expanded, expandedLoaded, id]);

  useEffect(() => {
    const media = window.matchMedia("(max-width: 760px)");
    const update = () => setHorizontal(media.matches);
    update();
    media.addEventListener("change", update);
    return () => media.removeEventListener("change", update);
  }, []);

  function moveTab(from: number, direction: number) {
    const next = (from + direction + sections.length) % sections.length;
    const nextSection = sections[next];
    if (!nextSection) return;
    selectSection(nextSection.id);
    requestAnimationFrame(() => document.getElementById(`${id}-tab-${nextSection.id}`)?.focus());
  }

  return (
    <section className="config-workspace" aria-labelledby={`${id}-title`}>
      <div className="config-heading">
        <div>
          <span className="config-eyebrow">{eyebrow}</span>
          <h2 id={`${id}-title`}>{title}</h2>
        </div>
        <div className="config-heading-actions">
          <p>{description}</p>
          {collapsible && (
            <button
              type="button"
              className="workspace-toggle"
              aria-expanded={expanded}
              aria-controls={`${id}-content`}
              onClick={() => setExpanded((value) => !value)}
            >
              {expanded ? "Hide" : "Show"}
              <span
                className={`workspace-chevron ${expanded ? "up" : "down"}`}
                aria-hidden="true"
              />
            </button>
          )}
        </div>
      </div>

      <div id={`${id}-content`} className="config-layout" hidden={collapsible && !expanded}>
        <nav className="config-nav" aria-label={`${title} sections`} role="tablist" aria-orientation={horizontal ? "horizontal" : "vertical"}>
          {sections.map((section, index) => (
            <button
              type="button"
              key={section.id}
              id={`${id}-tab-${section.id}`}
              role="tab"
              className={active === section.id ? "active" : ""}
              aria-controls={`${id}-panel-${section.id}`}
              aria-selected={active === section.id}
              tabIndex={active === section.id ? 0 : -1}
              onClick={() => selectSection(section.id)}
              onKeyDown={(event) => {
                if (event.key === "ArrowRight" || event.key === "ArrowDown") {
                  event.preventDefault();
                  moveTab(index, 1);
                } else if (event.key === "ArrowLeft" || event.key === "ArrowUp") {
                  event.preventDefault();
                  moveTab(index, -1);
                } else if (event.key === "Home" || event.key === "End") {
                  event.preventDefault();
                  moveTab(0, event.key === "Home" ? 0 : sections.length - 1);
                }
              }}
            >
              <span className="config-index" aria-hidden="true">
                {String(index + 1).padStart(2, "0")}
              </span>
              <span className="config-nav-copy">
                <strong>{section.label}</strong>
                {section.premium && <PlanBadge premium />}
                <small>{section.meta}</small>
              </span>
            </button>
          ))}
        </nav>

        <div className="config-content">
          {sections.map((section) => (
            <div
              key={section.id}
              id={`${id}-panel-${section.id}`}
              role="tabpanel"
              tabIndex={0}
              aria-labelledby={`${id}-tab-${section.id}`}
              hidden={active !== section.id}
            >
              {section.content}
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}
