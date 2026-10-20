"use client";

import { SidebarWorkspace, type WorkspaceSection } from "./SidebarWorkspace";

export function ConfigurationWorkspace({
  sections, active, onActiveChange,
}: {
  sections: WorkspaceSection[];
  /** Optional: the scan page observes which setup section is open. */
  active?: string;
  onActiveChange?: (id: string) => void;
}) {
  return (
    <SidebarWorkspace
      id="config"
      title="Scan configuration"
      eyebrow="Setup"
      description="Manage inputs, automation, and AI usage in one place."
      collapsible
      sections={sections}
      active={active}
      onActiveChange={onActiveChange}
    />
  );
}
