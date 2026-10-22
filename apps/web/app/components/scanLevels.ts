import type { ScanLevel } from "@/lib/api";

/** One scan level and the server passes it expands to. The web only sends `id`. */
export interface ScanLevelSpec {
  id: ScanLevel;
  title: string;
  blurb: string;
  passes: string[];
  aiPasses: string[];
}

/**
 * Mirrors `services/api/app/scans/run_levels.py`. Nothing here expands the
 * level into run flags — the server does that, with the tenant's entitlement
 * and deployment capabilities in view. The arrays describe the contract.
 */
export const SCAN_LEVELS: ScanLevelSpec[] = [
  {
    id: "quick",
    title: "Quick",
    blurb: "Core checks for access, risky input and security settings. The fastest pass.",
    passes: [],
    aiPasses: ["plan", "adjudicate", "security_review"],
  },
  {
    id: "standard",
    title: "Standard",
    blurb: "Quick + tests of schema rules. Adds deeper detections when your plan includes them.",
    passes: ["fuzz", "premium"],
    aiPasses: ["plan", "adjudicate", "security_review"],
  },
  {
    id: "deep",
    title: "Deep",
    blurb: "Standard + external scanners and lead confirmation. More traffic and time; needs configured tools.",
    passes: ["fuzz", "premium", "zap", "kali", "confirm", "testssl"],
    aiPasses: ["plan", "adjudicate", "security_review", "genai_payloads", "adaptive", "resource_refine"],
  },
];
