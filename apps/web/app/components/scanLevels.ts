import type { ScanLevel } from "@/lib/api";

/** One scan level and the server passes it expands to. The web only sends `id`. */
export interface ScanLevelSpec {
  id: ScanLevel;
  title: string;
  blurb: string;
  passes: string[];
  aiPasses: string[];
  cliOnly: boolean;
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
    blurb: "Engine checks only — the fastest pass, inside the request budget.",
    passes: [],
    aiPasses: ["plan", "adjudicate", "security_review"],
    cliOnly: false,
  },
  {
    id: "standard",
    title: "Standard",
    blurb: "Adds schema fuzzing and premium detections where the plan includes them.",
    passes: ["fuzz", "premium"],
    aiPasses: ["plan", "adjudicate", "security_review"],
    cliOnly: false,
  },
  {
    id: "deep",
    title: "Deep",
    blurb: "Adds ZAP, Kali tools, lead confirmation and a deep TLS audit — slow; runs from the CLI",
    passes: ["fuzz", "premium", "zap", "kali", "confirm", "testssl"],
    aiPasses: ["plan", "adjudicate", "security_review", "genai_payloads", "adaptive", "resource_refine"],
    cliOnly: true,
  },
];
