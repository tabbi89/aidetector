import type { RunOptions } from "@/lib/api";
import { SCAN_LEVELS } from "./scanLevels";

export type AiPassKey =
  | "plan"
  | "adjudicate"
  | "security_review"
  | "genai_payloads"
  | "adaptive"
  | "resource_refine";

export const AI_PASSES: {
  key: AiPassKey;
  title: string;
  hint: string;
  premium?: boolean;
  writes?: boolean;
}[] = [
  {
    key: "plan",
    title: "Risk plan",
    hint: "Prioritize endpoints before the scan starts.",
  },
  {
    key: "adjudicate",
    title: "Review findings",
    hint: "Assess BOLA, BFLA and SSRF evidence with a rationale.",
  },
  {
    key: "security_review",
    title: "Security design review",
    hint: "Suggest improvements from the API spec and available schema context.",
  },
  {
    key: "genai_payloads",
    title: "Generate payloads",
    hint: "Propose extra inputs for the existing injection checks.",
  },
  {
    key: "adaptive",
    title: "Adaptive validation",
    hint: "Try bounded, schema-shaped input variants.",
    premium: true,
  },
  {
    key: "resource_refine",
    title: "Refine test resources",
    hint: "Use AI to refine rejected create requests.",
    premium: true,
    writes: true,
  },
];

/** Advisory display of the maintained level table; the server still expands requests. */
export function levelPasses(options: RunOptions, entitled = true): Set<string> {
  const level = SCAN_LEVELS.find(
    (item) => item.id === (options.level ?? "quick"),
  )!;
  const passes = new Set([
    ...level.passes,
    ...(options.ai ? level.aiPasses : []),
  ]);
  if (!entitled)
    for (const pass of ["premium", "adaptive", "resource_refine"])
      passes.delete(pass);
  if (!options.mutate) passes.delete("resource_refine");
  return passes;
}

export function hasAiPasses(options: RunOptions): boolean {
  return options.ai || AI_PASSES.some(({ key }) => options[key]);
}

export function withoutAi(options: RunOptions): RunOptions {
  const next = { ...options, ai: false };
  for (const { key } of AI_PASSES) next[key] = false;
  return next;
}

/** Editing a bundle materializes only its AI passes, so unchecked means off. */
export function withAiPass(
  options: RunOptions,
  key: AiPassKey,
  enabled: boolean,
  entitled: boolean,
): RunOptions {
  const inherited = levelPasses(options, entitled);
  const next = { ...options, ai: false };
  if (options.ai)
    for (const pass of AI_PASSES)
      next[pass.key] = options[pass.key] || inherited.has(pass.key);
  next[key] = enabled;
  // Both premium loops use ctx.premium; resource refinement also requires writes.
  if (next.adaptive || next.resource_refine) next.premium = true;
  return next;
}
