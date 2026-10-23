---
version: alpha
name: runpentests
description: An evidence-first API security workbench with a visual explanation layer.
colors:
  primary: "#1a54ff"
  background: "#ffffff"
  surface: "#f7f8fa"
  ink: "#141920"
  muted: "#596575"
  success: "#087568"
  warning: "#8c5906"
  danger: "#cf2f36"
  premium: "#6534d8"
typography:
  sans:
    fontFamily: 'ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, sans-serif'
  mono:
    fontFamily: 'ui-monospace, "SF Mono", "JetBrains Mono", Menlo, Consolas, monospace'
rounded:
  sm: "8px"
  DEFAULT: "12px"
  lg: "16px"
spacing:
  page-max: "1080px"
  page-inset: "24px"
components:
  button:
    backgroundColor: "{colors.primary}"
    textColor: "{colors.background}"
  disclosure:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.ink}"
  evidence-proof:
    textColor: "{colors.success}"
  evidence-lead:
    textColor: "{colors.warning}"
  supporting-text:
    textColor: "{colors.muted}"
  coverage-explorer:
    textColor: "{colors.premium}"
  confirmation-danger-action:
    textColor: "{colors.danger}"
---

# runpentests design system

## Product context

API developers and security reviewers need to configure an authorized scan,
understand the evidence, and decide what to fix. This is a product workbench;
the public home page introduces the same workflow. Existing English UI and
`lang="en"` establish the language. No Japan-market requirement is present.
Desktop comparison and narrow-screen review both matter. Market scope is not
otherwise established; do not infer jurisdiction or legal claims.

## Visual direction

Keep the existing white/cobalt instrument-panel identity. Its signature is a
request/response evidence diagram: identity → endpoint → observation → decision.
Use this to teach unfamiliar concepts instead of adding decorative illustrations
or more paragraphs. Quiet borders, generous section spacing, and concise labels
surround the diagram. No stock security imagery, fake scan metrics, or animated
threat theatre. An illustration always says it is an example.

## Runtime ownership and mapping

Model B: `apps/web/app/globals.css` is canonical; this document mirrors its light
theme and explains intent. Dark overrides live in the same file and components
consume semantic variables. `components/theme.ts` and `ThemeToggle.tsx` own theme
boot and persistence. Dark is the default, including server markup; saved explicit
light or dark preferences win. Storage keys remain stable across the rename. Do not introduce a second token generator or webfont fetch.

| Document role | Runtime owner | Consumers |
|---|---|---|
| primary/background/surface/ink/muted | `--accent`, `--paper`, `--surface`, `--ink`, `--muted` | actions, explanatory surfaces, body and supporting text |
| success/warning/danger/premium | `--teal`, `--amber`, `--red`, `--violet` | evidence chips and explicit status labels |
| sans/mono | `--font`, `--mono` | prose/controls and routes/request examples |
| sm/DEFAULT/lg | `--radius-sm`, `--radius`, `--radius-lg` | controls, panels, larger surfaces |
| page-max/page-inset | `.wrap` max-width and padding | route content |
| scrollbar | `--scroll-thumb`, `--scroll-track`, `--scroll-hover`, `--scroll-active` | global scroll surfaces |

Token changes must update this mirror in the same change. Verify against runtime
computed styles in both themes; no generated adapters exist. New component styles
use existing variables. Spacing and type retain the established app scale.

## Typography, layout and depth

System sans avoids late font swaps; mono identifies routes, code, and technical
data. Headlines are compact and bold; explanatory copy uses a readable measure
around 65 characters. Sentence case; use “lead” before specialist “heuristic”.
White/surface layers and borders establish hierarchy; shadows are reserved for
overlays. Radius is 8px for controls, 12px for panels, 16px for large surfaces.
Natural document scrolling remains the page owner. Comparison grids stack on
phones; controls wrap without horizontal page overflow. Never constrain a long
form to the viewport to make a sibling table fit.

## Components and states

Reuse `.btn`, `.field`, `.spinner`, `TierChip`, `ErrorBanner`, and `useUrlState`.
`ValidatedForm` owns native-constraint feedback without browser bubbles: text
errors, field associations, first-invalid focus, preserved values and IME-safe
submission. `ExpandingTextarea` grows to 520px then scrolls; manual resizing is
disabled. These adapters extend existing field markup rather than replacing its
labels, constraint metadata, or server error handling.
`ConfirmationProvider` owns destructive/costly confirmations across scan and workspace flows. The native dialog supplies background isolation;
the shared owner supplies focus trapping/restoration, initial safe-action focus,
pending/error/retry behavior and optional typed object-name confirmation.
Native details/summary own progressive disclosure. Use native radios for scan
levels and native selects where OS-owned popups are acceptable. Catalogue filters
use the shared Radix-backed `Select` with themed menus, check marks, keyboard
navigation, typeahead, trigger-width geometry and wrapped full descriptions.
`GuideHero` reuses the homepage ScannerBot for Coverage and CLI illustrations.
The homepage technology strip identifies the user-confirmed stack, with locally
stored SVG marks and no third-party image requests. All enabled
targets have hover, pointer, visible focus and pressed/selected states; disabled
targets have an explanation and cannot activate. Evidence uses icon + word +
color. The three evidence-guide choices are pressed buttons, not ARIA tabs.

The public name and CLI command are `runpentests`; new project files use
`runpentests.yml`. `GuideNav` tracks the visible section and marks its anchor
with `aria-current="location"` without changing URL history during scroll.

The homepage `PlanComparison` presents Free and Premium as compact plan cards,
with clear actions and an additive test-signal count. Premium uses the existing
violet token; native disclosure holds the full feature descriptions. Do not
invent prices, discounts, recommendations or self-service billing behavior.

Scan details use `ScanPlanSummary` to distinguish plan access from deployment
availability. `PlanBadge` reuses the violet diamond in `TierChip` for Premium;
neutral Included labels identify features on both plans. Use these in shared
run options and premium workspace navigation. Web execution and server schedules
require Premium; Free runs locally with the CLI and reviews results in the web.
All scan levels remain available to Free local runs. Unknown access stays explicitly unconfirmed, with a retry.
Paid controls retain readable explanations when disabled; never dim their
requirements into illegibility. Do not use a premium marker for ordinary AI
planning, adjudication or security design review.

Findings prioritize search, severity and evidence filters. The single Export
menu reuses the shared owner; secondary filters and the badge explanation are
progressive disclosures. Do not repeat large severity totals beside the same
severity filters. Request log detail leads with the redacted request and response
bodies; headers and retained payload structure are secondary disclosures.
Keep body panes independently sized so a long response does not stretch the
request into an empty column. Transport errors and omitted/truncated samples
must remain explicit; a successful status alone never proves exploitation.

Coverage search is local, bounded by the maintained catalogue, and needs no
network loading state. Clear is immediate and returns focus. Committed filters
are shareable URL state. Each check has a summary; signal, caveat and source are
one disclosure away. No signal or caveat is removed from the catalogue.

## Content, motion and safety

One sentence for purpose; show an example; disclose mechanics on request.
Never equate severity, evidence confidence, entitlement, and completion. Verified
means demonstrated weakness; a lead needs investigation; skipped means untested.
No 100% safety claim from a coverage count. Writes, AI cost and testing consent
stay explicit and never become implied by a diagram or scan level.

Motion communicates feedback only. Existing 150ms transitions are sufficient;
global reduced-motion rules disable them. Charts have text equivalents. Global
scrollbars stay visible, support forced colors, and require no opt-in class.

Infrastructure monitoring is retired. The application navigation contains Scans
and New scan; no telemetry-monitor screens or associated UI components remain.
