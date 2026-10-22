# UX contract

## Context and sources

English product UI for API developers/security reviewers; target WCAG 2.2 AA.
Dates retain the app's browser-locale/timezone formatting. No locale provider or
Japan-market scope exists. Do not infer additional language or market policy.

| Scope | Authoritative source | UI consequence |
|---|---|---|
| Scan lifecycle and authorization | `services/api/app/api/routes/scans/runs.py`, `services/api/app/scans/run_options.py`; `CLAUDE.md` | Keep explicit consent, async job states, and per-run opt-ins |
| Scan level expansion | `services/api/app/scans/run_levels.py`; `apps/web/app/components/scanLevels.ts` | Quick/Standard/Deep never imply writes or AI; all three levels are available in web and CLI |
| Evidence and limits | `services/api/app/domain/enums.py`, `apps/web/lib/coverage.ts` | Distinguish proof, leads, planned and skipped; never invent a result |
| Permission/entitlement | `apps/web/app/components/useCapabilities.ts`, server gates | Capability UI is advisory; preserve server authorization |
| Secrets and retention | `CLAUDE.md`, `services/api/app/core/redact.py` | No credentials in query parameters, guides, feedback or logs |
| Design | `DESIGN.md`, `apps/web/app/globals.css` | Runtime CSS owns tokens; preserve light/dark language |

Pricing, retention and legal policy changes are outside this presentation slice.
Existing plan descriptions remain the source for plan presentation.

## Canonical UI Map

| Capability | Canonical owner | Source of truth | Allowed variants | Verification |
|---|---|---|---|---|
| Table Selection | Existing operation selector in scan wizard/configuration | Scan operation enabled state | explicit select all/none | `apps/web/e2e/scans.spec.ts` |
| Select/Listbox | Shared `Select` adapter over Radix Select for catalogue filters; global native fields for settings | `Select.tsx`, `globals.css` | Authored catalogue filter: portal, trigger-width menu, collision-aware placement, short labels/full descriptions. Native settings: OS popup accepted | `apps/web/e2e/coverage-selects.spec.ts`, existing native field flows |
| Date | Native date field in finding work | Existing finding-work workflow | native, OS calendar accepted | finding-work browser flow |
| Form | `ValidatedForm`, `ExpandingTextarea`, `.field`; existing workflow-owned server validation | Shared native-constraint feedback and existing credential/run panels | wizard/inline settings | `apps/web/e2e/visual-guides.spec.ts`, `credentials.spec.ts`, `scans.spec.ts` |
| Scrollbar | Global `globals.css` baseline | `DESIGN.md` | stable gutter for document | computed styles, narrow browser checks |
| Toast | Existing inline `ErrorBanner` and persistent status regions | Existing workspace feedback | inline alert/polite status; no new toast system | API-failure browser tests |
| CRUD | `api` client, existing wizard and scan-detail owners | API lifecycle | wizard continues; detail edits stay inline | `apps/web/e2e/scans.spec.ts` |
| Dialog | `ConfirmationProvider`, `useConfirmation` | `DESIGN.md` and existing API action contracts | danger/warning; typed monitor-name confirmation | `apps/web/e2e/visual-guides.spec.ts`, `scans.spec.ts` |

## Changed-surface behavior ledger

| Operation | Trigger | Pending | Success destination | Feedback / failure recovery |
|---|---|---|---|---|
| Learn evidence | Press named example button | Synchronous local state | Same guide | Pressed state + text; no network or target traffic |
| Search coverage | Type search or Enter | Local catalogue filter | Same route | Persistent result-count status; clear returns focus |
| Filter coverage | Select evidence/risk/plan | Synchronous | Same route, URL retained | Clear all recovers no-results; restore via reload/Back |
| Inspect a check | Native summary | Synchronous | Same check | Signal, caveat, source; Enter/Space toggle |
| Choose scan level | Native radio | Local options | Same RunPanel | Selected mark; all levels enabled, Deep traffic warning |
| Start scan | Existing authorization + Run scan | Busy/duplicate-submit guard | Existing scan detail | Server-confirmed job; persistent error preserves options |

## Navigation and datasets

Guides use `GuideNav` section anchors with measured header/nav offsets. The
visible section is highlighted with `aria-current="location"` on click, scroll,
deep link and history navigation. Manual scroll does not rewrite the URL. Coverage is a small bounded,
local catalogue: families start collapsed; filtering opens matching families,
and each check's mechanics remain in its disclosure. There is no API pagination to invent. Search, evidence, risk and plan
filters use `useUrlState`; queries are public catalogue terms, never credentials.
Filter changes do not move focus. No-results offers Clear filters. Existing
server pagination for scans/findings is retained. Native disclosure avoids a new
modal/focus-trap system. Document scrolling owns long guide sections.

## Workspace plan comparison

`PlanComparison` owns the public Free/Premium comparison. Feature entitlements
and detailed copy remain unchanged. Free leads to scan setup; Premium leads to
the filtered premium catalogue. Counts derive from the coverage mirror and
describe available signals, never completed checks or assurance. The full
comparison is a keyboard-accessible native disclosure. No price or checkout is
invented. Writes and token spending remain explicit choices on both plans.

## Web scan passes

Shared RunPanel supports optional premium detections and six individual AI passes.
The AI bundle follows the server level table; customizing materializes only its
current passes so an unchecked pass stays off. Turning AI off clears all AI flags.
Premium loops require entitlement and premium detections; refinement also needs
explicit write consent. Scope changes preserve these explicit switches. Writes
and AI remain off by default. Deep warns about additional traffic and time.
Source-mounted agent runs remain a local CLI feature. The server owns all gates.

## Safety and resilience

Web/server execution and automatic schedules require Premium. Free workspaces
can configure scans and review results in the web, and execute locally using
the CLI. The shared `WebRunNotice` explains this at the run/schedule entry point.
The server policy enforces the execution lane before admission/queueing; the
scheduler rechecks access on dispatch, pausing downgraded workspaces while still
allowing them to stop schedules. Source: current user product decision, enforced
by `services/api/app/scans/policy.py` and `scheduler.py`.

Scan details show workspace access from `useCapabilities`, with checking,
confirmed and unconfirmed states. Retry rechecks the same server; failure
does not imply Free or Premium. `PlanBadge` describes plan inclusion, never
runtime readiness or completed work. Schema context and the work queue carry
explicit Premium navigation badges. Ask your scan explains and disables
submission on a confirmed Free workspace before an avoidable 402; unknown
access still defers to the server. Source: scan findings/report entitlement
gates and `services/api/app/scans/run_levels.py`. Run options retain their
values after errors; busy configuration controls cannot change a queued request.

The shared RunPanel serves both wizard and detail: same labels, options, consent,
pending and error behavior. No backend state transition, retry, entitlement or
privacy policy changes belong to visual explanation work. A diagram never runs
a scan. Never hide the write-risk message when writes are enabled. No claimed
completion, cleanup guarantee, or security verdict may exceed observed evidence.

Confirmation dialogs name the object and consequence. Cancel receives initial
focus; Tab stays inside, Escape cancels while idle, and focus returns to the
trigger or main context. While the API mutation runs, actions and Escape are
blocked. API errors keep the dialog and allow retry; successful actions retain
their existing destination and feedback. Monitor deletion preserves typed-name
confirmation. Workspace `act` routes errors to the dialog for these actions;
ordinary saves continue using the page's persistent feedback.

New search is local and IME-safe; no remote race or offline mutation queue exists.
Existing session gates and API failure recovery remain. Inline alerts are
persistent; a toast must never become the only actionable error. Native inputs
retain actual labels and focus. Controls fit narrow screens and honor reduced
motion and forced colors. New UI uses no browser alert/confirm/prompt.

## Migration and verification

Finding filters retain their URL state and server paging/race protections.
More filters discloses check, endpoint, verdict, Premium, grouping and dismissed
controls; restored secondary filters open it automatically and its trigger
reports active filters even when collapsed. Search clear returns focus.
The shared ExportMenu owns report access, busy/error handling and keyboard
navigation in both the scan header and findings toolbar. The badge legend is
available under How to read findings. Request-log headers and payload structure
use native details; redacted bodies remain visible in each expanded call,
with keyboard-scrollable code areas and honest omission/error/truncation copy.
Ask your scan starts collapsed to prioritize findings; its stored disclosure
preference still wins on later visits.

This slice improves public learning/coverage, the shared run-level choice, and
shared validation/editor and confirmation foundations used by auth, monitors,
scan details and workspace settings. Result triage, long forms and detailed
monitor analysis remain candidates for further information-design work;
recording owners is not evidence that every legacy state is production-ready. Prioritized remaining work is recorded in
`docs/ui-ux-production-review-2026-10-22.md`.

Required checks: TypeScript, Next production build, ESLint via its maintained CLI
when the package's legacy Next lint command is unavailable, targeted and existing
Playwright flows, coverage mirror tests, strict premium audit. Browser evidence
must include light/dark, narrow desktop/mobile, keyboard, no results, URL restore,
IME, reduced motion, and unchanged consent/write/AI defaults. Compare the
coverage filters with existing findings filters and RunPanel in wizard/detail.
