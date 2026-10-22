# Production UX review — 22 October 2026

The product needs to teach three distinctions quickly: **who can access what**,
**evidence versus suspicion**, and **available checks versus checks that ran**.
The implementation now introduces those distinctions visually and keeps the
technical reference available on demand. It preserves the existing visual
identity and scan/API contracts.

## Implemented

| Problem | Change | User benefit |
|---|---|---|
| Home repeated browser, CLI, CI, source, evidence and coverage explanations | One setup sequence; one interactive evidence guide; compact workflow links to the maintained CLI guide | A shorter route to understanding and starting a scan |
| Coverage presented the entire technical catalogue at once | Search by term; filter by risk, evidence and plan; expandable families and signals; technical reference disclosures | Find the relevant check without reading the whole catalogue |
| Coverage tiles were passive descriptions | Each risk area opens its filtered catalogue | The diagram is also navigation |
| “Verified” and “heuristic” required specialist knowledge | Three selectable examples: wrong account, risky input, skipped check | The request, observation and next action explain the distinction |
| Run-level cards relied on prose | Visual depth marks, selected state, short descriptions, stable accessible names and all levels available in the browser | Compare Quick, Standard and Deep more easily |
| CLI precedence table clipped narrow columns | Fixed table geometry and wrapping, verified down to 320px | All winning values stay visible |
| Web could not request all supported run passes | Premium detections, Deep, individual AI passes and bounded attempt controls in shared RunPanel | Browser users can configure the same supported server work with explicit consent |
| Guide headers were text-heavy | Shared illustrated header reusing the homepage robot | Consistent visual explanation across Home, Coverage and CLI |
| Long risk-area selections clipped | Radix-backed filter menus with short labels and full descriptions | Readable selected values, themed open menus and keyboard selection |
| Homepage intro crowded the example | Shorter copy and explicit spacing; user-confirmed Cloudflare/Stripe/OpenAI stack strip | Clearer section rhythm and technology context |
| Free/Premium read like another feature section | Compact plan cards with distinct actions, additive signal counts and a single full-details disclosure | A clear plan decision with less initial text |
| Old product name and light default | Website/CLI use runpentests; dark server markup and first-paint default; saved preferences and legacy configuration stay compatible | Consistent naming and appearance without losing existing setup |
| Section navigation did not show reading position | Shared scroll-aware GuideNav, aria-current state and measured sticky offsets | The second bar highlights the section being read |
| Coverage text touched the evidence panel | EvidenceGuide owns the shared desktop/mobile intro gap | Consistent spacing on Home and Coverage |
| Readiness counts could imply execution | Counts explicitly describe eligibility by run options; actual coverage is named separately | Eligible checks are not mistaken for completed tests |
| Browser-native confirmations interrupted product flows | One shared app-owned modal for scans, credentials, monitoring, members, tokens, domains and notification endpoints | Consistent keyboard, pending, error and recovery behavior |
| Forms relied on browser validation bubbles | Shared constraint feedback, error-to-field association, first-error focus and preserved input | Failed validation gives a usable correction path |
| Text editors needed manual resizing | Shared editor expands to a bounded height and then scrolls | Longer specs/comments remain editable on narrow screens |
| Small status labels had low contrast | Stronger light-theme teal/amber/muted colors, opaque placeholders and visible global scrollbars | Better readability without changing semantic meaning |

Next.js and its matching ESLint configuration were patched from 15.5.25 to
15.5.28, and the affected source-map dependency refreshed. The production
dependency audit reports no advisories.

No backend scan behavior, permissions, plan entitlements or evidence grades were
changed. Writes and AI remain explicit opt-ins. A teaching diagram never sends
target traffic. The catalogue still uses `apps/web/lib/coverage.ts`; exact
signals, caveats and implementation references remain available.

## Information-design rules for future screens

1. **Lead with the decision.** Show what needs attention, the supporting
   observation and the next action. Put implementation details below disclosure.
2. **Use diagrams for relationships.** Identity → endpoint → observation is
   useful. A decorative lock, shield or arbitrary percentage explains little.
3. **Keep the axes separate.** Severity is impact; confidence is evidence;
   completion is work done; plan is access to features. Do not merge them into a
   single “security score”.
4. **Keep critical consequences visible.** Write effects, token spending,
   untested coverage and authorization stay beside the action. Secondary
   mechanics may be collapsed.
5. **Use the graphic as navigation.** A risk area should open its checks; a gap
   should open its prerequisite; a finding should open its recorded requests.
6. **Prefer honest absence over a success graphic.** Zero findings with missing
   coverage is not a clean bill of health.

The canonical visual and behavior owners are recorded in root `DESIGN.md` and
`UX-CONTRACT.md`. This makes future changes extensions of one system.

## Next improvements, in priority order

These are follow-up opportunities, not implemented behavior or claims of a
complete production certification.

| Priority | Surface | Improvement | Acceptance evidence |
|---|---|---|---|
| P1 | Scan setup and account readiness | Show account/tenant/privilege relationships visually, with separate readiness for cross-tenant reads and admin actions. Existing role-count shortcuts in wizard summaries deserve a dedicated pass. | Same-role/different-tenant, different-role/same-tenant, local-only and missing-account scenarios agree with engine pairing rules |
| P1 | Finding detail | A consistent “Observed → Why it matters → Fix → Retest” layout; a request/response comparison before raw JSON | Reviewers can locate proof and the affected endpoint with keyboard and on a phone; leads never look confirmed |
| P1 | Long forms | Add a coherent dirty-state navigation guard for settings and editors, with explicit exceptions for intentional wizard drafts | Browser Back, in-app links, logout and reload preserve safe drafts or explain loss; no persistent storage of secrets |
| P1 | Monitor failure states | Replace one-line loading/error fallbacks with a named, stable loading region and actionable retry/not-found states | Slow load, failed load, missing monitor and refresh failure all have a recovery path |
| P2 | Coverage detail | Link from a selected check or gap directly to the relevant prerequisite in setup | No duplicated prerequisite logic; actual skip reasons remain server-owned |
| P2 | Findings and run comparison | Add concise endpoint/severity distributions with accessible counts and links into the existing filters | Charts reflect complete server counts, preserve filters and cannot imply “fixed” for untested checks |
| P2 | Maintainability | Retire unused legacy home-diagram CSS after a reference audit; migrate `next lint` to the supported ESLint CLI when upgrading Next | No remaining consumers; visual regression and lint pass |
| P2 | Usability research | Observe first-time API developers setting up a scan and explaining a lead versus proof | Record task completion, incorrect confidence interpretations and time to the first useful finding |

## Verification and limits

Checks and final results are recorded in `docs/ui-ux-production-evidence.json`.
Browser tests use the mocked API at `api.test`; they do not scan a live target.
The full browser suite includes API-error recovery, polling, cancellation,
run-option defaults, exports, session recovery, URL filter restoration, IME,
keyboard focus, destructive-action retry, typed monitor confirmation and narrow
layouts. Guide screenshots cover light/dark at 390px and 1280px with reduced
motion. Existing scan-result browser tests provide the sibling-screen comparison.

The static premium audit and design-document lint supplement those checks; they
do not establish full WCAG conformance. Screen-reader review, Safari/Firefox,
physical mobile keyboards, and observed user comprehension remain release QA.
Screenshots show illustrative or fixture data, never a production finding.
