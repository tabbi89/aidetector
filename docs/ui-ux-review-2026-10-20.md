# UI/UX review — 20 October 2026

Review of the Next.js app in `apps/web` (layout, type, spacing, color, navigation, forms, empty and loading states, focus, and page titles). Suggestions stay inside the existing token system in `apps/web/app/globals.css`. Items marked **Shipped** are in the same change as this note. The rest are deliberately left as follow-ups.

API docs at `/docs` are the FastAPI service, not a page in this app. That is recorded below and was not restyled.

## What already works

- Light is the designed theme; dark is an explicit `data-theme` choice with a full token override (`globals.css`, boot script in `app/layout.tsx`). Colors are custom properties, so a new block that uses `--ink`, `--accent`, `--surface-2` follows both themes.
- A skip link, `lang="en"`, and a global `:focus-visible` ring are in place.
- Sign-in is one card with labelled fields, a live password rule, Caps Lock, and `role="alert"` on errors (`app/components/SignInPanel.tsx`).
- The scans list already has a skeleton, an error empty state with Retry, and a “No scans yet” state that says what to do next (`app/scans/page.tsx`).
- Workspace settings keep a standing `aria-live="polite"` region for success and errors (`app/workspace/page.tsx`). That is the pattern the sign-in form was missing.

## Shipped in this change

### 1. Sign-in and Request access looked tappable before JavaScript ran

**Where:** `app/components/SignInPanel.tsx`, styles in `globals.css` (`.auth-link:disabled`, `.auth-progress`).

**Why it hurts:** The panel is a client component. The server HTML includes the mode switch, Show/Hide, and submit button with working-looking styles. Until hydration, those clicks do nothing. There was no disabled state and no `<noscript>` explanation.

**Fix:** Every field and button stays `disabled` until a mount effect marks the form ready. A `<noscript>` line says JavaScript is required. Disabled auth links use the same reduced opacity as other disabled buttons.

### 2. “Sending request…” and “Request sent” were easy to miss

**Where:** `SignInPanel.tsx` (`RequestSent`, the submit button).

**Why it hurts:** Signup waits on a slow password hash. The only progress was the button label swapping to “Sending request…”. Success replaced the form with a new `role="status"` node. A live region that appears at the same moment as its text is often not announced. “Back to sign in” was a quiet button, and focus was left nowhere when the submit button unmounted, so the control was easy to skip past.

**Fix:** A polite live region is mounted with the card and then filled (progress, then “Request sent for …”). A visible line with the existing `.spinner` sits under the fields while the request is in flight. “Back to sign in” is a full-width primary button and takes focus when the confirmation appears. It stays an in-page button so the email the person typed is still there when they return.

### 3. Protected pages rendered an empty main while the session was checked

**Where:** `app/components/AuthGate.tsx`. The wait state was `<div className="wrap auth-wait" aria-busy="true" />` with only `min-height`.

**Why it hurts:** The first HTML for `/scans`, `/workspace`, and the other gated routes had a blank `<main>` until the client probe finished. `aria-busy` on an empty box does not tell anyone what is happening.

**Fix:** The wait state uses the same `.auth` / `.auth-card` shell as sign-in, with the heading “Checking your session…”, a one-line explanation, and the existing `.skel` bars.

### 4. Tab titles did not name the page

**Where:** Root template in `app/layout.tsx` (`%s · aidetector`). `app/page.tsx` set a full title string, so the template appended a second “· aidetector”. `/login`, `/scans`, `/scans/new`, `/scans/[id]`, `/monitoring`, `/monitoring/[id]`, and `/workspace` are client pages and exported no `metadata`, so they all kept the default “aidetector — active API security scanning”.

**Why it hurts:** Bookmarks, tabs, and history all read as the same product sentence.

**Fix:** Route `layout.tsx` files set short titles (Sign in, Scans, New scan, Scan, Monitoring, Monitor, Workspace). The home title is `absolute`, so it stays “aidetector — Run an API pen test. See what to fix.” `usePageTitle` fills the host on a scan, the monitor name, the workspace section, and the sign-in mode (“Request access”, “Request sent”) after the data is known.

### 5. “authorised” vs “authorized”

**Where:** Footer in `app/layout.tsx` said “authorised”. Run consent, the new-scan copy, the CLI guide, and the coverage page say “authorized”.

**Why it hurts:** The same gate is described with two spellings, one of them only in the footer.

**Fix:** The footer now says “authorized”, matching the rest of the UI.

### 6. Theme control, browser chrome, and focus rings

**Where:** `app/components/ThemeToggle.tsx`, boot script and `viewport.themeColor` in `app/layout.tsx`, focus rules in `globals.css`.

**Why it hurts:** The toggle was 32×32 next to a 36×36 account button, and its focus ring was only the global outline. `theme-color` was fixed at `#ffffff`, so a dark theme still painted the browser chrome white. A click in the first frame used the default “light” state, so a stored dark theme could ignore the first press. Field focus replaced the outline with a 3px ring at 15–18% accent (`input:focus`, `.ask-input textarea:focus`, `.target-edit input:focus`, monitoring tiles), which is faint on white. Request-log summaries set `outline: none` on `:focus-visible` and left only a background change.

**Fix:** The toggle is 36×36, disabled until it has read the stored theme, and has an explicit focus ring. Choosing a theme updates `theme-color` to the paper token (`#ffffff` / `#0e1116`); the boot script does the same before paint. Field and tile rings use 45% accent. The target-URL field and the request-log summary keep a visible focus ring.

### 7. A few app pages bypassed the type and spacing tokens

**Where:** `app/scans/page.tsx` set page padding and the action row with inline styles. `app/scans/new/page.tsx` set the title to `fontSize: 28`, under the `h1` token (`clamp(1.75rem, 4vw, 2.25rem)`). The footer links use `margin-left: auto`, which on a narrow screen left them hanging on the right of a wrapped note.

**Fix:** The scans index uses `.section` and `.actions`. The new-scan title uses the `h1` rule. Below 640px the footer links drop the auto margin and wrap across the row.

## Follow-ups (not in this change)

### P1 — Marketing and coverage are long, single-column catalogues

**Where:** `app/page.tsx` (hero, how it works, basics, results, CLI, MCP, whitebox, lanes, CI, evidence, checks, guardrails, plans, closer). `app/coverage/page.tsx` repeats a visual guide, a stats band, the OWASP matrix, a tier legend, premium, then one card per check, header tables, and limits.

**Why it hurts:** Each block is fine alone. In sequence the reader gets the same story (what a scan does, what evidence means, what premium adds) several times before an action. Section padding is already generous (`.section` is `40px 24px 80px`); the problem is length and repeated leads, not cramped type.

**Suggested fix:** Keep the hero, one “how a result is decided” section, and the closer. Move MCP, CI, whitebox, and the plan comparison behind the in-page links that already exist, or shorten those leads to one sentence plus a link to `/cli` or `/coverage`. On coverage, add a sticky contents list of the existing `h2`s (the CLI page already has this pattern in `TOC`) and leave the per-check cards as the detail.

### P1 — App footer and header are thin on purpose, and easy to under-read

**Where:** `app/components/Nav.tsx` (signed in: Scans, New scan, Monitoring). `app/components/FooterLinks.tsx` (Coverage, CLI guide, plus Scans or Sign in). Workspace and API docs live in `AccountMenu`.

**Why it hurts:** A signed-in customer looking for Coverage or the CLI has to notice the footer. The footer’s safety note and links sit in one wrapping row at 13px in `--muted` / `--ink-soft`. That split is intentional (the header comment says the guides live in the footer). Adding those links back into the header would undo it.

**Suggested fix:** Keep the header as the work links. In the footer, group “Product” (Coverage, CLI guide) and “This workspace” (Scans, New scan) as two clusters using the existing `.foot-links` type, still on one row on wide screens. Do not add a second navigation model.

### P1 — Monitor loading and empty states are one line

**Where:** `app/monitoring/[id]/page.tsx` renders `Loading…` or the error string with a back link until `monitor` is set. `app/monitoring/page.tsx` renders “No monitors yet.” above the create form. The scans list already uses `.empty` and `.skel`.

**Why it hurts:** A slow monitor page looks unfinished. “No monitors yet.” does not point at the form underneath it.

**Suggested fix:** Reuse the scan-detail skeleton (crumbs or back link, two `.skel` bars) for the monitor wait. Change the empty line to “No monitors yet. Create one below.” and leave the form where it is.

### P1 — “Monitoring v2 · WAF + ALB + OpenAPI” is implementer language

**Where:** The eyebrow on `app/monitoring/[id]/page.tsx`.

**Why it hurts:** The scans pages introduce themselves in product words (“API security scans”). This eyebrow names a version and three internal sources.

**Suggested fix:** Use the same `.eyebrow` treatment with a customer phrase already on the index (“Passive evidence”), and keep WAF / ALB / OpenAPI in the body where each source is explained.

### P2 — API docs are default Swagger UI

**Where:** Not in `apps/web`. `services/api/app/main.py` builds `FastAPI(title="aidetector API", ...)` with no `docs_url` override and no `swagger_ui_parameters`. The header and the account menu link to `${serverUrl}/docs` (`Nav.tsx`, `AccountMenu.tsx`).

**Why it hurts:** The page title in the spec is “aidetector API”, and the chrome around it is the stock Swagger header, font, and green authorize button. It does not use `--paper`, `--accent`, or the app’s top bar.

**Suggested fix:** Leave it generated. If it should feel like the product later, set FastAPI’s docs title and favicon only. Do not rebuild Swagger inside the Next app.

### P2 — Inter is named and not loaded

**Where:** `--font` in `globals.css` starts with `"Inter"`, then system fonts. No `next/font` import and no font stylesheet in `app/layout.tsx`.

**Why it hurts:** The intended face never arrives. Linux and Windows fall through to their UI font, so the “designed” type is whatever the OS provides. That is consistent on one machine and different across machines.

**Suggested fix:** Either load Inter with `next/font/google` (or a self-hosted file) on `<body>`, or delete `"Inter"` from the stack so the system font is the documented choice. Loading a webfont is the larger of the two; dropping the unused name is the smaller.

### P2 — Small text in `--muted` sits close to the contrast floor in light mode

**Where:** `--muted: #6a7585` on `--paper: #ffffff` is about 4.7:1. It is used at 12.5–13px for `.foot-note`, `.muted-sm`, hints, and placeholders. Placeholders also set `opacity: 0.75`, which pushes that gray under 4.5:1. Dark mode `--muted: #8b96a5` on `#0e1116` is about 6.2:1.

**Why it hurts:** Body text and the accent button (white on `#1a54ff`, about 5.6:1) clear AA. The smallest muted labels and placeholders are the ones that fail a strict check. Disabled `.btn` at `opacity: 0.45` is faint as well; WCAG exempts disabled controls, and the fade is the “not available” signal, so it should stay.

**Suggested fix:** Darken light-mode `--muted` slightly (a step toward `--ink-soft: #3d4653`) and drop placeholder opacity to `1`, still using `--muted`. Check the stats captions and footer note in both themes after that one token change.

### P2 — Two “screen reader only” utilities

**Where:** `.visually-hidden` (around the coverage styles) and `.sr-only` (around the CLI guide) in `globals.css` are the same clip pattern. Workspace uses `sr-only`; the auth live region uses `visually-hidden`.

**Suggested fix:** Keep one class. No visual change.

### P2 — Inline layout remains on the new-scan wizard

**Where:** `app/scans/new/page.tsx` still sets `style={{ listStyle: "none" }}` on step items. Several scan-detail skeletons use inline `maxWidth` / `marginTop` (`app/scans/[id]/page.tsx`).

**Suggested fix:** Move those into the existing `.steps` and skeleton rules the next time that wizard is touched. Not worth a separate pass.

## Out of scope

Pricing, legal pages, default credentials, and the scan engine were not reviewed and were not changed.
