# Product evaluation findings — runpentests.com / aidetector

Date: 2026-10-20 (Europe/Warsaw). Evaluated as a prospective customer of
[https://runpentests.com/](https://runpentests.com/) (public site and public API),
related to this repository (`aidetector` CLI and branding). The pass was
passive reading of public pages, one access-request submission with test
credentials the evaluator chose, and one login via the documented public API.
No scans were run against third-party hosts.

This note records what a buyer sees on the hosted product. It is not a
remediation plan and it does not change scanner behaviour. Follow-ups at the
end are a priority list for later work.

## Product summary

runpentests is an automated API security scanner built around OWASP API
Security Top 10 (2023), not a human-led pentest service. Inputs are an API base
URL, an endpoint inventory (OpenAPI/Swagger, Postman, or HAR), and ideally two
test identities. Runs go through a guided browser UI or the CLI (`aidetector`).
The coverage page documents 62 checks (38 verified, 24 leads). Optional AI
steps name DeepSeek and Opus. Free versus Premium messaging exists; Premium is
operator-gated (`premium_tenants`).

## Critical and high-priority findings

### 1. Default admin credentials on the live hosted service (security)

`POST https://runpentests.com/api/auth/login` with `you@example.com` /
`password` returns HTTP 200 with `role: "admin"`, tenant `default`, and display
name `"Your Name"` — not the "Test User" name from a Request access
submission. The Request access UI claims admin approval is required before
sign-in, but this credential pair logs in immediately as admin.

Implication: a guessable default or seed admin account appears present on the
production host. For a security product this is a top-severity issue (default
credentials and a broken access-control story).

Remediation: remove seed accounts from production; force unique bootstrap
passwords; never ship `password` as a live password; audit whether Request
access creates a pending user or collides with a seed user.

### 2. Missing legal, privacy, and security pages (trust and compliance)

`/terms`, `/privacy`, `/legal`, `/security`, and `/.well-known/security.txt`
return 404. The product stores API credentials, sends active attack traffic,
and can pass redacted evidence to external AI models (DeepSeek is named).
Buyers will block a purchase without terms of service, a privacy policy, a
DPA, and a subprocessor list.

### 3. No self-serve sign-up; approval with no SLA (onboarding)

Request access requires admin review with no stated wait time. Forgot
password says "Ask your workspace admin." That blocks evaluation.

### 4. No pricing page or purchase path (pricing)

`/pricing` is 404. The site says "The whole scanner is free. Premium goes
deeper." Premium is enabled by an operator setting `premium_tenants`. There is
no checkout and no contact for sales.

### 5. No company identity or contact (trust)

No About page, team, support email, or external reviews or launch posts were
found. That blocks enterprise buyers.

### 6. No public sample report or demo scan (content)

The CTAs "Start a pen test" and "View your results" hit the sign-in wall. The
app references `/scans/example`, which is also behind auth. `/api/health`
reported `"examples": false`.

## Messaging and product clarity

### 7. Positioning overclaims "pen test"

"Run an API pen test" and "pentest-grade" report language can imply a
compliance-grade human pentest or attestation. Competitors advertise
attestation. The product should say it is an automated scanner, and state
whether the output is suitable as SOC 2 or ISO evidence.

### 8. Dual branding: runpentests versus aidetector

The site brand is runpentests. The CLI, config (`aidetector.yml`), the theme
key `aidetector-theme`, and the API docs title "aidetector API" use
aidetector. Unrelated "infrastructure monitoring" endpoints appear in the
public OpenAPI document. One customer-facing name is needed.

### 9. Operator-facing copy on customer pages

Customer-facing pages expose self-hosting language: `make admin email=…`,
`premium_tenants`, `OAST_SERVER`, `SQLMAP_BIN`, `WITH_KALI_TOOLS=1`, and paths
such as `engine/checks/authz.py` (in this repo,
`services/api/app/engine/checks/authz.py`).

### 10. Lead versus verified underplayed next to "62 checks"

Injection checks are reflection-only by default ("Reflection alone is not
evidence of SQL injection"). Lead semantics need to sit next to the check
count.

### 11. Doc contradictions

Guardrails say a tool that did not run never reads as clean. Coverage says
checks stop silently once the budget is spent. Error-message disclosure is
listed as both not covered and caught (OWASP 2025 section).

## Onboarding and CLI

### 12. CLI install is incomplete

`/cli` says to put `aidetector` on `PATH` but provides no binary, checksum, or
package-manager install. It is unclear how to obtain an API key for
`aidetector login`.

### 13. Request access UX bugs (observed live)

- Clicking "Request access" before JavaScript finishes loading does nothing
  (no feedback).
- "Back to sign in" on the "Request sent" confirmation sometimes did nothing.
- Submit stayed on "Sending request…" for several seconds with weak progress
  feedback.
- The success confirmation is not announced in the alert region (accessibility).
- There is no ETA or status check for pending approval.
- Browser loads of `/login` repeatedly returned `ERR_TIMED_OUT` while `curl`
  returned 200 (possible bot or rate limiting). That hurts legitimate browser
  use and evaluation.

### 14. Weak password policy for a security product

The minimum is 6 characters. The login and request-access flow do not mention
SSO or 2FA.

## Technical, SEO, and hardening

### 15. CSP report-only would break the site if enforced

`Content-Security-Policy-Report-Only: default-src 'self'` produces many inline
script and style violations. `/api/docs` loads Swagger from `cdn.jsdelivr.net`.
Other headers (HSTS, `X-Frame-Options: DENY`, nosniff, `Referrer-Policy`,
`Permissions-Policy`) look sound. HSTS lacks `includeSubDomains` and `preload`.

### 16. Search and social discovery are intentionally weak

Every page is `noindex`. There is no Open Graph, Twitter card, or canonical
link. `/sitemap.xml` is 404. `robots.txt` blocks many AI crawlers, which may
be intentional.

### 17. Default FastAPI Swagger branding on `/api/docs`

The title is "aidetector API" v0.1.0, with the FastAPI favicon. It looks
unfinished.

### 18. Navigation gaps

There is no Pricing, Docs, FAQ, or Contact in the nav. The footer is Coverage,
CLI guide, and Sign in. Generic page titles are reused on `/login` and
`/scans/new`.

### 19. Dense pages

The homepage is about 157 KB of HTML; coverage is about 370 KB. A FAQ or
summary layer would help. Spelling mixes "authorised" and "authorized".

## What worked well

- The coverage page is unusually honest (verified versus lead counts, and
  explicit non-coverage).
- The authorization gate is clear ("I may test this host"). The server returns
  403 without it.
- There is a dual path (UI and CLI), including a CI `--fail-on` gate and a
  local or VPN scanning story.
- Export formats (PDF, HTML, JSON, SARIF) are called out on the free tier.

## Suggested follow-ups

These are implementation items, not documentation-only. Rough priority:

1. Remove or rotate production seed admin credentials. Fix signup versus seed
   collision. Do not advertise approval-required if seed accounts bypass it.
2. Add Terms, Privacy, `security.txt`, and a contact path before marketing the
   hosted product.
3. Offer self-serve signup or a timed trial, password reset, and a stated
   approval SLA if access stays gated.
4. Publish a pricing page and a real Premium purchase or contact path.
5. Publish a sample report and a demo scan that do not require login.
6. Unify brand naming (runpentests versus aidetector) in the UI, CLI, API
   docs, and environment variables.
7. Rewrite coverage and login copy for customers, and strip operator internals.
8. Document CLI install and API-key creation end to end.
9. Fix the Request access JavaScript race: disable buttons until the page is
   hydrated, and show loading states.
10. Enforce a real content security policy with nonces or hashes, raise the
    password minimum, and add a 2FA or SSO story.
11. Resolve the coverage and guardrail contradictions, and make lead semantics
    clear in marketing.

## Method notes

- Pages were fetched with curl and headless Chrome earlier in the evaluation.
  OpenAPI was read at `/api/openapi.json`.
- One access request was submitted (name Test User, email `you@example.com`).
  The confirmation was "Request sent".
- Browser sign-in often timed out. API login succeeded for the default
  credential pair above.
- No unauthorized scanning of third-party systems was performed as part of
  this write-up.
