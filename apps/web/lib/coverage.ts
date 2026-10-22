/**
 * What the scanner actually tests.
 *
 * Every entry below is derived from `services/api/app/engine/` — the check
 * registry in `checks/__init__.py` and the payload families in `payloads.py`.
 * `signal` describes the evidence the check actually uses to decide, which is
 * deliberately more conservative than the vulnerability class it is named for.
 *
 * Keep this in sync when engine checks change.
 */

export type Confidence =
  /** The signal evidences the class directly. */
  | "verified"
  /** Reflection/heuristic only — a lead that needs manual confirmation. */
  | "heuristic"
  /** Not implemented. */
  | "planned";

export interface Check {
  name: string;
  /**
   * Engine check key (`Check.key` in `engine/checks/`), when this entry
   * describes an engine-tier check. It is the machine-readable join between
   * this file and the registry: `tests/test_coverage_mirror.py` fails if a
   * registered check has no entry carrying its key. Adjunct and payload-family
   * entries have no single key and omit it.
   */
  key?: string;
  owasp?: string;
  confidence: Confidence;
  /** Premium tier: planned for the paid tier, absent from the free engine. */
  premium?: boolean;
  /** How the check decides — the literal detection signal. */
  signal: string;
  /** Known false-positive or coverage caveat. */
  caveat?: string;
  source: string;
}

export interface CheckGroup {
  title: string;
  blurb: string;
  checks: Check[];
}

export const CONFIDENCE_LABEL: Record<Confidence, string> = {
  verified: "Verified",
  heuristic: "Heuristic",
  planned: "Planned",
};

export const CONFIDENCE_HELP: Record<Confidence, string> = {
  verified:
    "The evidence the check collects demonstrates the weakness directly.",
  heuristic:
    "The check proves input reaches the response, not that it executes. Treat as a lead and confirm by hand.",
  planned: "Not implemented — listed so coverage gaps are explicit.",
};

/** The premium flag: a check reserved for the paid tier — implemented, but
 *  gated behind the run's `premium: true` opt-in (off by default). */
export const PREMIUM_LABEL = "Premium";

export const PREMIUM_HELP =
  "Reserved for the paid tier — implemented, but off unless the run opts in (premium: true), and the API refuses a non-premium tenant (402). These are deeper detections that need infrastructure the free tier deliberately avoids (JWKS/OAST egress, raw sockets, new protocol surfaces).";

export const GROUPS: CheckGroup[] = [
  {
    title: "Local project language versions",
    blurb:
      "CLI directory scans inspect PHP, Python, Kotlin, Java, Node.js and Go version declarations without executing project code. Dependency packages are not scanned.",
    checks: [
      {
        name: "Declared language/runtime CVEs",
        confidence: "heuristic",
        signal:
          "Exact versions from supported version files, Dockerfiles, Kotlin build declarations and Go toolchain pins are matched against live NVD CVEs. Findings include the declaring file, advisory link and upgrade guidance.",
        caveat:
          "A declaration does not prove the deployed runtime or exploitability. Java uses upstream OpenJDK matching; vendor backports and Kotlin component applicability require confirmation. Version ranges, unavailable lookups and limits are recorded as gaps. Requires a directory and internet access from the local runner.",
        source: "runner/source_audit.py",
      },
    ],
  },
  {
    title: "Premium adaptive validation",
    blurb:
      "A bounded, schema-shaped loop that selects a critical parameter, sends a valid control, and inspects only response structure. GET query/path inputs are read-only; JSON body fields on POST/PUT/PATCH are available only with writes on.",
    checks: [
      {
        name: "Adaptive payload validation",
        owasp: "API8:2023",
        confidence: "heuristic",
        premium: true,
        signal:
          "Flags a validation-gap lead when an out-of-range, enum, type, required, or max-length variant is accepted after a valid baseline. It covers GET query/path inputs by default and JSON body fields on POST/PUT/PATCH only with writes on; every attempt is bounded, and the finding it records carries no request values or body samples.",
        caveat:
          "Body probes can create or update target state, so they require the explicit mutation gate and are not cleaned up by this pass. The check still does not prove persistence or execution; optional database context is the newest structure-only snapshot a `runpentests` CLI run read from the tables its runpentests.yml lists — the server never connects to the database.",
        source: "engine/adaptive/runner.py · engine/adaptive/policy.py · specs/parser.py · db_schema/snapshots.py",
      },
    ],
  },
  {
    title: "Authorization & authentication",
    blurb:
      "The highest-value API checks, and the reason a scan takes two credential roles.",
    checks: [
      {
        name: "Broken Object Level Authorization (BOLA)",
        key: "bola",
        owasp: "API1:2023",
        confidence: "verified",
        signal:
          "Baseline-gated: only considers object GETs (snake_case or camelCase id params) where an anonymous request is rejected (auth is actually enforced). Object ids are harvested from the spec's collection/parent reads when possible so the oracle probes real objects. Then flags when two identities get an identical, object-specific body — a static-content guard (a different object id must return a different body) filters public/echo pages.",
        caveat:
          "Needs two credentials for the verified cross-identity oracle. With a single credential it degrades to sibling probing (read a reachable object, then a neighbouring id with the same token) and reports a LOW lead, because cross-tenant access cannot be proven without a second identity. Still infers ownership from a shared response rather than seeding a foreign object.",
        source: "engine/checks/authz.py",
      },
      {
        name: "Broken Function Level Authorization (BFLA)",
        key: "bfla",
        owasp: "API5:2023",
        confidence: "verified",
        signal:
          "Requires two distinct identities whose roles establish a low-to-high privilege boundary. It derives “privileged” from exact path segments or retained security scheme/OAuth scopes, harvests real object ids from related collection reads, proves anonymous access is rejected, then flags only when both the low-privilege and privileged identities reach the same function. Privilege is each identity's explicit rank, or inferred from its role name. With more than two tiers it tries each lower tier in turn when the one below was refused; a hit by the lowest tier is verified, a middle-tier hit is a lead.",
        source: "engine/checks/authz.py",
      },
      {
        name: "Broken authentication",
        key: "broken_auth",
        owasp: "API2:2023",
        confidence: "verified",
        signal:
          "Baseline-gated: first confirms an anonymous request is rejected (401/403), then tries forged credentials — a random token plus JWT alg=none/case, stripped/tampered signatures, elevated claims, and the existing kid empty-key traversal. For HS256/384/512 tokens it also tries at most 64 weak defaults for 50 ms offline. A recovered key is never retained: it is used only to sign a privilege probe and valid-signature expired/future-nbf probes. Time-claim findings additionally require the original token to succeed and an unchanged-claims bad-signature control to be rejected.",
        caveat:
          "Genuinely public endpoints are skipped. The weak-key list is intentionally tiny and is not password cracking; strong or asymmetric keys are not searched. Supplied JWTs are deduplicated, recovered keys never enter evidence/logs, and every confirmation request consumes the normal 750-request budget. POST/PUT/PATCH/DELETE and other state-changing methods are probed only with writes on.",
        source: "engine/checks/auth.py · engine/jwt_forge.py · engine/jwt_hmac.py",
      },
    ],
  },
  {
    title: "Authorization on writes (opt-in — mutates the target)",
    blurb:
      "Off by default: only runs with writes on, because it WRITES to the target. It pairs a write with a GET that reads the same resource back, sends the write as the low-privilege identity with a unique canary, then reads back as the high-privilege owner. A persisted canary proves a lower-privilege identity's write took effect — a verified authorization-on-write flaw, not a reflection lead. Updates are restored; created objects are deleted where the spec has a DELETE.",
    checks: [
      {
        name: "BOLA on write",
        key: "write_authz",
        owasp: "API1:2023",
        confidence: "verified",
        signal:
          "Low-privilege identity PUT/PATCHes (or POST-creates) an object; the high-privilege identity reads the canary back. Object-level write authorization is not enforced. With identities' tenant set, the writer is the other tenant's identity.",
        caveat:
          "Needs the spec to pair a mutating verb with a GET of the same resource, two distinct identities, and a writable string body field. Nested/typed bodies beyond flat string fields are not built. The CREATE path reaches nested resources (POST /projects/{id}/items) by seeding the parent chain first and tearing it down after; updates stay single-hop. DELETE is never used as an attack verb.",
        source: "engine/checks/write_oracle.py · engine/sequence.py · engine/resource_map.py",
      },
      {
        name: "BFLA on write",
        owasp: "API5:2023",
        confidence: "verified",
        signal:
          "Same read-back oracle on a privileged (admin) write path — a low-privilege write that persists is a function-level authorization failure (reported CRITICAL). With identities' tenant set, it also runs inside one tenant: a viewer whose write to its own workspace's object persists is BFLA on write, whatever the path is called (reported HIGH).",
        caveat:
          "Same pairing/identity prerequisites as BOLA-on-write; only string body fields are mutated.",
        source: "engine/checks/write_oracle.py",
      },
      {
        name: "Seeded cross-tenant BOLA (read)",
        key: "seeded_bola",
        owasp: "API1:2023",
        confidence: "verified",
        signal:
          "A real create-as-A → read-as-B sequence, so cross-tenant access is proven rather than inferred from identical bodies. It creates an object as one identity, tagging a string body field with a unique canary, then reads that exact object back as a DIFFERENT identity. The canary coming back means the second identity read an object it does not own — a confirmed cross-tenant read. An anonymous read is checked first as the baseline: an item read that does not enforce auth is simply public, so it is not flagged.",
        caveat:
          "Off by default: only runs with writes on, because it WRITES (creates) to the target. Needs the spec to pair a POST collection with a GET of the created item, two distinct identities, and a writable string body field. Only create pairs are used — a create is what guarantees the first identity owns the object read back. Reaches NESTED resources too (POST /projects/{id}/items): it first seeds the parent (create-parent → create-child → read) so a nested create hits a real object instead of a 404, and a parent with no create endpoint is skipped rather than probed. Everything it creates — child then parent — is deleted where the spec exposes a DELETE; DELETE is never used as an attack verb.",
        source: "engine/checks/seeded_bola.py · engine/sequence.py · engine/resource_map.py",
      },
      {
        name: "Mass assignment (client-writable server-owned field)",
        key: "mass_assignment",
        owasp: "API6:2023",
        confidence: "verified",
        signal:
          "The same read-back oracle asking a different question: not \"did the wrong identity's write persist\" but \"did the wrong field's\". Reads the object, picks a field already on it whose name means server-owned state — privilege (role, is_admin, permissions, scopes \u2192 CRITICAL), ownership (owner, owner_id, tenant_id, created_by) or state (balance, credits, verified, approved) \u2014 that the write operation's request schema does NOT declare, writes a canary into it, and confirms the read-back equals the canary. Verified: the value the client sent is the value the server stored. The original is restored afterwards.",
        caveat:
          "A canary is written, never a real privileged value \u2014 proving the field is client-writable is the finding, and sending role=admin would escalate privileges on a live system. That is also why only string-valued fields are probed: there is no non-escalating value for a boolean is_admin, so boolean flags are not tested. On an update pair (PUT/PATCH with a GET of the same path) only fields already present on the object are candidates, so the original value is known and restorable; a field the response schema declares but the object omits is skipped. On a create pair (POST collection with a GET of the created item) there is no object to read first, so it injects an undeclared server-owned name from a curated shortlist (role, group, owner, owner_id, tenant_id, created_by) at creation and confirms by reading the created object back \u2014 still verified, and the object it creates is deleted afterwards where the spec exposes a DELETE. The create path reaches nested resources (POST /projects/{id}/items) by seeding the parent chain once per pair and tearing it down after every field is probed. Two fields per resource pair.",
        source: "engine/checks/mass_assignment.py · engine/sequence.py · engine/resource_map.py",
      },
      {
        name: "Race condition / limit overrun",
        key: "race_condition",
        owasp: "API6:2023",
        confidence: "verified",
        signal:
          "The one check that fires a concurrent burst bypassing the per-host rate limiter \u2014 a serialized burst could never catch a race. On a create endpoint with a uniqueness-looking field, it first proves the constraint holds sequentially (a duplicate is rejected), then fires race_burst (default 6) identical creates at once. More than one succeeding means the check-then-act is not atomic (TOCTOU) \u2014 the shape behind double-spends, coupon reuse and duplicate accounts. Verified: the overrun is observed, not inferred.",
        caveat:
          "Needs the async transport (it no-ops on the sync in-process client, which cannot burst) and writes on. Only fires where a sequential duplicate is refused first, so an endpoint with no uniqueness constraint is never flagged. Objects created by the probe are deleted where the spec exposes a DELETE on the item path.",
        source: "engine/checks/race_condition.py · engine/transport.py",
      },
    ],
  },
  {
    title: "Injection — reflection probes",
    blurb:
      "One rotating payload per family per scan, seeded so repeated scans exercise different variants. The rotation pool is the curated in-code library plus a vendored offline corpus (PayloadsAllTheThings / FuzzDB style), and an opt-in AI pass can add re-validated variants on top — but the draw stays one payload per family per scan, so per-scan request volume is unchanged. Each payload carries a unique marker; a finding means the marker came back verbatim in the response body. Injection is spec-shaped: payloads go into GET query + path params (always) and POST/PUT/PATCH JSON body fields (only with writes on, since sending a body changes target state), values keep a valid prefix for typed/enum/formatted params, and the operation's other required params are filled with spec-valid baselines so the payload reaches the sink. Reflections seen ONLY in a >=400 error response are downgraded to informational (frameworks commonly echo the request path/params in 404 envelopes — that is the error handler, not the sink).",
    checks: [
      {
        name: "Cross-Site Scripting (XSS)",
        key: "reflected_injection",
        owasp: "CWE-74",
        confidence: "heuristic",
        signal:
          "Reflects <aidxMARKER>, svg/onload, img/onerror and javascript: payloads into query, path and JSON body parameters and looks for the marker in the body.",
        caveat:
          "The marker is alphanumeric, so correctly HTML-escaped output still matches. No output-context or encoding analysis.",
        source: "engine/payloads.py · engine/payload_corpus.py · checks/injection.py",
      },
      {
        name: "SQL injection (SQLi)",
        owasp: "CWE-74",
        confidence: "heuristic",
        signal:
          "Echo probes only — OR / UNION / stacked-statement payloads, flagged when the marker is reflected.",
        caveat:
          "No error-based, boolean-based, time-based or UNION verification. Reflection alone is not evidence of SQL injection.",
        source: "engine/payloads.py",
      },
      {
        name: "Server-Side Template Injection (SSTI)",
        owasp: "CWE-74",
        confidence: "heuristic",
        signal: "Sends {{marker}} and ${{marker}} and looks for the marker back.",
        caveat:
          "Detects reflection, not template evaluation. A real SSTI signal is arithmetic being evaluated (7*7 → 49); that is not tested.",
        source: "engine/payloads.py",
      },
      {
        name: "Command injection",
        owasp: "CWE-74",
        confidence: "heuristic",
        signal: "Sends ;echo marker and |echo marker, flagged on reflection.",
        caveat:
          "Any endpoint that echoes its input matches. No out-of-band or timing confirmation.",
        source: "engine/payloads.py",
      },
      {
        name: "Path traversal",
        owasp: "CWE-74",
        confidence: "heuristic",
        signal:
          "Sends ../../marker and its URL-encoded form, flagged on reflection.",
        caveat: "Reflection is not evidence that a file was read.",
        source: "engine/payloads.py",
      },
      {
        name: "CRLF injection",
        owasp: "CWE-74",
        confidence: "heuristic",
        signal: "Sends an encoded CRLF header payload, flagged on body reflection.",
        caveat:
          "Checks the body, not whether the response headers actually split — the signal a real CRLF test needs.",
        source: "engine/payloads.py",
      },
    ],
  },
  {
    title: "Injection — signature & error leads",
    blurb:
      "A second reflection tier for query-language classes, drawing benign marker-carrying payloads from PayloadsAllTheThings and backend error regexes from FuzzDB. One payload per class per scan, seeded so repeated scans rotate. Sinks match the reflection probes above (GET query + path params always; POST/PUT/PATCH JSON body fields only with writes on), with the same spec-shaped values. A backend error signature is medium (the payload reached the interpreter); bare marker reflection is low.",
    checks: [
      {
        name: "XPath injection",
        key: "signature_injection",
        owasp: "CWE-74",
        confidence: "heuristic",
        signal:
          "Sends malformed, marker-carrying XPath into query, path and JSON body parameters and looks for a known XPath error string. Medium on a signature (XPathException, xmlXPathEval, node-set errors); low on marker reflection.",
        caveat:
          "Reflection is not evaluation, and an error signature proves the parser was reached, not that the expression is injectable.",
        source: "engine/signatures.py · checks/signature_injection.py",
      },
      {
        name: "LDAP injection",
        owasp: "CWE-74",
        confidence: "heuristic",
        signal:
          "Sends unbalanced LDAP filter payloads into query, path and JSON body parameters. Medium on a JNDI/LDAP error (javax.naming, LDAPException, Bad search filter); low on reflection.",
        caveat:
          "Many backends swallow filter errors, so absence of a signature is not absence of the flaw.",
        source: "engine/signatures.py · checks/signature_injection.py",
      },
      {
        name: "NoSQL injection (NoSQLi)",
        owasp: "CWE-74",
        confidence: "heuristic",
        signal:
          "Sends operator- and JS-break payloads into query, path and JSON body parameters. Medium on a driver error (MongoError, BSON, CastError); low on reflection.",
        caveat:
          "Only echoed errors are caught — no operator-based auth-bypass is attempted.",
        source: "engine/signatures.py · checks/signature_injection.py",
      },
      {
        name: "Server-Side Includes (SSI)",
        owasp: "CWE-74",
        confidence: "heuristic",
        signal:
          "Sends an SSI directive carrying the marker and flags when the raw directive is reflected back.",
        caveat:
          "Reflection only — no benign evaluation signal, so a stripped-but-executed directive is invisible.",
        source: "engine/signatures.py · checks/signature_injection.py",
      },
      {
        name: "JSON injection",
        owasp: "CWE-74",
        confidence: "heuristic",
        signal:
          "Sends JSON-context-break payloads (marker plus quote/brace escapes, and a __proto__ probe) into query, path and JSON body fields; medium on a JSON parser error (Unexpected token, JSONDecodeError, Expecting value), low on marker reflection.",
        caveat:
          "Structural only — operator-style JSON is covered by NoSQLi, and server-side prototype pollution needs a behavioural follow-up this does not perform.",
        source: "engine/signatures.py · checks/signature_injection.py",
      },
    ],
  },
  {
    title: "Server-Side Request Forgery",
    blurb: "Parameter-name heuristics plus a link-local metadata probe.",
    checks: [
      {
        name: "SSRF candidate",
        key: "ssrf",
        owasp: "API7:2023",
        confidence: "heuristic",
        signal:
          "For query parameters named url, uri, webhook, redirect, callback, src, next and similar, injects a 169.254.169.254 metadata URL — always on reads, and also into JSON body fields on POST/PUT/PATCH with writes on (many real sinks are body fields: webhook URLs, return_url). Medium when the marker is reflected; low when the URL is accepted silently, and only when an OAST collector is configured.",
        caveat:
          "A matching parameter name is not a finding by itself — a target that refuses the internal URL (>=400 with no reflection) is validating its input and is left alone. The silent-accept lead is reported only when the opt-in out-of-band (OAST) check below can confirm it: without a collector, a URL-storing endpoint is indistinguishable from a blind SSRF.",
        source: "engine/checks/ssrf.py",
      },
    ],
  },
  {
    title: "Out-of-band confirmation (OAST)",
    blurb:
      "Opt-in and off by default — requires a self-hosted interactsh server (OAST_SERVER) and the interactsh-client binary in the worker image. Injects a unique callback token per injection point into GET query params (always) and JSON request-body fields (only with writes on, since a body write changes state), then polls for interactions. A callback is definitive: the target actually reached a server we control, so these are confirmations, not reflection leads.",
    checks: [
      {
        name: "Blind SSRF",
        key: "oob_injection",
        owasp: "API7:2023",
        confidence: "verified",
        signal:
          "Puts an OAST callback URL into url/webhook/redirect-style query params and JSON body fields; a callback confirms the server fetched an attacker-controlled host. High severity.",
        caveat:
          "Only fires when an OAST server is configured; otherwise this check is a no-op.",
        source: "engine/checks/oob_injection.py · engine/oob.py",
      },
      {
        name: "Remote File Inclusion (RFI)",
        owasp: "CWE-74",
        confidence: "verified",
        signal:
          "Puts an OAST URL into file/include/path/template-style params and body fields; a callback confirms remote inclusion. High severity.",
        caveat: "Opt-in (OAST server required).",
        source: "engine/checks/oob_injection.py",
      },
      {
        name: "Remote code execution (RCE)",
        owasp: "CWE-74",
        confidence: "verified",
        signal:
          "Injects a shell command that curls an OAST URL; a callback confirms command execution. Critical severity.",
        caveat:
          "Opt-in (OAST server required). Reaches GET query sinks always and JSON body sinks only with writes on — not headers, cookies or path params.",
        source: "engine/checks/oob_injection.py",
      },
      {
        name: "Edge-Side Includes (ESI)",
        owasp: "CWE-74",
        confidence: "verified",
        signal:
          "Injects an <esi:include src> pointing at an OAST URL; a callback confirms ESI processing. High severity.",
        caveat: "Opt-in (OAST server required).",
        source: "engine/checks/oob_injection.py",
      },
      {
        name: "XML External Entities (XXE) — partial",
        owasp: "CWE-74",
        confidence: "verified",
        signal:
          "Injects an external-entity DTD referencing an OAST URL into JSON body values; a callback confirms external-entity resolution. High severity.",
        caveat:
          "Partial: the probe sends JSON bodies, not XML-content-type bodies, so XXE only fires where a JSON value is concatenated into an XML parser downstream. True XML endpoints are not yet fuzzed.",
        source: "engine/checks/oob_injection.py",
      },
    ],
  },
  {
    title: "OWASP ZAP (opt-in parallel scanner)",
    blurb:
      "Opt-in per run (zap: true) and off by default — requires a running ZAP daemon (ZAP_BASE_URL). ZAP spiders and active-scans the target over its REST API and its alerts are mapped into findings. The spider is seeded with the base URL AND the scan's rendered operation URLs, so the active scan reaches the API paths the spec documents instead of only the root. It runs OUTSIDE the engine's 750-request budget and cooperative cancellation, on ZAP's own schedule, bounded only by a wall-clock timeout.",
    checks: [
      {
        name: "ZAP active-scan alerts",
        confidence: "verified",
        signal:
          "Maps ZAP alerts (risk High/Medium/Low/Info → severity) with CWE id, param, attack and evidence. Covers ZAP's own rule set (SQLi, XSS, path traversal, header issues, and more).",
        caveat:
          "Separate engine: does not honour the request budget or cancel-between-checks model, so it is gated behind an explicit opt-in. Overlaps the engine's own reflection checks.",
        source: "engine/zap.py",
      },
    ],
  },
  {
    title: "Kali tool adjuncts — lead confirmation (opt-in)",
    blurb:
      "Reflection tells you input reaches the response; these tools re-test only the parameters the engine already flagged and promote a lead to a verified finding when the tool reproduces the bug. They run in the worker when the matching *_BIN is set (env-gated, like OAST), outside the engine's 750-request budget, capped by target count and a wall-clock timeout, and skip cleanly when unavailable.",
    checks: [
      {
        name: "SQLi confirmation (sqlmap)",
        owasp: "CWE-74",
        confidence: "verified",
        signal:
          "Re-tests only parameters the engine already flagged as SQLi leads, using sqlmap's boolean/error/UNION/stacked/time techniques (--batch, level/risk 1, capped target count, wall-clock timeout). A sqlmap-reproduced injection upgrades the heuristic lead to a confirmed CWE-89 finding.",
        caveat:
          "Off unless SQLMAP_BIN is set and sqlmap is baked into the worker image (WITH_KALI_TOOLS=1). Makes its own requests outside the engine budget.",
        source: "engine/sqlmap_confirm.py",
      },
      {
        name: "XSS confirmation (dalfox)",
        owasp: "CWE-74",
        confidence: "verified",
        signal:
          "Re-tests parameters flagged as reflected-XSS leads with dalfox. A dalfox “verified” PoC fires the payload in a headless browser, so a hit upgrades the reflection lead to a confirmed CWE-79 finding — not just a reflected marker.",
        caveat:
          "Off unless DALFOX_BIN is set (dalfox is installed via WITH_KALI_TOOLS=1). Bare reflected/grep PoCs are ignored — the engine already reports those.",
        source: "engine/dalfox_confirm.py",
      },
      {
        name: "Command-injection confirmation (commix)",
        owasp: "CWE-74",
        confidence: "verified",
        signal:
          "Re-tests parameters flagged as command-injection leads with commix's results-/blind-/time-based techniques (--batch). A reproduced injection upgrades the lead to a confirmed CWE-78 finding at CRITICAL.",
        caveat:
          "Off unless COMMIX_BIN is set (installed via WITH_KALI_TOOLS=1). Runs outside the engine budget.",
        source: "engine/commix_confirm.py",
      },
      {
        name: "SSTI confirmation (tplmap)",
        owasp: "CWE-74",
        confidence: "verified",
        signal:
          "Re-tests parameters flagged as SSTI leads with tplmap, which detects template evaluation (and names the engine, e.g. Jinja2). A hit upgrades the reflection lead to a confirmed CWE-1336 finding.",
        caveat:
          "Off unless TPLMAP_BIN is set. tplmap is a deprecated Python-2 tool not packaged in Debian — provision it yourself and point TPLMAP_BIN at the launcher.",
        source: "engine/tplmap_confirm.py",
      },
      {
        name: "Deep TLS audit (testssl.sh)",
        owasp: "API8:2023",
        confidence: "verified",
        signal:
          "Full testssl.sh sweep of an HTTPS target — certificate chain, cipher suites, protocol support, known TLS CVEs — mapped from testssl's JSON into HIGH/MEDIUM findings. Complements the built-in single-handshake TLS check.",
        caveat:
          "Off by default: runs only when the run asks for it (the Deep level from the CLI, or an explicit testssl pass) and TESTSSL_BIN is set with testssl.sh baked into the worker image. HTTPS targets only; plaintext targets are flagged by the built-in TLS check instead.",
        source: "engine/testssl_scan.py",
      },
    ],
  },
  {
    title: "Kali tool adjuncts — discovery & breadth (opt-in)",
    blurb:
      "A separate Kali service built FROM the official kalilinux/kali-rolling image runs these over a small job API, gated per run via kali: true. The scanner passes (nuclei, nikto, whatweb, katana) receive the scan's rendered operation URLs as extra targets (capped) so they cover the documented API paths, not only the base URL; the fuzzing passes (ffuf discovery, Arjun params) stay on the base target to keep their workload bounded. All operate OUTSIDE the engine's 750-request budget, are rate- and wall-clock bounded, and each pass skips cleanly (the service 503s for a missing tool) without dropping the others.",
    checks: [
      {
        name: "nuclei template scan",
        confidence: "verified",
        signal:
          "Runs the nuclei community template library (CVEs, exposed panels, default credentials, known misconfigurations) against the target through the Kali service and maps each match with its template id, severity, matched location and any CVE ids the template declares.",
        caveat:
          "Confidence is only as good as the template — exploit-verifying templates are strong evidence, so info-level (fingerprint/tech-detect) matches are graded heuristic rather than verified. The template's own remediation, CVE/CWE ids and references are carried onto the finding when it defines them. Runs outside the engine budget, rate-limited by the service.",
        source: "engine/kali.py · services/kali",
      },
      {
        name: "Endpoint discovery (ffuf)",
        confidence: "verified",
        signal:
          "ffuf probes the target with a bounded API-oriented wordlist (~340 paths, or the larger SecLists API list on a deep run) and reports responding paths (anything but 404) that the uploaded spec never mentions — shadow/undocumented endpoint candidates.",
        caveat:
          "Verified as existence: a responding path is a fact. Under kali:true the engine then runs a second, separately-budgeted pass of its core checks (header sweep, authz, and \u2014 on arjun\u2019s params \u2014 reflection/SSRF) against these discovered paths. Does not mutate the spec's stored operation set.",
        source: "engine/kali.py · services/kali",
      },
      {
        name: "JS-aware crawl (katana)",
        confidence: "verified",
        signal:
          "katana crawls the target (including endpoints referenced from JavaScript) and reports discovered paths absent from the spec — shadow endpoints a static wordlist would miss.",
        caveat:
          "Existence only, like ffuf discovery. The engine re-tests undocumented crawled paths on its separate discovery budget; paths already represented by the spec are excluded. Bounded crawl depth and host-scoped.",
        source: "engine/kali.py · services/kali",
      },
      {
        name: "Hidden-parameter discovery (Arjun)",
        confidence: "verified",
        signal:
          "Arjun probes for query parameters the endpoint accepts but the spec never documents. Undocumented parameters are a common home for injection and authorization bugs.",
        caveat:
          "Reports the parameter names as a lead, then feeds only genuinely new parameters into the separate discovery pass. A documented route is not re-probed unless Arjun found a parameter absent from its spec operation.",
        source: "engine/kali.py · services/kali",
      },
      {
        name: "Web-server scan (nikto)",
        owasp: "API8:2023",
        confidence: "heuristic",
        signal:
          "nikto checks for server misconfigurations, outdated software banners and known/interesting files, reported as low-severity leads to triage.",
        caveat:
          "nikto's basic JSON carries no severity and many items are existence facts, so hits are graded low — verify by hand.",
        source: "engine/kali.py · services/kali",
      },
      {
        name: "Technology fingerprint (whatweb)",
        confidence: "verified",
        signal:
          "whatweb identifies the target's technology stack (server, framework, libraries), summarized into a single informational finding to focus which CVEs and misconfigurations to check.",
        caveat:
          "Informational context, not a vulnerability. Broader CORS misconfiguration beyond the engine's own header sweep is covered by nuclei templates rather than a dedicated tool.",
        source: "engine/kali.py · services/kali",
      },
    ],
  },
  {
    title: "Transport security (TLS)",
    blurb:
      "The one check that inspects the transport, not a response body. It opens a TLS handshake to the target host (a direct socket, outside the request budget) and analyses the presented certificate and negotiated parameters. Findings are verified — real certificate facts, not reflection leads. Built on the standard-library ssl module and cryptography (already a dependency).",
    checks: [
      {
        name: "Certificate & TLS configuration",
        key: "tls_config",
        owasp: "API8:2023",
        confidence: "verified",
        signal:
          "Flags an expired / not-yet-valid or self-signed certificate, a hostname/SAN mismatch, a wildcard certificate (low — hygiene), a weak signature hash (SHA-1/MD5), an RSA/DSA key under 2048 bits, a weak negotiated cipher (< 128-bit or RC4/3DES/DES/NULL/EXPORT), and deprecated protocol support (TLS 1.1 or older). A plaintext http:// target is flagged directly; an https:// target on port 443 also gets one credential-free GET to its http:// twin, flagged (medium) when it serves a 2xx, redirects without leaving cleartext, or answers with the HTTPS endpoint's own status. A closed port, 426, or a redirect to https:// is the right answer.",
        caveat:
          "Analyses the leaf certificate and one negotiated connection, not the full chain, OCSP/CRL revocation, or an exhaustive cipher-suite enumeration. The cleartext probe only tries port 80, so an https:// target on a non-standard port is not checked for a cleartext twin.",
        source: "engine/checks/tls.py",
      },
    ],
  },
  {
    title: "Excessive data exposure (what responses give away)",
    blurb:
      "These checks read what the target hands back when it behaves normally. They reuse the same per-endpoint sweep the header checks fire, so response analysis costs no extra requests; the uploaded specification is also scanned offline. Response values and potential credential candidates are never retained — findings contain only field names or a detector name with a sanitized structural location.",
    checks: [
      {
        name: "Sensitive fields in a response body",
        key: "data_exposure",
        owasp: "API3:2023",
        confidence: "verified",
        signal:
          "Field names in JSON responses, matched against five families: credential material (password/hash/salt/secret/api key), session and bearer tokens, payment data (card number, CVV, IBAN, routing/account number), government identifiers (SSN, passport, tax id, TIN/EIN), and internal state (internal_*, _*, debug, stack traces, hostnames). Naming style is normalised, so password_hash and passwordHash are one rule. Reads two corpora at no extra request: the header sweep\u2019s 2xx GET bodies, and the run\u2019s request trace \u2014 every call any check made, so a create that echoes a token back, a 5xx carrying internal state, the second identity\u2019s view and endpoints past the sweep\u2019s cap are all covered. Verified, not a lead: the field is present in the response \u2014 no exploitation step is missing. Credential, token, payment and identifier families are high; internal state is medium.",
        caveat:
          "Names only — a field called `notes` holding a customer's medical history is invisible to this, and a benign field with an alarming name is allow-listed (has_password, card_last4, token_type) rather than reported. Sweep-sourced findings walk nested objects to depth 5, the first 3 elements of an array, and 400 fields; a response larger than the 40 KB sample is skipped rather than guessed at. Trace-sourced findings carry field names only, so they raise the sensitive-name half but never spec drift, which needs the full field list.",
        source: "domain/sensitive.py · engine/exposure_policy.py · engine/checks/data_exposure.py",
      },
      {
        name: "Undeclared response fields (spec drift)",
        owasp: "API3:2023",
        confidence: "heuristic",
        signal:
          "Fields in the response that the operation's declared 2xx JSON schema does not mention — top-level fields, plus nested fields under a parent the schema actually describes (resolved through $ref, allOf/oneOf/anyOf, and unwrapped for array responses). Either the endpoint returns more than anyone reviewed, or the spec is stale and every client generator, reviewer and scanner is working from it.",
        caveat:
          "A lead, deliberately: from outside, a stale spec looks exactly like an over-exposing endpoint. Operations that declare no response schema are not compared at all — absence of a contract is not evidence of drift. An object declared with no properties leaves its children alone (its contents were never specified), but a described parent makes any undocumented child drift.",
        source: "engine/exposure_policy.py · specs/parser.py",
      },
      {
        name: "Potential credentials in responses and uploaded specifications",
        key: "potential_secrets",
        owasp: "API3:2023",
        confidence: "heuristic",
        signal:
          "Runs bounded detect-secrets rules offline over the existing GET/HEAD response samples and, separately, the stored uploaded OpenAPI text. Reports only the detector name, source and sanitized structural location; the candidate value, surrounding text, hashes and raw detector objects are discarded before a finding is created. Detection runs in a short-lived subprocess with credential verification disabled and network calls blocked.",
        caveat:
          "A regex or entropy match is a lead, not proof that a credential is live or exposed to the wrong caller. Placeholder values, UUIDs, explicit examples and responses from token/login/session routes are suppressed. Input bytes, traversal depth, matches and processing time are capped; truncated samples and false negatives remain possible. HAR/Postman conversion already discards captured values, so the stored synthesized spec cannot recover them.",
        source: "engine/secret_scan.py · engine/checks/potential_secrets.py",
      },
    ],
  },
  {
    title: "Misconfiguration & information disclosure",
    blurb:
      "A per-endpoint response-header sweep. Every safe endpoint in the spec (GET/HEAD, capped at 40, spread across path families) is probed once — one GET carrying a throwaway Origin, so the same request also exposes CORS behaviour — and its headers are scored for presence and for value quality. Endpoints that share an issue profile are reported as one finding, so a uniformly unhardened API stays one line while an endpoint that diverges from its neighbours gets a finding of its own. Both checks below read that single sweep.",
    checks: [
      {
        name: "Security header hardening (per endpoint)",
        key: "security_headers",
        owasp: "API8:2023",
        confidence: "verified",
        signal:
          "17 headers scored per endpoint, by presence and — for 14 of them — by value, since a header set to a value that permits everything buys nothing. The core set (CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, plus HSTS on HTTPS targets) is medium; the browser-hardening set is low. Header-by-header rules are tabulated below.",
        caveat:
          "The sweep uses GET/HEAD only, so an endpoint reachable solely by POST/PUT/PATCH is not sampled directly; an all-mutating spec falls back to the root path.",
        source: "engine/header_policy.py · engine/checks/misconfig.py",
      },
      {
        name: "Permissive CORS & cookie flags",
        owasp: "API8:2023",
        confidence: "verified",
        signal:
          "The sweep sends an Origin no target can legitimately allow-list. An Access-Control-Allow-Origin that echoes it back is reflecting any origin — high with Access-Control-Allow-Credentials: true, medium without; a wildcard origin with credentials is high, a bare wildcard low, and the 'null' origin medium. Set-Cookie is checked for HttpOnly, SameSite and (over HTTPS) Secure — medium. Only the cookie name and the missing attributes are ever surfaced, never the cookie value.",
        caveat:
          "Simple-request behaviour only; no preflight (OPTIONS) probing, and no check of Access-Control-Allow-Methods/Headers breadth.",
        source: "engine/header_policy.py",
      },
      {
        name: "Debug/trace, version-banner & internal-redirect disclosure",
        key: "info_disclosure",
        owasp: "API8:2023",
        confidence: "verified",
        signal:
          "Per endpoint; flags response headers that leak internal debug/trace correlation state (x-debug-id, x-trace-id, x-span-id, tracestate, …) and stack version banners (X-Powered-By, X-AspNet-Version, X-Generator, and Server when it carries a version), plus Location / Content-Location redirect targets naming a private or loopback address, an internal-only hostname, or the scanned host on a port the client never used. One extra request toggles the first route's trailing slash, since the framework's slash redirect is where upstream hosts and ports usually leak. Low severity — they help an attacker trace requests through backend services, map the network behind the edge, and narrow a CVE search.",
        caveat:
          "Header-based only; debug ids inside error bodies are not matched, and a bare Server: nginx with no version is deliberately not flagged. A redirect to another public host is a destination, not a leak, and a sibling internal host is not reported when the scanned target is itself internal.",
        source: "engine/checks/misconfig.py",
      },
      {
        name: "Schema fuzzing and response-contract validation",
        key: "schema_fuzz",
        owasp: "API8:2023",
        confidence: "heuristic",
        signal:
          "Opt-in (fuzz:true). Schemathesis explicitly generates positive and negative inputs, fairly sharing the configured per-scan case allowance across eligible operations. Each case runs once through the budget-bounded engine probe; that same response is checked for documented status, Content-Type, required/typed headers, and body-schema conformance. A 5xx is verified unhandled input (CWE-20); contract mismatches are low-severity heuristic drift because the implementation or uploaded spec may be stale. GET by default; POST/PUT/PATCH bodies only with writes on. Response bodies, header values, and generated request values are never retained.",
        source: "engine/checks/schema_fuzz.py",
      },
    ],
  },
  {
    title: "Business logic — enumeration, rate & resource limits",
    blurb:
      "Small, bounded probes for the account-enumeration, throttling and resource-consumption gaps a pure injection scanner misses. No second identity needed.",
    checks: [
      {
        name: "Missing rate limiting",
        key: "enumeration",
        owasp: "API4:2023",
        confidence: "heuristic",
        signal:
          "Sends a burst of 6 identical requests at up to two authentication-shaped endpoints (login/token/password/reset paths). If the burst mostly succeeds and nothing throttles (429), reports low: no rate limiting observable from the outside.",
        caveat:
          "Absence of a 429 in six requests is a weak oracle — a WAF or upstream throttle may simply not have engaged. Automatic 429 retries retain the original throttle signal, so a later 2xx cannot hide it. Safe methods run by default; POST/PUT/PATCH auth endpoints require writes.",
        source: "engine/checks/enumeration.py",
      },
      {
        name: "Unbounded page size (client-controlled response volume)",
        key: "resource_consumption",
        owasp: "API4:2023",
        confidence: "heuristic",
        signal:
          "The response-volume half of API4, orthogonal to rate limiting: a single request that forces an unbounded response. Spec-driven — only a collection GET that DECLARES a page-size query parameter (limit/per_page/page_size/count/size/top/max/…) is probed. Sends the endpoint two above-normal sizes (1000, then 5000); if the returned record count TRACKS the requested size (grows across the two) and is large in absolute terms, there is no effective server cap, so one caller can extract the whole collection. A server capped at, say, 100 returns 100 for both sizes — no growth, no finding — which is what separates an unbounded list from a correctly capped one.",
        caveat:
          "Read-only (GET), so no writes gate; up to three endpoints, two requests each, inside the 750 budget. Heuristic: response volume infers cost rather than measuring the server's real work, and only list-shaped JSON responses are counted (a large single object is a different weakness). Endpoints with no declared size parameter are not probed — the check skips and says so rather than guessing.",
        source: "engine/checks/resource_consumption.py",
      },
      {
        name: "Sensitive business flow without anti-automation",
        key: "business_flow",
        owasp: "API6:2023",
        confidence: "heuristic",
        signal:
          "API6 is about a FLOW the business assumes a human drives — checkout, redemption, signup, invite — exposed to a script at machine speed. With writes on, drives a bounded identical-body burst (5) at business-flow-shaped endpoints (checkout/purchase/redeem/coupon/invite/subscribe/booking/…) and flags one where every replay MINTS A DISTINCT new object with no throttle (429), no idempotency and no anti-automation control (CAPTCHA/challenge). The distinct-object oracle is what separates it from enumeration's rate probe and from a correctly idempotent flow: a flow returning the SAME id on a replay, demanding an idempotency key, or showing a challenge is treated as protected and not flagged.",
        caveat:
          "Off by default: writes only, because it drives a real write flow and (like the duplicate-create oracle) does not clean up the objects it creates — point it at a disposable/staging target. Authentication endpoints (login/token/reset) are excluded — enumeration owns those. Heuristic: the absence of a control across a short burst is a lead, and a response whose created-object id cannot be read is skipped rather than guessed. Up to two flows per scan.",
        source: "engine/checks/business_flow.py",
      },
      {
        name: "Duplicate-create enumeration oracle",
        owasp: "API2:2023",
        confidence: "verified",
        signal:
          "With writes on, creates the same object twice with a unique email/username/imei-ish value. A conflict-style rejection of the identical second attempt (409 or a duplicate/existing message) reveals whether the identifier already exists — an account/record enumeration oracle.",
        caveat:
          "Creates one real object per candidate endpoint (writes opt-in). Only flat top-level body fields are used; up to two create endpoints per scan.",
        source: "engine/checks/enumeration.py",
      },
    ],
  },
  {
    title: "Premium — advanced detection",
    blurb:
      "Detections reserved for the premium tier (premium:true, off unless the run opts in). All are implemented — host-header probing, spec design review, sustained rate-limiting, the out-of-band confirmation tier, JWT key confusion, request smuggling, bounded GraphQL introspection/suggestion/authorization behavior, and gRPC reflection. The free engine's bounded JWT forgery and weak-HMAC suite remains in broken_auth above.",
    checks: [
      {
        name: "JWT key confusion & header injection (RS256→HS256, jku)",
        key: "jwt_confusion",
        owasp: "API2:2023",
        confidence: "verified",
        premium: true,
        signal:
          "Confirmation-tier JWT attacks the blind forgery suite cannot reach: RS256→HS256 key confusion (fetch the server's public key from its JWKS, re-sign as HS256 with it, and prove acceptance) and jku header injection (point the token at an attacker-controlled key set and confirm the target fetches it via an OAST callback).",
        caveat:
          "Needs a JWT-bearing credential; the JWKS fetch is a same-origin egress, and jku confirmation needs a live OAST server. Premium-gated (premium:true).",
        source: "engine/checks/jwt_confusion.py · engine/jwt_forge.py",
      },
      {
        name: "GraphQL — introspection exposure",
        key: "graphql_introspection",
        owasp: "API8:2023",
        confidence: "verified",
        premium: true,
        signal:
          "Sends a standard GraphQL introspection query anonymously to a GraphQL-shaped endpoint and flags when the response returns a schema — an unauthenticated caller can enumerate the API surface.",
        caveat:
          "Introspection exposure is schema discovery, not an authorization bypass. The separate bounded behavior check below handles suggestions and differential alias/batch authorization. Premium-gated (premium:true).",
        source: "engine/checks/graphql_introspection.py",
      },
      {
        name: "GraphQL — anonymous field suggestions",
        key: "graphql_behavior",
        owasp: "API8:2023",
        confidence: "heuristic",
        premium: true,
        signal:
          "Sends at most three one-field invalid queries and reports only sanitized identifier suggestions returned to an anonymous caller. Query size is capped at 512 bytes, depth at four, targets at two, and each endpoint stops after 1.5 seconds or a server error.",
        caveat:
          "Suggestions demonstrate limited schema information exposure, not exploitation. They are low-severity heuristic leads; generic GraphQL errors are ignored.",
        source: "engine/checks/graphql_behavior.py",
      },
      {
        name: "GraphQL — alias/batch authorization differential",
        owasp: "API2:2023",
        confidence: "verified",
        premium: true,
        signal:
          "Uses one bounded, read-only query example from the uploaded OpenAPI contract. A finding requires the owner to receive data, both anonymous and low-privilege normal queries to be denied, and the same low-privilege identity to receive equivalent data only through one alias or a batch of two. Alias or batch support by itself is never reported.",
        caveat:
          "Skips when two identities or a safe known query are unavailable. Variables, fragments, queries deeper than four and documents over 512 bytes are skipped. Mutation and subscription examples are never replayed—even with writes on—because safe GraphQL cleanup cannot be inferred. Deep/overload probes remain deliberately unimplemented.",
        source: "engine/checks/graphql_behavior.py",
      },
      {
        name: "gRPC — reflection exposure",
        key: "grpc_reflection",
        owasp: "API9:2023",
        confidence: "verified",
        premium: true,
        signal:
          "Sends a gRPC server-reflection list-services request over gRPC-Web and flags when the response enumerates services — any caller can enumerate the entire gRPC surface.",
        caveat:
          "This is the reflection slice of gRPC scanning; exercising the resolved protobuf RPCs with schema-valid payloads (HTTP/2 + protobuf) is not yet built. Premium-gated (premium:true).",
        source: "engine/checks/grpc_reflection.py",
      },
      {
        name: "Insecure deserialization (gadget chains)",
        key: "deserialization",
        owasp: "API10:2023",
        confidence: "verified",
        premium: true,
        signal:
          "Injects gadget payloads (Python pickle, PHP unserialize, plus Java/.NET markers) into body fields and confirms execution via an OAST callback — the target reaching back proves the chain fired, not merely that the payload reflected.",
        caveat:
          "Dangerous, so confirmation-tier and off by default (premium:true + writes + OAST). The corpus is a starter set; Java/.NET entries are markers to be replaced with a curated ysoserial/.NET corpus.",
        source: "engine/checks/deserialization.py",
      },
      {
        name: "Unsafe consumption of an upstream API",
        key: "unsafe_consumption",
        owasp: "API10:2023",
        confidence: "verified",
        premium: true,
        signal:
          "The mirror of SSRF: not \"can the server be made to reach a host\" (API7) but \"does the server trust and relay what an upstream returns\". Injects an OAST callback URL into a URL/upstream-shaped parameter (url/endpoint/source/upstream/api/… — GET query always, JSON body with writes on) and fires only on the CONJUNCTION of two proofs: an out-of-band callback (the fetch left the server) AND the upstream-correlated token coming back in the target's own response (it relayed downstream content). A callback alone is blind SSRF (oob_injection); reflection alone is reflected_injection; only the pair is unsafe consumption, so the three never overlap.",
        caveat:
          "Confirmation-tier and off by default (premium:true + a live OAST collector; body sinks also need writes). Verified only on the callback-plus-reflection conjunction; a callback with no reflected marker is left to oob_injection. Redirect-following and TLS-downgrade variants of API10 are not yet built.",
        source: "engine/checks/unsafe_consumption.py",
      },
      {
        name: "XXE confirmation (out-of-band)",
        key: "xxe_confirmation",
        owasp: "CWE-74",
        confidence: "verified",
        premium: true,
        signal:
          "Injects three out-of-band XXE variants — external entity, parameter entity (external DTD), and an external DTD with a file declaration — into XML-facing body fields and confirms them when the target resolves the entity and calls back to our OAST server. The callback proves entity resolution, not local-file reading or exfiltration.",
        caveat:
          "Needs a live OAST server, plus writes (an XML body is a write). Premium-gated (premium:true). SSRF filter-bypass and cloud-metadata exfil variants are not yet included.",
        source: "engine/checks/xxe_confirmation.py",
      },
      {
        name: "HTTP request smuggling / desync",
        key: "request_smuggling",
        owasp: "API8:2023",
        confidence: "verified",
        premium: true,
        signal:
          "Sends CL.TE and TE.CL ambiguity probes over a raw socket and flags when one connection yields two responses — the front-end and back-end disagree on framing.",
        caveat:
          "Raw-socket work outside the httpx probe; it opens one short-lived connection per probe and never bursts, so it cannot become a load test. Premium-gated (premium:true).",
        source: "engine/checks/request_smuggling.py",
      },
      {
        name: "Host header / vhost injection",
        key: "host_header",
        owasp: "API8:2023",
        confidence: "heuristic",
        premium: true,
        signal:
          "Sends a spoofed-host canary in the forwarded-host headers (X-Forwarded-Host, X-Forwarded-Server, X-Host) and flags when it comes back in the response body or Location — the target built a link or redirect from the Host header, the prerequisite for password-reset poisoning and web-cache poisoning.",
        caveat:
          "Reflection proves the header is used, not that it is exploitable. Premium-gated (premium:true) and off unless the run opts in.",
        source: "engine/checks/host_header.py",
      },
      {
        name: "Spec design review (A06 Insecure Design)",
        key: "design_review",
        owasp: "API2:2023",
        confidence: "heuristic",
        premium: true,
        signal:
          "Reads the safely parsed full spec (no target traffic, secrets or AI) and flags design-level risks a behavioral scan cannot see: a sensitive operation with no effective auth, credential material in a URL parameter, a server-owned request field, no error response contract, no documented 429/rate-limit headers, and a collection response schema without maxItems. Local response/schema refs and inherited or explicitly anonymous security requirements are resolved.",
        caveat:
          "Static design review, not runtime proof: the spec may be stale, gateway controls may be documented elsewhere, and a maxItems contract does not itself enforce resource limits. Each signal is a low/medium heuristic review lead. Premium-gated (premium:true) and off unless the run opts in.",
        source: "engine/checks/design_review.py",
      },
      {
        name: "Advanced rate-limit (sustained load)",
        key: "advanced_rate_limit",
        owasp: "API4:2023",
        confidence: "heuristic",
        premium: true,
        signal:
          "Sends a sustained sequence (24 requests) to authentication-shaped endpoints and flags when all of it is served without a throttle (429) — catching limits that only engage past the free check's 6-request burst (per-minute caps, larger token buckets).",
        caveat:
          "A stronger 'no rate limiting' claim than the free enumeration check, at a higher request cost; the 24-request sequence is exempt from per-operation fairness but still bounded by the global 750-request ceiling. Automatic retries retain any observed 429. Safe methods run by default; state-changing auth endpoints also require writes. Premium-gated (premium:true).",
        source: "engine/checks/advanced_rate_limit.py",
      },
    ],
  },
];

export type HeaderSeverity = "high" | "medium" | "low";

export interface HeaderRule {
  header: string;
  severity: HeaderSeverity;
  /** What the header buys you. */
  purpose: string;
  /** The value the sweep treats as correct. */
  good: string;
  /** What the sweep rejects. `null` when the check is presence-only. */
  bad: string | null;
}

/**
 * The per-endpoint header sweep, header by header — every header the engine
 * scores, whether it scores the value as well as the presence, and what it
 * considers a good value.
 *
 * Hand-maintained mirror of `services/api/app/engine/header_policy.py`
 * (`_CORE`, `_HYGIENE`, `_HYGIENE_EXPECTED`, `_cors_issues`, `_cookie_issues`).
 * Keep the two in sync.
 */
export const HEADER_POLICY: HeaderRule[] = [
  {
    header: "Content-Security-Policy",
    severity: "medium",
    purpose: "Restricts which sources may load and execute script.",
    good: "default-src 'self'",
    bad: "Absent; no default-src or script-src directive; or script sources allowing *, http:, https:, 'unsafe-inline' or 'unsafe-eval'.",
  },
  {
    header: "Strict-Transport-Security",
    severity: "medium",
    purpose:
      "Forces HTTPS and blocks downgrade attacks. Scored on HTTPS targets only — over plaintext the header is ignored by browsers.",
    good: "max-age=31536000; includeSubDomains",
    bad: "Absent; max-age under a year (31536000); or no includeSubDomains.",
  },
  {
    header: "X-Frame-Options",
    severity: "medium",
    purpose: "Stops the response being framed for clickjacking.",
    good: "DENY (or SAMEORIGIN)",
    bad: "Absent, or any other value — ALLOWALL, ALLOW-FROM …",
  },
  {
    header: "X-Content-Type-Options",
    severity: "medium",
    purpose: "Stops browsers MIME-sniffing the response body.",
    good: "nosniff",
    bad: "Absent, or any value other than nosniff.",
  },
  {
    header: "Referrer-Policy",
    severity: "medium",
    purpose: "Limits how much of the URL leaks to third parties.",
    good: "strict-origin-when-cross-origin",
    bad: "Absent, unsafe-url, or no-referrer-when-downgrade.",
  },
  {
    header: "Access-Control-Allow-Origin",
    severity: "high",
    purpose:
      "Names which origins may read the response cross-site. The sweep sends an Origin no target can legitimately allow-list, so a target that echoes it back is reflecting any origin.",
    good: "A fixed, allow-listed origin",
    bad: "Echoes back the probe Origin, or *: high with Access-Control-Allow-Credentials: true, medium (reflection) or low (bare wildcard) without. The null origin is medium.",
  },
  {
    header: "Set-Cookie",
    severity: "medium",
    purpose:
      "Cookie hardening. Only the cookie name and its missing attributes are ever reported — never the cookie value.",
    good: "HttpOnly; Secure; SameSite=Strict",
    bad: "Missing HttpOnly, missing SameSite, or (over HTTPS) missing Secure.",
  },
  {
    header: "Permissions-Policy",
    severity: "low",
    purpose: "Restricts powerful browser features (camera, mic, geolocation).",
    good: "geolocation=(), camera=(), microphone=()",
    bad: null,
  },
  {
    header: "Cross-Origin-Opener-Policy",
    severity: "low",
    purpose: "Isolates the browsing context from cross-origin popups.",
    good: "same-origin",
    bad: "Absent, or anything but same-origin / same-origin-allow-popups.",
  },
  {
    header: "Cross-Origin-Embedder-Policy",
    severity: "low",
    purpose: "Blocks loading cross-origin resources that have not opted in.",
    good: "require-corp",
    bad: "Absent, or anything but require-corp / credentialless.",
  },
  {
    header: "Cross-Origin-Resource-Policy",
    severity: "low",
    purpose: "Restricts which origins may embed this response.",
    good: "same-origin",
    bad: "Absent, or cross-origin.",
  },
  {
    header: "X-Permitted-Cross-Domain-Policies",
    severity: "low",
    purpose: "Denies legacy Flash/PDF cross-domain policy files.",
    good: "none",
    bad: "Absent, or a value that still permits policy files — all, master-only, by-content-type.",
  },
  {
    header: "Origin-Agent-Cluster",
    severity: "low",
    purpose: "Requests an origin-keyed agent cluster, isolating the origin.",
    good: "?1",
    bad: "Absent, or ?0.",
  },
  {
    header: "X-DNS-Prefetch-Control",
    severity: "low",
    purpose: "Stops the browser pre-resolving linked hostnames.",
    good: "off",
    bad: "Absent, or on.",
  },
  {
    header: "X-Download-Options",
    severity: "low",
    purpose:
      "Stops legacy IE opening a download in the site's own context. Retained for completeness; the browser it protects is end-of-life.",
    good: "noopen",
    bad: "Absent, or any other value.",
  },
  {
    header: "Document-Policy",
    severity: "low",
    purpose:
      "Configures per-document behaviour such as disabling document.write. Chromium only.",
    good: "document-write=?0",
    bad: null,
  },
  {
    header: "Integrity-Policy",
    severity: "low",
    purpose:
      "Requires Subresource Integrity, so a script with no valid hash is blocked.",
    good: "blocked-destinations=(script)",
    bad: null,
  },
];

/** Headers the sweep deliberately does not score, and why. */
export const HEADERS_NOT_SWEPT: { header: string; why: string }[] = [
  {
    header: "Clear-Site-Data",
    why: "A logout/revocation instruction rather than a hardening header — correct on a sign-out response and wrong everywhere else. A per-endpoint sweep cannot call it missing without firing on every endpoint that should not send it.",
  },
  {
    header: "Upgrade-Insecure-Requests",
    why: "A request header (and a CSP directive); as a response header it carries no standard meaning. The server-side control that does the same job is HSTS, already in the core set.",
  },
];

/** Headers flagged for being present at all — the disclosure side of the sweep. */
export const DISCLOSURE_HEADERS: string[] = [
  "Server (only when it carries a version, e.g. nginx/1.18.0)",
  "X-Powered-By",
  "X-AspNet-Version, X-AspNetMvc-Version",
  "X-Generator",
  "Any header naming debug/trace/span correlation state (x-debug-id, x-trace-id, tracestate, …). x-request-id is deliberately not matched.",
];

/** Classes people expect from an API scanner that this engine does not test. */
export const NOT_COVERED: string[] = [
  "Prompt injection",
  "Memory disclosure / leaks",
  "Detailed error-message disclosure",
  "Sensitive data under an innocuous field name (the exposure check reads names, never values)",
  "Compute/memory amplification beyond response volume (unbounded page size is now probed by resource_consumption, and request-rate limits by enumeration/advanced_rate_limit; expensive-operation abuse — heavy queries, zip bombs, regex/JSON blowups — is not)",
];

/** Structural limits of the current engine, from base.py and the checks. */
export const LIMITS: string[] = [
  "Authorization depth depends on the credentials you upload: verified cross-identity BOLA needs two distinct identities, while BFLA additionally needs their roles to establish a low-to-high privilege boundary. With a single credential, BOLA degrades to a low-severity sibling-id probe (a lead, not proof) and the BFLA/write oracles stay inert.",
  "The reflection checks reach GET query + path parameters always, and POST/PUT/PATCH JSON request-body fields only with writes on (a body write changes target state), shaped to each parameter's declared type/enum/format. The out-of-band checks reach GET query params (and JSON body fields with writes on), never path. Headers, cookies, query/path on mutating verbs, and non-JSON (XML/form) bodies are still never fuzzed.",
  "Every scan is capped at 750 HTTP requests; checks stop silently once the budget is spent.",
  "Writes let state-changing probes run: the write oracle (BOLA/BFLA-on-write, which restores its own updates and deletes what it creates), body-sink injection, and authentication/authorization/rate probes against unsafe HTTP methods. Injection and rate payloads written to bodies are NOT generally cleaned up, so writes should target a disposable/staging environment only.",
  "Out-of-band (OAST) confirmation exists but is opt-in and off by default: it needs a self-hosted interactsh server plus the interactsh-client binary in the worker. Without it, blind classes are not tested.",
  "The core engine has no timing/execution analysis, so it reports injection as reflection leads only. The opt-in confirmation adjuncts (confirm:true) promote those leads to verified findings — sqlmap (SQLi: boolean/error/UNION/stacked/time), dalfox (XSS: headless execution), commix (command injection) and tplmap (SSTI: template evaluation) — but only for parameters the engine already flagged, only when the tool is installed, and off by default because they are slow.",
  "All external adjuncts (ZAP, the confirm tools, testssl, Kali) share one wall-clock budget (default 600s) and a cancellation check between passes: once spent, the remaining passes are skipped rather than letting a scan hang for tens of minutes in a slow tool.",
  "On GET operations, path parameters are fuzzed like query params; elsewhere (and for the parameters a check is not targeting) they are rendered as a spec-valid baseline derived from their type/enum/format, defaulting to 1.",
  "The core engine is hand-written httpx probes. Optional adjuncts can be layered on — OWASP ZAP per run, plus the Kali tools (sqlmap, dalfox, commix, tplmap, testssl.sh, nuclei, ffuf, nikto, whatweb, katana, arjun) — but they run outside the engine\u2019s request budget and cancellation model, each behind its own opt-in.",
  "Endpoint and parameter discovery (ffuf, katana, arjun) report undocumented paths and params; under kali:true the engine runs a second pass of its core checks only against undocumented paths or newly discovered parameters, on a small separate budget (discovery_probe_budget, default 150) independent of the main 750. It deduplicates findings already produced by the main pass. The discovery pass never mutates \u2014 a shadow path has no spec pairing to restore \u2014 and checks needing a declared schema (write oracle, mass assignment, schema fuzz) are excluded.",
];

/**
 * Honest mapping to the OWASP Top 10:2025 (the web-app list). This is an
 * API-first scanner built around the OWASP API Security Top 10 (2023) — the
 * per-check `owasp` tags above use those codes — so this table is a cross-walk,
 * not a compliance claim. No black-box active scanner "fully supports" the
 * Top 10: several categories (insecure design, supply chain, logging) are not
 * observable from the outside. Levels are deliberately conservative.
 */
/**
 * The OWASP API Security Top 10 (2023) — the list this scanner is built around,
 * used by the coverage-matrix visual. Names are stable; the per-code tier the
 * matrix shows is derived from GROUPS at render time by {@link apiCoverage}, so
 * it can never drift from the checks.
 */
export interface ApiTop10Entry {
  code: string;
  short: string;
  name: string;
}

export const API_TOP10_2023: ApiTop10Entry[] = [
  { code: "API1:2023", short: "BOLA", name: "Broken Object Level Authorization" },
  { code: "API2:2023", short: "Auth", name: "Broken Authentication" },
  { code: "API3:2023", short: "BOPLA", name: "Broken Object Property Level Authorization" },
  { code: "API4:2023", short: "Resource", name: "Unrestricted Resource Consumption" },
  { code: "API5:2023", short: "BFLA", name: "Broken Function Level Authorization" },
  { code: "API6:2023", short: "Flows", name: "Unrestricted Access to Sensitive Business Flows" },
  { code: "API7:2023", short: "SSRF", name: "Server-Side Request Forgery" },
  { code: "API8:2023", short: "Misconfig", name: "Security Misconfiguration" },
  { code: "API9:2023", short: "Inventory", name: "Improper Inventory Management" },
  { code: "API10:2023", short: "Consumption", name: "Unsafe Consumption of APIs" },
];

export interface ApiCoverageCell extends ApiTop10Entry {
  /** Strongest evidence tier a check for this code produces, or null for a gap. */
  best: "verified" | "heuristic" | null;
  /** How many registered checks carry this code. */
  count: number;
  /** True when every check for this code is premium-gated. */
  premiumOnly: boolean;
}

/**
 * Roll the per-check `owasp` codes up to one cell per API Top-10 family. Pure,
 * derived from {@link GROUPS}, so the matrix visual stays a mirror of the engine
 * exactly like the rest of this file. OWASP API labels use the canonical dated
 * form (`"API4:2023"`); injection families use their canonical CWE label.
 */
export function apiCoverage(): ApiCoverageCell[] {
  const all = GROUPS.flatMap((g) => g.checks).filter(
    (c) => c.confidence !== "planned",
  );
  return API_TOP10_2023.map((entry) => {
    const hits = all.filter((c) => c.owasp === entry.code);
    const best: ApiCoverageCell["best"] = hits.some(
      (c) => c.confidence === "verified",
    )
      ? "verified"
      : hits.some((c) => c.confidence === "heuristic")
        ? "heuristic"
        : null;
    return {
      ...entry,
      best,
      count: hits.length,
      premiumOnly: hits.length > 0 && hits.every((c) => c.premium === true),
    };
  });
}

export type CoverageLevel = "strong" | "partial" | "none";

export const COVERAGE_LEVEL_LABEL: Record<CoverageLevel, string> = {
  strong: "Strong",
  partial: "Partial",
  none: "Not covered",
};

export interface OwaspMapping {
  code: string;
  name: string;
  level: CoverageLevel;
  note: string;
}

export const OWASP_2025: OwaspMapping[] = [
  {
    code: "A01:2025",
    name: "Broken Access Control",
    level: "strong",
    note: "The engine's core strength: BOLA (API1) and BFLA (API5) across two identities, forged-token acceptance, and — with writes on — verified BOLA/BFLA-on-write via the write oracle (a write by a low-privilege identity read back by the owner). Not exhaustive: no CSRF, forced-browsing, or traversal-to-file enumeration.",
  },
  {
    code: "A02:2025",
    name: "Security Misconfiguration",
    level: "partial",
    note: "A per-endpoint response-header sweep (hardening headers by presence and by value, permissive CORS, cookie flags, version banners), a verified TLS-configuration audit, and a response-body read for over-exposed fields and spec drift. No default-credential or exposed-admin-surface sweeps, and no CORS preflight probing.",
  },
  {
    code: "A03:2025",
    name: "Software Supply Chain Failures",
    level: "none",
    note: "No dependency, SBOM, or build-integrity analysis. The opt-in nuclei adjunct may match some known-CVE components, but supply-chain risk is not something a black-box API scan can assess.",
  },
  {
    code: "A04:2025",
    name: "Cryptographic Failures",
    level: "partial",
    note: "A verified transport-layer audit (certificate, negotiated cipher and protocol, read from a direct TLS socket). No application-layer cryptography analysis.",
  },
  {
    code: "A05:2025",
    name: "Injection",
    level: "partial",
    note: "Reflection leads across SQLi / XSS / SSTI / command / traversal / CRLF / XPath / LDAP / NoSQL / SSI / JSON, plus OOB-confirmed blind classes (SSRF/RFI/RCE/ESI/XXE) and optional sqlmap / dalfox / commix / tplmap confirmation. Reflection alone is a lead, not proof — only OOB callbacks and the confirmation tools verify execution.",
  },
  {
    code: "A06:2025",
    name: "Insecure Design",
    level: "partial",
    note: "A design-level risk — not detectable by an active black-box scanner. The premium spec design review reads the OpenAPI design artifact (operations, schemas and auth scope — no secrets, no values) and flags spec-visible design risks such as sensitive endpoints with no declared auth, secrets in query/path params, and over-permissive request schemas. It is a static review of the design, not behavioral detection, so its findings are heuristic and it cannot see design flaws invisible in the spec.",
  },
  {
    code: "A07:2025",
    name: "Authentication Failures",
    level: "partial",
    note: "Detects a random, never-issued token being accepted on endpoints that look protected, duplicate-create enumeration oracles (writes), and unthrottled auth-shaped endpoints. No credential-stuffing, weak-password, MFA, or session-management testing.",
  },
  {
    code: "A08:2025",
    name: "Software or Data Integrity Failures",
    level: "partial",
    note: "The write oracle confirms an unauthorized write persists across identities — a data-integrity failure — with writes on. No deserialization, update-channel, or CI/CD integrity checks.",
  },
  {
    code: "A09:2025",
    name: "Security Logging & Alerting Failures",
    level: "none",
    note: "Not observable from outside via active scanning.",
  },
  {
    code: "A10:2025",
    name: "Mishandling of Exceptional Conditions",
    level: "partial",
    note: "New in 2025. Backend error signatures (FuzzDB regexes) and verbose error / stack-trace disclosure are caught as evidence, but exceptional-condition handling is not systematically exercised.",
  },
];

/** How optional AI participates without owning scanner safety decisions. */
export const AI_CASCADE = {
  blurb:
    "Six opt-in, off-by-default touch points: planning, payload design, adaptive validation, rejected-resource refinement, adjudication, and security design review. The engine never depends on AI: it owns the method, routes, schemas, gates, budgets, validation, and every network request. The model can propose an ordering or a bounded payload; it cannot send one directly or create a finding.",
  steps: [
    {
      k: "Before — plan (plan:true)",
      v: "The planner reads the spec's operations (method, path, params, auth scope — no credentials) and ranks each by risk, so the engine spends its 750-request budget on the likeliest-vulnerable endpoints first. The plan (priority + one-line rationale per endpoint) is shown on the scan.",
    },
    {
      k: "Before — payload design (genai_payloads:true)",
      v: "DeepSeek proposes extra reflection-payload variants that deepen the rotation pool the reflected-injection check draws from. Every proposed string is re-validated (unique marker present, a neutralisable metacharacter, no control characters, length-capped) before it can reach the target, and it only ever adds to the curated + vendored-corpus pool — the model cannot narrow coverage or change which findings can exist. Per-scan request volume is unchanged (still one payload per family per scan).",
    },
    {
      k: "During — adaptive validation",
      v: "With premium:true + adaptive:true, the planner may choose the next prevalidated variant from a fixed 2–3-attempt set. Body variants additionally require writes. The engine builds and sends the request and stores value-free response structure; the run's request log additionally keeps a redacted, size-capped body sample.",
    },
    {
      k: "During — refine a rejected create",
      v: "With authorized + premium:true + writes + the separate resource-refinement switch, only a 400, 409, or 422 create rejection can trigger a retry. The planner receives the declared request schema, the previous scanner-generated body, a redacted error excerpt, and optional read-only DB schema metadata. Its body must pass spec validation before the engine sends it; total attempts stay at 2 or 3.",
    },
    {
      k: "After — adjudicate (adjudicate:true)",
      v: "Judgment-heavy findings are reviewed after testing. Each is reduced to a compact view of class, endpoint and redacted evidence; the model can set a verdict and rationale but cannot alter the observed evidence.",
    },
    {
      k: "After — security design review (security_review:true)",
      v: "DeepSeek compares a structural OpenAPI view with the database table structure a local run read on the CLI machine, when the scan has one. It returns bounded, referenced suggestions covering authorization, tenant isolation, sensitive fields, mass assignment and security-relevant constraint mismatches. The Security improvements section keeps this advisory review separate from detected vulnerabilities. No application rows, credentials or target requests are involved; unavailable database metadata falls back to OpenAPI alone.",
    },
    {
      k: "Isolation & cost",
      v: "The planner runs in an isolated subprocess and any failure degrades to deterministic engine behavior. Planning, payload design, resource proposals, adjudication, and security design review calls are metered into the per-scan token ledger; the summary shows models, phases, tokens, and total cost.",
    },
  ],
};
