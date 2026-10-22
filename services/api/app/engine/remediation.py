"""What we know about each check: what it means, and what to change.

A finding that nobody fixes is a finding that did no work. Every check has one
entry here carrying its CWE, a one-line summary, a remediation template and
references — so a finding arrives with the change to make, not just the problem.

The remediation text is a template filled from the finding's own evidence, which
is what keeps it actionable: "enforce an ownership check in the handler for
``GET /accounts/{id}``" is a task, "implement object-level authorization" is a
slogan. Missing evidence keys degrade to neutral wording rather than raising, so
a check that changes its evidence shape can never break a scan.

Pure — no I/O, no DB, no engine state. ``run_record.append_finding`` fills a
finding from here unless the check supplied its own text, and ``scans/sarif.py``
reads the same entries for rule metadata, so the two can never disagree.

Advice is deliberately generic about *frameworks* and specific about *where*:
this scanner sees HTTP, not your handlers, and guessing at an ORM would produce
confident nonsense.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# Reference URLs used by more than one entry.
_API_TOP10 = "https://owasp.org/API-Security/editions/2023/en/0x11-t10/"
_CS = "https://cheatsheetseries.owasp.org/cheatsheets/"


@dataclass(frozen=True)
class CheckKnowledge:
    """Everything the product knows about one check key."""

    #: One line naming the weakness — SARIF ``shortDescription``.
    summary: str
    #: Best-effort CWE for downstream triage tooling.
    cwe: str | None
    #: Remediation template. ``{path}``, ``{method}``, ``{param}``, ``{location}``,
    #: ``{identity}``, ``{field}``, ``{family}``, ``{host}`` are filled from the
    #: finding's evidence; anything absent degrades to neutral wording.
    remediation: str
    references: tuple[str, ...] = field(default_factory=tuple)


#: Neutral stand-ins, so a template never renders "None" or raises KeyError.
_FALLBACKS = {
    "path": "the affected endpoint",
    "method": "the request",
    "param": "the affected parameter",
    "location": "request",
    "identity": "the low-privilege identity",
    "field": "the affected field",
    "family": "the payload",
    "host": "the target host",
}


class _Evidence(dict):
    """Evidence for ``format_map``: unknown or empty keys fall back to prose."""

    def __missing__(self, key: str) -> str:
        return _FALLBACKS.get(key, f"the {key.replace('_', ' ')}")


CATALOGUE: dict[str, CheckKnowledge] = {
    "source_runtime_cve": CheckKnowledge(
        summary="Declared runtime version matches a published vulnerability advisory.",
        cwe="CWE-1395",
        remediation=("Update the runtime declared in {location} to a supported patched release. "
                     "Confirm the deployed version and vendor backports against the advisory, "
                     "rebuild the image, deploy it and rerun the source advisory checks."),
        references=("https://nvd.nist.gov/",),
    ),
    "adaptive_validation": CheckKnowledge(
        summary="Controlled validation variant accepted after a valid baseline.",
        cwe="CWE-20",
        remediation=(
            "Validate {field} at the API boundary for the tested {rule} rule on "
            "{method} {path}. Keep the declared contract and persistence model "
            "aligned, reject malformed values before business logic, and add a "
            "regression test for the exact boundary case. This adaptive result "
            "is a lead until a safe business-impact oracle confirms a bypass."
        ),
        references=(
            "https://cwe.mitre.org/data/definitions/20.html",
            "https://owasp.org/www-project-api-security/",
        ),
    ),
    # ---- authorization & authentication --------------------------------------
    "bola": CheckKnowledge(
        summary="Broken Object Level Authorization (OWASP API1).",
        cwe="CWE-639",
        remediation=(
            "Authorize the *object*, not just the caller, in the handler for "
            "{method} {path}. Look up the record and compare its owner (tenant, "
            "user or organisation) against the authenticated principal before "
            "returning it, and return the same 404 for 'not yours' as for 'does "
            "not exist' so the endpoint stops confirming which ids are real. "
            "Applying the ownership predicate in the query itself — scoping the "
            "read by owner rather than filtering after the fetch — makes the "
            "check impossible to forget on the next endpoint."
        ),
        references=(
            _API_TOP10,
            f"{_CS}Authorization_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/639.html",
        ),
    ),
    "bfla": CheckKnowledge(
        summary="Broken Function Level Authorization (OWASP API5).",
        cwe="CWE-285",
        remediation=(
            "Require the privileged role on {method} {path}. The identity "
            "'{identity}' reached this function, so the route is either missing "
            "its role check or inheriting one that does not apply. Deny by "
            "default at the router or middleware and opt each route into the "
            "role it needs, rather than adding a role check per handler — the "
            "handler that is added next is the one that will be missed."
        ),
        references=(
            _API_TOP10,
            f"{_CS}Authorization_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/285.html",
        ),
    ),
    "broken_auth": CheckKnowledge(
        summary="Broken Authentication (OWASP API2).",
        cwe="CWE-287",
        remediation=(
            "Reject the forged token on {method} {path}. Verify the signature "
            "against a pinned algorithm — never trust the token's own `alg` header, "
            "and never accept `none` — use a generated high-entropy HMAC key rather "
            "than a word or default, and validate `exp`, `nbf`, `iss` and `aud` on "
            "every request. Use your library's strict verification entry point rather "
            "than decoding the payload and reading claims, which is the usual "
            "route to accepting an unsigned token."
        ),
        references=(
            _API_TOP10,
            f"{_CS}JSON_Web_Token_for_Java_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/287.html",
        ),
    ),
    "seeded_bola": CheckKnowledge(
        summary="Cross-tenant object read, proven by seeding (OWASP API1).",
        cwe="CWE-639",
        remediation=(
            "Scope the read on {method} {path} to the object's owner. An object "
            "created by one identity was read back by '{identity}', so the item "
            "read authenticates the caller but never checks that the object "
            "belongs to them. Apply the ownership predicate in the query — scope "
            "the fetch by owner (tenant, user or organisation) rather than "
            "looking the record up by id alone — and return the same 404 for "
            "'not yours' as for 'does not exist' so ids stop being enumerable."
        ),
        references=(
            _API_TOP10,
            f"{_CS}Authorization_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/639.html",
        ),
    ),
    "write_authz": CheckKnowledge(
        summary="Authorization not enforced on a write (OWASP API1/API5).",
        cwe="CWE-285",
        remediation=(
            "Apply the same ownership check to writes as to reads on {path}: a "
            "write by '{identity}' to '{field}' persisted and was read back by "
            "another identity. Authorize the target object before mutating it, "
            "and scope the update statement by owner so a row belonging to "
            "someone else cannot be addressed at all."
        ),
        references=(
            _API_TOP10,
            f"{_CS}Authorization_Cheat_Sheet.html",
        ),
    ),
    "mass_assignment": CheckKnowledge(
        summary="Mass assignment — a client-writable server-owned field (OWASP API6).",
        cwe="CWE-915",
        remediation=(
            "Bind the request body to an explicit input model on {method} "
            "{path}, listing the fields a caller may set, and copy only those "
            "onto the record. '{field}' is server-owned state and reached it "
            "straight from the body, so the handler is binding the whole "
            "payload — patching the object with the parsed request, or passing "
            "it to the ORM's update. An allowlist stays correct when a column "
            "is added; a denylist of fields to strip does not, because the "
            "field added next will not be on it. Where a privileged field "
            "genuinely must be settable, authorize it separately from the rest "
            "of the update."
        ),
        references=(
            _API_TOP10,
            f"{_CS}Mass_Assignment_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/915.html",
        ),
    ),
    "race_condition": CheckKnowledge(
        summary="Race condition / limit overrun on a business flow (OWASP API6).",
        cwe="CWE-362",
        remediation=(
            "Make the check and the write on {method} {path} atomic. '{field}' is "
            "enforced unique sequentially but not under concurrency, so the "
            "check-then-act has a gap that racing requests slip through. Enforce "
            "it in the datastore — a unique constraint or index, or a "
            "SELECT ... FOR UPDATE / compare-and-set inside one transaction — "
            "rather than a read followed by a conditional write in application "
            "code. An idempotency key on the create makes a retried or "
            "duplicated request safe as well."
        ),
        references=(
            _API_TOP10,
            "https://cwe.mitre.org/data/definitions/362.html",
        ),
    ),
    # ---- injection -----------------------------------------------------------
    "reflected_injection": CheckKnowledge(
        summary="Unescaped reflection of attacker input (injection lead).",
        cwe="CWE-79",
        remediation=(
            "Treat the '{param}' {location} parameter on {path} as untrusted. "
            "This is a lead — the marker came back, which proves input reaches "
            "the response, not that it executes — so confirm it by hand or with "
            "`confirm: true` first. The fix is the same either way: validate the "
            "parameter against its declared type/format, keep it out of "
            "interpreted contexts (SQL, shell, template, path), and encode it "
            "for the context it is rendered into rather than filtering it on the "
            "way in."
        ),
        references=(
            f"{_CS}Injection_Prevention_Cheat_Sheet.html",
            f"{_CS}Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
        ),
    ),
    "signature_injection": CheckKnowledge(
        summary="Backend interpreter error or reflection signature (injection lead).",
        cwe="CWE-943",
        remediation=(
            "The '{param}' {location} parameter on {path} reached a backend "
            "interpreter — the response carried an error signature for the "
            "{family} family. Parameterise the query or expression instead of "
            "building it from the input (bound parameters for SQL, a filter "
            "object for NoSQL, an escaped literal for XPath/LDAP), and stop "
            "returning raw interpreter errors to callers: they hand an attacker "
            "the backend's structure."
        ),
        references=(
            f"{_CS}Injection_Prevention_Cheat_Sheet.html",
            f"{_CS}Query_Parameterization_Cheat_Sheet.html",
        ),
    ),
    "ssrf": CheckKnowledge(
        summary="Server-Side Request Forgery candidate (OWASP API7).",
        cwe="CWE-918",
        remediation=(
            "The '{param}' parameter on {path} accepts a URL the server may "
            "fetch. Resolve and validate the destination against an allowlist of "
            "hosts before requesting it, re-checking after DNS resolution and on "
            "every redirect; block link-local and cloud-metadata ranges "
            "(169.254.0.0/16 especially) and private address space unless the "
            "feature genuinely needs them. Where the set of destinations is "
            "known, take an identifier and map it to the URL server-side rather "
            "than accepting a URL at all."
        ),
        references=(
            _API_TOP10,
            f"{_CS}Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html",
        ),
    ),
    "oob_injection": CheckKnowledge(
        summary="Out-of-band interaction confirmed (blind injection/SSRF).",
        cwe="CWE-918",
        remediation=(
            "Confirmed: the target made a network call to a host supplied "
            "through '{param}' on {path}, so this is not a lead. Treat it as an "
            "exploitable {family} issue and fix the sink — allowlist outbound "
            "destinations, disable external entity resolution in the XML parser, "
            "and never pass caller-supplied values into a fetch, include or "
            "template-evaluation call."
        ),
        references=(
            _API_TOP10,
            f"{_CS}Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html",
            f"{_CS}XML_External_Entity_Prevention_Cheat_Sheet.html",
        ),
    ),
    "data_exposure": CheckKnowledge(
        summary="Excessive data exposure in a response body (OWASP API3).",
        cwe="CWE-213",
        remediation=(
            "Shape the response on {path} to what the caller needs. Serialise "
            "through an explicit response model that names the fields to "
            "include, rather than returning the ORM object or dumping the "
            "record — an allowlist stays correct when a column is added, a "
            "denylist does not. Where the finding names undeclared fields, "
            "either the spec is stale (fix it: every client generator and "
            "reviewer works from it) or the endpoint returns more than anyone "
            "reviewed. Filtering in the client is not a fix: the data was "
            "already sent."
        ),
        references=(
            _API_TOP10,
            f"{_CS}Mass_Assignment_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/213.html",
        ),
    ),
    "potential_secrets": CheckKnowledge(
        summary="Potential credential material in a response or uploaded specification.",
        cwe="CWE-200",
        remediation=(
            "Inspect the named structural location and determine whether the "
            "candidate is real; this offline detector does not establish that a "
            "credential is live. If it is real, revoke or rotate it immediately, "
            "remove it from the response or specification, and load the replacement "
            "from a secret manager at runtime. Shape response models so credential "
            "material cannot be serialised, and publish examples that use unmistakable "
            "placeholders rather than working values."
        ),
        references=(
            _API_TOP10,
            "https://cwe.mitre.org/data/definitions/200.html",
            "https://cwe.mitre.org/data/definitions/798.html",
        ),
    ),
    # ---- misconfiguration ----------------------------------------------------
    "security_headers": CheckKnowledge(
        summary="Missing or weak security response headers (OWASP API8).",
        cwe="CWE-693",
        remediation=(
            "Set the missing headers on every response, in shared middleware or "
            "at the edge proxy rather than per route — the route added next is "
            "the one that will miss them. The coverage page lists the value this "
            "scanner treats as correct for each header. Where the finding names "
            "CORS, replace a reflected or wildcard origin with a fixed "
            "allowlist, and never combine a reflected origin with "
            "`Access-Control-Allow-Credentials: true`; where it names a cookie, "
            "add `HttpOnly`, `Secure` and `SameSite`."
        ),
        references=(
            f"{_CS}HTTP_Headers_Cheat_Sheet.html",
            "https://owasp.org/www-project-secure-headers/",
        ),
    ),
    "info_disclosure": CheckKnowledge(
        summary="Information disclosure in response headers (OWASP API8).",
        cwe="CWE-200",
        remediation=(
            "Strip the identifying headers at the edge. Version banners and "
            "internal debug/trace headers give an attacker your stack and "
            "patch level for free, and no client needs them. Most servers and "
            "proxies have a one-line directive to suppress them."
        ),
        references=(
            f"{_CS}HTTP_Headers_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/200.html",
        ),
    ),
    "tls_config": CheckKnowledge(
        summary="Weak TLS configuration or certificate (transport security).",
        cwe="CWE-326",
        remediation=(
            "Fix the transport configuration on {host}: serve TLS 1.2 at minimum "
            "(prefer 1.3), disable the deprecated protocol versions and cipher "
            "suites the finding names, and keep the certificate current with a "
            "key and signature hash of adequate strength. Terminate TLS in one "
            "place — the edge proxy or load balancer — so the policy is set once "
            "rather than per service."
        ),
        references=(
            f"{_CS}Transport_Layer_Security_Cheat_Sheet.html",
            "https://wiki.mozilla.org/Security/Server_Side_TLS",
        ),
    ),
    "schema_fuzz": CheckKnowledge(
        summary="Generated input exposes a server error or response-contract drift.",
        cwe="CWE-20",
        remediation=(
            "Reconcile the implementation and OpenAPI contract for {path}: return "
            "only documented statuses and media types, include required headers, "
            "and serialize the declared response shape. Validate generated input "
            "at the edge and reject invalid data with a documented 4xx; catch "
            "unexpected exceptions and map them to a generic error response."
        ),
        references=(
            _API_TOP10,
            f"{_CS}Input_Validation_Cheat_Sheet.html",
        ),
    ),
    "enumeration": CheckKnowledge(
        summary="Enumeration oracle or missing rate limiting (OWASP API4/API2).",
        cwe="CWE-307",
        remediation=(
            "Rate-limit {path} per identity *and* per source address, and answer "
            "identically whether or not the record exists — a distinct conflict "
            "response on '{field}' tells an attacker which accounts are real. "
            "For registration and password-reset flows, respond the same way in "
            "both cases and deliver the difference out of band by email."
        ),
        references=(
            _API_TOP10,
            f"{_CS}Authentication_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/307.html",
        ),
    ),
    # ---- adjunct tools -------------------------------------------------------
    "zap": CheckKnowledge(
        summary="Reported by the OWASP ZAP active scanner.",
        cwe=None,
        remediation=(
            "Read ZAP's own `solution` text in the evidence — it is alert-"
            "specific and more precise than anything this catalogue can say "
            "generically. Confirm the alert against the endpoint before "
            "scheduling work: ZAP alerts range from proven to fingerprint-level."
        ),
        references=("https://www.zaproxy.org/docs/alerts/",),
    ),
    "kali_nuclei": CheckKnowledge(
        summary="A nuclei template matched the target.",
        cwe=None,
        remediation=(
            "Open the matched template — its id is in the evidence — for the "
            "specific condition and fix. Exploit-verifying templates are strong "
            "evidence; fingerprint-style templates only say a component is "
            "present, so check which kind matched before acting."
        ),
        references=("https://docs.projectdiscovery.io/templates/introduction",),
    ),
    "kali_discovery": CheckKnowledge(
        summary="An endpoint absent from the spec responded (OWASP API9).",
        cwe="CWE-1059",
        remediation=(
            "Decide whether {path} should exist. If it should, document it in "
            "the spec so it is scanned like everything else; if it should not, "
            "remove it or block it at the gateway. Undocumented endpoints are "
            "where old versions and debug routes survive unnoticed — this "
            "scanner does not yet run its checks against them, so it is untested "
            "surface either way."
        ),
        references=(_API_TOP10,),
    ),
    "kali_crawl": CheckKnowledge(
        summary="A crawled endpoint is absent from the spec (OWASP API9).",
        cwe="CWE-1059",
        remediation=(
            "Reconcile {path} with the spec — either document it so it is "
            "covered by scans and reviews, or retire it. An endpoint the spec "
            "does not know about is an endpoint nobody is testing."
        ),
        references=(_API_TOP10,),
    ),
    "kali_params": CheckKnowledge(
        summary="Parameters accepted but not declared in the spec.",
        cwe="CWE-1059",
        remediation=(
            "Undeclared parameters on {path} are accepted input that no schema "
            "constrains and no review has seen. Document them, or stop binding "
            "them — an accepted-but-undocumented field is the usual shape of a "
            "mass-assignment bug."
        ),
        references=(_API_TOP10,),
    ),
    "kali_nikto": CheckKnowledge(
        summary="Reported by the nikto web-server scanner.",
        cwe=None,
        remediation=(
            "Confirm before acting: nikto's basic output carries no severity and "
            "many items are version or existence checks rather than proven "
            "issues. Where it names a file or directory that should not be "
            "public, remove it."
        ),
        references=("https://github.com/sullo/nikto/wiki",),
    ),
    "kali_whatweb": CheckKnowledge(
        summary="Technology fingerprint of the target stack.",
        cwe="CWE-200",
        remediation=(
            "Informational. Reduce what the stack volunteers — version banners "
            "in headers and error pages — and use the inventory to check the "
            "named components are patched."
        ),
        references=(f"{_CS}HTTP_Headers_Cheat_Sheet.html",),
    ),
    "testssl": CheckKnowledge(
        summary="Reported by the testssl.sh transport audit.",
        cwe="CWE-326",
        remediation=(
            "Apply testssl's finding to the TLS termination point: protocol "
            "versions, cipher suites and certificate properties are all set "
            "there. Fixing it at the edge fixes it for every service behind it."
        ),
        references=(
            f"{_CS}Transport_Layer_Security_Cheat_Sheet.html",
            "https://wiki.mozilla.org/Security/Server_Side_TLS",
        ),
    ),
    "sqlmap_confirm": CheckKnowledge(
        summary="SQL injection reproduced by sqlmap (confirmed).",
        cwe="CWE-89",
        remediation=(
            "Confirmed exploitable: sqlmap reproduced injection through "
            "'{param}' on {path}. Replace the concatenated query with bound "
            "parameters — escaping is not a fix — and review the same pattern "
            "wherever that query is built. Treat any data reachable by that "
            "query as exposed until you know otherwise."
        ),
        references=(
            f"{_CS}SQL_Injection_Prevention_Cheat_Sheet.html",
            f"{_CS}Query_Parameterization_Cheat_Sheet.html",
        ),
    ),
    "dalfox_confirm": CheckKnowledge(
        summary="Cross-site scripting reproduced by dalfox (confirmed).",
        cwe="CWE-79",
        remediation=(
            "Confirmed exploitable: the payload executed in a browser context "
            "via '{param}' on {path}. Encode output for the context it lands in "
            "rather than sanitising input, and add a Content-Security-Policy "
            "that forbids inline script as defence in depth."
        ),
        references=(f"{_CS}Cross_Site_Scripting_Prevention_Cheat_Sheet.html",),
    ),
    "commix_confirm": CheckKnowledge(
        summary="Command injection reproduced by commix (confirmed).",
        cwe="CWE-78",
        remediation=(
            "Confirmed exploitable: '{param}' on {path} reaches a shell. Stop "
            "passing caller input to a shell — call the binary directly with an "
            "argument list and no shell interpretation, or remove the shell-out "
            "entirely. Assume the host is compromised until investigated."
        ),
        references=(f"{_CS}OS_Command_Injection_Defense_Cheat_Sheet.html",),
    ),
    "tplmap_confirm": CheckKnowledge(
        summary="Server-side template injection reproduced by tplmap (confirmed).",
        cwe="CWE-1336",
        remediation=(
            "Confirmed exploitable: '{param}' on {path} is evaluated as a "
            "template, which is usually remote code execution. Never build a "
            "template from caller input — pass it as a *value* into a fixed "
            "template — and sandbox the engine if user-authored templates are a "
            "genuine requirement."
        ),
        references=(f"{_CS}Injection_Prevention_Cheat_Sheet.html",),
    ),
    "host_header": CheckKnowledge(
        summary="Host-header reflection: the target builds links or redirects from a spoofed Host.",
        cwe="CWE-644",
        remediation=(
            "The application built output on {method} {route} from the Host/"
            "forwarded-host header. Never trust a client-supplied host for "
            "absolute URLs or cache keys: use a configured canonical origin and "
            "build links and redirects from that, not from the request's Host."
        ),
        references=(f"{_CS}HTTP_Headers_Cheat_Sheet.html",),
    ),
    "design_review": CheckKnowledge(
        summary="Spec design review: a design-level risk visible in the OpenAPI spec.",
        cwe="CWE-306",
        remediation=(
            "The spec declares a design-level risk on {method} {route}: a "
            "sensitive operation without authentication, credential material in "
            "the URL, a server-owned field exposed to clients, a missing error or "
            "rate-limit contract, or an unbounded collection response. Review the "
            "design: require authentication on sensitive operations, move secrets "
            "to headers or the request body, and remove server-owned fields from "
            "client-writable schemas. Declare consistent error and 429 behavior "
            "with retry headers, and put an explicit maxItems bound on collection "
            "response schemas."
        ),
        references=(f"{_CS}Authorization_Cheat_Sheet.html",),
    ),
    "unsafe_consumption": CheckKnowledge(
        summary="Upstream response consumed and relayed unvalidated (OWASP API10).",
        cwe="CWE-918",
        remediation=(
            "{method} {path} fetched an upstream chosen through '{param}' and "
            "relayed its response to the caller without validating it. Restrict "
            "the upstreams the server will call to a strict allow-list of hosts, "
            "require TLS on downstream calls, validate and schema-check every "
            "response before using or forwarding it, and never echo raw upstream "
            "content back to clients. Treat data from an integrated API as "
            "untrusted, exactly like direct user input."
        ),
        references=(
            f"{_CS}Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html",
            _API_TOP10,
        ),
    ),
    "business_flow": CheckKnowledge(
        summary="Sensitive business flow with no anti-automation (OWASP API6).",
        cwe="CWE-799",
        remediation=(
            "{method} {path} let an identical request be replayed rapidly, each "
            "time creating a new object, with no throttle or anti-automation "
            "control. Add a control appropriate to the flow's value: an "
            "idempotency key so a replay returns the first result instead of a "
            "new one, per-identity and per-source rate limiting, and — for "
            "high-value flows like checkout or signup — a human-verification "
            "step (CAPTCHA or device attestation) and business-rule quotas."
        ),
        references=(
            f"{_CS}Denial_of_Service_Cheat_Sheet.html",
            _API_TOP10,
        ),
    ),
    "resource_consumption": CheckKnowledge(
        summary="Client-controlled page size with no effective cap (OWASP API4).",
        cwe="CWE-770",
        remediation=(
            "{method} {path} returned more records as the client asked for more, "
            "with no effective ceiling on '{param}'. Enforce a maximum page size "
            "server-side (a hard cap the client cannot exceed) and require "
            "pagination on collection responses, so one request cannot force the "
            "whole table to be assembled, serialised and transferred."
        ),
        references=(
            f"{_CS}Denial_of_Service_Cheat_Sheet.html",
            _API_TOP10,
        ),
    ),
    "advanced_rate_limit": CheckKnowledge(
        summary="No rate limiting observed under sustained load.",
        cwe="CWE-799",
        remediation=(
            "{method} {route} served a sustained burst of identical requests "
            "without throttling. Rate-limit authentication-shaped endpoints "
            "(login, token, reset) by source and by account, and apply the same "
            "limit to sustained traffic, not only to a short burst."
        ),
        references=(f"{_CS}Authentication_Cheat_Sheet.html",),
    ),
    "xxe_confirmation": CheckKnowledge(
        summary="XXE confirmed: the target resolved an out-of-band XML external entity.",
        cwe="CWE-611",
        remediation=(
            "The target parsed attacker-controlled XML and resolved the external "
            "entity sent through '{field}' on {route}. Disable DTDs and external "
            "entities in the XML parser, and reject XML unless the endpoint truly "
            "needs it."
        ),
        references=(f"{_CS}XML_External_Entity_Prevention_Cheat_Sheet.html",),
    ),
    "jwt_confusion": CheckKnowledge(
        summary="JWT verification is confused: key confusion or a client-supplied key location.",
        cwe="CWE-345",
        remediation=(
            "The JWT verifier on {route} either HMACs with the public key (RS256→"
            "HS256 confusion) or fetches a client-supplied jku/x5u key location. "
            "Pin the algorithm per key and ignore jku/x5u unless the key set is "
            "fetched from a configured, allow-listed origin."
        ),
        references=(f"{_CS}JSON_Web_Token_for_Java_Cheat_Sheet.html",),
    ),
    "deserialization": CheckKnowledge(
        summary="Insecure deserialization confirmed: the target executed an untrusted gadget.",
        cwe="CWE-502",
        remediation=(
            "The target deserialized attacker-controlled input sent through "
            "'{field}' on {route} and executed it. Never deserialize untrusted "
            "data; prefer safe parsers (json, protobuf), and where a native "
            "format is required, constrain the allowed types and validate before "
            "deserializing."
        ),
        references=(f"{_CS}Deserialization_Cheat_Sheet.html",),
    ),
    "graphql_introspection": CheckKnowledge(
        summary="GraphQL introspection is enabled: the schema is exposed to any caller.",
        cwe="CWE-200",
        remediation=(
            "{route} answered a GraphQL introspection query with the schema, "
            "revealing the entire API surface. Disable introspection in "
            "production, or gate it behind authentication and logging."
        ),
        references=(f"{_CS}Authorization_Cheat_Sheet.html",),
    ),
    "graphql_behavior": CheckKnowledge(
        summary="GraphQL schema suggestion exposure or alternative-form auth bypass.",
        cwe="CWE-285",
        remediation=(
            "Disable field-name suggestions in production error responses on "
            "{route}. For an alias or batch bypass, apply authorization during "
            "field resolution for every operation independently — do not authorize "
            "only the raw query text, first root field, or outer HTTP request. "
            "Apply the same depth, alias and batching policy before execution."
        ),
        references=(
            f"{_CS}Authorization_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/285.html",
        ),
    ),
    "request_smuggling": CheckKnowledge(
        summary="HTTP request smuggling: the front-end and back-end disagree on framing.",
        cwe="CWE-444",
        remediation=(
            "The front-end and back-end parse request framing differently on "
            "{route}. Use HTTP/2 end-to-end, or normalise and reject requests that "
            "carry both Content-Length and Transfer-Encoding, and configure the "
            "front-end and back-end to agree on one framing rule."
        ),
        references=(f"{_CS}HTTP_Headers_Cheat_Sheet.html",),
    ),
    "grpc_reflection": CheckKnowledge(
        summary="gRPC reflection is enabled: the service catalogue is exposed to any caller.",
        cwe="CWE-200",
        remediation=(
            "{route} answered a gRPC reflection request with the service list, "
            "revealing the full API surface. Disable server reflection in "
            "production, or gate it behind authentication and logging."
        ),
        references=(f"{_CS}Authorization_Cheat_Sheet.html",),
    ),
}


def knowledge(check: str) -> CheckKnowledge | None:
    """The catalogue entry for a check key, or None for an unknown key."""
    return CATALOGUE.get(check)


def cwe(check: str) -> str | None:
    entry = CATALOGUE.get(check)
    return entry.cwe if entry else None


def summary(check: str) -> str:
    entry = CATALOGUE.get(check)
    return entry.summary if entry else check


def remediate(check: str, evidence: dict[str, Any] | None = None) -> tuple[str, list[str]]:
    """Remediation text and references for a finding, shaped by its evidence.

    Returns ``("", [])`` for a check with no entry — an unknown key means the
    catalogue is behind the engine, which should leave the finding bare rather
    than attach advice about the wrong weakness. Never raises: a template
    referencing evidence the check did not supply degrades to neutral wording.
    """
    entry = CATALOGUE.get(check)
    if entry is None:
        return "", []
    values = {
        k: v
        for k, v in (evidence or {}).items()
        if isinstance(v, str | int | float) and str(v).strip()
    }
    # `path` is what was probed — a rendered URL carrying an object id or a
    # payload. `route` is the spec template the handler is written against, and
    # a fix is made in a handler. The same rule the fingerprint uses.
    if values.get("route"):
        values["path"] = values["route"]
    try:
        text = entry.remediation.format_map(_Evidence(values))
    except (IndexError, ValueError):  # a malformed template must not break a scan
        text = entry.remediation
    return text, list(entry.references)
