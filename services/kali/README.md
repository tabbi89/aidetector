# Kali adjunct service

Opt-in sidecar that gives the scanner access to curated Kali Linux tools —
built `FROM kalilinux/kali-rolling` (the official Kali Docker image, which
ships **no tools by default**; we install only what the worker drives: nuclei,
ffuf, nikto, whatweb, katana, arjun, plus the `seclists` wordlists).

It exposes a small job API consumed by `services/api/app/engine/kali.py`,
the same way the ZAP daemon is consumed by `app/engine/zap.py`:

| Endpoint             | Tool    | What it does                                        |
| -------------------- | ------- | --------------------------------------------------- |
| `POST /run/nuclei`   | nuclei  | Template scan (CVEs, exposures, misconfigs) over the base target plus the extra operation URLs; `-rate-limit` from the request, 200 findings max |
| `POST /run/discover` | ffuf    | Content discovery against the base target with `app/wordlist.txt`, or the SecLists API list when `deep`; wildcard hosts auto-calibrated away, 100 paths max |
| `POST /run/nikto`    | nikto   | Web-server misconfig / known-file scan over the base and extra targets (comma-separated); `-Pause 1/rate`, 200 findings max |
| `POST /run/whatweb`  | whatweb | Technology fingerprint of the base and extra targets; single-threaded, `--wait 1/rate` |
| `POST /run/crawl`    | katana  | JS-aware crawl (depth 2, same FQDN only) of the base and extra targets; `-rl` from the request, 100 paths max |
| `POST /run/params`   | arjun   | Hidden query-parameter discovery against the base target; `--rate-limit` from the request, 100 params max |
| `GET /health`        | —       | Reports which of the six tools are present in the image |

Every `POST /run/*` takes the same body: `target`, `timeout_seconds` (wall
clock), `rate_limit`, and optionally `deep` (discovery only) and
`extra_targets` (scanner passes only — nuclei, nikto, whatweb, katana — at
most 25).

## Running

```bash
docker compose --profile kali up kali        # or: make up-kali
```

Then set in `.env` and run scans with `kali: true`:

```
KALI_BASE_URL=http://localhost:8091
KALI_API_KEY=changeme
```

## Safety posture

- Runs **outside** the engine's 500-request budget, like ZAP — bounded instead
  by per-request rate limits and wall-clock timeouts on both sides;
  cancellation is checked between passes only. The run's selected rate reaches
  nuclei, ffuf, Nikto, WhatWeb, katana, and Arjun; direct sidecar calls default
  to 10 requests/second. Hence the explicit per-run opt-in.
- No `shell=True`; targets are validated as http(s) URLs before reaching a CLI.
- Any failure (service down, tool missing, timeout) degrades gracefully: the
  worker emits `kali_skipped` (or `kali_partial` when only some passes failed)
  and the scan completes with engine findings.
- Optional `KALI_API_KEY`: when set, callers must send `X-API-Key`.

## Notes

- Packages come from the Kali rolling archive. If a build fails on a package
  name (Kali occasionally renames/archives), adjust the `apt-get install`
  list in the Dockerfile; the service 503s cleanly for a missing tool.
- katana is not in the Kali apt archive, so the Dockerfile builds it from
  source with a Go toolchain it purges again afterwards.
- Wordlist is `app/wordlist.txt` (342 API-oriented paths) — intentionally
  small so discovery stays bounded. `deep` discovery runs swap in SecLists'
  `Discovery/Web-Content/api/api-endpoints.txt` when the package is installed.
- This container must never be exposed publicly: it exists to scan targets
  you are authorized to test.
