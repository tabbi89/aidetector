# G4 TLS scanner benchmark: SSLyze versus testssl.sh

Date: 2026-09-06. Decision: **do not adopt SSLyze in the scan pipeline**.
Retain testssl.sh as the optional deep-TLS adjunct and the built-in bounded TLS
check as the default. The comparison is reproducible with
[`services/api/benchmarks/tls_scanners.py`](../services/api/benchmarks/tls_scanners.py).

## Method

The benchmark used [SSLyze 6.3.1](https://github.com/nabla-c0d3/sslyze/releases/tag/6.3.1)
and [testssl.sh 3.2.4](https://github.com/testssl/testssl.sh/releases/tag/v3.2.4)
on Apple Silicon with Python 3.13.5. Each run scanned a fresh loopback-only
Python TLS/HTTP fixture:

- `modern`: TLS 1.3 only, three standard TLS 1.3 cipher suites;
- `legacy`: TLS 1.0–1.2 with only RSA `AES128-SHA` and no forward secrecy.

Both fixtures used the same 2048-bit, SHA-256, localhost self-signed certificate
valid for two days. The harness counts accepted TCP connections and records wall
time, child CPU, peak RSS and JSON size. Scanners ran one target at a time with a
240-second outer timeout. SSLyze used `--slow_connection`; testssl used batch
warnings, a fixed loopback IP, `--nodns none`, and no `--phone-out`. SSLyze's
trust-store updater was not invoked. Thus neither scanner needed auxiliary
network access.

## Results

| Tool / fixture | Wall | Connections | Child CPU | Peak RSS | JSON |
| --- | ---: | ---: | ---: | ---: | ---: |
| SSLyze / modern | 0.399 s | 579 | 0.250 s | 65.9 MiB | 182,002 B |
| SSLyze / legacy | 0.396 s | 568 | 0.259 s | 66.4 MiB | 177,816 B |
| testssl / modern | 112.343 s | 117 | 21.660 s | 19.7 MiB | 42,845 B |
| testssl / legacy | 119.356 s | 148 | 16.239 s | 23.4 MiB | 43,749 B |

SSLyze was dramatically faster, but its reduced-concurrency mode still used
about four to five times as many connections. That is the wrong trade for an
active scanner whose adjunct phase must remain bounded and courteous. SSLyze's
CLI exposes a concurrency reduction, not a total connection ceiling; the
benchmark observed more connections than the engine's entire 500-request main
budget for one TLS target.

## Finding comparison

Both tools identified the certificate trust/validity problem and distinguished
the TLS 1.3-only fixture from the legacy protocol/RSA-CBC fixture. Both tested
Heartbleed, CCS injection, renegotiation, compression and ROBOT-class behavior.
SSLyze produced richer structured cipher rejection and curve/compliance data;
testssl additionally reported forward-secrecy/BEAST posture, certificate
revocation metadata and HTTP security-header observations.

No unique, confirmed actionable weakness from SSLyze remained after accounting
for the built-in TLS check and testssl. One important disagreement also prevents
crediting apparent unique results without adjudication: testssl labelled the
legacy fixture ROBOT-vulnerable while SSLyze returned `NOT_VULNERABLE_NO_ORACLE`.
The benchmark records that as inconclusive, not as a verified advantage for
either tool.

The current testssl mapper exposed two defects during the comparison and they
are fixed with G4: it now uses the documented `--jsonfile` option, and retains
`CRITICAL` results instead of accidentally dropping them. Existing testssl
finding identities are unchanged; newly retained critical entries appear as new
findings once, with no fixed-and-new churn for previously stored entries.

## Deployment and adoption decision

SSLyze installed successfully on the benchmark host, but added a compiled
`nassl` wheel and grew an isolated environment to 52 MiB versus 15 MiB for the
testssl checkout. Its cryptography range is currently compatible with the API
service, but it creates another compiled dependency and platform-wheel
constraint in the worker image.

Do not add an SSLyze dependency, run flag, mapper or second TLS adjunct now.
The speed advantage does not offset the connection volume, duplicate actionable
coverage and unresolved cross-tool disagreement. Reconsider only if SSLyze gains
an enforceable total-connection cap or a future controlled fixture demonstrates
a unique finding important enough to justify a separately reviewed default-off
pass. Any later proposal must also bound retries, concurrency and elapsed time,
disable auxiliary network access, and define deduplication against both `tls_config`
and `testssl` before it can be adopted.
