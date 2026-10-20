#!/usr/bin/env bash
# qodana-scan.sh — run Qodana over the three aidetector deployables.
#
# One scan per deployable, because Qodana is per-language and this is a
# Python + TypeScript + Go monorepo:
#
#   web  apps/web        jetbrains/qodana-js
#   api  services/api    jetbrains/qodana-python
#   cli  cli             jetbrains/qodana-go
#
# Token: read from $QODANA_TOKEN, else the macOS keychain item "qodana-token"
# (the same shape scripts/flash uses for deepseek-api). The value is never
# written to a file and never echoed. With no token the script prints one line
# and exits 0, so the SessionEnd hook that calls it stays quiet until you have
# provisioned one.
#
#   scripts/qodana-scan.sh                 # all three targets
#   scripts/qodana-scan.sh web api         # a subset
#   scripts/qodana-scan.sh --dry-run       # print the commands, run nothing
#
# Reports land in .qodana/results/<target>/ (gitignored).
#
# Exit codes: 0 = every requested scan ran, 2 = usage or tooling error,
# 3 = a scan failed to run. Findings are reported, not fatal: this runs from a
# SessionEnd hook, which cannot block the session anyway.
#
# UNVERIFIED FLAG SURFACE: the qodana CLI flags below have not been checked
# against `qodana scan --help` on this machine, because the shell is currently
# unusable (see the session notes). Run `--dry-run` first and correct the
# invocation in scan_target() if your CLI version names them differently.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$ROOT/.qodana/results"

die() { printf 'qodana-scan: %s\n' "$*" >&2; exit 2; }

dry_run=0
targets=()
for arg in "$@"; do
  case "$arg" in
    --dry-run) dry_run=1 ;;
    -h|--help) sed -n '2,32p' "${BASH_SOURCE[0]}"; exit 0 ;;
    web|api|cli) targets+=("$arg") ;;
    *) die "unknown argument '$arg' (expected: web|api|cli|--dry-run)" ;;
  esac
done
[[ ${#targets[@]} -gt 0 ]] || targets=(web api cli)

token="${QODANA_TOKEN:-}"
if [[ -z "$token" ]] && command -v security >/dev/null 2>&1; then
  token="$(security find-generic-password -s qodana-token -w 2>/dev/null || true)"
fi
if [[ -z "$token" ]]; then
  printf 'qodana-scan: no QODANA_TOKEN (or keychain item qodana-token) — skipping.\n'
  exit 0
fi

if [[ $dry_run -eq 0 ]]; then
  command -v qodana >/dev/null || die "qodana CLI not found (npm i -g @jetbrains/qodana-cli)"
  command -v docker >/dev/null || die "docker not found — the qodana CLI runs the linter in a container"
fi

scan_target() {  # key label image dir
  local key="$1" label="$2" image="$3" dir="$4" out="$OUT/$key"
  printf 'qodana-scan: %s → %s\n' "$label" "$out"
  if [[ $dry_run -eq 1 ]]; then
    printf '  (cd %q && qodana scan --image %q --results-dir %q)\n' "$dir" "$image" "$out"
    return 0
  fi
  mkdir -p "$out"
  # cwd is the target so the scan covers that deployable alone; the image picks
  # the language linter. QODANA_TOKEN is exported for this call only.
  ( cd "$dir" && QODANA_TOKEN="$token" qodana scan --image "$image" --results-dir "$out" )
}

rc=0
for t in "${targets[@]}"; do
  case "$t" in
    web) scan_target web "frontend (Next.js)" jetbrains/qodana-js    "$ROOT/apps/web"     || rc=3 ;;
    api) scan_target api "backend (FastAPI)"  jetbrains/qodana-python "$ROOT/services/api" || rc=3 ;;
    cli) scan_target cli "CLI (Go)"           jetbrains/qodana-go     "$ROOT/cli"          || rc=3 ;;
  esac
done

if [[ $dry_run -eq 1 ]]; then
  printf 'qodana-scan: dry run, nothing executed.\n'
elif [[ $rc -eq 0 ]]; then
  printf 'qodana-scan: all requested scans finished; reports in %s\n' "$OUT"
fi
exit "$rc"
