"""Offline potential-secret detection over existing response/spec samples.

This check spends no HTTP requests of its own. It reuses the memoised header
sweep bodies and separately scans the stored uploaded OpenAPI text. Matches are
heuristic: no candidate is verified online, and authentication endpoints are
excluded because returning a freshly issued token there is expected behavior.

Only detector name and a bounded structural location reach findings. Candidate
values, surrounding text, hashes and raw detector objects never leave the
isolated worker.
"""
from __future__ import annotations

import json
import re
from typing import Any

import yaml

from app.domain.enums import Confidence, Severity
from app.engine.base import EngineFinding, HeaderSnapshot, ScanContext
from app.engine.checks.misconfig import sweep_headers
from app.engine.secret_scan import (
    MAX_MATCHES,
    ScanUnit,
    SecretMatch,
    scan_offline_truncated,
)

MAX_RESPONSE_UNITS = 160
MAX_SPEC_UNITS = 96
MAX_DEPTH = 8
MAX_CHILDREN = 64

_TOKEN_ROUTE = re.compile(
    r"(?:^|[/_.-])(auth|authenticate|authentication|authorize|login|signin|token|oauth|refresh|session)(?:$|[/_.-])",
    re.IGNORECASE,
)
_EXAMPLE_LINE = re.compile(
    r"^\s*(?:example|examples)\s*:|[\"'](?:example|examples)[\"']\s*:",
    re.IGNORECASE,
)


def _line_units(text: str, source_id: int, prefix: str, cap: int) -> list[ScanUnit]:
    units: list[ScanUnit] = []
    for number, line in enumerate(text.splitlines() or [text], start=1):
        if not line.strip():
            continue
        units.append(ScanUnit(source_id, f"{prefix}/line-{number}", line))
        if len(units) >= cap:
            break
    return units


def _structured_units(
    payload: Any,
    source_id: int,
    prefix: str,
    cap: int,
    *,
    skip_examples: bool = False,
) -> list[ScanUnit]:
    units: list[ScanUnit] = []

    def walk(value: Any, location: str, depth: int) -> None:
        if len(units) >= cap or depth > MAX_DEPTH:
            return
        if isinstance(value, str):
            for number, line in enumerate(value.splitlines() or [value], start=1):
                units.append(
                    ScanUnit(
                        source_id,
                        f"{location}/text-line-{number}",
                        json.dumps(line),
                    )
                )
                if len(units) >= cap:
                    return
        elif isinstance(value, dict):
            # Keys are used only to create a deterministic ordinal and are
            # never copied into a location or finding.
            keys = sorted(value, key=lambda item: str(item))[:MAX_CHILDREN]
            for ordinal, key in enumerate(keys):
                if skip_examples and str(key).lower() in {"example", "examples"}:
                    continue
                walk(value[key], f"{location}/object[{ordinal}]", depth + 1)
        elif isinstance(value, list):
            for item in value[:MAX_CHILDREN]:
                walk(item, f"{location}/array[]", depth + 1)

    walk(payload, prefix, 0)
    return units


def _response_units(snapshot: HeaderSnapshot, source_id: int) -> list[ScanUnit]:
    body = snapshot.body.strip()
    if not body:
        return []
    try:
        return _structured_units(
            json.loads(body), source_id, "json", MAX_RESPONSE_UNITS
        )
    except (ValueError, RecursionError):
        return _line_units(body, source_id, "text", MAX_RESPONSE_UNITS)


def _spec_units(spec_text: str) -> list[ScanUnit]:
    try:
        try:
            payload = json.loads(spec_text)
        except json.JSONDecodeError:
            payload = yaml.safe_load(spec_text)
        # Walking values structurally avoids one ``example`` property in a
        # minified document suppressing every unrelated scalar on that line.
        return _structured_units(
            payload,
            -1,
            "spec",
            MAX_SPEC_UNITS,
            skip_examples=True,
        )
    except (ValueError, yaml.YAMLError, RecursionError):
        units = _line_units(spec_text, -1, "spec", MAX_SPEC_UNITS * 2)
        return [
            unit for unit in units if not _EXAMPLE_LINE.search(unit.text)
        ][:MAX_SPEC_UNITS]


def _fair_units(groups: list[list[ScanUnit]], cap: int) -> list[ScanUnit]:
    """Round-robin bounded units so one large response cannot starve the rest."""
    selected: list[ScanUnit] = []
    offset = 0
    while len(selected) < cap:
        added = False
        for group in groups:
            if offset < len(group):
                selected.append(group[offset])
                added = True
                if len(selected) >= cap:
                    break
        if not added:
            break
        offset += 1
    return selected


def _fair_matches(groups: list[list[SecretMatch]], cap: int) -> list[SecretMatch]:
    """Keep the final bound while giving response and spec matches a share."""
    selected: list[SecretMatch] = []
    offset = 0
    while len(selected) < cap:
        added = False
        for group in groups:
            if offset < len(group):
                selected.append(group[offset])
                added = True
                if len(selected) >= cap:
                    break
        if not added:
            break
        offset += 1
    return selected


class PotentialSecretsCheck:
    key = "potential_secrets"

    def run(self, ctx: ScanContext) -> list[EngineFinding]:
        snapshots = sweep_headers(ctx)
        searchable: list[HeaderSnapshot] = []
        response_groups: list[list[ScanUnit]] = []
        for snapshot in snapshots:
            route = self._route(ctx, snapshot)
            if _TOKEN_ROUTE.search(route):
                continue
            source_id = len(searchable)
            response_units = _response_units(snapshot, source_id)
            if not response_units:
                continue
            searchable.append(snapshot)
            response_groups.append(response_units)

        try:
            response_matches, resp_truncated = scan_offline_truncated(
                _fair_units(response_groups, MAX_RESPONSE_UNITS)
            )
            match_groups = [response_matches]
            truncated = resp_truncated
            if ctx.spec_text:
                # Separate pass: response volume can never hide a credential in
                # the uploaded artifact (or vice versa).
                spec_matches, spec_truncated = scan_offline_truncated(
                    _spec_units(ctx.spec_text)
                )
                match_groups.append(spec_matches)
                truncated = truncated or spec_truncated
            matches = _fair_matches(match_groups, MAX_MATCHES)
        except Exception:  # noqa: BLE001 - optional detector failure is non-fatal
            return []

        findings: list[EngineFinding] = []
        seen: set[tuple[str, str, str, str]] = set()
        for match in matches:
            finding = self._finding(ctx, searchable, match, truncated=truncated)
            if finding is None:
                continue
            evidence = finding.evidence
            key = (
                str(evidence.get("source")),
                str(evidence.get("route")),
                str(evidence.get("detector")),
                str(evidence.get("location")),
            )
            if key not in seen:
                seen.add(key)
                findings.append(finding)
        return findings

    @staticmethod
    def _route(ctx: ScanContext, snapshot: HeaderSnapshot) -> str:
        templates = {op.id: op.path for op in ctx.operations if op.id}
        route = templates.get(snapshot.operation_id or "", snapshot.path)
        return route.split("?", 1)[0].split("#", 1)[0][:300]

    def _finding(
        self,
        ctx: ScanContext,
        snapshots: list[HeaderSnapshot],
        match: SecretMatch,
        *,
        truncated: bool = False,
    ) -> EngineFinding | None:
        evidence: dict[str, Any] = {
            "detector": match.detector,
            "location": match.location,
        }
        if truncated:
            # A byte/unit cap cut the input short: the scan may be incomplete,
            # not clean.
            evidence["truncated"] = True
        if match.source_id == -1:
            evidence["source"] = "uploaded_spec"
            scope = "the uploaded API specification"
            operation_id = None
        elif 0 <= match.source_id < len(snapshots):
            snapshot = snapshots[match.source_id]
            route = self._route(ctx, snapshot)
            evidence.update(
                {
                    "source": "response",
                    "method": snapshot.method,
                    "route": route,
                }
            )
            scope = f"the response from {snapshot.method} {route}"
            operation_id = snapshot.operation_id
        else:
            return None

        return EngineFinding(
            check=self.key,
            confidence=Confidence.heuristic,
            owasp_id="API3:2023",
            severity=Severity.medium,
            title=f"Potential secret detected in {scope}"[:255],
            description=(
                f"The offline {match.detector} rule found a potential credential at "
                f"{match.location} in {scope}. This is a heuristic match, not proof that "
                "the value is live or exposed to the wrong caller. The candidate, its "
                "surrounding text and any derived hash were discarded."
            ),
            evidence=evidence,
            operation_id=operation_id,
        )
