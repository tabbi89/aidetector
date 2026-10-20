"""Isolated Cursor runtime for passive-monitoring explanations and briefings.

This module is intentionally a subprocess entrypoint.  It is not imported by
the FastAPI process, so the optional Cursor SDK cannot alter scan dependencies.

It writes one JSON object per line on stdout: ``{"event": {...}}`` for each step
while the agent works, then a final ``{"result": ...}``-shaped object. Events
name steps (tools called, a few safe arguments, token counts) and never carry
tool results, file contents or the model's reasoning text.
"""
from __future__ import annotations

import json
import os
import re
import sys
import tempfile
from collections.abc import Mapping
from datetime import UTC, datetime

_FENCE = re.compile(r"^```(?:json)?\s*|\s*```$")
# Denied as well as left out of the allowlist: deny wins in the SDK, so a
# change in default tools can never hand the agent a shell or file access.
_DENIED_TOOLS = ["shell", "edit", "read", "task", "webSearch"]
# Tool arguments safe to show in the activity log: locations, never contents.
_BRIEF_ARGS = ("owner", "repo", "path", "ref", "branch", "sha", "query", "q", "pattern")


def _mcp_servers() -> dict[str, dict[str, object]]:
    """Allow only configured HTTPS MCP endpoints; reject executable stdio."""
    raw = os.environ.get("CURSOR_MCP_SERVERS_JSON", "")
    if not raw:
        return {}
    try:
        config = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError("CURSOR_MCP_SERVERS_JSON is not valid JSON") from exc
    if not isinstance(config, Mapping):
        raise RuntimeError("Cursor MCP configuration must be an object")
    servers: dict[str, dict[str, object]] = {}
    for name, value in config.items():
        if not isinstance(name, str) or not isinstance(value, Mapping):
            continue
        if value.get("type", "http") not in {"http", "sse"}:
            continue
        url = value.get("url")
        if not isinstance(url, str) or not url.startswith("https://"):
            continue
        allowed = {"type", "url", "headers", "auth"}
        servers[name[:80]] = {key: value[key] for key in allowed if key in value}
    return servers


def _prompt(request: Mapping[str, object], has_github: bool) -> str:
    observation = request.get("observation", {})
    context = request.get("context", {})
    repository = context.get("repository") if isinstance(context, Mapping) else None
    method = observation.get("method") if isinstance(observation, Mapping) else None
    route = observation.get("route_family") if isinstance(observation, Mapping) else None
    lines = [
        "You are a passive infrastructure security analyst explaining one deterministic "
        "monitoring observation. It is a heuristic lead, not a confirmed vulnerability.",
        "Rules: use only the supplied value-free metrics and read-only tools. Do not modify "
        "anything, create branches, issues or pull requests, and do not recommend active "
        "testing against production.",
    ]
    if has_github and isinstance(repository, Mapping):
        lines.append(
            f"Repository: {repository.get('repository')} at ref {repository.get('ref')}, "
            "through the read-only GitHub MCP tools. Find where "
            f"{method} {route} is declared and handled, and whether the handler checks "
            "authentication and object ownership. Cite files and lines you actually read."
        )
        current = observation.get("current") if isinstance(observation, Mapping) else None
        locations = current.get("sensitive_locations") if isinstance(current, Mapping) else None
        if isinstance(locations, list) and locations:
            lines.append(
                "Request metadata involved (names only): "
                + ", ".join(str(location) for location in locations[:10])
                + "."
            )
        lines.append(
            "Work efficiently: search the code for the route's file name and those names "
            "first, read only the files that handle them, and stop after at most 15 tool calls."
        )
    lines += [
        'Reply with JSON only: {"summary": str, "code_refs": [{"path": str, "line": int | '
        'null, "note": str}], "remediation": str, "questions": [str]}.',
        "If `Context.sampling.method` is `newest_per_hour`, the observation's counts are "
        "within the newest events kept for each hour, not the full volume: say 'in the "
        "sample' and do not present them as totals.",
        f"Observation: {json.dumps(observation, sort_keys=True)}",
        f"Context: {json.dumps(context, sort_keys=True)}",
    ]
    return "\n\n".join(lines)


BRIEFING_SCHEMA = (
    '{"headline": str, "verdict": "act_now" | "review" | "all_clear" | "not_enough_data", '
    '"traffic_summary": str, '
    '"act_now": [{"title": str, "why": str, "action": str, "lead_type": str | null}], '
    '"review": [{"title": str, "why": str, "action": str, "lead_type": str | null}], '
    '"safe_to_ignore": [{"title": str, "why": str}], '
    '"earlier": [{"title": str, "why": str, "days": str, "lead_type": str | null}], '
    '"alerting": {"current_state": str, "will_alert_when": [str], "gaps": [str]}, '
    '"questions": [str]}'
)


def _briefing_prompt(request: Mapping[str, object]) -> str:
    evidence = request.get("evidence", {})
    return "\n\n".join([
        "You are a security analyst briefing the owner of a web API on what their passive "
        "monitoring shows about AI, bot and automated client traffic. The reader is not a "
        "WAF specialist: use plain language, name the bot or route involved, and quote the "
        "numbers you rely on.",
        "Answer three questions: (1) is there anything here worth caring about, and how "
        "dangerous is it; (2) when should they react, and what exactly should they do; "
        "(3) how does this monitor turn what it sees into an alert, and what would it not "
        "alert on in their current situation.",
        "Rules: use only the supplied evidence. The `rules` list is the exact behaviour of "
        "the detectors and `alerting` is exactly how alerts are raised; do not invent other "
        "thresholds or features. Every lead is heuristic — say what it suggests, never that "
        "a breach is confirmed. Rank by danger: payloads that reached the origin and "
        "identifier enumeration first, then impersonated crawlers, probing, AI surges, and "
        "bots on protected routes last. Verified search, monitoring and link-preview bots "
        "are normal. If the latest day is warming_up or there are no complete days, say "
        "what is still unknown. Never recommend active testing against production without "
        "authorization.",
        "How the evidence is laid out: `latest_day.open_leads` carries full evidence for "
        "what is open now, and `latest_day.suppressed_leads` names what the owner already "
        "marked as fine. `lead_history` is every distinct lead in the window with the days "
        "it appeared: use it to say what happened earlier, whether it is continuing or "
        "stopped, and to judge a lead that is no longer on the latest day. "
        "`load_balancer_days` is how the app answered each day (error shares, p99, worst "
        "hours) — use it to say whether errors and latency were normal, and to line up "
        "hours with leads as timing, never as attribution. Each crawler in `bots.crawlers` "
        "lists its busiest routes. `tls_clients` is the latest day only. If "
        "`evidence_trimmed` is not empty, say which parts were cut and that the briefing "
        "may miss detail there.",
        "`act_now` is for open leads that deserve action today; `review` for leads to check "
        "this week; `safe_to_ignore` for traffic that looks alarming but is normal here; "
        "`earlier` for leads from `lead_history` that are not on the latest day — say when "
        "they happened and whether later days saw them, and move one into `act_now` or "
        "`review` only "
        "if it still needs a decision. Put empty lists where nothing applies.",
        "Sampling: each complete day in `days`, and `latest_day`, carries `sampling`. "
        "`method: newest_per_hour` means only the newest `per_hour` WAF events of each UTC "
        "hour were kept — the tail of every hour, not a random sample — and `kept_share` is "
        "the kept events over the load balancer's request count. On such a day every count "
        "in leads, `lead_history`, `bots` and `tls_clients` is a count within the sample: "
        "write it as 'N in the sample', never as the client's or route's total, and take "
        "real volume from `load_balancer_days`. Absence in a sampled day is not evidence of "
        "stopping: a client or lead missing from a sampled day was 'not seen in the sample', "
        "not 'stopped'. Only a `method: every_event` day supports 'did not appear'.",
        "Bot names come from AWS Bot Control labels, and a request an earlier WAF rule "
        "blocked never receives one. A crawler's `blocked` count therefore omits requests "
        "that attack rules stopped: never call a crawler 'all allowed' when a lead or TLS "
        "client for the same traffic shows blocks.",
        f"Reply with JSON only: {BRIEFING_SCHEMA}.",
        f"Evidence: {json.dumps(evidence, sort_keys=True)}",
    ])


def _structured(text: str) -> dict[str, object] | None:
    try:
        value = json.loads(_FENCE.sub("", text.strip()))
    except (ValueError, RecursionError):
        return None
    return value if isinstance(value, dict) else None


_TOOL_NAME_KEYS = ("toolName", "tool_name", "name", "tool")
_SERVER_KEYS = ("providerIdentifier", "server", "serverName", "server_name", "provider")
_NESTED_ARG_KEYS = ("args", "arguments", "input", "params")
# Lines that only say the model is busy; consecutive ones collapse into one.
_BUSY = frozenset({"thinking…", "writing the answer…"})


def _brief(args: object) -> str:
    if not isinstance(args, Mapping):
        return ""
    return ", ".join(f"{key}={str(args[key])[:80]}" for key in _BRIEF_ARGS if key in args)[:240]


def _mapping(value: object) -> Mapping | None:
    if isinstance(value, Mapping):
        return value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except (ValueError, RecursionError):
            return None
        return parsed if isinstance(parsed, Mapping) else None
    return None


def _tool_label(name: str, args: object, *, with_args: bool) -> str:
    """``server.tool(path=…)`` for wrapped MCP calls; argument values are never shown
    beyond the location keys in ``_BRIEF_ARGS``, and unknown shapes list key names only."""
    fields = _mapping(args)
    if fields is None:
        return f"{name}()" if with_args else name
    wrapper = ""
    # Unwrap single-key envelopes such as {"mcpToolCall": {"args": {...}}}.
    for _ in range(3):
        if any(key in fields for key in (*_TOOL_NAME_KEYS, *_SERVER_KEYS)) or len(fields) != 1:
            break
        (key, value), = fields.items()
        inner = _mapping(value)
        if inner is None:
            break
        if key not in _NESTED_ARG_KEYS:
            wrapper = re.sub(r"ToolCall$", "", str(key))[:60]
        fields = inner
    tool = next((str(fields[k]) for k in _TOOL_NAME_KEYS if isinstance(fields.get(k), str)), "")
    server = next((str(fields[k]) for k in _SERVER_KEYS if isinstance(fields.get(k), str)), "")
    nested = next((m for k in _NESTED_ARG_KEYS if (m := _mapping(fields.get(k))) is not None), None)
    label = f"{server}.{tool}" if server and tool else tool or wrapper or name
    if not with_args:
        return label[:120]
    brief = _brief(nested if nested is not None else fields)
    if not brief and not tool:
        brief = "keys: " + ", ".join(sorted(str(key) for key in fields)[:8])
    return f"{label}({brief})"[:260]


def _describe(message: object) -> str | None:
    """One activity-log line for an SDK message, or None when it says nothing new."""
    kind = getattr(message, "type", "")
    if kind == "system":
        tools = ", ".join(str(tool) for tool in getattr(message, "tools", ()) or ()) or "none"
        return f"Agent started · tools offered: {tools}"
    if kind == "tool_call":
        name = str(getattr(message, "name", "tool"))
        status = str(getattr(message, "status", ""))
        args = getattr(message, "args", None)
        if status == "running":
            return f"→ {_tool_label(name, args, with_args=True)}"
        label = _tool_label(name, args, with_args=False)
        if status == "completed":
            return f"✓ {label} returned"
        return f"✗ {label} {status}".strip()
    if kind == "thinking":
        return "thinking…"
    if kind == "assistant":
        return "writing the answer…"
    if kind == "status":
        return f"status: {getattr(message, 'status', '')} {getattr(message, 'message', '')}".strip()
    if kind == "task":
        return f"task {getattr(message, 'status', '')}".strip()
    if kind == "usage":
        usage = getattr(message, "usage", None)
        return (
            f"tokens so far: {getattr(usage, 'input_tokens', 0)} in, "
            f"{getattr(usage, 'output_tokens', 0)} out"
        )
    return None


class _EventDescriber:
    """One log line per run event.

    Tool calls are named from interaction updates, which carry the call itself;
    the thinner SDK tool messages (a bare ``mcp``) are used only until the first
    such update arrives, so a call is not logged twice.
    """

    def __init__(self) -> None:
        self.tool_updates = False

    def __call__(self, event: object) -> str | None:
        update = getattr(event, "interaction_update", None)
        if update is not None:
            kind = getattr(update, "type", "")
            call = getattr(update, "tool_call", None)
            if kind == "tool-call-started":
                self.tool_updates = True
                return f"→ {_tool_label('tool', call, with_args=True)}"
            if kind == "tool-call-completed":
                self.tool_updates = True
                return f"✓ {_tool_label('tool', call, with_args=False)} returned"
            return None
        message = getattr(event, "sdk_message", None)
        if message is None or (self.tool_updates and getattr(message, "type", "") == "tool_call"):
            return None
        return _describe(message)


class _Log:
    """Writes activity events to stdout, dropping immediate repeats."""

    def __init__(self) -> None:
        self.last = ""

    def __call__(self, text: str | None) -> None:
        if not text or text == self.last or (text in _BUSY and self.last in _BUSY):
            return
        self.last = text
        event = {"t": datetime.now(UTC).isoformat(timespec="seconds"), "text": text[:300]}
        print(json.dumps({"event": event}), flush=True)


def _run(request: Mapping[str, object]) -> dict[str, object]:
    mode = request.get("mode")
    if mode == "monitoring_explain":
        prompt = _prompt(request, "github" in _mcp_servers())
    elif mode == "monitoring_briefing":
        prompt = _briefing_prompt(request)
    else:
        raise RuntimeError("unsupported monitoring agent mode")
    try:
        from cursor_sdk import Agent, AgentOptions, LocalAgentOptions
    except ImportError as exc:
        raise RuntimeError("cursor-sdk is not installed in the AI runtime") from exc

    log = _Log()
    servers = _mcp_servers()
    model = str(request.get("model") or "composer-2.5")
    log(f"Connecting to Cursor · model {model} · MCP servers: {', '.join(servers) or 'none'}")
    with tempfile.TemporaryDirectory(prefix="aidetector-monitoring-") as workspace:
        # The SDK launches its bridge with the *process* working directory as the
        # workspace (LocalAgentOptions.cwd does not change it), so move into the
        # empty directory before the first SDK call.
        os.chdir(workspace)
        try:
            options = AgentOptions(
                model=model,
                # MCP-only: no shell, file, edit, web or task tools are offered.
                tools=["mcp"],
                disallowed_tools=_DENIED_TOOLS,
                # No project, user or plugin settings: they could add servers or rules.
                local=LocalAgentOptions(cwd=workspace, setting_sources=[]),
                mcp_servers=servers,
            )
            with Agent.create(options) as agent:
                run = agent.send(prompt)
                describe = _EventDescriber()
                for event in run.events():
                    log(describe(event))
                result = run.wait()
        finally:
            os.chdir("/")
    status = getattr(result, "status", "finished")
    log(f"Run {status}")
    if status != "finished":
        raise RuntimeError(f"Cursor agent run ended as {status}")
    usage = getattr(result, "usage", None)
    usages = []
    if usage is not None:
        usages.append(
            {
                "model": model,
                "tokens_in": int(getattr(usage, "input_tokens", 0)),
                "tokens_out": int(getattr(usage, "output_tokens", 0)),
            }
        )
    text = str(getattr(result, "result", "") or "")
    return {"model": model, "text": text, "structured": _structured(text), "usages": usages}


if __name__ == "__main__":
    try:
        print(json.dumps(_run(json.load(sys.stdin))), flush=True)
    except Exception as exc:  # noqa: BLE001 — subprocess returns a safe error
        print(f"{type(exc).__name__}: {exc}"[:500], file=sys.stderr)
        raise SystemExit(1) from exc
