"""Provider-neutral seam for optional infrastructure-monitoring explanations."""
from __future__ import annotations

import contextlib
import json
import logging
import os
import queue
import signal
import subprocess
import tempfile
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from app.ai.subprocess_env import inherited_env
from app.ai.types import Usage
from app.core.config import settings

log = logging.getLogger(__name__)
_SERVICE_DIR = Path(__file__).resolve().parents[2]
_AGENT_SCRIPT = _SERVICE_DIR / "ai_runtime" / "monitoring_agent.py"


@dataclass(frozen=True)
class ProviderResponse:
    """A bounded provider response plus billing metadata when available."""

    provider: str
    model: str
    text: str
    usages: tuple[Usage, ...] = ()
    structured: dict[str, Any] | None = None


class MonitoringAIProvider(Protocol):
    provider_id: str

    def explain(
        self,
        observation: Mapping[str, object],
        *,
        context: Mapping[str, object] | None = None,
        github_token: str | None = None,
        on_event: Callable[[Mapping[str, object]], None] | None = None,
    ) -> ProviderResponse:
        """Explain an already-created observation; never create a finding.

        ``on_event`` receives value-free progress lines while the provider works.
        """

    def brief(
        self,
        evidence: Mapping[str, object],
        *,
        on_event: Callable[[Mapping[str, object]], None] | None = None,
    ) -> ProviderResponse:
        """Brief a person on a monitor's traffic, leads and alerting; never create one."""


class ProviderUnavailable(RuntimeError):
    """The optional provider is not configured or failed safely.

    ``code`` is a fixed identifier that is safe to persist and show; the message
    is for logs.
    """

    def __init__(self, message: str, code: str = "provider_unavailable"):
        super().__init__(message)
        self.code = code


class NullMonitoringAIProvider:
    provider_id = "none"

    def explain(
        self,
        observation: Mapping[str, object],
        *,
        context: Mapping[str, object] | None = None,
        github_token: str | None = None,
        on_event: Callable[[Mapping[str, object]], None] | None = None,
    ) -> ProviderResponse:
        raise ProviderUnavailable("monitoring AI provider is disabled", "disabled")

    def brief(
        self,
        evidence: Mapping[str, object],
        *,
        on_event: Callable[[Mapping[str, object]], None] | None = None,
    ) -> ProviderResponse:
        raise ProviderUnavailable("monitoring AI provider is disabled", "disabled")


def github_mcp_servers(repository: object, token: str | None) -> dict[str, dict[str, object]]:
    """GitHub's hosted MCP server, read-only, for the monitor's own repository.

    The monitor's fine-grained token is the security boundary: its repository
    scope and read-only permission decide what the agent can reach. The
    read-only header and the single toolset narrow the tools it is offered;
    they are not what stops a write.
    """
    if not repository:
        return {}
    if (
        not isinstance(repository, str)
        or not token
        or not settings.monitoring_github_mcp_url.startswith("https://")
    ):
        raise ProviderUnavailable("GitHub MCP access is not configured", "github_not_configured")
    return {
        "github": {
            "type": "http",
            "url": settings.monitoring_github_mcp_url,
            "headers": {
                "Authorization": f"Bearer {token}",
                "X-MCP-Readonly": "true",
                "X-MCP-Toolsets": "repos",
            },
        }
    }


def _extra_mcp_servers() -> dict[str, Any]:
    if not settings.cursor_mcp_servers_json:
        return {}
    try:
        extra = json.loads(settings.cursor_mcp_servers_json)
    except json.JSONDecodeError:
        raise ProviderUnavailable(
            "CURSOR_MCP_SERVERS_JSON is not valid JSON", "invalid_configuration"
        ) from None
    if not isinstance(extra, dict):
        raise ProviderUnavailable(
            "CURSOR_MCP_SERVERS_JSON must be an object", "invalid_configuration"
        )
    extra.pop("github", None)  # the deployment-scoped GitHub server is authoritative
    return extra


class CursorMonitoringProvider:
    """Cursor adapter executed in the isolated AI runtime.

    The main API process never imports ``cursor_sdk``. The subprocess receives
    only sanitized observations and context, uses an empty local workspace, and
    is offered MCP tools only: GitHub read-only for the monitor's repository,
    plus any operator-configured HTTPS servers. The deterministic detector stays
    authoritative.
    """

    provider_id = "cursor"

    def __init__(self, model: str | None = None) -> None:
        self.model = model or settings.cursor_model
        self.python = Path(settings.ai_python) if settings.ai_python else _default_ai_python()

    def explain(
        self,
        observation: Mapping[str, object],
        *,
        context: Mapping[str, object] | None = None,
        github_token: str | None = None,
        on_event: Callable[[Mapping[str, object]], None] | None = None,
    ) -> ProviderResponse:
        if not settings.cursor_api_key:
            raise ProviderUnavailable("CURSOR_API_KEY is not configured", "not_configured")
        repository = (context or {}).get("repository")
        repo_name = repository.get("repository") if isinstance(repository, Mapping) else None
        # The token goes only into the MCP server headers, never the request payload.
        servers = {**_extra_mcp_servers(), **github_mcp_servers(repo_name, github_token)}
        # on_event is passed to _run_agent below; the token never reaches an event.
        request = {
            "mode": "monitoring_explain",
            "model": self.model,
            "observation": _json_safe(observation),
            "context": _json_safe(context or {}),
        }
        return self._invoke(request, servers, on_event, secret=github_token)

    def brief(
        self,
        evidence: Mapping[str, object],
        *,
        on_event: Callable[[Mapping[str, object]], None] | None = None,
    ) -> ProviderResponse:
        """A briefing reads only the supplied aggregates, so no MCP server is offered."""
        if not settings.cursor_api_key:
            raise ProviderUnavailable("CURSOR_API_KEY is not configured", "not_configured")
        request = {
            "mode": "monitoring_briefing",
            "model": self.model,
            "evidence": _json_safe(evidence),
        }
        return self._invoke(request, {}, on_event)

    def _invoke(
        self,
        request: Mapping[str, object],
        servers: Mapping[str, object],
        on_event: Callable[[Mapping[str, object]], None] | None,
        *,
        secret: str | None = None,
    ) -> ProviderResponse:
        if not self.python.exists() or not _AGENT_SCRIPT.exists():
            raise ProviderUnavailable("AI runtime is not installed", "runtime_missing")
        # Never the worker's own environment: see app/ai/subprocess_env.py.
        env = inherited_env()
        env |= {
            "CURSOR_API_KEY": settings.cursor_api_key,
            "CURSOR_MCP_SERVERS_JSON": json.dumps(servers),
        }
        try:
            returncode, stdout, stderr = _run_agent(
                [str(self.python), str(_AGENT_SCRIPT)],
                json.dumps(request),
                env,
                settings.monitoring_ai_timeout_seconds,
                on_event,
            )
        except subprocess.TimeoutExpired as exc:
            log.warning("Cursor agent timed out after %ss", settings.monitoring_ai_timeout_seconds)
            raise ProviderUnavailable("Cursor agent timed out", "timeout") from exc
        if returncode != 0:
            reason = stderr.strip()[-300:]
            if secret:
                reason = reason.replace(secret, "***")
            log.warning("Cursor agent exited %s: %s", returncode, reason)
            raise ProviderUnavailable(f"Cursor agent exited {returncode}", "agent_failed")
        try:
            result: dict = json.loads(stdout)
        except json.JSONDecodeError as exc:
            raise ProviderUnavailable("Cursor agent output is not JSON", "agent_failed") from exc
        structured = result.get("structured")
        return ProviderResponse(
            provider=self.provider_id,
            model=str(result.get("model") or self.model),
            text=str(result.get("text") or ""),
            usages=tuple(_usages(result)),
            structured=structured if isinstance(structured, dict) else None,
        )


def _run_agent(
    args: list[str],
    payload: str,
    env: dict[str, str],
    timeout: float,
    on_event: Callable[[Mapping[str, object]], None] | None = None,
) -> tuple[int, str, str]:
    """Run the agent, relaying its progress events; returns (code, result line, stderr).

    The agent writes ``{"event": ...}`` lines while it works and its result last.
    It runs in its own session so a timeout ends the whole process tree: the
    Cursor SDK starts a Node bridge that inherits the agent's pipes, and killing
    only the direct child would leave the reader waiting on them forever.
    """
    proc = subprocess.Popen(
        args,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
        cwd=tempfile.gettempdir(),
        start_new_session=True,
    )
    assert proc.stdin is not None and proc.stdout is not None and proc.stderr is not None
    stdout, stderr_pipe = proc.stdout, proc.stderr
    lines: queue.Queue[str | None] = queue.Queue()
    errors: list[str] = []

    def pump_stdout() -> None:
        for line in stdout:
            lines.put(line)
        lines.put(None)

    def pump_stderr() -> None:
        errors.append(stderr_pipe.read())

    readers = [
        threading.Thread(target=pump_stdout, daemon=True),
        threading.Thread(target=pump_stderr, daemon=True),
    ]
    for reader in readers:
        reader.start()
    deadline = time.monotonic() + timeout
    result = ""
    try:
        with contextlib.suppress(BrokenPipeError):
            proc.stdin.write(payload)
            proc.stdin.close()
        while True:
            try:
                line = lines.get(timeout=max(0.0, deadline - time.monotonic()))
            except queue.Empty:
                raise subprocess.TimeoutExpired(args, timeout) from None
            if line is None:
                break
            try:
                message = json.loads(line)
            except ValueError:
                continue
            if isinstance(message, dict) and isinstance(message.get("event"), dict):
                if on_event is not None:
                    with contextlib.suppress(Exception):  # a log sink never fails the run
                        on_event(message["event"])
            elif line.strip():
                result = line
        proc.wait(timeout=max(1.0, deadline - time.monotonic()))
    finally:
        # A timeout, or a bridge outliving a finished agent: end the whole group.
        with contextlib.suppress(ProcessLookupError, PermissionError):
            os.killpg(proc.pid, signal.SIGKILL)
        proc.wait()
        for reader in readers:
            reader.join(timeout=2)
    return proc.returncode, result, "".join(errors)


def build_monitoring_provider() -> MonitoringAIProvider:
    """Build the configured optional provider; default is deterministic-only."""
    if settings.monitoring_ai_provider == "cursor":
        return CursorMonitoringProvider()
    return NullMonitoringAIProvider()


def _default_ai_python() -> Path:
    return _SERVICE_DIR / ".venv-ai" / "bin" / "python"


def _json_safe(value: object) -> object:
    return json.loads(json.dumps(value, default=str))


def _usages(result: Mapping[str, object]) -> list[Usage]:
    raw = result.get("usages", [])
    if not isinstance(raw, list):
        return []
    return [
        Usage(
            model=str(item.get("model", "cursor")),
            phase="monitoring",
            tokens_in=int(item.get("tokens_in", 0)),
            tokens_out=int(item.get("tokens_out", 0)),
        )
        for item in raw
        if isinstance(item, Mapping)
    ]
