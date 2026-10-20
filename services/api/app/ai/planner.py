"""AI planner — invokes ``ai_runtime/plan_agent.py`` as a subprocess.

``settings.planner_provider`` picks who does the planner's job:

- ``deepseek`` (default) — every mode is one direct DeepSeek completion. The
  agent script then needs only ``httpx``, so it runs under the configured AI
  python when present and the service's own interpreter otherwise: no Claude
  Agent SDK, ``claude`` CLI or ``.venv-ai`` required.
- ``anthropic`` — plan/adjudicate/adaptive/propose_resource run on the Claude
  Agent SDK, whose transitive deps (mcp/starlette) conflict with FastAPI, so it
  lives in a separate venv (``.venv-ai``) driven over stdin/stdout.

Anything missing raises PlannerUnavailable and the caller degrades gracefully.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from app.ai.limits import runtime_limits
from app.ai.subprocess_env import inherited_env
from app.ai.types import Usage
from app.core.config import settings

_SERVICE_DIR = Path(__file__).resolve().parents[2]  # services/api
_AGENT_SCRIPT = _SERVICE_DIR / "ai_runtime" / "plan_agent.py"
#: Operator settings the `claude` CLI reads (its config dir, an API gateway).
#: They configure the CLI rather than hold a service secret, so the anthropic
#: provider passes them through when the worker sets them.
_CLAUDE_CLI_ENV = ("CLAUDE_CONFIG_DIR", "ANTHROPIC_BASE_URL")


def _default_ai_python() -> Path:
    return _SERVICE_DIR / ".venv-ai" / "bin" / "python"


class PlannerUnavailable(RuntimeError):
    pass


class PlannerNotStarted(PlannerUnavailable):
    """The call failed before anything reached a provider, so it cost nothing.

    Every other ``PlannerUnavailable`` (a timeout, a runtime that crashed after
    its completion, unreadable output) may have been paid for.
    """


class OpusPlanner:
    """The planner seam. The name predates ``planner_provider``; it is no longer
    necessarily Opus — see the module docstring."""

    def __init__(self, model: str | None = None) -> None:
        self.provider = settings.planner_provider
        self.model = model or settings.effective_planner_model()
        configured = Path(settings.ai_python) if settings.ai_python else _default_ai_python()
        # DeepSeek mode needs only httpx, which the service already has: fall
        # back to this interpreter rather than requiring the Agent SDK venv.
        self.python = (
            configured
            if self.provider == "anthropic" or configured.exists()
            else Path(sys.executable)
        )

    def adjudicate(
        self, findings_payload: list[dict]
    ) -> tuple[list[dict], list[Usage]]:
        out = self._invoke({"mode": "adjudicate", "findings": findings_payload})
        return out.get("verdicts", []), self._usages(out)

    def plan(
        self, operations_payload: list[dict]
    ) -> tuple[list[dict], list[Usage]]:
        """Prioritise operations before the engine runs. Returns
        ([{operation_id, priority, rationale}], usages)."""
        out = self._invoke({"mode": "plan", "operations": operations_payload})
        return out.get("plan", []), self._usages(out)

    def answer(
        self, findings_payload: list[dict], question: str
    ) -> tuple[str, list[Usage]]:
        """Answer a natural-language question about the findings."""
        out = self._invoke(
            {"mode": "qa", "findings": findings_payload, "question": question}
        )
        return str(out.get("answer", "")), self._usages(out)

    def generate_payloads(
        self, families_payload: list[dict]
    ) -> tuple[dict, list[Usage]]:
        """Propose extra reflection-payload variants per family.

        Returns ({family: [raw string, ...]}, usages). The worker re-validates
        every string before it is used, so a bad or unavailable runtime returns
        {} here and the engine falls back to its curated + vendored corpus.
        """
        out = self._invoke({"mode": "payloads", "families": families_payload})
        payloads = out.get("payloads", {})
        return (payloads if isinstance(payloads, dict) else {}), self._usages(out)

    def review_security(self, payload: dict) -> tuple[dict, list[Usage]]:
        """Direct DeepSeek static design review with bounded structural context."""
        out = self._invoke({"mode": "security_review", "payload": payload})
        return out.get("review", {}), self._usages(out)

    def refine(self, payload: dict) -> tuple[dict, list[Usage]]:
        """Suggest the next bounded payload variant for adaptive validation.

        Returns (proposal, usages): the call is paid for even when the proposal
        is rejected, so the caller must meter what the provider reported.
        """
        out = self._invoke({"mode": "adaptive", "payload": payload})
        proposal = out.get("proposal", {})
        return (
            proposal if isinstance(proposal, dict) else {},
            self._usages(out),
        )

    def propose_resource(self, payload: dict) -> tuple[dict, list[Usage]]:
        """Propose a spec-valid create body for a resource the heuristic seed

        could not create (J1). The worker validates it against the declared
        schema before sending; a bad or unavailable runtime returns {} here and
        the fallback degrades to the deterministic seed's failure.
        """
        out = self._invoke({"mode": "propose_resource", "payload": payload})
        proposal = out.get("proposal", {})
        body = proposal if isinstance(proposal, dict) else {}
        return body, self._usages(out)

    @staticmethod
    def _usages(out: dict) -> list[Usage]:
        return [
            Usage(
                model=u["model"],
                phase=u["phase"],
                tokens_in=int(u.get("tokens_in", 0)),
                tokens_out=int(u.get("tokens_out", 0)),
                cache_read_tokens=int(u.get("cache_read_tokens", 0) or 0),
                cache_write_tokens=int(u.get("cache_write_tokens", 0) or 0),
            )
            for u in out.get("usages", [])
        ]

    def _invoke(self, extra: dict) -> dict:
        if not self.python.exists():
            raise PlannerNotStarted(f"AI runtime python not found: {self.python}")
        if not _AGENT_SCRIPT.exists():
            raise PlannerNotStarted(f"agent script not found: {_AGENT_SCRIPT}")
        if self.provider == "deepseek" and not settings.deepseek_api_key:
            raise PlannerNotStarted("DEEPSEEK_API_KEY is not set")

        cfg = {
            "provider": self.provider,
            "planner_model": self.model,
            "executor_model": settings.executor_model,
            "deepseek_base_url": settings.deepseek_base_url,
            # The ceilings the budget reservation priced this call at
            # (app/ai/limits.py); the runtime is held to them.
            **runtime_limits(str(extra.get("mode", "adjudicate"))),
            **extra,
        }
        # An allowlist, never a copy of the worker's environment: the agent
        # sends data to an external model and must not hold the VAULT_KEY,
        # DATABASE_URL, broker URL or cloud credentials (subprocess_env.py).
        env = inherited_env(_CLAUDE_CLI_ENV if self.provider == "anthropic" else ())
        env |= {
            "DEEPSEEK_API_KEY": settings.deepseek_api_key,
            "EXECUTOR_MAX_TOKENS": str(settings.executor_max_tokens),
        }
        if self.provider == "anthropic":
            env["ANTHROPIC_API_KEY"] = settings.anthropic_api_key
        if self.provider == "anthropic" and settings.anthropic_workspace_id:
            env["ANTHROPIC_WORKSPACE_ID"] = settings.anthropic_workspace_id
            # The CLI does not forward ANTHROPIC_WORKSPACE_ID to the API, so an
            # identity-linked key can't select its workspace. Inject it as a
            # custom request header (needs a workspace the key can actually access).
            env["ANTHROPIC_CUSTOM_HEADERS"] = (
                f"anthropic-workspace-id: {settings.anthropic_workspace_id}"
            )
        try:
            proc = subprocess.run(
                [str(self.python), str(_AGENT_SCRIPT)],
                input=json.dumps(cfg),
                capture_output=True,
                text=True,
                env=env,
                timeout=settings.ai_timeout_seconds,
            )
        except subprocess.TimeoutExpired as exc:
            raise PlannerUnavailable("agent timed out") from exc

        if proc.returncode != 0:
            raise PlannerUnavailable(
                f"agent exited {proc.returncode}: {proc.stderr[-500:]}"
            )
        try:
            result: dict = json.loads(proc.stdout)
        except json.JSONDecodeError as exc:
            raise PlannerUnavailable(
                f"agent produced non-JSON output: {proc.stdout[:200]}"
            ) from exc
        return result
