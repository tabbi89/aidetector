# AI runtime (isolated Agent SDK planner)

**By default nothing here needs installing.** `PLANNER_PROVIDER=deepseek` (the
default) runs every AI mode — plan, adjudicate, adaptive, propose_resource,
Q&A, payloads, security review — as a direct DeepSeek completion. `plan_agent.py`
then imports only `httpx`, so it runs under the service's own interpreter when
`.venv-ai` is absent; set `DEEPSEEK_API_KEY` and you are done.

The rest of this page is for `PLANNER_PROVIDER=anthropic`, where the AI
cascade's **Opus planner** runs the [Claude Agent SDK], which pulls
transitive deps (`mcp`, `starlette`) that conflict with FastAPI's pinned
Starlette. To keep the main service's dependency tree clean, the planner lives
here and runs in **its own venv**, driven by the main app over stdin/stdout
(`app/ai/planner.py` → subprocess → `plan_agent.py`).

```
main service venv (.venv)     ─ FastAPI, engine, Celery — NO Agent SDK
ai_runtime venv (.venv-ai)    ─ claude-agent-sdk + httpx only
```

## Setup

### Docker (recommended)

Bake the venv **and** the `claude` CLI into the worker/api image with a build arg:

```bash
WITH_AI=1 docker compose build api worker beat
WITH_AI=1 make up      # AI_PYTHON defaults to /opt/venv-ai/bin/python
```

The Dockerfile creates `/opt/venv-ai` (container Python, outside the `/app`
bind-mount so it isn't shadowed) and installs the native `claude` CLI.

The agent runs with **no `bypassPermissions`**: `plan_agent.py` passes a
`can_use_tool` callback that approves exactly one tool — the DeepSeek `triage`
MCP tool — and denies everything else (any built-in file/bash tool the CLI
exposes). That replaces the blanket permission bypass, so the subprocess no
longer needs `--dangerously-skip-permissions` (nor the old `IS_SANDBOX=1` hack
that let the CLI accept that flag as root), and its behaviour no longer depends
on the worker's uid.

### Local (host) venv

```bash
cd services/api
python3.13 -m venv .venv-ai
.venv-ai/bin/pip install -r ai_runtime/requirements.txt
```

### Credentials (`.env`)

The Agent SDK needs the **`claude` CLI** on PATH plus valid Anthropic
credentials:

- `ANTHROPIC_API_KEY` — **use a workspace-scoped key**. This is the reliable
  path: it carries its workspace implicitly, so no header juggling is needed.
- `ANTHROPIC_WORKSPACE_ID` — only for an **identity-linked** key. The `claude`
  CLI does not forward it, so the runner injects it as an
  `anthropic-workspace-id` request header (`ANTHROPIC_CUSTOM_HEADERS`). The
  workspace must be one the key can actually access — a stale/deleted workspace
  id yields `Workspace ... not found` and the AI step is skipped.
- `DEEPSEEK_API_KEY`, `DEEPSEEK_BASE_URL`, `EXECUTOR_MODEL`.

## Graceful degradation

If the venv, the `claude` CLI, or credentials are missing, the planner raises
`PlannerUnavailable`, the runner logs it, emits an `ai_skipped` event, and the
scan completes with engine findings intact (verdicts stay `unreviewed`). The AI
cascade is strictly opt-in per run (`adjudicate: true`).

## Protocol

`plan_agent.py` reads one JSON object on stdin and writes one on stdout:

```
in : {planner_model, executor_model, deepseek_base_url, findings:[...]}
out: {verdicts:[{id,verdict,rationale}], usages:[{model,phase,tokens_in,tokens_out}]}
```

[Claude Agent SDK]: https://code.claude.com/docs/en/agent-sdk/python
