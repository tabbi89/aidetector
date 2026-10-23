FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

COPY requirements.txt requirements-dev.txt ./
# WITH_DEV=1 adds ruff/mypy and the rest of requirements-dev.txt so `make lint`
# runs where `make test` does. Resolved in one pip call with the runtime pins,
# exactly as CI installs them. The dev compose's api service turns it on; any
# other build of this image stays lean.
ARG WITH_DEV=0
RUN pip install --no-cache-dir -r requirements.txt \
        $(if [ "$WITH_DEV" = "1" ]; then echo "-r requirements-dev.txt"; fi)

# Optional: out-of-band (OAST) support needs the interactsh-client binary in the
# worker. Off by default to keep the image lean. Enable with:
#   docker build --build-arg WITH_INTERACTSH=1 [--build-arg INTERACTSH_VERSION=x.y.z]
# Verify the release URL/version at github.com/projectdiscovery/interactsh/releases.
ARG WITH_INTERACTSH=0
ARG INTERACTSH_VERSION=1.2.4
RUN if [ "$WITH_INTERACTSH" = "1" ]; then \
      apt-get update && apt-get install -y --no-install-recommends curl ca-certificates unzip && \
      arch="$(dpkg --print-architecture)"; case "$arch" in arm64) a=arm64;; *) a=amd64;; esac && \
      curl -fsSL -o /tmp/ish.zip \
        "https://github.com/projectdiscovery/interactsh/releases/download/v${INTERACTSH_VERSION}/interactsh-client_${INTERACTSH_VERSION}_linux_${a}.zip" && \
      unzip -o /tmp/ish.zip -d /usr/local/bin interactsh-client && rm /tmp/ish.zip && \
      apt-get purge -y unzip && rm -rf /var/lib/apt/lists/*; \
    fi

# Optional: worker-side lead-confirmation tools. These re-test parameters the
# engine already flagged and must run in the worker (they need the finding
# context), unlike the stateless kali service. Off by default to keep the image
# lean. Enable with:
#   docker build --build-arg WITH_KALI_TOOLS=1
# and set the matching *_BIN in .env to activate each:
#   SQLMAP_BIN=sqlmap     — SQLi confirmation (Debian apt)
#   TESTSSL_BIN=testssl   — deep TLS audit (Debian names the binary `testssl`)
#   COMMIX_BIN=commix     — command-injection confirmation (git, Python 3)
#   DALFOX_BIN=dalfox     — XSS confirmation (Go build)
# Heavier discovery tools (nuclei, ffuf, nikto, whatweb, katana, arjun) live in
# the separate kali service instead.
#
# sqlmap + testssl.sh are in Debian; commix is not, so it is cloned and wrapped
# on PATH; dalfox is a Go build. The Go toolchain is removed afterwards to keep
# the image lean.
#
# tplmap (SSTI confirmation, TPLMAP_BIN) is a deprecated Python-2 tool not
# packaged in Debian; provision it yourself if you want it, e.g.:
#   git clone https://github.com/epinna/tplmap /opt/tplmap
# then set TPLMAP_BIN=/opt/tplmap/tplmap.py (needs a python2 interpreter).
ARG WITH_KALI_TOOLS=0
RUN if [ "$WITH_KALI_TOOLS" = "1" ]; then \
      apt-get update && apt-get install -y --no-install-recommends \
        sqlmap testssl.sh golang-go git && \
      GOBIN=/usr/local/bin go install github.com/hahwul/dalfox/v2@latest && \
      git clone --depth 1 https://github.com/commixproject/commix /opt/commix && \
      printf '#!/bin/sh\nexec python3 /opt/commix/commix.py "$@"\n' > /usr/local/bin/commix && \
      chmod +x /usr/local/bin/commix && \
      apt-get purge -y golang-go && apt-get autoremove -y && \
      rm -rf /var/lib/apt/lists/* /root/go /root/.cache/go-build; \
    fi

# Optional: the AI cascade's isolated Agent SDK runtime. The planner
# (adjudication + pre-scan planning) runs the Claude Agent SDK, which needs its
# own venv (its mcp/starlette deps conflict with FastAPI's) AND the `claude` CLI
# on PATH. Both are baked here, OUTSIDE /app so the source bind-mount can't
# shadow them. Off by default to keep the image lean. Enable with:
#   docker build --build-arg WITH_AI=1
# and set AI_PYTHON=/opt/venv-ai/bin/python plus ANTHROPIC_API_KEY in .env.
ARG WITH_AI=0
COPY ai_runtime/requirements.txt /tmp/ai-requirements.txt
RUN if [ "$WITH_AI" = "1" ]; then \
      set -e; \
      apt-get update && apt-get install -y --no-install-recommends curl ca-certificates git && \
      python -m venv /opt/venv-ai; \
      /opt/venv-ai/bin/pip install --no-cache-dir -r /tmp/ai-requirements.txt && \
      curl -fsSL https://claude.ai/install.sh | bash && \
      ln -sf /root/.local/bin/claude /usr/local/bin/claude && \
      /usr/local/bin/claude --version && \
      /opt/venv-ai/bin/python -c "import claude_agent_sdk"; \
      apt-get purge -y git && apt-get autoremove -y && rm -rf /var/lib/apt/lists/*; \
    fi

COPY . .

EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
