# syntax=docker/dockerfile:1
FROM python:3.12-slim-bookworm AS source
RUN --mount=type=bind,target=/context,ro \
    python /context/scripts/package_runner.py --source /context --output /export

# Build the Go tools on the build host and cross-compile them for the target.
FROM --platform=$BUILDPLATFORM golang:1.27-bookworm AS tools
ARG TARGETOS
ARG TARGETARCH
ARG INTERACTSH_VERSION=v1.2.4
ARG DALFOX_VERSION=v2.13.0
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@${INTERACTSH_VERSION}
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go install github.com/hahwul/dalfox/v2@${DALFOX_VERSION}
# go install puts cross-compiled binaries in an OS_ARCH subdirectory.
RUN mkdir /out && find /go/bin -type f -exec cp '{}' /out/ \;
RUN mkdir /licenses && cp /usr/local/go/LICENSE /licenses/GO-LICENSE && \
    find /go/pkg/mod -type f \( -iname 'LICENSE*' -o -iname 'COPYING*' -o -iname 'NOTICE*' \) \
      -exec cp --parents '{}' /licenses/ \;

FROM python:3.12-slim-bookworm AS runtime
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 HOME=/tmp
WORKDIR /app
COPY requirements-runner.txt /tmp/requirements-runner.txt
RUN pip install --no-cache-dir -r /tmp/requirements-runner.txt && \
    rm /tmp/requirements-runner.txt
ARG COMMIX_VERSION=v4.1
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl git sqlmap testssl.sh && \
    git clone --depth 1 --branch "$COMMIX_VERSION" \
      https://github.com/commixproject/commix /opt/commix && \
    rm -rf /opt/commix/.git && \
    printf '#!/bin/sh\nexec python3 /opt/commix/commix.py "$@"\n' > /usr/local/bin/commix && \
    chmod 755 /usr/local/bin/commix && \
    apt-get purge -y git curl && apt-get autoremove -y && \
    rm -rf /var/lib/apt/lists/*
COPY --from=tools /out/ /usr/local/bin/
COPY --from=tools /licenses/ /usr/share/doc/runpentests-go-tools/
COPY --from=source /export/app/ /app/app/
# Smoke-test the exported tree, not the private checkout. Includes every check
# and the optional local source/schema/adaptive imports.
RUN --network=none python -c "import app.runner.main, app.runner.source_audit, app.agent.loop, app.db_schema.postgres, app.engine.adaptive.runner; from app.engine.checks import ALL_CHECKS; assert ALL_CHECKS"
USER 65534:65534
CMD ["python", "-m", "app.runner"]
