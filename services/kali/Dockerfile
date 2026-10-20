# Kali adjunct service — a curated toolbox container, deliberately NOT the
# kali-linux-headless metapackage (~2 GB). Built from the official Kali image
# (see kali.org/docs/containers) with only the tools the worker drives:
#   nuclei   — template scanning (CVEs, exposures, misconfigs)
#   ffuf     — content discovery
#   nikto    — web-server misconfig / known-file scan
#   whatweb  — technology fingerprint
#   katana   — JS-aware crawler for shadow endpoints
#   arjun    — hidden HTTP-parameter discovery
#   seclists — larger wordlists for `deep` discovery runs
FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive

# If Kali renames or archives a package, adjust this list — the service reports
# missing tools via /health and 503s cleanly instead of crashing, so a single
# unavailable package degrades one pass rather than breaking the build's intent.
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        python3 \
        python3-pip \
        nuclei \
        ffuf \
        nikto \
        whatweb \
        arjun \
        seclists \
    && rm -rf /var/lib/apt/lists/*

# katana is not in the Kali apt archive, so install it from source with a Go
# toolchain that we remove again to keep the image lean (mirrors how the worker
# image builds dalfox). If the build host is offline this layer fails loudly;
# the service still 503s cleanly at runtime if the binary ends up absent.
RUN apt-get update && apt-get install -y --no-install-recommends golang-go git && \
    GOBIN=/usr/local/bin go install github.com/projectdiscovery/katana/cmd/katana@latest && \
    apt-get purge -y golang-go git && apt-get autoremove -y && \
    rm -rf /var/lib/apt/lists/* /root/go /root/.cache/go-build

RUN pip3 install --no-cache-dir --break-system-packages fastapi uvicorn

WORKDIR /opt/kali
COPY app ./app

# Bake the nuclei template library into the image so the first scan does not
# pay the download. Network failure here must not break the build — nuclei
# retries the download at runtime.
RUN nuclei -update-templates || echo "nuclei templates deferred to first run"

EXPOSE 8091
CMD ["python3", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8091"]
