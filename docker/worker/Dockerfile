# Stage 1: Build pinned Go web-recon tools (gau, waybackurls, kxss, dalfox)
FROM golang:1.23.4-bookworm AS go-builder

RUN go install -v github.com/lc/gau/v2/cmd/gau@v2.2.3 \
    && go install -v github.com/tomnomnom/waybackurls@v0.1.0 \
    && go install -v github.com/Emoe/kxss@v0.1.0 \
    && go install -v github.com/hahwul/dalfox/v2@v2.9.2

# Stage 2: Hardened non-root Recon Worker
FROM python:3.11.11-slim-bookworm

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    nmap \
    bind9-dnsutils \
    ca-certificates \
    wget \
    tar \
    unzip \
    && rm -rf /var/lib/apt/lists/*

ENV PATH="/opt/pd-tools/bin:/opt/web-tools/bin:${PATH}"

# Pinned ProjectDiscovery tools + Gitleaks with SHA-256 verification
RUN set -e; ARCH=$(uname -m); \
    if [ "$ARCH" = "x86_64" ]; then PD_ARCH="amd64"; GL_ARCH="x64"; \
    elif [ "$ARCH" = "aarch64" ]; then PD_ARCH="arm64"; GL_ARCH="arm64"; \
    else PD_ARCH="amd64"; GL_ARCH="x64"; fi; \
    mkdir -p /opt/pd-tools/bin /opt/web-tools/bin; \
    for tool in \
        "subfinder:v2.6.6:2.6.6:subfinder_2.6.6_checksums.txt" \
        "dnsx:v1.2.1:1.2.1:dnsx_1.2.1_checksums.txt" \
        "httpx:v1.6.0:1.6.0:httpx_1.6.0_checksums.txt" \
        "naabu:v2.3.1:2.3.1:naabu-linux-checksums.txt" \
        "nuclei:v3.2.4:3.2.4:nuclei_3.2.4_checksums.txt"; do \
        NAME="${tool%%:*}"; REST="${tool#*:}"; VER="${REST%%:*}"; REST2="${REST#*:}"; NUM="${REST2%%:*}"; CHK="${REST2#*:}"; \
        ZIP="${NAME}_${NUM}_linux_${PD_ARCH}.zip"; \
        wget -qO "/tmp/${ZIP}" "https://github.com/projectdiscovery/${NAME}/releases/download/${VER}/${ZIP}"; \
        wget -qO "/tmp/${CHK}" "https://github.com/projectdiscovery/${NAME}/releases/download/${VER}/${CHK}"; \
        (cd /tmp && grep -F "${ZIP}" "${CHK}" | sha256sum -c -); \
        unzip -oq "/tmp/${ZIP}" "${NAME}" -d /opt/pd-tools/bin; \
        rm -f "/tmp/${ZIP}" "/tmp/${CHK}"; \
        chmod 0755 "/opt/pd-tools/bin/${NAME}"; \
    done; \
    GL_TGZ="gitleaks_8.18.4_linux_${GL_ARCH}.tar.gz"; \
    wget -qO "/tmp/${GL_TGZ}" "https://github.com/gitleaks/gitleaks/releases/download/v8.18.4/${GL_TGZ}"; \
    wget -qO /tmp/gitleaks_checksums.txt "https://github.com/gitleaks/gitleaks/releases/download/v8.18.4/gitleaks_8.18.4_checksums.txt"; \
    (cd /tmp && grep -F "${GL_TGZ}" gitleaks_checksums.txt | sha256sum -c -); \
    tar -xzf "/tmp/${GL_TGZ}" -C /usr/local/bin gitleaks; \
    rm -f "/tmp/${GL_TGZ}" /tmp/gitleaks_checksums.txt; \
    chmod 0755 /usr/local/bin/gitleaks

COPY --from=go-builder /go/bin/* /opt/web-tools/bin/

COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
    && pip install --no-cache-dir dnstwist==20240116 redis==5.2.1

RUN useradd --create-home --shell /bin/bash openrecon \
    && mkdir -p /app/data/evidences /app/data/misp_galaxy /app/data/repo_sandbox \
    && chown -R openrecon:openrecon /app

COPY --chown=openrecon:openrecon backend/ /app/

USER openrecon

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD python -c "import app.core.security_guard as g; print(g.SecurityGovernanceGuard.is_kill_switch_active())" >/dev/null || exit 1

CMD ["python", "-m", "app.worker"]
