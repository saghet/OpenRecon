FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    git \
    nmap \
    bind9-dnsutils \
    ca-certificates \
    wget \
    tar \
    unzip \
    && rm -rf /var/lib/apt/lists/*

# Install pinned ProjectDiscovery tools (subfinder, dnsx, httpx, naabu, nuclei) into /opt/pd-tools/bin
# so Python's httpx CLI wrapper in /usr/local/bin never shadows ProjectDiscovery httpx, and install Gitleaks.
ENV PATH="/opt/pd-tools/bin:${PATH}"
RUN set -e; ARCH=$(uname -m); \
    if [ "$ARCH" = "x86_64" ]; then PD_ARCH="amd64"; GL_ARCH="x64"; \
    elif [ "$ARCH" = "aarch64" ]; then PD_ARCH="arm64"; GL_ARCH="arm64"; \
    else PD_ARCH="amd64"; GL_ARCH="x64"; fi; \
    mkdir -p /opt/pd-tools/bin; \
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
        test -s "/tmp/${ZIP}"; \
        (cd /tmp && grep -F "${ZIP}" "${CHK}" | sha256sum -c -); \
        unzip -oq "/tmp/${ZIP}" "${NAME}" -d /opt/pd-tools/bin; \
        rm -f "/tmp/${ZIP}" "/tmp/${CHK}"; \
        chmod 0755 "/opt/pd-tools/bin/${NAME}"; \
        "/opt/pd-tools/bin/${NAME}" -version; \
    done; \
    GL_TGZ="gitleaks_8.18.4_linux_${GL_ARCH}.tar.gz"; \
    wget -qO "/tmp/${GL_TGZ}" "https://github.com/gitleaks/gitleaks/releases/download/v8.18.4/${GL_TGZ}"; \
    wget -qO /tmp/gitleaks_checksums.txt "https://github.com/gitleaks/gitleaks/releases/download/v8.18.4/gitleaks_8.18.4_checksums.txt"; \
    test -s "/tmp/${GL_TGZ}"; \
    (cd /tmp && grep -F "${GL_TGZ}" gitleaks_checksums.txt | sha256sum -c -); \
    tar -xzf "/tmp/${GL_TGZ}" -C /usr/local/bin gitleaks; \
    rm -f "/tmp/${GL_TGZ}" /tmp/gitleaks_checksums.txt; \
    chmod 0755 /usr/local/bin/gitleaks; \
    /usr/local/bin/gitleaks version

# Copy requirements and install Python dependencies + pinned dnstwist
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
    && pip install --no-cache-dir dnstwist==20240116

# Create non-root user and writable data directory
RUN useradd --create-home --shell /bin/bash openrecon \
    && mkdir -p /app/data/misp_galaxy /app/data/repo_sandbox \
    && chown -R openrecon:openrecon /app

# Copy source code
COPY --chown=openrecon:openrecon . .

USER openrecon

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8000/ || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
