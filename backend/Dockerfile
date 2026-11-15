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

# Install ProjectDiscovery tools (subfinder, httpx, naabu, nuclei)
RUN set -e; ARCH=$(uname -m); \
    if [ "$ARCH" = "x86_64" ]; then PD_ARCH="amd64"; elif [ "$ARCH" = "aarch64" ]; then PD_ARCH="arm64"; else PD_ARCH="amd64"; fi; \
    for tool in \
        "subfinder:v2.6.6:subfinder_2.6.6_linux_${PD_ARCH}.zip" \
        "httpx:v1.6.0:httpx_1.6.0_linux_${PD_ARCH}.zip" \
        "naabu:v2.3.1:naabu_2.3.1_linux_${PD_ARCH}.zip" \
        "nuclei:v3.2.4:nuclei_3.2.4_linux_${PD_ARCH}.zip"; do \
        NAME="${tool%%:*}"; REST="${tool#*:}"; VER="${REST%%:*}"; ZIP="${REST#*:}"; \
        wget -qO "/tmp/${NAME}.zip" "https://github.com/projectdiscovery/${NAME}/releases/download/${VER}/${ZIP}" && \
        unzip -oq "/tmp/${NAME}.zip" "${NAME}" -d /usr/local/bin && \
        rm -f "/tmp/${NAME}.zip" && \
        chmod +x "/usr/local/bin/${NAME}"; \
    done

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code
COPY . .

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
