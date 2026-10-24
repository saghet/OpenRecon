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
    && rm -rf /var/lib/apt/lists/*

# Install ProjectDiscovery tools (subfinder, httpx, naabu, nuclei)
RUN ARCH=$(uname -m) && \
    if [ "$ARCH" = "x86_64" ]; then PD_ARCH="amd64"; elif [ "$ARCH" = "aarch64" ]; then PD_ARCH="arm64"; else PD_ARCH="amd64"; fi && \
    wget -qO- https://github.com/projectdiscovery/subfinder/releases/download/v2.6.6/subfinder_2.6.6_linux_${PD_ARCH}.zip | busybox unzip - -d /usr/local/bin subfinder 2>/dev/null || true && \
    wget -qO- https://github.com/projectdiscovery/httpx/releases/download/v1.6.0/httpx_1.6.0_linux_${PD_ARCH}.zip | busybox unzip - -d /usr/local/bin httpx 2>/dev/null || true && \
    wget -qO- https://github.com/projectdiscovery/naabu/releases/download/v2.3.1/naabu_2.3.1_linux_${PD_ARCH}.zip | busybox unzip - -d /usr/local/bin naabu 2>/dev/null || true && \
    wget -qO- https://github.com/projectdiscovery/nuclei/releases/download/v3.2.4/nuclei_3.2.4_linux_${PD_ARCH}.zip | busybox unzip - -d /usr/local/bin nuclei 2>/dev/null || true && \
    chmod +x /usr/local/bin/* 2>/dev/null || true

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code
COPY . .

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
