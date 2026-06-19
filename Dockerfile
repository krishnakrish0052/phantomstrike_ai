# PhantomStrike — Kali Linux rolling base image
FROM kalilinux/kali-rolling:latest

# Avoid interactive prompts during package install
ENV DEBIAN_FRONTEND=noninteractive

# ── System basics + build deps ─────────────────────────────────────────────────
RUN apt-get update -qq && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    gcc \
    git \
    python3 \
    python3-dev \
    python3-pip \
    python3-venv \
    sudo \
    wget \
 && rm -rf /var/lib/apt/lists/*

# ── Install all PhantomStrike tool dependencies via phantomstrike.sh -t ──────────────
WORKDIR /opt/phantomstrike

# Copy the repo into the image
COPY . .

# Run tool install (apt/cargo tools only).
RUN apt-get update -qq && \
    chmod +x phantomstrike.sh && \
    bash phantomstrike.sh -t && \
    rm -rf /var/lib/apt/lists/*

# ── Runtime config ─────────────────────────────────────────────────────────────
# Bind to 0.0.0.0 inside the container so the mapped port is reachable
ENV PHANTOMSTRIKE_HOST=0.0.0.0
ENV PHANTOMSTRIKE_PORT=8888

# Ensure Go and Rust/Cargo tool binaries are on PATH
ENV PATH="/root/go/bin:/root/.cargo/bin:${PATH}"

EXPOSE 8888

# ── Additional runtime dependencies for merged capabilities ──────────────────
# Chrome/Chromium for Browser Agent (Selenium)
# mitmproxy for HTTP Testing Framework proxy mode
# Clean stale third-party repos first to avoid apt-get update failures
RUN rm -f /etc/apt/sources.list.d/*trivy* /etc/apt/sources.list.d/*aqua* 2>/dev/null; \
    apt-get update -qq && apt-get install -y --no-install-recommends \
    chromium \
    chromium-driver \
    mitmproxy \
 && rm -rf /var/lib/apt/lists/*

# ── Python dependencies ──────────────────────────────────────────────────────
RUN python3 -m pip install --no-cache-dir --break-system-packages \
    selenium>=4.15.0 \
    webdriver-manager>=4.0.0 \
    h2>=4.0.0 \
    mitmproxy>=9.0.0

# ── Entrypoint ─────────────────────────────────────────────────────────────────
RUN chmod +x docker-entrypoint.sh

ENTRYPOINT ["/opt/phantomstrike/docker-entrypoint.sh"]
