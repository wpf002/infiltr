# Infiltr production image — API + console + the scan toolchain.
FROM kalilinux/kali-rolling:latest

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    INFILTR_XSSTRIKE=/opt/XSStrike/xsstrike.py \
    INFILTR_WORDLIST=/usr/share/wordlists/dirb/common.txt

# Scan tools + python (dalfox isn't packaged in Kali — installed via Go below)
RUN apt-get update && apt-get install -y --no-install-recommends \
      nmap nikto whatweb hydra sqlmap wfuzz ffuf gobuster feroxbuster \
      theharvester seclists git python3 python3-pip python3-venv ca-certificates \
      nuclei httpx-toolkit subfinder dnsx sslscan testssl.sh wafw00f \
      wpscan masscan metasploit-framework \
    && rm -rf /var/lib/apt/lists/*

# dalfox (Go tool, not in the Kali repo) — build then drop the Go toolchain
RUN apt-get update && apt-get install -y --no-install-recommends golang git \
    && GOBIN=/usr/local/bin GOFLAGS=-buildvcs=false go install github.com/hahwul/dalfox/v2@latest \
    && apt-get purge -y golang && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/* /root/go /root/.cache

# XSStrike (cloned tool)
RUN git clone --depth 1 https://github.com/s0md3v/XSStrike.git /opt/XSStrike \
    && pip3 install --no-cache-dir --break-system-packages -r /opt/XSStrike/requirements.txt || true

WORKDIR /app
COPY requirements.txt .
RUN pip3 install --no-cache-dir --break-system-packages -r requirements.txt

COPY . .

# non-root runtime; /data is the persistence volume mountpoint (init'd with the
# volume so SQLite/report files are writable by the unprivileged user)
RUN useradd -m -u 10001 infiltr \
    && mkdir -p /data \
    && chown -R infiltr:infiltr /app /data
VOLUME ["/data"]
USER infiltr

# Pre-fetch nuclei templates so scans run offline/fast
# (NOT with -disable-update-check — that flag suppresses the initial install)
RUN nuclei -ut 2>&1 | tail -2 || true

EXPOSE 8000
# $PORT is injected by Railway/Heroku-style platforms; defaults to 8000 locally.
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD python3 -c "import os,urllib.request,sys; p=os.environ.get('PORT','8000'); sys.exit(0 if urllib.request.urlopen(f'http://127.0.0.1:{p}/health').status==200 else 1)" || exit 1

CMD ["sh", "-c", "exec python3 -m uvicorn infiltr.api.app:app --host 0.0.0.0 --port ${PORT:-8000}"]
