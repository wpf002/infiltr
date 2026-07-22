# Infiltr production image — API + console + the scan toolchain.
FROM kalilinux/kali-rolling:latest

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    INFILTR_XSSTRIKE=/opt/XSStrike/xsstrike.py \
    INFILTR_WORDLIST=/usr/share/wordlists/dirb/common.txt

# Scan tools + python
RUN apt-get update && apt-get install -y --no-install-recommends \
      nmap nikto whatweb hydra sqlmap wfuzz ffuf gobuster feroxbuster \
      theharvester seclists git python3 python3-pip python3-venv ca-certificates \
      nuclei httpx-toolkit subfinder dnsx dalfox sslscan testssl.sh wafw00f \
      wpscan masscan metasploit-framework \
    && rm -rf /var/lib/apt/lists/*

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

# Pre-fetch nuclei templates so scans run offline/fast (best-effort)
RUN nuclei -update-templates -disable-update-check 2>/dev/null || true

EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD python3 -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health').status==200 else 1)" || exit 1

CMD ["python3", "-m", "uvicorn", "infiltr.api.app:app", "--host", "0.0.0.0", "--port", "8000"]
