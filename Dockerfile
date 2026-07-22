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
    && rm -rf /var/lib/apt/lists/*

# XSStrike (cloned tool)
RUN git clone --depth 1 https://github.com/s0md3v/XSStrike.git /opt/XSStrike \
    && pip3 install --no-cache-dir --break-system-packages -r /opt/XSStrike/requirements.txt || true

WORKDIR /app
COPY requirements.txt .
RUN pip3 install --no-cache-dir --break-system-packages -r requirements.txt

COPY . .

# non-root runtime
RUN useradd -m -u 10001 infiltr && chown -R infiltr:infiltr /app
USER infiltr

EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD python3 -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health').status==200 else 1)" || exit 1

CMD ["python3", "-m", "uvicorn", "infiltr.api.app:app", "--host", "0.0.0.0", "--port", "8000"]
