"""Minimal HTTP client for native modules (stdlib urllib, no third-party deps)."""
from __future__ import annotations

import ssl
import urllib.error
import urllib.request
from typing import Any

_UA = "Infiltr/1.0 (+authorized-scan)"
_MAX = 2_000_000  # cap body reads


def _ctx() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # scanning: don't fail on bad/self-signed certs
    return ctx


def fetch(url: str, method: str = "GET", timeout: int = 15,
          headers: dict | None = None, max_bytes: int = _MAX) -> dict[str, Any]:
    """Return {status, headers(lowercased), body, url}. status 0 on transport error."""
    hdrs = {"User-Agent": _UA}
    if headers:
        hdrs.update(headers)
    req = urllib.request.Request(url, method=method, headers=hdrs)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_ctx()) as r:  # noqa: S310
            body = r.read(max_bytes).decode("utf-8", "replace")
            return {"status": r.status, "headers": _lower(r.headers), "body": body, "url": r.geturl()}
    except urllib.error.HTTPError as e:
        body = ""
        try:
            body = e.read(max_bytes).decode("utf-8", "replace")
        except Exception:  # noqa: BLE001
            pass
        return {"status": e.code, "headers": _lower(e.headers or {}), "body": body, "url": url}
    except Exception as e:  # noqa: BLE001
        return {"status": 0, "headers": {}, "body": "", "url": url, "error": str(e)}


def _lower(headers) -> dict[str, str]:
    out: dict[str, str] = {}
    try:
        items = headers.items()
    except AttributeError:
        items = dict(headers).items()
    for k, v in items:
        out[str(k).lower()] = str(v)
    return out
