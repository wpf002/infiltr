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


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Return 30x responses as-is instead of following them (open-redirect checks)."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401
        return None


def fetch(url: str, method: str = "GET", timeout: int = 15,
          headers: dict | None = None, max_bytes: int = _MAX,
          follow_redirects: bool = True, data: bytes | str | None = None) -> dict[str, Any]:
    """Return {status, headers(lowercased), body, url}. status 0 on transport error.

    follow_redirects=False surfaces the raw 30x + Location header (a 30x then
    counts as an HTTPError, whose headers still carry Location).
    `data` sends a request body (e.g. a JSON POST); pass method="POST" too."""
    hdrs = {"User-Agent": _UA}
    if headers:
        hdrs.update(headers)
    payload = data.encode("utf-8") if isinstance(data, str) else data
    req = urllib.request.Request(url, method=method, headers=hdrs, data=payload)
    try:
        if follow_redirects:
            opener_open = lambda: urllib.request.urlopen(req, timeout=timeout, context=_ctx())  # noqa: E731,S310
        else:
            opener = urllib.request.build_opener(_NoRedirect(), urllib.request.HTTPSHandler(context=_ctx()))
            opener_open = lambda: opener.open(req, timeout=timeout)  # noqa: E731
        with opener_open() as r:  # noqa: S310
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
