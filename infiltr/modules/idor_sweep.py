"""Native IDOR/BOLA sweep — auto-discovers victim-owned objects, then checks
whether the attacker (scan identity) can read each of them.

This is the fan-out the single-target `idor` module can't do. Given a second
identity (the victim) plus one or more seed URLs (typically the authenticated
endpoints Quarry already discovered), it:

  1. Crawls SAME-HOST as the victim, harvesting id-bearing resource URLs the
     victim can actually read (HTTP 200, non-trivial body). Ids come from the
     seed paths themselves and from id fields inside the victim's JSON responses
     (a collection like /api/orders -> /api/orders/{id}). These are, by
     construction, the victim's own objects.
  2. For every distinct URL SHAPE (ids replaced by a placeholder), runs the same
     differential oracle idor.py uses: the victim reads their resource, the
     attacker requests the SAME url, an anonymous request is the control. An
     exact attacker==victim body on a non-public, non-login response is a
     confirmed cross-user read.

Read-only (GET), same-host only, bounded by max_urls and a per-shape cap so a
big API doesn't turn into an unbounded crawl. Without a second identity it does
nothing (emits a note); it never guesses or fabricates a finding.
"""
from __future__ import annotations

import json
import re
from collections import deque
from urllib.parse import urlparse, urljoin

from ..base import NativeWrapper, Finding, SEV_INFO, SEV_HIGH
from ..webutil import fetch

_LOGIN_HINT = re.compile(r"(sign in|log ?in|password|unauthori[sz]ed|forbidden|access denied|please log)", re.I)
_UUID = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
_ID_SEG = re.compile(rf"^(\d+|{_UUID})$", re.I)
_ID_EXACT = {"id", "uid", "uuid", "guid", "pid", "oid", "ref"}


def _is_id_key(k: str) -> bool:
    """A query-param name that carries an object id: exact (id/uid/uuid/...),
    snake_case (*_id), or camelCase with a capital I (userId, orderId). The
    capital-I requirement avoids false positives like 'grid' or 'void'."""
    if not k:
        return False
    if k.lower() in _ID_EXACT:
        return True
    if k.lower().endswith("_id"):
        return True
    return re.search(r"[a-z]Id$", k) is not None
# id-looking keys inside a JSON object (id, _id, userId, orderId, ...)
_ID_KEY = re.compile(r"(^id$|_id$|^uuid$|Id$)")
_HREF = re.compile(r"""(?:href|src|action)=["']([^"']+)["']""", re.I)
# common locations an OpenAPI/Swagger spec is served at
_SPEC_PROBE = ["/api-docs/swagger.json", "/swagger.json", "/swagger/v1/swagger.json",
               "/openapi.json", "/v3/api-docs", "/api-docs"]


class IdorSweepWrapper(NativeWrapper):
    MODULE_NAME = "idor_sweep"
    CATEGORY = "web"
    DESCRIPTION = "IDOR/BOLA sweep: discovers victim objects, tests attacker access across the whole API (needs 2 identities)"
    VERSION = "1.0"
    DEFAULT_TIMEOUT = 180

    def collect(self, target: str) -> list[Finding]:
        victim = self.options.get("victim_headers") or {}
        attacker = self.auth_headers()
        max_urls = int(self.options.get("max_urls", 60))
        per_shape = int(self.options.get("per_shape", 2))
        timeout = int(self.options.get("timeout", 12))
        seeds = self.options.get("seeds") or [target]

        if not victim:
            return [Finding(type="note", name="idor_sweep", value="skipped: no second identity",
                            detail="needs context.idor.victim_headers (attacker = scan auth)", severity=SEV_INFO)]
        if not attacker:
            return [Finding(type="note", name="idor_sweep", value="skipped: no scan auth",
                            detail="needs the authenticated scan identity (context.auth.headers)", severity=SEV_INFO)]

        host = (urlparse(target).hostname or "").lower()
        origin = _origin(target)
        # Turn any OpenAPI/Swagger spec into extra seeds: its parameterized
        # resources' collections, which the victim crawl then harvests ids from.
        spec_seeds = self._seed_from_openapi(origin, seeds, victim, host, timeout) \
            if self.options.get("openapi", True) else []
        candidates = self._discover(seeds + spec_seeds, victim, host, max_urls, timeout)

        findings: list[Finding] = []
        shape_hits: dict[str, int] = {}
        tested = 0
        for url in candidates:
            if tested >= max_urls:
                break
            shape = _shape(url)
            if shape_hits.get(shape, 0) >= per_shape:
                continue
            v = fetch(url, timeout=timeout, headers=victim)
            if v.get("status") != 200 or len((v.get("body") or "")) < 16:
                continue  # not a real victim-owned resource
            tested += 1
            a = fetch(url, timeout=timeout, headers=attacker)
            anon = fetch(url, timeout=timeout, headers={})
            if _is_cross_user_read(a, v, anon):
                shape_hits[shape] = shape_hits.get(shape, 0) + 1
                findings.append(Finding(
                    type="idor", name="IDOR / broken object-level auth", value=url,
                    detail=f"the scan identity retrieved another user's resource (attacker body == victim body); shape {shape}",
                    severity=SEV_HIGH,
                    metadata={"url": url, "matched_at": url, "shape": shape,
                              "attacker_status": a.get("status"), "victim_status": v.get("status"),
                              "confidence": 0.9, "confirmed": True}))

        if not findings:
            findings.append(Finding(type="note", name="idor_sweep", value="no cross-user reads",
                                    detail=f"tested {tested} victim-owned url(s); none were readable by the attacker",
                                    severity=SEV_INFO, metadata={"tested": tested, "candidates": len(candidates)}))
        return findings

    def summarize(self, findings: list[Finding]) -> str:
        n = sum(1 for f in findings if f.type == "idor")
        return f"{n} IDOR/BOLA issue(s) across the swept surface." if n else "No cross-user reads."

    # ---- discovery ----------------------------------------------------
    def _discover(self, seeds: list[str], victim: dict, host: str,
                  max_urls: int, timeout: int) -> list[str]:
        """BFS same-host as the victim; return id-bearing URLs the victim can read."""
        out: list[str] = []
        seen_url: set[str] = set()
        seen_shape: set[str] = set()
        queue: deque[tuple[str, int]] = deque()
        for s in seeds:
            if _same_host(s, host):
                queue.append((s, 0))
        fetches = 0
        fetch_budget = max_urls * 2
        while queue and len(out) < max_urls and fetches < fetch_budget:
            url, depth = queue.popleft()
            if url in seen_url:
                continue
            seen_url.add(url)
            # an id-bearing seed/url is itself a candidate
            if _is_id_bearing(url):
                sh = _shape(url)
                if sh not in seen_shape:
                    seen_shape.add(sh)
                    out.append(url)
            if depth > 2:
                continue
            r = fetch(url, timeout=timeout, headers=victim)
            fetches += 1
            if r.get("status") != 200:
                continue
            body = r.get("body") or ""
            ctype = (r.get("headers") or {}).get("content-type", "")
            found = _links_from_json(url, body) if "json" in ctype or _looks_json(body) else _links_from_html(url, body)
            for nxt in found:
                if not _same_host(nxt, host) or nxt in seen_url:
                    continue
                if _is_id_bearing(nxt):
                    sh = _shape(nxt)
                    if sh not in seen_shape:
                        seen_shape.add(sh)
                        out.append(nxt)
                # only follow collection-ish urls deeper (avoid crawling assets)
                if depth < 2 and _followable(nxt):
                    queue.append((nxt, depth + 1))
        return out[:max_urls]

    def _seed_from_openapi(self, origin: str, seeds: list[str], victim: dict,
                           host: str, timeout: int) -> list[str]:
        """Fetch an OpenAPI/Swagger spec (from a seed or a few common paths) as the
        victim and return the collection URLs of its parameterized resources."""
        spec_urls = [s for s in seeds if _same_host(s, host) and _looks_spec_url(s)]
        spec_urls += [urljoin(origin + "/", p.lstrip("/")) for p in _SPEC_PROBE]
        out: list[str] = []
        seen: set[str] = set()
        for su in spec_urls:
            if su in seen:
                continue
            seen.add(su)
            r = fetch(su, timeout=timeout, headers=victim)
            if r.get("status") != 200:
                continue
            try:
                spec = json.loads(r.get("body") or "")
            except Exception:  # noqa: BLE001
                continue
            if not (isinstance(spec, dict) and ("openapi" in spec or "swagger" in spec or "paths" in spec)):
                continue
            out = _openapi_collections(spec, origin)
            if out:
                break  # one good spec is enough
        uniq: list[str] = []
        s2: set[str] = set()
        for u in out:
            if _same_host(u, host) and u not in s2:
                s2.add(u)
                uniq.append(u)
        return uniq


# ---- pure helpers (unit-tested) ---------------------------------------
def _origin(url: str) -> str:
    p = urlparse(url)
    return f"{p.scheme}://{p.netloc}"


def _looks_spec_url(u: str) -> bool:
    p = urlparse(u).path.lower()
    return "swagger" in p or "openapi" in p or p.endswith("/api-docs") or p.endswith("/v3/api-docs")


def _openapi_collections(spec: dict, origin: str) -> list[str]:
    """Collection URLs for every parameterized path in an OpenAPI/Swagger spec.
    /api/Users/{id} -> {origin}/api/Users ; honors swagger 2.0 basePath."""
    paths = spec.get("paths") if isinstance(spec, dict) else None
    if not isinstance(paths, dict):
        return []
    base = spec.get("basePath") if isinstance(spec.get("basePath"), str) else ""
    cols: set[str] = set()
    for path in paths:
        if not isinstance(path, str) or "{" not in path:
            continue
        prefix = path.split("{", 1)[0].rstrip("/")
        if not prefix:
            continue
        rel = (base.rstrip("/") + prefix) if base else prefix
        cols.add(urljoin(origin + "/", rel.lstrip("/")))
    return sorted(cols)


def _same_host(url: str, host: str) -> bool:
    try:
        h = (urlparse(url).hostname or "").lower()
        return bool(h) and h == host
    except ValueError:
        return False


def _is_id_bearing(url: str) -> bool:
    try:
        p = urlparse(url)
    except ValueError:
        return False
    for seg in p.path.split("/"):
        if _ID_SEG.match(seg):
            return True
    for kv in p.query.split("&"):
        if _is_id_key(kv.split("=", 1)[0]):
            return True
    return False


def _shape(url: str) -> str:
    """Collapse ids to :id so /a/1 and /a/2 share one shape (query keys only)."""
    p = urlparse(url)
    segs = [(":id" if _ID_SEG.match(s) else s) for s in p.path.split("/")]
    keys = sorted(kv.split("=", 1)[0] for kv in p.query.split("&") if kv)
    q = ("?" + ",".join(keys)) if keys else ""
    return f"{p.path and '/'.join(segs)}{q}"


def _followable(url: str) -> bool:
    """Skip obvious static assets; follow api/rest/html-ish paths."""
    path = urlparse(url).path.lower()
    if re.search(r"\.(css|js|png|jpe?g|gif|svg|ico|woff2?|ttf|map|pdf|zip)$", path):
        return False
    return True


def _looks_json(body: str) -> bool:
    s = body.lstrip()[:1]
    return s in ("{", "[")


def _links_from_html(base: str, body: str) -> list[str]:
    out = []
    for m in _HREF.findall(body):
        u = urljoin(base, m)
        if u.startswith("http"):
            out.append(u.split("#", 1)[0])
    return out


def _links_from_json(base: str, body: str) -> list[str]:
    """Harvest same-origin URLs/paths and construct collection/{id} item urls."""
    try:
        data = json.loads(body)
    except Exception:  # noqa: BLE001
        return []
    out: list[str] = []
    base_path = urlparse(base).path.rstrip("/")

    def walk(node):
        if isinstance(node, dict):
            for k, val in node.items():
                if _ID_KEY.search(k) and isinstance(val, (int, str)):
                    sval = str(val)
                    if _ID_SEG.match(sval):
                        # treat the seed's path as a collection -> /collection/{id}
                        out.append(urljoin(base.rstrip("/") + "/", sval))
                        out.append(base_path and urljoin(base, f"{base_path}/{sval}"))
                if isinstance(val, str) and (val.startswith("/") or val.startswith("http")):
                    out.append(urljoin(base, val.split("#", 1)[0]))
                walk(val)
        elif isinstance(node, list):
            for it in node:
                walk(it)

    walk(data)
    return [u for u in out if u]


def _is_cross_user_read(a: dict, v: dict, anon: dict) -> bool:
    if a.get("status") != 200 or v.get("status") != 200:
        return False
    ab, vb = a.get("body", "") or "", v.get("body", "") or ""
    if len(vb) < 16 or _LOGIN_HINT.search(ab[:400]):
        return False
    if ab != vb:
        return False
    anon_body = anon.get("body", "") or ""
    if anon.get("status") == 200 and anon_body == vb:
        return False  # public/login/error page shared by everyone
    return True
