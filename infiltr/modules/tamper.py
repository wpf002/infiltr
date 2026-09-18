"""Native parameter-tampering detection for money/quantity fields (single target).

Deterministic signal, not a guess: for a target URL that already carries a
money/quantity parameter (price, amount, qty, total, discount, ...), we send a
distinctive out-of-bounds value (a negative sentinel) and check whether the
server ACCEPTS and REFLECTS it. Confirmation requires: the baseline request
(original value) returns 200, the tampered request returns 200, the tampered
response introduces no new validation-error text the baseline lacked, and the
distinctive tampered value appears in the tampered body but not the baseline
body. Reflection of a client-controlled negative price/quantity is a strong
lead that the server trusts the value; final business impact (does checkout
honor it?) still needs a human, so this is reported as a lead, not auto-confirmed.

Uses the scan auth so it tests the value the logged-in user would send. If the
target has no money/quantity parameter, the module reports nothing.
"""
from __future__ import annotations

import re
from urllib.parse import urlparse, urlencode, parse_qsl, urlunparse

from ..base import NativeWrapper, Finding, SEV_INFO, SEV_MEDIUM
from ..webutil import fetch

# client-controlled fields whose value should be validated server-side
_MONEY = {"price", "amount", "cost", "total", "subtotal", "discount", "balance",
          "credit", "fee", "unit_price", "unitprice"}
_QTY = {"qty", "quantity", "count", "quantities", "num", "points", "items"}
# a new occurrence of any of these in the tampered body (absent from baseline)
# means the server rejected the value — so it is NOT accepted.
_ERROR = re.compile(
    r"(invalid|must be|cannot be|not allowed|negative|out of range|"
    r"greater than|less than|required|exception|error|denied|rejected)",
    re.I,
)
# distinctive sentinels so reflection is unambiguous (won't appear by chance)
_MONEY_SENTINEL = "-13.37"
_QTY_SENTINEL = "-1337"


class TamperWrapper(NativeWrapper):
    MODULE_NAME = "tamper"
    CATEGORY = "web"
    DESCRIPTION = "Price/quantity tampering: server accepts & reflects a negative money/qty value"
    VERSION = "1.0"
    DEFAULT_TIMEOUT = 45

    def collect(self, target: str) -> list[Finding]:
        timeout = int(self.options.get("timeout", 15))
        auth = self.auth_headers()
        p = urlparse(target)
        params = dict(parse_qsl(p.query))
        targets = [(k, v) for k, v in params.items() if _classify(k)]

        if not targets:
            return [Finding(type="note", name="tamper", value="no money/qty param",
                            detail="target has no price/amount/qty parameter to tamper",
                            severity=SEV_INFO, metadata={"url": target})]

        baseline = fetch(target, timeout=timeout, headers=auth)
        findings: list[Finding] = []
        for name, _orig in targets:
            sentinel = _MONEY_SENTINEL if _classify(name) == "money" else _QTY_SENTINEL
            tampered_url = _with_param(p, params, name, sentinel)
            resp = fetch(tampered_url, timeout=timeout, headers=auth)
            if self._accepted(baseline, resp, sentinel):
                findings.append(Finding(
                    type="tamper", name=f"Parameter tampering via '{name}'", value=tampered_url,
                    detail=f"server accepted and reflected a negative value ({sentinel}) for '{name}' — verify checkout honors it",
                    severity=SEV_MEDIUM,
                    metadata={"url": tampered_url, "matched_at": tampered_url, "param": name,
                              "sentinel": sentinel, "confidence": 0.6, "confirmed": False}))

        if not findings:
            findings.append(Finding(type="note", name="tamper", value="not accepted",
                                    detail="no money/qty parameter accepted and reflected a negative value",
                                    severity=SEV_INFO, metadata={"url": target}))
        return findings

    def summarize(self, findings: list[Finding]) -> str:
        n = sum(1 for f in findings if f.type == "tamper")
        return f"{n} tampering lead(s)." if n else "No tampering accepted."

    @staticmethod
    def _accepted(baseline: dict, tampered: dict, sentinel: str) -> bool:
        if baseline.get("status") != 200 or tampered.get("status") != 200:
            return False
        bb = baseline.get("body", "") or ""
        tb = tampered.get("body", "") or ""
        # the tampered value must be echoed back (server took the client value)...
        if sentinel not in tb or sentinel in bb:
            return False
        # ...and the tampered response must not have introduced a validation error
        # that the baseline didn't already show.
        base_errs = set(m.lower() for m in _ERROR.findall(bb))
        tamp_errs = set(m.lower() for m in _ERROR.findall(tb))
        if tamp_errs - base_errs:
            return False
        return True


def _classify(name: str) -> str | None:
    n = name.lower()
    if n in _MONEY:
        return "money"
    if n in _QTY:
        return "qty"
    return None


def _with_param(p, params: dict, name: str, value: str) -> str:
    q = dict(params)
    q[name] = value
    return urlunparse(p._replace(query=urlencode(q)))
