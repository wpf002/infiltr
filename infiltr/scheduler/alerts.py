"""Alert delivery for monitoring: webhook, Slack, email.

Dependency-free: webhook/Slack use urllib; email uses smtplib or a SendGrid HTTP
call when configured. Every sender is best-effort and never raises into the
scheduler loop.
"""
from __future__ import annotations

import json
import os
import smtplib
import urllib.request
from email.mime.text import MIMEText
from typing import Any


def _post_json(url: str, payload: dict[str, Any], timeout: int = 10) -> bool:
    data = json.dumps(payload).encode()
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 (config-provided URL)
            return 200 <= resp.status < 300
    except Exception:  # noqa: BLE001
        return False


def send_webhook(url: str, event: dict[str, Any]) -> bool:
    return _post_json(url, event)


def send_slack(webhook_url: str, text: str) -> bool:
    return _post_json(webhook_url, {"text": text})


def send_email(to_addr: str, subject: str, body: str) -> bool:
    # SendGrid HTTP API if configured
    sg_key = os.environ.get("SENDGRID_API_KEY")
    from_addr = os.environ.get("INFILTR_ALERT_FROM", "infiltr@localhost")
    if sg_key:
        payload = {
            "personalizations": [{"to": [{"email": to_addr}]}],
            "from": {"email": from_addr},
            "subject": subject,
            "content": [{"type": "text/plain", "value": body}],
        }
        req = urllib.request.Request(
            "https://api.sendgrid.com/v3/mail/send",
            data=json.dumps(payload).encode(),
            headers={"Authorization": f"Bearer {sg_key}", "Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:  # noqa: S310
                return 200 <= resp.status < 300
        except Exception:  # noqa: BLE001
            return False
    # else fall back to SMTP if configured
    host = os.environ.get("SMTP_HOST")
    if not host:
        return False
    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = from_addr
    msg["To"] = to_addr
    try:
        with smtplib.SMTP(host, int(os.environ.get("SMTP_PORT", "25")), timeout=10) as smtp:
            user, pw = os.environ.get("SMTP_USER"), os.environ.get("SMTP_PASS")
            if user and pw:
                smtp.starttls()
                smtp.login(user, pw)
            smtp.send_message(msg)
        return True
    except Exception:  # noqa: BLE001
        return False


def dispatch_alerts(alerts: dict[str, Any], summary: dict[str, Any]) -> dict[str, bool]:
    """Fire every configured channel for a delta summary. Returns per-channel status."""
    target = summary.get("target")
    new_count = summary.get("new_count", 0)
    scan_id = summary.get("scan_id")
    text = (
        f"[Infiltr] {new_count} new finding(s) on {target} "
        f"(scan #{scan_id}, modules: {', '.join(summary.get('new_modules', [])) or '—'})"
    )
    results: dict[str, bool] = {}
    if alerts.get("webhook"):
        results["webhook"] = send_webhook(alerts["webhook"], {"text": text, **summary})
    if alerts.get("slack"):
        results["slack"] = send_slack(alerts["slack"], text)
    if alerts.get("email"):
        results["email"] = send_email(alerts["email"], f"Infiltr: {new_count} new on {target}", text)
    return results
