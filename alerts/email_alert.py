"""Email alert sender (async via aiosmtplib)."""
from __future__ import annotations

import asyncio
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from config.settings import Settings
from storage.models import HoneypotEvent
from utils.logger import get_logger

logger = get_logger(__name__)


def _build_html(event: HoneypotEvent) -> str:
    canary_label = event.canary_token.label if event.canary_token else "N/A"
    color_map = {
        "low": "#22C55E",
        "medium": "#EAB308",
        "high": "#F97316",
        "critical": "#EF4444",
    }
    badge_color = color_map.get(event.risk_level, "#A855F7")
    return f"""<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="font-family:Arial,sans-serif;background:#0a0e1a;color:#f1f5f9;padding:20px;">
  <div style="max-width:600px;margin:0 auto;background:#111827;border-radius:8px;overflow:hidden;">
    <div style="background:{badge_color};padding:16px 24px;">
      <h2 style="margin:0;color:#fff;">🍯 Honeypot Alert — {event.risk_level.upper()}</h2>
    </div>
    <div style="padding:24px;">
      <table style="width:100%;border-collapse:collapse;">
        <tr><td style="padding:8px;color:#9ca3af;">Source IP</td><td style="padding:8px;">{event.source_ip}</td></tr>
        <tr><td style="padding:8px;color:#9ca3af;">Country</td><td style="padding:8px;">{event.geo_country or "unknown"}</td></tr>
        <tr><td style="padding:8px;color:#9ca3af;">City</td><td style="padding:8px;">{event.geo_city or "unknown"}</td></tr>
        <tr><td style="padding:8px;color:#9ca3af;">Risk Score</td><td style="padding:8px;font-weight:bold;">{event.risk_score}</td></tr>
        <tr><td style="padding:8px;color:#9ca3af;">Event Type</td><td style="padding:8px;">{event.event_type}</td></tr>
        <tr><td style="padding:8px;color:#9ca3af;">Canary</td><td style="padding:8px;">{canary_label}</td></tr>
        <tr><td style="padding:8px;color:#9ca3af;">Path</td><td style="padding:8px;">{event.path or "N/A"}</td></tr>
        <tr><td style="padding:8px;color:#9ca3af;">User-Agent</td><td style="padding:8px;word-break:break-all;">{(event.user_agent or "N/A")[:300]}</td></tr>
        <tr><td style="padding:8px;color:#9ca3af;">Timestamp</td><td style="padding:8px;">{event.timestamp.isoformat() if event.timestamp else "N/A"}</td></tr>
      </table>
    </div>
    <div style="padding:12px 24px;background:#1f2937;font-size:12px;color:#6b7280;">
      GitHub Honeypot Monitor — Authorized Defensive Research Only
    </div>
  </div>
</body>
</html>"""


def _send_email_sync(event: HoneypotEvent, settings: Settings) -> bool:
    """Send email synchronously (run in thread executor)."""
    msg = MIMEMultipart("alternative")
    msg["Subject"] = (
        f"[HONEYPOT ALERT] Risk: {event.risk_level.upper()} — IP: {event.source_ip}"
    )
    msg["From"] = settings.EMAIL_USER
    msg["To"] = settings.EMAIL_TO

    html_part = MIMEText(_build_html(event), "html")
    msg.attach(html_part)

    with smtplib.SMTP(settings.EMAIL_HOST, settings.EMAIL_PORT) as smtp:
        smtp.starttls()
        smtp.login(settings.EMAIL_USER, settings.EMAIL_PASS)
        smtp.sendmail(settings.EMAIL_USER, settings.EMAIL_TO, msg.as_string())
    return True


async def send_email(event: HoneypotEvent, settings: Settings) -> bool:
    """Async wrapper: sends email in a thread executor to avoid blocking."""
    try:
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, _send_email_sync, event, settings)
        return True
    except Exception as exc:
        logger.error("Email send error: %s", exc)
        return False
