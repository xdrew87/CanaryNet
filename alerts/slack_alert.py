"""Slack alert sender (Block Kit)."""
from __future__ import annotations

import httpx

from storage.models import HoneypotEvent
from utils.logger import get_logger

logger = get_logger(__name__)

_RISK_EMOJIS = {
    "low": ":large_green_circle:",
    "medium": ":large_yellow_circle:",
    "high": ":large_orange_circle:",
    "critical": ":red_circle:",
}


async def send_slack(event: HoneypotEvent, webhook_url: str) -> bool:
    """Send a Slack Block Kit message for a honeypot event."""
    emoji = _RISK_EMOJIS.get(event.risk_level, ":purple_circle:")
    canary_label = event.canary_token.label if event.canary_token else "N/A"

    blocks = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"🍯 Honeypot Alert {emoji} — {event.risk_level.upper()}",
            },
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Source IP:*\n{event.source_ip}"},
                {"type": "mrkdwn", "text": f"*Country:*\n{event.geo_country or 'unknown'}"},
                {"type": "mrkdwn", "text": f"*Risk Score:*\n{event.risk_score}"},
                {"type": "mrkdwn", "text": f"*Canary:*\n{canary_label}"},
                {"type": "mrkdwn", "text": f"*Event Type:*\n{event.event_type}"},
                {"type": "mrkdwn", "text": f"*City:*\n{event.geo_city or 'unknown'}"},
            ],
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*User-Agent:*\n```{(event.user_agent or 'N/A')[:300]}```",
            },
        },
        {"type": "divider"},
        {
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": f"GitHub Honeypot Monitor | {event.timestamp.isoformat() if event.timestamp else 'N/A'}",
                }
            ],
        },
    ]

    payload = {"blocks": blocks}
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(webhook_url, json=payload)
            if resp.status_code in (200, 204):
                return True
            logger.warning("Slack webhook returned %d: %s", resp.status_code, resp.text)
            return False
    except Exception as exc:
        logger.error("Slack send error: %s", exc)
        return False
