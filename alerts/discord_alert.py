"""Discord alert sender."""
from __future__ import annotations

from datetime import timezone
from typing import Optional

import httpx

from storage.models import HoneypotEvent
from utils.logger import get_logger

logger = get_logger(__name__)

_RISK_COLORS = {
    "low": 0x22C55E,       # green
    "medium": 0xEAB308,    # yellow
    "high": 0xF97316,      # orange
    "critical": 0xEF4444,  # red
}


async def send_discord(event: HoneypotEvent, webhook_url: str) -> bool:
    """Send a rich Discord embed for a honeypot event."""
    color = _RISK_COLORS.get(event.risk_level, 0xA855F7)
    ts = event.timestamp.isoformat() if event.timestamp else "unknown"

    canary_label = "N/A"
    if event.canary_token:
        canary_label = event.canary_token.label

    embed = {
        "title": f"🍯 Honeypot Alert — {event.risk_level.upper()}",
        "color": color,
        "timestamp": ts,
        "fields": [
            {"name": "🌐 Source IP", "value": event.source_ip or "unknown", "inline": True},
            {"name": "🗺️ Country", "value": event.geo_country or "unknown", "inline": True},
            {"name": "🏙️ City", "value": event.geo_city or "unknown", "inline": True},
            {"name": "🎯 Risk Score", "value": str(event.risk_score), "inline": True},
            {"name": "📌 Risk Level", "value": event.risk_level.upper(), "inline": True},
            {"name": "🪤 Canary", "value": canary_label, "inline": True},
            {"name": "🔍 User-Agent", "value": (event.user_agent or "N/A")[:200], "inline": False},
            {"name": "📋 Event Type", "value": event.event_type, "inline": True},
            {"name": "🔗 Path", "value": (event.path or "N/A")[:200], "inline": True},
        ],
        "footer": {"text": "GitHub Honeypot Monitor"},
    }

    payload = {"embeds": [embed]}
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(webhook_url, json=payload)
            if resp.status_code in (200, 204):
                return True
            logger.warning("Discord webhook returned %d", resp.status_code)
            return False
    except Exception as exc:
        logger.error("Discord send error: %s", exc)
        return False
