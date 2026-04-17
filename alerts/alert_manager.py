"""Alert manager — dispatches alerts to all configured channels."""
from __future__ import annotations

import uuid
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from config.settings import get_settings
from storage.database import get_session
from storage.models import Actor, AlertLog, HoneypotEvent
from utils.logger import get_logger

logger = get_logger(__name__)
_settings = get_settings()

# Sliding window: ip -> deque of timestamps
_burst_windows: dict[str, deque] = defaultdict(deque)


class AlertManager:
    """Dispatch alerts to configured channels and manage burst detection."""

    def is_burst(self, ip: str) -> bool:
        """Return True if this IP has exceeded the burst threshold."""
        now = datetime.now(timezone.utc)
        window = timedelta(seconds=_settings.ALERT_BURST_WINDOW_SECONDS)
        dq = _burst_windows[ip]
        cutoff = now - window
        while dq and dq[0] < cutoff:
            dq.popleft()
        dq.append(now)
        return len(dq) >= _settings.ALERT_BURST_THRESHOLD

    async def send_alert(
        self, event: HoneypotEvent, actor: Optional[Actor] = None
    ) -> None:
        """Send alert to all configured channels if score crosses threshold."""
        if event.risk_score < 20:
            return

        if self.is_burst(event.source_ip):
            logger.warning("Burst detected for %s — suppressing duplicate alert", event.source_ip)
            return

        channels = _settings.alert_channels
        if not channels:
            logger.info(
                "No alert channels configured. Event %s risk=%s score=%d",
                event.id,
                event.risk_level,
                event.risk_score,
            )
            return

        for channel in channels:
            ok = await self._dispatch(channel, event)
            await self._log_alert(channel, event, ok)

    async def _dispatch(self, channel: str, event: HoneypotEvent) -> bool:
        try:
            if channel == "discord":
                from alerts.discord_alert import send_discord
                return await send_discord(event, _settings.DISCORD_WEBHOOK_URL)
            elif channel == "slack":
                from alerts.slack_alert import send_slack
                return await send_slack(event, _settings.SLACK_WEBHOOK_URL)
            elif channel == "email":
                from alerts.email_alert import send_email
                return await send_email(event, _settings)
        except Exception as exc:
            logger.error("Dispatch to %s failed: %s", channel, exc)
        return False

    async def _log_alert(
        self, channel: str, event: HoneypotEvent, ok: bool
    ) -> None:
        try:
            async with get_session() as db:
                log = AlertLog(
                    id=str(uuid.uuid4()),
                    alert_type="event_alert",
                    channel=channel,
                    target=event.source_ip,
                    message=f"risk={event.risk_level} score={event.risk_score} event={event.id}",
                    sent_ok=ok,
                )
                db.add(log)
        except Exception as exc:
            logger.error("Failed to log alert: %s", exc)

    async def send_daily_summary(self, db: AsyncSession) -> None:
        """Pull last 24h stats and dispatch summary to all channels."""
        since = datetime.now(timezone.utc) - timedelta(hours=24)

        total_result = await db.execute(
            select(func.count()).select_from(HoneypotEvent).where(
                HoneypotEvent.timestamp >= since
            )
        )
        total_hits = total_result.scalar() or 0

        new_actors_result = await db.execute(
            select(func.count()).select_from(Actor).where(Actor.first_seen >= since)
        )
        new_actors = new_actors_result.scalar() or 0

        risk_breakdown: dict[str, int] = {}
        for level in ("low", "medium", "high", "critical"):
            r = await db.execute(
                select(func.count()).select_from(HoneypotEvent).where(
                    HoneypotEvent.timestamp >= since,
                    HoneypotEvent.risk_level == level,
                )
            )
            risk_breakdown[level] = r.scalar() or 0

        summary = (
            f"📊 Daily Honeypot Summary\n"
            f"Total hits (24h): {total_hits}\n"
            f"New actors: {new_actors}\n"
            f"Risk breakdown: {risk_breakdown}"
        )
        logger.info(summary)

        channels = _settings.alert_channels
        for channel in channels:
            try:
                if channel == "discord" and _settings.DISCORD_WEBHOOK_URL:
                    import httpx
                    async with httpx.AsyncClient(timeout=10) as client:
                        await client.post(
                            _settings.DISCORD_WEBHOOK_URL,
                            json={"content": summary},
                        )
                elif channel == "slack" and _settings.SLACK_WEBHOOK_URL:
                    import httpx
                    async with httpx.AsyncClient(timeout=10) as client:
                        await client.post(
                            _settings.SLACK_WEBHOOK_URL,
                            json={"text": summary},
                        )
            except Exception as exc:
                logger.error("Daily summary to %s failed: %s", channel, exc)
