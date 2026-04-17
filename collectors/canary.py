"""Canary token manager."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from config.settings import get_settings
from storage.models import CanaryToken, HoneypotEvent
from utils.logger import get_logger

logger = get_logger(__name__)
_settings = get_settings()


class CanaryManager:
    """Create and manage canary tokens, record hits."""

    def __init__(self, db: AsyncSession) -> None:
        self.db = db

    async def generate_token(
        self,
        label: str,
        bait_type: str = "custom",
        description: Optional[str] = None,
    ) -> CanaryToken:
        """Create a new canary token and persist it."""
        token_value = uuid.uuid4().hex[:16]
        token = CanaryToken(
            id=str(uuid.uuid4()),
            token=token_value,
            label=label,
            bait_type=bait_type,
            description=description,
            url=self.build_url(token_value),
        )
        self.db.add(token)
        await self.db.flush()
        logger.info("Created canary token %s (%s)", token_value, label)
        return token

    def build_url(self, token: str) -> str:
        """Return the full tracking URL for a token."""
        return f"{_settings.CANARY_BASE_URL}/track/{token}"

    async def record_hit(
        self, token: str, request_info: dict
    ) -> Optional[HoneypotEvent]:
        """Log a canary hit, update counters, return the created event."""
        try:
            result = await self.db.execute(
                select(CanaryToken).where(CanaryToken.token == token)
            )
            canary = result.scalar_one_or_none()

            event = HoneypotEvent(
                id=str(uuid.uuid4()),
                source_ip=request_info.get("source_ip", "0.0.0.0"),
                user_agent=request_info.get("user_agent"),
                method=request_info.get("method", "GET"),
                path=request_info.get("path", f"/track/{token}"),
                referrer=request_info.get("referrer"),
                headers_json=request_info.get("headers", {}),
                event_type="canary_hit",
                canary_token_id=canary.id if canary else None,
            )
            self.db.add(event)

            if canary:
                canary.hit_count += 1
                canary.last_hit = datetime.now(timezone.utc)

            await self.db.flush()
            logger.info("Canary hit recorded: token=%s ip=%s", token, event.source_ip)
            return event
        except Exception as exc:
            logger.error("Error recording canary hit: %s", exc)
            return None

    async def list_tokens(self) -> list[CanaryToken]:
        """Return all canary tokens."""
        result = await self.db.execute(select(CanaryToken).order_by(CanaryToken.created_at.desc()))
        return list(result.scalars().all())

    async def deactivate_token(self, token_id: str) -> bool:
        """Deactivate a token by ID."""
        result = await self.db.execute(
            select(CanaryToken).where(CanaryToken.id == token_id)
        )
        token = result.scalar_one_or_none()
        if not token:
            return False
        token.is_active = False
        await self.db.flush()
        return True

    async def get_stats(self) -> dict:
        """Return summary stats about canary tokens."""
        all_tokens = await self.list_tokens()
        active = [t for t in all_tokens if t.is_active]
        total_hits = sum(t.hit_count for t in all_tokens)
        top = max(all_tokens, key=lambda t: t.hit_count, default=None)
        return {
            "total_tokens": len(all_tokens),
            "active_tokens": len(active),
            "total_hits": total_hits,
            "top_token": top.to_dict() if top else None,
        }
