"""SQLAlchemy models for the honeypot system."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy import (
    Boolean,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Integer,
    JSON,
    String,
    Text,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _new_uuid() -> str:
    return str(uuid.uuid4())


class Base(DeclarativeBase):
    pass


# ---------------------------------------------------------------------------
# Enums (stored as strings)
# ---------------------------------------------------------------------------
EventTypeEnum = Enum(
    "canary_hit", "webhook", "direct_access", "bait_request", name="event_type_enum"
)
RiskLevelEnum = Enum("low", "medium", "high", "critical", name="risk_level_enum")
BaitTypeEnum = Enum(
    "env_file", "config", "pat", "ci_cd", "api_doc", "webhook", "custom",
    name="bait_type_enum",
)


# ---------------------------------------------------------------------------
# CanaryToken
# ---------------------------------------------------------------------------
class CanaryToken(Base):
    __tablename__ = "canary_tokens"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_new_uuid)
    token: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    label: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    bait_type: Mapped[str] = mapped_column(BaitTypeEnum, nullable=False, default="custom")
    url: Mapped[Optional[str]] = mapped_column(String(1024), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow
    )
    last_hit: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    hit_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    events: Mapped[list["HoneypotEvent"]] = relationship(
        "HoneypotEvent", back_populates="canary_token", lazy="select"
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "token": self.token,
            "label": self.label,
            "description": self.description,
            "bait_type": self.bait_type,
            "url": self.url,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "last_hit": self.last_hit.isoformat() if self.last_hit else None,
            "hit_count": self.hit_count,
            "is_active": self.is_active,
        }


# ---------------------------------------------------------------------------
# Actor
# ---------------------------------------------------------------------------
class Actor(Base):
    __tablename__ = "actors"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_new_uuid)
    ip_address: Mapped[str] = mapped_column(String(45), unique=True, nullable=False)
    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow
    )
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, onupdate=_utcnow
    )
    total_hits: Mapped[int] = mapped_column(Integer, default=0)
    canaries_hit: Mapped[int] = mapped_column(Integer, default=0)
    risk_score_avg: Mapped[float] = mapped_column(Float, default=0.0)
    risk_level: Mapped[str] = mapped_column(
        RiskLevelEnum, nullable=False, default="low"
    )
    tags: Mapped[Optional[list]] = mapped_column(JSON, default=list)
    is_blocklisted: Mapped[bool] = mapped_column(Boolean, default=False)
    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    events: Mapped[list["HoneypotEvent"]] = relationship(
        "HoneypotEvent", back_populates="actor", lazy="select"
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "ip_address": self.ip_address,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "total_hits": self.total_hits,
            "canaries_hit": self.canaries_hit,
            "risk_score_avg": self.risk_score_avg,
            "risk_level": self.risk_level,
            "tags": self.tags or [],
            "is_blocklisted": self.is_blocklisted,
            "notes": self.notes,
        }


# ---------------------------------------------------------------------------
# HoneypotEvent
# ---------------------------------------------------------------------------
class HoneypotEvent(Base):
    __tablename__ = "honeypot_events"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_new_uuid)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, index=True
    )
    source_ip: Mapped[str] = mapped_column(String(45), nullable=False, index=True)
    user_agent: Mapped[Optional[str]] = mapped_column(String(1024), nullable=True)
    method: Mapped[Optional[str]] = mapped_column(String(16), nullable=True)
    path: Mapped[Optional[str]] = mapped_column(String(2048), nullable=True)
    referrer: Mapped[Optional[str]] = mapped_column(String(1024), nullable=True)
    headers_json: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)

    canary_token_id: Mapped[Optional[str]] = mapped_column(
        String(36), ForeignKey("canary_tokens.id"), nullable=True
    )
    event_type: Mapped[str] = mapped_column(
        EventTypeEnum, nullable=False, default="direct_access"
    )
    risk_score: Mapped[int] = mapped_column(Integer, default=0)
    risk_level: Mapped[str] = mapped_column(
        RiskLevelEnum, nullable=False, default="low"
    )

    # Geo
    geo_country: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    geo_city: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    geo_asn: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    geo_isp: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    # UA analysis
    ua_is_bot: Mapped[bool] = mapped_column(Boolean, default=False)
    ua_browser: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    ua_os: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)

    # Threat intel
    abuseipdb_score: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    greynoise_classification: Mapped[Optional[str]] = mapped_column(
        String(64), nullable=True
    )

    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    actor_id: Mapped[Optional[str]] = mapped_column(
        String(36), ForeignKey("actors.id"), nullable=True
    )

    canary_token: Mapped[Optional[CanaryToken]] = relationship(
        "CanaryToken", back_populates="events"
    )
    actor: Mapped[Optional[Actor]] = relationship("Actor", back_populates="events")

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "source_ip": self.source_ip,
            "user_agent": self.user_agent,
            "method": self.method,
            "path": self.path,
            "referrer": self.referrer,
            "headers_json": self.headers_json,
            "canary_token_id": self.canary_token_id,
            "event_type": self.event_type,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "geo_country": self.geo_country,
            "geo_city": self.geo_city,
            "geo_asn": self.geo_asn,
            "geo_isp": self.geo_isp,
            "ua_is_bot": self.ua_is_bot,
            "ua_browser": self.ua_browser,
            "ua_os": self.ua_os,
            "abuseipdb_score": self.abuseipdb_score,
            "greynoise_classification": self.greynoise_classification,
            "notes": self.notes,
            "actor_id": self.actor_id,
            "canary_label": self.canary_token.label if self.canary_token else None,
        }


# ---------------------------------------------------------------------------
# AlertLog
# ---------------------------------------------------------------------------
class AlertLog(Base):
    __tablename__ = "alert_logs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_new_uuid)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow
    )
    alert_type: Mapped[str] = mapped_column(String(64), nullable=False)
    channel: Mapped[str] = mapped_column(String(64), nullable=False)
    target: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    sent_ok: Mapped[bool] = mapped_column(Boolean, default=False)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "alert_type": self.alert_type,
            "channel": self.channel,
            "target": self.target,
            "message": self.message,
            "sent_ok": self.sent_ok,
        }
