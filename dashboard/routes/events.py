"""Events API routes."""
from __future__ import annotations

from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from storage.database import get_db
from storage.models import HoneypotEvent

router = APIRouter(prefix="/api/events", tags=["events"])


@router.get("")
async def list_events(
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    ip: Optional[str] = None,
    risk_level: Optional[str] = None,
    start_date: Optional[datetime] = None,
    end_date: Optional[datetime] = None,
    db: AsyncSession = Depends(get_db),
):
    """List honeypot events with optional filters."""
    stmt = (
        select(HoneypotEvent)
        .options(selectinload(HoneypotEvent.canary_token))
        .order_by(HoneypotEvent.timestamp.desc())
    )
    if ip:
        stmt = stmt.where(HoneypotEvent.source_ip == ip)
    if risk_level:
        stmt = stmt.where(HoneypotEvent.risk_level == risk_level)
    if start_date:
        stmt = stmt.where(HoneypotEvent.timestamp >= start_date)
    if end_date:
        stmt = stmt.where(HoneypotEvent.timestamp <= end_date)

    total_stmt = select(func.count()).select_from(stmt.subquery())
    total_result = await db.execute(total_stmt)
    total = total_result.scalar() or 0

    stmt = stmt.limit(limit).offset(offset)
    result = await db.execute(stmt)
    events = result.scalars().all()

    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "items": [e.to_dict() for e in events],
    }


@router.get("/stats")
async def get_event_stats(db: AsyncSession = Depends(get_db)):
    """Return summary statistics for the dashboard."""
    total = (await db.execute(select(func.count()).select_from(HoneypotEvent))).scalar() or 0

    risk_breakdown: dict[str, int] = {}
    for level in ("low", "medium", "high", "critical"):
        count = (
            await db.execute(
                select(func.count()).select_from(HoneypotEvent).where(
                    HoneypotEvent.risk_level == level
                )
            )
        ).scalar() or 0
        risk_breakdown[level] = count

    # Top 5 IPs by event count
    top_ips_result = await db.execute(
        select(HoneypotEvent.source_ip, func.count().label("cnt"))
        .group_by(HoneypotEvent.source_ip)
        .order_by(func.count().desc())
        .limit(5)
    )
    top_ips = [{"ip": row[0], "count": row[1]} for row in top_ips_result]

    # Events per day — last 30 days
    from sqlalchemy import cast, Date
    daily_result = await db.execute(
        select(
            cast(HoneypotEvent.timestamp, Date).label("day"),
            func.count().label("cnt"),
        )
        .group_by("day")
        .order_by("day")
        .limit(30)
    )
    daily = [{"date": str(row[0]), "count": row[1]} for row in daily_result]

    # Unique IPs
    unique_ips = (
        await db.execute(
            select(func.count(func.distinct(HoneypotEvent.source_ip)))
        )
    ).scalar() or 0

    return {
        "total_events": total,
        "unique_ips": unique_ips,
        "risk_breakdown": risk_breakdown,
        "daily_events": daily,
        "top_ips": top_ips,
    }


@router.get("/{event_id}")
async def get_event(event_id: str, db: AsyncSession = Depends(get_db)):
    """Get a single event by ID."""
    result = await db.execute(
        select(HoneypotEvent)
        .options(selectinload(HoneypotEvent.canary_token), selectinload(HoneypotEvent.actor))
        .where(HoneypotEvent.id == event_id)
    )
    event = result.scalar_one_or_none()
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")
    return event.to_dict()


@router.delete("/{event_id}")
async def delete_event(event_id: str, db: AsyncSession = Depends(get_db)):
    """Delete a single event (admin)."""
    result = await db.execute(
        select(HoneypotEvent).where(HoneypotEvent.id == event_id)
    )
    event = result.scalar_one_or_none()
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")
    await db.delete(event)
    return {"deleted": event_id}
