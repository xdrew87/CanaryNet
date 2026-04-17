"""Actors API routes."""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from storage.database import get_db
from storage.exporter import export_events_json
from storage.models import Actor, HoneypotEvent

router = APIRouter(prefix="/api/actors", tags=["actors"])


@router.get("")
async def list_actors(
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    risk_level: Optional[str] = None,
    is_blocklisted: Optional[bool] = None,
    db: AsyncSession = Depends(get_db),
):
    """List actor profiles."""
    stmt = select(Actor).order_by(Actor.last_seen.desc())
    if risk_level:
        stmt = stmt.where(Actor.risk_level == risk_level)
    if is_blocklisted is not None:
        stmt = stmt.where(Actor.is_blocklisted == is_blocklisted)

    total = (await db.execute(select(func.count()).select_from(stmt.subquery()))).scalar() or 0
    stmt = stmt.limit(limit).offset(offset)
    result = await db.execute(stmt)
    actors = result.scalars().all()
    return {"total": total, "limit": limit, "offset": offset, "items": [a.to_dict() for a in actors]}


@router.get("/{actor_id}")
async def get_actor(actor_id: str, db: AsyncSession = Depends(get_db)):
    """Get actor detail with their events."""
    result = await db.execute(
        select(Actor)
        .options(selectinload(Actor.events))
        .where(Actor.id == actor_id)
    )
    actor = result.scalar_one_or_none()
    if not actor:
        raise HTTPException(status_code=404, detail="Actor not found")
    data = actor.to_dict()
    data["events"] = [e.to_dict() for e in actor.events[:100]]
    return data


@router.post("/{actor_id}/blocklist")
async def toggle_blocklist(actor_id: str, db: AsyncSession = Depends(get_db)):
    """Toggle blocklist status for an actor."""
    result = await db.execute(select(Actor).where(Actor.id == actor_id))
    actor = result.scalar_one_or_none()
    if not actor:
        raise HTTPException(status_code=404, detail="Actor not found")
    actor.is_blocklisted = not actor.is_blocklisted
    return {"id": actor_id, "is_blocklisted": actor.is_blocklisted}


@router.post("/{actor_id}/tag")
async def add_tag(actor_id: str, tag: str, db: AsyncSession = Depends(get_db)):
    """Add a tag to an actor."""
    result = await db.execute(select(Actor).where(Actor.id == actor_id))
    actor = result.scalar_one_or_none()
    if not actor:
        raise HTTPException(status_code=404, detail="Actor not found")
    tags = list(actor.tags or [])
    if tag not in tags:
        tags.append(tag)
        actor.tags = tags
    return {"id": actor_id, "tags": actor.tags}


@router.get("/{actor_id}/export")
async def export_actor_events(actor_id: str, db: AsyncSession = Depends(get_db)):
    """Export all events for an actor as JSON."""
    from fastapi.responses import Response

    result = await db.execute(
        select(Actor).options(selectinload(Actor.events)).where(Actor.id == actor_id)
    )
    actor = result.scalar_one_or_none()
    if not actor:
        raise HTTPException(status_code=404, detail="Actor not found")

    json_str = export_events_json(actor.events)
    return Response(
        content=json_str,
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="actor_{actor_id}_events.json"'},
    )
