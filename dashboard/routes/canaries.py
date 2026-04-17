"""Canaries API routes."""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from collectors.canary import CanaryManager
from storage.database import get_db
from storage.exporter import export_events_csv
from storage.models import CanaryToken, HoneypotEvent

router = APIRouter(prefix="/api/canaries", tags=["canaries"])


class CreateCanaryRequest(BaseModel):
    label: str
    bait_type: str = "custom"
    description: Optional[str] = None


@router.get("")
async def list_canaries(db: AsyncSession = Depends(get_db)):
    """List all canary tokens."""
    manager = CanaryManager(db)
    tokens = await manager.list_tokens()
    return {"items": [t.to_dict() for t in tokens]}


@router.post("")
async def create_canary(body: CreateCanaryRequest, db: AsyncSession = Depends(get_db)):
    """Create a new canary token."""
    manager = CanaryManager(db)
    token = await manager.generate_token(
        label=body.label,
        bait_type=body.bait_type,
        description=body.description,
    )
    return token.to_dict()


@router.get("/export")
async def export_canaries(db: AsyncSession = Depends(get_db)):
    """Export all canary stats as CSV."""
    result = await db.execute(
        select(CanaryToken)
        .options(selectinload(CanaryToken.events))
        .order_by(CanaryToken.created_at.desc())
    )
    tokens = result.scalars().all()
    import csv, io

    buf = io.StringIO()
    writer = csv.DictWriter(
        buf,
        fieldnames=["id", "token", "label", "bait_type", "url", "hit_count", "last_hit", "is_active", "created_at"],
    )
    writer.writeheader()
    for t in tokens:
        writer.writerow(t.to_dict())

    return Response(
        content=buf.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="canaries.csv"'},
    )


@router.get("/{canary_id}")
async def get_canary(canary_id: str, db: AsyncSession = Depends(get_db)):
    """Get canary detail with hit history."""
    result = await db.execute(
        select(CanaryToken)
        .options(selectinload(CanaryToken.events))
        .where(CanaryToken.id == canary_id)
    )
    token = result.scalar_one_or_none()
    if not token:
        raise HTTPException(status_code=404, detail="Canary token not found")
    data = token.to_dict()
    data["events"] = [e.to_dict() for e in token.events[:100]]
    return data


@router.delete("/{canary_id}")
async def deactivate_canary(canary_id: str, db: AsyncSession = Depends(get_db)):
    """Deactivate a canary token."""
    manager = CanaryManager(db)
    ok = await manager.deactivate_token(canary_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Canary token not found")
    return {"deactivated": canary_id}
