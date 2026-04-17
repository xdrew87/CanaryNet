"""FastAPI webhook receiver router."""
from __future__ import annotations

import hashlib
import hmac
import json
import uuid
from typing import Optional

from fastapi import APIRouter, BackgroundTasks, Header, HTTPException, Request, Response
from fastapi.responses import RedirectResponse

from config.settings import get_settings
from storage.database import get_session
from storage.models import HoneypotEvent
from utils.helpers import headers_to_dict
from utils.logger import get_logger

logger = get_logger(__name__)
_settings = get_settings()

router = APIRouter(prefix="/webhook", tags=["webhooks"])


def _get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "0.0.0.0"


# ---------------------------------------------------------------------------
# GitHub webhook receiver
# ---------------------------------------------------------------------------
@router.post("/github")
async def receive_github_webhook(
    request: Request,
    background_tasks: BackgroundTasks,
    x_hub_signature_256: Optional[str] = Header(default=None),
    x_github_event: Optional[str] = Header(default=None),
):
    """Receive and validate GitHub webhook events."""
    body = await request.body()

    # Validate HMAC signature
    if _settings.WEBHOOK_SECRET and _settings.WEBHOOK_SECRET != "change-this-webhook-secret":
        if not x_hub_signature_256:
            logger.warning("GitHub webhook missing signature")
            return Response(content='{"status":"ok"}', media_type="application/json")

        expected = "sha256=" + hmac.HMAC(
            _settings.WEBHOOK_SECRET.encode(),
            body,
            hashlib.sha256,
        ).hexdigest()
        if not hmac.compare_digest(expected, x_hub_signature_256):
            logger.warning("GitHub webhook signature mismatch")
            return Response(content='{"status":"ok"}', media_type="application/json")

    try:
        payload = json.loads(body)
    except Exception:
        payload = {}

    source_ip = _get_client_ip(request)
    sender = payload.get("sender", {}).get("login", "unknown")
    repo = payload.get("repository", {}).get("full_name", "unknown")
    action = payload.get("action", "unknown")

    background_tasks.add_task(
        _log_github_event,
        source_ip=source_ip,
        user_agent=request.headers.get("User-Agent"),
        event_type_str=x_github_event or "unknown",
        sender=sender,
        repo=repo,
        action=action,
        headers=headers_to_dict(dict(request.headers)),
    )
    return Response(content='{"status":"ok"}', media_type="application/json")


async def _log_github_event(
    source_ip: str,
    user_agent: Optional[str],
    event_type_str: str,
    sender: str,
    repo: str,
    action: str,
    headers: dict,
) -> None:
    try:
        async with get_session() as db:
            event = HoneypotEvent(
                id=str(uuid.uuid4()),
                source_ip=source_ip,
                user_agent=user_agent,
                method="POST",
                path="/webhook/github",
                headers_json=headers,
                event_type="webhook",
                notes=f"GitHub event={event_type_str} sender={sender} repo={repo} action={action}",
            )
            db.add(event)
    except Exception as exc:
        logger.error("Error logging GitHub webhook event: %s", exc)


# ---------------------------------------------------------------------------
# Canary hit via POST
# ---------------------------------------------------------------------------
@router.post("/canary/{token}")
async def canary_post_hit(
    token: str,
    request: Request,
    background_tasks: BackgroundTasks,
):
    """Record a POST-based canary hit. Always returns 200."""
    try:
        background_tasks.add_task(_process_canary_hit, token, request)
    except Exception as exc:
        logger.error("Canary POST hit error: %s", exc)
    return {"status": "ok"}


# ---------------------------------------------------------------------------
# Canary hit via GET (redirect)
# ---------------------------------------------------------------------------
@router.get("/track/{token}", include_in_schema=False)
async def canary_get_hit(
    token: str,
    request: Request,
    background_tasks: BackgroundTasks,
):
    """Record a GET-based canary hit, then return a neutral 404-like page."""
    try:
        background_tasks.add_task(_process_canary_hit, token, request)
    except Exception as exc:
        logger.error("Canary GET hit error: %s", exc)
    return Response(content="Not Found", status_code=404)


async def _process_canary_hit(token: str, request: Request) -> None:
    """Background task: enrich and persist the canary hit."""
    try:
        from collectors.canary import CanaryManager

        request_info = {
            "source_ip": _get_client_ip(request),
            "user_agent": request.headers.get("User-Agent"),
            "method": request.method,
            "path": str(request.url.path),
            "referrer": request.headers.get("Referer"),
            "headers": headers_to_dict(dict(request.headers)),
        }
        async with get_session() as db:
            manager = CanaryManager(db)
            event = await manager.record_hit(token, request_info)
            if event:
                await _enrich_and_alert(event, db)
    except Exception as exc:
        logger.error("Error processing canary hit: %s", exc)


async def _enrich_and_alert(event: HoneypotEvent, db) -> None:
    """Run enrichment and fire alerts for a recorded event."""
    try:
        from enrichers.ip_enricher import IPEnricher
        from enrichers.ua_fingerprint import UAFingerprinter
        from enrichers.risk_scorer import RiskScorer
        from alerts.alert_manager import AlertManager

        enricher = IPEnricher()
        geo = await enricher.enrich(event.source_ip)

        ua_info = UAFingerprinter().analyze(event.user_agent or "")

        event_data = {
            "source_ip": event.source_ip,
            "referrer": event.referrer,
            "canary_hits": 1,
        }
        scorer = RiskScorer()
        score, level = scorer.score(event_data, {**geo, **ua_info})

        event.geo_country = geo.get("country")
        event.geo_city = geo.get("city")
        event.geo_asn = geo.get("asn")
        event.geo_isp = geo.get("isp")
        event.ua_is_bot = ua_info.get("is_bot", False)
        event.ua_browser = ua_info.get("browser")
        event.ua_os = ua_info.get("os")
        event.abuseipdb_score = geo.get("abuseipdb_score")
        event.greynoise_classification = geo.get("greynoise_classification")
        event.risk_score = score
        event.risk_level = level

        await db.flush()

        alert_mgr = AlertManager()
        await alert_mgr.send_alert(event)
    except Exception as exc:
        logger.error("Enrichment/alert error: %s", exc)
