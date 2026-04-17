"""IP geolocation and threat intelligence enricher."""
from __future__ import annotations

import asyncio
import time
from typing import Any, Optional

import httpx

from config.settings import get_settings
from utils.logger import get_logger

logger = get_logger(__name__)
_settings = get_settings()

# In-memory cache: ip -> (timestamp, data)
_cache: dict[str, tuple[float, dict]] = {}
_CACHE_TTL = 1800  # 30 minutes


class IPEnricher:
    """Fetch geo and threat intel data for an IP address."""

    def __init__(self) -> None:
        self._client = httpx.AsyncClient(timeout=10.0)

    async def enrich(self, ip: str) -> dict[str, Any]:
        """Return enrichment dict for the given IP. Results are cached."""
        now = time.monotonic()
        if ip in _cache:
            ts, data = _cache[ip]
            if now - ts < _CACHE_TTL:
                return data

        result: dict[str, Any] = {
            "country": None,
            "city": None,
            "region": None,
            "isp": None,
            "asn": None,
            "lat": None,
            "lon": None,
            "abuseipdb_score": None,
            "greynoise_classification": None,
            "greynoise_noise": None,
            "greynoise_riot": None,
        }

        geo = await self._fetch_geo(ip)
        result.update(geo)

        if _settings.ABUSEIPDB_API_KEY:
            abuse = await self._fetch_abuseipdb(ip)
            result.update(abuse)

        if _settings.GREYNOISE_API_KEY:
            gn = await self._fetch_greynoise(ip)
            result.update(gn)

        _cache[ip] = (now, result)
        return result

    async def _fetch_geo(self, ip: str) -> dict:
        """ip-api.com — free, no key required."""
        url = f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,regionName,city,isp,org,as,lat,lon"
        for attempt in range(3):
            try:
                resp = await self._client.get(url)
                if resp.status_code == 200:
                    data = resp.json()
                    if data.get("status") == "success":
                        return {
                            "country": data.get("countryCode"),
                            "city": data.get("city"),
                            "region": data.get("regionName"),
                            "isp": data.get("isp"),
                            "asn": data.get("as"),
                            "lat": data.get("lat"),
                            "lon": data.get("lon"),
                        }
            except Exception as exc:
                logger.debug("ip-api attempt %d failed: %s", attempt + 1, exc)
                await asyncio.sleep(2 ** attempt)
        return {}

    async def _fetch_abuseipdb(self, ip: str) -> dict:
        """AbuseIPDB v2 check endpoint."""
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {
            "Key": _settings.ABUSEIPDB_API_KEY,
            "Accept": "application/json",
        }
        params = {"ipAddress": ip, "maxAgeInDays": 90}
        for attempt in range(3):
            try:
                resp = await self._client.get(url, headers=headers, params=params)
                if resp.status_code == 200:
                    data = resp.json().get("data", {})
                    return {"abuseipdb_score": data.get("abuseConfidenceScore")}
            except Exception as exc:
                logger.debug("AbuseIPDB attempt %d: %s", attempt + 1, exc)
                await asyncio.sleep(2 ** attempt)
        return {}

    async def _fetch_greynoise(self, ip: str) -> dict:
        """GreyNoise community API."""
        url = f"https://api.greynoise.io/v3/community/{ip}"
        headers = {"key": _settings.GREYNOISE_API_KEY}
        for attempt in range(3):
            try:
                resp = await self._client.get(url, headers=headers)
                if resp.status_code == 200:
                    data = resp.json()
                    return {
                        "greynoise_classification": data.get("classification"),
                        "greynoise_noise": data.get("noise"),
                        "greynoise_riot": data.get("riot"),
                    }
                if resp.status_code == 404:
                    return {}
            except Exception as exc:
                logger.debug("GreyNoise attempt %d: %s", attempt + 1, exc)
                await asyncio.sleep(2 ** attempt)
        return {}

    async def aclose(self) -> None:
        await self._client.aclose()
