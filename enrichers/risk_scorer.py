"""Risk scoring engine."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from utils.logger import get_logger

logger = get_logger(__name__)

_RULES_PATH = Path(__file__).parent.parent / "config" / "rules.json"


def _load_rules() -> dict:
    try:
        return json.loads(_RULES_PATH.read_text(encoding="utf-8"))
    except Exception:
        return {}


class RiskScorer:
    """Evaluate risk score for a honeypot event."""

    def __init__(self) -> None:
        self._rules = _load_rules()
        self._weights: dict[str, int] = self._rules.get("risk_weights", {})
        self._thresholds: dict[str, int] = self._rules.get("risk_thresholds", {
            "low": 20, "medium": 50, "high": 75, "critical": 90
        })

    def _level(self, score: int) -> str:
        if score >= self._thresholds.get("critical", 90):
            return "critical"
        if score >= self._thresholds.get("high", 75):
            return "high"
        if score >= self._thresholds.get("medium", 50):
            return "medium"
        return "low"

    def score(self, event_data: dict[str, Any], enrichment: dict[str, Any]) -> tuple[int, str]:
        """
        Compute total risk score and level.

        Returns (score: int, level: str).
        """
        total = 0
        w = self._weights

        if enrichment.get("is_scanner"):
            total += w.get("known_scanner_ua", 30)
        if enrichment.get("is_headless"):
            total += w.get("headless_browser", 20)
        if enrichment.get("is_bot"):
            pass  # covered by scanner/headless or no-referrer

        referrer = event_data.get("referrer")
        if not referrer:
            total += w.get("no_referrer", 10)

        canary_hits = event_data.get("canary_hits", 0)
        if canary_hits > 1:
            total += w.get("multiple_canaries_hit", 35)

        rapid = event_data.get("rapid_requests", False)
        if rapid:
            total += w.get("rapid_requests", 25)

        suspicious_countries: list[str] = self._rules.get("suspicious_countries", [])
        if enrichment.get("country") in suspicious_countries:
            total += w.get("suspicious_country", 15)

        abuseipdb_score = enrichment.get("abuseipdb_score") or 0
        if abuseipdb_score >= 50:
            total += w.get("abuseipdb_score_high", 40)

        gn_class = enrichment.get("greynoise_classification", "")
        if gn_class == "malicious":
            total += w.get("greynoise_malicious", 45)

        repeated = event_data.get("repeated_actor", False)
        if repeated:
            total += w.get("repeated_actor", 20)

        total = min(total, 100)
        return total, self._level(total)

    def get_factor_breakdown(
        self, event_data: dict[str, Any], enrichment: dict[str, Any]
    ) -> list[dict[str, Any]]:
        """Return a list of {factor, weight, triggered} dicts."""
        w = self._weights
        factors = [
            {
                "factor": "known_scanner_ua",
                "weight": w.get("known_scanner_ua", 30),
                "triggered": bool(enrichment.get("is_scanner")),
            },
            {
                "factor": "headless_browser",
                "weight": w.get("headless_browser", 20),
                "triggered": bool(enrichment.get("is_headless")),
            },
            {
                "factor": "no_referrer",
                "weight": w.get("no_referrer", 10),
                "triggered": not bool(event_data.get("referrer")),
            },
            {
                "factor": "multiple_canaries_hit",
                "weight": w.get("multiple_canaries_hit", 35),
                "triggered": (event_data.get("canary_hits", 0) > 1),
            },
            {
                "factor": "rapid_requests",
                "weight": w.get("rapid_requests", 25),
                "triggered": bool(event_data.get("rapid_requests")),
            },
            {
                "factor": "suspicious_country",
                "weight": w.get("suspicious_country", 15),
                "triggered": enrichment.get("country") in self._rules.get("suspicious_countries", []),
            },
            {
                "factor": "abuseipdb_score_high",
                "weight": w.get("abuseipdb_score_high", 40),
                "triggered": (enrichment.get("abuseipdb_score") or 0) >= 50,
            },
            {
                "factor": "greynoise_malicious",
                "weight": w.get("greynoise_malicious", 45),
                "triggered": enrichment.get("greynoise_classification") == "malicious",
            },
            {
                "factor": "repeated_actor",
                "weight": w.get("repeated_actor", 20),
                "triggered": bool(event_data.get("repeated_actor")),
            },
        ]
        return factors
