"""User-agent fingerprinting."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from user_agents import parse as ua_parse

from utils.logger import get_logger

logger = get_logger(__name__)

_RULES_PATH = Path(__file__).parent.parent / "config" / "rules.json"


def _load_scanner_uas() -> list[str]:
    try:
        rules = json.loads(_RULES_PATH.read_text(encoding="utf-8"))
        return [s.lower() for s in rules.get("scanner_user_agents", [])]
    except Exception:
        return []


_SCANNER_UAS = _load_scanner_uas()
_HEADLESS_MARKERS = ["headlesschrome", "phantomjs", "slimerjs", "jsdom", "htmlunit"]


class UAFingerprinter:
    """Parse and classify a user-agent string."""

    def analyze(self, user_agent_string: str) -> dict[str, Any]:
        """Return a dict with browser, os, device, is_bot, is_scanner, is_headless, confidence_score."""
        if not user_agent_string:
            return {
                "browser": None,
                "os": None,
                "device": None,
                "is_bot": True,
                "is_scanner": False,
                "is_headless": False,
                "confidence_score": 80,
            }

        ua_lower = user_agent_string.lower()
        parsed = ua_parse(user_agent_string)

        is_bot = parsed.is_bot
        is_scanner = any(s in ua_lower for s in _SCANNER_UAS)
        is_headless = any(h in ua_lower for h in _HEADLESS_MARKERS)

        # Confidence scoring
        confidence = 0
        if is_bot:
            confidence += 50
        if is_scanner:
            confidence += 30
        if is_headless:
            confidence += 20
        confidence = min(confidence, 100)

        return {
            "browser": parsed.browser.family if parsed.browser else None,
            "os": parsed.os.family if parsed.os else None,
            "device": parsed.device.family if parsed.device else None,
            "is_bot": is_bot or is_scanner or is_headless,
            "is_scanner": is_scanner,
            "is_headless": is_headless,
            "confidence_score": confidence,
        }
