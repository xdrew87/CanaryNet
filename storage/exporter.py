"""Export utilities for events and actors."""
from __future__ import annotations

import csv
import io
import json
from datetime import datetime, timezone
from pathlib import Path

from storage.models import Actor, HoneypotEvent


def export_events_json(events: list[HoneypotEvent]) -> str:
    """Serialize a list of HoneypotEvent objects to a JSON string."""
    data = [e.to_dict() for e in events]
    return json.dumps(data, indent=2, default=str)


def export_events_csv(events: list[HoneypotEvent]) -> str:
    """Serialize a list of HoneypotEvent objects to a CSV string."""
    if not events:
        return ""
    buf = io.StringIO()
    fieldnames = [
        "id", "timestamp", "source_ip", "user_agent", "method", "path",
        "referrer", "event_type", "risk_score", "risk_level",
        "geo_country", "geo_city", "geo_asn", "geo_isp",
        "ua_is_bot", "ua_browser", "ua_os",
        "abuseipdb_score", "greynoise_classification",
        "canary_token_id", "actor_id", "notes",
    ]
    writer = csv.DictWriter(buf, fieldnames=fieldnames, extrasaction="ignore")
    writer.writeheader()
    for event in events:
        writer.writerow(event.to_dict())
    return buf.getvalue()


def export_actors_json(actors: list[Actor]) -> str:
    """Serialize a list of Actor objects to a JSON string."""
    data = [a.to_dict() for a in actors]
    return json.dumps(data, indent=2, default=str)


def save_report(data: str, filename: str, folder: str = "reports") -> Path:
    """Save report data to a file, creating the folder if needed."""
    report_dir = Path(folder)
    report_dir.mkdir(parents=True, exist_ok=True)
    output_path = report_dir / filename
    output_path.write_text(data, encoding="utf-8")
    return output_path
