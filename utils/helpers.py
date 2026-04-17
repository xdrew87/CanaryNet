"""Utility helpers."""
from __future__ import annotations

import ipaddress
import json
import uuid
from datetime import datetime


def generate_uuid() -> str:
    """Return a new UUID4 string."""
    return str(uuid.uuid4())


def truncate_string(s: str, max_len: int = 100) -> str:
    """Truncate a string to max_len characters."""
    if not s:
        return s
    return s[:max_len] + ("…" if len(s) > max_len else "")


def safe_json_loads(s: str) -> dict:
    """Parse JSON string, returning {} on any error."""
    try:
        result = json.loads(s)
        return result if isinstance(result, dict) else {}
    except Exception:
        return {}


_SENSITIVE_HEADERS = {
    "authorization",
    "x-api-key",
    "x-auth-token",
    "cookie",
    "set-cookie",
    "proxy-authorization",
}


def headers_to_dict(headers: dict) -> dict:
    """Convert headers to a dict, redacting sensitive values."""
    return {
        k: "[REDACTED]" if k.lower() in _SENSITIVE_HEADERS else v
        for k, v in headers.items()
    }


def is_private_ip(ip: str) -> bool:
    """Return True if the IP is RFC1918 private or loopback."""
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback or addr.is_link_local
    except ValueError:
        return False


def format_timestamp(dt: datetime) -> str:
    """Return ISO 8601 formatted timestamp string."""
    return dt.isoformat()


def mask_ip(ip: str) -> str:
    """Mask the last octet of an IPv4 address for logging (e.g., 192.168.1.x)."""
    try:
        addr = ipaddress.ip_address(ip)
        if addr.version == 4:
            parts = ip.split(".")
            parts[-1] = "x"
            return ".".join(parts)
        # IPv6: mask last group
        parts = ip.split(":")
        if parts:
            parts[-1] = "xxxx"
        return ":".join(parts)
    except ValueError:
        return ip
