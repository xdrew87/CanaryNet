"""Structured logging setup."""
from __future__ import annotations

import logging
import logging.handlers
from pathlib import Path

from rich.logging import RichHandler

from config.settings import get_settings

_settings = get_settings()
_LOG_DIR = Path("logs")
_LOG_DIR.mkdir(exist_ok=True)

_LOG_FILE = _LOG_DIR / "honeypot.log"

_configured = False


def _configure() -> None:
    global _configured
    if _configured:
        return
    _configured = True

    level = getattr(logging, _settings.LOG_LEVEL.upper(), logging.INFO)

    # Rich console handler
    rich_handler = RichHandler(
        rich_tracebacks=True,
        markup=True,
        show_path=False,
    )
    rich_handler.setLevel(level)

    # Rotating file handler — JSON-ish format
    file_handler = logging.handlers.RotatingFileHandler(
        _LOG_FILE,
        maxBytes=10 * 1024 * 1024,  # 10 MB
        backupCount=5,
        encoding="utf-8",
    )
    file_handler.setLevel(level)
    file_fmt = logging.Formatter(
        '{"time":"%(asctime)s","level":"%(levelname)s","name":"%(name)s","message":"%(message)s"}'
    )
    file_handler.setFormatter(file_fmt)

    root = logging.getLogger()
    root.setLevel(level)
    root.addHandler(rich_handler)
    root.addHandler(file_handler)


def get_logger(name: str) -> logging.Logger:
    """Return a configured logger for the given name."""
    _configure()
    return logging.getLogger(name)
