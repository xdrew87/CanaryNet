"""Application settings loaded from environment variables."""
from __future__ import annotations

from functools import lru_cache
from typing import Optional
from pydantic import field_validator, AnyHttpUrl
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # Database
    DATABASE_URL: str = "sqlite+aiosqlite:///./honeypot.db"

    # Admin auth
    ADMIN_SECRET: str = "change-this-secret-key"

    # Discord
    DISCORD_WEBHOOK_URL: Optional[str] = None

    # Slack
    SLACK_WEBHOOK_URL: Optional[str] = None

    # Email
    EMAIL_HOST: str = "smtp.hostinger.com"
    EMAIL_PORT: int = 465
    EMAIL_USER: Optional[str] = None
    EMAIL_PASS: Optional[str] = None
    EMAIL_TO: Optional[str] = None

    # Threat Intelligence
    ABUSEIPDB_API_KEY: Optional[str] = None
    GREYNOISE_API_KEY: Optional[str] = None
    VIRUSTOTAL_API_KEY: Optional[str] = None

    # Canary
    CANARY_BASE_URL: str = "http://localhost:8000"

    # GitHub Webhook
    WEBHOOK_SECRET: str = "change-this-webhook-secret"

    # Alert tuning
    ALERT_BURST_THRESHOLD: int = 5
    ALERT_BURST_WINDOW_SECONDS: int = 60
    DAILY_SUMMARY_HOUR: int = 8

    # Logging
    LOG_LEVEL: str = "INFO"

    # Honeypot identity
    HONEYPOT_REPO_NAME: str = "dev-tools-2024"
    HONEYPOT_ORG: str = "your-github-org"

    @field_validator("CANARY_BASE_URL", mode="before")
    @classmethod
    def validate_canary_url(cls, v: str) -> str:
        if not v.startswith(("http://", "https://")):
            raise ValueError("CANARY_BASE_URL must be a valid HTTP/HTTPS URL")
        return v.rstrip("/")

    @property
    def is_database_postgres(self) -> bool:
        return self.DATABASE_URL.startswith("postgres")

    @property
    def alert_channels(self) -> list[str]:
        channels: list[str] = []
        if self.DISCORD_WEBHOOK_URL:
            channels.append("discord")
        if self.SLACK_WEBHOOK_URL:
            channels.append("slack")
        if self.EMAIL_USER and self.EMAIL_PASS and self.EMAIL_TO:
            channels.append("email")
        return channels


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
