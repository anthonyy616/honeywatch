"""Canonical HoneyWatch schemas and enums.

This module knows nothing about SQLite, Textual or network servers. It is
the shared vocabulary for producers, the pipeline, storage and presentation.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from .sanitize import safe_text

# Capture-time maximums (see docs/EVENT_SCHEMA.md).
MAX_USERNAME = 256
MAX_PASSWORD = 256
MAX_COMMAND = 1024
MAX_PATH = 2048
MAX_QUERY = 2048
MAX_BODY_SNIPPET = 1024
MAX_USER_AGENT = 512
MAX_HTTP_BODY_READ = 8192
MAX_SSH_LINE = 4096
MAX_INPUT_TOKENS = 16


class Service(StrEnum):
    SSH = "ssh"
    HTTP = "http"
    SYSTEM = "system"


class EventType(StrEnum):
    CONNECT = "connect"
    DISCONNECT = "disconnect"
    LOGIN_ATTEMPT = "login_attempt"
    LOGIN_SUCCESS = "login_success"
    COMMAND = "command"
    HTTP_REQUEST = "http_request"
    HTTP_LOGIN_ATTEMPT = "http_login_attempt"


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


SEVERITY_ORDER: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


def severity_at_least(value: Severity | str, minimum: Severity | str) -> bool:
    """Return True when ``value`` is at least as severe as ``minimum``."""
    return SEVERITY_ORDER[Severity(value)] >= SEVERITY_ORDER[Severity(minimum)]


def max_severity(values: list[Severity] | list[str]) -> Severity:
    """Return the most severe member of ``values`` (default ``info``)."""
    best = Severity.INFO
    for item in values:
        candidate = Severity(item)
        if SEVERITY_ORDER[candidate] > SEVERITY_ORDER[best]:
            best = candidate
    return best


def utcnow() -> datetime:
    """Timezone-aware current UTC time."""
    return datetime.now(UTC)


def iso(dt: datetime) -> str:
    """Serialize a datetime as ISO-8601 UTC with a trailing ``Z``."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


class HoneyWatchModel(BaseModel):
    """Base model: strict about unknown keys, silent about coercion bugs."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)


class RuleHit(HoneyWatchModel):
    """A single rule match against a single event."""

    rule_id: str
    title: str = ""
    attack: str | None = None
    attack_name: str | None = None
    severity: Severity = Severity.INFO
    ts: datetime = Field(default_factory=utcnow)

    def to_row(self) -> tuple[str, str, str | None, str | None, str, str]:
        return (self.rule_id, self.title, self.attack, self.attack_name, self.severity, iso(self.ts))


class Event(HoneyWatchModel):
    """One flat observation. Non-applicable fields are explicitly ``None``."""

    id: int | None = None
    ts: datetime = Field(default_factory=utcnow)
    service: Service
    event_type: EventType
    src_ip: str
    src_port: int | None = None
    session_id: str = ""
    username: str | None = None
    password: str | None = None
    command: str | None = None
    http_method: str | None = None
    path: str | None = None
    query: str | None = None
    user_agent: str | None = None
    body_snippet: str | None = None
    client_banner: str | None = None
    geo_country: str | None = None
    geo_city: str | None = None
    asn: int | None = None
    as_org: str | None = None
    tags: list[str] = Field(default_factory=list)
    rule_ids: list[str] = Field(default_factory=list)
    severity: Severity = Severity.INFO

    @field_validator("username", mode="before")
    @classmethod
    def _clip_username(cls, value: Any) -> Any:
        return _clip(value, MAX_USERNAME)

    @field_validator("password", mode="before")
    @classmethod
    def _clip_password(cls, value: Any) -> Any:
        return _clip(value, MAX_PASSWORD)

    @field_validator("command", mode="before")
    @classmethod
    def _clip_command(cls, value: Any) -> Any:
        return _clip(value, MAX_COMMAND)

    @field_validator("path", "query", mode="before")
    @classmethod
    def _clip_path(cls, value: Any) -> Any:
        return _clip(value, MAX_PATH)

    @field_validator("body_snippet", mode="before")
    @classmethod
    def _clip_body(cls, value: Any) -> Any:
        return _clip(value, MAX_BODY_SNIPPET)

    @field_validator("user_agent", "client_banner", "session_id", "src_ip", mode="before")
    @classmethod
    def _clip_short(cls, value: Any) -> Any:
        return _clip(value, MAX_USER_AGENT)

    @field_validator("ts")
    @classmethod
    def _utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value.astimezone(UTC)

    def to_json_dict(self) -> dict[str, Any]:
        """Flat dictionary in stable key order (used by the JSONL archive)."""
        data = self.model_dump(mode="json")
        data["ts"] = iso(self.ts)
        return data

    def summary(self) -> str:
        """Concise single-line description used by feed and reports."""
        if self.service is Service.SSH:
            match self.event_type:
                case EventType.CONNECT:
                    return "ssh connect"
                case EventType.DISCONNECT:
                    return "ssh disconnect"
                case EventType.LOGIN_SUCCESS:
                    return f"login ok {self.username or '?'}"
                case EventType.LOGIN_ATTEMPT:
                    return f"login {self.username or '?'}/{self.password or '?'}"
                case EventType.COMMAND:
                    return f"cmd {self.command or ''}"
                case _:
                    return self.event_type
        if self.event_type is EventType.HTTP_LOGIN_ATTEMPT:
            return f"POST {self.path or ''} {self.username or '?'}/{self.password or '?'}"
        if self.event_type is EventType.HTTP_REQUEST:
            return f"{self.http_method or 'GET'} {self.path or ''}"
        return self.event_type


def _clip(value: Any, limit: int) -> Any:
    if not isinstance(value, str):
        return value
    cleaned = safe_text(value, limit=limit * 4, keep_newlines=True)
    return cleaned[:limit] if len(cleaned) > limit else cleaned


class AlertRecord(HoneyWatchModel):
    """Audit row for an outbound (or attempted) Telegram notification."""

    ts: datetime = Field(default_factory=utcnow)
    rule_id: str | None = None
    src_ip: str
    severity: Severity
    title: str = ""
    status: str = "sent"
    detail: str | None = None


class Verdict(StrEnum):
    NOISE = "Noise"
    SUSPICIOUS = "Suspicious"
    HOSTILE = "Hostile"
    PERSISTENT = "Persistent"


class Classification(StrEnum):
    INTRUDER = "Intruder"
    MALWARE_DROPPER = "Malware dropper"
    BRUTE_FORCER = "Brute-forcer"
    CREDENTIAL_SPRAYER = "Credential sprayer"
    WEB_EXPLOITER = "Web exploiter"
    SCANNER = "Scanner"
    RECON = "Recon"
    UNCLASSIFIED = "Unclassified"


VERDICT_THRESHOLDS: tuple[tuple[float, Verdict], ...] = (
    (100.0, Verdict.PERSISTENT),
    (40.0, Verdict.HOSTILE),
    (10.0, Verdict.SUSPICIOUS),
    (0.0, Verdict.NOISE),
)