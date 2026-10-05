"""Configuration loading and validation.

Configuration is validated with pydantic before any listener starts. Unknown
keys are rejected so a typo cannot silently disable a security control.

Path semantics: every relative path in the configuration is resolved against
the **process working directory**, uniformly for ``data_dir``, GeoIP
databases and the rules directory. That single rule is documented, tested and
never mixed with another convention. Deployment configs use absolute paths.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from .models import Severity

DEFAULT_BANNER = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"
DEFAULT_SERVER_HEADER = "Apache/2.4.41 (Ubuntu)"
DEFAULT_WEAK_PASSWORDS = ["123456", "password", "admin", "root", "toor", "12345678"]


class ConfigError(Exception):
    """Raised for missing, unreadable or invalid configuration."""


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class SSHConfig(StrictModel):
    enabled: bool = True
    bind: str = "0.0.0.0"
    port: int = Field(default=2222, ge=1, le=65535)
    banner: str = DEFAULT_BANNER
    hostname: str = "srv-prod-02"
    accept_after_failures: int = Field(default=4, ge=1, le=1000)
    weak_passwords: list[str] = Field(default_factory=lambda: list(DEFAULT_WEAK_PASSWORDS))
    max_connections: int = Field(default=100, ge=1, le=100000)
    max_per_ip: int = Field(default=5, ge=1, le=10000)
    session_timeout_s: int = Field(default=300, ge=5, le=86400)
    idle_timeout_s: int = Field(default=60, ge=5, le=3600)
    max_commands: int = Field(default=50, ge=1, le=10000)

    @field_validator("banner")
    @classmethod
    def _check_banner(cls, value: str) -> str:
        if not value.startswith("SSH-2.0-"):
            raise ValueError("ssh.banner must start with 'SSH-2.0-'")
        if len(value) > 255:
            raise ValueError("ssh.banner must be at most 255 characters")
        return value

    @field_validator("weak_passwords")
    @classmethod
    def _bound_passwords(cls, value: list[str]) -> list[str]:
        if len(value) > 1000:
            raise ValueError("ssh.weak_passwords supports at most 1000 entries")
        return [item[:256] for item in value]


class HTTPConfig(StrictModel):
    enabled: bool = True
    bind: str = "0.0.0.0"
    port: int = Field(default=8080, ge=1, le=65535)
    server_header: str = DEFAULT_SERVER_HEADER
    max_body_bytes: int = Field(default=8192, ge=0, le=1_048_576)


class RulesConfig(StrictModel):
    directory: Path = Path("./rules")
    reload_on_sighup: bool = True


class EnrichmentConfig(StrictModel):
    geoip_city_db: Path | None = None
    geoip_asn_db: Path | None = None


class ScoringConfig(StrictModel):
    half_life_hours: float = Field(default=6.0, gt=0)
    weights: dict[str, float] = Field(
        default_factory=lambda: {
            "info": 1,
            "low": 3,
            "medium": 8,
            "high": 20,
            "critical": 40,
        }
    )

    @field_validator("weights")
    @classmethod
    def _known_weights(cls, value: dict[str, float]) -> dict[str, float]:
        for key in value:
            if key not in set(Severity):
                raise ValueError(f"scoring.weights has unknown severity {key!r}")
        return value


class TelegramConfig(StrictModel):
    enabled: bool = False
    token_env: str = "HONEYWATCH_TG_TOKEN"
    chat_id: str = ""
    min_severity: Severity = Severity.HIGH
    max_per_hour: int = Field(default=20, ge=1, le=10000)
    timeout_s: float = Field(default=10.0, gt=0, le=120)
    retries: int = Field(default=2, ge=0, le=10)
    base_url: str = "https://api.telegram.org"


class AlertsConfig(StrictModel):
    telegram: TelegramConfig = Field(default_factory=TelegramConfig)


class StorageConfig(StrictModel):
    retention_days: int = Field(default=30, ge=0, le=36500)
    queue_size: int = Field(default=10000, ge=16, le=10_000_000)
    raw_archive: bool = True
    compress_after_days: int = Field(default=7, ge=0, le=3650)


class SimulatorConfig(StrictModel):
    profiles: list[str] = Field(default_factory=list)


class Config(StrictModel):
    data_dir: Path = Path("./data")
    log_level: str = "INFO"
    ssh: SSHConfig = Field(default_factory=SSHConfig)
    http: HTTPConfig = Field(default_factory=HTTPConfig)
    rules: RulesConfig = Field(default_factory=RulesConfig)
    enrichment: EnrichmentConfig = Field(default_factory=EnrichmentConfig)
    scoring: ScoringConfig = Field(default_factory=ScoringConfig)
    alerts: AlertsConfig = Field(default_factory=AlertsConfig)
    storage: StorageConfig = Field(default_factory=StorageConfig)
    simulator: SimulatorConfig = Field(default_factory=SimulatorConfig)

    @field_validator("log_level")
    @classmethod
    def _check_level(cls, value: str) -> str:
        allowed = {"CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG"}
        upper = value.upper()
        if upper not in allowed:
            raise ValueError(f"log_level must be one of {sorted(allowed)}")
        return upper

    # ---- derived paths -------------------------------------------------

    @property
    def resolved_data_dir(self) -> Path:
        return self.data_dir

    @property
    def db_path(self) -> Path:
        return self.resolved_data_dir / "honeywatch.db"

    @property
    def raw_dir(self) -> Path:
        return self.resolved_data_dir / "raw"

    @property
    def geo_dir(self) -> Path:
        return self.resolved_data_dir / "geo"

    @property
    def host_key_path(self) -> Path:
        return self.resolved_data_dir / "ssh_host_key"

    @property
    def rules_dir(self) -> Path:
        return self.rules.directory

    def ensure_data_dir(self) -> Path:
        """Create the data directory tree, raising a clear error on failure."""
        try:
            self.resolved_data_dir.mkdir(parents=True, exist_ok=True)
            self.raw_dir.mkdir(parents=True, exist_ok=True)
            self.geo_dir.mkdir(parents=True, exist_ok=True)
        except OSError as exc:  # pragma: no cover - environment dependent
            raise ConfigError(f"cannot create data directory {self.resolved_data_dir}: {exc}") from exc
        if not os.access(self.resolved_data_dir, os.W_OK):
            raise ConfigError(f"data directory is not writable: {self.resolved_data_dir}")
        return self.resolved_data_dir

    def telegram_token(self) -> str | None:
        """Read the Telegram token from the environment (never from config)."""
        token = os.environ.get(self.alerts.telegram.token_env, "").strip()
        return token or None


def _resolve_paths(raw: dict[str, Any], base: Path) -> dict[str, Any]:
    """Resolve every configured relative path against ``base`` (the CWD)."""
    resolved = dict(raw)

    data_dir = Path(resolved.get("data_dir", "./data"))
    resolved["data_dir"] = (data_dir if data_dir.is_absolute() else (base / data_dir)).resolve()

    rules_dir = Path((resolved.get("rules") or {}).get("directory", "./rules"))
    resolved.setdefault("rules", {})
    resolved["rules"]["directory"] = (
        rules_dir if rules_dir.is_absolute() else (base / rules_dir)
    ).resolve()

    enrichment = dict(resolved.get("enrichment") or {})
    for key in ("geoip_city_db", "geoip_asn_db"):
        value = enrichment.get(key)
        if value:
            path = Path(value)
            enrichment[key] = (path if path.is_absolute() else (base / path)).resolve()
    resolved["enrichment"] = enrichment
    return resolved


def parse_config(data: dict[str, Any], *, base_dir: Path | None = None) -> Config:
    """Validate a configuration mapping, resolving relative paths."""
    base = base_dir or Path.cwd()
    try:
        return Config.model_validate(_resolve_paths(data, base))
    except ValidationError as exc:
        raise ConfigError(_format_validation_error(exc)) from exc


def _format_validation_error(exc: ValidationError) -> str:
    lines = ["invalid configuration:"]
    for err in exc.errors():
        loc = ".".join(str(part) for part in err.get("loc", ())) or "<root>"
        lines.append(f"  - {loc}: {err.get('msg', 'invalid value')}")
    return "\n".join(lines)


def load_config(path: str | os.PathLike[str] | None) -> Config:
    """Load configuration from YAML.

    Args:
        path: Config file path. When ``None`` the default search locations
            are used (``$HONEYWATCH_CONFIG``, ``./config/honeywatch.yaml``,
            ``./config/honeywatch.example.yaml``).

    Raises:
        ConfigError: The file is missing, unreadable, not valid YAML or fails
            validation. Never a raw traceback.
    """
    base_dir = Path.cwd()
    if path is None:
        env_path = os.environ.get("HONEYWATCH_CONFIG")
        candidates = [Path(env_path)] if env_path else []
        candidates += [
            Path("config/honeywatch.yaml"),
            Path("config/honeywatch.example.yaml"),
        ]
        chosen = next((c for c in candidates if c.is_file()), None)
        if chosen is None:
            raise ConfigError(
                "no configuration file found; looked for "
                + ", ".join(str(c) for c in candidates)
                + " (set HONEYWATCH_CONFIG or pass --config)"
            )
    else:
        chosen = Path(path)
        if not chosen.is_file():
            raise ConfigError(f"configuration file not found: {chosen}")

    try:
        text = chosen.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigError(f"cannot read configuration {chosen}: {exc}") from exc

    try:
        data = yaml.safe_load(text) or {}
    except yaml.YAMLError as exc:
        raise ConfigError(f"invalid YAML in {chosen}: {exc}") from exc

    if not isinstance(data, dict):
        raise ConfigError(f"configuration root must be a mapping, got {type(data).__name__}")

    return parse_config(data, base_dir=base_dir)