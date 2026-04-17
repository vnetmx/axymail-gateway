from __future__ import annotations

from cryptography.fernet import Fernet
from pydantic_settings import BaseSettings, SettingsConfigDict


def _default_encryption_key() -> str:
    """Generate a fresh Fernet key if none is configured."""
    return Fernet.generate_key().decode()


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
    )

    database_url: str = "sqlite+aiosqlite:///./axymail_gateway.db"
    # Derive the plain filesystem path used by aiosqlite directly.
    # Defaults to a file in the current working directory.
    db_path: str = "./axymail_gateway.db"

    # Fernet key — base64-url-encoded 32-byte key.
    # Auto-generated at startup if not provided via env.
    encryption_key: str = ""

    # Admin API key — grants access to privileged operations (e.g. delete any account).
    # If left empty, admin access is disabled; only self-service operations are allowed.
    admin_api_key: str = ""

    # Secret key for signing session cookies used by the admin dashboard.
    # Auto-generated (ephemeral) if not set — sessions won't survive restarts.
    secret_key: str = ""

    # ── Observability ────────────────────────────────────────────────────────
    # OpenTelemetry tracing
    otel_enabled: bool = False
    otel_service_name: str = "axymail-gateway"
    # OTLP HTTP endpoint, e.g. http://otel-collector:4318
    # When empty, a no-op exporter is used (spans are generated but not exported).
    otel_exporter_otlp_endpoint: str = ""

    # Prometheus metrics — exposes /metrics in OpenMetrics format
    prometheus_enabled: bool = True

    # ── Content guard service (external LLM-based prompt injection detection) ─
    # URL of the guard service API, e.g. http://llm-guard:8000
    # When empty or disabled, only the local regex-based sanitizer is used.
    guard_enabled: bool = False
    guard_service_url: str = ""
    guard_timeout: float = 5.0        # seconds per request
    # Behavior when the guard service is unreachable:
    #   "open"   — serve content with regex-only sanitization (permissive)
    #   "closed" — reject the request with HTTP 503 (strict)
    guard_fail_mode: str = "open"

    api_host: str = "0.0.0.0"
    api_port: int = 3000
    debug: bool = False

    def get_encryption_key(self) -> str:
        """Return the configured key or generate one (ephemeral)."""
        if self.encryption_key:
            return self.encryption_key
        return _default_encryption_key()


settings = Settings()
