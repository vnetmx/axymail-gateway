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

    api_host: str = "0.0.0.0"
    api_port: int = 3000
    debug: bool = False

    def get_encryption_key(self) -> str:
        """Return the configured key or generate one (ephemeral)."""
        if self.encryption_key:
            return self.encryption_key
        return _default_encryption_key()


settings = Settings()
