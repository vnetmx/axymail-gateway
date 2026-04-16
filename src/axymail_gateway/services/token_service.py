from __future__ import annotations

import hashlib
import secrets
import uuid

from cryptography.fernet import Fernet


def generate_token() -> str:
    """Generate a random opaque bearer token."""
    return secrets.token_urlsafe(48)


def hash_token(token: str) -> str:
    """Return the SHA-256 hex digest of a token for safe storage."""
    return hashlib.sha256(token.encode()).hexdigest()


def generate_account_id() -> str:
    """Generate a new UUID4 string."""
    return str(uuid.uuid4())


def get_fernet(key: str) -> Fernet:
    """Return a Fernet instance from a base64-url key string."""
    return Fernet(key.encode())


def encrypt(fernet: Fernet, value: str) -> str:
    """Encrypt *value* and return a UTF-8 string."""
    return fernet.encrypt(value.encode()).decode()


def decrypt(fernet: Fernet, value: str) -> str:
    """Decrypt a Fernet-encrypted UTF-8 string."""
    return fernet.decrypt(value.encode()).decode()
