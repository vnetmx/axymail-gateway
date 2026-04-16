from __future__ import annotations

import aiosqlite
from contextlib import asynccontextmanager
from typing import AsyncIterator

CREATE_ACCOUNTS_TABLE = """
CREATE TABLE IF NOT EXISTS accounts (
    id TEXT PRIMARY KEY,
    token_hash TEXT UNIQUE NOT NULL,
    email TEXT NOT NULL,
    imap_host TEXT NOT NULL,
    imap_port INTEGER NOT NULL,
    imap_user TEXT NOT NULL,
    imap_password_enc TEXT NOT NULL,
    imap_tls INTEGER NOT NULL DEFAULT 1,
    smtp_host TEXT NOT NULL,
    smtp_port INTEGER NOT NULL,
    smtp_user TEXT NOT NULL,
    smtp_password_enc TEXT NOT NULL,
    smtp_tls INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL
)
"""


async def init_db(db_path: str) -> None:
    """Create the accounts table if it does not already exist."""
    async with aiosqlite.connect(db_path) as conn:
        await conn.execute(CREATE_ACCOUNTS_TABLE)
        await conn.commit()


@asynccontextmanager
async def get_db(db_path: str) -> AsyncIterator[aiosqlite.Connection]:
    """Async context manager that yields an aiosqlite connection."""
    async with aiosqlite.connect(db_path) as conn:
        conn.row_factory = aiosqlite.Row
        yield conn


async def insert_account(conn: aiosqlite.Connection, record: dict) -> None:
    await conn.execute(
        """
        INSERT INTO accounts (
            id, token_hash, email,
            imap_host, imap_port, imap_user, imap_password_enc, imap_tls,
            smtp_host, smtp_port, smtp_user, smtp_password_enc, smtp_tls,
            created_at
        ) VALUES (
            :id, :token_hash, :email,
            :imap_host, :imap_port, :imap_user, :imap_password_enc, :imap_tls,
            :smtp_host, :smtp_port, :smtp_user, :smtp_password_enc, :smtp_tls,
            :created_at
        )
        """,
        record,
    )
    await conn.commit()


async def get_account_by_token_hash(
    conn: aiosqlite.Connection, token_hash: str
) -> dict | None:
    async with conn.execute(
        "SELECT * FROM accounts WHERE token_hash = ?", (token_hash,)
    ) as cursor:
        row = await cursor.fetchone()
        if row is None:
            return None
        return dict(row)


async def get_account_by_id(
    conn: aiosqlite.Connection, account_id: str
) -> dict | None:
    async with conn.execute(
        "SELECT * FROM accounts WHERE id = ?", (account_id,)
    ) as cursor:
        row = await cursor.fetchone()
        if row is None:
            return None
        return dict(row)


async def list_accounts(conn: aiosqlite.Connection) -> list[dict]:
    async with conn.execute("SELECT * FROM accounts ORDER BY created_at DESC") as cursor:
        rows = await cursor.fetchall()
        return [dict(row) for row in rows]


async def delete_account(conn: aiosqlite.Connection, account_id: str) -> bool:
    cursor = await conn.execute(
        "DELETE FROM accounts WHERE id = ?", (account_id,)
    )
    await conn.commit()
    return cursor.rowcount > 0
