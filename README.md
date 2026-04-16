# axymail-gateway

A self-hosted REST API gateway that sits in front of any IMAP/SMTP mail server.

Register an email account once, get a bearer token, and use it to read, search, flag, delete messages and send email — all via a clean HTTP API. No Gmail API, no OAuth, no vendor lock-in.

---

## Features

- **Account registration** — store IMAP + SMTP credentials, receive a bearer token
- **IMAP operations** — list folders, list messages (paginated), fetch full message, set flags (read/flagged), delete
- **SMTP send** — compose and send with plain text and/or HTML body, CC, BCC
- **Async throughout** — FastAPI + `aioimaplib` + `aiosmtplib` + `aiosqlite`
- **Credentials encrypted at rest** — Fernet symmetric encryption via `cryptography`
- **Token hashing** — raw token returned once; only SHA-256 hash stored in DB
- **Zero infrastructure** — single SQLite file, runs in one Docker container

---

## Stack

| Layer | Library |
|---|---|
| API | FastAPI |
| IMAP | aioimaplib (async, native) |
| SMTP | aiosmtplib (async) |
| Database | SQLite via aiosqlite + SQLAlchemy |
| Models | Pydantic v2 |
| Encryption | cryptography (Fernet) |
| Tests | pytest + pytest-asyncio + httpx |
| Container | Docker + docker-compose |

---

## API Overview

```
POST   /v1/accounts                          Register account → returns token
GET    /v1/accounts/{id}                     Account info
GET    /v1/accounts/{id}/mailboxes           List IMAP folders
GET    /v1/accounts/{id}/messages            List messages (paginated)
GET    /v1/accounts/{id}/messages/{uid}      Fetch full message
PUT    /v1/accounts/{id}/messages/{uid}      Update flags (seen, flagged)
DELETE /v1/accounts/{id}/messages/{uid}      Delete message
POST   /v1/accounts/{id}/send               Send email via SMTP
```

All endpoints (except `POST /v1/accounts`) require:

```
Authorization: Bearer <token>
```

---

## Quick Start

### Local development

```bash
# Install
pip install -e ".[dev]"

# Run (hot reload)
uvicorn axymail_gateway.main:app --reload

# Docs
open http://localhost:8000/docs
```

### Docker + Mailpit (local IMAP/SMTP test server)

```bash
docker compose -f examples/docker-compose.yml up -d
```

| Service | URL |
|---|---|
| axymail-gateway API | http://localhost:3000 |
| Mailpit Web UI | http://localhost:8025 |
| Mailpit IMAP | localhost:1143 |
| Mailpit SMTP | localhost:1025 |

### Register an account (Mailpit example)

```bash
curl -s -X POST http://localhost:3000/v1/accounts \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "imap_host": "localhost", "imap_port": 1143, "imap_user": "test@example.com", "imap_password": "any", "imap_tls": false,
    "smtp_host": "localhost", "smtp_port": 1025, "smtp_user": "test@example.com", "smtp_password": "any", "smtp_tls": false
  }'
```

Response:
```json
{
  "id": "b3f1c2d4-...",
  "token": "a1b2c3d4-...",
  "email": "test@example.com"
}
```

---

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `ENCRYPTION_KEY` | *(required)* | Fernet key for credential encryption at rest |
| `DB_PATH` | `./axymail_gateway.db` | SQLite file path |
| `HOST` | `0.0.0.0` | Bind address |
| `PORT` | `3000` | Listen port |

Generate a Fernet key:
```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

---

## Project Structure

```
src/
├── axymail_gateway/
│   ├── main.py              # FastAPI app + lifespan
│   ├── config.py            # Settings (env vars)
│   ├── database.py          # SQLite + aiosqlite setup
│   ├── models.py            # Pydantic v2 request/response models
│   ├── deps.py              # FastAPI dependencies (token → account)
│   ├── router/
│   │   ├── accounts.py      # POST /accounts, GET /accounts/{id}
│   │   ├── mailboxes.py     # GET .../mailboxes
│   │   ├── messages.py      # GET/PUT/DELETE .../messages
│   │   └── send.py          # POST .../send
│   └── services/
│       ├── token_service.py # Token generation, hashing, lookup
│       ├── imap_service.py  # IMAP via aioimaplib
│       └── smtp_service.py  # SMTP via aiosmtplib
├── tests/
└── examples/
    └── docker-compose.yml   # axymail-gateway + Mailpit
```

---

## License

MIT
