"""
Admin dashboard — server-side rendered HTML via Jinja2.

Authentication: the admin key is submitted via a password form (POST /admin/login),
stored in a signed session cookie, and checked on every protected route.
"""
from __future__ import annotations

from pathlib import Path

from cryptography.fernet import Fernet
from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from axymail_gateway.database import (
    delete_account,
    delete_provider,
    get_account_by_id,
    get_db,
    get_provider_by_name,
    insert_provider,
    list_accounts,
    list_providers,
)
from axymail_gateway.services.token_service import encrypt

router = APIRouter(prefix="/admin", tags=["admin"])

_TEMPLATES_DIR = Path(__file__).parent.parent / "templates"
templates = Jinja2Templates(directory=str(_TEMPLATES_DIR))


# ── helpers ──────────────────────────────────────────────────────────────────

def _is_authenticated(request: Request) -> bool:
    return bool(request.session.get("admin_authenticated"))


def _redirect_to_login() -> RedirectResponse:
    return RedirectResponse(url="/admin/login", status_code=302)


def _pop_flash(request: Request) -> dict | None:
    return request.session.pop("flash", None)


def _set_flash(request: Request, kind: str, msg: str) -> None:
    request.session["flash"] = {"type": kind, "msg": msg}


# ── auth ──────────────────────────────────────────────────────────────────────

@router.get("/login", response_class=HTMLResponse, include_in_schema=False)
async def login_page(request: Request) -> HTMLResponse:
    if _is_authenticated(request):
        return RedirectResponse(url="/admin/", status_code=302)  # type: ignore[return-value]
    return templates.TemplateResponse("admin/login.html", {
        "request": request,
        "admin_configured": bool(request.app.state.admin_api_key),
        "error": request.session.pop("login_error", None),
    })


@router.post("/login", include_in_schema=False)
async def login(request: Request, api_key: str = Form(...)) -> RedirectResponse:
    admin_api_key: str = request.app.state.admin_api_key
    if admin_api_key and api_key == admin_api_key:
        request.session["admin_authenticated"] = True
        return RedirectResponse(url="/admin/", status_code=302)
    request.session["login_error"] = "Invalid admin key."
    return RedirectResponse(url="/admin/login", status_code=302)


@router.get("/logout", include_in_schema=False)
async def logout(request: Request) -> RedirectResponse:
    request.session.clear()
    return RedirectResponse(url="/admin/login", status_code=302)


# ── accounts dashboard ────────────────────────────────────────────────────────

@router.get("/", response_class=HTMLResponse, include_in_schema=False)
async def dashboard(request: Request) -> HTMLResponse:
    if not _is_authenticated(request):
        return _redirect_to_login()  # type: ignore[return-value]
    db_path: str = request.app.state.db_path
    async with get_db(db_path) as conn:
        accounts = await list_accounts(conn)
        providers = await list_providers(conn)
    return templates.TemplateResponse("admin/dashboard.html", {
        "request": request,
        "accounts": accounts,
        "provider_count": len(providers),
        "flash": _pop_flash(request),
    })


@router.get("/accounts/{account_id}/delete", response_class=HTMLResponse, include_in_schema=False)
async def delete_account_confirm(account_id: str, request: Request) -> HTMLResponse:
    if not _is_authenticated(request):
        return _redirect_to_login()  # type: ignore[return-value]
    db_path: str = request.app.state.db_path
    async with get_db(db_path) as conn:
        account = await get_account_by_id(conn, account_id)
    if account is None:
        _set_flash(request, "error", "Account not found.")
        return RedirectResponse(url="/admin/", status_code=302)  # type: ignore[return-value]
    return templates.TemplateResponse("admin/delete_confirm.html", {
        "request": request,
        "type": "account",
        "item": account,
        "cancel_url": "/admin/",
    })


@router.post("/accounts/{account_id}/delete", include_in_schema=False)
async def delete_account_action(account_id: str, request: Request) -> RedirectResponse:
    if not _is_authenticated(request):
        return _redirect_to_login()
    db_path: str = request.app.state.db_path
    async with get_db(db_path) as conn:
        deleted = await delete_account(conn, account_id)
    if deleted:
        _set_flash(request, "success", "Account deleted.")
    else:
        _set_flash(request, "error", "Account not found.")
    return RedirectResponse(url="/admin/", status_code=302)


# ── providers dashboard ───────────────────────────────────────────────────────

@router.get("/providers", response_class=HTMLResponse, include_in_schema=False)
async def providers_page(request: Request) -> HTMLResponse:
    if not _is_authenticated(request):
        return _redirect_to_login()  # type: ignore[return-value]
    db_path: str = request.app.state.db_path
    async with get_db(db_path) as conn:
        providers = await list_providers(conn)
    return templates.TemplateResponse("admin/providers.html", {
        "request": request,
        "providers": providers,
        "flash": _pop_flash(request),
        "form_error": None,
        "form_data": None,
    })


@router.post("/providers", include_in_schema=False)
async def create_provider_action(
    request: Request,
    name: str = Form(...),
    client_id: str = Form(...),
    client_secret: str = Form(...),
    redirect_uri: str = Form(...),
):
    if not _is_authenticated(request):
        return _redirect_to_login()

    db_path: str = request.app.state.db_path
    fernet: Fernet = request.app.state.fernet

    import re
    from datetime import datetime, timezone

    # Validate slug
    if not re.match(r'^[a-z0-9][a-z0-9\-]*[a-z0-9]$', name):
        async with get_db(db_path) as conn:
            providers = await list_providers(conn)
        return templates.TemplateResponse("admin/providers.html", {
            "request": request,
            "providers": providers,
            "flash": None,
            "form_error": "Name must be lowercase letters, numbers, and hyphens only.",
            "form_data": {"name": name, "client_id": client_id, "redirect_uri": redirect_uri},
        })

    async with get_db(db_path) as conn:
        existing = await get_provider_by_name(conn, name)
        if existing:
            providers = await list_providers(conn)
            return templates.TemplateResponse("admin/providers.html", {
                "request": request,
                "providers": providers,
                "flash": None,
                "form_error": f"Provider '{name}' already exists.",
                "form_data": {"name": name, "client_id": client_id, "redirect_uri": redirect_uri},
            })
        await insert_provider(conn, {
            "name": name,
            "client_id": client_id,
            "client_secret_enc": encrypt(fernet, client_secret),
            "redirect_uri": redirect_uri,
            "created_at": datetime.now(timezone.utc).isoformat(),
        })

    _set_flash(request, "success", f"Provider '{name}' registered successfully.")
    return RedirectResponse(url="/admin/providers", status_code=302)


@router.get("/providers/{name}/delete", response_class=HTMLResponse, include_in_schema=False)
async def delete_provider_confirm(name: str, request: Request) -> HTMLResponse:
    if not _is_authenticated(request):
        return _redirect_to_login()  # type: ignore[return-value]
    db_path: str = request.app.state.db_path
    async with get_db(db_path) as conn:
        provider = await get_provider_by_name(conn, name)
    if provider is None:
        _set_flash(request, "error", "Provider not found.")
        return RedirectResponse(url="/admin/providers", status_code=302)  # type: ignore[return-value]
    return templates.TemplateResponse("admin/delete_confirm.html", {
        "request": request,
        "type": "provider",
        "item": provider,
        "cancel_url": "/admin/providers",
    })


@router.post("/providers/{name}/delete", include_in_schema=False)
async def delete_provider_action(name: str, request: Request) -> RedirectResponse:
    if not _is_authenticated(request):
        return _redirect_to_login()
    db_path: str = request.app.state.db_path
    async with get_db(db_path) as conn:
        deleted = await delete_provider(conn, name)
    if deleted:
        _set_flash(request, "success", f"Provider '{name}' deleted.")
    else:
        _set_flash(request, "error", "Provider not found.")
    return RedirectResponse(url="/admin/providers", status_code=302)
