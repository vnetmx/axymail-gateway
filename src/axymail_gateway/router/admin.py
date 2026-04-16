"""
Admin dashboard — server-side rendered HTML via Jinja2.

Authentication: the admin key is submitted via a password form (POST /admin/login),
stored in a signed session cookie, and checked on every protected route.
No key in the URL, no JavaScript prompts.
"""
from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from axymail_gateway.database import delete_account, get_account_by_id, get_db, list_accounts

router = APIRouter(prefix="/admin", tags=["admin"])

_TEMPLATES_DIR = Path(__file__).parent.parent / "templates"
templates = Jinja2Templates(directory=str(_TEMPLATES_DIR))


# ── helpers ──────────────────────────────────────────────────────────────────

def _is_authenticated(request: Request) -> bool:
    return bool(request.session.get("admin_authenticated"))


def _redirect_to_login() -> RedirectResponse:
    return RedirectResponse(url="/admin/login", status_code=302)


def _pop_flash(request: Request) -> dict | None:
    """Read and clear the one-shot flash message from the session."""
    return request.session.pop("flash", None)


def _set_flash(request: Request, kind: str, msg: str) -> None:
    request.session["flash"] = {"type": kind, "msg": msg}


# ── auth routes ───────────────────────────────────────────────────────────────

@router.get("/login", response_class=HTMLResponse, include_in_schema=False)
async def login_page(request: Request) -> HTMLResponse:
    if _is_authenticated(request):
        return RedirectResponse(url="/admin/", status_code=302)  # type: ignore[return-value]

    return templates.TemplateResponse(
        "admin/login.html",
        {
            "request": request,
            "admin_configured": bool(request.app.state.admin_api_key),
            "error": request.session.pop("login_error", None),
        },
    )


@router.post("/login", include_in_schema=False)
async def login(
    request: Request,
    api_key: str = Form(...),
) -> RedirectResponse:
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


# ── dashboard ────────────────────────────────────────────────────────────────

@router.get("/", response_class=HTMLResponse, include_in_schema=False)
async def dashboard(request: Request) -> HTMLResponse:
    if not _is_authenticated(request):
        return _redirect_to_login()  # type: ignore[return-value]

    db_path: str = request.app.state.db_path
    async with get_db(db_path) as conn:
        accounts = await list_accounts(conn)

    return templates.TemplateResponse(
        "admin/dashboard.html",
        {
            "request": request,
            "accounts": accounts,
            "flash": _pop_flash(request),
        },
    )


# ── account delete ────────────────────────────────────────────────────────────

@router.get("/accounts/{account_id}/delete", response_class=HTMLResponse, include_in_schema=False)
async def delete_confirm_page(account_id: str, request: Request) -> HTMLResponse:
    if not _is_authenticated(request):
        return _redirect_to_login()  # type: ignore[return-value]

    db_path: str = request.app.state.db_path
    async with get_db(db_path) as conn:
        account = await get_account_by_id(conn, account_id)

    if account is None:
        _set_flash(request, "error", "Account not found.")
        return RedirectResponse(url="/admin/", status_code=302)  # type: ignore[return-value]

    return templates.TemplateResponse(
        "admin/delete_confirm.html",
        {"request": request, "account": account},
    )


@router.post("/accounts/{account_id}/delete", include_in_schema=False)
async def delete_account_action(account_id: str, request: Request) -> RedirectResponse:
    if not _is_authenticated(request):
        return _redirect_to_login()

    db_path: str = request.app.state.db_path
    async with get_db(db_path) as conn:
        deleted = await delete_account(conn, account_id)

    if deleted:
        _set_flash(request, "success", "Account deleted successfully.")
    else:
        _set_flash(request, "error", "Account not found.")

    return RedirectResponse(url="/admin/", status_code=302)
