"""Local password login, App Service Authentication headers, and the integration key."""

from __future__ import annotations

import base64
import json
import secrets

from itsdangerous import BadSignature, URLSafeSerializer
from starlette.requests import Request

from app.config import Settings
from app.errors import OpsError, Principal

COOKIE = "ase_user"
LOCAL_USERS = {
    "viewer@localhost": frozenset({"viewer"}),
    "approver@localhost": frozenset({"approver"}),
    "operator@localhost": frozenset({"operator", "approver"}),
    "admin@localhost": frozenset({"admin", "operator", "approver", "viewer"}),
}


def signer(settings: Settings) -> URLSafeSerializer:
    return URLSafeSerializer(settings.secret, salt="ase-ops")


def principal_from_request(request: Request) -> Principal | None:
    settings: Settings = request.app.state.settings
    header = request.headers.get("x-ms-client-principal")
    if header:
        return _easy_auth(header, settings)
    token = request.cookies.get(COOKIE)
    if not token or settings.app_env != "local":
        return None
    try:
        data = signer(settings).loads(token)
    except BadSignature:
        return None
    roles = LOCAL_USERS.get(data.get("name", ""))
    if roles is None:
        return None
    return Principal(data["name"], roles)


def login_local(settings: Settings, email: str, password: str) -> str:
    if settings.app_env != "local" or not settings.dev_login_password:
        raise OpsError(403, "forbidden", "local login is disabled")
    if email not in LOCAL_USERS or not secrets.compare_digest(password, settings.dev_login_password):
        raise OpsError(401, "unauthorized", "unknown user or password")
    return signer(settings).dumps({"name": email})


def _easy_auth(header: str, settings: Settings) -> Principal:
    try:
        payload = json.loads(base64.b64decode(header))
    except (ValueError, json.JSONDecodeError) as exc:
        raise OpsError(401, "unauthorized", "the Entra principal header is not valid") from exc
    claims = {item.get("typ"): item.get("val") for item in payload.get("claims", [])}
    name = claims.get("preferred_username") or claims.get("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress") or "unknown"
    raw_roles = [
        item.get("val")
        for item in payload.get("claims", [])
        if item.get("typ") in {"roles", "http://schemas.microsoft.com/ws/2008/06/identity/claims/role"}
    ]
    roles = frozenset(role for role in raw_roles if role)
    allowed = {item.strip().lower() for item in settings.poc_admins.split(",") if item.strip()}
    if str(name).lower() in allowed:
        roles = frozenset({"admin", "operator", "approver", "viewer"})
    elif not roles:
        roles = frozenset({"viewer"})
    return Principal(str(name), roles)
