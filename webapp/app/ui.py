"""Server-rendered pages. They call the same operations as the JSON API."""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Form, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import func, select

from app.auth import COOKIE, LOCAL_USERS, login_local, principal_from_request
from app.ops import OpsError
from app.orm import ApprovalRow, AuditRow, BlockRow, IncidentRow

ui = APIRouter()
templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))


def _render(request: Request, name: str, **extra):
    return templates.TemplateResponse(
        request,
        name,
        {
            "principal": principal_from_request(request),
            "users": sorted(LOCAL_USERS),
            "message": request.query_params.get("message", ""),
            "error": request.query_params.get("error", ""),
            **extra,
        },
    )


@ui.get("/")
def dashboard(request: Request):
    db = request.state.db
    pending = db.scalar(select(func.count()).select_from(ApprovalRow).where(ApprovalRow.state == "pending")) or 0
    incidents = db.scalar(select(func.count()).select_from(IncidentRow)) or 0
    blocks = db.scalar(select(func.count()).select_from(BlockRow).where(BlockRow.active == True)) or 0
    recent = db.scalars(select(IncidentRow).order_by(IncidentRow.received_at.desc()).limit(5)).all()
    return _render(
        request,
        "dashboard.html",
        pending=pending,
        incidents=incidents,
        blocks=blocks,
        cap=request.app.state.settings.product_cap,
        recent=recent,
        live=False,
    )


@ui.get("/login")
def login_form(request: Request):
    return _render(request, "login.html")


@ui.post("/login")
def login(request: Request, email: str = Form(...), password: str = Form(...)):
    try:
        token = login_local(request.app.state.settings, email, password)
    except OpsError as exc:
        return RedirectResponse(f"/login?error={exc}", status_code=303)
    response = RedirectResponse("/", status_code=303)
    response.set_cookie(COOKIE, token, httponly=True, samesite="lax")
    return response


@ui.post("/logout")
def logout() -> RedirectResponse:
    response = RedirectResponse("/", status_code=303)
    response.delete_cookie(COOKIE)
    return response


@ui.get("/incidents")
def incidents(request: Request, q: str = ""):
    if principal_from_request(request) is None:
        return RedirectResponse("/login", status_code=303)
    query = select(IncidentRow).order_by(IncidentRow.received_at.desc())
    rows = request.state.db.scalars(query).all()
    if q:
        rows = [row for row in rows if q in row.title or q in row.ip_address or q in row.incident_number]
    return _render(request, "incidents.html", rows=rows, q=q)


@ui.get("/incidents/{incident_id}")
def incident_detail(request: Request, incident_id: str):
    if principal_from_request(request) is None:
        return RedirectResponse("/login", status_code=303)
    row = request.state.db.get(IncidentRow, incident_id)
    approvals = request.state.db.scalars(select(ApprovalRow).where(ApprovalRow.incident_id == incident_id)).all()
    return _render(request, "incident.html", incident=row, approvals=approvals)


@ui.post("/incidents/{incident_id}/retry")
def incident_retry(request: Request, incident_id: str):
    actor = principal_from_request(request)
    if actor is None:
        return RedirectResponse("/login", status_code=303)
    try:
        request.app.state.ops.retry(request.state.db, incident_id, actor)
    except OpsError as exc:
        return RedirectResponse(f"/incidents/{incident_id}?error={exc}", status_code=303)
    return RedirectResponse(f"/incidents/{incident_id}?message=Approval+reopened", status_code=303)


@ui.get("/approvals")
def approvals(request: Request, state: str = ""):
    if principal_from_request(request) is None:
        return RedirectResponse("/login", status_code=303)
    query = select(ApprovalRow).order_by(ApprovalRow.created_at.desc())
    if state:
        query = query.where(ApprovalRow.state == state)
    rows = request.state.db.scalars(query).all()
    return _render(request, "approvals.html", rows=rows, state=state)


@ui.get("/approvals/{approval_id}")
def approval_detail(request: Request, approval_id: str):
    if principal_from_request(request) is None:
        return RedirectResponse(f"/login?next=/approvals/{approval_id}", status_code=303)
    try:
        payload = request.app.state.ops._approval_payload(
            request.state.db,
            request.app.state.ops._approval(request.state.db, approval_id),
        )
    except OpsError as exc:
        return _render(request, "approval.html", approval=None, error=str(exc))
    return _render(request, "approval.html", approval=payload)


@ui.post("/approvals/{approval_id}/decision")
def approval_decision(
    request: Request,
    approval_id: str,
    decision: str = Form(...),
    version: int = Form(...),
    comment: str = Form(""),
):
    actor = principal_from_request(request)
    if actor is None:
        return RedirectResponse("/login", status_code=303)
    try:
        request.app.state.ops.decide(request.state.db, approval_id, actor, decision, version, comment)
    except OpsError as exc:
        return RedirectResponse(f"/approvals/{approval_id}?error={exc}", status_code=303)
    return RedirectResponse(f"/approvals/{approval_id}?message=Decision+recorded", status_code=303)


@ui.get("/blocks")
def blocks(request: Request, q: str = ""):
    if principal_from_request(request) is None:
        return RedirectResponse("/login", status_code=303)
    policy_key = request.app.state.waf.get_default_key()
    rows = request.state.db.scalars(
        select(BlockRow).where(BlockRow.policy_key == policy_key, BlockRow.active == True)
    ).all()
    if q:
        rows = [row for row in rows if q in row.cidr]
    return _render(request, "blocks.html", rows=rows, q=q, policy_key=policy_key, cap=request.app.state.settings.product_cap)


@ui.post("/blocks/preview")
def blocks_preview(request: Request, cidr: str = Form(...), reason: str = Form("")):
    actor = principal_from_request(request)
    if actor is None:
        return RedirectResponse("/login", status_code=303)
    try:
        preview = request.app.state.ops.add_block(request.state.db, actor, cidr, reason, False)
    except OpsError as exc:
        return RedirectResponse(f"/blocks?error={exc}", status_code=303)
    return _render(request, "blocks.html", rows=[], q="", policy_key="", cap=request.app.state.settings.product_cap, preview=preview, cidr=cidr, reason=reason)


@ui.post("/blocks")
def blocks_add(request: Request, cidr: str = Form(...), reason: str = Form("")):
    actor = principal_from_request(request)
    if actor is None:
        return RedirectResponse("/login", status_code=303)
    try:
        request.app.state.ops.add_block(request.state.db, actor, cidr, reason, True)
    except OpsError as exc:
        return RedirectResponse(f"/blocks?error={exc}", status_code=303)
    return RedirectResponse("/blocks?message=Block+list+updated", status_code=303)


@ui.post("/blocks/{entry_id}/remove")
def blocks_remove(request: Request, entry_id: str, host: str = Form(""), split_external: str = Form("")):
    actor = principal_from_request(request)
    if actor is None:
        return RedirectResponse("/login", status_code=303)
    try:
        request.app.state.ops.remove_block(
            request.state.db,
            actor,
            entry_id,
            host=host,
            split_external=split_external == "yes",
            apply=True,
        )
    except OpsError as exc:
        return RedirectResponse(f"/blocks?error={exc}", status_code=303)
    return RedirectResponse("/blocks?message=Entry+removed", status_code=303)


@ui.get("/discovery")
def discovery(request: Request):
    if principal_from_request(request) is None:
        return RedirectResponse("/login", status_code=303)
    catalog = request.app.state.ops
    from app.waf import fixture_catalog

    return _render(request, "discovery.html", catalog=fixture_catalog(), config=catalog.configuration(request.state.db))


@ui.post("/discovery/confirm")
def discovery_confirm(request: Request, policy_key: str = Form(...)):
    actor = principal_from_request(request)
    if actor is None:
        return RedirectResponse("/login", status_code=303)
    from app.waf import fixture_catalog

    match = next((item for item in fixture_catalog().policies if item["policyKey"] == policy_key), None)
    if match is None or match["provider"] != "ApplicationGateway":
        return RedirectResponse("/discovery?error=Choose+an+Application+Gateway+policy", status_code=303)
    try:
        request.app.state.ops.save_configuration(
            request.state.db,
            actor,
            {
                "policyKey": policy_key,
                "wafProvider": "ApplicationGateway",
                "policyName": match["name"],
                "source": "user-confirmed-fixture",
            },
        )
    except OpsError as exc:
        return RedirectResponse(f"/discovery?error={exc}", status_code=303)
    return RedirectResponse("/discovery?message=Configuration+saved", status_code=303)


@ui.get("/settings")
def settings_page(request: Request):
    if principal_from_request(request) is None:
        return RedirectResponse("/login", status_code=303)
    return _render(
        request,
        "settings.html",
        settings=request.app.state.settings,
        config=request.app.state.ops.configuration(request.state.db),
    )


@ui.get("/audit")
def audit(request: Request):
    if principal_from_request(request) is None:
        return RedirectResponse("/login", status_code=303)
    rows = request.state.db.scalars(select(AuditRow).order_by(AuditRow.created_at.desc()).limit(100)).all()
    return _render(request, "audit.html", rows=rows)
