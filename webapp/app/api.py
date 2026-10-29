"""JSON API. State changes are POST, PUT, or DELETE. None are GET."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from sqlalchemy import func, select

from app.auth import integration_principal, require_user
from app.cidr import PLATFORM_MATCH_VALUES
from app.ops import OpsError
from app.orm import ApprovalRow, AuditRow, BlockRow, IncidentRow
from app.waf import fixture_catalog

router = APIRouter()


def install_errors(app) -> None:
    @app.exception_handler(OpsError)
    async def handle(request: Request, exc: OpsError) -> JSONResponse:
        return JSONResponse(status_code=exc.status, content={"error": {"code": exc.code, "message": str(exc)}})


@router.get("/health")
def health(request: Request) -> dict:
    policy = request.app.state.waf.get_default_key()
    return {"status": "ok", "waf": "fixture", "policyKey": policy, "liveAzure": False}


@router.get("/api/v1/discovery/subscriptions")
def subscriptions(request: Request) -> dict:
    require_user(request)
    return {"source": "fixture", "items": fixture_catalog().subscriptions}


@router.get("/api/v1/discovery/resource-groups")
def resource_groups(request: Request) -> dict:
    require_user(request)
    return {"source": "fixture", "items": fixture_catalog().resource_groups}


@router.get("/api/v1/discovery/log-analytics")
def workspaces(request: Request) -> dict:
    require_user(request)
    return {"source": "fixture", "items": fixture_catalog().workspaces}


@router.get("/api/v1/discovery/sentinel")
def sentinel(request: Request) -> dict:
    require_user(request)
    items = [item for item in fixture_catalog().workspaces if item.get("sentinel") == "enabled"]
    return {"source": "fixture", "items": items}


@router.get("/api/v1/discovery/application-gateways")
def gateways(request: Request) -> dict:
    require_user(request)
    return {"source": "fixture", "items": fixture_catalog().gateways}


@router.get("/api/v1/discovery/waf-policies")
def policies(request: Request) -> dict:
    require_user(request)
    items = [item for item in fixture_catalog().policies if item["provider"] == "ApplicationGateway"]
    return {"source": "fixture", "items": items}


@router.get("/api/v1/configuration")
def get_configuration(request: Request) -> dict:
    require_user(request)
    return request.app.state.ops.configuration(request.state.db)


@router.put("/api/v1/configuration")
def put_configuration(request: Request, body: dict) -> dict:
    actor = require_user(request)
    return request.app.state.ops.save_configuration(request.state.db, actor, body)


@router.post("/api/v1/integrations/sentinel/incidents")
def ingest(request: Request, body: dict) -> dict:
    integration_principal(request)
    correlation = request.headers.get("x-correlation-id") or str(uuid.uuid4())
    return request.app.state.ops.ingest(request.state.db, body, correlation)


@router.post("/api/v1/integrations/notifications/status")
def notification_status(request: Request, body: dict) -> dict:
    actor = integration_principal(request)
    request.app.state.ops.audit(
        request.state.db,
        actor.name,
        "notification_status",
        str(body.get("approvalId") or ""),
        {"status": body.get("status")},
    )
    return {"recorded": True}


@router.get("/api/v1/incidents")
def list_incidents(request: Request, q: str = "", status: str = "", limit: int = 50, offset: int = 0) -> dict:
    require_user(request)
    limit = max(1, min(limit, 100))
    query = select(IncidentRow)
    if status:
        query = query.where(IncidentRow.processing_status == status)
    if q:
        like = f"%{q}%"
        query = query.where((IncidentRow.title.like(like)) | (IncidentRow.ip_address.like(like)) | (IncidentRow.incident_number.like(like)))
    total = request.state.db.scalar(select(func.count()).select_from(query.subquery()))
    rows = request.state.db.scalars(query.order_by(IncidentRow.received_at.desc()).offset(offset).limit(limit)).all()
    return {"total": total, "items": [_incident(row) for row in rows]}


@router.get("/api/v1/incidents/{incident_id}")
def get_incident(request: Request, incident_id: str) -> dict:
    require_user(request)
    row = request.state.db.get(IncidentRow, incident_id)
    if row is None:
        raise OpsError(404, "not_found", "incident not found")
    approvals = request.state.db.scalars(select(ApprovalRow).where(ApprovalRow.incident_id == incident_id)).all()
    payload = _incident(row)
    payload["approvals"] = [_approval_brief(item) for item in approvals]
    return payload


@router.post("/api/v1/incidents/{incident_id}/retry")
def retry_incident(request: Request, incident_id: str) -> dict:
    actor = require_user(request)
    return request.app.state.ops.retry(request.state.db, incident_id, actor)


@router.get("/api/v1/approvals")
def list_approvals(request: Request, state: str = "", limit: int = 50, offset: int = 0) -> dict:
    require_user(request)
    limit = max(1, min(limit, 100))
    query = select(ApprovalRow)
    if state:
        query = query.where(ApprovalRow.state == state)
    total = request.state.db.scalar(select(func.count()).select_from(query.subquery()))
    rows = request.state.db.scalars(query.order_by(ApprovalRow.created_at.desc()).offset(offset).limit(limit)).all()
    return {"total": total, "items": [_approval_brief(row) for row in rows]}


@router.get("/api/v1/approvals/{approval_id}")
def get_approval(request: Request, approval_id: str) -> dict:
    require_user(request)
    return request.app.state.ops._approval_payload(request.state.db, request.app.state.ops._approval(request.state.db, approval_id))


@router.post("/api/v1/approvals/{approval_id}/decision")
def decide(request: Request, approval_id: str, body: dict) -> dict:
    actor = require_user(request)
    return request.app.state.ops.decide(
        request.state.db,
        approval_id,
        actor,
        str(body.get("decision") or ""),
        int(body.get("version") or 0),
        str(body.get("comment") or ""),
    )


@router.post("/api/v1/approvals/{approval_id}/resume")
def resume(request: Request, approval_id: str) -> dict:
    actor = require_user(request)
    return request.app.state.ops.resume_execution(request.state.db, approval_id, actor)


@router.get("/api/v1/waf/policies")
def waf_policies(request: Request) -> dict:
    require_user(request)
    policy = request.app.state.waf.get(request.app.state.waf.get_default_key())
    return {
        "liveAzure": False,
        "items": [
            {
                "policyKey": policy.policy_key,
                "name": policy.name,
                "provider": policy.provider,
                "etag": policy.etag,
                "productCap": request.app.state.settings.product_cap,
                "platformCap": PLATFORM_MATCH_VALUES,
            }
        ],
    }


@router.get("/api/v1/waf/policies/{policy_key}/blocks")
def list_blocks(request: Request, policy_key: str, q: str = "") -> dict:
    require_user(request)
    rows = request.state.db.scalars(select(BlockRow).where(BlockRow.policy_key == policy_key, BlockRow.active == True)).all()
    items = [_block(row) for row in rows if not q or q in row.cidr]
    return {"items": items, "count": len(items), "productCap": request.app.state.settings.product_cap, "platformCap": PLATFORM_MATCH_VALUES}


@router.post("/api/v1/waf/policies/{policy_key}/preview")
def preview_add(request: Request, policy_key: str, body: dict) -> dict:
    actor = require_user(request)
    if body.get("removeEntryId"):
        return request.app.state.ops.remove_block(
            request.state.db,
            actor,
            str(body["removeEntryId"]),
            host=str(body.get("host") or ""),
            split_external=bool(body.get("splitExternal")),
            apply=False,
        )
    return request.app.state.ops.add_block(request.state.db, actor, str(body.get("cidr") or ""), str(body.get("reason") or ""), False)


@router.post("/api/v1/waf/policies/{policy_key}/blocks")
def add_block(request: Request, policy_key: str, body: dict) -> dict:
    actor = require_user(request)
    return request.app.state.ops.add_block(
        request.state.db,
        actor,
        str(body.get("cidr") or ""),
        str(body.get("reason") or ""),
        True,
    )


@router.delete("/api/v1/waf/policies/{policy_key}/blocks/{entry_id}")
def delete_block(request: Request, policy_key: str, entry_id: str, host: str = "", split_external: bool = False) -> dict:
    actor = require_user(request)
    return request.app.state.ops.remove_block(
        request.state.db,
        actor,
        entry_id,
        host=host,
        split_external=split_external,
        apply=True,
    )


@router.post("/api/v1/operations/reconcile")
def reconcile(request: Request, body: dict | None = None) -> dict:
    actor = require_user(request)
    payload = body or {}
    return request.app.state.ops.reconcile(request.state.db, actor, bool(payload.get("repair")))


@router.get("/api/v1/audit-logs")
def audit(request: Request, limit: int = 50, offset: int = 0) -> dict:
    require_user(request)
    limit = max(1, min(limit, 100))
    total = request.state.db.scalar(select(func.count()).select_from(AuditRow))
    rows = request.state.db.scalars(select(AuditRow).order_by(AuditRow.created_at.desc()).offset(offset).limit(limit)).all()
    return {
        "total": total,
        "items": [
            {
                "id": row.id,
                "actor": row.actor,
                "action": row.action,
                "target": row.target,
                "detail": row.detail,
                "createdAt": row.created_at.isoformat(),
            }
            for row in rows
        ],
    }


def _incident(row: IncidentRow) -> dict:
    return {
        "id": row.id,
        "sentinelId": row.sentinel_id,
        "number": row.incident_number,
        "title": row.title,
        "severity": row.severity,
        "sentinelStatus": row.sentinel_status,
        "sentinelUrl": row.sentinel_url,
        "ipAddress": row.ip_address,
        "processingStatus": row.processing_status,
        "correlationId": row.correlation_id,
        "receivedAt": row.received_at.isoformat(),
    }


def _approval_brief(row: ApprovalRow) -> dict:
    return {
        "id": row.id,
        "incidentId": row.incident_id,
        "state": row.state,
        "version": row.version,
        "proposed": row.proposed,
        "reviewer": row.reviewer,
        "createdAt": row.created_at.isoformat(),
    }


def _block(row: BlockRow) -> dict:
    return {
        "id": row.id,
        "cidr": row.cidr,
        "ownership": row.ownership,
        "ruleName": row.rule_name,
        "reason": row.reason,
        "incidentId": row.incident_id,
        "approvalId": row.approval_id,
        "createdAt": row.created_at.isoformat(),
    }
