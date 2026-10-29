"""Thin HTTP adapter. Business rules live in sentinel_waf_block."""

from __future__ import annotations

import json
import logging
import os
from dataclasses import replace

import azure.functions as func

from sentinel_waf_block.azure_clients import ArmWafClient, SentinelCommentClient
from sentinel_waf_block.config import ConfigError, config_from_env
from sentinel_waf_block.engine import Engine
from sentinel_waf_block.models import (
    STATUS_INTERNAL,
    STATUS_VALIDATION,
    Config,
    Incident,
    InputError,
    incident_from_payload,
)
from sentinel_waf_block.notifiers import DEFAULT_EVENTS, FLOW_AUDIENCE, TeamsWorkflowNotifier

log = logging.getLogger("sentinel_waf_block.function")
app = func.FunctionApp(http_auth_level=func.AuthLevel.FUNCTION)


def _effective_config(incident: Incident, config: Config) -> Config:
    # The execution field is authoritative and fail-closed: even a deployment
    # with AUTO_BLOCK_ENABLED=true cannot block on the evaluation call. The
    # playbook sends execution=enforce only after an approver chose Approve,
    # so approval stays the only gate.
    if incident.execution == "enforce":
        return replace(config, auto_block_enabled=True)
    if incident.execution == "dry-run":
        return replace(config, auto_block_enabled=False)
    return config


def _notifier_from_env() -> TeamsWorkflowNotifier | None:
    url = os.environ.get("NOTIFY_TEAMS_URL", "")
    if not url:
        return None
    raw = os.environ.get("NOTIFY_EVENTS", "")
    events = tuple(item.strip() for item in raw.split(",") if item.strip()) or DEFAULT_EVENTS
    # New Workflows triggers authenticate with Entra tokens instead of a URL
    # signature. NOTIFY_TEAMS_AUTH=entra switches the notifier to send the
    # managed identity token for the flow service audience.
    auth_scope = FLOW_AUDIENCE if os.environ.get("NOTIFY_TEAMS_AUTH", "").lower() == "entra" else ""
    return TeamsWorkflowNotifier(url, events=events, auth_scope=auth_scope)


@app.route(route="SentinelWafAutoBlock", methods=["POST"])
def sentinel_waf_auto_block(req: func.HttpRequest) -> func.HttpResponse:
    try:
        payload = req.get_json()
    except ValueError:
        return _response(
            {"status": STATUS_VALIDATION, "changed": False, "reason": "request body is not JSON"},
            400,
        )
    try:
        incident = incident_from_payload(payload)
        config = config_from_env()
    except InputError as exc:
        return _response({"status": STATUS_VALIDATION, "changed": False, "reason": str(exc)}, 400)
    except ConfigError as exc:
        return _response(
            {"status": STATUS_VALIDATION, "changed": False, "reason": "configuration: " + str(exc)},
            500,
        )
    try:
        result = Engine(ArmWafClient(), SentinelCommentClient(), _notifier_from_env()).execute(
            incident, _effective_config(incident, config)
        )
    except Exception:
        log.warning("unhandled failure during execution")
        return _response({"status": STATUS_INTERNAL, "changed": False, "reason": "internal error"}, 500)
    return _response(result.to_dict(), 200)


def _response(body: dict[str, object], status: int) -> func.HttpResponse:
    return func.HttpResponse(json.dumps(body), status_code=status, mimetype="application/json")
