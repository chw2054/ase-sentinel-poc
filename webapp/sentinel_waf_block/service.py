"""HTTP-agnostic entry point used by the operations app and its block API.

The playbook posts incident JSON to this entry point. The page
handlers call this directly. Neither path imports a web framework.
"""

from __future__ import annotations

import logging
import os
from dataclasses import replace

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
    manual_from_payload,
)
from sentinel_waf_block.notifiers import DEFAULT_EVENTS, FLOW_AUDIENCE, TeamsWorkflowNotifier

log = logging.getLogger("sentinel_waf_block.service")


def execution_override(execution: str, config: Config) -> Config:
    # execution is authoritative and fail-closed. The playbook sends
    # execution=approved only after an approver chose Approve. The operations
    # app sends it for a manual add, remove, or incident block.
    if execution == "approved":
        return replace(config, auto_block_enabled=True)
    if execution == "awaiting-approval":
        return replace(config, auto_block_enabled=False)
    return config


def effective_config(incident: Incident, config: Config) -> Config:
    return execution_override(incident.execution, config)


def notifier_from_env() -> TeamsWorkflowNotifier | None:
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


def execute_payload(payload: object) -> tuple[int, dict[str, object]]:
    """Run one block request. Returns an HTTP status and a JSON object."""

    try:
        manual = manual_from_payload(payload)
        config = config_from_env()
        incident = None if manual is not None else incident_from_payload(payload)
    except InputError as exc:
        return 400, {"status": STATUS_VALIDATION, "changed": False, "reason": str(exc)}
    except ConfigError as exc:
        return 500, {"status": STATUS_VALIDATION, "changed": False, "reason": "configuration: " + str(exc)}
    try:
        engine = Engine(ArmWafClient(), SentinelCommentClient(), notifier_from_env())
        if manual is not None:
            operation, address, execution = manual
            shown = execution_override(execution, config)
            result = engine.add_entry(address, shown) if operation == "add" else engine.remove_entry(address, shown)
        else:
            assert incident is not None
            result = engine.execute(incident, effective_config(incident, config))
    except Exception:
        log.warning("unhandled failure during execution")
        return 500, {"status": STATUS_INTERNAL, "changed": False, "reason": "internal error"}
    return 200, result.to_dict()
