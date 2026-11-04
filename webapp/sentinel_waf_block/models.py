"""Typed input, configuration, and the structured execution result."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


APPLICATION_GATEWAY = "ApplicationGateway"
FRONT_DOOR = "FrontDoor"
PROVIDERS = frozenset({APPLICATION_GATEWAY, FRONT_DOOR})
# One IPMatch condition holds 600 values. Another custom rule on the same policy extends the list.
MATCH_VALUES_PER_POLICY = 600
BLOCK_POLICY_TAG = "ase-sentinel-block-list"

STATUS_AWAITING_APPROVAL = "awaiting-approval"
STATUS_APPROVED = "approved"
STATUS_ALREADY_BLOCKED = "already-blocked"
STATUS_REMOVED = "removed"
STATUS_NOT_LISTED = "not-listed"
STATUS_NOTHING = "nothing-to-block"
STATUS_CAPACITY = "capacity-exceeded"
STATUS_RANGES = "protected-ranges-invalid"
STATUS_VALIDATION = "validation-failed"
STATUS_PROVIDER = "unsupported-provider"
STATUS_GET = "waf-get-failed"
STATUS_SHAPE = "policy-shape-invalid"
STATUS_PUT = "waf-put-failed"
STATUS_COMMENT = "blocked-comment-failed"
STATUS_INTERNAL = "internal-error"


@dataclass(frozen=True)
class Incident:
    """Normalized Sentinel incident. Addresses are raw entity strings."""

    arm_id: str
    number: str
    title: str
    ip_entities: tuple[str, ...]
    # "" lets the deployed setting decide. "awaiting-approval" never PUTs.
    # "approved" PUTs on this request only, which is how the playbook acts
    # after the approver chooses Approve. The engine still re-validates every address.
    execution: str = ""


@dataclass(frozen=True)
class Config:
    """Deployment settings. Booleans are not coerced from strings."""

    waf_policy_resource_id: str
    waf_provider: str
    protected_ip_ranges: tuple[str, ...] = ()
    auto_block_enabled: object = False
    override_protected_ranges: object = False
    block_rule_name: str = "SentinelAutoBlock"
    block_rule_priority: int = 10
    arm_api_version: str = "2024-05-01"


@dataclass(frozen=True)
class Rejection:
    value: str
    reason: str


@dataclass(frozen=True)
class Result:
    status: str
    changed: bool = False
    candidate_addresses: tuple[str, ...] = ()
    new_addresses: tuple[str, ...] = ()
    rejected_addresses: tuple[Rejection, ...] = ()
    existing_count: int | None = None
    resulting_count: int | None = None
    reason: str = ""
    invalid_protected_ranges: tuple[str, ...] = ()
    comment: str = ""
    comment_error: str = ""
    notify_error: str = ""
    policy_resource_id: str = ""
    written_rule: str = ""
    written_priority: int = 0

    def to_dict(self) -> dict[str, Any]:
        body: dict[str, Any] = {
            "status": self.status,
            "changed": self.changed,
            "candidate_addresses": list(self.candidate_addresses),
            "new_addresses": list(self.new_addresses),
            "rejected_addresses": [
                {"value": item.value, "reason": item.reason} for item in self.rejected_addresses
            ],
            "existing_count": self.existing_count,
            "resulting_count": self.resulting_count,
            "reason": self.reason,
            "invalid_protected_ranges": list(self.invalid_protected_ranges),
            "comment": self.comment,
            "comment_error": self.comment_error,
            "notify_error": self.notify_error,
            "policy_resource_id": self.policy_resource_id,
            "written_rule": self.written_rule,
            "written_priority": self.written_priority,
        }
        return body


class InputError(ValueError):
    """The HTTP payload is not a usable incident."""


def incident_from_payload(payload: object) -> Incident:
    """Map the function JSON object to an incident. Raises InputError."""

    if not isinstance(payload, dict):
        raise InputError("request body must be a JSON object")
    missing = [
        key
        for key in ("incidentArmId", "incidentNumber", "incidentTitle", "ipEntities")
        if key not in payload
    ]
    if missing:
        raise InputError("missing fields: " + ", ".join(missing))
    arm_id = payload["incidentArmId"]
    title = payload["incidentTitle"]
    number = payload["incidentNumber"]
    entities = payload["ipEntities"]
    if not isinstance(arm_id, str) or not arm_id.startswith("/"):
        raise InputError("incidentArmId must be an ARM resource id")
    if not isinstance(title, str):
        raise InputError("incidentTitle must be a string")
    if isinstance(number, bool) or not isinstance(number, (int, str)):
        raise InputError("incidentNumber must be a string or integer")
    if isinstance(number, str) and number.strip() != number:
        raise InputError("incidentNumber must not contain surrounding whitespace")
    if not isinstance(entities, list) or any(not isinstance(item, str) for item in entities):
        raise InputError("ipEntities must be an array of strings")
    execution = payload.get("execution", "")
    if execution not in ("", "awaiting-approval", "approved"):
        raise InputError('execution must be "awaiting-approval" or "approved"')
    return Incident(
        arm_id=arm_id,
        number=str(number),
        title=title,
        ip_entities=tuple(entities),
        execution=execution,
    )


def manual_from_payload(payload: object) -> tuple[str, str, str] | None:
    """Return add/remove fields, or None when the body is an incident call.

    The playbook omits operation. A manual edit from the operations app sends
    operation add or remove and one address.
    """

    if not isinstance(payload, dict) or "operation" not in payload:
        return None
    operation = payload["operation"]
    if operation not in {"add", "remove"}:
        raise InputError("operation must be add or remove")
    address = payload.get("address")
    if not isinstance(address, str):
        raise InputError("address must be a string")
    execution = payload.get("execution", "")
    if execution not in ("", "awaiting-approval", "approved"):
        raise InputError('execution must be "awaiting-approval" or "approved"')
    return operation, address, execution
