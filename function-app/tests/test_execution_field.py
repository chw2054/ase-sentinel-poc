"""The execution field makes approval the only gate for a block."""

from __future__ import annotations

from function_app import _effective_config
from sentinel_waf_block.models import Config, Incident, InputError, incident_from_payload

BASE = Config(waf_policy_resource_id="/subscriptions/s/rg", waf_provider="ApplicationGateway")
INCIDENT_ID = "/subscriptions/s/workspaces/w/providers/Microsoft.SecurityInsights/incidents/i"


def _incident(execution: str) -> Incident:
    return Incident(arm_id=INCIDENT_ID, number="1", title="t", ip_entities=("203.0.113.5",), execution=execution)


def test_enforce_overrides_the_false_setting() -> None:
    merged = _effective_config(_incident("enforce"), BASE)
    assert merged.auto_block_enabled is True


def test_dry_run_overrides_the_true_setting() -> None:
    merged = _effective_config(_incident("dry-run"), Config(waf_policy_resource_id="/s", waf_provider="ApplicationGateway", auto_block_enabled=True))
    assert merged.auto_block_enabled is False


def test_absent_execution_keeps_the_setting() -> None:
    assert _effective_config(_incident(""), BASE).auto_block_enabled is False


def test_unknown_execution_is_rejected() -> None:
    for bad in ("ENFORCE", "block", "approve", None, True):
        payload = {
            "incidentArmId": INCIDENT_ID,
            "incidentNumber": "1",
            "incidentTitle": "t",
            "ipEntities": ["203.0.113.5"],
            "execution": bad,
        }
        if bad is None:
            payload["execution"] = None
        try:
            incident_from_payload(payload)
        except InputError:
            continue
        raise AssertionError(f"execution={bad!r} was accepted")


def test_absent_execution_field_parses() -> None:
    payload = {
        "incidentArmId": INCIDENT_ID,
        "incidentNumber": "1",
        "incidentTitle": "t",
        "ipEntities": ["203.0.113.5"],
    }
    assert incident_from_payload(payload).execution == ""
