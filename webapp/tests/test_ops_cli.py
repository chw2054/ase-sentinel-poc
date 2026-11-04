"""The local operations CLI reads Azure with a stdin token and does not print it."""

import json
from io import StringIO

import pytest

from app.live import AzureCallError, GatewayView, Inventory, LiveIncident, PolicyView, RuleView
from ase_sentinel_ops.cli import main

SUB = "ae4654a2-8a96-431c-ad3d-176ae51ec9d8"
RG = "rg-ase-sentinel-poc"
WORKSPACE = "log-ase-sentinel-poc"
POLICY = (
    f"/subscriptions/{SUB}/resourceGroups/{RG}/providers/Microsoft.Network/"
    "applicationGatewayWebApplicationFirewallPolicies/wafpol-ase-sentinel-poc"
)
INCIDENT = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
TOKEN = "header.payload.signature"


class FakeAzure:
    def __init__(self) -> None:
        self.token_calls = 0

    def list_open(self) -> list[LiveIncident]:
        return [
            LiveIncident(
                INCIDENT,
                "19",
                "probe",
                "Medium",
                "Active",
                "2026-11-03T08:35:00Z",
                f"/subscriptions/{SUB}/resourceGroups/{RG}/providers/Microsoft.SecurityInsights/incidents/{INCIDENT}",
                ("203.0.113.9",),
            )
        ]

    def get(self, incident_id: str) -> LiveIncident:
        found = self.list_open()[0]
        assert incident_id == found.id
        return found

    def inventory(self) -> Inventory:
        policy = PolicyView(
            "wafpol-ase-sentinel-poc",
            POLICY,
            (RuleView("SentinelAutoBlock", ("203.0.113.4",)),),
            (GatewayView("agw-ase-sentinel-poc", "http://203.0.113.20"),),
        )
        return Inventory(WORKSPACE, f"/subscriptions/{SUB}/workspaces/{WORKSPACE}", (policy,), "")


def _env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AZURE_SUBSCRIPTION_ID", SUB)
    monkeypatch.setenv("AZURE_RESOURCE_GROUP", RG)
    monkeypatch.setenv("SENTINEL_WORKSPACE_NAME", WORKSPACE)
    monkeypatch.setenv("WAF_POLICY_RESOURCE_ID", POLICY)
    monkeypatch.setenv("BLOCK_API_KEY", "must-not-appear")


def _run(argv: list[str], factory, token: str = TOKEN) -> tuple[int, dict, str]:
    stdout = StringIO()
    code = main(argv, stdin=StringIO(token + "\n"), stdout=stdout, azure_factory=factory)
    text = stdout.getvalue()
    return code, json.loads(text), text


def test_list_returns_incidents_and_hides_the_token(monkeypatch: pytest.MonkeyPatch) -> None:
    _env(monkeypatch)
    seen: dict = {}

    def factory(settings, token: str) -> FakeAzure:
        seen["token"] = token
        seen["key"] = settings.block_api_key
        seen["policy"] = settings.waf_policy_id
        return FakeAzure()

    code, payload, text = _run(["list"], factory)
    assert code == 0
    assert payload["incidents"][0]["number"] == "19"
    assert payload["incidents"][0]["ips"] == ["203.0.113.9"]
    assert seen["token"] == TOKEN
    assert seen["key"] == ""
    assert seen["policy"] == POLICY
    assert TOKEN not in text
    assert "must-not-appear" not in text


def test_inventory_returns_the_pinned_policy(monkeypatch: pytest.MonkeyPatch) -> None:
    _env(monkeypatch)
    code, payload, _text = _run(["inventory"], lambda _settings, _token: FakeAzure())
    assert code == 0
    assert payload["policies"][0]["rules"][0]["values"] == ["203.0.113.4"]
    assert payload["policies"][0]["gateways"][0]["url"] == "http://203.0.113.20"


def test_show_rejects_a_non_guid_before_calling_azure(monkeypatch: pytest.MonkeyPatch) -> None:
    _env(monkeypatch)
    called = False

    def factory(_settings, _token):
        nonlocal called
        called = True
        return FakeAzure()

    code, payload, text = _run(["show", "../not-a-guid"], factory)
    assert code == 2
    assert payload["error"] == "incident id must be a GUID"
    assert called is False
    assert TOKEN not in text


def test_show_reads_one_incident(monkeypatch: pytest.MonkeyPatch) -> None:
    _env(monkeypatch)
    code, payload, _text = _run(["show", INCIDENT], lambda _settings, _token: FakeAzure())
    assert code == 0
    assert payload["incident"]["id"] == INCIDENT


def test_missing_settings_do_not_call_azure(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AZURE_SUBSCRIPTION_ID", raising=False)
    monkeypatch.delenv("AZURE_RESOURCE_GROUP", raising=False)
    monkeypatch.delenv("SENTINEL_WORKSPACE_NAME", raising=False)
    monkeypatch.delenv("WAF_POLICY_RESOURCE_ID", raising=False)
    called = False

    def factory(_settings, _token):
        nonlocal called
        called = True
        return FakeAzure()

    code, payload, _text = _run(["list"], factory)
    assert code == 2
    assert "AZURE_SUBSCRIPTION_ID" in payload["error"]
    assert called is False


def test_policy_outside_the_pinned_subscription_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    _env(monkeypatch)
    other = "11111111-2222-3333-4444-555555555555"
    monkeypatch.setenv(
        "WAF_POLICY_RESOURCE_ID",
        f"/subscriptions/{other}/resourceGroups/{RG}/providers/Microsoft.Network/"
        "applicationGatewayWebApplicationFirewallPolicies/wafpol-ase-sentinel-poc",
    )
    code, payload, _text = _run(["list"], lambda _settings, _token: FakeAzure())
    assert code == 2
    assert "AZURE_SUBSCRIPTION_ID" in payload["error"]


def test_a_non_waf_resource_id_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    _env(monkeypatch)
    monkeypatch.setenv(
        "WAF_POLICY_RESOURCE_ID",
        f"/subscriptions/{SUB}/resourceGroups/{RG}/providers/Microsoft.Network/applicationGateways/agw",
    )
    code, payload, _text = _run(["list"], lambda _settings, _token: FakeAzure())
    assert code == 2
    assert "WAF policy" in payload["error"]


def test_portal_and_arm_policy_id_casing_are_accepted(monkeypatch: pytest.MonkeyPatch) -> None:
    _env(monkeypatch)
    portal = "/resource" + POLICY.replace(
        "applicationGatewayWebApplicationFirewallPolicies",
        "ApplicationGatewayWebApplicationFirewallPolicies",
    )
    seen: dict = {}

    def factory(settings, _token):
        seen["policy"] = settings.waf_policy_id
        return FakeAzure()

    monkeypatch.setenv("WAF_POLICY_RESOURCE_ID", portal)
    code, payload, _text = _run(["list"], factory)
    assert code == 0
    assert payload["incidents"][0]["number"] == "19"
    assert seen["policy"] == "/subscriptions/" + portal.split("/subscriptions/", 1)[1]
    assert seen["policy"].startswith("/subscriptions/")


def test_empty_stdin_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    _env(monkeypatch)
    stdout = StringIO()
    code = main(["list"], stdin=StringIO("\n"), stdout=stdout, azure_factory=lambda _s, _t: FakeAzure())
    assert code == 2
    assert json.loads(stdout.getvalue())["error"] == "a bearer token is required on stdin"


def test_azure_errors_stay_on_the_public_message(monkeypatch: pytest.MonkeyPatch) -> None:
    _env(monkeypatch)

    class Broken:
        def list_open(self):
            raise AzureCallError(f"Azure returned HTTP 403. denied {TOKEN}")

    code, payload, text = _run(["list"], lambda _settings, _token: Broken())
    assert code == 3
    assert payload["error"] == "Azure returned HTTP 403. denied [redacted]"
    assert TOKEN not in text
    assert "Traceback" not in text


def test_unexpected_errors_hide_the_exception(monkeypatch: pytest.MonkeyPatch) -> None:
    _env(monkeypatch)

    class Broken:
        def list_open(self):
            raise RuntimeError(TOKEN)

    code, payload, text = _run(["list"], lambda _settings, _token: Broken())
    assert code == 3
    assert payload == {"error": "the Azure call failed"}
    assert TOKEN not in text
