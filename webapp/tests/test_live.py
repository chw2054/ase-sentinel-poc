"""Live mode reads Sentinel and the WAF policy. The web app engine is the only block write."""

import json

import httpx
from fastapi.testclient import TestClient

from app.config import Settings
from app.live import SentinelAzure, _on_block_list
from app.main import create_app

INCIDENT_ID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
ARM_ID = (
    "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.OperationalInsights/"
    "workspaces/ws/providers/Microsoft.SecurityInsights/incidents/" + INCIDENT_ID
)
POLICY_ID = (
    "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/"
    "applicationGatewayWebApplicationFirewallPolicies/wafpol-ase-sentinel-poc"
)
SECOND_POLICY_ID = POLICY_ID + "-2"
OTHER_POLICY_ID = (
    "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/"
    "applicationGatewayWebApplicationFirewallPolicies/wafpol-other"
)
WORKSPACE = "log-ase-sentinel-poc-7ttpll74bmhiq"
SENTINEL_ID = (
    "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.OperationalInsights/"
    "workspaces/" + WORKSPACE
)


def settings() -> Settings:
    return Settings(
        secret="test-secret",
        dev_login_password="local-dev",
        subscription_id="sub",
        resource_group="rg",
        workspace_name=WORKSPACE,
        waf_policy_id=POLICY_ID,
        block_api_key="test-key",
        poc_admins="admin@mngenvmcap591832.onmicrosoft.com",
    )


def _incident_body() -> dict:
    return {
        "name": INCIDENT_ID,
        "id": ARM_ID,
        "properties": {
            "incidentNumber": 9,
            "title": "ASE POC simulated WAF probe from 203.0.113.9",
            "severity": "Medium",
            "status": "Active",
            "createdTimeUtc": "2026-10-28T22:00:00Z",
            "description": "probe",
            "owner": {"email": "admin@mngenvmcap591832.onmicrosoft.com"},
            "labels": [{"labelName": "poc-simulated-probe"}],
        },
    }


def transport(calls: list[httpx.Request]) -> httpx.MockTransport:
    def handle(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        url = str(request.url)
        if request.method == "GET" and "/incidents?" in url and INCIDENT_ID not in url:
            return httpx.Response(200, json={"value": [_incident_body()]})
        if request.method == "POST" and url.endswith("/entities?api-version=2024-03-01"):
            return httpx.Response(
                200,
                json={"entities": [{"kind": "Ip", "properties": {"address": "203.0.113.9"}}]},
            )
        path = url.split("?", 1)[0]
        if path.endswith("applicationGatewayWebApplicationFirewallPolicies"):
            return httpx.Response(
                200,
                json={
                    "value": [
                        {
                            "id": POLICY_ID,
                            "name": "wafpol-ase-sentinel-poc",
                            "tags": {"ase-sentinel-block-list": "true"},
                            "properties": {
                                "customRules": [
                                    {
                                        "name": "SentinelAutoBlock",
                                        "matchConditions": [{"matchValues": ["198.51.100.4"]}],
                                    },
                                    {
                                        "name": "PocSimulatedProbe",
                                        "matchConditions": [{"matchValues": ["ase-poc-probe"]}],
                                    },
                                    {
                                        "name": "SentinelAutoBlock-2",
                                        "matchConditions": [{"matchValues": ["198.51.100.8"]}],
                                    },
                                ]
                            },
                        },
                        {
                            "id": OTHER_POLICY_ID,
                            "name": "wafpol-other",
                            "tags": {"env": "poc"},
                            "properties": {
                                "customRules": [
                                    {
                                        "name": "SentinelAutoBlock",
                                        "matchConditions": [{"matchValues": ["203.0.113.50"]}],
                                    }
                                ]
                            },
                        },
                        {
                            "id": SECOND_POLICY_ID,
                            "name": "wafpol-ase-sentinel-poc-2",
                            "tags": {"ASE-SENTINEL-BLOCK-LIST": "Yes"},
                            "properties": {
                                "customRules": [
                                    {
                                        "name": "SentinelAutoBlock",
                                        "matchConditions": [{"matchValues": ["198.51.100.8"]}],
                                    }
                                ]
                            },
                        },
                    ]
                },
            )
        if path.endswith("applicationGateways"):
            return httpx.Response(
                200,
                json={
                    "value": [
                        {
                            "name": "agw-ase-sentinel-poc",
                            "properties": {
                                "firewallPolicy": {"id": POLICY_ID},
                                "frontendIPConfigurations": [
                                    {
                                        "name": "frontendPublic",
                                        "properties": {
                                            "publicIPAddress": {
                                                "id": "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/publicIPAddresses/pip"
                                            }
                                        },
                                    }
                                ],
                            },
                        },
                        {
                            "name": "agw-ase-sentinel-poc-2",
                            "properties": {
                                "firewallPolicy": {"id": SECOND_POLICY_ID},
                                "frontendIPConfigurations": [
                                    {
                                        "name": "frontendPublic",
                                        "properties": {
                                            "publicIPAddress": {
                                                "id": "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/publicIPAddresses/pip-2"
                                            }
                                        },
                                    }
                                ],
                            },
                        },
                    ]
                },
            )
        if path.endswith("/publicIPAddresses/pip"):
            return httpx.Response(200, json={"properties": {"ipAddress": "20.169.234.86"}})
        if path.endswith("/publicIPAddresses/pip-2"):
            return httpx.Response(200, json={"properties": {"ipAddress": "20.240.1.2"}})
        if request.method == "GET" and url.endswith(f"/{INCIDENT_ID}?api-version=2024-03-01"):
            return httpx.Response(200, json=_incident_body())
        if request.method == "PUT" and "/comments/" in url:
            return httpx.Response(200, json={"name": "comment"})
        if request.method == "PUT" and url.endswith(f"/{INCIDENT_ID}?api-version=2024-03-01"):
            return httpx.Response(200, json={"name": INCIDENT_ID})
        return httpx.Response(500, json={"error": {"message": "unexpected " + url}})

    return httpx.MockTransport(handle)


def _block_result(recorded: list[dict]):
    def block(payload: object) -> tuple[int, dict]:
        assert isinstance(payload, dict)
        recorded.append(payload)
        if payload.get("operation") == "remove":
            return 200, {
                "status": "removed",
                "changed": True,
                "written_rule": "SentinelAutoBlock",
                "new_addresses": [payload.get("address")],
                "notify_error": "",
            }
        if payload.get("operation") == "add":
            return 200, {
                "status": "blocked",
                "changed": True,
                "written_rule": "SentinelAutoBlock-2",
                "new_addresses": ["203.0.113.0/24"],
                "notify_error": "",
            }
        return 200, {"status": "blocked", "changed": True, "notify_error": ""}

    return block


def client(calls: list[httpx.Request], recorded: list[dict] | None = None) -> TestClient:
    azure = SentinelAzure(
        settings(),
        http=httpx.Client(transport=transport(calls)),
        token=lambda: "arm-token",
        block=_block_result(recorded if recorded is not None else []),
    )
    return TestClient(create_app(settings(), azure))


def sign_in(api: TestClient, email: str = "admin@localhost") -> None:
    response = api.post("/login", data={"email": email, "password": "local-dev"}, follow_redirects=False)
    assert response.status_code == 303


def test_home_lists_the_sentinel_incident_and_skips_sql() -> None:
    calls: list[httpx.Request] = []
    api = client(calls)
    assert api.get("/health").json() == {"status": "ok", "liveAzure": True, "sql": False}
    sign_in(api)
    page = api.get("/")
    assert page.status_code == 200
    assert f"/incidents/{INCIDENT_ID}" in page.text
    assert ">9</a>" in page.text
    assert "203.0.113.9" in page.text
    assert "Not blocked" in page.text
    assert "1 still need a decision" in page.text
    assert "2 addresses are on the block list" in page.text
    assert f"Sentinel <strong>{WORKSPACE}</strong>" in page.text
    assert SENTINEL_ID in page.text
    assert ">wafpol-ase-sentinel-poc</strong>" in page.text
    assert "wafpol-ase-sentinel-poc-2" not in page.text
    assert "wafpol-other" not in page.text
    assert ">SentinelAutoBlock</strong>" in page.text
    assert ">SentinelAutoBlock-2</strong>" in page.text
    assert "PocSimulatedProbe" not in page.text
    assert "http://20.169.234.86" in page.text
    assert "http://20.240.1.2" not in page.text
    assert ">agw-ase-sentinel-poc</strong>" in page.text
    assert "agw-ase-sentinel-poc-2" not in page.text
    assert "1 / 600" in page.text
    blocks = api.get("/blocks")
    assert blocks.status_code == 200
    assert "198.51.100.4" in blocks.text
    assert "198.51.100.8" in blocks.text
    assert "SentinelAutoBlock-2" in blocks.text
    assert "203.0.113.50" not in blocks.text
    assert "ase-poc-probe" not in blocks.text
    assert "http://20.169.234.86" in blocks.text
    assert 'name="address"' in blocks.text
    assert "Remove" in blocks.text
    assert 'value="198.51.100.4"' in blocks.text
    detail = api.get(f"/incidents/{INCIDENT_ID}")
    assert detail.status_code == 200
    assert WORKSPACE in detail.text
    assert "http://20.169.234.86" in detail.text
    listed = [call for call in calls if call.method == "GET" and "/incidents?" in str(call.url)]
    assert listed and "api-version=2024-03-01" in str(listed[0].url)
    assert not any("webapp-data" in str(call.url) for call in calls)


def test_block_posts_execution_enforce_and_does_not_close() -> None:
    calls: list[httpx.Request] = []
    recorded: list[dict] = []
    api = client(calls, recorded)
    sign_in(api)
    response = api.post(f"/incidents/{INCIDENT_ID}/block", follow_redirects=False)
    assert response.status_code == 303
    assert "SentinelAutoBlock" in response.headers["location"]
    assert len(recorded) == 1
    assert recorded[0]["execution"] == "enforce"
    assert recorded[0]["ipEntities"] == ["203.0.113.9"]
    assert recorded[0]["incidentArmId"] == ARM_ID
    assert not any(call.method == "PUT" and "/comments/" in str(call.url) for call in calls)


def test_cidr_entry_covers_an_incident_host() -> None:
    assert _on_block_list(("203.0.113.9",), {"203.0.113.0/24"})
    assert not _on_block_list(("198.51.100.4",), {"203.0.113.0/24"})


def test_block_page_adds_and_removes_an_ip_or_cidr() -> None:
    calls: list[httpx.Request] = []
    recorded: list[dict] = []
    api = client(calls, recorded)
    sign_in(api)
    added = api.post("/blocks", data={"address": "203.0.113.5/24"}, follow_redirects=False)
    assert added.status_code == 303
    assert "Added%20203.0.113.0/24" in added.headers["location"]
    removed = api.post("/blocks/remove", data={"address": "198.51.100.4"}, follow_redirects=False)
    assert removed.status_code == 303
    assert "Removed%20198.51.100.4" in removed.headers["location"]
    assert recorded[0] == {"operation": "add", "address": "203.0.113.5/24", "execution": "enforce"}
    assert recorded[1] == {"operation": "remove", "address": "198.51.100.4", "execution": "enforce"}
    assert not any(call.method == "PUT" for call in calls)


def test_viewer_cannot_edit_the_block_list() -> None:
    calls: list[httpx.Request] = []
    recorded: list[dict] = []
    api = client(calls, recorded)
    sign_in(api, "viewer@localhost")
    response = api.post("/blocks/remove", data={"address": "198.51.100.4"}, follow_redirects=False)
    assert response.status_code == 303
    assert "does%20not%20allow" in response.headers["location"]
    assert recorded == []


def test_dismiss_closes_without_calling_the_block_service() -> None:
    calls: list[httpx.Request] = []
    recorded: list[dict] = []
    api = client(calls, recorded)
    sign_in(api)
    response = api.post(f"/incidents/{INCIDENT_ID}/dismiss", follow_redirects=False)
    assert response.status_code == 303
    assert "not%20changed" in response.headers["location"]
    close = [call for call in calls if call.method == "PUT" and str(call.url).endswith(f"/{INCIDENT_ID}?api-version=2024-03-01")]
    assert len(close) == 1
    body = json.loads(close[0].content)
    assert body["properties"]["status"] == "Closed"
    assert body["properties"]["classification"] == "BenignPositive"
    assert body["properties"]["labels"][0]["labelName"] == "poc-simulated-probe"
    assert "chose not to block 203.0.113.9" in body["properties"]["classificationComment"]
    assert recorded == []


def test_viewer_cannot_block() -> None:
    calls: list[httpx.Request] = []
    recorded: list[dict] = []
    api = client(calls, recorded)
    sign_in(api, "viewer@localhost")
    response = api.post(f"/incidents/{INCIDENT_ID}/block", follow_redirects=False)
    assert response.status_code == 303
    assert "does%20not%20allow" in response.headers["location"]
    assert recorded == []


def test_playbook_api_requires_the_shared_key() -> None:
    calls: list[httpx.Request] = []
    recorded: list[dict] = []
    api = client(calls, recorded)
    missing = api.post("/api/SentinelWafAutoBlock", json={"execution": "dry-run"})
    assert missing.status_code == 401
    assert missing.json()["reason"] == "unauthorized"
    wrong = api.post(
        "/api/SentinelWafAutoBlock",
        headers={"x-functions-key": "nope"},
        json={"execution": "dry-run"},
    )
    assert wrong.status_code == 401
    assert recorded == []
    accepted = api.post(
        "/api/SentinelWafAutoBlock",
        headers={"x-functions-key": "test-key"},
        json={"incidentArmId": ARM_ID, "execution": "dry-run"},
    )
    assert accepted.status_code == 200
    assert accepted.json()["status"] == "blocked"
    assert recorded == [{"incidentArmId": ARM_ID, "execution": "dry-run"}]
    garbage = api.post(
        "/api/SentinelWafAutoBlock",
        headers={"x-functions-key": "test-key"},
        content=b"not-json",
    )
    assert garbage.status_code == 400
    assert garbage.json()["reason"] == "request body is not JSON"
