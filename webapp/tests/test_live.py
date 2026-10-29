"""Live mode reads Sentinel and the WAF policy. The function is the only block write."""

import json

import httpx
from fastapi.testclient import TestClient

from app.config import Settings
from app.live import SentinelAzure
from app.main import create_app

INCIDENT_ID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
ARM_ID = (
    "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.OperationalInsights/"
    "workspaces/ws/providers/Microsoft.SecurityInsights/incidents/" + INCIDENT_ID
)
POLICY_ID = (
    "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/"
    "applicationGatewayWebApplicationFirewallPolicies/wafpol"
)
SECOND_POLICY_ID = POLICY_ID + "-2"
OTHER_POLICY_ID = POLICY_ID + "-other"
WORKSPACE = "log-ase-sentinel-poc-7ttpll74bmhiq"
SENTINEL_ID = (
    "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.OperationalInsights/"
    "workspaces/" + WORKSPACE
)


def settings() -> Settings:
    return Settings(
        database_url="",
        secret="test-secret",
        dev_login_password="local-dev",
        integration_key="",
        seed_fixture=False,
        live_azure=True,
        subscription_id="sub",
        resource_group="rg",
        workspace_name=WORKSPACE,
        waf_policy_id=POLICY_ID,
        function_url="https://fn.example/api/SentinelWafAutoBlock",
        function_key="test-key",
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
                                    }
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
        if request.method == "POST" and url.startswith("https://fn.example/"):
            return httpx.Response(200, json={"status": "blocked", "changed": True, "notify_error": ""})
        return httpx.Response(500, json={"error": {"message": "unexpected " + url}})

    return httpx.MockTransport(handle)


def client(calls: list[httpx.Request]) -> TestClient:
    azure = SentinelAzure(settings(), http=httpx.Client(transport=transport(calls)), token=lambda: "arm-token")
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
    assert ">wafpol-ase-sentinel-poc-2</strong>" in page.text
    assert "wafpol-other" not in page.text
    assert "http://20.169.234.86" in page.text
    assert "http://20.240.1.2" in page.text
    assert ">agw-ase-sentinel-poc</strong>" in page.text
    assert ">agw-ase-sentinel-poc-2</strong>" in page.text
    assert "1 / 600" in page.text
    blocks = api.get("/blocks")
    assert blocks.status_code == 200
    assert "198.51.100.4" in blocks.text
    assert "198.51.100.8" in blocks.text
    assert "203.0.113.50" not in blocks.text
    assert "http://20.169.234.86" in blocks.text
    detail = api.get(f"/incidents/{INCIDENT_ID}")
    assert detail.status_code == 200
    assert WORKSPACE in detail.text
    assert "http://20.169.234.86" in detail.text
    listed = [call for call in calls if call.method == "GET" and "/incidents?" in str(call.url)]
    assert listed and "api-version=2024-03-01" in str(listed[0].url)
    assert not any("webapp-data" in str(call.url) for call in calls)


def test_block_posts_execution_enforce_and_does_not_close() -> None:
    calls: list[httpx.Request] = []
    api = client(calls)
    sign_in(api)
    response = api.post(f"/incidents/{INCIDENT_ID}/block", follow_redirects=False)
    assert response.status_code == 303
    assert "SentinelAutoBlock" in response.headers["location"]
    function_calls = [call for call in calls if str(call.url).startswith("https://fn.example/")]
    assert len(function_calls) == 1
    body = json.loads(function_calls[0].content)
    assert body["execution"] == "enforce"
    assert body["ipEntities"] == ["203.0.113.9"]
    assert body["incidentArmId"] == ARM_ID
    assert function_calls[0].headers["x-functions-key"] == "test-key"
    assert not any(call.method == "PUT" and "/comments/" in str(call.url) for call in calls)


def test_dismiss_closes_without_calling_the_function() -> None:
    calls: list[httpx.Request] = []
    api = client(calls)
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
    assert not any(str(call.url).startswith("https://fn.example/") for call in calls)


def test_viewer_cannot_block() -> None:
    calls: list[httpx.Request] = []
    api = client(calls)
    sign_in(api, "viewer@localhost")
    response = api.post(f"/incidents/{INCIDENT_ID}/block", follow_redirects=False)
    assert response.status_code == 303
    assert "does%20not%20allow" in response.headers["location"]
    assert not any(str(call.url).startswith("https://fn.example/") for call in calls)


def test_sql_mode_stays_on_the_fixture() -> None:
    api = TestClient(create_app(Settings(database_url="sqlite:///:memory:", seed_fixture=False)))
    assert api.get("/health").json()["liveAzure"] is False
