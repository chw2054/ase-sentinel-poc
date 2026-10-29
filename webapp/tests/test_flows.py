from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app


def client() -> TestClient:
    app = create_app(
        Settings(
            database_url="sqlite:///:memory:",
            seed_fixture=True,
            integration_key="test-key",
            dev_login_password="local-dev",
            secret="test-secret",
            product_cap=100,
        )
    )
    return TestClient(app)


def sign_in(api: TestClient, email: str) -> None:
    response = api.post("/login", data={"email": email, "password": "local-dev"}, follow_redirects=False)
    assert response.status_code == 303


def ingest(api: TestClient, sentinel_id: str, address: str, number: str = "20") -> dict:
    response = api.post(
        "/api/v1/integrations/sentinel/incidents",
        headers={"X-Integration-Key": "test-key", "X-Correlation-Id": "corr-" + number},
        json={
            "sentinelIncidentId": sentinel_id,
            "incidentNumber": number,
            "title": f"probe from {address}",
            "severity": "Medium",
            "sentinelStatus": "Active",
            "sentinelUrl": "https://portal.azure.com/#sentinel",
            "ipAddresses": [address],
        },
    )
    assert response.status_code == 200, response.text
    return response.json()


def test_incident_approval_writes_the_fixture_once() -> None:
    api = client()
    first = ingest(api, "incident-a", "203.0.113.20")
    assert first["duplicate"] is False
    assert first["notification"]["link"].endswith(f"/approvals/{first['approvalId']}")
    again = ingest(api, "incident-a", "203.0.113.20")
    assert again["duplicate"] is True
    assert again["notification"] is None
    sign_in(api, "approver@localhost")
    detail = api.get(f"/api/v1/approvals/{first['approvalId']}")
    approved = api.post(
        f"/api/v1/approvals/{first['approvalId']}/decision",
        json={"decision": "approve", "version": detail.json()["version"], "comment": "yes"},
    )
    assert approved.status_code == 200, approved.text
    assert approved.json()["state"] == "executed"
    assert approved.json()["execution"]["changed"] is True
    second = api.post(
        f"/api/v1/approvals/{first['approvalId']}/decision",
        json={"decision": "approve", "version": approved.json()["version"], "comment": "again"},
    )
    assert second.status_code == 409
    listed = api.get("/api/v1/waf/policies/local-wafpol-ase-sentinel-poc/blocks")
    values = {item["cidr"] for item in listed.json()["items"]}
    assert "203.0.113.20" in values
    assert api.app.state.waf.puts == 1


def test_rejection_does_not_change_the_waf() -> None:
    api = client()
    created = ingest(api, "incident-b", "203.0.113.21", "21")
    sign_in(api, "approver@localhost")
    detail = api.get(f"/api/v1/approvals/{created['approvalId']}").json()
    rejected = api.post(
        f"/api/v1/approvals/{created['approvalId']}/decision",
        json={"decision": "reject", "version": detail["version"], "comment": "no"},
    )
    assert rejected.json()["state"] == "rejected"
    assert api.app.state.waf.puts == 0


def test_viewer_and_anonymous_cannot_approve() -> None:
    api = client()
    created = ingest(api, "incident-c", "203.0.113.22", "22")
    missing = api.post(
        f"/api/v1/approvals/{created['approvalId']}/decision",
        json={"decision": "approve", "version": 1},
    )
    assert missing.status_code == 401
    sign_in(api, "viewer@localhost")
    denied = api.post(
        f"/api/v1/approvals/{created['approvalId']}/decision",
        json={"decision": "approve", "version": 1},
    )
    assert denied.status_code == 403
    assert api.app.state.waf.puts == 0


def test_removed_host_is_not_added_again() -> None:
    api = client()
    sign_in(api, "operator@localhost")
    listed = api.get("/api/v1/waf/policies/local-wafpol-ase-sentinel-poc/blocks").json()
    entry = next(item for item in listed["items"] if item["cidr"] == "4.194.122.162")
    removed = api.delete(f"/api/v1/waf/policies/local-wafpol-ase-sentinel-poc/blocks/{entry['id']}")
    assert removed.status_code == 200, removed.text
    created = ingest(api, "incident-d", "4.194.122.162", "24")
    assert created["processingStatus"] == "suppressed"
    assert created["notification"] is None


def test_split_removes_one_host_from_a_cidr() -> None:
    api = client()
    sign_in(api, "operator@localhost")
    added = api.post(
        "/api/v1/waf/policies/local-wafpol-ase-sentinel-poc/blocks",
        json={"cidr": "203.0.113.0/30", "reason": "lab"},
    )
    assert added.status_code == 200, added.text
    listed = api.get("/api/v1/waf/policies/local-wafpol-ase-sentinel-poc/blocks").json()
    entry = next(item for item in listed["items"] if item["cidr"] == "203.0.113.0/30")
    removed = api.delete(
        f"/api/v1/waf/policies/local-wafpol-ase-sentinel-poc/blocks/{entry['id']}?host=203.0.113.1"
    )
    assert removed.status_code == 200, removed.text
    values = set(removed.json()["values"])
    assert "203.0.113.1" not in values
    assert "203.0.113.0" in values
    assert "203.0.113.2/31" in values
    assert "49.216.110.148" in values


def test_pages_render_for_an_operator() -> None:
    api = client()
    sign_in(api, "operator@localhost")
    for path in ["/", "/incidents", "/approvals", "/blocks", "/discovery", "/settings", "/audit"]:
        response = api.get(path)
        assert response.status_code == 200, path
        assert "Dashboard" in response.text
