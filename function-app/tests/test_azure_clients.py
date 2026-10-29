import traceback

import pytest

from sentinel_waf_block.azure_clients import ArmWafClient
from sentinel_waf_block.engine import AuthenticationError, WafGetError, WafPutError


class _Token:
    def __init__(self, token: str) -> None:
        self.token = token


class _Credential:
    def __init__(self, error: Exception | None = None) -> None:
        self.error = error

    def get_token(self, scope: str) -> _Token:
        if self.error:
            raise self.error
        return _Token("super-secret-token")


class _Response:
    def __init__(self, status: int, payload: object | None = None) -> None:
        self.status_code = status
        self._payload = payload

    def json(self) -> object:
        return self._payload


class _Session:
    def __init__(self, response: _Response | None = None, error: Exception | None = None) -> None:
        self.response = response or _Response(200, {"ok": True})
        self.error = error
        self.calls: list[dict[str, object]] = []

    def request(self, method: str, url: str, params: dict | None = None, json: object = None, headers: dict | None = None, timeout: float | None = None) -> _Response:
        self.calls.append({"method": method, "url": url, "headers": headers or {}, "json": json, "timeout": timeout})
        if self.error:
            raise self.error
        return self.response


def test_get_and_put_do_not_leak_the_token_on_failure() -> None:
    session = _Session(response=_Response(403, {"error": "no"}))
    client = ArmWafClient(credential=_Credential(), session=session)
    with pytest.raises(WafGetError) as got:
        client.get_policy("/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/applicationGatewayWebApplicationFirewallPolicies/waf", "2024-05-01")
    assert "super-secret-token" not in str(got.value)
    assert session.calls[0]["headers"]["Authorization"] == "Bearer super-secret-token"

    class _ReadTimeout(Exception):
        def __str__(self) -> str:
            return "Authorization: Bearer super-secret-token"

    session = _Session(error=_ReadTimeout())
    client = ArmWafClient(credential=_Credential(), session=session)
    with pytest.raises(WafPutError) as put:
        client.put_policy("/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/applicationGatewayWebApplicationFirewallPolicies/waf", "2024-05-01", {"location": "eastus"})
    rendered = "".join(traceback.format_exception(put.value))
    assert "super-secret-token" not in rendered
    assert "timed out" in str(put.value)


def test_credential_failure_does_not_keep_the_token_in_the_chain() -> None:
    client = ArmWafClient(credential=_Credential(error=RuntimeError("Bearer super-secret-token")), session=_Session())
    with pytest.raises(AuthenticationError) as got:
        client.get_policy("/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/applicationGatewayWebApplicationFirewallPolicies/waf", "2024-05-01")
    rendered = "".join(traceback.format_exception(got.value))
    assert "super-secret-token" not in rendered


def test_get_retries_a_timeout_then_returns_the_policy() -> None:
    class _ConnectTimeout(Exception):
        pass

    class _Flaky:
        def __init__(self) -> None:
            self.calls = 0

        def request(self, method: str, url: str, params=None, json=None, headers=None, timeout=None):
            self.calls += 1
            if self.calls == 1:
                raise _ConnectTimeout()
            return _Response(200, {"name": "waf"})

    session = _Flaky()
    client = ArmWafClient(credential=_Credential(), session=session)
    document = client.get_policy(
        "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/applicationGatewayWebApplicationFirewallPolicies/waf",
        "2024-05-01",
    )
    assert document == {"name": "waf"}
    assert session.calls == 2


def test_get_reports_timeout_after_the_retries_are_exhausted() -> None:
    class _ReadTimeout(Exception):
        pass

    class _Always:
        def __init__(self) -> None:
            self.calls = 0

        def request(self, method: str, url: str, params=None, json=None, headers=None, timeout=None):
            self.calls += 1
            raise _ReadTimeout()

    session = _Always()
    client = ArmWafClient(credential=_Credential(), session=session)
    with pytest.raises(WafGetError, match="GET timed out"):
        client.get_policy(
            "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/applicationGatewayWebApplicationFirewallPolicies/waf",
            "2024-05-01",
        )
    assert session.calls == 3


def test_tagged_policy_ids_keep_only_the_block_list_tag() -> None:
    primary = (
        "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/"
        "applicationGatewayWebApplicationFirewallPolicies/waf"
    )
    second = primary + "-2"
    other = primary + "-other"

    class _Listing:
        def __init__(self) -> None:
            self.calls: list[dict[str, object]] = []

        def request(self, method: str, url: str, params=None, json=None, headers=None, timeout=None):
            self.calls.append({"method": method, "url": url, "params": params})
            return _Response(
                200,
                {
                    "value": [
                        {"id": primary, "tags": {"ase-sentinel-block-list": "true"}},
                        {"id": second, "tags": {"ASE-SENTINEL-BLOCK-LIST": "Yes"}},
                        {"id": other, "tags": {"env": "poc"}},
                        {"id": primary + "-off", "tags": {"ase-sentinel-block-list": "false"}},
                        {"name": "missing-id", "tags": {"ase-sentinel-block-list": "true"}},
                    ]
                },
            )

    session = _Listing()
    client = ArmWafClient(credential=_Credential(), session=session)
    assert client.tagged_policy_ids("not-an-id", "2024-05-01") == []
    assert session.calls == []
    found = client.tagged_policy_ids(primary, "2024-05-01")
    assert found == [primary, second]
    assert session.calls[0]["method"] == "GET"
    assert str(session.calls[0]["url"]).endswith(
        "/resourceGroups/rg/providers/Microsoft.Network/applicationGatewayWebApplicationFirewallPolicies"
    )
    assert session.calls[0]["params"] == {"api-version": "2024-05-01"}
    assert "super-secret-token" not in str(found)

    denied = ArmWafClient(credential=_Credential(), session=_Session(response=_Response(403, {})))
    with pytest.raises(WafGetError, match="HTTP 403"):
        denied.tagged_policy_ids(primary, "2024-05-01")


def test_accepted_put_is_not_success() -> None:
    client = ArmWafClient(credential=_Credential(), session=_Session(response=_Response(202, {})))
    with pytest.raises(WafPutError, match="did not finish"):
        client.put_policy("/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/frontDoorWebApplicationFirewallPolicies/waf", "2024-02-01", {"sku": {}})
