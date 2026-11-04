import pytest

from sentinel_waf_block.engine import Engine, NotifyError, WafPutError
from sentinel_waf_block.models import STATUS_APPROVED, STATUS_CAPACITY, Result
from sentinel_waf_block.notifiers import (
    EVENT_BLOCKED,
    EVENT_CAPACITY,
    EVENT_PUT_FAILED,
    EVENT_WOULD_BLOCK,
    FLOW_AUDIENCE,
    TeamsWorkflowNotifier,
)
from tests.engine.conftest import (
    FakeNotifier,
    FakeWaf,
    agw_block_rule,
    agw_policy,
    config,
    incident,
    probe_rule,
)

URL = "https://example.invalid/webhook"


class _Response:
    def __init__(self, status: int) -> None:
        self.status_code = status


class _Session:
    def __init__(self, response: _Response | None = None, error: Exception | None = None) -> None:
        self.response = response or _Response(200)
        self.error = error
        self.posts: list[dict[str, object]] = []

    def post(self, url: str, json: object = None, headers: dict | None = None, timeout: float | None = None) -> _Response:
        self.posts.append({"url": url, "json": json, "headers": headers or {}, "timeout": timeout})
        if self.error:
            raise self.error
        return self.response


class _Credential:
    def __init__(self, token: str | None = "test-mi-token", error: Exception | None = None) -> None:
        self.token = token
        self.error = error
        self.scopes: list[str] = []

    def get_token(self, scope: str):
        self.scopes.append(scope)
        if self.error:
            raise self.error

        class _Token:
            pass

        item = _Token()
        item.token = self.token
        return item


def test_would_block_card_says_awaiting_approval() -> None:
    session = _Session()
    notifier = TeamsWorkflowNotifier(URL, session=session)
    notifier.notify(EVENT_WOULD_BLOCK, Result(status="awaiting-approval", new_addresses=("203.0.113.9",)))
    card = session.posts[0]["json"]["attachments"][0]["content"]
    facts = {item["title"]: item["value"] for item in card["body"][1]["facts"]}
    assert facts["Status"] == "awaiting-approval"
    assert "waiting for approval" in card["body"][0]["text"]


def test_blocked_card_carries_the_new_addresses() -> None:
    session = _Session()
    notifier = TeamsWorkflowNotifier(URL, session=session)
    result = Result(status=STATUS_APPROVED, changed=True, new_addresses=("203.0.113.5",))
    notifier.notify(EVENT_BLOCKED, result)
    payload = session.posts[0]["json"]
    card = payload["attachments"][0]["content"]
    assert "blocked an IP" in card["body"][0]["text"]
    facts = {item["title"]: item["value"] for item in card["body"][1]["facts"]}
    assert facts["Status"] == STATUS_APPROVED
    assert facts["New addresses"] == "203.0.113.5"


def test_rejected_addresses_and_reason_are_escaped() -> None:
    session = _Session()
    notifier = TeamsWorkflowNotifier(URL, session=session)
    result = Result(
        status=STATUS_CAPACITY,
        reason="merged list 2 <b> exceeds maximumBlockEntries",
    )
    notifier.notify(EVENT_CAPACITY, result)
    encoded = str(session.posts[0]["json"])
    assert "<b>" not in encoded
    assert "&lt;b&gt;" in encoded


def test_url_and_exception_text_are_never_in_the_error() -> None:
    class _Boom(Exception):
        def __str__(self) -> str:
            return "post to https://outlook.office365.com/webhook/secreturl failed"

    session = _Session(error=_Boom())
    notifier = TeamsWorkflowNotifier(URL.replace("example.invalid", "outlook.office365.com/webhook/secreturl"), session=session)
    with pytest.raises(NotifyError) as got:
        notifier.notify(EVENT_BLOCKED, Result(status=STATUS_APPROVED))
    assert "secreturl" not in str(got.value)
    assert "notify failed" in str(got.value)


def test_timeout_names_the_failure_without_the_url() -> None:
    class ConnectTimeout(Exception):
        pass

    session = _Session(error=ConnectTimeout("slow"))
    notifier = TeamsWorkflowNotifier(URL, session=session)
    with pytest.raises(NotifyError) as got:
        notifier.notify(EVENT_BLOCKED, Result(status=STATUS_APPROVED))
    assert "timed out" in str(got.value)
    assert URL not in str(got.value)


def test_http_failure_carries_the_status_only() -> None:
    session = _Session(response=_Response(400))
    notifier = TeamsWorkflowNotifier(URL, session=session)
    with pytest.raises(NotifyError) as got:
        notifier.notify(EVENT_BLOCKED, Result(status=STATUS_APPROVED))
    assert str(got.value) == "notify failed with HTTP 400"


def test_insecure_url_is_rejected() -> None:
    with pytest.raises(NotifyError, match="https"):
        TeamsWorkflowNotifier("http://example.invalid/webhook")


def test_unlisted_events_are_not_sent() -> None:
    session = _Session()
    notifier = TeamsWorkflowNotifier(URL, events=(EVENT_BLOCKED,), session=session)
    notifier.notify(EVENT_CAPACITY, Result(status=STATUS_CAPACITY))
    assert session.posts == []


def test_entra_scope_adds_the_bearer_header() -> None:
    session = _Session()
    credential = _Credential()
    notifier = TeamsWorkflowNotifier(URL, session=session, auth_scope=FLOW_AUDIENCE, credential=credential)
    notifier.notify(EVENT_BLOCKED, Result(status=STATUS_APPROVED))
    assert credential.scopes == [FLOW_AUDIENCE]
    assert session.posts[0]["headers"]["Authorization"] == "Bearer test-mi-token"


def test_credential_failure_does_not_leak_the_token() -> None:
    session = _Session()

    class _Boom(Exception):
        def __str__(self) -> str:
            return "Bearer test-mi-token failed"

    notifier = TeamsWorkflowNotifier(URL, session=session, auth_scope=FLOW_AUDIENCE, credential=_Credential(error=_Boom()))
    with pytest.raises(NotifyError) as got:
        notifier.notify(EVENT_BLOCKED, Result(status=STATUS_APPROVED))
    assert "test-mi-token" not in str(got.value)
    assert "authentication failed" in str(got.value)
    assert session.posts == []


def test_no_scope_sends_no_auth_header() -> None:
    session = _Session()
    notifier = TeamsWorkflowNotifier(URL, session=session)
    notifier.notify(EVENT_BLOCKED, Result(status=STATUS_APPROVED))
    assert "Authorization" not in session.posts[0]["headers"]


def test_engine_notifies_blocked_and_survives_notify_failure() -> None:
    notifier = FakeNotifier(error=NotifyError("notify failed"))
    app = Engine(FakeWaf(agw_policy(probe_rule())), None, notifier)
    result = app.execute(incident("203.0.113.5"), config(auto_block_enabled=True))
    assert result.status == "approved"
    assert result.changed is True
    assert result.notify_error == "notify failed"
    assert [event for event, _result in notifier.calls] == ["blocked"]
    assert "The Teams notification was not delivered" in result.comment


def test_engine_dry_run_notifies_would_block() -> None:
    notifier = FakeNotifier()
    app = Engine(FakeWaf(), None, notifier)
    result = app.execute(incident("203.0.113.5"), config())
    assert result.status == "awaiting-approval"
    assert [event for event, _result in notifier.calls] == ["would_block"]
    assert result.notify_error == ""


def test_engine_does_not_notify_when_would_block_is_filtered_out() -> None:
    notifier = FakeNotifier()
    app = Engine(FakeWaf(), None, notifier)
    app._notifier = None
    result = app.execute(incident("203.0.113.5"), config())
    assert result.status == "awaiting-approval"


def test_engine_notifies_put_failure_and_keeps_the_status() -> None:
    notifier = FakeNotifier()
    app = Engine(FakeWaf(put_error=WafPutError("PUT timed out")), None, notifier)
    result = app.execute(incident("203.0.113.5"), config(auto_block_enabled=True))
    assert result.status == "waf-put-failed"
    assert result.notify_error == ""
    assert [event for event, _result in notifier.calls] == [EVENT_PUT_FAILED]


def test_engine_notifies_capacity() -> None:
    notifier = FakeNotifier()
    full = [f"198.51.{index // 256}.{index % 256}" for index in range(1, 601)]
    rules = []
    for priority in range(1, 101):
        if priority == 10:
            rules.append(agw_block_rule(full))
        else:
            rules.append({"name": f"Occupied{priority}", "priority": priority, "matchConditions": []})
    document = agw_policy(*rules)
    app = Engine(FakeWaf(document), None, notifier)
    result = app.execute(incident("203.0.113.5"), config(auto_block_enabled=True))
    assert result.status == "capacity-exceeded"
    assert [event for event, _result in notifier.calls] == [EVENT_CAPACITY]
