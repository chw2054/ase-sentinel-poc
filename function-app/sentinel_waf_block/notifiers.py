"""Teams Workflows adaptive-card notifier.

The workflow URL is a secret. Errors and logs receive only a status or a
generic failure name, never the URL, its headers, or the response body.
"""

from __future__ import annotations

import html
from typing import Any

from sentinel_waf_block.engine import NotifyError
from sentinel_waf_block.models import (
    STATUS_BLOCKED,
    STATUS_CAPACITY,
    STATUS_PUT,
    Result,
)

EVENT_BLOCKED = "blocked"
EVENT_PUT_FAILED = "put_failed"
EVENT_CAPACITY = "capacity"
EVENT_WOULD_BLOCK = "would_block"
DEFAULT_EVENTS: tuple[str, ...] = (
    EVENT_WOULD_BLOCK,
    EVENT_BLOCKED,
    EVENT_PUT_FAILED,
    EVENT_CAPACITY,
)

# Public-cloud Workflows trigger audience. Exact match including the trailing
# slash; see https://learn.microsoft.com/en-us/power-automate/oauth-authentication
FLOW_AUDIENCE = "https://service.flow.microsoft.com/"

_TITLES = {
    EVENT_WOULD_BLOCK: "ASE POC proposes to block an IP (waiting for approval)",
    EVENT_BLOCKED: "ASE POC blocked an IP",
    EVENT_PUT_FAILED: "ASE POC failed to update the WAF policy",
    EVENT_CAPACITY: "ASE POC refused to block: the block list is full",
}


def _escape(text: str) -> str:
    return html.escape(text, quote=False)


def _message(event: str, result: Result) -> dict[str, Any]:
    title = _TITLES.get(event, "ASE POC block decision")
    facts: list[dict[str, str]] = [{"title": "Status", "value": result.status}]
    if result.new_addresses:
        facts.append({"title": "New addresses", "value": ", ".join(result.new_addresses)})
    if result.rejected_addresses:
        facts.append(
            {
                "title": "Rejected",
                "value": "; ".join(
                    f"{item.value} ({item.reason})" for item in result.rejected_addresses
                ),
            }
        )
    if result.existing_count is not None:
        facts.append(
            {
                "title": "List size",
                "value": f"{result.resulting_count} (was {result.existing_count})",
            }
        )
    if result.notify_error:
        facts.append({"title": "Comment to Sentinel", "value": result.comment_error or "written"})
        facts.append({"title": "Notification", "value": "not delivered: " + result.notify_error})
    if result.reason and result.status not in {STATUS_BLOCKED, STATUS_PUT}:
        facts.append({"title": "Reason", "value": result.reason})
    card = {
        "type": "AdaptiveCard",
        "version": "1.2",
        "body": [
            {
                "type": "TextBlock",
                "size": "Medium",
                "weight": "Bolder",
                "text": _escape(title),
            },
            {
                "type": "FactSet",
                "facts": [
                    {"title": _escape(item["title"]), "value": _escape(item["value"])}
                    for item in facts
                ],
            },
        ],
    }
    return {
        "type": "message",
        "attachments": [
            {"contentType": "application/vnd.microsoft.card.adaptive", "content": card}
        ],
    }


class TeamsWorkflowNotifier:
    """Post the result as an Adaptive Card to a Teams Workflows endpoint.

    The newer Workflows triggers answer 401 without an Entra token and 403
    when the audience is wrong. Set auth_scope to the flow service audience
    ("https://service.flow.microsoft.com/") and the credential supplies the
    bearer token per call.
    """

    def __init__(
        self,
        url: str,
        events: tuple[str, ...] = DEFAULT_EVENTS,
        session: object | None = None,
        timeout_seconds: float = 30,
        auth_scope: str = "",
        credential: object | None = None,
    ) -> None:
        if not url.startswith("https://"):
            raise NotifyError("notify url must be https")
        self._url = url
        self._events = frozenset(events)
        self._session = session
        self._timeout = timeout_seconds
        self._auth_scope = auth_scope
        self._credential = credential

    def notify(self, event: str, result: Result) -> None:
        if event not in self._events:
            return
        headers = {"Content-Type": "application/json"}
        token = self._token()
        if token:
            headers["Authorization"] = "Bearer " + token
        try:
            response = self._session_or_default().post(
                self._url, json=_message(event, result), headers=headers, timeout=self._timeout
            )
        except Exception as exc:
            if "Timeout" in type(exc).__name__:
                raise NotifyError("notify timed out") from None
            raise NotifyError("notify failed") from None
        status = getattr(response, "status_code", 0)
        if not 200 <= status < 300:
            raise NotifyError(f"notify failed with HTTP {status}")

    def _token(self) -> str:
        if not self._auth_scope:
            return ""
        if self._credential is None:
            from azure.identity import ManagedIdentityCredential

            self._credential = ManagedIdentityCredential()
        try:
            return self._credential.get_token(self._auth_scope).token
        except Exception as exc:
            raise NotifyError("notify authentication failed") from _redacted(exc)

    def _session_or_default(self) -> object:
        if self._session is None:
            import requests

            self._session = requests.Session()
        return self._session


def _redacted(exc: Exception) -> Exception:
    """Drop the original exception text so a token in it cannot reach logs."""

    return NotifyError(type(exc).__name__)
