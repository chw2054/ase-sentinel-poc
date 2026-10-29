"""Orchestrate validation, the WAF read, and a conditional update."""

from __future__ import annotations

import logging
from dataclasses import replace
from typing import Protocol

from sentinel_waf_block.addresses import (
    canonical_host,
    parse_protected_ranges,
    protection_reason,
)
from sentinel_waf_block.comments import render
from sentinel_waf_block.decision import (
    enforcement_enabled,
    exceeds_capacity,
    merge_addresses,
    override_enabled,
)
from sentinel_waf_block.models import (
    BLOCK_POLICY_TAG,
    MATCH_VALUES_PER_POLICY,
    PROVIDERS,
    STATUS_ALREADY_BLOCKED,
    STATUS_BLOCKED,
    STATUS_CAPACITY,
    STATUS_COMMENT,
    STATUS_DRY_RUN,
    STATUS_GET,
    STATUS_NOTHING,
    STATUS_PROVIDER,
    STATUS_PUT,
    STATUS_RANGES,
    STATUS_SHAPE,
    STATUS_VALIDATION,
    Config,
    Incident,
    Rejection,
    Result,
)
from sentinel_waf_block.waf_arm import PolicyShapeError, build_put_body, read_policy

log = logging.getLogger("sentinel_waf_block")


class WafClient(Protocol):
    def get_policy(self, resource_id: str, api_version: str) -> object: ...

    def put_policy(
        self,
        resource_id: str,
        api_version: str,
        body: object,
        timeout_seconds: float = 120,
    ) -> None: ...


class CommentClient(Protocol):
    def write_comment(self, incident_arm_id: str, message: str) -> None: ...


class Notifier(Protocol):
    def notify(self, event: str, result: Result) -> None: ...


class NotifyError(Exception):
    """Notification delivery failed. The message must not carry the URL."""


class AuthenticationError(Exception):
    """Credential acquisition failed. The message must not carry a token."""


class WafGetError(Exception):
    pass


class WafPutError(Exception):
    pass


class CommentError(Exception):
    pass


class Engine:
    def __init__(
        self,
        waf: WafClient,
        comments: CommentClient | None = None,
        notifier: Notifier | None = None,
    ) -> None:
        self._waf = waf
        self._comments = comments
        self._notifier = notifier

    def execute(self, incident: Incident, config: Config) -> Result:
        result = self._decide(incident, config)
        shown = config
        if result.policy_resource_id:
            shown = replace(config, waf_policy_resource_id=result.policy_resource_id)
        result = replace(result, comment=render(result, incident, shown))
        result = self._deliver_comment(incident, result)
        result = self._deliver_notify(incident, config, result)
        log.info(
            "status=%s changed=%s incident=%s existing=%s resulting=%s new=%s rejected=%s",
            result.status,
            result.changed,
            incident.number,
            result.existing_count,
            result.resulting_count,
            len(result.new_addresses),
            len(result.rejected_addresses),
        )
        return result

    def _decide(self, incident: Incident, config: Config) -> Result:
        if type(config.maximum_block_entries) is not int or config.maximum_block_entries < 1:
            return _result(STATUS_VALIDATION, reason="maximumBlockEntries must be a positive integer")
        if type(config.block_rule_priority) is not int:
            return _result(STATUS_VALIDATION, reason="blockRulePriority must be an integer")
        if not isinstance(config.block_rule_name, str) or config.block_rule_name == "":
            return _result(STATUS_VALIDATION, reason="blockRuleName must be a non-empty string")
        if config.waf_provider not in PROVIDERS:
            return _result(
                STATUS_PROVIDER,
                reason="wafProvider must be ApplicationGateway or FrontDoor",
            )
        _networks, invalid_ranges = parse_protected_ranges(config.protected_ip_ranges)
        if invalid_ranges:
            return _result(
                STATUS_RANGES,
                reason="protectedIpRanges cannot be evaluated",
                invalid_protected_ranges=invalid_ranges,
            )
        rejected: list[Rejection] = []
        enforceable: list[str] = []
        seen: set[str] = set()
        override = override_enabled(config.override_protected_ranges)
        for raw in incident.ip_entities:
            classified = canonical_host(raw)
            if classified.reason is not None or classified.canonical is None:
                rejected.append(Rejection(raw, classified.reason or "invalid"))
                continue
            reason = protection_reason(
                classified.canonical,
                _networks,
                override=override,
            )
            if reason is not None:
                rejected.append(Rejection(classified.canonical, reason))
                continue
            if classified.canonical in seen:
                continue
            seen.add(classified.canonical)
            enforceable.append(classified.canonical)
        rejections = tuple(rejected)
        if not enforceable:
            return _result(
                STATUS_NOTHING,
                rejected_addresses=rejections,
                reason="no enforceable address",
            )
        if not config.waf_policy_resource_id.startswith("/"):
            return _result(
                STATUS_GET,
                candidate_addresses=tuple(enforceable),
                rejected_addresses=rejections,
                reason="wafPolicyResourceId is missing",
            )
        views, failure = self._policy_views(config, enforceable, rejections)
        if failure is not None:
            return failure
        plans = []
        full: list[str] = []
        for policy_id, view in views:
            # Copy the address onto every policy that can still take it. A
            # policy at 600 is left unchanged. One gateway enforces only the
            # policy attached to it, so the duplicate is what makes the block
            # apply on each of those gateways.
            missing = [address for address in enforceable if address not in view.existing_values]
            if not missing:
                continue
            merged, added = merge_addresses(list(view.existing_values), missing)
            if exceeds_capacity(merged, MATCH_VALUES_PER_POLICY):
                full.append(policy_id)
                continue
            plans.append((policy_id, view, merged, added))
        if not plans:
            policy_id, view = views[0]
            if full:
                return _result(
                    STATUS_CAPACITY,
                    candidate_addresses=tuple(enforceable),
                    new_addresses=tuple(address for address in enforceable if address not in view.existing_values),
                    rejected_addresses=rejections,
                    existing_count=len(view.existing_values),
                    resulting_count=len(view.existing_values) + len(enforceable),
                    policy_resource_id=policy_id,
                    reason=(
                        f"every block policy that is missing an address already holds "
                        f"{MATCH_VALUES_PER_POLICY} addresses; "
                        f"tag another policy {BLOCK_POLICY_TAG}=true; "
                        f"proposed {', '.join(address for address in enforceable if address not in view.existing_values)}"
                    ),
                )
            return _result(
                STATUS_ALREADY_BLOCKED,
                candidate_addresses=tuple(enforceable),
                rejected_addresses=rejections,
                existing_count=len(view.existing_values),
                resulting_count=len(view.existing_values),
                policy_resource_id=policy_id,
                reason="address is already listed",
            )
        added_all: list[str] = []
        seen_added: set[str] = set()
        for _policy_id, _view, _merged, added in plans:
            for address in added:
                if address not in seen_added:
                    seen_added.add(address)
                    added_all.append(address)
        written_ids = [policy_id for policy_id, _view, _merged, _added in plans]
        _policy_id, view, merged, _added = plans[0]
        base = _result(
            STATUS_DRY_RUN,
            candidate_addresses=tuple(enforceable),
            new_addresses=tuple(added_all),
            rejected_addresses=rejections,
            existing_count=len(view.existing_values),
            resulting_count=len(merged),
            policy_resource_id=", ".join(written_ids),
        )
        if not enforcement_enabled(config.auto_block_enabled):
            return base
        written: list[str] = []
        for policy_id, view, merged, _added in plans:
            body = build_put_body(view, merged, config)
            try:
                self._waf.put_policy(policy_id, config.arm_api_version, body, timeout_seconds=120)
            except AuthenticationError:
                return replace(
                    base,
                    status=STATUS_PUT,
                    changed=bool(written),
                    policy_resource_id=", ".join(written),
                    reason="authentication failed",
                )
            except WafPutError as exc:
                return replace(
                    base,
                    status=STATUS_PUT,
                    changed=bool(written),
                    policy_resource_id=", ".join(written),
                    reason=_safe_text(exc),
                )
            written.append(policy_id)
        return replace(base, status=STATUS_BLOCKED, changed=True, policy_resource_id=", ".join(written), reason="")

    def _policy_views(self, config: Config, enforceable: list[str], rejections: tuple[Rejection, ...]):
        views = []
        for index, policy_id in enumerate(self._policy_ids(config)):
            try:
                document = self._waf.get_policy(policy_id, config.arm_api_version)
                view = read_policy(document, config.waf_provider, config.block_rule_name)
            except AuthenticationError:
                if index == 0:
                    return [], _result(
                        STATUS_GET,
                        candidate_addresses=tuple(enforceable),
                        rejected_addresses=rejections,
                        reason="authentication failed",
                    )
                continue
            except WafGetError as exc:
                if index == 0:
                    return [], _result(
                        STATUS_GET,
                        candidate_addresses=tuple(enforceable),
                        rejected_addresses=rejections,
                        reason=_safe_text(exc),
                    )
                continue
            except PolicyShapeError as exc:
                if index == 0:
                    return [], _result(
                        STATUS_SHAPE,
                        candidate_addresses=tuple(enforceable),
                        rejected_addresses=rejections,
                        reason=_safe_text(exc),
                    )
                continue
            views.append((policy_id, view))
        return views, None

    def _policy_ids(self, config: Config) -> list[str]:
        found = [config.waf_policy_resource_id]
        finder = getattr(self._waf, "tagged_policy_ids", None)
        if finder is None:
            return found
        try:
            extra = finder(config.waf_policy_resource_id, config.arm_api_version)
        except (AuthenticationError, WafGetError):
            return found
        seen = {config.waf_policy_resource_id.casefold()}
        for item in extra or []:
            if isinstance(item, str) and item.startswith("/") and item.casefold() not in seen:
                seen.add(item.casefold())
                found.append(item)
        return found

    def _deliver_comment(self, incident: Incident, result: Result) -> Result:
        if self._comments is None:
            return result
        try:
            self._comments.write_comment(incident.arm_id, result.comment)
        except (CommentError, AuthenticationError) as exc:
            message = _safe_text(exc)
            if result.status == STATUS_BLOCKED:
                return replace(result, status=STATUS_COMMENT, comment_error=message)
            return replace(result, comment_error=message)
        return result


    def _deliver_notify(self, incident: Incident, config: Config, result: Result) -> Result:
        if self._notifier is None:
            return result
        event = _NOTIFY_EVENTS.get(result.status)
        if event is None:
            return result
        try:
            self._notifier.notify(event, result)
        except NotifyError as exc:
            failed = replace(result, notify_error=_safe_text(exc))
            # Re-render so the Sentinel comment records the undelivered notification.
            return replace(failed, comment=render(failed, incident, config))
        return result


_NOTIFY_EVENTS = {
    # blocked-comment-failed is still a completed PUT; the Teams card should
    # say the block happened and mention the comment failure separately.
    STATUS_BLOCKED: "blocked",
    STATUS_COMMENT: "blocked",
    STATUS_PUT: "put_failed",
    STATUS_CAPACITY: "capacity",
    # The evaluation phase of the approval flow also notifies: the channel
    # sees the proposal, the approver still gates the actual block.
    STATUS_DRY_RUN: "would_block",
}


def _result(status: str, **kwargs: object) -> Result:
    return Result(status=status, **kwargs)  # type: ignore[arg-type]


def _safe_text(exc: Exception) -> str:
    text = str(exc).replace("\n", " ")
    if "bearer" in text.casefold() or "authorization" in text.casefold():
        return exc.__class__.__name__
    return text[:300]
