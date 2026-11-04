"""Orchestrate validation, the WAF read, and a conditional update."""

from __future__ import annotations

import logging
from dataclasses import replace
from typing import Protocol

from sentinel_waf_block.addresses import (
    canonical_block_entry,
    canonical_host,
    entry_protection_reason,
    parse_protected_ranges,
    protection_reason,
)
from sentinel_waf_block.comments import render
from sentinel_waf_block.decision import (
    enforcement_enabled,
    override_enabled,
)
from sentinel_waf_block.models import (
    PROVIDERS,
    STATUS_ALREADY_BLOCKED,
    STATUS_APPROVED,
    STATUS_CAPACITY,
    STATUS_COMMENT,
    STATUS_AWAITING_APPROVAL,
    STATUS_GET,
    STATUS_NOT_LISTED,
    STATUS_NOTHING,
    STATUS_REMOVED,
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
from sentinel_waf_block.waf_arm import (
    BlockList,
    PolicyShapeError,
    PolicyView,
    RuleTarget,
    build_put_body,
    ordered_block_lists,
    read_policy,
    select_block_list,
)

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
        updates: dict[str, object] = {}
        if result.policy_resource_id:
            updates["waf_policy_resource_id"] = result.policy_resource_id
        if result.written_rule:
            updates["block_rule_name"] = result.written_rule
        if result.written_priority:
            updates["block_rule_priority"] = result.written_priority
        if updates:
            shown = replace(config, **updates)
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

    def add_entry(self, raw: str, config: Config) -> Result:
        """Add one host or CIDR to a block list rule. Does not comment an incident."""

        parsed = canonical_block_entry(raw)
        if parsed.canonical is None:
            return _result(STATUS_VALIDATION, reason=parsed.reason or "invalid")
        networks, invalid_ranges = parse_protected_ranges(config.protected_ip_ranges)
        if invalid_ranges:
            return _result(
                STATUS_RANGES,
                reason="protectedIpRanges cannot be evaluated",
                invalid_protected_ranges=invalid_ranges,
            )
        protected = entry_protection_reason(
            parsed.canonical,
            networks,
            override=override_enabled(config.override_protected_ranges),
        )
        if protected is not None:
            return _result(
                STATUS_VALIDATION,
                candidate_addresses=(parsed.canonical,),
                rejected_addresses=(Rejection(parsed.canonical, protected),),
                reason=protected,
            )
        view, failure = self._policy_view(config, [parsed.canonical], ())
        if failure is not None:
            return failure
        assert view is not None
        if any(parsed.canonical in block.values for block in view.block_lists):
            holder = _holder(view, config.block_rule_name, [parsed.canonical])
            return _result(
                STATUS_ALREADY_BLOCKED,
                candidate_addresses=(parsed.canonical,),
                policy_resource_id=config.waf_policy_resource_id,
                written_rule=holder.name if holder is not None else "",
                written_priority=holder.priority if holder is not None else 0,
                reason="address is already listed",
            )
        target = select_block_list(view, [parsed.canonical], config)
        if target is None:
            return _result(
                STATUS_CAPACITY,
                candidate_addresses=(parsed.canonical,),
                new_addresses=(parsed.canonical,),
                policy_resource_id=config.waf_policy_resource_id,
                reason=f"no block list can take {parsed.canonical}",
            )
        base = _result(
            STATUS_AWAITING_APPROVAL,
            candidate_addresses=(parsed.canonical,),
            new_addresses=target.added,
            existing_count=len(target.merged) - len(target.added),
            resulting_count=len(target.merged),
            policy_resource_id=config.waf_policy_resource_id,
            written_rule=target.name,
            written_priority=target.priority,
        )
        if not enforcement_enabled(config.auto_block_enabled):
            return base
        return self._put(config, view, target, base, STATUS_APPROVED)

    def remove_entry(self, raw: str, config: Config) -> Result:
        """Remove one stored host or CIDR. An emptied rule is dropped, not left blank."""

        if raw == "" or any(character in raw for character in "\r\n") or len(raw) > 100:
            return _result(STATUS_VALIDATION, reason="address must be one IP or CIDR")
        view, failure = self._policy_view(config, [raw], ())
        if failure is not None:
            return failure
        assert view is not None
        found = _stored_value(view, config.block_rule_name, raw)
        if found is None:
            parsed = canonical_block_entry(raw)
            if parsed.canonical is not None and parsed.canonical != raw:
                found = _stored_value(view, config.block_rule_name, parsed.canonical)
            if found is None:
                if parsed.canonical is None:
                    return _result(STATUS_VALIDATION, reason=parsed.reason or "invalid")
                return _result(
                    STATUS_NOT_LISTED,
                    candidate_addresses=(parsed.canonical,),
                    policy_resource_id=config.waf_policy_resource_id,
                    reason="address is not on a block list",
                )
        block, stored = found
        remaining = tuple(value for value in block.values if value != stored)
        target = RuleTarget(block.name, block.priority, remaining, (stored,), False)
        base = _result(
            STATUS_AWAITING_APPROVAL,
            candidate_addresses=(stored,),
            new_addresses=(stored,),
            existing_count=len(block.values),
            resulting_count=len(remaining),
            policy_resource_id=config.waf_policy_resource_id,
            written_rule=block.name,
            written_priority=block.priority,
        )
        if not enforcement_enabled(config.auto_block_enabled):
            return base
        return self._put(config, view, target, base, STATUS_REMOVED)

    def _put(self, config: Config, view, target, base: Result, done: str) -> Result:
        body = build_put_body(view, target, config)
        try:
            self._waf.put_policy(
                config.waf_policy_resource_id,
                config.arm_api_version,
                body,
                timeout_seconds=120,
            )
        except AuthenticationError:
            return replace(base, status=STATUS_PUT, changed=False, reason="authentication failed")
        except WafPutError as exc:
            return replace(base, status=STATUS_PUT, changed=False, reason=_safe_text(exc))
        return replace(base, status=done, changed=True, reason="")

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
        view, failure = self._policy_view(config, enforceable, rejections)
        if failure is not None:
            return failure
        assert view is not None
        # One address is written to one custom rule on this policy. Any of
        # those rules blocks traffic, because the gateway uses this policy.
        listed = {value for block in view.block_lists for value in block.values}
        new = [address for address in enforceable if address not in listed]
        policy_id = config.waf_policy_resource_id
        if not new:
            holder = _holder(view, config.block_rule_name, enforceable)
            return _result(
                STATUS_ALREADY_BLOCKED,
                candidate_addresses=tuple(enforceable),
                rejected_addresses=rejections,
                existing_count=len(holder.values) if holder is not None else 0,
                resulting_count=len(holder.values) if holder is not None else 0,
                policy_resource_id=policy_id,
                written_rule=holder.name if holder is not None else config.block_rule_name,
                written_priority=holder.priority if holder is not None else config.block_rule_priority,
                reason="address is already listed",
            )
        target = select_block_list(view, new, config)
        if target is None:
            first = ordered_block_lists(view, config.block_rule_name)
            existing = len(first[0].values) if first else 0
            return _result(
                STATUS_CAPACITY,
                candidate_addresses=tuple(enforceable),
                new_addresses=tuple(new),
                rejected_addresses=rejections,
                existing_count=existing,
                resulting_count=existing + len(new),
                policy_resource_id=policy_id,
                reason=(
                    f"no block list can take another address and no new custom rule "
                    f"can be added; proposed {', '.join(new)}"
                ),
            )
        base = _result(
            STATUS_AWAITING_APPROVAL,
            candidate_addresses=tuple(enforceable),
            new_addresses=target.added,
            rejected_addresses=rejections,
            existing_count=len(target.merged) - len(target.added),
            resulting_count=len(target.merged),
            policy_resource_id=policy_id,
            written_rule=target.name,
            written_priority=target.priority,
        )
        if not enforcement_enabled(config.auto_block_enabled):
            return base
        body = build_put_body(view, target, config)
        try:
            self._waf.put_policy(policy_id, config.arm_api_version, body, timeout_seconds=120)
        except AuthenticationError:
            return replace(base, status=STATUS_PUT, changed=False, reason="authentication failed")
        except WafPutError as exc:
            return replace(base, status=STATUS_PUT, changed=False, reason=_safe_text(exc))
        return replace(base, status=STATUS_APPROVED, changed=True, reason="")

    def _policy_view(self, config: Config, enforceable: list[str], rejections: tuple[Rejection, ...]):
        try:
            document = self._waf.get_policy(config.waf_policy_resource_id, config.arm_api_version)
            return read_policy(document, config.waf_provider, config.block_rule_name), None
        except AuthenticationError:
            failure = _result(
                STATUS_GET,
                candidate_addresses=tuple(enforceable),
                rejected_addresses=rejections,
                reason="authentication failed",
            )
        except WafGetError as exc:
            failure = _result(
                STATUS_GET,
                candidate_addresses=tuple(enforceable),
                rejected_addresses=rejections,
                reason=_safe_text(exc),
            )
        except PolicyShapeError as exc:
            failure = _result(
                STATUS_SHAPE,
                candidate_addresses=tuple(enforceable),
                rejected_addresses=rejections,
                reason=_safe_text(exc),
            )
        return None, failure

    def _deliver_comment(self, incident: Incident, result: Result) -> Result:
        if self._comments is None:
            return result
        try:
            self._comments.write_comment(incident.arm_id, result.comment)
        except (CommentError, AuthenticationError) as exc:
            message = _safe_text(exc)
            if result.status == STATUS_APPROVED:
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
    # blocked-comment-failed is still a completed PUT. The Teams event name
    # stays "blocked" so NOTIFY_EVENTS keeps matching. The API status is approved.
    STATUS_APPROVED: "blocked",
    STATUS_COMMENT: "blocked",
    STATUS_PUT: "put_failed",
    STATUS_CAPACITY: "capacity",
    # The evaluation phase notifies before anyone approves. The event name
    # stays "would_block". The API status is awaiting-approval.
    STATUS_AWAITING_APPROVAL: "would_block",
}


def _stored_value(view: PolicyView, base_name: str, address: str) -> tuple[BlockList, str] | None:
    for block in ordered_block_lists(view, base_name):
        if address in block.values:
            return block, address
    return None


def _holder(view: PolicyView, base_name: str, addresses: list[str]) -> BlockList | None:
    for block in ordered_block_lists(view, base_name):
        if any(address in block.values for address in addresses):
            return block
    return None


def _result(status: str, **kwargs: object) -> Result:
    return Result(status=status, **kwargs)  # type: ignore[arg-type]


def _safe_text(exc: Exception) -> str:
    text = str(exc).replace("\n", " ")
    if "bearer" in text.casefold() or "authorization" in text.casefold():
        return exc.__class__.__name__
    return text[:300]
