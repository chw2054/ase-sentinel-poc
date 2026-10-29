"""Render a Sentinel incident comment from a structured result."""

from __future__ import annotations

import html

from sentinel_waf_block.models import (
    APPLICATION_GATEWAY,
    MATCH_VALUES_PER_POLICY,
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
    Result,
)

_EXPIRY = "There is no automatic expiry. Rollback is an operator action."


def render(result: Result, incident: Incident, config: Config) -> str:
    title = html.escape(incident.title, quote=False)
    number = html.escape(incident.number, quote=False)
    provider = html.escape(config.waf_provider, quote=False)
    policy = html.escape(config.waf_policy_resource_id, quote=False)
    rule = html.escape(config.block_rule_name, quote=False)
    parts = [_headline(result, config, provider, number, title, policy, rule)]
    lines = _action_lines(result)
    if lines:
        parts.append("<p>" + "<br>".join(html.escape(line, quote=False) for line in lines) + "</p>")
    if result.status in {STATUS_DRY_RUN, STATUS_BLOCKED, STATUS_COMMENT}:
        size = result.resulting_count if result.resulting_count is not None else 0
        if result.status == STATUS_DRY_RUN:
            parts.append(
                "<p>Provider: "
                f"{provider}. Policy: {policy}. Custom rule that would be updated: {rule}. "
                "Resulting list size if blocking were enabled: "
                f"{size} of {MATCH_VALUES_PER_POLICY} on this custom rule.</p>"
            )
        else:
            kind = "variable" if config.waf_provider == APPLICATION_GATEWAY else "matchVariable"
            parts.append(
                f"<p>Custom rule {rule}, {kind} RemoteAddr, operator IPMatch, action Block, "
                f"priority {config.block_rule_priority}. List size {size} of "
                f"{MATCH_VALUES_PER_POLICY} on this custom rule. Other custom rules were kept. "
                f"Policy: {policy}.</p>"
            )
            if config.waf_provider == APPLICATION_GATEWAY:
                parts.append("<p>Read-only policy links were not sent back on the PUT.</p>")
            parts.append(f"<p>{_EXPIRY}</p>")
    if result.rejected_addresses:
        rejected = "<br>".join(
            html.escape(f"{item.value} rejected: {item.reason}", quote=False)
            for item in result.rejected_addresses
        )
        parts.append(f"<p>Rejected:<br>{rejected}</p>")
    if result.reason and result.status not in {STATUS_DRY_RUN, STATUS_BLOCKED, STATUS_COMMENT}:
        parts.append(f"<p>{html.escape(result.reason, quote=False)}</p>")
    if result.notify_error:
        parts.append(
            "<p>The Teams notification was not delivered: "
            f"{html.escape(result.notify_error, quote=False)}</p>"
        )
    return "".join(parts)


def _headline(
    result: Result,
    config: Config,
    provider: str,
    number: str,
    title: str,
    policy: str,
    rule: str,
) -> str:
    status = result.status
    if status == STATUS_DRY_RUN:
        return (
            "<p><strong>ASE POC playbook dry-run.</strong> autoBlockEnabled is false. "
            "The WAF policy was not changed. "
            f"Incident {number} ({title}).</p>"
        )
    if status in {STATUS_BLOCKED, STATUS_COMMENT}:
        product = "Front Door" if config.waf_provider != APPLICATION_GATEWAY else "Application Gateway"
        return (
            f"<p><strong>ASE POC playbook updated the {product} WAF policy.</strong> "
            f"Incident {number} ({title}).</p>"
        )
    if status == STATUS_ALREADY_BLOCKED:
        listed = html.escape(", ".join(result.candidate_addresses), quote=False)
        return (
            "<p><strong>ASE POC playbook made no change.</strong> "
            f"{listed} is already on custom rule {rule}. The WAF policy was not written again.</p>"
        )
    if status == STATUS_NOTHING:
        return (
            "<p><strong>ASE POC playbook made no change.</strong> "
            "No block candidate remained. The WAF policy was not read or changed.</p>"
        )
    if status == STATUS_CAPACITY:
        return (
            "<p><strong>ASE POC playbook refused to block.</strong> "
            f"No block list custom rule can take another address, and a new custom rule "
            f"cannot be added. Each rule holds at most {MATCH_VALUES_PER_POLICY} addresses. "
            "The WAF policy was not changed.</p>"
        )
    if status == STATUS_RANGES:
        values = html.escape(", ".join(result.invalid_protected_ranges), quote=False)
        return (
            "<p><strong>ASE POC playbook refused to block.</strong> "
            "The WAF policy was not changed. protectedIpRanges contains a value this "
            f"playbook cannot compare: {values}. No Would-block line was recorded.</p>"
        )
    if status == STATUS_GET:
        return (
            "<p><strong>ASE POC playbook could not read the WAF policy.</strong> "
            "The policy was not changed, and no Would-block line was recorded, "
            "because the current block list is unknown.</p>"
        )
    if status == STATUS_SHAPE:
        return (
            "<p><strong>ASE POC playbook could not read custom rules from the WAF policy.</strong> "
            f"The policy was not changed. wafProvider is {provider}.</p>"
        )
    if status == STATUS_PUT:
        product = "Front Door" if config.waf_provider != APPLICATION_GATEWAY else "Application Gateway"
        proposed = html.escape(", ".join(result.new_addresses), quote=False)
        return (
            f"<p><strong>ASE POC playbook failed while updating the {product} WAF policy.</strong> "
            f"Do not assume {proposed} was blocked. Read the policy before you retry.</p>"
        )
    if status == STATUS_PROVIDER:
        return (
            "<p><strong>ASE POC playbook made no change.</strong> "
            f"wafProvider {provider} is unsupported. The WAF policy was not read or changed.</p>"
        )
    if status == STATUS_VALIDATION:
        return (
            "<p><strong>ASE POC playbook made no change.</strong> "
            "The request failed validation. The WAF policy was not read or changed.</p>"
        )
    return (
        "<p><strong>ASE POC playbook made no change.</strong> "
        "The WAF policy was not changed.</p>"
    )


def _action_lines(result: Result) -> list[str]:
    if result.status == STATUS_DRY_RUN:
        return [f"Would block IP: {address}" for address in result.new_addresses]
    if result.status in {STATUS_BLOCKED, STATUS_COMMENT}:
        return [f"Blocked IP: {address}" for address in result.new_addresses]
    return []


