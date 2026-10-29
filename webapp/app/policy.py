"""Pack application-managed networks onto Application Gateway custom rules.

External match values that already sit on the managed rule are preserved as
exact strings. Other custom rules are not rebuilt.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass

from app.cidr import (
    MAX_CUSTOM_RULES,
    PLATFORM_MATCH_VALUES,
    PRIORITY_MAX,
    PRIORITY_MIN,
    CidrError,
    collapse_exact,
    render,
)


@dataclass(frozen=True)
class RuleWrite:
    name: str
    priority: int
    values: tuple[str, ...]


@dataclass(frozen=True)
class PackResult:
    rules: tuple[RuleWrite, ...]
    retired_names: tuple[str, ...]


def pack_rules(
    managed: list[ipaddress.IPv4Network],
    external_values: list[str],
    *,
    product_cap: int,
    base_name: str,
    base_priority: int,
    occupied_priorities: set[int],
    occupied_names: set[str],
    existing_managed_names: list[str],
    per_rule: int = PLATFORM_MATCH_VALUES,
    max_rules: int = MAX_CUSTOM_RULES,
) -> PackResult:
    collapsed = collapse_exact(managed)
    external = _unique_external(external_values)
    _reject_overlap(collapsed, external)
    managed_values = [render(network) for network in collapsed]
    total = len(managed_values) + len(external)
    if total > product_cap:
        raise CidrError(
            "capacity_exceeded",
            f"{total} entries would exceed maximumBlockEntries {product_cap}",
        )
    slots = _rule_slots(
        base_name,
        base_priority,
        occupied_priorities,
        occupied_names,
        existing_managed_names,
        max_rules,
    )
    chunks = _chunks(managed_values, external, per_rule)
    if len(chunks) > len(slots):
        raise CidrError(
            "capacity_exceeded",
            "collapsed entries do not fit in the remaining custom rules",
        )
    written = [
        RuleWrite(name=slot[0], priority=slot[1], values=tuple(chunk))
        for slot, chunk in zip(slots, chunks)
    ]
    used = {rule.name for rule in written}
    retired = tuple(name for name in existing_managed_names if name not in used and name != base_name)
    return PackResult(tuple(written), retired)


def agw_rule(name: str, priority: int, values: list[str]) -> dict[str, object]:
    """Application Gateway API 2024-05-01 requires the misspelled property."""

    return {
        "name": name,
        "priority": priority,
        "ruleType": "MatchRule",
        "action": "Block",
        "state": "Enabled",
        "matchConditions": [
            {
                "matchVariables": [{"variableName": "RemoteAddr"}],
                "operator": "IPMatch",
                "negationConditon": False,
                "matchValues": list(values),
                "transforms": [],
            }
        ],
    }


def build_agw_put_body(
    document: dict[str, object],
    written: list[RuleWrite],
    retired: list[str],
) -> dict[str, object]:
    properties = document.get("properties")
    if not isinstance(properties, dict) or not isinstance(properties.get("customRules"), list):
        raise CidrError("policy_shape", "Application Gateway customRules must be an array")
    by_name = {rule.name: rule for rule in written}
    kept: list[dict[str, object]] = []
    seen: set[str] = set()
    for rule in properties["customRules"]:
        if not isinstance(rule, dict) or not isinstance(rule.get("name"), str):
            raise CidrError("policy_shape", "a custom rule is not an object")
        name = rule["name"]
        if name in retired:
            continue
        if name in by_name:
            kept.append(agw_rule(name, by_name[name].priority, list(by_name[name].values)))
            seen.add(name)
        else:
            kept.append(rule)
    for rule in written:
        if rule.name not in seen:
            kept.append(agw_rule(rule.name, rule.priority, list(rule.values)))
    body = {
        "location": document.get("location"),
        "tags": document.get("tags") or {},
        "properties": {
            "policySettings": properties.get("policySettings"),
            "managedRules": properties.get("managedRules"),
            "customRules": kept,
        },
    }
    return body


def _unique_external(values: list[str]) -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        ordered.append(value)
    return ordered


def _reject_overlap(managed: list[ipaddress.IPv4Network], external: list[str]) -> None:
    parsed: list[tuple[str, ipaddress.IPv4Network]] = []
    for value in external:
        text = value if "/" in value else f"{value}/32"
        try:
            parsed.append((value, ipaddress.ip_network(text, strict=False)))
        except ValueError as exc:
            raise CidrError("external_unparsed", f"external match value {value!r} is not IPv4") from exc
    for network in managed:
        for value, other in parsed:
            if network.overlaps(other):
                raise CidrError(
                    "overlaps_external",
                    f"{render(network)} overlaps external entry {value}",
                )


def _chunks(managed: list[str], external: list[str], per_rule: int) -> list[list[str]]:
    if not managed and not external:
        return [external]
    first_room = per_rule - len(external)
    if first_room < 0 or (managed and first_room == 0):
        raise CidrError(
            "capacity_exceeded",
            "the primary rule has no room left beside the external entries",
        )
    chunks = [external + managed[:first_room]]
    rest = managed[first_room:]
    while rest:
        chunks.append(rest[:per_rule])
        rest = rest[per_rule:]
    return chunks


def _rule_slots(
    base_name: str,
    base_priority: int,
    occupied_priorities: set[int],
    occupied_names: set[str],
    existing_managed_names: list[str],
    max_rules: int,
) -> list[tuple[str, int]]:
    if not PRIORITY_MIN <= base_priority <= PRIORITY_MAX:
        raise CidrError("priority_invalid", "block rule priority must be from 1 to 100")
    slots = [(base_name, base_priority)]
    used_priority = set(occupied_priorities)
    used_priority.add(base_priority)
    used_names = set(occupied_names)
    used_names.add(base_name)
    managed_extra = [name for name in existing_managed_names if name != base_name]
    index = 2
    while len(slots) < max_rules:
        name = managed_extra[index - 2] if index - 2 < len(managed_extra) else f"{base_name}-{index}"
        if name in used_names and name not in managed_extra:
            index += 1
            continue
        priority = base_priority + index - 1
        while priority in used_priority and priority <= PRIORITY_MAX:
            priority += 1
        if priority > PRIORITY_MAX:
            break
        slots.append((name, priority))
        used_priority.add(priority)
        used_names.add(name)
        index += 1
    return slots
