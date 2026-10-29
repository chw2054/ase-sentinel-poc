"""Read a WAF GET document and build the provider PUT body.

Block lists are custom rules named like the configured rule, for example
SentinelAutoBlock and SentinelAutoBlock-2. One address is written to one of
those rules. Every other custom rule object is copied through. Existing match
values are opaque strings.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass
from typing import Any

from sentinel_waf_block.decision import exceeds_capacity, merge_addresses
from sentinel_waf_block.models import (
    APPLICATION_GATEWAY,
    FRONT_DOOR,
    MATCH_VALUES_PER_POLICY,
    Config,
)

MAX_CUSTOM_RULES = 100
PRIORITY_MIN = 1
PRIORITY_MAX = 100


@dataclass(frozen=True)
class BlockList:
    name: str
    priority: int
    values: tuple[str, ...]


@dataclass(frozen=True)
class RuleTarget:
    """The one custom rule a new address is written to."""

    name: str
    priority: int
    merged: tuple[str, ...]
    added: tuple[str, ...]
    created: bool


@dataclass(frozen=True)
class PolicyView:
    location: str
    tags: dict[str, Any]
    sku: dict[str, Any] | None
    policy_settings: dict[str, Any]
    managed_rules: dict[str, Any]
    block_lists: tuple[BlockList, ...]
    other_rules: tuple[dict[str, Any], ...]


class PolicyShapeError(Exception):
    """The GET document does not match the selected provider."""


def read_policy(document: object, provider: str, rule_name: str) -> PolicyView:
    if not isinstance(document, dict):
        raise PolicyShapeError("WAF document is not an object")
    location = document.get("location")
    if not isinstance(location, str) or location == "":
        raise PolicyShapeError("WAF location is missing")
    tags = document.get("tags", {})
    if tags is None:
        tags = {}
    if not isinstance(tags, dict):
        raise PolicyShapeError("WAF tags are not an object")
    properties = document.get("properties")
    if not isinstance(properties, dict):
        raise PolicyShapeError("WAF properties are missing")
    policy_settings = properties.get("policySettings")
    managed_rules = properties.get("managedRules")
    if not isinstance(policy_settings, dict) or not isinstance(managed_rules, dict):
        raise PolicyShapeError("policySettings or managedRules is missing")
    sku = document.get("sku")
    if provider == FRONT_DOOR:
        if not isinstance(sku, dict):
            raise PolicyShapeError("Front Door sku is missing")
    elif sku is not None and not isinstance(sku, dict):
        raise PolicyShapeError("WAF sku is not an object")
    block_lists, others = _rules_and_values(properties, provider, rule_name)
    return PolicyView(
        location=location,
        tags=copy.deepcopy(tags),
        sku=copy.deepcopy(sku) if isinstance(sku, dict) else None,
        policy_settings=copy.deepcopy(policy_settings),
        managed_rules=copy.deepcopy(managed_rules),
        block_lists=tuple(block_lists),
        other_rules=tuple(others),
    )


def ordered_block_lists(view: PolicyView, base_name: str) -> tuple[BlockList, ...]:
    return tuple(sorted(view.block_lists, key=lambda item: _sort_key(item.name, base_name)))


def select_block_list(view: PolicyView, new: list[str], config: Config) -> RuleTarget | None:
    """Pick one block list with room, or a new rule on this same policy.

    A new rule is created only when every existing block list would pass 600.
    Returns None when the new addresses do not fit in one rule, or when this
    policy has no free custom-rule priority left.
    """

    for block in ordered_block_lists(view, config.block_rule_name):
        merged, added = merge_addresses(list(block.values), new)
        if not exceeds_capacity(merged, MATCH_VALUES_PER_POLICY):
            return RuleTarget(block.name, block.priority, tuple(merged), tuple(added), False)
    if len(new) > MATCH_VALUES_PER_POLICY:
        return None
    if len(view.block_lists) + len(view.other_rules) >= MAX_CUSTOM_RULES:
        return None
    taken = {block.name for block in view.block_lists}
    used = {block.priority for block in view.block_lists}
    for rule in view.other_rules:
        name = rule.get("name")
        priority = rule.get("priority")
        if isinstance(name, str):
            taken.add(name)
        if type(priority) is int:
            used.add(priority)
    if config.block_rule_name not in taken:
        priority = _base_priority(config.block_rule_priority, used)
        if priority is None:
            return None
        return RuleTarget(config.block_rule_name, priority, tuple(new), tuple(new), True)
    name = _free_name(config.block_rule_name, taken)
    priority = _free_priority(used, config.block_rule_priority + 1)
    if name is None or priority is None:
        return None
    return RuleTarget(name, priority, tuple(new), tuple(new), True)


def build_put_body(
    view: PolicyView,
    target: RuleTarget,
    config: Config,
) -> dict[str, Any]:
    written = _block_rule(config, target.name, target.priority, list(target.merged))
    custom_rules: list[dict[str, Any]] = []
    replaced = False
    for block in ordered_block_lists(view, config.block_rule_name):
        if block.name == target.name:
            # An empty IPMatch list is invalid. Drop the rule instead.
            if target.merged:
                custom_rules.append(written)
            replaced = True
        else:
            custom_rules.append(
                _block_rule(config, block.name, block.priority, list(block.values))
            )
    if not replaced:
        custom_rules.append(written)
    custom_rules.extend(view.other_rules)
    properties: dict[str, Any] = {
        "policySettings": copy.deepcopy(view.policy_settings),
        "managedRules": copy.deepcopy(view.managed_rules),
    }
    body: dict[str, Any] = {
        "location": view.location,
        "tags": copy.deepcopy(view.tags) if view.tags else {},
    }
    if config.waf_provider == FRONT_DOOR:
        body["sku"] = copy.deepcopy(view.sku)
        properties["customRules"] = {"rules": custom_rules}
    elif config.waf_provider == APPLICATION_GATEWAY:
        properties["customRules"] = custom_rules
    else:
        raise PolicyShapeError("unsupported provider")
    body["properties"] = properties
    return body


def _rules_and_values(
    properties: dict[str, Any],
    provider: str,
    rule_name: str,
) -> tuple[list[BlockList], list[dict[str, Any]]]:
    custom = properties.get("customRules", None)
    if provider == APPLICATION_GATEWAY:
        if not isinstance(custom, list):
            raise PolicyShapeError("Application Gateway customRules must be an array")
        rules = custom
        value_key = "matchValues"
    elif provider == FRONT_DOOR:
        if not isinstance(custom, dict) or not isinstance(custom.get("rules"), list):
            raise PolicyShapeError("Front Door customRules.rules must be an array")
        rules = custom["rules"]
        value_key = "matchValue"
    else:
        raise PolicyShapeError("unsupported provider")
    block_lists: list[BlockList] = []
    others: list[dict[str, Any]] = []
    for rule in rules:
        if not isinstance(rule, dict):
            raise PolicyShapeError("a custom rule is not an object")
        name = rule.get("name")
        if isinstance(name, str) and _is_block_list_name(name, rule_name):
            priority = rule.get("priority")
            if type(priority) is not int:
                raise PolicyShapeError("block list priority must be an integer")
            block_lists.append(BlockList(name, priority, tuple(_match_values(rule, value_key))))
            continue
        others.append(copy.deepcopy(rule))
    return block_lists, others


def _match_values(rule: dict[str, Any], value_key: str) -> list[str]:
    conditions = rule.get("matchConditions", [])
    if conditions is None:
        raise PolicyShapeError("matchConditions is null")
    if not isinstance(conditions, list):
        raise PolicyShapeError("matchConditions is not an array")
    if not conditions:
        return []
    first = conditions[0]
    if not isinstance(first, dict):
        raise PolicyShapeError("match condition is not an object")
    if value_key not in first or first[value_key] is None:
        return []
    values = first[value_key]
    if not isinstance(values, list) or any(not isinstance(item, str) for item in values):
        raise PolicyShapeError(f"{value_key} must be an array of strings")
    return list(values)


def _block_rule(config: Config, name: str, priority: int, merged: list[str]) -> dict[str, Any]:
    if config.waf_provider == APPLICATION_GATEWAY:
        # API 2024-05-01 rejects the corrected spelling negationCondition.
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
                    "matchValues": list(merged),
                    "transforms": [],
                }
            ],
        }
    return {
        "name": name,
        "enabledState": "Enabled",
        "priority": priority,
        "ruleType": "MatchRule",
        "action": "Block",
        "matchConditions": [
            {
                "matchVariable": "RemoteAddr",
                "operator": "IPMatch",
                "negateCondition": False,
                "matchValue": list(merged),
            }
        ],
    }


def _is_block_list_name(name: object, base: str) -> bool:
    return isinstance(name, str) and (name == base or name.startswith(base + "-"))


def _sort_key(name: str, base: str) -> tuple[int, int, str]:
    if name == base:
        return (0, 0, name)
    suffix = name[len(base) + 1 :]
    if suffix.isdigit():
        return (1, int(suffix), name)
    return (2, 0, name)


def _base_priority(configured: int, used: set[int]) -> int | None:
    if PRIORITY_MIN <= configured <= PRIORITY_MAX and configured not in used:
        return configured
    return _free_priority(used, configured + 1)


def _free_priority(used: set[int], start: int) -> int | None:
    if not PRIORITY_MIN <= start <= PRIORITY_MAX:
        start = PRIORITY_MIN
    for priority in range(start, PRIORITY_MAX + 1):
        if priority not in used:
            return priority
    for priority in range(PRIORITY_MIN, start):
        if priority not in used:
            return priority
    return None


def _free_name(base: str, taken: set[str]) -> str | None:
    for index in range(2, MAX_CUSTOM_RULES + 1):
        name = f"{base}-{index}"
        if name not in taken:
            return name
    return None
