"""Load deployment settings from a JSON object or JSON-valued environment variables.

String values are never coerced to boolean. ``true`` is the JSON boolean.
``"true"`` remains a string and does not enable enforcement.
"""

from __future__ import annotations

import json
import os
from collections.abc import Mapping
from typing import Any

from sentinel_waf_block.models import APPLICATION_GATEWAY, FRONT_DOOR, Config


class ConfigError(ValueError):
    pass


def config_from_mapping(data: Mapping[str, Any]) -> Config:
    if not isinstance(data, Mapping):
        raise ConfigError("configuration must be a JSON object")
    provider = data.get("wafProvider", APPLICATION_GATEWAY)
    if not isinstance(provider, str):
        raise ConfigError("wafProvider must be a string")
    resource_id = data.get("wafPolicyResourceId", "")
    if not isinstance(resource_id, str):
        raise ConfigError("wafPolicyResourceId must be a string")
    ranges = data.get("protectedIpRanges", [])
    if isinstance(ranges, str) or not isinstance(ranges, list):
        raise ConfigError("protectedIpRanges must be an array")
    maximum = data.get("maximumBlockEntries", 100)
    priority = data.get("blockRulePriority", 10)
    if type(maximum) is not int or isinstance(maximum, bool):
        raise ConfigError("maximumBlockEntries must be an integer")
    if type(priority) is not int or isinstance(priority, bool):
        raise ConfigError("blockRulePriority must be an integer")
    rule_name = data.get("blockRuleName", "SentinelAutoBlock")
    if not isinstance(rule_name, str):
        raise ConfigError("blockRuleName must be a string")
    api_version = data.get("armApiVersion")
    if api_version is None:
        api_version = "2024-02-01" if provider == FRONT_DOOR else "2024-05-01"
    if not isinstance(api_version, str) or api_version == "":
        raise ConfigError("armApiVersion must be a string")
    return Config(
        waf_policy_resource_id=resource_id,
        waf_provider=provider,
        protected_ip_ranges=tuple(ranges),
        maximum_block_entries=maximum,
        auto_block_enabled=data.get("autoBlockEnabled", False),
        override_protected_ranges=data.get("overrideProtectedRanges", False),
        block_rule_name=rule_name,
        block_rule_priority=priority,
        arm_api_version=api_version,
    )


def config_from_env(env: Mapping[str, str] | None = None) -> Config:
    """Build config from ``SENTINEL_WAF_CONFIG`` or individual JSON values."""

    source = os.environ if env is None else env
    path = source.get("SENTINEL_WAF_CONFIG")
    if path:
        with open(path, encoding="utf-8") as handle:
            loaded = json.load(handle)
        if not isinstance(loaded, dict):
            raise ConfigError("SENTINEL_WAF_CONFIG must contain a JSON object")
        return config_from_mapping(loaded)
    required = ("WAF_POLICY_RESOURCE_ID", "WAF_PROVIDER")
    missing = [name for name in required if not source.get(name)]
    if missing:
        raise ConfigError("missing environment values: " + ", ".join(missing))
    data: dict[str, Any] = {
        "wafPolicyResourceId": source["WAF_POLICY_RESOURCE_ID"],
        "wafProvider": source["WAF_PROVIDER"],
    }
    if "PROTECTED_IP_RANGES" in source:
        data["protectedIpRanges"] = _json_value("PROTECTED_IP_RANGES", source["PROTECTED_IP_RANGES"])
    if "MAXIMUM_BLOCK_ENTRIES" in source:
        data["maximumBlockEntries"] = _json_value("MAXIMUM_BLOCK_ENTRIES", source["MAXIMUM_BLOCK_ENTRIES"])
    if "AUTO_BLOCK_ENABLED" in source:
        data["autoBlockEnabled"] = _json_value("AUTO_BLOCK_ENABLED", source["AUTO_BLOCK_ENABLED"])
    if "OVERRIDE_PROTECTED_RANGES" in source:
        data["overrideProtectedRanges"] = _json_value(
            "OVERRIDE_PROTECTED_RANGES",
            source["OVERRIDE_PROTECTED_RANGES"],
        )
    if "BLOCK_RULE_NAME" in source:
        data["blockRuleName"] = source["BLOCK_RULE_NAME"]
    if "BLOCK_RULE_PRIORITY" in source:
        data["blockRulePriority"] = _json_value("BLOCK_RULE_PRIORITY", source["BLOCK_RULE_PRIORITY"])
    if "ARM_API_VERSION" in source:
        data["armApiVersion"] = source["ARM_API_VERSION"]
    return config_from_mapping(data)


def _json_value(name: str, raw: str) -> Any:
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ConfigError(f"{name} must be a JSON value") from exc
