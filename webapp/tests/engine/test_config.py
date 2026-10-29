import json

import pytest

from sentinel_waf_block.config import ConfigError, config_from_env, config_from_mapping
from sentinel_waf_block.models import InputError, incident_from_payload


POLICY = "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies/waf"


def test_missing_auto_block_setting_stays_dry_run() -> None:
    loaded = config_from_env(
        {
            "WAF_POLICY_RESOURCE_ID": POLICY,
            "WAF_PROVIDER": "ApplicationGateway",
        }
    )
    assert loaded.auto_block_enabled is False


def test_json_boolean_true_enables_and_string_does_not() -> None:
    enabled = config_from_mapping(
        {"wafPolicyResourceId": POLICY, "wafProvider": "ApplicationGateway", "autoBlockEnabled": True}
    )
    disabled = config_from_mapping(
        {"wafPolicyResourceId": POLICY, "wafProvider": "ApplicationGateway", "autoBlockEnabled": "true"}
    )
    assert enabled.auto_block_enabled is True
    assert disabled.auto_block_enabled == "true"
    assert disabled.auto_block_enabled is not True


def test_env_bool_and_array_are_json_values() -> None:
    loaded = config_from_env(
        {
            "WAF_POLICY_RESOURCE_ID": POLICY,
            "WAF_PROVIDER": "FrontDoor",
            "AUTO_BLOCK_ENABLED": "true",
            "PROTECTED_IP_RANGES": json.dumps(["203.0.113.0/24"]),
            "MAXIMUM_BLOCK_ENTRIES": "100",
        }
    )
    assert loaded.auto_block_enabled is True
    assert loaded.protected_ip_ranges == ("203.0.113.0/24",)
    assert loaded.arm_api_version == "2024-02-01"
    quoted = config_from_env(
        {
            "WAF_POLICY_RESOURCE_ID": POLICY,
            "WAF_PROVIDER": "ApplicationGateway",
            "AUTO_BLOCK_ENABLED": json.dumps("true"),
        }
    )
    assert quoted.auto_block_enabled == "true"


def test_bool_is_not_accepted_as_an_integer() -> None:
    with pytest.raises(ConfigError):
        config_from_mapping({"wafPolicyResourceId": POLICY, "wafProvider": "ApplicationGateway", "maximumBlockEntries": True})


def test_incident_payload_rejects_non_strings() -> None:
    with pytest.raises(InputError):
        incident_from_payload(
            {
                "incidentArmId": "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/log/providers/Microsoft.SecurityInsights/incidents/1",
                "incidentNumber": 11,
                "incidentTitle": "probe",
                "ipEntities": ["203.0.113.5", 10],
            }
        )
    parsed = incident_from_payload(
        {
            "incidentArmId": "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/log/providers/Microsoft.SecurityInsights/incidents/1",
            "incidentNumber": 11,
            "incidentTitle": "probe",
            "ipEntities": ["203.0.113.5"],
        }
    )
    assert parsed.number == "11"
    assert parsed.ip_entities == ("203.0.113.5",)
