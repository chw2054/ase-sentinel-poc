"""Shared fixtures. No network and no Azure subscription."""

from __future__ import annotations

import copy

from sentinel_waf_block.models import APPLICATION_GATEWAY, FRONT_DOOR, Config, Incident

POLICY = (
    "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-example"
    "/providers/Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies/wafpol-example"
)
INCIDENT_ID = (
    "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-example"
    "/providers/Microsoft.OperationalInsights/workspaces/log-example"
    "/providers/Microsoft.SecurityInsights/incidents/00000000-0000-0000-0000-000000000001"
)


def incident(*addresses: str, number: str = "11") -> Incident:
    return Incident(
        arm_id=INCIDENT_ID,
        number=number,
        title="ASE POC simulated WAF probe",
        ip_entities=addresses,
    )


def config(**overrides: object) -> Config:
    values: dict[str, object] = {
        "waf_policy_resource_id": POLICY,
        "waf_provider": APPLICATION_GATEWAY,
        "protected_ip_ranges": (),
        "maximum_block_entries": 100,
        "auto_block_enabled": False,
        "override_protected_ranges": False,
        "block_rule_name": "SentinelAutoBlock",
        "block_rule_priority": 10,
        "arm_api_version": "2024-05-01",
    }
    values.update(overrides)
    return Config(**values)  # type: ignore[arg-type]


def front_door(**overrides: object) -> Config:
    values = {"waf_provider": FRONT_DOOR, "arm_api_version": "2024-02-01"}
    values.update(overrides)
    return config(**values)


def probe_rule() -> dict:
    return {
        "name": "PocSimulatedProbe",
        "priority": 50,
        "ruleType": "MatchRule",
        "action": "Block",
        "state": "Enabled",
        "matchConditions": [
            {
                "matchVariables": [{"variableName": "QueryString"}],
                "operator": "Contains",
                "negationConditon": False,
                "matchValues": ["ase-poc-probe"],
            }
        ],
    }


def agw_block_rule(values: list[str]) -> dict:
    return {
        "name": "SentinelAutoBlock",
        "priority": 10,
        "ruleType": "MatchRule",
        "action": "Block",
        "state": "Enabled",
        "matchConditions": [
            {
                "matchVariables": [{"variableName": "RemoteAddr"}],
                "operator": "IPMatch",
                "negationConditon": False,
                "matchValues": values,
            }
        ],
    }


def agw_policy(*rules: dict) -> dict:
    return {
        "location": "eastus",
        "tags": {"env": "poc"},
        "sku": {"name": "WAF_v2"},
        "properties": {
            "policySettings": {"mode": "Prevention", "state": "Enabled"},
            "managedRules": {"managedRuleSets": [{"ruleSetType": "OWASP", "ruleSetVersion": "3.2"}]},
            "customRules": list(rules),
        },
    }


def front_door_policy(*rules: dict) -> dict:
    return {
        "location": "eastus",
        "sku": {"name": "Premium_AzureFrontDoor"},
        "tags": {"env": "poc"},
        "properties": {
            "policySettings": {"enabledState": "Enabled", "mode": "Prevention"},
            "managedRules": {"managedRuleSets": []},
            "customRules": {"rules": list(rules)},
        },
    }


class FakeWaf:
    def __init__(self, document: dict | None = None, get_error: Exception | None = None, put_error: Exception | None = None) -> None:
        self.document = document if document is not None else agw_policy(probe_rule())
        self.get_error = get_error
        self.put_error = put_error
        self.gets: list[tuple[str, str]] = []
        self.puts: list[dict] = []

    def get_policy(self, resource_id: str, api_version: str) -> dict:
        self.gets.append((resource_id, api_version))
        if self.get_error:
            raise self.get_error
        return copy.deepcopy(self.document)

    def put_policy(self, resource_id: str, api_version: str, body: dict, timeout_seconds: float = 120) -> None:
        self.puts.append(body)
        if self.put_error:
            raise self.put_error


class FakeComments:
    def __init__(self, error: Exception | None = None) -> None:
        self.error = error
        self.messages: list[tuple[str, str]] = []

    def write_comment(self, incident_arm_id: str, message: str) -> None:
        if self.error:
            raise self.error
        self.messages.append((incident_arm_id, message))


class FakeNotifier:
    def __init__(self, error: Exception | None = None) -> None:
        self.error = error
        self.calls: list[tuple[str, object]] = []

    def notify(self, event: str, result: object) -> None:
        self.calls.append((event, result))
        if self.error:
            raise self.error
