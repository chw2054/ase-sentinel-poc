import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import ase_diff

ROOT = Path(__file__).resolve().parents[1]
PROFILE = json.loads((ROOT / "profiles" / "poc.json").read_text(encoding="utf-8"))
PREFIX = "ase-sentinel-poc"
UNIQUE = "cc5a2vz77toz6"
SUB = "00000000-0000-0000-0000-000000000001"
RG = "rg-ase-sentinel-poc"
LOC = "eastus"
WORKSPACE = f"log-{PREFIX}-{UNIQUE}"
WORKSPACE_ID = (
    f"/subscriptions/{SUB}/resourceGroups/{RG}/providers/"
    f"Microsoft.OperationalInsights/workspaces/{WORKSPACE}"
)
POLICY_ID = (
    f"/subscriptions/{SUB}/resourceGroups/{RG}/providers/"
    "Microsoft.Network/applicationGatewayWebApplicationFirewallPolicies/"
    f"wafpol-{PREFIX}"
)
GATEWAY_ID = (
    f"/subscriptions/{SUB}/resourceGroups/{RG}/providers/"
    f"Microsoft.Network/applicationGateways/agw-{PREFIX}"
)
PLAYBOOK_ID = (
    f"/subscriptions/{SUB}/resourceGroups/{RG}/providers/"
    f"Microsoft.Logic/workflows/playbook-{PREFIX}-block-malicious-ip"
)
FUNCTION_ID = (
    f"/subscriptions/{SUB}/resourceGroups/{RG}/providers/"
    f"Microsoft.Web/sites/fn-{PREFIX}-{UNIQUE[:8]}"
)
STORAGE_ID = (
    f"/subscriptions/{SUB}/resourceGroups/{RG}/providers/"
    f"Microsoft.Storage/storageAccounts/st{UNIQUE}"
)
INSIGHTS_ID = (
    f"/subscriptions/{SUB}/resourceGroups/{RG}/providers/"
    f"Microsoft.Insights/components/appi-{PREFIX}"
)
RG_ID = f"/subscriptions/{SUB}/resourceGroups/{RG}"
FUNCTION_PRINCIPAL = "11111111-1111-1111-1111-111111111111"
PLAYBOOK_PRINCIPAL = "22222222-2222-2222-2222-222222222222"


def test_profile_names_match_bicep_templates():
    variables = {
        "namePrefix": PREFIX,
        "unique": UNIQUE,
        "unique8": UNIQUE[:8],
        "workspaceName": WORKSPACE,
        "playbookName": f"playbook-{PREFIX}-block-malicious-ip",
        "policyName": f"wafpol-{PREFIX}",
    }
    names = {
        item["id"]: ase_diff.expand(item["name"], variables)
        for item in PROFILE["resources"]
        if "name" in item
    }
    assert names["workspace"] == "log-ase-sentinel-poc-cc5a2vz77toz6"
    assert "storage" not in names
    assert "functionApp" not in names
    assert "plan" not in names
    assert "appInsights" not in names
    assert names["appGateway"] == "agw-ase-sentinel-poc"
    assert names["publicIp"] == "pip-ase-sentinel-poc"
    assert names["vnet"] == "vnet-ase-sentinel-poc"
    assert names["wafPolicy"] == "wafpol-ase-sentinel-poc"
    assert names["playbook"] == "playbook-ase-sentinel-poc-block-malicious-ip"
    assert names["solution"] == "SecurityInsights(log-ase-sentinel-poc-cc5a2vz77toz6)"
    assert names["sentinelConnection"] == (
        "azuresentinel-playbook-ase-sentinel-poc-block-malicious-ip"
    )


def test_missing_workspace_and_unresolved_unique_names():
    report = ase_diff.compare(PROFILE, _base())
    statuses = {row["id"]: row["status"] for row in report["resources"]}
    assert statuses["workspace"] == "missing"
    assert "storage" not in statuses
    assert "functionApp" not in statuses
    assert report["deploy"]["deployTestWaf"] is True
    assert report["deploy"]["willNotChangeCustomRules"] is False


def test_location_display_name_matches_region_slug():
    observed = _matching()
    _by_type(observed, "Microsoft.Logic/workflows")["location"] = "East US"
    report = ase_diff.compare(PROFILE, observed)
    assert _row(report, "playbook")["status"] == "match"


def test_location_mismatch_is_different():
    observed = _matching()
    workspace = _by_type(observed, "Microsoft.OperationalInsights/workspaces")
    workspace["location"] = "westus"
    report = ase_diff.compare(PROFILE, observed)
    row = _row(report, "workspace")
    assert row["status"] == "different"
    assert row["differences"][0]["field"] == "location"
    assert row["differences"][0]["actual"] == "westus"


def test_matching_snapshot_and_disabled_rule_is_different():
    report = ase_diff.compare(PROFILE, _matching())
    assert all(row["status"] == "match" for row in report["resources"])
    unmanaged = {(item["type"], item["name"]) for item in report["unmanaged"]}
    assert ("Microsoft.Storage/storageAccounts", f"st{UNIQUE}") in unmanaged
    assert ("Microsoft.Web/serverFarms", f"asp-{PREFIX}-fn") in unmanaged
    assert ("Microsoft.Web/sites", f"fn-{PREFIX}-{UNIQUE[:8]}") in unmanaged
    assert ("Microsoft.Insights/components", f"appi-{PREFIX}") in unmanaged
    assert report["deploy"]["deployTestWaf"] is False
    assert report["deploy"]["existingWafPolicyName"] == "wafpol-ase-sentinel-poc"
    assert report["deploy"]["willNotChangeCustomRules"] is True

    observed = _matching()
    rule = next(
        item
        for item in observed["resources"]
        if item["type"] == "Microsoft.SecurityInsights/alertRules"
    )
    rule["properties"]["enabled"] = False
    changed = ase_diff.compare(PROFILE, observed)
    row = _row(changed, "analyticsRule")
    assert row["status"] == "different"
    assert row["differences"][0]["field"] == "properties.enabled"
    assert changed["deploy"]["willNotChangeCustomRules"] is True


def test_preserved_counts_omit_addresses_and_probe_rule():
    observed = _matching()
    policy = _by_type(observed, "Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies")
    policy["properties"]["customRules"] = [
        {
            "name": "SentinelAutoBlock",
            "priority": 10,
            "matchConditions": [{"matchValues": ["198.51.100.9", "203.0.113.5", "192.0.2.8", "198.51.100.10"]}],
        },
        {
            "name": "PocSimulatedProbe",
            "priority": 50,
            "matchConditions": [{"matchValues": ["ase-poc-probe"]}],
        },
        {
            "name": "CapacityTestBlock",
            "priority": 90,
            "matchConditions": [{"matchValues": ["203.0.113.4"] * 600}],
        },
    ]
    report = ase_diff.compare(PROFILE, observed)
    encoded = json.dumps(report)
    assert "198.51.100.9" not in encoded
    assert "203.0.113.4" not in encoded
    preserved = {item["name"]: item["count"] for item in report["preserved"]}
    assert preserved == {"SentinelAutoBlock": 4, "CapacityTestBlock": 600}
    assert _row(report, "wafPolicy")["status"] == "match"


def test_connection_string_is_dropped_before_the_report():
    observed = _matching()
    observed["functionSettings"].append(
        {
            "name": "APPLICATIONINSIGHTS_CONNECTION_STRING",
            "value": "InstrumentationKey=abc;IngestionEndpoint=https://example.invalid",
        }
    )
    report = ase_diff.compare(PROFILE, observed)
    encoded = json.dumps(report)
    assert "InstrumentationKey=" not in encoded
    assert "example.invalid" not in encoded
    assert "functionApp" not in {row["id"] for row in report["resources"]}


def test_existing_policy_refuses_forced_test_waf_deploy():
    observed = _matching()
    observed["forceDeployTestWaf"] = True
    report = ase_diff.compare(PROFILE, observed)
    assert report["deploy"]["refuse"]
    assert report["deploy"]["deployTestWaf"] is False
    assert report["deploy"]["willNotChangeCustomRules"] is True


def test_unreadable_role_assignment_is_unknown():
    observed = _matching()
    observed["roles"]["resourceGroup"] = {"ok": False, "items": []}
    report = ase_diff.compare(PROFILE, observed)
    assert _row(report, "playbookSentinelResponder")["status"] == "unknown"
    ids = {row["id"] for row in report["resources"]}
    assert "functionSentinelResponder" not in ids
    assert "functionWafContributor" not in ids


def test_extra_resource_is_unmanaged():
    observed = _matching()
    observed["resources"].append(
        {
            "id": f"{RG_ID}/providers/Microsoft.Compute/virtualMachines/extra",
            "name": "extra",
            "type": "Microsoft.Compute/virtualMachines",
            "location": LOC,
        }
    )
    report = ase_diff.compare(PROFILE, observed)
    assert {"type": "Microsoft.Compute/virtualMachines", "name": "extra"} in report["unmanaged"]


def _base() -> dict:
    return {
        "namePrefix": PREFIX,
        "location": LOC,
        "subscriptionId": SUB,
        "resourceGroup": RG,
        "forceDeployTestWaf": False,
        "resources": [],
        "functionSettings": [],
        "roles": {
            "resourceGroup": {"ok": True, "items": []},
            "wafPolicy": {"ok": True, "items": []},
            "storage": {"ok": True, "items": []},
            "appInsights": {"ok": True, "items": []},
        },
    }


def _matching() -> dict:
    observed = _base()
    resources = [
        {
            "id": WORKSPACE_ID,
            "name": WORKSPACE,
            "type": "Microsoft.OperationalInsights/workspaces",
            "location": LOC,
            "properties": {"sku": {"name": "PerGB2018"}},
        },
        {
            "id": f"{RG_ID}/providers/Microsoft.OperationsManagement/solutions/SecurityInsights({WORKSPACE})",
            "name": f"SecurityInsights({WORKSPACE})",
            "type": "Microsoft.OperationsManagement/solutions",
            "location": LOC,
        },
        {
            "id": f"{WORKSPACE_ID}/providers/Microsoft.SecurityInsights/onboardingStates/default",
            "parentId": WORKSPACE_ID,
            "name": "default",
            "type": "Microsoft.SecurityInsights/onboardingStates",
        },
        {
            "id": f"{WORKSPACE_ID}/providers/Microsoft.SecurityInsights/watchlists/AseWafIpAllowlist",
            "parentId": WORKSPACE_ID,
            "name": "AseWafIpAllowlist",
            "type": "Microsoft.SecurityInsights/watchlists",
        },
        {
            "id": f"{WORKSPACE_ID}/providers/Microsoft.SecurityInsights/alertRules/rule",
            "parentId": WORKSPACE_ID,
            "name": "rule",
            "type": "Microsoft.SecurityInsights/alertRules",
            "properties": {
                "displayName": "ASE POC - simulated WAF probe",
                "enabled": True,
                "query": "AGWFirewallLogs | where Action == 'Blocked'",
                "incidentConfiguration": {
                    "groupingConfiguration": {
                        "reopenClosedIncident": False,
                        "lookbackDuration": "PT12H",
                    }
                },
            },
        },
        {
            "id": f"{WORKSPACE_ID}/providers/Microsoft.SecurityInsights/automationRules/auto",
            "parentId": WORKSPACE_ID,
            "name": "auto",
            "type": "Microsoft.SecurityInsights/automationRules",
            "properties": {
                "displayName": "ASE POC - run block playbook for simulated WAF probe",
                "triggeringLogic": {
                    "isEnabled": True,
                    "triggersOn": "Incidents",
                    "triggersWhen": "Created",
                },
            },
        },
        {
            "id": POLICY_ID,
            "name": f"wafpol-{PREFIX}",
            "type": "Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies",
            "location": LOC,
            "properties": {
                "policySettings": {"mode": "Prevention", "state": "Enabled"},
                "customRules": [
                    {"name": "SentinelAutoBlock", "priority": 10, "valueCount": 4},
                    {"name": "PocSimulatedProbe", "priority": 50, "valueCount": 1},
                    {"name": "CapacityTestBlock", "priority": 90, "valueCount": 600},
                ],
            },
        },
        {
            "id": f"{RG_ID}/providers/Microsoft.Network/publicIPAddresses/pip-{PREFIX}",
            "name": f"pip-{PREFIX}",
            "type": "Microsoft.Network/publicIPAddresses",
            "location": LOC,
            "sku": {"name": "Standard"},
        },
        {
            "id": f"{RG_ID}/providers/Microsoft.Network/virtualNetworks/vnet-{PREFIX}",
            "name": f"vnet-{PREFIX}",
            "type": "Microsoft.Network/virtualNetworks",
            "location": LOC,
        },
        {
            "id": GATEWAY_ID,
            "name": f"agw-{PREFIX}",
            "type": "Microsoft.Network/applicationGateways",
            "location": LOC,
            "properties": {"sku": {"name": "WAF_v2"}},
        },
        {
            "id": f"{GATEWAY_ID}/providers/Microsoft.Insights/diagnosticSettings/diag-waf-to-sentinel",
            "parentId": GATEWAY_ID,
            "name": "diag-waf-to-sentinel",
            "type": "Microsoft.Insights/diagnosticSettings",
            "properties": {"workspaceId": WORKSPACE_ID},
        },
        {
            "id": STORAGE_ID,
            "name": f"st{UNIQUE}",
            "type": "Microsoft.Storage/storageAccounts",
            "location": LOC,
            "sku": {"name": "Standard_LRS"},
        },
        {
            "id": f"{RG_ID}/providers/Microsoft.Web/serverFarms/asp-{PREFIX}-fn",
            "name": f"asp-{PREFIX}-fn",
            "type": "Microsoft.Web/serverFarms",
            "location": LOC,
            "sku": {"name": "FC1"},
        },
        {
            "id": FUNCTION_ID,
            "name": f"fn-{PREFIX}-{UNIQUE[:8]}",
            "type": "Microsoft.Web/sites",
            "location": LOC,
            "identity": {"principalId": FUNCTION_PRINCIPAL},
        },
        {
            "id": INSIGHTS_ID,
            "name": f"appi-{PREFIX}",
            "type": "Microsoft.Insights/components",
            "location": LOC,
            "properties": {
                "IngestionMode": "LogAnalytics",
                "WorkspaceResourceId": WORKSPACE_ID,
            },
        },
        {
            "id": PLAYBOOK_ID,
            "name": f"playbook-{PREFIX}-block-malicious-ip",
            "type": "Microsoft.Logic/workflows",
            "location": LOC,
            "identity": {"principalId": PLAYBOOK_PRINCIPAL},
        },
        {
            "id": f"{RG_ID}/providers/Microsoft.Web/connections/azuresentinel-playbook-{PREFIX}-block-malicious-ip",
            "name": f"azuresentinel-playbook-{PREFIX}-block-malicious-ip",
            "type": "Microsoft.Web/connections",
            "location": LOC,
        },
        {
            "id": f"{PLAYBOOK_ID}/providers/Microsoft.Insights/diagnosticSettings/diag-playbook-runtime",
            "parentId": PLAYBOOK_ID,
            "name": "diag-playbook-runtime",
            "type": "Microsoft.Insights/diagnosticSettings",
            "properties": {"workspaceId": WORKSPACE_ID},
        },
    ]
    observed["resources"] = resources
    observed["functionSettings"] = [
        {"name": "AUTO_BLOCK_ENABLED", "value": "true"},
        {"name": "OVERRIDE_PROTECTED_RANGES", "value": "false"},
        {"name": "WAF_PROVIDER", "value": "ApplicationGateway"},
        {"name": "BLOCK_RULE_NAME", "value": "SentinelAutoBlock"},
        {"name": "BLOCK_RULE_PRIORITY", "value": "10"},
        {"name": "MAXIMUM_BLOCK_ENTRIES", "value": "100"},
        {"name": "PROTECTED_IP_RANGES", "value": "[]"},
        {"name": "NOTIFY_EVENTS", "value": "would_block,blocked,put_failed,capacity"},
        {"name": "APPLICATIONINSIGHTS_AUTHENTICATION_STRING", "value": "Authorization=AAD"},
        {"name": "AzureWebJobsStorage__credential", "value": "managedidentity"},
        {"name": "ARM_API_VERSION", "value": "2024-05-01"},
        {"name": "WAF_POLICY_RESOURCE_ID", "value": POLICY_ID},
    ]
    observed["roles"] = {
        "resourceGroup": {
            "ok": True,
            "items": [
                _role("3e150937-b8fe-4cfb-8069-0eaf05ecd056", FUNCTION_PRINCIPAL, RG_ID),
                _role("3e150937-b8fe-4cfb-8069-0eaf05ecd056", PLAYBOOK_PRINCIPAL, RG_ID),
            ],
        },
        "wafPolicy": {
            "ok": True,
            "items": [_role("4d97b98b-1d4f-4787-a291-c67834d212e7", FUNCTION_PRINCIPAL, POLICY_ID)],
        },
        "storage": {
            "ok": True,
            "items": [
                _role("b7e6dc6d-f1e8-4753-8033-0f276bb0955b", FUNCTION_PRINCIPAL, STORAGE_ID),
                _role("974c5e8b-45b9-4653-ba55-5f855dd0fb88", FUNCTION_PRINCIPAL, STORAGE_ID),
                _role("0a9a7e1f-b9d0-4cc4-a60d-0319b160aaa3", FUNCTION_PRINCIPAL, STORAGE_ID),
            ],
        },
        "appInsights": {
            "ok": True,
            "items": [_role("3913510d-42f4-4e42-8a64-420c390055eb", FUNCTION_PRINCIPAL, INSIGHTS_ID)],
        },
    }
    return observed


def _role(role_id: str, principal: str, scope: str) -> dict:
    return {
        "roleDefinitionId": f"/subscriptions/{SUB}/providers/Microsoft.Authorization/roleDefinitions/{role_id}",
        "principalId": principal,
        "scope": scope,
    }


def _by_type(observed: dict, resource_type: str) -> dict:
    return next(item for item in observed["resources"] if item["type"] == resource_type)


def _row(report: dict, row_id: str) -> dict:
    return next(item for item in report["resources"] if item["id"] == row_id)
