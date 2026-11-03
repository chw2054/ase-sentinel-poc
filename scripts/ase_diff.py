"""Compare an Azure snapshot with a PoC profile.

The snapshot may contain WAF match values. compare() drops addresses before
it builds the report. Callers still should not write the raw snapshot to disk.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

SECRET_MARKERS = (
    "instrumentationkey=",
    "accountkey=",
    "defaultendpointsprotocol=",
    "sharedaccesskey",
    "applicationinsights_connection_string",
)

_TOKEN = re.compile(r"\$\{([A-Za-z0-9_]+)\}")


def expand(template: str, variables: dict[str, str]) -> str:
    def replace(match: re.Match[str]) -> str:
        key = match.group(1)
        if key not in variables:
            return match.group(0)
        return str(variables[key])

    return _TOKEN.sub(replace, template)


def find_unique(resources: list[dict[str, Any]], name_prefix: str) -> str | None:
    workspace_prefix = f"log-{name_prefix}-"
    for resource in resources:
        if _type_is(resource, "Microsoft.OperationalInsights/workspaces"):
            name = str(resource.get("name", ""))
            if name.startswith(workspace_prefix):
                suffix = name[len(workspace_prefix) :]
                if re.fullmatch(r"[a-z0-9]{13}", suffix):
                    return suffix
    for resource in resources:
        if _type_is(resource, "Microsoft.Storage/storageAccounts"):
            name = str(resource.get("name", ""))
            if re.fullmatch(r"st[a-z0-9]{13}", name):
                return name[2:]
    return None


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, dict):
        return [value]
    return []


def compare(profile: dict[str, Any], observed: dict[str, Any]) -> dict[str, Any]:
    resources = [_sanitize_resource(item) for item in _as_list(observed.get("resources"))]
    variables = _variables(profile, observed, resources)
    expected = [item for item in profile["resources"] if _included(item, profile)]
    matched: dict[str, dict[str, Any]] = {}
    rows: list[dict[str, Any]] = []

    for spec in expected:
        name = _expected_name(spec, variables)
        if name is None:
            rows.append(
                {
                    "id": spec["id"],
                    "name": spec.get("name", spec["id"]),
                    "status": "missing",
                    "differences": [
                        {
                            "field": "name",
                            "expected": spec.get("name", ""),
                            "actual": None,
                            "note": "uniqueString(resourceGroup().id) is assigned on the first deployment",
                        }
                    ],
                }
            )
            continue
        found = _find(spec, resources, matched, name, variables)
        if found is None:
            rows.append({"id": spec["id"], "name": name, "status": "missing", "differences": []})
            continue
        matched[spec["id"]] = found
        differences = _compare_fields(spec.get("compare") or [], found, variables)
        if spec["id"] == "wafPolicy":
            differences.extend(_probe_differences(profile, found))
        rows.append(
            {
                "id": spec["id"],
                "name": str(found.get("name") or name),
                "status": _status_from(differences),
                "differences": differences,
            }
        )

    rows.extend(_role_rows(profile, observed, matched, variables))
    preserved = _preserved(profile, matched.get("wafPolicy"))
    unmanaged = _unmanaged(resources, matched)
    deploy = _deploy_plan(profile, observed, matched.get("wafPolicy"), variables)
    report = {
        "profile": profile["name"],
        "resources": rows,
        "preserved": preserved,
        "unmanaged": unmanaged,
        "deploy": deploy,
    }
    _reject_secrets(report)
    return report


def render_text(report: dict[str, Any]) -> str:
    lines: list[str] = []
    grouped = {"missing": "缺少", "different": "不同", "unknown": "讀不到", "match": "相符"}
    for status, title in grouped.items():
        chosen = [row for row in report["resources"] if row["status"] == status]
        lines.append(f"{title} ({len(chosen)})")
        if not chosen:
            lines.append("  (none)")
        for row in chosen:
            lines.append(f"  {row['status']}  {row['id']}  {row['name']}")
            for diff in row["differences"]:
                if diff.get("unread"):
                    lines.append(f"    {diff['field']}: 讀不到")
                    continue
                actual = _show(diff.get("actual"))
                expected = _show(diff.get("expected"))
                note = diff.get("note")
                if note:
                    lines.append(f"    {diff['field']}: {note}")
                else:
                    lines.append(f"    {diff['field']}: expected {expected} actual {actual}")
        lines.append("")
    lines.append("保留的規則資料")
    if not report["preserved"]:
        lines.append("  (none)")
    for item in report["preserved"]:
        if item.get("unread"):
            lines.append(f"  {item['name']}  讀不到")
        else:
            lines.append(f"  {item['name']}  count={item['count']}")
    lines.append("")
    lines.append("未管理")
    if not report["unmanaged"]:
        lines.append("  (none)")
    for item in report["unmanaged"]:
        lines.append(f"  {item['type']}  {item['name']}")
    lines.append("")
    deploy = report["deploy"]
    lines.append("部署")
    if deploy.get("refuse"):
        lines.append(f"  拒絕: {deploy['refuse']}")
    else:
        lines.append(f"  DeployTestWaf={str(deploy['deployTestWaf']).lower()}")
        lines.append(f"  ExistingWafPolicyName={deploy.get('existingWafPolicyName') or ''}")
        if deploy.get("willNotChangeCustomRules"):
            lines.append("  不會重寫 WAF custom rules")
    lines.append("")
    return "\n".join(lines)


def _variables(
    profile: dict[str, Any], observed: dict[str, Any], resources: list[dict[str, Any]]
) -> dict[str, str]:
    name_prefix = str(observed["namePrefix"])
    unique = find_unique(resources, name_prefix) or ""
    parameters = profile["parameters"]
    policy_name = str(observed.get("existingWafPolicyName") or f"wafpol-{name_prefix}")
    subscription = str(observed.get("subscriptionId") or "")
    resource_group = str(observed.get("resourceGroup") or "")
    workspace_name = f"log-{name_prefix}-{unique}" if unique else ""
    workspace_id = ""
    if workspace_name:
        workspace_id = (
            f"/subscriptions/{subscription}/resourceGroups/{resource_group}"
            f"/providers/Microsoft.OperationalInsights/workspaces/{workspace_name}"
        )
    policy_id = (
        f"/subscriptions/{subscription}/resourceGroups/{resource_group}"
        "/providers/Microsoft.Network/applicationGatewayWebApplicationFirewallPolicies/"
        f"{policy_name}"
    )
    playbook_name = f"playbook-{name_prefix}-block-malicious-ip"
    return {
        "namePrefix": name_prefix,
        "location": str(observed.get("location") or ""),
        "subscriptionId": subscription,
        "resourceGroup": resource_group,
        "unique": unique,
        "unique8": unique[:8],
        "wafProvider": str(parameters["wafProvider"]),
        "blockRuleName": str(parameters["blockRuleName"]),
        "armApiVersion": str(parameters["armApiVersion"]),
        "policyName": policy_name,
        "workspaceName": workspace_name,
        "workspaceId": workspace_id,
        "wafPolicyId": policy_id,
        "playbookName": playbook_name,
    }


def _included(spec: dict[str, Any], profile: dict[str, Any]) -> bool:
    if spec.get("when") == "testWaf":
        return bool(profile.get("includesTestWaf"))
    return True


def _expected_name(spec: dict[str, Any], variables: dict[str, str]) -> str | None:
    if "match" in spec:
        return spec["id"]
    template = str(spec["name"])
    if not variables["unique"] and any(
        token in template for token in ("${unique}", "${unique8}", "${workspaceName}", "${workspaceId}")
    ):
        return None
    expanded = expand(template, variables)
    if "${" in expanded:
        return None
    return expanded


def _under_parent(item: dict[str, Any], parent_id: str) -> bool:
    explicit = str(item.get("parentId") or "")
    if explicit:
        return explicit.lower() == parent_id.lower()
    resource_id = str(item.get("id") or "")
    return resource_id.lower().startswith(parent_id.lower() + "/")


def _find(
    spec: dict[str, Any],
    resources: list[dict[str, Any]],
    matched: dict[str, dict[str, Any]],
    name: str,
    variables: dict[str, str],
) -> dict[str, Any] | None:
    if spec.get("parent") and spec["parent"] not in matched:
        return None
    parent = matched.get(spec["parent"]) if spec.get("parent") else None
    parent_id = str(parent.get("id") or "") if parent else ""
    candidates = [item for item in resources if _type_is(item, spec["type"])]
    if parent_id:
        candidates = [item for item in candidates if _under_parent(item, parent_id)]
    if "match" in spec:
        for item in candidates:
            if all(_equals(get_path(item, field)[0], expand(str(value), variables), True) for field, value in spec["match"].items()):
                return item
        return None
    for item in candidates:
        if str(item.get("name", "")).lower() == name.lower():
            return item
    return None


def _compare_fields(
    compares: list[dict[str, Any]], resource: dict[str, Any], variables: dict[str, str]
) -> list[dict[str, Any]]:
    differences: list[dict[str, Any]] = []
    for check in compares:
        actual, present = get_path(resource, check["field"])
        if not present:
            differences.append({"field": check["field"], "expected": None, "actual": None, "unread": True})
            continue
        if "notContains" in check:
            token = str(check["notContains"])
            if not isinstance(actual, str):
                differences.append({"field": check["field"], "expected": None, "actual": None, "unread": True})
            elif token in actual:
                differences.append(
                    {
                        "field": check["field"],
                        "expected": f"without {token}",
                        "actual": f"contains {token}",
                    }
                )
            continue
        expected = check["equals"]
        if isinstance(expected, str):
            expected = expand(expected, variables)
        if check["field"] == "location" and isinstance(actual, str) and isinstance(expected, str):
            if _location_key(actual) != _location_key(expected):
                differences.append({"field": check["field"], "expected": expected, "actual": actual})
            continue
        ignore_case = bool(check.get("ignoreCase"))
        if not _equals(actual, expected, ignore_case):
            differences.append({"field": check["field"], "expected": expected, "actual": actual})
    return differences


def _probe_differences(profile: dict[str, Any], policy: dict[str, Any]) -> list[dict[str, Any]]:
    parameters = profile["parameters"]
    wanted_name = parameters["probeRuleName"]
    wanted_priority = parameters["probeRulePriority"]
    rules = _custom_rules(policy)
    if rules is None:
        return [{"field": "probeRule", "expected": wanted_name, "actual": None, "unread": True}]
    found = next((rule for rule in rules if str(rule.get("name")) == wanted_name), None)
    if found is None:
        return [{"field": "probeRule", "expected": wanted_name, "actual": None}]
    if found.get("priority") != wanted_priority:
        return [
            {
                "field": "probeRule.priority",
                "expected": wanted_priority,
                "actual": found.get("priority"),
            }
        ]
    return []


def _role_rows(
    profile: dict[str, Any],
    observed: dict[str, Any],
    matched: dict[str, dict[str, Any]],
    variables: dict[str, str],
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    roles = observed.get("roles") or {}
    scope_ids = {
        "resourceGroup": f"/subscriptions/{variables['subscriptionId']}/resourceGroups/{variables['resourceGroup']}",
        "wafPolicy": str((matched.get("wafPolicy") or {}).get("id") or ""),
        "storage": str((matched.get("storage") or {}).get("id") or ""),
        "appInsights": str((matched.get("appInsights") or {}).get("id") or ""),
    }
    for spec in profile.get("roles") or []:
        source = matched.get(spec["principalFrom"])
        principal = None
        if source is not None:
            principal = get_path(source, "identity.principalId")[0]
        scope_name = spec["scope"]
        scope_read = roles.get(scope_name) or {"ok": False}
        label = f"{spec['principalFrom']}:{spec['roleDefinitionId'][:8]}"
        if source is None or not principal:
            rows.append(
                {
                    "id": spec["id"],
                    "name": label,
                    "status": "unknown",
                    "differences": [
                        {
                            "field": "principalId",
                            "expected": spec["principalFrom"],
                            "actual": None,
                            "unread": True,
                        }
                    ],
                }
            )
            continue
        if not scope_read.get("ok"):
            rows.append(
                {
                    "id": spec["id"],
                    "name": label,
                    "status": "unknown",
                    "differences": [{"field": "roleAssignment", "expected": spec["roleDefinitionId"], "actual": None, "unread": True}],
                }
            )
            continue
        found = False
        for item in _as_list(scope_read.get("items")):
            role_id = str(item.get("roleDefinitionId") or "")
            if not role_id.lower().endswith("/" + spec["roleDefinitionId"].lower()):
                continue
            if str(item.get("principalId") or "").lower() != str(principal).lower():
                continue
            item_scope = str(item.get("scope") or "")
            expected_scope = scope_ids.get(scope_name) or ""
            if expected_scope and item_scope and item_scope.lower() != expected_scope.lower():
                continue
            found = True
            break
        rows.append(
            {
                "id": spec["id"],
                "name": label,
                "status": "match" if found else "missing",
                "differences": [] if found else [{"field": "roleAssignment", "expected": spec["roleDefinitionId"], "actual": None}],
            }
        )
    return rows


def _preserved(profile: dict[str, Any], policy: dict[str, Any] | None) -> list[dict[str, Any]]:
    parameters = profile["parameters"]
    probe_name = parameters["probeRuleName"]
    block_name = parameters["blockRuleName"]
    rules = _custom_rules(policy) if policy else []
    if rules is None:
        return [{"name": block_name, "count": None, "unread": True}]
    preserved: list[dict[str, Any]] = []
    seen_block = False
    for rule in rules:
        name = str(rule.get("name") or "")
        if name == probe_name:
            continue
        preserved.append({"name": name, "count": _rule_count(rule)})
        if name == block_name:
            seen_block = True
    if not seen_block:
        preserved.insert(0, {"name": block_name, "count": 0})
    return preserved


def _unmanaged(resources: list[dict[str, Any]], matched: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    matched_ids = {str(item.get("id") or "").lower() for item in matched.values() if item.get("id")}
    rows: list[dict[str, Any]] = []
    for resource in resources:
        resource_id = str(resource.get("id") or "").lower()
        if resource_id and resource_id in matched_ids:
            continue
        resource_type = str(resource.get("type") or "")
        if resource_type.lower() == "microsoft.authorization/roleassignments":
            continue
        if "/subnets" in resource_type.lower() or resource_type.lower().endswith("/subnets"):
            continue
        rows.append({"type": resource_type, "name": str(resource.get("name") or "")})
    rows.sort(key=lambda item: (item["type"].lower(), item["name"].lower()))
    return rows


def _deploy_plan(
    profile: dict[str, Any],
    observed: dict[str, Any],
    policy: dict[str, Any] | None,
    variables: dict[str, str],
) -> dict[str, Any]:
    if observed.get("forceDeployTestWaf") and policy is not None:
        return {
            "refuse": "WAF policy already exists. Refusing DeployTestWaf because that deployment rewrites custom rules.",
            "deployTestWaf": False,
            "existingWafPolicyName": str(policy.get("name") or variables["policyName"]),
            "willNotChangeCustomRules": True,
        }
    if policy is not None:
        return {
            "refuse": None,
            "deployTestWaf": False,
            "existingWafPolicyName": str(policy.get("name") or variables["policyName"]),
            "willNotChangeCustomRules": True,
        }
    if profile.get("includesTestWaf"):
        return {
            "refuse": None,
            "deployTestWaf": True,
            "existingWafPolicyName": "",
            "willNotChangeCustomRules": False,
        }
    return {
        "refuse": "Profile does not include a test WAF and no existing policy was found.",
        "deployTestWaf": False,
        "existingWafPolicyName": "",
        "willNotChangeCustomRules": True,
    }


def _sanitize_resource(resource: dict[str, Any]) -> dict[str, Any]:
    cleaned = json.loads(json.dumps(resource))
    rules = _custom_rules(cleaned)
    if not rules:
        return cleaned
    sanitized = []
    for rule in rules:
        sanitized.append(
            {
                "name": rule.get("name"),
                "priority": rule.get("priority"),
                "valueCount": _rule_count(rule),
            }
        )
    properties = cleaned.setdefault("properties", {})
    properties["customRules"] = sanitized
    return cleaned


def _custom_rules(policy: dict[str, Any] | None) -> list[dict[str, Any]] | None:
    if policy is None:
        return []
    properties = policy.get("properties")
    if not isinstance(properties, dict) or "customRules" not in properties:
        return None
    rules = properties.get("customRules")
    if rules is None:
        return []
    if isinstance(rules, dict):
        return [rules]
    if not isinstance(rules, list):
        return None
    return rules


def _rule_count(rule: dict[str, Any]) -> int:
    conditions = rule.get("matchConditions")
    if isinstance(conditions, list) and conditions:
        total = 0
        for condition in conditions:
            if "valueCount" in condition:
                total += int(condition["valueCount"])
            else:
                total += len(condition.get("matchValues") or [])
        return total
    if "valueCount" in rule:
        return int(rule["valueCount"])
    return 0


def _status_from(differences: list[dict[str, Any]]) -> str:
    if any(not item.get("unread") for item in differences):
        return "different"
    if differences:
        return "unknown"
    return "match"


def _equals(actual: Any, expected: Any, ignore_case: bool) -> bool:
    if ignore_case and isinstance(actual, str) and isinstance(expected, str):
        return actual.casefold() == expected.casefold()
    return actual == expected


def _location_key(value: str) -> str:
    return "".join(value.split()).casefold()


def get_path(value: Any, path: str) -> tuple[Any, bool]:
    current = value
    for part in path.split("."):
        if not isinstance(current, dict) or part not in current:
            return None, False
        current = current[part]
    return current, True


def _type_is(resource: dict[str, Any], expected: str) -> bool:
    return str(resource.get("type") or "").lower() == expected.lower()


def _show(value: Any) -> str:
    if value is None:
        return "null"
    text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False)
    if _secret_text(text):
        return "<redacted>"
    if len(text) > 160:
        return text[:160] + "..."
    return text


def _secret_text(text: str) -> bool:
    lowered = text.lower()
    return any(marker in lowered for marker in SECRET_MARKERS)


def _reject_secrets(report: dict[str, Any]) -> None:
    encoded = json.dumps(report).lower()
    for marker in ("instrumentationkey=", "accountkey=", "defaultendpointsprotocol="):
        if marker in encoded:
            raise RuntimeError("diff report contained a secret marker")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--profile", required=True)
    parser.add_argument("--snapshot", required=True)
    parser.add_argument("--report", required=True)
    args = parser.parse_args()
    profile = json.loads(Path(args.profile).read_text(encoding="utf-8"))
    observed = json.loads(Path(args.snapshot).read_text(encoding="utf-8"))
    report = compare(profile, observed)
    report_path = Path(args.report)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    report_path.with_suffix(".txt").write_text(render_text(report), encoding="utf-8")


if __name__ == "__main__":
    main()
