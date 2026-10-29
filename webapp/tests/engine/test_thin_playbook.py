"""The deployed playbook only forwards the incident. It does not decide blocks."""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
THIN = ROOT / "playbooks" / "block-malicious-ip" / "thin-workflow.json"
REFERENCE = ROOT / "playbooks" / "block-malicious-ip" / "workflow.json"
PLAYBOOK = ROOT / "infra" / "modules" / "playbook.bicep"
FUNCTION = ROOT / "infra" / "modules" / "function.bicep"
MAIN = ROOT / "infra" / "main.bicep"


def _workflow() -> dict:
    return json.loads(THIN.read_text(encoding="utf-8"))


def test_thin_playbook_forwards_one_post() -> None:
    workflow = _workflow()
    call = _find(workflow["actions"], "Call_block_function")
    assert workflow["triggers"]["Microsoft_Sentinel_incident"]["inputs"]["path"] == "/incident-creation"
    assert call["inputs"]["method"] == "POST"
    assert call["inputs"]["uri"] == "@parameters('functionUrl')"
    assert call["inputs"]["headers"]["x-functions-key"] == "@parameters('functionKey')"
    assert call["inputs"]["retryPolicy"]["type"] == "none"
    assert call["limit"]["timeout"] == "PT2M"
    assert call["inputs"]["body"]["ipEntities"] == "@body('Select_IP_addresses')"
    assert call["inputs"]["body"]["execution"] == "dry-run"
    select = workflow["actions"]["Select_IP_addresses"]["inputs"]
    assert select["from"] == "@coalesce(body('Entities_-_Get_IPs')?['IPs'], json('[]'))"
    assert select["select"] == "@coalesce(item()?['Address'], '')"


def _find(node: object, name: str) -> dict:
    if isinstance(node, dict):
        if name in node and isinstance(node[name], dict) and "runAfter" in node.get(name, {}):
            return node[name]
        for value in node.values():
            found = _find(value, name)
            if found is not None:
                return found
    return None


def test_approval_flow_is_fail_closed() -> None:
    workflow = _workflow()
    approval = _find(workflow["actions"], "Start_and_wait_for_an_approval")
    assert approval["type"] == "ApiConnectionWebhook"
    assert "method" not in approval["inputs"]
    assert approval["inputs"]["path"] == "/approvalmail/$subscriptions"
    assert approval["inputs"]["body"]["NotificationUrl"] == "@{listCallbackUrl()}"
    message = approval["inputs"]["body"]["Message"]
    assert message["To"] == "@parameters('approverEmail')"
    assert message["Options"] == "Approve, Reject"
    assert message["ShowHTMLConfirmationDialog"] is True
    assert "approvalOptions" not in approval["inputs"]["body"]
    assert "/approvalmail/$approved" not in THIN.read_text(encoding="utf-8")

    decision = _find(workflow["actions"], "Decision")
    assert decision["expression"]["equals"] == [
        "@toLower(coalesce(body('Start_and_wait_for_an_approval')?['SelectedOption'], ''))",
        "approve",
    ]

    enforce = _find(workflow["actions"], "Call_block_function_-_enforce")
    assert enforce["inputs"]["body"]["execution"] == "enforce"

    empty = _find(workflow["actions"], "Check_approver")
    assert "approver email is empty" in json.dumps(empty)
    approve_branch = json.dumps(_find(workflow["actions"], "Decision")["else"])
    assert "The approver did not choose Approve" in approve_branch
    assert "The WAF policy was not changed" in approve_branch
    failed = json.dumps(_find(workflow["actions"], "Add_comment_-_approval_failed"))
    assert "The WAF policy was not changed" in failed


def test_thin_playbook_does_not_decide_or_write_the_policy() -> None:
    text = THIN.read_text(encoding="utf-8")
    assert "Would block IP" not in text
    assert "Blocked IP:" not in text
    assert "https://management.azure.com" not in text
    assert "negationConditon" not in text
    assert "Do not assume the WAF policy was changed" in text
    reference = REFERENCE.read_text(encoding="utf-8")
    assert "Would block IP:" in reference


def test_bicep_deploys_the_function_and_keeps_the_logic_app_thin() -> None:
    playbook = PLAYBOOK.read_text(encoding="utf-8")
    function = FUNCTION.read_text(encoding="utf-8")
    main = MAIN.read_text(encoding="utf-8")
    assert "thin-workflow.json" in playbook
    assert "role-waf-policy.bicep" not in playbook
    assert "office365" in playbook
    assert "approverEmail" in playbook
    assert "modules/function.bicep" in main
    assert "AUTO_BLOCK_ENABLED" in function
    assert "autoBlockEnabled ? 'true' : 'false'" in function
    assert "string(autoBlockEnabled)" not in function
    assert "string(overrideProtectedRanges)" not in function
    assert "APPLICATIONINSIGHTS_CONNECTION_STRING" in function
    assert "APPLICATIONINSIGHTS_AUTHENTICATION_STRING" in function
    assert "Authorization=AAD" in function
    assert "3913510d-42f4-4e42-8a64-420c390055eb" in function
    assert "Microsoft.Insights/components@2020-02-02" in function
    assert "param autoBlockEnabled bool = true" in main
    assert "3e150937-b8fe-4cfb-8069-0eaf05ecd056" in function
    assert "role-waf-policy.bicep" in function
    assert "FC1" in function
    assert "version: '3.11'" in function
