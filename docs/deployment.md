# Deployment

Use `scripts/deploy.ps1`. It creates the resource group, deploys `infra/main.bicep`, publishes the Python Function App, binds the playbook to that function, removes Network Contributor from the playbook identity, assigns the Sentinel automation role, and then deploys the automation rule. `infra/parameters/main.bicepparam` is the safe default set for review. A deployment that uses only that file does not publish the function and does not create the automation rule, so Sentinel will not call a working playbook.

## Default test rig

```powershell
./scripts/deploy.ps1 -ResourceGroupName rg-ase-sentinel-poc -Location eastus
```

What-if, main template only:

```powershell
./scripts/deploy.ps1 -ResourceGroupName rg-ase-sentinel-poc -Location eastus -WhatIf
```

The script prints a warning that WAF_v2 bills hourly. Application Gateway deployments often take 20 to 40 minutes.

Outputs include the workspace name, workspace resource id, policy id, playbook name, function app name, Application Insights name, `autoBlockEnabled`, the detection query kind, the analytics rule id, and the public IP when the test rig was created. The Application Insights connection string is not printed.

## Parameters the script enforces

- `QueryFrequencyMinutes` <= `QueryLookbackMinutes`
- Application Gateway min capacity <= max capacity, and max capacity >= 2
- `ProbeRulePriority` != `BlockRulePriority`
- `FrontDoor` requires `-DeployTestWaf $false` and either `-ExistingWafPolicyName` or `-ExistingWafPolicyResourceId`
- The test rig rejects an existing policy name or id at the same time, so a deploy cannot silently ignore one
- An existing resource id must be the ARM type for the selected provider
- `-AutoBlockEnabled` defaults to `$true`. `$false` deploys a dry-run. `-ConfirmAutoBlock` is accepted and is not required
- `-OverrideProtectedRanges $true` requires `-ConfirmOverrideProtectedRanges`
- Each `ProtectedIpRanges` entry is an IPv4 address or `/8`, `/16`, `/24`, `/32`. Any other form is rejected.
- `NamePrefix` is 3 to 24 characters of lowercase letters, digits, and hyphens
- `ProbeMarker` is 3 to 40 letters, digits, and hyphens, so it cannot break the KQL string it is substituted into

Customer ranges are passed as a JSON array string. A one-element array stays an array.

## Existing Application Gateway policy

Only do this with a disposable policy. The function identity receives Network Contributor on that policy. Opt-in mode PUTs the policy.

```powershell
./scripts/deploy.ps1 `
  -ResourceGroupName rg-ase-sentinel-poc `
  -DeployTestWaf $false `
  -WafProvider ApplicationGateway `
  -ExistingWafPolicyName wafpol-disposable
```

This path does **not** add `PocSimulatedProbe` and does **not** create a diagnostic setting. Create an equivalent custom rule yourself if you want the same marker, and point that gateway's `ApplicationGatewayFirewallLog` at the workspace this deployment creates. If the policy is in another resource group, pass `-ExistingWafPolicyResourceId` instead of the name. The identity that runs the script needs `Microsoft.Authorization/roleAssignments/write` on that policy.

Until those logs arrive, the analytics rule has nothing to match. That is expected. This repository does not attach diagnostics to a gateway it did not create.

## Front Door

```powershell
./scripts/deploy.ps1 `
  -ResourceGroupName rg-ase-sentinel-poc `
  -WafProvider FrontDoor `
  -DeployTestWaf $false `
  -ExistingWafPolicyResourceId /subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.Network/frontDoorWebApplicationFirewallPolicies/<policy> `
  -FrontDoorLogDestination AzureDiagnostics
```

What this does not do:

- Create a Front Door profile, endpoint, origin, or WAF policy
- Enable Front Door diagnostic logs
- Send test traffic at a Front Door hostname
- Prove that `AzureFrontDoorWebApplicationFirewallLog` exists

`AzureDiagnostics` is the query Microsoft documents (`Category == "FrontDoorWebApplicationFirewallLog"`, with `column_ifexists` for `clientIP_s`, `action_s`, `ruleName_s`, `requestUri_s`, and `host_s`). Use `-FrontDoorLogDestination ResourceSpecific` only after ASE confirms `AzureFrontDoorWebApplicationFirewallLog` in the chosen workspace. The script warns when that option is selected.

Blocking stays on unless you also pass `-AutoBlockEnabled $false`.

## Automation rule phase

Sentinel returns an error if an automation rule uses `RunPlaybook` before the **Azure Security Insights** service principal has **Microsoft Sentinel Automation Contributor** on the playbook's resource group.

The script:

1. Resolves that principal with `az ad sp list --display-name "Azure Security Insights"`.
2. Deploys `infra/role-sentinel-automation.bicep`.
3. Waits 30 seconds.
4. Deploys `sentinel/automation-rules/block-malicious-ip.bicep` using the workspace name, analytics rule id, and playbook id from the main deployment outputs.

If the principal cannot be found, the script leaves the analytics rule and the playbook in place and tells you to re-run:

```powershell
./scripts/deploy.ps1 -ResourceGroupName rg-ase-sentinel-poc -AutomationRuleOnly
```

`-AutomationRuleOnly` still needs a successful `ase-sentinel-poc-main` deployment in that resource group. It does not combine with `-WhatIf`.

If the second deployment fails on replication, wait and run `-AutomationRuleOnly` again. The rule name is stable, so the retry updates the same rule.

## Application Insights

The function module creates a workspace-based Application Insights component on the Sentinel Log Analytics workspace and assigns Monitoring Metrics Publisher to the function identity. The function app settings are `APPLICATIONINSIGHTS_CONNECTION_STRING` and `APPLICATIONINSIGHTS_AUTHENTICATION_STRING=Authorization=AAD`. The script does not print the connection string. Invocation and trace rows show up in that workspace after the function handles a request. Sampling is off in `function-app/host.json`.

## Returning to dry-run

Redeploy with the same resource group and name prefix:

```powershell
./scripts/deploy.ps1 `
  -ResourceGroupName rg-ase-sentinel-poc `
  -NamePrefix ase-sentinel-poc `
  -AutoBlockEnabled $false
```

Bicep writes `AUTO_BLOCK_ENABLED` as the JSON token `false`. Previous incidents are not replayed. The default deploy writes the token `true`.

The function publish packs `function-app/function_app.py`, `host.json`, `sentinel_waf_block`, and Linux wheels. It does not use remote build. The script then reads the host function key, writes it only into a temporary parameters file, and deploys `infra/modules/playbook.bicep` again so the Logic App secure parameter is set. The script does not print the key. A full deploy clears that parameter during the main template and sets it again in the binding step. Until the binding step finishes, the playbook comments that the function URL is empty, or that the call did not finish, and it does not decide a block. After publish, the script reads the app settings back. If `AUTO_BLOCK_ENABLED` or `OVERRIDE_PROTECTED_RANGES` is not the lowercase JSON token, it rewrites the whole setting dictionary and restarts the app. That rewrite keeps every other setting, including the Application Insights connection string.

## Destroy

```powershell
./scripts/cleanup.ps1 -ResourceGroupName rg-ase-sentinel-poc
```

Type the resource group name when prompted. `-Force` skips the prompt and is still a full group delete.

If opt-in mode wrote a policy outside this resource group, `cleanup.ps1` does not remove those addresses. Remove them with the procedure in the README first.
