# Deployment

Use `scripts/deploy.ps1` for a new resource group. It creates the resource group, deploys `infra/main.bicep`, removes Network Contributor from the playbook identity, assigns the Sentinel automation role, and then deploys the automation rule. It does not create or publish a Function App, and it does not write the operations web app's settings. Do not run it against the live resource group: the main template redeploys the playbook with an empty `functionKey` and can reset the Office 365 connection. `infra/parameters/main.bicepparam` is the safe default set for review. A deployment that uses only that file does not create the automation rule, so Sentinel will not call the playbook.

## Default test rig

```powershell
./scripts/deploy.ps1 -ResourceGroupName rg-ase-sentinel-poc -Location eastus
```

What-if, main template only:

```powershell
./scripts/deploy.ps1 -ResourceGroupName rg-ase-sentinel-poc -Location eastus -WhatIf
```

The script prints a warning that WAF_v2 bills hourly. Application Gateway deployments often take 20 to 40 minutes.

Outputs include the workspace name, workspace resource id, policy id, playbook name, `blockApiUrl`, `autoBlockEnabled`, the detection query kind, the analytics rule id, and the public IP when the test rig was created. `autoBlockEnabled` is a deployment output. It does not change the web app setting `AUTO_BLOCK_ENABLED`.

## Parameters the script enforces

- `QueryFrequencyMinutes` <= `QueryLookbackMinutes`
- Application Gateway min capacity <= max capacity, and max capacity >= 2
- `ProbeRulePriority` != `BlockRulePriority`
- `FrontDoor` requires `-DeployTestWaf $false` and either `-ExistingWafPolicyName` or `-ExistingWafPolicyResourceId`
- The test rig rejects an existing policy name or id at the same time, so a deploy cannot silently ignore one
- An existing resource id must be the ARM type for the selected provider
- `-AutoBlockEnabled` defaults to `$true`. `$false` is recorded on the deployment output. The script does not write `AUTO_BLOCK_ENABLED` on the web app
- `-OverrideProtectedRanges $true` requires `-ConfirmOverrideProtectedRanges`
- Each `ProtectedIpRanges` entry is an IPv4 address or `/8`, `/16`, `/24`, `/32`. Any other form is rejected.
- `NamePrefix` is 3 to 24 characters of lowercase letters, digits, and hyphens
- `ProbeMarker` is 3 to 40 letters, digits, and hyphens, so it cannot break the KQL string it is substituted into

Customer ranges are passed as a JSON array string. A one-element array stays an array.

## Existing Application Gateway policy

Only do this with a disposable policy. This template does not grant Network Contributor. The identity that calls the block API needs that role on the policy before a PUT can succeed. The live web app already has it. A new environment does not receive it from `infra/main.bicep`.

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

`-AutoBlockEnabled` changes the deployment output only. The web app setting `AUTO_BLOCK_ENABLED` stays whatever is already on that app.

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

## Block API URL

`-BlockApiUrl` is the HTTPS URL of `POST /api/SentinelWafAutoBlock` on the operations web app. The template passes it to the playbook parameter `functionUrl`. The parameter name stays `functionUrl`. Empty leaves that parameter empty, so a new playbook does not call the API. The script does not set `functionKey`. Put `BLOCK_API_KEY` into that secure parameter outside this script, and do not print it.

## Leftover telemetry resources

The template no longer creates Application Insights or a storage account. Incremental Bicep will not delete `appi-ase-sentinel-poc` or `st7ttpll74bmhiq` if they are still in the resource group. Leave them until you confirm the web app does not use them.

## Dry-run

Keep `AUTO_BLOCK_ENABLED` as the JSON token `false` on the operations web app. The playbook sends `execution=awaiting-approval`, then `execution=approved` only after approval. `execution=approved` writes for that call. `execution=awaiting-approval` does not. `-AutoBlockEnabled $false` changes the deployment output only. Do not redeploy the live playbook to change that flag.

## Destroy

```powershell
./scripts/cleanup.ps1 -ResourceGroupName rg-ase-sentinel-poc
```

Type the resource group name when prompted. `-Force` skips the prompt and is still a full group delete.

If opt-in mode wrote a policy outside this resource group, `cleanup.ps1` does not remove those addresses. Remove them with the procedure in the README first.
