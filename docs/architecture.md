# Architecture

The POC is one resource group. An engineer can delete that group and redeploy it. Sentinel content that must exist before an automation rule can call a playbook is a second deployment in the same group. See [deployment.md](deployment.md).

## Test rig versus the customer's WAF

`wafProvider` is `ApplicationGateway` or `FrontDoor`.

| | Application Gateway (default) | Front Door |
| --- | --- | --- |
| Created by this repo | Yes, when `deployTestWaf` is true | No |
| Policy type | `Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies` | `Microsoft.Network/frontDoorWebApplicationFirewallPolicies` |
| ARM api-version used by the playbook | `2024-05-01` | `2024-02-01` |
| Diagnostics configured here | Dedicated, category `ApplicationGatewayFirewallLog` | Not configured. ASE must already send logs |
| Table the analytics rule queries | `AGWFirewallLogs` | Default: `AzureDiagnostics`. Optional: `AzureFrontDoorWebApplicationFirewallLog` |
| Why that table is safe to name | `logAnalyticsDestinationType = Dedicated` on that category writes `AGWFirewallLogs`. Without Dedicated, the same category lands in `AzureDiagnostics` | Microsoft’s Front Door WAF samples use `AzureDiagnostics` and category `FrontDoorWebApplicationFirewallLog`. This repo does not create a resource-specific setting, so it does not claim `AzureFrontDoorWebApplicationFirewallLog` unless `frontDoorLogDestination` is set to `ResourceSpecific` |
| Action values the query accepts | `Blocked`, `Detected` | `Block`, `Log` |
| Block-rule JSON | `customRules[]`, `matchVariables[].variableName`, `matchValues`, `state` | `customRules.rules[]`, `matchVariable`, `matchValue`, `enabledState`, plus `sku` echoed from GET |

The KQL files are selected at deploy time in `infra/modules/sentinel.bicep`. Replacing the WAF product is a parameter and a policy resource id, not a rewrite of the incident path. The function branches on `wafProvider` and will not PUT when that value is anything else.

The Sentinel module waits for the test-rig module, which creates the Dedicated diagnostic setting, before the analytics rule that names `AGWFirewallLogs` is saved.

`deployTestWaf` is ignored unless the provider is Application Gateway. The deploy script rejects `FrontDoor` combined with the test rig so the two are not half-configured.

## Request path on the test rig

`scripts/test.ps1` sends `GET /?ase-poc-probe=1` to the gateway public IP on port 80.

The WAF policy is OWASP 3.2 plus one custom rule, `PocSimulatedProbe`, priority 50, match variable QueryString, operator Contains, value `ase-poc-probe`, action Block. No empty IPMatch rule is deployed. `SentinelAutoBlock` does not exist until the first opted-in playbook run.

The backend pool is `192.0.2.10`, a documentation address. In Prevention mode the probe rule is expected to answer 403 before that backend matters. Microsoft’s custom-rule documentation says Detection mode logs a custom block rule and does not enforce it, so a Detection-mode gateway is expected to pass the request and then fail at the dummy backend.

The gateway diagnostic setting enables `ApplicationGatewayFirewallLog` and `ApplicationGatewayAccessLog` with destination type Dedicated. Firewall rows are the detection source. Access logs are there so an operator can see the request if the firewall row is missing. The analytics rule does not read the access log.

## Detection

The scheduled rule is named **ASE POC - simulated WAF probe**. Its resource name is `guid('ase-waf-malicious-source-ip', workspace.id)` so a redeploy updates the same rule.

The query keeps a row when all of the following are true:

- The row is in the observation window (`queryLookbackMinutes`, also applied as the rule period).
- Application Gateway: `Action` is `Blocked` or `Detected`. Front Door: `Action` is `Block` or `Log`.
- The rule name is not `SentinelAutoBlock`.
- The rule name is `PocSimulatedProbe`, or the request URI contains `ase-poc-probe`.
- The client value is a non-empty dotted IPv4 address. The query uses the IPv4 range functions only.
- Unless `overrideProtectedRanges` is true: the address is not private, not inside the built-in ranges, and not inside watchlist `AseWafIpAllowlist`.

The summary is one row per client IP. Projected string columns are `ClientIp`, `EventCountText`, `RuleIdList`, `MessageList`, `RequestUriList`, `HostnameList`, `ActionList`, `FirstSeenText`, `LastSeenText`, and `ProbeMarkerText`. Sentinel custom details have to be strings. The IP entity mapping uses `ClientIp`.

The alert title is `ASE POC simulated WAF probe from {{ClientIp}}`. The description uses three placeholders, which is the Sentinel maximum: the event count, the client IP, and the action list. Rule ids, requests, hosts, and timestamps stay on the custom details.

Threshold and the observation window are parameters. The rule trigger is `GreaterThan 0` because the KQL already applies the threshold. Frequency cannot be below 5 minutes.

Incidents group on the IP entity for 12 hours. That lookback is separate from the observation window. The rule does not close incidents.

Tokens in the KQL files are replaced by Bicep `replace()` for the threshold, window, block rule name, probe rule name, probe marker, watchlist alias, and the override flag. The override flag is substituted as the bare KQL booleans `true` or `false`.

## Playbook

The deployed playbook is a Consumption Logic App, system-assigned managed identity, definition in `playbooks/block-malicious-ip/thin-workflow.json`. `workflow.json` in the same folder is the previous expression implementation. Deploy does not load it.

The Sentinel connection uses `parameterValueType: Alternative` and `ManagedServiceIdentity`. Bicep warns BCP187 on `kind` and BCP037 on `parameterValueType`. Those properties are required for this connection and are kept.

Trigger path: `/incident-creation`. The Logic App calls `Entities - Get IPs`, selects each `Address`, and POSTs once to `/api/SentinelWafAutoBlock`. The HTTP action does not retry and times out at two minutes. A successful response already includes the incident comment, so the Logic App does not write a second one. If the entity call or the function call fails, the Logic App comments and does not claim the address was blocked.

The Python function owns validation, the WAF read, dry-run, and the PUT. `autoBlockEnabled` is a Function App setting. The deployed default is the JSON boolean `true`. Only that JSON boolean sends a PUT. A missing setting stays dry-run. The contract is in `function-app/README.md`.

The function runs on Flex Consumption (`FC1`), Python 3.11, with a system-assigned managed identity. In `eastus` this subscription has no quota for Y1, Basic, Standard, Premium v3, or Elastic Premium. Flex bills for executions. The scale cap is 40 instances, which is the documented minimum for that cap. `scripts/deploy.ps1` publishes the zip after the main template and then binds the function key. The key is not printed. The main template first deploys the playbook with an empty key, so a run during that window stops before a block decision.

Application Insights is a workspace-based component on the same Log Analytics workspace. The function settings are `APPLICATIONINSIGHTS_CONNECTION_STRING` and `APPLICATIONINSIGHTS_AUTHENTICATION_STRING=Authorization=AAD`. The connection string is not printed. Invocation logs are `AppRequests` and `AppTraces` in that workspace. `host.json` turns sampling off.

This subscription's storage policies force `publicNetworkAccess` to Disabled and shared-key access off unless the account is tagged `SecurityControl=Ignore`. That tag is set only on the function storage account. Public network access stays enabled so Flex can reach the blob container without a private endpoint. Shared-key access stays enabled because Flex package upload uses the account key. The function runtime still uses its managed identity for host storage. Anonymous blob access stays disabled. The account key is not written to the repository.

## Identity and RBAC

| Principal | Role | Scope |
| --- | --- | --- |
| Playbook managed identity | Microsoft Sentinel Responder `3e150937-b8fe-4cfb-8069-0eaf05ecd056` | POC resource group, so it can read IP entities and comment when the function call does not finish |
| Function managed identity | Microsoft Sentinel Responder `3e150937-b8fe-4cfb-8069-0eaf05ecd056` | POC resource group, so it can comment on the incident after a decision |
| Function managed identity | Network Contributor `4d97b98b-1d4f-4787-a291-c67834d212e7` | The one WAF policy resource |
| Function managed identity | Storage Blob Data Owner, Storage Queue Data Contributor, Storage Table Data Contributor | The function storage account |
| Function managed identity | Monitoring Metrics Publisher `3913510d-42f4-4e42-8a64-420c390055eb` | The Application Insights component |
| Azure Security Insights service principal | Microsoft Sentinel Automation Contributor `f4c81013-99ee-4d62-a7ee-b3f1f648599a` | POC resource group, so the automation rule can start the playbook |

No user OAuth token is stored in source. The function reaches its storage account with managed identity, not an account key. The function key is created at deploy time and is not printed. The automation-rule role assignment name is `guid(resourceGroup, principalId, roleId)`. The automation rule name is `guid('ase-waf-block-playbook', workspace.id)`.

Network Contributor can change more than the custom-rule list. That gap is recorded in [security-considerations.md](security-considerations.md) and [production-hardening.md](production-hardening.md). A custom role definition was not added, because its exact action set should be confirmed against the policy type ASE uses.

## What is out of scope

- Production ASE WAF, Front Door, or an existing workspace. The questions in the README stay open.
- Microsoft Sentinel Content Hub solution for WAF. Those workbooks often assume `AzureDiagnostics`.
- Private Link, TLS, a real backend, zones, an NSG, and customer-managed keys.
- Automatic expiry, unblock, or an approval action inside the automation rule.
- Blocking text that is not a canonical IPv4 address. The function rejects it. The test gateway frontend is IPv4.
- Rewriting match values already stored on the named rule. Those strings are copied back unchanged.
