# Block malicious IP playbook

`playbookMode` chooses the definition. The default is `thin`.

`thin` deploys `thin-workflow.json` through `infra/modules/playbook.bicep`. Bicep passes workflow parameters `functionUrl` and `functionKey`. Those names stay. The URL is the operations web app and the key is `BLOCK_API_KEY`. The playbook does not validate addresses and it does not PUT the WAF policy. The web app does that work. `AUTO_BLOCK_ENABLED` on the web app stays the JSON boolean `false` for this POC. The first call sends `execution=awaiting-approval` and does not write. After Approve, the second call sends `execution=approved`.

`full` deploys `workflow.json` through `infra/modules/playbook-full.bicep`. That Logic App validates addresses, reads the WAF policy, comments, and PUTs when `autoBlockEnabled` is true. It does not call the web app, does not send the Office 365 approval email, and does not send a Teams card. Each custom rule holds 600 match values. A full rule opens the next `SentinelAutoBlock-<n>` rule on the same policy. A new batch larger than 600, a policy that already has 100 custom rules, or no free priority from 1 to 100 is refused and does not PUT. `-PlaybookMode full -AutoBlockEnabled $true` requires `-ConfirmAutoBlock` because that combination writes with no approval email. `-AutoBlockEnabled $false` comments and does not PUT.

The web app accepts an IPv4 host, or a customer prefix of `/8`, `/16`, `/24`, or `/32`. Any other incident value is rejected and is not written to the WAF rule. A customer prefix the service cannot compare stops the run before any would-block line.

Both identities need Microsoft Sentinel Responder on the workspace resource group. The thin playbook does not get Network Contributor. `scripts/deploy.ps1` removes that role after a thin deploy and grants it on the one WAF policy after a full deploy. The template itself does not grant it. The web app identity still needs that role for the thin path. The header `x-functions-key` must match the web app setting `BLOCK_API_KEY` on the thin path only.

`workflow.json` uses `json('[]')` for empty arrays. `createArray()` with no arguments is rejected by the Logic Apps runtime. The web app builds those lists in code instead.

The Application Gateway match condition uses the ARM property `negationConditon`. That spelling is what API version `2024-05-01` accepts. `negationCondition` makes the policy PUT return InvalidJson. Front Door uses `negateCondition`. The web app keeps that spelling.
