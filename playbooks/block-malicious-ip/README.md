# Block malicious IP playbook

Deployed Logic App definition: `thin-workflow.json`. Bicep passes workflow parameters `functionUrl` and `functionKey`. Those names stay. The URL is the operations web app and the key is `BLOCK_API_KEY`. `workflow.json` is the previous expression implementation and is not deployed.

The playbook is started by the Sentinel incident trigger. It reads IP entities and POSTs them to the operations web app at `POST /api/SentinelWafAutoBlock`. It does not validate addresses and it does not PUT the WAF policy. The web app does that work. `AUTO_BLOCK_ENABLED` on the web app stays the JSON boolean `false` for this POC, so the first call is a dry-run unless the body sets `execution` to `enforce`.

The web app accepts an IPv4 host, or a customer prefix of `/8`, `/16`, `/24`, or `/32`. Any other incident value is rejected and is not written to the WAF rule. A customer prefix the service cannot compare stops the run before any would-block line.

The playbook identity needs Microsoft Sentinel Responder on the workspace resource group. The web app identity needs that role and Network Contributor on the one WAF policy. The header `x-functions-key` must match the web app setting `BLOCK_API_KEY`.

`workflow.json` uses `json('[]')` for empty arrays. `createArray()` with no arguments is rejected by the Logic Apps runtime. The web app builds those lists in code instead.

The Application Gateway match condition uses the ARM property `negationConditon`. That spelling is what API version `2024-05-01` accepts. `negationCondition` makes the policy PUT return InvalidJson. Front Door uses `negateCondition`. The web app keeps that spelling.
