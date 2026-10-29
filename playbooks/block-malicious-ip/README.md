# Block malicious IP playbook

Deployed Logic App definition: `thin-workflow.json`. Bicep passes the function URL and function key from `infra/modules/playbook.bicep`. `workflow.json` is the previous expression implementation and is not deployed.

The playbook is started by the Sentinel incident trigger. It reads IP entities and POSTs them to `POST /api/SentinelWafAutoBlock`. It does not validate addresses and it does not PUT the WAF policy. The Python function does that work. `AUTO_BLOCK_ENABLED` defaults to the JSON boolean `true` on the Function App. `false` is dry-run.

The function accepts an IPv4 host, or a customer prefix of `/8`, `/16`, `/24`, or `/32`. Any other incident value is rejected and is not written to the WAF rule. A customer prefix the function cannot compare stops the run before any would-block line.

The playbook identity needs Microsoft Sentinel Responder on the workspace resource group. The function identity needs that role and Network Contributor on the one WAF policy. Both assignments are in the Bicep modules.

`workflow.json` uses `json('[]')` for empty arrays. `createArray()` with no arguments is rejected by the Logic Apps runtime. The Python function builds those lists in code instead.

The Application Gateway match condition uses the ARM property `negationConditon`. That spelling is what API version `2024-05-01` accepts. `negationCondition` makes the policy PUT return InvalidJson. Front Door uses `negateCondition`. The function keeps that spelling.
