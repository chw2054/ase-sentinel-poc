# Security considerations

The operations web app changes a WAF policy when the effective block flag is the JSON boolean `true`. `AUTO_BLOCK_ENABLED` on the web app is that flag. The playbook sends `execution=awaiting-approval` and, after approval, `execution=approved`. `execution=approved` writes for that call even when the app setting is `false`. `execution=awaiting-approval` does not write. `dry-run` and `enforce` are rejected. The template parameter `autoBlockEnabled` is a deployment output and does not set the web app. The strings `True` and `False` are rejected.

## Identity

The playbook and the operations web app each use a system-assigned managed identity. The Sentinel API connection is `ManagedServiceIdentity` with `parameterValueType` Alternative. There is no user OAuth token in source.

The playbook identity can read incident entities and write a comment when the block API call does not finish. It does not have Network Contributor. The web app identity can comment on incidents in the POC resource group (Sentinel Responder) and can write the single WAF policy (Network Contributor). That policy assignment already exists on the live web app. `infra/main.bicep` does not grant it. Neither identity is a subscription Owner or a contributor on the resource group.

Network Contributor is broader than updating one custom rule. A holder of the web app identity can change other properties of that policy, including managed rules, if the code is changed later. The web app PUTs `policySettings`, `customRules`, and `managedRules` echoed from the GET, plus the block rule. It does not grant itself more roles.

The playbook secure parameter `functionKey` holds the web app setting `BLOCK_API_KEY`. The workflow parameter name stays `functionKey`. `deploy.ps1` does not print it and does not set it. There is no Function App and no Flex package upload in the template. Do not run `deploy.ps1` against the live resource group. The main template redeploys the playbook with an empty `functionKey`.

The Azure Security Insights service principal is granted Microsoft Sentinel Automation Contributor on the POC resource group so an automation rule can start the playbook. That is the role Microsoft requires for `RunPlaybook`. It is not granted on other resource groups by this template.

## What cannot be blocked by default

The analytics rule and the playbook both refuse, unless `overrideProtectedRanges` is explicitly set:

- `0.0.0.0/8`
- RFC1918: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`
- Loopback `127.0.0.0/8`
- Link-local `169.254.0.0/16`, which includes the instance metadata address `169.254.169.254`
- `100.64.0.0/10`

The rule also applies watchlist `AseWafIpAllowlist`. The web app applies `protectedIpRanges` from its app settings and does not read that watchlist. Built-in ranges are hard-coded in the KQL and in the web app, so a watchlist edit cannot remove them.

`overrideProtectedRanges` skips those filters in both places. The deploy script will not set it without `-ConfirmOverrideProtectedRanges`. Empty values and non-canonical addresses are still rejected. They are not written into `IPMatch` or Front Door `matchValue`.

Customer ranges the web app cannot parse fail the run before any block decision, including the dry-run sentence. The deploy script rejects those ranges first. The web app check remains so a later app-setting edit cannot silently ignore a prefix such as `/12`.

## Dry-run and opt-in

The web app sends a PUT only when the effective flag is the JSON boolean `true`. The string `"true"` stays `awaiting-approval` when `execution` is omitted and does not write. That call still GETs the policy so it can avoid saying "Would block" for an address that is already listed. GET does not modify the policy. An incident with no canonical IPv4 address does not GET. The web app rejects those values and does not change the policy.

Duplicates are removed before a write. A second incident for an address already on a SentinelAutoBlock rule does not PUT. One custom rule holds 600 match values. When that rule would exceed 600, the engine selects the next SentinelAutoBlock rule on the same policy. When the new batch itself exceeds 600, the policy already has 100 custom rules, or priorities 1–100 are full, the result is `capacity-exceeded` and nothing is written.

The automation rule starts the playbook and does not itself approve a block. The playbook waits for an Office 365 approval before it sends `execution=approved`. Keep `AUTO_BLOCK_ENABLED` false on the web app unless a request is supposed to write when `execution` is omitted.

## Evidence

Each terminal path comments on the incident: incident number, title, decision, rejected addresses, policy id, and the Logic App run name. Alert custom details carry the request, rule, action, and timestamps from the WAF row. Playbook runtime logs go to the same workspace.

The WAF rule itself does not store a reason. If the incident is closed and deleted, or the resource group is deleted, that comment is gone. Export it before cleanup when the record has to be kept. Workspace retention defaults to 30 days.

A failed PUT tells the operator not to assume the address was blocked. The PUT is not retried, because a timeout after a successful write must not be followed by a second write from the same action. The operator reads the policy before resubmitting.

## Integrity of the policy write

The PUT replaces the custom-rule collection with "every existing rule except the block rule, plus the new block rule". A bug in provider selection could send the wrong JSON shape. The intended result is an ARM validation error and the failure comment. Do not point `wafProvider` at a policy of the other type to find out. The deploy script checks the resource-id type when a full id is supplied.

There is no `If-Match` etag. Two writers can lose an update. This matters if an operator edits the same policy while a playbook run is in flight.

The block rule uses action Block. On Application Gateway that action is enforced in Prevention mode. In Detection mode Microsoft documents that the custom rule is logged and not enforced. Opting in while the policy is in Detection mode can still write the IP onto the rule. It should not be described as blocking traffic until the policy mode enforces it.

## Test rig exposure

The test gateway has a public IPv4 address and an HTTP listener. The backend is not a real application. The listener is still on the internet and the gateway is billed. Delete the resource group when the test is finished.

No customer data and no production WAF is required to run the default path. Attaching the playbook to an existing policy is a separate, explicit parameter set and should be a disposable policy until ASE names the real target.

## Secrets

Source, parameter files, and scripts do not contain keys, passwords, or connection strings. `.gitignore` excludes local ARM build output. Do not add a service principal secret to make the deploy script non-interactive. Use the Azure CLI login you already have.
