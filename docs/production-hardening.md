# Production hardening

Items below are recommendations for a later design. They are not implemented in this POC, and they are not assumptions about ASE's environment. Confirm the open questions in the README before treating any of them as a build task.

## Decide the product and the workspace first

- Confirm Application Gateway WAF versus Front Door WAF, and which diagnostic categories are already enabled.
- Point the playbook at the confirmed policy resource id. Do not create a second WAF in production to host this test.
- If the production logs are `AzureDiagnostics` rather than `AGWFirewallLogs`, deploy the Front Door or legacy diagnostic query that matches the rows you can already see. Do not switch table names without a sample row.
- Keep the simulated-probe rule out of production, or restrict it to a non-production listener. A production analytics rule needs a pattern ASE has agreed, with its own threshold and window.

## Replace dry-run with an approval, not with an always-on PUT

This POC uses `autoBlockEnabled` as the only gate. A production automation rule should require an analyst action, or a separate approved playbook, before `autoBlockEnabled` is true. Record who approved the change on the incident. The current automation rule labels the incident and starts the playbook immediately. The playbook forwards the incident to the Function App.

## Narrow the write permission

Network Contributor on the policy is a POC shortcut. Replace it with a custom role that can read the policy and write custom rules, and nothing else, after the action list is confirmed for the policy type. Keep the assignment on the one policy resource, not the resource group.

## Make the block list operable

- Alert when the playbook run fails, when the list reaches `maximumBlockEntries`, and when a PUT succeeds.
- Store the incident id, address, rule, and time somewhere that survives incident deletion if ASE's retention question requires that. The incident comment is the only evidence store in this POC.
- Define who may remove an address, the maximum age of an entry, and whether removal is another reviewed change. This repo has no expiry job.
- Put `If-Match` on the PUT, or use a patch API if the policy type provides one, so a portal edit is not overwritten.
- Page on a sudden increase in blocked addresses. One rule with a long IP list is the POC shape. A production design may need a different control (Front Door rule limits, a WAF custom rule per change window, or a network deny list ASE already operates).

## Protect the ranges ASE names

Pass ASE's management and egress ranges in `protectedIpRanges`. Keep the built-in private, loopback, link-local, metadata, and CGNAT checks. Do not enable `overrideProtectedRanges` to "make the test work" from an office network. Add the office egress prefix to the protected list, or run the probe from a public test host that is allowed to be listed.

The function can evaluate an IPv4 host or `/8`, `/16`, `/24`, and `/32`. A production matcher has to honor the prefixes ASE actually uses, including `/12` if they put it in the customer list rather than relying on the built-in RFC1918 check. This POC rejects any value that contains `:`.

## Hardening the test shortcuts that must not ship

| POC choice | Production direction |
| --- | --- |
| HTTP/80 and no TLS | The customer's existing listener and certificate |
| Backend `192.0.2.10` | Do not deploy this gateway at all |
| No NSG, no zones, public ingestion and query | The customer's network baseline |
| 30 day retention and no daily cap | The customer's retention and cost controls |
| WAF_v2 min 1 / max 2 | Not a sizing recommendation |
| Consumption Logic App | The hosting model ASE operates, with run-failure alerts |
| OWASP 3.2 copied onto a new policy | Do not replace an existing managed-rule set |
| Content Hub WAF solution not installed | Add it only if its workbooks match the log schema you use |
| Display-name lookup for Azure Security Insights | Pin the application id ASE's tenant actually has, if it differs |
| 30 second RBAC wait | Retry the automation-rule deployment until the role replicates |

## Detection

Keep the statement that a rule matches a configured pattern. Do not describe the incident as attribution. Set severity, grouping, and the observation window with ASE. Exclude the remediation rule from the detection so enforcement cannot create another incident. Re-test that exclusion after the first real block, because a higher-priority block rule can stop the original rule from logging.

## Change control

Treat a flip of `autoBlockEnabled` as a change. Redeploy through the script. The default is true. Pass `-AutoBlockEnabled $false` to return to dry-run. Review the Logic App run and the policy diff after a blocking incident.
