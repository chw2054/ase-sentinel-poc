# Testing

The test is a repeatable GET. It does not depend on malicious traffic. Default `autoBlockEnabled` is true, so a successful run PUTs the address onto `SentinelAutoBlock` and comments `Blocked IP: <address>`.

## Before you start

- Deploy with `scripts/deploy.ps1` and wait until the public IP is present.
- Leave `wafMode` at `Prevention` if you want HTTP 403. Detection mode is not expected to enforce the custom block rule.
- Leave `autoBlockEnabled` at its default `true` when the goal is to block the probe address. Pass `-AutoBlockEnabled $false` when the goal is a dry-run comment and an unchanged policy.
- The analytics threshold default is 3. Send at least that many requests.

## Steps

1. **Generate controlled traffic.**

   ```powershell
   ./scripts/test.ps1 -Target http://<public-ip>/ -Count 5
   ```

   Each request is `GET /?ase-poc-probe=1`. The script prints the status code. It does not send SQL injection, XSS, or path traversal payloads.

2. **WAF processes the traffic.** On the test rig in Prevention mode, expect HTTP 403 for every request. The custom rule is `PocSimulatedProbe`. A 502 means the request reached the dummy backend `192.0.2.10`, so the probe rule did not block it.

3. **Log appears in Log Analytics.** In the Sentinel Logs blade, run `sentinel/queries/verify-application-gateway.kql`. Rows come from `AGWFirewallLogs`, which the Dedicated diagnostic setting writes. Ingestion can lag a few minutes. The optional `-WorkspaceId` and `-WaitSeconds` switches on `test.ps1` run that file through Azure CLI. A short wait often returns no rows even when the gateway returned 403.

   Front Door verification files are `verify-front-door-azurediagnostics.kql` and `verify-front-door-resource-specific.kql`. This POC does not generate those rows. Use them only after ASE has pointed Front Door diagnostics at the workspace.

4. **KQL identifies the source.** The verification query projects `ClientIp`, `Action`, `RuleId` or the Front Door rule name, the request, and the timestamp. The deployed analytics query is the matching file under `sentinel/analytics-rules/` with its tokens replaced. Operator verification files are not edited by the deployment.

   `scripts/test-ip-ranges.ps1` checks the deploy-time parser. It does not run KQL.

5. **Sentinel creates an alert and an incident.** Allow the rule period. With a 5 minute schedule this is usually 10 to 15 minutes after the log row exists. Incident title: `ASE POC simulated WAF probe from <ip>`. Severity Medium. The IP is an entity. Custom details include the action, rule, request, host, and the first and last timestamps.

6. **The automation rule triggers.** The incident is Active and labeled `poc-simulated-probe`. The rule runs only for this analytics rule, and only when the incident is created.

7. **The playbook receives the IP.** Open the Logic App run. `Entities - Get IPs` should list the same address as the incident entity, and `Call_block_function` should return the function JSON. The function writes the incident comment. The Logic App writes a comment only when that call does not finish.

8. **The default deploy blocks the address.** The incident comment contains `Blocked IP: <address>`. A failed PUT comment says not to assume the address was blocked. Read the policy before retrying. Confirm the rule:

   ```powershell
   az network application-gateway waf-policy custom-rule list `
     --resource-group rg-ase-sentinel-poc `
     --policy-name <policy-name>
   ```

   `PocSimulatedProbe` is present. `SentinelAutoBlock` contains the probe address after a successful PUT.

9. **Optional dry-run.** Redeploy with `-AutoBlockEnabled $false`. Send the probe again from a different public IP. The comment contains `Would block IP: <address>` and the policy is not changed. An address that is already listed does not get a Would-block line.

10. **Subsequent validation.** After a successful PUT, show the rule and confirm `matchValues` (Application Gateway) or `matchValue` (Front Door) contains that IP once. Send the probe again from the same IP. The gateway should still return 403, now from `SentinelAutoBlock` at priority 10, and the playbook should comment that the address is already listed rather than adding a duplicate. A client inside `10.0.0.0/8`, `127.0.0.0/8`, `169.254.169.254`, or a configured `protectedIpRanges` entry should be listed as rejected and must not appear on the rule.

## What a dry-run comment contains

- Incident number and title
- The line `Would block IP: <address>`
- Provider, policy resource id, and the rule that would be updated
- The list size that would result, and `maximumBlockEntries`
- Rejected addresses and the reason
- The Logic App run name

An address that fails validation does not get a "Would block" line. An address already on the rule does not get one either.

## What this test does not prove

- That the marker is malicious. It is not.
- That Front Door logging works. This repo does not configure it.
- That Detection mode blocks. Microsoft documents that it does not enforce a custom block rule.
- A production change window, approval, or rollback owner. Those are open questions for ASE.
