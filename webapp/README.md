# ASE Sentinel operations Web App

The operations app reads open Sentinel incidents and one Application Gateway WAF policy. It does not open a database. Starting it requires `AZURE_SUBSCRIPTION_ID`, `AZURE_RESOURCE_GROUP`, `SENTINEL_WORKSPACE_NAME`, `WAF_POLICY_RESOURCE_ID`, and `BLOCK_API_KEY`.

```text
cd webapp
python -m venv .venv
.venv\Scripts\python -m pip install -r requirements.txt
.venv\Scripts\python -m pytest
```

Pages list open Sentinel incidents and the custom rules on `WAF_POLICY_RESOURCE_ID` whose names are `BLOCK_RULE_NAME` or `BLOCK_RULE_NAME-<number>`. Each of those rules holds 600 addresses. The Application Gateway bound to that policy applies every rule, so an address on any of them is blocked. Block, add, and remove call `sentinel_waf_block` in this process with `execution=enforce`. That write goes to one rule still below 600. When every rule is full, the engine creates the next rule on the same policy. Don't block closes the incident with a comment. The block list page can add or remove one IP or CIDR. The page shows the Sentinel workspace name, the WAF policy name, each block list rule, and the Application Gateway URL. `POC_ADMIN_USERS` is the Entra sign-in that may decide.

`POST /api/SentinelWafAutoBlock` is the playbook entry. Easy Auth excludes that path. The caller sends `x-functions-key` equal to `BLOCK_API_KEY`. The body is the same incident JSON, or `operation` `add` or `remove` with one `address`. `execution` is `dry-run`, `enforce`, or omitted. `AUTO_BLOCK_ENABLED` stays the JSON boolean `false` unless a request sets `execution` to `enforce`. The web app identity needs Network Contributor on the WAF policy, Microsoft Sentinel Responder on the resource group, and the Teams notifier settings `NOTIFY_TEAMS_URL`, `NOTIFY_TEAMS_AUTH`, and `NOTIFY_EVENTS`.

`APP_ENV=local` can use the password form. Any other `APP_ENV` rejects `DEV_LOGIN_PASSWORD`. Production sign-in is Entra ID.
