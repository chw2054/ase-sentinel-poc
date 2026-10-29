# ASE Sentinel operations Web App

Local control plane for incident intake, approval, and the Application Gateway block list. The default WAF is an in-memory fixture seeded with the four addresses observed on 29 October 2026. Starting this app does not call Azure.

See `docs/current-state.md` for the system this replaces as a control plane, and `docs/webapp-migration.md` for how to run it and how a later cutover stays away from the live playbook deploy.

```text
cd webapp
python -m venv .venv
.venv\Scripts\python -m pip install -r requirements.txt
.venv\Scripts\python -m uvicorn app.main:app --app-dir .
.venv\Scripts\python -m pytest
```

`LIVE_AZURE=true` is the deployed operations app. It lists open Sentinel incidents and the custom rules on `WAF_POLICY_RESOURCE_ID` whose names are `BLOCK_RULE_NAME` or `BLOCK_RULE_NAME-<number>`. Each of those rules holds 600 addresses. The Application Gateway bound to that policy applies every rule, so an address on any of them is blocked. Block, add, and remove call `sentinel_waf_block` in this process with `execution=enforce`. That write goes to one rule still below 600. When every rule is full, the engine creates the next rule on the same policy. Don't block closes the incident with a comment. The app does not open `DATABASE_URL`. Required settings are `AZURE_SUBSCRIPTION_ID`, `AZURE_RESOURCE_GROUP`, `SENTINEL_WORKSPACE_NAME`, `WAF_POLICY_RESOURCE_ID`, and `BLOCK_API_KEY`. The block list page can add or remove one IP or CIDR. The page shows the Sentinel workspace name, the WAF policy name, each block list rule, and the Application Gateway URL. `POC_ADMIN_USERS` is the Entra sign-in that may decide.

`POST /api/SentinelWafAutoBlock` is the playbook entry. Easy Auth excludes that path. The caller sends `x-functions-key` equal to `BLOCK_API_KEY`. The body is the same incident JSON, or `operation` `add` or `remove` with one `address`. `execution` is `dry-run`, `enforce`, or omitted. `AUTO_BLOCK_ENABLED` stays the JSON boolean `false` unless a request sets `execution` to `enforce`. The web app identity needs Network Contributor on the WAF policy, Microsoft Sentinel Responder on the resource group, and the Teams notifier settings `NOTIFY_TEAMS_URL`, `NOTIFY_TEAMS_AUTH`, and `NOTIFY_EVENTS`.

Without `LIVE_AZURE`, production still requires `APP_ENV=production`, an Azure SQL `DATABASE_URL`, `APP_SECRET`, and `INTEGRATION_API_KEY`. The local password form is disabled outside local mode.
