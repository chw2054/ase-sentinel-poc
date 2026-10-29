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

`LIVE_AZURE=true` is the deployed operations app. It lists open Sentinel incidents and every WAF policy tagged `BLOCK_POLICY_TAG=true` (default key `ase-sentinel-block-list`), plus the configured policy. Each policy holds 600 addresses. Block posts the existing function with `execution=enforce`. The function fills the configured policy and then another tagged policy that still has room. Don't block closes the incident with a comment. The app does not open `DATABASE_URL`. Required settings are `AZURE_SUBSCRIPTION_ID`, `AZURE_RESOURCE_GROUP`, `SENTINEL_WORKSPACE_NAME`, `WAF_POLICY_RESOURCE_ID`, `BLOCK_FUNCTION_URL`, and `BLOCK_FUNCTION_KEY`. The page shows the Sentinel workspace name, each WAF policy name, and the Application Gateway URL. `POC_ADMIN_USERS` is the Entra sign-in that may decide.

Without `LIVE_AZURE`, production still requires `APP_ENV=production`, an Azure SQL `DATABASE_URL`, `APP_SECRET`, and `INTEGRATION_API_KEY`. The local password form is disabled outside local mode.
