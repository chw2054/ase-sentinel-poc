# Retired Function App

The block engine now lives in `webapp/sentinel_waf_block`. The operations app calls it in process, and the playbook posts `POST /api/SentinelWafAutoBlock` on the web app with header `x-functions-key`.

Do not publish this directory. `scripts/deploy.ps1` still contains the old Function App publish and a playbook redeploy. Running that script against the live resource group resets the Office 365 connection.
