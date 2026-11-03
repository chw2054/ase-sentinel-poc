# ASE Microsoft Sentinel 部署與操作指南

## 1. 部署概觀

### 1.1 目的與範圍

本指南說明如何理解、驗證與操作已經在 `rg-ase-sentinel-poc` 的 POC，以及哪些步驟**不能**照現有腳本重做。它不指示執行部署。`scripts/deploy.ps1` 檔頭寫明：不要對這個資源群組執行該腳本，主範本會重新部署 playbook，並可能清掉 Office 365 連接器授權。

### 1.2 目標環境假設

| 項目 | 本次看到的值 |
| --- | --- |
| 訂用帳戶 | `ME-MngEnvMCAP591832-v-henchang-1`（`ae4654a2-8a96-431c-ad3d-176ae51ec9d8`） |
| 租用戶 | 操作時必須讓 Azure CLI 落在這個訂用帳戶。檢視開始時 CLI 預設在另一個訂用帳戶，資源群組會回 `ResourceGroupNotFound` |
| 資源群組 | `rg-ase-sentinel-poc` |
| 偵測與封鎖區域 | eastus |
| 作業 Web App 區域 | centralus |
| 分支 | `feature/laptop-sentinel-ops`，commit `7a291a6` |

### 1.3 支援與不支援

支援並已在線上的拓撲：Application Gateway 測試 WAF、Sentinel、Logic App、作業 Web App 上的 `POST /api/SentinelWafAutoBlock`。

不支援由本儲存庫建立：

- Front Door 本體與 Front Door 診斷設定。`scripts/deploy.ps1` 在 `DeployTestWaf` 與 Front Door 同時為真時會丟出錯誤。
- 以 `scripts/deploy.ps1` 重新發布封鎖引擎或重建現有 playbook。腳本不再複製 Function 檔案，但仍會重布 playbook，並把 `functionKey` 留空。

`infra/modules/webapp.bicep` 沒有被 `infra/main.bicep` 引用。線上 Web App 是既有資源，不是這次文件撰寫時由該 Bicep 模組證明出來的部署。

### 1.4 必要服務

Microsoft Sentinel、Log Analytics、Application Gateway WAF_v2、Logic Apps、App Service、Entra ID、Office 365 連接器、Teams Workflows。作業 Web App 不使用資料庫。Azure SQL 已於 2026-11-02 從資源群組刪除。

## 2. 先決條件

### 2.1 權限

建立新環境時，`scripts/deploy.ps1` 與 `README.md` 要求能建立資源群組、角色指派與 Sentinel，並能把 Microsoft Sentinel Automation Contributor 指給 **Azure Security Insights** 服務主體。腳本以顯示名稱精確比對該主體。比對失敗時，腳本註明可在 Sentinel 可用之後用 `-AutomationRuleOnly` 重跑。`-AutomationRuleOnly` 仍然會走後段部署，不應在未閱讀腳本的情況下對現有 POC 執行。

操作現有 POC 至少需要：

- 讀取資源群組、WAF 政策、Logic App、Web App 設定的權限。
- 若要核准：`approverEmail` 所代表的信箱。程式預設與多份文件使用 `admin@mngenvmcap591832.onmicrosoft.com`。線上 `APPROVER_EMAIL` 已設定，本次未核對是否仍是這個地址。
- 若要改政策：Web App 受控識別需要目標政策的寫入權。本次未重讀角色指派，標為待確認。

### 2.2 工具

- Azure CLI。本次讀取使用已登入的 CLI。Logic 延伸模組沒有安裝；`az logic workflow show` 會要求互動安裝，因此 playbook 改由 ARM REST 讀取。
- PowerShell 7。`scripts/deploy.ps1` 與 `scripts/test.ps1` 都要求 7.0。
- 引擎執行期：線上站點 `PYTHON|3.11`，gunicorn 加 uvicorn worker。
- 本機測試使用 `webapp` 的 pytest。本次文件撰寫沒有重跑測試，所以不把「測試通過」寫成結果。

### 2.3 連接器

- Sentinel 連接器：`azuresentinel-playbook-ase-sentinel-poc-block-malicious-ip`。Bicep 設 `parameterValueType` 為 `Alternative`，驗證使用受控識別。
- Office 365 連接器：`office365-playbook-ase-sentinel-poc-block-malicious-ip`。必須由核准人在入口網站授權。沒有授權時，核准動作會失敗，playbook 應寫未核准註解且不 PUT。授權是否仍然有效，待確認。

### 2.4 不要做的事

不要執行 `scripts/deploy.ps1` 來「對齊文件」。不要把 `DeployTestWaf` 設為 true 去重布 `wafpol-ase-sentinel-poc`。不要刪除資源群組。不要用 Complete 模式部署。

## 3. 資源清單

| 資源 | Azure 類型 | 用途 | 相依 | 設定來源 |
| --- | --- | --- | --- | --- |
| `log-ase-sentinel-poc-7ttpll74bmhiq` | `Microsoft.OperationalInsights/workspaces` | 日誌與 Sentinel | 訂用帳戶 | `infra/modules/log-analytics.bicep`。線上名稱含後綴 `7ttpll74bmhiq`，與 `profiles/poc-approval.json` 的 `log-${namePrefix}-${unique}` 相符 |
| `SecurityInsights(...)` | `Microsoft.OperationsManagement/solutions` | 啟用 Sentinel | workspace | `infra/modules/sentinel.bicep` |
| `agw-ase-sentinel-poc` | `Microsoft.Network/applicationGateways` | 測試入口 | 公開 IP、VNet、WAF 政策 | `infra/modules/waf.bicep` |
| `pip-ase-sentinel-poc` | `Microsoft.Network/publicIPAddresses` | 前端 | 無 | 同上。IP 位址本次未重讀 |
| `wafpol-ase-sentinel-poc` | Application Gateway WAF policy | 探測與封鎖 | 被閘道引用。引用關係本次未重讀 | 同上。標籤含 `ase-sentinel-block-list=true` |
| `wafpol-ase-sentinel-poc-2` | Application Gateway WAF policy | 待確認 | 0 條自訂規則 | 標籤 `ManagedBy=manual`。儲存庫沒有建立它的步驟 |
| `vnet-ase-sentinel-poc` | Virtual Network | 閘道子網路 | NSG | `infra/modules/waf.bicep` |
| `playbook-ase-sentinel-poc-block-malicious-ip` | `Microsoft.Logic/workflows` | 編排 | Sentinel 觸發、Web App、兩個連接器 | `playbooks/block-malicious-ip/thin-workflow.json` 經 `infra/modules/playbook.bicep` |
| `azuresentinel-playbook-...` | `Microsoft.Web/connections` | Sentinel API | playbook 受控識別 | `infra/modules/playbook.bicep` |
| `office365-playbook-...` | `Microsoft.Web/connections` | 核准信 | 核准人授權 | 同上 |
| `app-ase-sentinel-poc-7ttpll74` | `Microsoft.Web/sites` | 引擎與作業頁面 | 政策的 RBAC、App Settings | 線上已存在。`infra/main.bicep` 不部署它 |
| `app-ase-sentinel-poc-7ttpll74-plan` | `Microsoft.Web/serverFarms` | 方案 | 無 | 同上。SKU 本次未重讀 |
| `appi-ase-sentinel-poc` | Application Insights | 遙測 | workspace | 範本不再建立。是否仍有資料源，待確認。增量部署不會刪除它 |
| `st7ttpll74bmhiq` | Storage | 舊 Function 支撐 | 無現行 Function | 範本不再建立。設定檔不再期望它。增量部署不會刪除它 |
| `vnet-app-ase-sentinel-poc-7ttpll74` | Virtual Network | Web App 的 VNet integration，子網路 `snet-app` | Web App | 2026-11-02 刪除 Azure SQL、私人端點、私人 DNS 與私人端子網路後仍保留。`infra/main.bicep` 不部署它 |
| `fn-ase-sentinel-poc-7ttpll74` | Function App | 舊進入點 | 不存在 | 範本已移除。線上資源不存在 |

分析規則與自動化規則是 workspace 子資源，不會出現在資源群組的一般 `az resource list` 結果。名稱期望值：

- 分析規則顯示名稱：`ASE POC - simulated WAF probe`（`profiles/poc-approval.json`）。
- 自動化規則顯示名稱：`ASE POC - run block playbook for simulated WAF probe`。

兩者本次都未重讀，標為待確認是否與 Bicep 一致。

## 4. 部署步驟與現況

下列每一步都先寫「現況」，再寫儲存庫裡的建立方式。沒有命令的步驟代表儲存庫沒有可安全重跑的自動化。

### 4.1 資源群組與主範本

- 目的：建立 workspace、Sentinel、測試 WAF、playbook 骨架。
- 現況：資源群組已存在。主範本不再建立 Function。
- 儲存庫命令形狀寫在 `README.md`：`./scripts/deploy.ps1 -ResourceGroupName rg-ase-sentinel-poc -Location eastus`。
- 預期：新資源群組會得到測試閘道與 playbook，不會得到 Function。對**現有**群組的預期是連接器被重置，且 playbook 的 `functionKey` 被清成空。
- 驗證：不要執行。若只做 what-if，腳本有 `-WhatIf`，且與 `-AutomationRuleOnly` 互斥。本次未執行 what-if。
- 常見問題：CLI 訂用帳戶錯了會找不到資源群組。

### 4.2 Log Analytics、診斷設定與 Sentinel

- 目的：`AGWFirewallLogs` 進入 workspace，再由排程分析規則開事件。
- 現況：workspace 與 Sentinel 方案在線上。診斷設定 `diag-waf-to-sentinel` 只出現在 `profiles/poc-approval.json` 的期望清單，本次未讀診斷設定本體。
- 參數預設：門檻 3、每 5 分鐘、回看 30 分鐘、標記 `ase-poc-probe`、分組 12 小時。來源是 `scripts/deploy.ps1` 與 `infra/modules/sentinel.bicep`。
- 驗證查詢檔：`sentinel/queries/verify-application-gateway.kql`。本次未對 workspace 執行。
- 常見問題：watchlist 尚未有 `IPAddress` 欄位時，若 KQL 直接點欄位，Sentinel 會拒絕規則。現行程式使用 `column_ifexists`。

### 4.3 分析規則與自動化規則

- 目的：達到門檻才開事件；只有 Created 才跑 playbook。
- 儲存庫：`sentinel/analytics-rules/simulated-probe.application-gateway.kql`、`sentinel/automation-rules/block-malicious-ip.bicep`。
- 現況：未重讀。部署自動化規則前，Azure Security Insights 需要 Automation Contributor。這是 Bicep 註解中的已知失敗模式。
- 驗證：在 Sentinel 打開顯示名稱如上的規則，確認 `triggersWhen` 為 Created，且條件含該分析規則資源 ID。

### 4.4 Playbook

- 目的：取 IP、dry-run、等候核准、必要時 enforce。
- 現況：Logic App Enabled，系統受控識別，URL 主機 `app-ase-sentinel-poc-7ttpll74.azurewebsites.net`，路徑 `/api/SentinelWafAutoBlock`，參數含 `functionKey`。
- 定義來源：`infra/modules/playbook.bicep` 載入 `thin-workflow.json`。
- 常見問題：重新部署 playbook 模組會碰到 Office 365 連接器。授權遺失時，核准步驟失敗，政策不應變更。失敗後要讀 run 與事件註解，不要只看 Logic App 最終狀態。失敗分支使用 `Terminate` 且 `runStatus` 為 Succeeded，所以 run 顯示成功不代表已封鎖。

### 4.5 封鎖 API

- 目的：驗證 IP、讀寫 WAF、寫註解、送 Teams。
- 現況：由 Web App 提供。`APP_ENV=production`，`LIVE_AZURE=true`，`AUTO_BLOCK_ENABLED=false`，`WAF_PROVIDER=ApplicationGateway`。儲存庫已不讀 `LIVE_AZURE`。線上設定仍留 `true`，因為目前部署的程式在重啟時還會讀它。
- 儲存庫沒有一條已核對過、可把 `webapp/` 發布到這個站點的腳本。`scripts/deploy.ps1` 不再發布 Function，也不發布這個 Web App。
- 發布缺口標為缺少自動化。在補上之前，變更引擎必須沿用當初發布 Web App 的程序，而該程序沒有寫進目前腳本。
- 驗證：`GET /health` 在程式中回 `liveAzure: true`。該路徑是否被 Easy Auth 排除，本次未測，所以不把 HTTP 200 寫成本次結果。

### 4.6 身分與 RBAC

- 目的：讓執行引擎的主體能讀寫目標政策、能對事件寫註解，並讓 Sentinel 能啟動 playbook。
- 現況：Function 主體已不在。Web App 與 playbook 的角色指派本次未讀，全部標為待確認。
- 設定檔中的角色 ID 見設計規格第 7 章。不要把設定檔當成線上已指派的證據。

### 4.7 核准連接器與 Teams

- Office 365：入口網站打開連接器，以核准人授權。沒有命令列可代替這一步。Bicep 已說明原因。
- Teams：`NOTIFY_TEAMS_URL` 已在 App Settings，`NOTIFY_TEAMS_AUTH=entra`。URL 不進部署範本，`deploy.ps1` 註明如此，以免留在部署歷史。值不要貼到工單或文件。
- 驗證：下一筆 dry-run 應產生 `awaiting-approval` 卡片，且 HTTP 狀態仍是 `dry-run`。本次沒有製造這一筆。

### 4.8 WAF 整合

- 目的：核准後的 PUT 只改自訂規則所需的政策內容，並保留 `policySettings` 與 `managedRules`。
- 現況：`wafpol-ase-sentinel-poc` 有 `SentinelAutoBlock` 與 `PocSimulatedProbe`。`wafpol-ase-sentinel-poc-2` 沒有自訂規則，也沒有封鎖清單標籤。
- 引擎只 PUT `WAF_POLICY_RESOURCE_ID`。不要假設第二份政策會自動跟著變。

### 4.9 部署後檢查清單

本次已核對的項目打勾。其餘留空，代表尚未在這次文件工作中重做。

- [x] 資源群組存在，訂用帳戶正確。
- [x] 主 WAF 政策 Prevention 且 Enabled。
- [x] `SentinelAutoBlock` 與 `PocSimulatedProbe` 都在，priority 分別是 10 與 50。
- [x] Playbook Enabled，URL 指向 Web App 的封鎖 API。
- [x] Web App Running，`LIVE_AZURE=true`，`AUTO_BLOCK_ENABLED=false`。
- [x] Function App 名稱已確認不存在。
- [ ] 診斷設定仍把防火牆日誌送到該 workspace。
- [ ] 分析規則啟用，門檻與 12 小時分組與參數檔一致。
- [ ] 自動化規則只在 Created 時啟動，且 Azure Security Insights 有 Automation Contributor。
- [ ] Office 365 連接器狀態為已連線。
- [ ] Web App 受控識別對主政策有寫入權、對資源群組有 Sentinel Responder。
- [ ] Easy Auth 排除 `/api/SentinelWafAutoBlock`，其餘頁面要登入。
- [ ] 一筆 dry-run 與一筆 Reject 不改變 match value 數量。

## 5. 設定參考

參數預設來自 `scripts/deploy.ps1`，除非另有註明。

| 參數或設定 | 預設或線上值 | 格式 | 機密 | 設定位置 |
| --- | --- | --- | --- | --- |
| `ResourceGroupName` | `rg-ase-sentinel-poc` | 資源群組名稱 | 否 | 腳本參數 |
| `Location` | `eastus` | 區域 | 否 | 腳本參數。不涵蓋 centralus 的 Web App |
| `WafProvider` | `ApplicationGateway` | 列舉 | 否 | 腳本與 `WAF_PROVIDER` |
| `WafMode` | `Prevention` | Prevention 或 Detection | 否 | 腳本。線上政策為 Prevention |
| `DeployTestWaf` | `true` | bool | 否 | 腳本。對現有政策不要設 true |
| `AutoBlockEnabled` | 腳本預設 `true`；線上 App Setting `false` | JSON boolean，不是字串 `True` | 否 | 腳本會寫 Function 設定。線上實際旗標在 Web App |
| `DetectionThreshold` | 3 | 1 到 100 | 否 | 腳本 |
| `QueryFrequencyMinutes` | 5 | 5 到 60，且不大於 lookback | 否 | 腳本 |
| `QueryLookbackMinutes` | 30 | 5 到 1440 | 否 | 腳本 |
| `ProbeMarker` | `ase-poc-probe` | 3 到 40 碼的英數與連字號 | 否 | 腳本與測試腳本 |
| `ProbeRuleName` / `ProbeRulePriority` | `PocSimulatedProbe` / 50 | 名稱與 1 到 100 | 否 | 腳本。線上 priority 50 |
| `BlockRuleName` / `BlockRulePriority` | `SentinelAutoBlock` / 10 | 同上 | 否 | 腳本與線上 |
| `MaximumBlockEntries` | 100 | 腳本允許 1 到 500 | 否 | 線上 App Setting 100。ARM 引擎單規則容量另以 600 計算 |
| `OverrideProtectedRanges` | `false` | JSON boolean | 否 | 線上亦為 false |
| `ProtectedIpRanges` | 腳本預設空陣列 | JSON 陣列。prefix 僅 8、16、24、32 | 可能含客戶網路 | 線上有設定，值未摘錄 |
| `ApproverEmail` | 腳本預設空字串，空字串會讓 playbook 停在評估前 | 電子郵件 | 個人資料 | playbook 參數與 `APPROVER_EMAIL` |
| `NotifyTeamsUrl` | 空字串則嘗試沿用舊設定 | `https://` URL | 是 | Web App `NOTIFY_TEAMS_URL` |
| `NotifyEvents` | 腳本預設 `blocked,put_failed,capacity` | 逗號分隔 | 否 | 線上實際為 `would_block,blocked,put_failed,capacity` |
| `BLOCK_API_KEY` | 無預設值可公開 | 共用祕密 | 是 | Web App 與 playbook `functionKey` |
| `LIVE_AZURE` | 線上 `true` | 儲存庫已不讀。線上舊程式仍讀 | 否 | 新程式發布前不要刪。刪了之後重啟會走已移除的 SQL 啟動檢查 |
| `APP_ENV` | 線上 `production` | 字串 | 否 | Web App。非 `local` 時拒絕 `DEV_LOGIN_PASSWORD`。不再要求資料庫 |

`execution` 不是 App Setting。它在每次 POST 的 JSON。`enforce` 只應出現在核准之後的第二次呼叫，或已授權的手動維護。

## 6. 端到端驗證

本次沒有發送探測、沒有按核准、也沒有重跑 pytest。下表的「證據」只列應該蒐集的東西，以及哪些項目已有程式或先前設計可對照。不要把本表當成測試報告。

| 測試 | 先決條件 | 步驟來源 | 預期 | 要留下的證據 | 回復 |
| --- | --- | --- | --- | --- | --- |
| 產生 WAF 事件 | 知道閘道前端位址。位址本次未重讀 | `scripts/test.ps1 -Target <url> -Count 3` | 探測 URL 回 403，規則為 `PocSimulatedProbe`，除非來源已在 `SentinelAutoBlock` | `AGWFirewallLogs` 的 `RuleId` 與 `ClientIp` | 無政策寫入 |
| 日誌進入 workspace | 診斷設定正確 | `sentinel/queries/verify-application-gateway.kql` | 查詢有資料列 | 查詢結果的時間與規則 ID | 無 |
| 開事件 | 同一 IP 在 30 分鐘內至少 3 筆，且不在封鎖規則、私有範圍、watchlist | 等候分析規則，最多約一個排程週期再加處理時間 | 新事件。12 小時內同一 IP 併入原事件，不再 Created | 事件編號、實體 IP | 關閉事件不會自動改 WAF |
| Playbook | 自動化規則啟用 | 看該事件的 playbook run | 先 POST `execution=dry-run` | run 動作 `Call_block_function` 的狀態碼與 `status` 欄位。不要複製 `x-functions-key` | 無 |
| Dry-run | `AUTO_BLOCK_ENABLED=false` | 由 playbook 呼叫 | `status=dry-run`，`changed=false`，註解含 `Would block IP` | 事件註解與 PUT 前的 match value 數量 | 無 |
| Reject | 核准信可達 | 選 Reject | 註解說明未選擇 Approve，政策不變 | 核准動作輸出不含祕密的選項文字、match value 數量不變 | 無 |
| Approve 後寫入 | 核准人與 RBAC 正確 | 選 Approve | 第二次 `execution=enforce`，`status=blocked`，`changed=true` | 政策比對，只多出該 IP。註解不再叫人假設 | 依第 8 章移除該 IP |
| 重複 IP | 位址已在規則內 | 再觸發一次 | `already-blocked`，不寄核准信，不 PUT | run 與註解 | 無 |
| 無效 IP | 實體不是單一公開 IPv4 | 引擎單測在 `webapp/tests/engine/test_addresses.py` | 拒絕，不讀或不寫政策，視失敗點而定 | 單測或註解中的 reason | 無 |
| 呼叫失敗 | API 金鑰錯誤或站點不可達 | 不要在正式視窗故意做 | 註解寫明不要假設政策已改，run 仍可能 Succeeded | 註解與站點日誌 | 讀政策確認 |
| PUT 202 或失敗 | 權限不足或政策衝突 | 引擎把 202 當失敗 | `waf-put-failed`，`changed=false` | 註解與政策前後差異 | 讀政策後再決定是否重送。Playbook 不會自動重試 PUT |

已知探測機制仍由 `scripts/test.ps1` 與分析規則支援。來源 IP 若已在 `SentinelAutoBlock`，首頁與探測都會先被 priority 10 擋下，不會再用探測規則製造新事件。

## 7. 操作與疑難排解

### 7.1 Logic App

在資源 `playbook-ase-sentinel-poc-block-malicious-ip` 打開 run。核對順序：取 IP、第一次 HTTP、是否進入核准、第二次 HTTP。Succeeded 且停在「未核准」或「呼叫失敗」註解時，代表流程依設計停止，不是已封鎖。

### 7.2 Web App

站點 `app-ase-sentinel-poc-7ttpll74`。記錄在 App Service 記錄與 Application Insights。引擎日誌格式在 `engine.py`：`status`、`changed`、事件編號與計數。不要把含 `BLOCK_API_KEY` 的要求標頭貼到票證。

### 7.3 Sentinel

事件註解是給人看的稽核。dry-run、已在名單、容量不足、讀取失敗、PUT 失敗的句型都在 `webapp/sentinel_waf_block/comments.py`。PUT 失敗的註解要求先讀政策。

### 7.4 WAF 日誌

`AGWFirewallLogs` 的 `RuleId` 區分 `PocSimulatedProbe` 與 `SentinelAutoBlock`。`AGWAccessLogs` 的 HTTP 403 不足以單獨判斷是哪一條規則。

### 7.5 核准失敗

連接器未授權、核准人信箱錯誤、或 run 已經結束才去點舊信，都不會寫入政策。舊信對應已結束的 run 時，Logic Apps 會拒絕繼續。處理方式是看該 run 是否仍在等待，而不是對同一封信重複點擊。若要重做，必須有一張新的 Created 事件，或在確認政策現況後由已授權的人做手動維護。本儲存庫沒有「重播舊核准」的命令。

### 7.6 RBAC 與認證

GET 或 PUT 若回 `authentication failed`，先確認 CLI 或受控識別的租用戶是 POC 租用戶，再確認角色在**政策資源**上，不是只在資源群組看得到讀取權。`azure_clients.py` 不會把權杖放進例外訊息。

### 7.7 容量

數 `SentinelAutoBlock` 與 `SentinelAutoBlock-*` 的 match value。單條達到 600 才會再開規則，且整份政策自訂規則不可超過 100，其中還包含 `PocSimulatedProbe`。線上主政策目前是 2 條自訂規則，封鎖規則 6 個值。產品設定 100 沒有在這條 PUT 路徑生效。

### 7.8 稽核

一筆變更要能對上四樣東西：Sentinel 事件編號、Logic App run 名稱、核准選項、政策 diff。WAF 規則本身沒有核准人欄位。

## 8. 回復

### 8.1 停止自動化

停用自動化規則，或停用 Logic App。兩者都能讓新的 Created 事件不再呼叫 API。本次沒有執行，也沒有把停用命令寫成必須貼上的操作，以免誤關。入口網站的 Disable 與 Bicep `enabled=false` 是兩種做法。後者屬於部署，會碰到第 1 章的限制。

### 8.2 回到 dry-run

線上已經是 `AUTO_BLOCK_ENABLED=false`。保持這個值。不要把腳本預設的 `-AutoBlockEnabled $true` 套到 Web App。

### 8.3 移除錯誤位址

1. 讀取政策，確認位址在哪一條規則、是哪一個字串。
2. 用已授權的維護路徑呼叫 `operation=remove`，或依 `README.md` 編輯 `matchValues` 後 PUT。
3. 若該規則會變成空的，刪除規則，不要送空陣列。
4. 再讀一次政策。引擎不會因為註解寫了失敗就自動回復。

PUT 必須包含原有的 `location`、`tags`、`policySettings`、`customRules`、`managedRules`。引擎的 `build_put_body` 就是這樣組的。手動 PUT 時要一併保留 `PocSimulatedProbe`，否則探測規則會消失。

### 8.4 部分失敗

核准已按、第二次 HTTP 失敗：註解會寫核准已給但呼叫失敗。此時政策可能沒變，也可能 PUT 已生效而回應遺失。唯一依據是再讀 `matchValues`。不要立刻再按另一封信。

### 8.5 已知安全狀態

目前可描述的安全狀態是：自動旗標關閉、playbook 仍會在有新位址時寄信、主政策有一條 6 個值的封鎖規則。這不是「空的封鎖名單」。回復到空名單是一項變更，不在本次文件工作中執行。

## 9. 複製到另一座 ASE 工廠

### 9.1 可調整參數

`NamePrefix`、`Location`、`ApproverEmail`、`ProtectedIpRanges`、現有政策資源 ID、`NotifyTeamsUrl`、門檻與排程、探測標記。watchlist 名稱在程式是 `AseWafIpAllowlist`，換工廠時要決定沿用或改名。改名必須同時改 KQL 權杖 `__WATCHLIST__` 的替換值。

### 9.2 不可直接複製的東西

- 測試閘道、`192.0.2.10` 後端、模擬標記。正式工廠通常已有自己的 Application Gateway。對現有政策使用 `-DeployTestWaf $false` 與現有政策資源 ID。這個開關在腳本裡有檢查，但整份腳本仍不適合執行，見第 1 章。
- 訂用帳戶、workspace、連接器授權、Teams flow URL、`BLOCK_API_KEY`。
- centralus 的 Web App。新工廠的區域要依配額另選，不能假設 eastus 有 App Service 配額。作業應用程式不需要 Azure SQL。
- `wafpol-ase-sentinel-poc-2`。用途未知，不要複製。

### 9.3 必須先確認

- 該工廠的 WAF 是 Application Gateway 還是 Front Door。Front Door 引擎有程式分支，部署腳本不建立 Front Door。
- CRS 版本是否為 3.2 或更新，以確認 600 筆上限。
- 核准人是誰，信箱是否允許收到事件標題與 IP。
- 是否允許模擬探測打到正式閘道。若否，分析規則不能沿用 `ase-poc-probe`。
- 誰可以對政策做 PUT，角色要指到政策資源。
- 12 小時分組是否符合該工廠的事件作業。分組窗內不會再次啟動 playbook。

### 9.4 交接檢查

- 資源名稱與區域表已填，且不含祕密。
- 一筆 Reject 的 run 連結已存檔。
- 一筆 Approve 的政策 diff 已存檔，並標明回復方式。
- 部署腳本的缺口已告知：不能靠 `deploy.ps1` 重建 Web App 路徑。
- Azure SQL 已刪除。Function App 不在資源群組，範本也不再描述它。`scripts/deploy.ps1` 仍不應用來重建現有群組。

## 10. 正式環境準備度

| 控制 | 狀態 |
| --- | --- |
| 預設不自動 PUT | 已在線上設定證實 `AUTO_BLOCK_ENABLED=false` |
| 核准後才 enforce | 已實作於 playbook。線上定義未逐行動 diff |
| 私有與中繼位址拒絕 | 已實作於程式。線上 `OVERRIDE_PROTECTED_RANGES=false` |
| 重複位址不寫第二次 | 已實作。未在本次重測 |
| 空規則刪除 | 已實作於 `build_put_body` |
| 呼叫失敗不宣稱已封鎖 | 已實作於註解與 playbook |
| 祕密不在原始碼 | URL 與金鑰在 App Settings。沒有 Key Vault |
| 最小權限已核對 | 未做。Function 角色設定檔已過時 |
| 可重複部署 | 未達成。腳本與線上路徑不一致 |
| 產品上限 100 已在寫入路徑生效 | 未達成 |
| 監控與警示 | 未見針對這條流程的警示 |
| 第二工廠參數表 | 待客戶填寫 |
| 瀏覽器作業頁面已驗收 | 未在本次驗證 |
| Office 365 連接器仍有效 | 待確認 |
