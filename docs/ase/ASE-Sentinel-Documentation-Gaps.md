# ASE Microsoft Sentinel 文件落差與驗證報告

檢視日期：2026-11-02。分支 `feature/laptop-sentinel-ops`，commit `7a291a6`。Azure 檢視為唯讀，結束後 CLI 預設訂用帳戶已恢復為檢視前的訂用帳戶。

優先順序：P1 會讓重建或正式使用做出錯誤的封鎖或部署。P2 會讓交接時無法證明現況。P3 是後續改善。

## 1. 缺少的實作證據

| ID | 優先順序 | 元件 | 說明 | 建議動作 | 來源 |
| --- | --- | --- | --- | --- | --- |
| G-1 | P1 | 部署腳本 | `scripts/deploy.ps1` 不再複製 Function 檔案，主範本也不再建立 Function。腳本仍會重布 playbook。空的 `functionKey` 會清掉線上金鑰，也可能重置 Office 365。Web App 發布程序仍未寫進腳本 | 不要對現有資源群組執行該腳本。另寫一條只發布 `webapp/`、不重布 WAF 與 playbook 連接器的程序 | `scripts/deploy.ps1`；`infra/main.bicep` |
| G-2 | P1 | 基礎結構 | `infra/main.bicep` 不參考 `infra/modules/webapp.bicep`。線上 Web App、centralus 方案與 `vnet-app-ase-sentinel-poc-7ttpll74` 沒有由目前主範本證明的部署路徑。Azure SQL 與私人端點已刪除，`webapp.bicep` 也不再描述它們 | 把 Web App 標成既有資源，不要靠現有主範本重建。補部署程序前不要把 `webapp.bicep` 部署到這個資源群組 | `infra/main.bicep`、資源清單 |
| G-3 | P2 | 引擎位置 | `function-app/` 已從儲存庫移除。執行中的原始碼在 `webapp/sentinel_waf_block/` | 不要把舊的本機快取當成來源 | `webapp/sentinel_waf_block/` |
| G-4 | P2 | 第二份政策 | `wafpol-ase-sentinel-poc-2` 存在，0 條自訂規則，`ManagedBy=manual`，沒有 `ase-sentinel-block-list=true`。引擎只 PUT `WAF_POLICY_RESOURCE_ID` | 請資源擁有者說明用途。沒有用途就不要在文件或複製程序中把它當成封鎖目標 | 本次政策讀取；`service.execute_payload` |
| G-5 | P2 | 範本 | `docs/模組設計說明書範本 v0.1.docx` 是 OLE 檔，不是 OOXML，無法抽出章節 | 若必須符合該範本，請提供未加密的 `.docx`。本次三份 Markdown 依任務大綱撰寫 | 檔頭 `D0 CF 11 E0` |

## 2. 尚未驗證的 Azure 設定

| ID | 優先順序 | 元件 | 說明 | 建議動作 | 來源 |
| --- | --- | --- | --- | --- | --- |
| G-6 | P1 | RBAC | 設定檔只保留 playbook 的 Sentinel Responder。Function 角色列已刪除。Web App 的 Network Contributor 是既有指派，主範本不會建立它。本次文件更新沒有重讀線上角色 | 列出 Web App 系統受控識別在政策與資源群組上的角色。確認 playbook 沒有 WAF 寫入權 | `profiles/poc-approval.json`；`scripts/deploy.ps1` 的 `Remove-PlaybookNetworkContributor` |
| G-7 | P1 | Easy Auth | 封鎖 API 依賴 Easy Auth 排除 `/api/SentinelWafAutoBlock`，頁面則應要求登入。本次沒有讀 authsettings，也沒有呼叫 `/health` | 唯讀匯出排除路徑與未登入時的 `unauthenticatedClientAction`。用無金鑰的 POST 確認得到 401，而不是匿名執行引擎 | `webapp/app/live.py`；`webapp/README.md` |
| G-8 | P2 | Office 365 連接器 | 連接器資源在線上。是否仍為核准人已授權，本次未查 | 在入口網站看連接器狀態。不要重新部署 playbook 來「修復」 | `infra/modules/playbook.bicep` |
| G-9 | P2 | 分析規則與自動化規則 | workspace 子資源沒有出現在資源群組清單。門檻 3、5 分鐘、30 分鐘回看、12 小時分組只存在於參數與 Bicep | 讀這兩條規則的 `enabled`、查詢、`triggersWhen` 與分析規則條件 | `infra/modules/sentinel.bicep`；`sentinel/automation-rules/block-malicious-ip.bicep` |
| G-10 | P2 | 診斷設定 | `diag-waf-to-sentinel` 與 `diag-playbook-runtime` 只在設定檔 | 確認防火牆日誌類別仍送到 `log-ase-sentinel-poc-7ttpll74bmhiq`，且目標類型是 Dedicated | `profiles/poc-approval.json` |
| G-11 | P2 | 閘道綁定 | 公開 IP 位址、WAF policy 與 `agw-ase-sentinel-poc` 的關聯、SKU、後端是否仍為 `192.0.2.10`，本次未重讀。後端位址只在 Bicep 證實為設計值 | 讀閘道的 `firewallPolicy`、frontend IP 與 backend pool | `infra/modules/waf.bicep` |
| G-12 | P2 | Teams | `NOTIFY_TEAMS_URL` 與 `NOTIFY_TEAMS_AUTH=entra` 已設定。本次沒有收到或看到卡片 | 用下一筆非破壞性的 dry-run 確認卡片 Status 為 `awaiting-approval`，且政策 match value 數量不變 | `webapp/sentinel_waf_block/notifiers.py` |
| G-13 | P3 | App Insights 與儲存體 | `appi-ase-sentinel-poc` 與 `st7ttpll74bmhiq` 仍在。範本已不再建立它們。增量 Bicep 不會刪除殘留資源 | 確認 Web App 是否使用它們之後，再決定是否從 Azure 刪除。不要在未確認前刪除 | 資源清單；`infra/main.bicep` |
| G-14 | P3 | `ARM_API_VERSION` 與 `BLOCK_POLICY_TAG` 的線上值 | 設定名稱存在，本次摘要沒有印出值。程式預設分別是 `2024-05-01` 與 `ase-sentinel-block-list` | 核對線上值與預設是否相同。標籤目前不被 PUT 路徑用來選擇多份政策 | Web App 設定名稱清單；`config.py` |

## 3. 缺少的部署自動化

| ID | 優先順序 | 元件 | 說明 | 建議動作 | 來源 |
| --- | --- | --- | --- | --- | --- |
| G-15 | P1 | Web App 發布 | 沒有已驗證的指令可從 `webapp/` 建置並發布到 `app-ase-sentinel-poc-7ttpll74`，同時不改 WAF、不重設 Office 365 | 把實際使用過的發布步驟寫進腳本或執行手冊，並在非現有政策的資源群組演練 | `scripts/deploy.ps1` 與線上 URL 主機的差異 |
| G-16 | P1 | 主範本輸出 | 主範本不再輸出 Function。參數 `blockApiUrl` 預設空字串，傳入 playbook 的 `functionUrl`。空值會把新部署的 playbook URL 清成空，且 `functionKey` 仍是空的 | 不要對現有群組執行主範本。新環境要明確傳入 Web App 的封鎖 URL，並在範本之外設定 `functionKey` | `infra/main.bicep`；`scripts/deploy.ps1` |
| G-17 | P2 | 自動化規則的獨立部署 | Bicep 註明必須等 Azure Security Insights 有 Automation Contributor 之後才能 `RunPlaybook`。這段沒有在本次環境重做 | 在第二座工廠把這個失敗模式寫進執行手冊，並記錄服務主體物件 ID 的取得方式 | `sentinel/automation-rules/block-malicious-ip.bicep` |
| G-18 | P3 | CI | 儲存庫沒有看到會發布這條路徑的 CI 設定。本次沒有把「沒有 CI」擴大解釋成已搜尋每一個外部系統 | 若有 Azure DevOps 或 GitHub Actions 在儲存庫外，請補連結。儲存庫內目前以腳本為準 | 儲存庫佈局 |

## 4. 未寫清的安全決策

| ID | 優先順序 | 元件 | 說明 | 建議動作 | 來源 |
| --- | --- | --- | --- | --- | --- |
| G-19 | P1 | 兩條授權路徑 | Playbook 要等 Office 365 Approve。`service.py` 允許作業應用程式對手動 add 或 remove 送 `execution=approved`，從而在該次請求打開 PUT | 確認只有已登入的操作者打得到手動路由。文件與介面要寫明手動維護不經過核准信 | `webapp/sentinel_waf_block/service.py`；`webapp/app/live.py` |
| G-20 | P1 | 祕密存放 | `BLOCK_API_KEY`、Teams URL、Easy Auth 祕密是 App Settings，不是 Key Vault 參考 | 決定正式環境是否改為 Key Vault reference，以及金鑰輪替時如何更新 playbook 的 `functionKey` 而不重布整份定義 | Web App 設定名稱 |
| G-21 | P2 | 核准人身分 | 核准信箱只在 playbook 參數 `approverEmail`。Web App 不再有 `APPROVER_EMAIL`。文件預設郵件為 `admin@mngenvmcap591832.onmicrosoft.com`，本次沒有重讀參數值 | 核對 playbook 參數是否仍是這個人，並指定代理人 | `infra/modules/playbook.bicep` |
| G-22 | P2 | 頁面角色 | `POC_ADMIN_USERS` 已設定。live 頁面如何把 Easy Auth 對應到可按封鎖的角色，本次沒有逐行對到測試證據 | 補一節權限矩陣：誰可看事件、誰可手動增刪 | `webapp/app/config.py` |
| G-23 | P2 | 模擬探測打到測試閘道 | 探測來源就是操作者的出口 IP。核准後該 IP 會進入封鎖規則 | 向客戶說明這不是攻擊者 IP。正式閘道禁止用個人出口做 Approve 演練 | `scripts/test.ps1`；分析規則 KQL |

## 5. 測試落差

| ID | 優先順序 | 元件 | 說明 | 建議動作 | 來源 |
| --- | --- | --- | --- | --- | --- |
| G-24 | P1 | 端到端 | 本次沒有發送探測、沒有 Reject、沒有 Approve、沒有重跑 pytest。資源存在不能當成測試通過 | 在維護視窗做一筆 Reject，比對 match value 數量不變。Approve 只在客戶同意使用測試 IP 時進行，並事先寫好移除步驟 | 部署指南第 6 章 |
| G-25 | P2 | 單元測試 | `webapp/tests/engine/` 與 `webapp/tests/test_live.py`、`test_playbook.py` 覆蓋位址、執行旗標、playbook 條件與 live 路由。結果沒有在這次文件工作中產生 | 交接前記下指令與通過數量。未跑之前，文件不引用通過次數 | `webapp/tests/` |
| G-26 | P2 | 延伸規則與分析規則 | KQL 只排除名稱完全等於 `SentinelAutoBlock` 的列。`SentinelAutoBlock-2` 的阻擋可能再被計入。線上尚無延伸規則，所以這不是已觀察到的事件 | 用測試政策驗證，或把排除條件改成規則名稱起始於基底名稱。這是程式變更，不在本次文件範圍執行 | `simulated-probe.application-gateway.kql`；`waf_arm.py` 的 `_is_block_list_name` |
| G-27 | P2 | 單規則容量 | 未使用的 `MAXIMUM_BLOCK_ENTRIES` 已從程式、部署參數與 App Settings 移除。`select_block_list` 以 600 個 match value 為一條規則的上限，滿了就在同一政策開下一條規則。新的一批超過 600、自訂規則已達 100，或 priority 1–100 已滿時回 `capacity-exceeded` 且不 PUT | 若要更小的產品上限，必須另外加檢查。現在沒有 100 的開關 | `waf_arm.py` |
| G-28 | P3 | 並行 PUT | 沒有 ETag 或鎖。兩個 run 可能覆蓋 | 用兩個重疊的 dry-run 無法測出，必須在測試訂用帳戶做可控的並行 enforce | `engine.py` 的 `_decide` |

## 6. POC 到正式環境的落差

| ID | 優先順序 | 元件 | 說明 | 建議動作 | 來源 |
| --- | --- | --- | --- | --- | --- |
| G-29 | P1 | 偵測內容 | 規則描述寫明這不是惡意行為者辨識，只比對模擬標記 | 正式使用前換成 ASE 同意的偵測，並重做門檻、白名單與核准文案 | `infra/modules/sentinel.bicep` 的 description |
| G-30 | P1 | 測試後端 | 未封鎖的請求落到 `192.0.2.10`。502 不是正式應用程式的健康狀態 | 正式閘道維持既有後端。不要把這組測試閘道的 HTTP 碼寫進 SLO | `infra/modules/waf.bicep` |
| G-31 | P2 | 區域與成本 | 封鎖鏈在 eastus，Web App 在 centralus。Azure SQL 已刪除。儲存體、第二份政策與 App Insights 仍在 | 決定儲存體、第二份政策與 App Insights 的去留 | 資源清單 |
| G-32 | P2 | 稽核欄位 | WAF 規則沒有事件編號與核准人。稽核分散在 Sentinel 註解與 Logic App run | 正式作業要規定保留期限，以及 run 與事件的對照方式 | `comments.py` |
| G-33 | P2 | 警示 | 未見 playbook 失敗、PUT 失敗或容量拒絕的警示規則 | 用 Logic App 診斷與 App Service 日誌建立警示。這是建議，不是已部署功能 | 資源清單只有 Application Insights Smart Detection |
| G-34 | P3 | 解除封鎖與到期 | 沒有自動到期。移除是手動 `remove` 或編輯政策 | 若 ASE 需要到期，應另案設計，不要把 POC 說成會自動復原 | `engine.remove_entry`；`README.md` |

## 7. 第二座工廠要客戶決定的事

| ID | 優先順序 | 問題 | 不決定時的影響 | 來源 |
| --- | --- | --- | --- | --- |
| G-35 | P1 | 使用現有 Application Gateway 政策，還是新建測試閘道？ | 腳本預設 `DeployTestWaf=true` 會建立測試政策。對正式政策執行現有腳本不安全 | `scripts/deploy.ps1` |
| G-36 | P1 | 核准人信箱與是否允許代理人 | 空信箱會讓 playbook 在評估前停止。這是安全的失敗，但也表示流程不會跑完 | `thin-workflow.json` |
| G-37 | P1 | 能否在該工廠的閘道上送 `ase-poc-probe` | 不能的話，整條分析規則都要改，不能只改 playbook | KQL 與 `scripts/test.ps1` |
| G-38 | P1 | 是否要另設低於 600 的產品上限 | 殘留的 100 設定已移除。引擎就是每條規則 600，並可再開下一條自訂規則。現在沒有更小的開關 | G-27 |
| G-39 | P2 | 客戶保護範圍有哪些，prefix 是否只使用 8、16、24、32 | 其他 prefix 會讓整次執行變成 `protected-ranges-invalid`，且不讀政策 | `addresses.py` |
| G-40 | P2 | 12 小時分組是否可接受 | 窗內後續探測不會新開 playbook，也不會再寄核准信 | `sentinel.bicep` |
| G-41 | P2 | Teams 通知是否為必要交付物，flow 由誰擁有 | URL 是祕密，且綁定單一 Power Automate 環境 | `notifiers.py` |
| G-42 | P2 | 作業頁面要不要對第二座工廠的人員開放 | 頁面的手動 enforce 是另一條寫入路徑 | G-19 |
| G-43 | P3 | SQL 作業模式是否保留 | 儲存庫已移除。`LIVE_AZURE` 已於 2026-11-04 從 App Settings 刪除。`main.py` 不讀它。刪除後重啟，`GET /health` 回 200 | `webapp/app/main.py` |

## 8. 建議的後續順序

1. 核對 G-6、G-7、G-8。這三項決定目前線上路徑還能不能安全地做一次 Reject 演練。
2. 做 G-24 的 Reject 演練，補上唯一缺少的「現況仍會停在 dry-run」操作證據。
3. 停用或改寫 `scripts/deploy.ps1` 的 Function 發布段，避免下一次操作誤跑。這是程式變更，需另案同意。
4. 若第二座工廠要低於 600 的產品上限，必須另外設計。未使用的 100 設定已經移除。
5. 決定 G-4、G-13、G-31 的殘留資源去留，再寫第二座工廠的參數表。
6. 若客戶提供可讀的模組設計說明書範本，再把這三份 Markdown 的章節映射到該範本。本次無法從現有 `.docx` 做這件事。

## 9. 本次已核對、不應再列為未知的項目

- 主政策 mode 為 Prevention、state 為 Enabled。
- 主政策有 `SentinelAutoBlock`（priority 10，6 個 match value）與 `PocSimulatedProbe`（priority 50）。
- Playbook Enabled，封鎖 URL 指向作業 Web App，不是 Function App。
- Web App Running，Python 3.11，`AUTO_BLOCK_ENABLED=false`，`WAF_PROVIDER=ApplicationGateway`。`LIVE_AZURE` 已於 2026-11-04 刪除。同日 `GET /health` 回 200，主體仍是寫死的 `liveAzure: true` 與 `sql: false`。
- Azure SQL server、資料庫 `aseops`、私人端點與 `privatelink.database.windows.net` 已刪除。`vnet-app-ase-sentinel-poc-7ttpll74` 的 `snet-app` 仍供 Web App 整合。
- Function 站點不存在。
- 範本檔無法當 Office Open XML 讀取。
