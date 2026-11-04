# Deploys the ASE WAF -> Sentinel -> block proof of concept.
# -PlaybookMode thin is the default. That Logic App posts to the operations web
# app. -PlaybookMode full deploys the expression workflow, which does not call
# the web app. This script does not create or publish a Function App, and it
# does not write the web app's app settings.
# Do not run this script against the live resource group: the main template
# redeploys the playbook with an empty functionKey and can reset the Office 365
# connection. An empty -BlockApiUrl also clears the playbook parameter functionUrl.
# For thin mode, -AutoBlockEnabled is recorded on the deployment output only. It
# does not change the web app setting AUTO_BLOCK_ENABLED. For full mode, that
# flag is the workflow parameter that decides whether the Logic App PUTs.
# Requires Azure CLI, a subscription, and rights to create the resource group,
# role assignments, and Microsoft Sentinel. This script does not register resource providers.
#requires -Version 7.0
[CmdletBinding()]
param(
    [string] $SubscriptionId,
    [string] $ResourceGroupName = 'rg-ase-sentinel-poc',
    [string] $Location = 'eastus',
    [ValidatePattern('^[a-z0-9-]{3,24}$')]
    [string] $NamePrefix = 'ase-sentinel-poc',
    [ValidateSet('ApplicationGateway', 'FrontDoor')]
    [string] $WafProvider = 'ApplicationGateway',
    [bool] $DeployTestWaf = $true,
    [string] $ExistingWafPolicyName = '',
    [string] $ExistingWafPolicyResourceId = '',
    [ValidatePattern('^https://')]
    [string] $NotifyTeamsUrl = '',
    [ValidatePattern('^[a-z_,]*$')]
    [string] $NotifyEvents = 'blocked,put_failed,capacity',
    # The thin playbook stops fail-closed when this is empty: no approver, no block.
    # The full playbook does not send this approval email.
    [ValidatePattern('^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$')]
    [string] $ApproverEmail = '',
    # thin calls the operations web app. full runs the expression workflow.
    [ValidateSet('thin', 'full')]
    [string] $PlaybookMode = 'thin',
    # HTTPS URL of POST /api/SentinelWafAutoBlock. Empty leaves the playbook
    # parameter functionUrl empty. The workflow parameter name stays functionUrl.
    [string] $BlockApiUrl = '',
    [ValidateSet('AzureDiagnostics', 'ResourceSpecific')]
    [string] $FrontDoorLogDestination = 'AzureDiagnostics',
    [ValidateSet('Prevention', 'Detection')]
    [string] $WafMode = 'Prevention',
    [bool] $AutoBlockEnabled = $true,
    # Required only for -PlaybookMode full -AutoBlockEnabled $true. That
    # combination PUTs from the Logic App with no approval email.
    [switch] $ConfirmAutoBlock,
    [bool] $OverrideProtectedRanges = $false,
    [switch] $ConfirmOverrideProtectedRanges,
    [string[]] $ProtectedIpRanges = @(),
    [ValidateRange(1, 100)]
    [int] $DetectionThreshold = 3,
    [ValidateRange(5, 60)]
    [int] $QueryFrequencyMinutes = 5,
    [ValidateRange(5, 1440)]
    [int] $QueryLookbackMinutes = 30,
    [ValidatePattern('^[A-Za-z0-9-]{3,40}$')]
    [string] $ProbeMarker = 'ase-poc-probe',
    [ValidatePattern('^[A-Za-z][A-Za-z0-9]{2,39}$')]
    [string] $ProbeRuleName = 'PocSimulatedProbe',
    [ValidateRange(1, 100)]
    [int] $ProbeRulePriority = 50,
    [ValidatePattern('^[A-Za-z][A-Za-z0-9]{2,39}$')]
    [string] $BlockRuleName = 'SentinelAutoBlock',
    [ValidateRange(1, 100)]
    [int] $BlockRulePriority = 10,
    [ValidateRange(1, 10)]
    [int] $AppGatewayMinCapacity = 1,
    [ValidateRange(2, 10)]
    [int] $AppGatewayMaxCapacity = 2,
    [switch] $AutomationRuleOnly,
    [switch] $WhatIf
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if (Test-Path variable:PSNativeCommandUseErrorActionPreference) {
    $PSNativeCommandUseErrorActionPreference = $false
}

if ($WhatIf -and $AutomationRuleOnly) {
    throw 'Use either -WhatIf or -AutomationRuleOnly, not both.'
}
if ($QueryFrequencyMinutes -gt $QueryLookbackMinutes) {
    throw "QueryFrequencyMinutes ($QueryFrequencyMinutes) must be less than or equal to QueryLookbackMinutes ($QueryLookbackMinutes)."
}
if ($AppGatewayMinCapacity -gt $AppGatewayMaxCapacity) {
    throw "AppGatewayMinCapacity ($AppGatewayMinCapacity) must be less than or equal to AppGatewayMaxCapacity ($AppGatewayMaxCapacity)."
}
if ($ProbeRulePriority -eq $BlockRulePriority) {
    throw 'ProbeRulePriority and BlockRulePriority must be different. The block rule is created later on the same policy.'
}
if ($WafProvider -eq 'FrontDoor' -and $DeployTestWaf) {
    throw 'This repository deploys a test WAF only for Application Gateway. For Front Door, pass -DeployTestWaf $false and an existing policy name or resource id. Front Door itself and its diagnostic settings are not created here.'
}
if ($DeployTestWaf -and -not [string]::IsNullOrWhiteSpace($ExistingWafPolicyName)) {
    throw 'DeployTestWaf creates the WAF policy. Do not also pass -ExistingWafPolicyName.'
}
if ($DeployTestWaf -and -not [string]::IsNullOrWhiteSpace($ExistingWafPolicyResourceId)) {
    throw 'DeployTestWaf creates the WAF policy. Do not also pass -ExistingWafPolicyResourceId.'
}
if (-not $DeployTestWaf -and [string]::IsNullOrWhiteSpace($ExistingWafPolicyName) -and [string]::IsNullOrWhiteSpace($ExistingWafPolicyResourceId)) {
    throw 'Without the test WAF, pass -ExistingWafPolicyName (same resource group) or -ExistingWafPolicyResourceId.'
}
if ($OverrideProtectedRanges -and -not $ConfirmOverrideProtectedRanges) {
    throw 'Refusing to skip protected ranges. Re-run with -OverrideProtectedRanges $true -ConfirmOverrideProtectedRanges only when that exception is intended. Invalid IPs are still rejected.'
}
if ($WafProvider -eq 'FrontDoor' -and $FrontDoorLogDestination -eq 'ResourceSpecific') {
    Write-Warning 'ResourceSpecific selects AzureFrontDoorWebApplicationFirewallLog. This repository does not create that diagnostic setting. Use it only after ASE confirms the table exists. The default AzureDiagnostics query is the one Microsoft documents.'
}
if ($WafMode -eq 'Detection') {
    Write-Warning 'Detection mode logs an Application Gateway custom block rule and does not enforce it. The analytics rule accepts Action Blocked or Detected. A Prevention-mode test is what produces HTTP 403.'
}
if (-not [string]::IsNullOrWhiteSpace($BlockApiUrl) -and $BlockApiUrl -notmatch '^https://') {
    throw 'BlockApiUrl must be empty or an https URL of POST /api/SentinelWafAutoBlock.'
}
if ($PlaybookMode -eq 'full' -and $AutoBlockEnabled -and -not $ConfirmAutoBlock) {
    throw 'A full playbook with -AutoBlockEnabled $true writes the WAF policy from the Logic App and does not send an approval email. Re-run with -ConfirmAutoBlock only when that write is intended. Pass -AutoBlockEnabled $false for a full playbook that comments and does not PUT.'
}
if ($PlaybookMode -eq 'thin' -and $ConfirmAutoBlock) {
    Write-Warning '-ConfirmAutoBlock has no effect on the thin playbook. That playbook writes only after Office 365 approval, through the web app.'
}
if ($PlaybookMode -eq 'full' -and -not [string]::IsNullOrWhiteSpace($BlockApiUrl)) {
    Write-Warning '-BlockApiUrl is ignored when -PlaybookMode is full. The expression playbook does not call the web app.'
}
if ($PlaybookMode -eq 'full') {
    if ($AutoBlockEnabled) {
        Write-Warning 'Playbook mode is full and autoBlockEnabled is true. The Logic App PUTs the WAF policy with no approval email. This script does not change the web app setting AUTO_BLOCK_ENABLED.'
    }
    else {
        Write-Warning 'Playbook mode is full and autoBlockEnabled is false. The Logic App comments and does not PUT. This script does not change the web app setting AUTO_BLOCK_ENABLED.'
    }
}
elseif ($AutoBlockEnabled) {
    Write-Warning 'autoBlockEnabled is recorded as true on the deployment output. This script does not change the operations web app setting AUTO_BLOCK_ENABLED.'
}
else {
    Write-Warning 'autoBlockEnabled is recorded as false on the deployment output. This script does not change the operations web app setting AUTO_BLOCK_ENABLED.'
}
if (-not [string]::IsNullOrWhiteSpace($NotifyTeamsUrl) -or $NotifyEvents -ne 'blocked,put_failed,capacity') {
    Write-Warning 'NotifyTeamsUrl and NotifyEvents are not written by this script. Set NOTIFY_TEAMS_URL, NOTIFY_TEAMS_AUTH, and NOTIFY_EVENTS on the operations web app.'
}

. (Join-Path $PSScriptRoot 'ip-ranges.ps1')
$ProtectedIpRanges = @(
    foreach ($entry in $ProtectedIpRanges) {
        ConvertTo-CanonicalIpRange -Entry $entry
    }
)
if (-not [string]::IsNullOrWhiteSpace($ExistingWafPolicyResourceId)) {
    $agwType = 'Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies'
    $fdType = 'Microsoft.Network/frontDoorWebApplicationFirewallPolicies'
    $expectedType = if ($WafProvider -eq 'FrontDoor') { $fdType } else { $agwType }
    if ($ExistingWafPolicyResourceId -notmatch "^/subscriptions/[^/]+/resourceGroups/[^/]+/providers/$([regex]::Escape($expectedType))/[^/]+$") {
        throw "ExistingWafPolicyResourceId must be a resource id for $expectedType."
    }
}

function ConvertTo-BicepArray {
    param([string[]] $Values)
    if ($null -eq $Values -or $Values.Count -eq 0) {
        return '[]'
    }
    $quoted = foreach ($value in $Values) {
        '"' + $value + '"'
    }
    return '[' + ($quoted -join ',') + ']'
}

function Invoke-AzCli {
    param(
        [Parameter(Mandatory)]
        [string[]] $Arguments
    )
    Write-Host "az $($Arguments -join ' ')"
    & az @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Azure CLI failed with exit code $LASTEXITCODE."
    }
}

function Grant-PlaybookNetworkContributor {
    param(
        [Parameter(Mandatory)]
        [string] $PolicyId,
        [Parameter(Mandatory)]
        [string] $PrincipalId
    )
    $roleId = '4d97b98b-1d4f-4787-a291-c67834d212e7'
    $raw = az role assignment list --scope $PolicyId --assignee-object-id $PrincipalId --role $roleId --query '[].id' --output tsv
    if ($LASTEXITCODE -ne 0) {
        throw 'Could not list playbook role assignments on the WAF policy.'
    }
    $ids = @($raw -split "\r?\n" | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    if ($ids.Count -gt 0) {
        Write-Host 'The playbook identity already has Network Contributor on the WAF policy.'
        return
    }
    Write-Host 'Granting Network Contributor to the playbook identity on the WAF policy.'
    & az role assignment create --scope $PolicyId --assignee-object-id $PrincipalId --assignee-principal-type ServicePrincipal --role $roleId --output none
    if ($LASTEXITCODE -ne 0) {
        throw 'Could not grant Network Contributor to the playbook identity.'
    }
}

function Remove-PlaybookNetworkContributor {
    param(
        [Parameter(Mandatory)]
        [string] $PolicyId,
        [Parameter(Mandatory)]
        [string] $PrincipalId
    )
    Write-Host 'Removing Network Contributor from the playbook identity on the WAF policy.'
    $raw = az role assignment list --scope $PolicyId --assignee-object-id $PrincipalId --role '4d97b98b-1d4f-4787-a291-c67834d212e7' --query '[].id' --output tsv
    if ($LASTEXITCODE -ne 0) {
        throw 'Could not list playbook role assignments on the WAF policy.'
    }
    $ids = @($raw -split "\r?\n" | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    foreach ($id in $ids) {
        & az role assignment delete --ids $id --output none
        if ($LASTEXITCODE -ne 0) {
            throw 'Could not remove Network Contributor from the playbook identity.'
        }
    }
}

if (-not (Get-Command az -ErrorAction SilentlyContinue)) {
    throw 'Azure CLI (az) is not installed or not on PATH.'
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$infra = Join-Path $repoRoot 'infra'
$rangesJson = ConvertTo-BicepArray -Values $ProtectedIpRanges

if ($SubscriptionId) {
    Invoke-AzCli @('account', 'set', '--subscription', $SubscriptionId)
}
Invoke-AzCli @('account', 'show', '--output', 'none')

if (-not $AutomationRuleOnly) {
    if ($DeployTestWaf) {
        Write-Warning 'The test Application Gateway uses WAF_v2 and bills hourly until the resource group is deleted.'
    }
    Invoke-AzCli @(
        'group', 'create',
        '--name', $ResourceGroupName,
        '--location', $Location,
        '--tags', 'Customer=ASE', 'Purpose=SentinelWafBlockPoc', 'Environment=poc', 'ManagedBy=bicep'
    )

    $mainArgs = @(
        'deployment', 'group', $(if ($WhatIf) { 'what-if' } else { 'create' }),
        '--name', 'ase-sentinel-poc-main',
        '--resource-group', $ResourceGroupName,
        '--template-file', (Join-Path $infra 'main.bicep'),
        '--parameters',
        "location=$Location",
        "namePrefix=$NamePrefix",
        "wafProvider=$WafProvider",
        "deployTestWaf=$($DeployTestWaf.ToString().ToLowerInvariant())",
        "existingWafPolicyName=$ExistingWafPolicyName",
        "existingWafPolicyResourceId=$ExistingWafPolicyResourceId",
        "frontDoorLogDestination=$FrontDoorLogDestination",
        "wafMode=$WafMode",
        "autoBlockEnabled=$($AutoBlockEnabled.ToString().ToLowerInvariant())",
        "overrideProtectedRanges=$($OverrideProtectedRanges.ToString().ToLowerInvariant())",
        "protectedIpRanges=$rangesJson",
        "detectionThreshold=$DetectionThreshold",
        "queryFrequencyMinutes=$QueryFrequencyMinutes",
        "queryLookbackMinutes=$QueryLookbackMinutes",
        "probeMarker=$ProbeMarker",
        "probeRuleName=$ProbeRuleName",
        "probeRulePriority=$ProbeRulePriority",
        "blockRuleName=$BlockRuleName",
        "blockRulePriority=$BlockRulePriority",
        "playbookMode=$PlaybookMode",
        "blockApiUrl=$BlockApiUrl",
        "approverEmail=$ApproverEmail",
        "appGatewayMinCapacity=$AppGatewayMinCapacity",
        "appGatewayMaxCapacity=$AppGatewayMaxCapacity"
    )
    if (-not $WhatIf) {
        Write-Host 'Main deployment started. Application Gateway WAF_v2 often takes 20 to 40 minutes.'
    }
    Invoke-AzCli $mainArgs
}

if ($WhatIf) {
    Write-Host 'What-if complete. No automation rule was deployed. Nothing was blocked.'
    return
}

if (-not $AutomationRuleOnly) {
    $mainOutputsRaw = az deployment group show --name 'ase-sentinel-poc-main' --resource-group $ResourceGroupName --query 'properties.outputs' --output json
    if ($LASTEXITCODE -ne 0) {
        throw 'Could not read outputs from deployment ase-sentinel-poc-main.'
    }
    $mainOutputs = $mainOutputsRaw | ConvertFrom-Json
    if ($PlaybookMode -eq 'full') {
        Grant-PlaybookNetworkContributor -PolicyId $mainOutputs.wafPolicyId.value -PrincipalId $mainOutputs.playbookPrincipalId.value
    }
    else {
        Remove-PlaybookNetworkContributor -PolicyId $mainOutputs.wafPolicyId.value -PrincipalId $mainOutputs.playbookPrincipalId.value
    }
}

function Get-SentinelAutomationPrincipalId {
    # display-name is a prefix match and also returns Content As Code and Management.
    $raw = az ad sp list --display-name 'Azure Security Insights' --query "[?displayName=='Azure Security Insights'].id" --output tsv 2>$null
    if ($LASTEXITCODE -ne 0) {
        return $null
    }
    $lines = @($raw -split "\r?\n" | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    if ($lines.Count -eq 0) {
        return $null
    }
    return $lines[0]
}

$principalId = Get-SentinelAutomationPrincipalId
if (-not $principalId) {
    Write-Warning 'Could not find the Azure Security Insights service principal. The workspace, analytics rule, and playbook are deployed. The automation rule was not created. After Sentinel is available in the tenant, re-run this script with -AutomationRuleOnly.'
}
else {
    Write-Host "Azure Security Insights object id: $principalId"
    Invoke-AzCli @(
        'deployment', 'group', 'create',
        '--name', 'ase-sentinel-poc-automation-role',
        '--resource-group', $ResourceGroupName,
        '--template-file', (Join-Path $infra 'role-sentinel-automation.bicep'),
        '--parameters', "principalId=$principalId"
    )
    Write-Host 'Waiting 30 seconds for the role assignment to replicate before creating the automation rule.'
    Start-Sleep -Seconds 30
    $deployment = az deployment group show --name 'ase-sentinel-poc-main' --resource-group $ResourceGroupName --query 'properties.outputs' --output json
    if ($LASTEXITCODE -ne 0) {
        throw 'Could not read outputs from deployment ase-sentinel-poc-main.'
    }
    $outputs = $deployment | ConvertFrom-Json
    Invoke-AzCli @(
        'deployment', 'group', 'create',
        '--name', 'ase-sentinel-poc-automation-rule',
        '--resource-group', $ResourceGroupName,
        '--template-file', (Join-Path $repoRoot 'sentinel\automation-rules\block-malicious-ip.bicep'),
        '--parameters',
        "workspaceName=$($outputs.workspaceName.value)",
        "analyticsRuleId=$($outputs.analyticsRuleId.value)",
        "playbookResourceId=$($outputs.playbookResourceId.value)",
        'enabled=true'
    )
}

$shownRaw = az deployment group show --name 'ase-sentinel-poc-main' --resource-group $ResourceGroupName --query 'properties.outputs' --output json
if ($LASTEXITCODE -ne 0) {
    throw 'Could not read outputs from deployment ase-sentinel-poc-main.'
}
$shown = $shownRaw | ConvertFrom-Json
Write-Host ''
Write-Host "Resource group:      $ResourceGroupName"
Write-Host "Workspace:           $($shown.workspaceName.value)"
Write-Host "Workspace id:        $($shown.workspaceResourceId.value)"
Write-Host "WAF provider:        $($shown.wafProvider.value)"
Write-Host "WAF policy:          $($shown.wafPolicyName.value)"
Write-Host "WAF policy id:       $($shown.wafPolicyId.value)"
$shownMode = if ($shown.PSObject.Properties.Name -contains 'playbookMode') { $shown.playbookMode.value } else { $PlaybookMode }
Write-Host "Playbook:            $($shown.playbookName.value)"
Write-Host "Playbook mode:       $shownMode"
if ($shown.blockApiUrl.value) {
    Write-Host "Block API URL:       $($shown.blockApiUrl.value)"
}
else {
    Write-Host 'Block API URL:       empty. The playbook parameter functionUrl stays empty until -BlockApiUrl is passed.'
}
Write-Host "autoBlockEnabled:    $($shown.autoBlockEnabled.value) (deployment output only; the web app setting is unchanged)"
Write-Host "Detection query:     $($shown.detectionQueryKind.value)"
Write-Host "Analytics rule id:   $($shown.analyticsRuleId.value)"
Write-Host "Probe marker:        $($shown.probeMarker.value)"
if ($shown.publicIpAddress.value) {
    Write-Host "Application Gateway: http://$($shown.publicIpAddress.value)/"
    Write-Host "Test:                ./scripts/test.ps1 -Target http://$($shown.publicIpAddress.value)/ -Count $DetectionThreshold"
}
else {
    Write-Host 'This deployment did not create a test Application Gateway. An empty public IP output does not delete a gateway that is already in the resource group.'
}
Write-Host ''
if ($shownMode -eq 'full') {
    Write-Host 'The full playbook decides the block. It does not call the operations web app.'
    Write-Host 'autoBlockEnabled true PUTs the one custom rule. false comments and does not PUT.'
    Write-Host 'Each custom rule holds 600 match values. A full rule opens the next SentinelAutoBlock rule on the same policy. The full playbook does not send a Teams card.'
}
else {
    Write-Host 'The operations web app decides the block. AUTO_BLOCK_ENABLED on that app is not set by this script.'
    Write-Host 'A playbook call with execution=approved writes for that call. execution=awaiting-approval does not.'
}
Write-Host 'Cleanup: ./scripts/cleanup.ps1 -ResourceGroupName' $ResourceGroupName
Write-Host 'Incident latency is usually 10 to 15 minutes: ingestion plus the analytics schedule.'
Write-Host 'The procedure is in docs/testing.md.'
