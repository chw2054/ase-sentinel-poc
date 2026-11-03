# Diff or deploy the ASE Sentinel WAF PoC from one profile.
# diff is read-only. deploy calls scripts/deploy.ps1 only when -Apply is set.
# deploy.ps1 uses az deployment group create, which is incremental. This script
# never passes --mode Complete. When the WAF policy already exists, DeployTestWaf
# is forced off so the deployment does not rewrite custom rules.
#requires -Version 7.0
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidateSet('diff', 'deploy')]
    [string] $Action,

    [string] $Profile = 'poc',
    [string] $SubscriptionId = '',
    [string] $ResourceGroupName = 'rg-ase-sentinel-poc',
    [string] $Location = 'eastus',
    [ValidatePattern('^[a-z0-9-]{3,24}$')]
    [string] $NamePrefix = 'ase-sentinel-poc',
    [string] $ExistingWafPolicyName = '',
    [switch] $DeployTestWaf,
    [switch] $Apply,
    [string] $SnapshotPath = '',
    [string] $OutputDir = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if (Test-Path variable:PSNativeCommandUseErrorActionPreference) {
    $PSNativeCommandUseErrorActionPreference = $false
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$profilePath = Join-Path $repoRoot "profiles/$Profile.json"
if (-not (Test-Path -LiteralPath $profilePath)) {
    throw "Profile not found: $profilePath"
}

$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
if (-not $OutputDir) {
    $OutputDir = Join-Path $repoRoot "ase-out/$stamp"
}
New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

function Invoke-AzJson {
    param(
        [Parameter(Mandatory = $true)][string[]] $AzArguments,
        [switch] $Required
    )
    $raw = & az @AzArguments -o json --only-show-errors
    $code = $LASTEXITCODE
    $text = ($raw | Out-String).Trim()
    if ($code -ne 0) {
        if ($Required) {
            throw "az failed: $($AzArguments -join ' ')"
        }
        return $null
    }
    if ([string]::IsNullOrWhiteSpace($text) -or $text -eq '[]') {
        return ,([object[]] @())
    }
    return ($text | ConvertFrom-Json)
}

function Select-FirstType {
    param($Items, [string] $TypeName)
    $wanted = $TypeName.ToLowerInvariant()
    return @($Items) | Where-Object { ([string] $_.type).ToLowerInvariant() -eq $wanted } | Select-Object -First 1
}

function Get-SubscriptionId {
    if (-not [string]::IsNullOrWhiteSpace($SubscriptionId)) {
        & az account set --subscription $SubscriptionId --only-show-errors | Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw "Could not select subscription $SubscriptionId."
        }
        return $SubscriptionId
    }
    $current = & az account show --query id -o tsv --only-show-errors
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($current)) {
        throw 'Could not read the current Azure subscription. Pass -SubscriptionId.'
    }
    return $current.Trim()
}

function Remove-CustomRuleValues {
    param($Resource)
    if ($null -eq $Resource) { return }
    $propertiesMember = $Resource.PSObject.Properties['properties']
    if ($null -eq $propertiesMember -or $null -eq $propertiesMember.Value) { return }
    $rulesMember = $propertiesMember.Value.PSObject.Properties['customRules']
    if ($null -eq $rulesMember -or $null -eq $rulesMember.Value) { return }
    $clean = foreach ($rule in @($rulesMember.Value)) {
        if ($null -eq $rule) { continue }
        $count = 0
        $conditionsMember = $rule.PSObject.Properties['matchConditions']
        if ($null -ne $conditionsMember) {
            foreach ($condition in @($conditionsMember.Value)) {
                if ($null -eq $condition) { continue }
                $valuesMember = $condition.PSObject.Properties['matchValues']
                if ($null -ne $valuesMember) {
                    $count += @($valuesMember.Value).Count
                }
            }
        }
        [pscustomobject]@{
            name       = [string] $rule.name
            priority   = $rule.priority
            valueCount = $count
        }
    }
    $propertiesMember.Value.customRules = @($clean)
}

function Get-RoleItems {
    param([string] $Scope, [string] $Subscription)
    $listed = Invoke-AzJson @(
        'role', 'assignment', 'list',
        '--scope', $Scope,
        '--subscription', $Subscription
    )
    if ($null -eq $listed) {
        return @{ ok = $false; items = @() }
    }
    $items = [System.Collections.Generic.List[object]]::new()
    foreach ($item in @($listed)) {
        if ($null -eq $item) { continue }
        $items.Add([pscustomobject]@{
                roleDefinitionId = [string] $item.roleDefinitionId
                principalId      = [string] $item.principalId
                scope            = [string] $item.scope
            })
    }
    return @{ ok = $true; items = $items }
}

function Get-ChildResources {
    param(
        [string] $ParentId,
        [string] $ProviderAndType,
        [string] $ApiVersion
    )
    $page = Invoke-AzJson @(
        'rest', '--method', 'get',
        '--url', "https://management.azure.com$ParentId/providers/${ProviderAndType}?api-version=$ApiVersion"
    )
    if ($null -eq $page) {
        return ,([object[]] @())
    }
    $valueMember = $page.PSObject.Properties['value']
    if ($null -eq $valueMember) {
        return ,([object[]] @())
    }
    $values = @($valueMember.Value)
    foreach ($item in $values) {
        if ($null -eq $item) { continue }
        $item | Add-Member -NotePropertyName parentId -NotePropertyValue $ParentId -Force
    }
    return ,$values
}

function Get-LiveSnapshot {
    param([string] $Subscription)
    $listed = @(Invoke-AzJson -Required @(
            'resource', 'list',
            '--resource-group', $ResourceGroupName,
            '--subscription', $Subscription
        ))
    $detailTypes = @(
        'microsoft.operationalinsights/workspaces',
        'microsoft.network/publicipaddresses',
        'microsoft.network/applicationgatewaywebapplicationfirewallpolicies',
        'microsoft.network/virtualnetworks',
        'microsoft.network/applicationgateways',
        'microsoft.operationsmanagement/solutions',
        'microsoft.web/connections',
        'microsoft.logic/workflows',
        'microsoft.storage/storageaccounts',
        'microsoft.web/serverfarms',
        'microsoft.web/sites',
        'microsoft.insights/components'
    )
    $resources = foreach ($item in $listed) {
        $typeName = [string] $item.type
        if ($detailTypes -contains $typeName.ToLowerInvariant() -and [string] $item.id -notmatch '[()]') {
            $shown = Invoke-AzJson @(
                'resource', 'show',
                '--ids', [string] $item.id,
                '--subscription', $Subscription
            )
            if ($null -ne $shown) {
                Remove-CustomRuleValues -Resource $shown
                $shown
                continue
            }
        }
        [pscustomobject]@{
            id       = [string] $item.id
            name     = [string] $item.name
            type     = $typeName
            location = [string] $item.location
        }
    }
    $resources = @($resources)

    $workspace = Select-FirstType -Items $resources -TypeName 'Microsoft.OperationalInsights/workspaces'
    if ($null -ne $workspace) {
        $resources += Get-ChildResources -ParentId ([string] $workspace.id) -ProviderAndType 'Microsoft.SecurityInsights/alertRules' -ApiVersion '2024-01-01-preview'
        $resources += Get-ChildResources -ParentId ([string] $workspace.id) -ProviderAndType 'Microsoft.SecurityInsights/automationRules' -ApiVersion '2024-01-01-preview'
        $resources += Get-ChildResources -ParentId ([string] $workspace.id) -ProviderAndType 'Microsoft.SecurityInsights/watchlists' -ApiVersion '2024-01-01-preview'
        $resources += Get-ChildResources -ParentId ([string] $workspace.id) -ProviderAndType 'Microsoft.SecurityInsights/onboardingStates' -ApiVersion '2024-01-01-preview'
    }
    foreach ($parent in @($resources)) {
        if ($null -eq $parent) { continue }
        $typeName = ([string] $parent.type).ToLowerInvariant()
        if ($typeName -eq 'microsoft.network/applicationgateways' -or $typeName -eq 'microsoft.logic/workflows') {
            $resources += Get-ChildResources -ParentId ([string] $parent.id) -ProviderAndType 'Microsoft.Insights/diagnosticSettings' -ApiVersion '2021-05-01-preview'
        }
    }

    $roles = @{}
    $roles.resourceGroup = Get-RoleItems -Scope "/subscriptions/$Subscription/resourceGroups/$ResourceGroupName" -Subscription $Subscription
    foreach ($pair in @(
            @{ Key = 'wafPolicy'; Type = 'Microsoft.Network/applicationGatewayWebApplicationFirewallPolicies' },
            @{ Key = 'storage'; Type = 'Microsoft.Storage/storageAccounts' },
            @{ Key = 'appInsights'; Type = 'Microsoft.Insights/components' }
        )) {
        $target = Select-FirstType -Items $resources -TypeName $pair.Type
        if ($null -eq $target) {
            $roles[$pair.Key] = @{ ok = $false; items = @() }
        }
        else {
            $roles[$pair.Key] = Get-RoleItems -Scope ([string] $target.id) -Subscription $Subscription
        }
    }

    return [pscustomobject]@{
        namePrefix             = $NamePrefix
        location               = $Location
        subscriptionId         = $Subscription
        resourceGroup          = $ResourceGroupName
        existingWafPolicyName  = $ExistingWafPolicyName
        forceDeployTestWaf    = [bool] $DeployTestWaf
        functionSettingsRead   = $true
        resources              = @($resources)
        functionSettings       = @()
        roles                  = $roles
    }
}

function Write-DiffReport {
    param($Snapshot, [string] $ReportBaseName)
    $tempSnapshot = Join-Path ([System.IO.Path]::GetTempPath()) ("ase-snapshot-{0}.json" -f [guid]::NewGuid().ToString('n'))
    $reportPath = Join-Path $OutputDir "$ReportBaseName.json"
    try {
        if ($Snapshot -is [string]) {
            Copy-Item -LiteralPath $Snapshot -Destination $tempSnapshot -Force
        }
        else {
            $Snapshot | ConvertTo-Json -Depth 40 | Set-Content -LiteralPath $tempSnapshot -Encoding utf8NoBOM
        }
        & python (Join-Path $PSScriptRoot 'ase_diff.py') --profile $profilePath --snapshot $tempSnapshot --report $reportPath
        if ($LASTEXITCODE -ne 0) {
            throw 'ase_diff.py failed.'
        }
    }
    finally {
        Remove-Item -LiteralPath $tempSnapshot -Force -ErrorAction SilentlyContinue
    }
    $textPath = [System.IO.Path]::ChangeExtension($reportPath, '.txt')
    Write-Host (Get-Content -LiteralPath $textPath -Raw)
    return Get-Content -LiteralPath $reportPath -Raw | ConvertFrom-Json
}

function Get-PreservedCount {
    param($Report, [string] $Name)
    $item = @($Report.preserved) | Where-Object { [string] $_.name -eq $Name } | Select-Object -First 1
    if ($null -eq $item -or $null -eq $item.count) {
        return $null
    }
    return [int] $item.count
}

if (-not (Get-Command az -ErrorAction SilentlyContinue)) {
    throw 'Azure CLI (az) is not installed or not on PATH.'
}
if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    throw 'python is not installed or not on PATH.'
}

$subscription = $null
if ($SnapshotPath) {
    if (-not (Test-Path -LiteralPath $SnapshotPath)) {
        throw "Snapshot not found: $SnapshotPath"
    }
    $report = Write-DiffReport -Snapshot $SnapshotPath -ReportBaseName 'diff'
}
else {
    $subscription = Get-SubscriptionId
    $live = Get-LiveSnapshot -Subscription $subscription
    $report = Write-DiffReport -Snapshot $live -ReportBaseName 'diff'
}

Write-Host "Report directory: $OutputDir"

if ($Action -eq 'diff') {
    return
}

if ($report.deploy.refuse) {
    throw [string] $report.deploy.refuse
}
if ($report.deploy.deployTestWaf -and -not [string]::IsNullOrWhiteSpace([string] $report.deploy.existingWafPolicyName)) {
    throw 'Refusing to create the test WAF while an existing policy name is set.'
}

$deployTestWaf = [bool] $report.deploy.deployTestWaf
$policyName = [string] $report.deploy.existingWafPolicyName
Write-Host ("deploy.ps1 -DeployTestWaf {0} -ExistingWafPolicyName {1}" -f $deployTestWaf.ToString().ToLowerInvariant(), $policyName)
Write-Host 'Mode is the default incremental deployment. Complete is not used.'
if (-not $Apply) {
    Write-Host 'Deploy was not applied. Re-run with -Apply to call deploy.ps1.'
    return
}

$beforeBlock = Get-PreservedCount -Report $report -Name 'SentinelAutoBlock'
$beforeCapacity = Get-PreservedCount -Report $report -Name 'CapacityTestBlock'

$deployParams = @{
    SubscriptionId           = $(if ($subscription) { $subscription } else { $SubscriptionId })
    ResourceGroupName        = $ResourceGroupName
    Location                 = $Location
    NamePrefix               = $NamePrefix
    DeployTestWaf            = $deployTestWaf
    ExistingWafPolicyName    = $policyName
    AutoBlockEnabled         = $true
    OverrideProtectedRanges  = $false
}
& (Join-Path $PSScriptRoot 'deploy.ps1') @deployParams
if (-not $?) {
    throw 'deploy.ps1 failed.'
}

if (-not $SnapshotPath) {
    $afterLive = Get-LiveSnapshot -Subscription $subscription
    $after = Write-DiffReport -Snapshot $afterLive -ReportBaseName 'after'
    $afterBlock = Get-PreservedCount -Report $after -Name 'SentinelAutoBlock'
    $afterCapacity = Get-PreservedCount -Report $after -Name 'CapacityTestBlock'
    if ($null -ne $beforeBlock -and $beforeBlock -ne $afterBlock) {
        throw "SentinelAutoBlock count changed from $beforeBlock to $afterBlock."
    }
    if ($null -ne $beforeCapacity -and $beforeCapacity -ne $afterCapacity) {
        throw "CapacityTestBlock count changed from $beforeCapacity to $afterCapacity."
    }
}
