# Deploys the ASE WAF -> Sentinel -> Function App block proof of concept.
# AUTO_BLOCK_ENABLED defaults to the JSON boolean true. Pass -AutoBlockEnabled $false for dry-run.
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
    # The playbook stops fail-closed when this is empty: no approver, no block.
    [ValidatePattern('^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$')]
    [string] $ApproverEmail = '',
    [ValidateSet('AzureDiagnostics', 'ResourceSpecific')]
    [string] $FrontDoorLogDestination = 'AzureDiagnostics',
    [ValidateSet('Prevention', 'Detection')]
    [string] $WafMode = 'Prevention',
    [bool] $AutoBlockEnabled = $true,
    # Accepted so an older command that still passes -ConfirmAutoBlock keeps working.
    # Blocking is the default and does not require this switch.
    [switch] $ConfirmAutoBlock,
    [bool] $OverrideProtectedRanges = $false,
    [switch] $ConfirmOverrideProtectedRanges,
    [string[]] $ProtectedIpRanges = @(),
    [ValidateRange(1, 500)]
    [int] $MaximumBlockEntries = 100,
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
if ($AutoBlockEnabled) {
    Write-Warning 'autoBlockEnabled is true. The next matching incident will PUT the WAF policy.'
}
else {
    Write-Warning 'autoBlockEnabled is false. This deployment stays in dry-run and does not PUT the WAF policy.'
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

function Publish-BlockFunction {
    param(
        [Parameter(Mandatory)]
        [string] $ResourceGroupName,
        [Parameter(Mandatory)]
        [string] $FunctionAppName,
        [Parameter(Mandatory)]
        [string] $RepoRoot
    )
    $stamp = [guid]::NewGuid().ToString('n')
    $stage = Join-Path ([System.IO.Path]::GetTempPath()) "ase-sentinel-poc-func-$stamp"
    $zip = Join-Path ([System.IO.Path]::GetTempPath()) "ase-sentinel-poc-func-$stamp.zip"
    $source = Join-Path $RepoRoot 'function-app'
    New-Item -ItemType Directory -Path $stage | Out-Null
    try {
        Copy-Item -Path (Join-Path $source 'function_app.py') -Destination $stage
        Copy-Item -Path (Join-Path $source 'host.json') -Destination $stage
        Copy-Item -Path (Join-Path $source 'sentinel_waf_block') -Destination (Join-Path $stage 'sentinel_waf_block') -Recurse
        $packages = Join-Path $stage '.python_packages\lib\site-packages'
        New-Item -ItemType Directory -Path $packages | Out-Null
        # Flex Consumption rejects Oryx app settings, so the Linux wheels are
        # installed here. The function runtime is Python 3.11.
        & python -m pip install --target $packages --requirement (Join-Path $source 'requirements.txt') --platform manylinux2014_x86_64 --python-version 3.11 --implementation cp --only-binary=:all: --upgrade --index-url 'https://packagefeedproxy.microsoft.io/pypi/simple/'
        if ($LASTEXITCODE -ne 0) {
            throw "pip install failed with exit code $LASTEXITCODE."
        }
        Get-ChildItem -Path $stage -Recurse -Directory -Filter '__pycache__' | Remove-Item -Recurse -Force
        Compress-Archive -Path (Join-Path $stage '*') -DestinationPath $zip
        Write-Host "Publishing Python workload to $FunctionAppName"
        # Flex rejects these. A site update does not always remove them, and if
        # they remain the package deploy is treated as a remote build and fails.
        & az functionapp config appsettings delete --resource-group $ResourceGroupName --name $FunctionAppName --setting-names SCM_DO_BUILD_DURING_DEPLOYMENT ENABLE_ORYX_BUILD --output none
        if ($LASTEXITCODE -ne 0) {
            throw 'Could not remove the Flex-unsupported build app settings.'
        }
        $deadline = (Get-Date).AddMinutes(8)
        do {
            & az functionapp deployment source config-zip --resource-group $ResourceGroupName --name $FunctionAppName --src $zip --timeout 600
            if ($LASTEXITCODE -eq 0) {
                break
            }
            if ((Get-Date) -ge $deadline) {
                throw "Azure CLI failed with exit code $LASTEXITCODE."
            }
            Write-Host 'Function zip deploy was rejected. Waiting 30 seconds before retrying.'
            Start-Sleep -Seconds 30
        } while ($true)
    }
    finally {
        Remove-Item -LiteralPath $stage -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $zip -Force -ErrorAction SilentlyContinue
    }
}

function Get-BlockFunctionKey {
    param(
        [Parameter(Mandatory)]
        [string] $ResourceGroupName,
        [Parameter(Mandatory)]
        [string] $FunctionAppName
    )
    $deadline = (Get-Date).AddMinutes(5)
    do {
        $key = az functionapp keys list --resource-group $ResourceGroupName --name $FunctionAppName --query 'functionKeys.default' --output tsv 2>$null
        if ($LASTEXITCODE -eq 0 -and -not [string]::IsNullOrWhiteSpace($key)) {
            return $key.Trim()
        }
        Start-Sleep -Seconds 15
    } while ((Get-Date) -lt $deadline)
    throw 'The Function App did not expose a default function key. The playbook stays fail-closed until this step succeeds.'
}

function Set-PlaybookFunctionBinding {
    param(
        [Parameter(Mandatory)]
        [string] $ResourceGroupName,
        [Parameter(Mandatory)]
        [string] $Location,
        [Parameter(Mandatory)]
        [string] $PlaybookName,
        [Parameter(Mandatory)]
        [string] $FunctionUrl,
        [Parameter(Mandatory)]
        [string] $FunctionKey,
        [Parameter(Mandatory)]
        [string] $WorkspaceResourceId,
        [Parameter(Mandatory)]
        [string] $ApproverEmail,
        [Parameter(Mandatory)]
        [string] $TemplateFile
    )
    $parameterFile = Join-Path ([System.IO.Path]::GetTempPath()) ("ase-sentinel-poc-bind-{0}.json" -f [guid]::NewGuid().ToString('n'))
    $payload = [ordered]@{
        '$schema' = 'https://schema.management.azure.com/schemas/2019-04-01/deploymentParameters.json#'
        contentVersion = '1.0.0.0'
        parameters = [ordered]@{
            location = @{ value = $Location }
            playbookName = @{ value = $PlaybookName }
            functionUrl = @{ value = $FunctionUrl }
            functionKey = @{ value = $FunctionKey }
            approverEmail = @{ value = $ApproverEmail }
            logAnalyticsWorkspaceId = @{ value = $WorkspaceResourceId }
            tags = @{
                value = @{
                    Customer = 'ASE'
                    Purpose = 'SentinelWafBlockPoc'
                    Environment = 'poc'
                    ManagedBy = 'bicep'
                }
            }
        }
    }
    $payload | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $parameterFile -Encoding utf8NoBOM
    try {
        Write-Host "az deployment group create --name ase-sentinel-poc-function-binding --resource-group $ResourceGroupName --template-file $TemplateFile --parameters <function key omitted>"
        & az deployment group create --name 'ase-sentinel-poc-function-binding' --resource-group $ResourceGroupName --template-file $TemplateFile --parameters "@$parameterFile" --output none
        if ($LASTEXITCODE -ne 0) {
            throw 'Azure CLI failed while binding the playbook to the function.'
        }
    }
    finally {
        Remove-Item -LiteralPath $parameterFile -Force -ErrorAction SilentlyContinue
    }
}

function Remove-PlaybookNetworkContributor {
    param(
        [Parameter(Mandatory)]
        [string] $PolicyId,
        [Parameter(Mandatory)]
        [string] $PrincipalId
    )
    Write-Host 'Removing Network Contributor from the playbook identity on the WAF policy. The function identity keeps that role.'
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

function Repair-JsonFlagAppSettings {
    param(
        [Parameter(Mandatory)]
        [string] $ResourceGroupName,
        [Parameter(Mandatory)]
        [string] $FunctionAppName,
        [Parameter(Mandatory)]
        [bool] $AutoBlockEnabled,
        [Parameter(Mandatory)]
        [bool] $OverrideProtectedRanges
    )
    $expectedAuto = if ($AutoBlockEnabled) { 'true' } else { 'false' }
    $expectedOverride = if ($OverrideProtectedRanges) { 'true' } else { 'false' }
    $subscriptionId = az account show --query id --output tsv
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($subscriptionId)) {
        throw 'Could not read the current subscription id.'
    }
    $subscriptionId = $subscriptionId.Trim()
    $root = Join-Path ([System.IO.Path]::GetTempPath()) ("ase-sentinel-poc-settings-{0}" -f [guid]::NewGuid().ToString('n'))
    New-Item -ItemType Directory -Path $root | Out-Null
    $pyPath = Join-Path $root 'repair.py'
    $listPath = Join-Path $root 'list.json'
    $bodyPath = Join-Path $root 'body.json'
    $statusPath = Join-Path $root 'status.json'
    $errPath = Join-Path $root 'az-error.txt'
    @'
import json
import sys

list_path, body_path, status_path, expected_auto, expected_override = sys.argv[1:6]
with open(list_path, encoding="utf-8-sig") as handle:
    items = json.load(handle)
if not isinstance(items, list):
    raise SystemExit(2)
props = {}
for item in items:
    if not isinstance(item, dict):
        raise SystemExit("app setting entry is not an object")
    name = item.get("name")
    value = item.get("value")
    if not isinstance(name, str) or name == "":
        raise SystemExit("app setting name is missing")
    if value is None:
        value = ""
    if not isinstance(value, str):
        raise SystemExit(name + " value is not a string")
    props[name] = value
required = (
    "AzureWebJobsStorage__accountName",
    "AzureWebJobsStorage__credential",
    "WAF_POLICY_RESOURCE_ID",
    "WAF_PROVIDER",
    "AUTO_BLOCK_ENABLED",
    "OVERRIDE_PROTECTED_RANGES",
    "BLOCK_RULE_NAME",
    "APPLICATIONINSIGHTS_CONNECTION_STRING",
    "APPLICATIONINSIGHTS_AUTHENTICATION_STRING",
)
missing = [name for name in required if props.get(name, "") == ""]
if missing:
    if len(props) < 8:
        raise SystemExit(2)
    raise SystemExit("missing app settings: " + ", ".join(missing))
if props["APPLICATIONINSIGHTS_AUTHENTICATION_STRING"] != "Authorization=AAD":
    raise SystemExit("APPLICATIONINSIGHTS_AUTHENTICATION_STRING is not Authorization=AAD")
changed = False
if props["AUTO_BLOCK_ENABLED"] != expected_auto:
    props["AUTO_BLOCK_ENABLED"] = expected_auto
    changed = True
if props["OVERRIDE_PROTECTED_RANGES"] != expected_override:
    props["OVERRIDE_PROTECTED_RANGES"] = expected_override
    changed = True
with open(body_path, "w", encoding="utf-8", newline="\n") as handle:
    json.dump({"properties": props}, handle, ensure_ascii=True)
    handle.write("\n")
with open(status_path, "w", encoding="utf-8", newline="\n") as handle:
    json.dump(
        {
            "changed": changed,
            "count": len(props),
            "auto": props["AUTO_BLOCK_ENABLED"],
            "override": props["OVERRIDE_PROTECTED_RANGES"],
        },
        handle,
    )
    handle.write("\n")
'@ | Set-Content -LiteralPath $pyPath -Encoding utf8NoBOM
    try {
        $status = $null
        $deadline = (Get-Date).AddMinutes(3)
        do {
            & az functionapp config appsettings list --resource-group $ResourceGroupName --name $FunctionAppName --output json |
                Set-Content -LiteralPath $listPath -Encoding utf8NoBOM
            if ($LASTEXITCODE -ne 0) {
                throw 'Could not list Function App settings.'
            }
            & python $pyPath $listPath $bodyPath $statusPath $expectedAuto $expectedOverride
            if ($LASTEXITCODE -eq 0) {
                $status = Get-Content -LiteralPath $statusPath -Raw | ConvertFrom-Json
                break
            }
            if ($LASTEXITCODE -ne 2 -or (Get-Date) -ge $deadline) {
                throw 'Function App settings are missing Application Insights or the JSON block flags. The values were not printed.'
            }
            Write-Host 'Function App settings are not ready. Waiting 15 seconds before reading them again.'
            Start-Sleep -Seconds 15
        } while ($true)
        Write-Host "App settings: count=$($status.count) AUTO_BLOCK_ENABLED=$($status.auto) OVERRIDE_PROTECTED_RANGES=$($status.override) ApplicationInsights=connected"
        if (-not $status.changed) {
            return $false
        }
        $uri = "https://management.azure.com/subscriptions/$subscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.Web/sites/$FunctionAppName/config/appsettings?api-version=2024-04-01"
        Write-Host 'Rewriting AUTO_BLOCK_ENABLED and OVERRIDE_PROTECTED_RANGES as the JSON tokens true or false.'
        $verified = $null
        $readBackDeadline = (Get-Date).AddMinutes(2)
        & az rest --method put --uri $uri --body "@$bodyPath" --output none 2>$errPath
        if ($LASTEXITCODE -ne 0) {
            throw "Updating Function App settings failed with exit code $LASTEXITCODE. The response was not printed."
        }
        do {
            & az functionapp config appsettings list --resource-group $ResourceGroupName --name $FunctionAppName --output json |
                Set-Content -LiteralPath $listPath -Encoding utf8NoBOM
            if ($LASTEXITCODE -ne 0) {
                throw 'Could not read Function App settings after the update.'
            }
            & python $pyPath $listPath $bodyPath $statusPath $expectedAuto $expectedOverride
            if ($LASTEXITCODE -eq 0) {
                $verified = Get-Content -LiteralPath $statusPath -Raw | ConvertFrom-Json
                if (-not $verified.changed) {
                    break
                }
            }
            elseif ($LASTEXITCODE -ne 2) {
                throw 'Function App settings did not read back after the update.'
            }
            if ((Get-Date) -ge $readBackDeadline) {
                $autoText = if ($verified) { $verified.auto } else { 'unread' }
                $overrideText = if ($verified) { $verified.override } else { 'unread' }
                throw "AUTO_BLOCK_ENABLED read back as '$autoText' and OVERRIDE_PROTECTED_RANGES read back as '$overrideText'. Expected $expectedAuto and $expectedOverride."
            }
            Start-Sleep -Seconds 10
        } while ($true)
        Write-Host "App settings verified: AUTO_BLOCK_ENABLED=$($verified.auto) OVERRIDE_PROTECTED_RANGES=$($verified.override)"
        return $true
    }
    finally {
        Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
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

# Bicep owns the app settings list, so a main deployment resets every setting
# that is not in the template. Capture the Teams notifier URL first so it can
# be restored after the deployment when -NotifyTeamsUrl is not passed.
$preservedNotifyUrl = ''
if (-not $WhatIf) {
    $prevFn = az deployment group show --name 'ase-sentinel-poc-main' --resource-group $ResourceGroupName --query 'properties.outputs.functionAppName.value' --output tsv 2>$null
    if ($LASTEXITCODE -eq 0 -and -not [string]::IsNullOrWhiteSpace($prevFn)) {
        $captured = az functionapp config appsettings list --resource-group $ResourceGroupName --name $prevFn --query "[?name=='NOTIFY_TEAMS_URL'].value" --output tsv 2>$null
        if ($LASTEXITCODE -eq 0 -and -not [string]::IsNullOrWhiteSpace($captured)) {
            $preservedNotifyUrl = $captured.Trim()
        }
    }
}

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
        "maximumBlockEntries=$MaximumBlockEntries",
        "detectionThreshold=$DetectionThreshold",
        "queryFrequencyMinutes=$QueryFrequencyMinutes",
        "queryLookbackMinutes=$QueryLookbackMinutes",
        "probeMarker=$ProbeMarker",
        "probeRuleName=$ProbeRuleName",
        "probeRulePriority=$ProbeRulePriority",
        "blockRuleName=$BlockRuleName",
        "blockRulePriority=$BlockRulePriority",
        "notifyEvents=$NotifyEvents",
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
    if ([string]::IsNullOrWhiteSpace($mainOutputs.functionAppName.value) -or [string]::IsNullOrWhiteSpace($mainOutputs.functionUrl.value)) {
        throw 'The main deployment did not return the Function App name and URL.'
    }
    Publish-BlockFunction -ResourceGroupName $ResourceGroupName -FunctionAppName $mainOutputs.functionAppName.value -RepoRoot $repoRoot
    $rewritten = Repair-JsonFlagAppSettings `
        -ResourceGroupName $ResourceGroupName `
        -FunctionAppName $mainOutputs.functionAppName.value `
        -AutoBlockEnabled $AutoBlockEnabled `
        -OverrideProtectedRanges $OverrideProtectedRanges
    if ($rewritten) {
        Write-Host 'Restarting the Function App so the worker loads the corrected JSON settings.'
        Invoke-AzCli @('functionapp', 'restart', '--resource-group', $ResourceGroupName, '--name', $mainOutputs.functionAppName.value)
    }
    $notifyUrl = $NotifyTeamsUrl
    if (-not $notifyUrl) {
        $notifyUrl = $preservedNotifyUrl
    }
    if ($notifyUrl) {
        # The Workflows URL is not a template parameter, so it stays out of the
        # deployment history. Direct call, not Invoke-AzCli, which echoes the
        # command line. The new direct/cu triggers require an Entra token, so
        # NOTIFY_TEAMS_AUTH=entra makes the notifier send the managed identity
        # token for https://service.flow.microsoft.com/.
        Write-Host 'Storing the Teams Workflows URL as an app setting. The value is not printed.'
        & az functionapp config appsettings set `
            --resource-group $ResourceGroupName `
            --name $mainOutputs.functionAppName.value `
            --settings "NOTIFY_TEAMS_URL=$notifyUrl" "NOTIFY_TEAMS_AUTH=entra" `
            --output none
        if ($LASTEXITCODE -ne 0) {
            throw 'Could not set the Teams notifier app settings. Notifications stay silent until they are set.'
        }
    }
    $functionKey = Get-BlockFunctionKey -ResourceGroupName $ResourceGroupName -FunctionAppName $mainOutputs.functionAppName.value
    Set-PlaybookFunctionBinding `
        -ResourceGroupName $ResourceGroupName `
        -Location $Location `
        -PlaybookName $mainOutputs.playbookName.value `
        -FunctionUrl $mainOutputs.functionUrl.value `
        -FunctionKey $functionKey `
        -WorkspaceResourceId $mainOutputs.workspaceResourceId.value `
        -ApproverEmail $ApproverEmail `
        -TemplateFile (Join-Path $infra 'modules\playbook.bicep')
    Remove-PlaybookNetworkContributor -PolicyId $mainOutputs.wafPolicyId.value -PrincipalId $mainOutputs.playbookPrincipalId.value
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
Write-Host "Playbook:            $($shown.playbookName.value)"
if ($shown.PSObject.Properties.Name -contains 'functionAppName' -and $shown.functionAppName.value) {
    Write-Host "Function:            $($shown.functionAppName.value)"
}
if ($shown.PSObject.Properties.Name -contains 'appInsightsName' -and $shown.appInsightsName.value) {
    Write-Host "Application Insights: $($shown.appInsightsName.value)"
}
Write-Host "autoBlockEnabled:    $($shown.autoBlockEnabled.value)"
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
if ($shown.autoBlockEnabled.value -eq $true) {
    Write-Host 'Blocking is enabled. A matching incident can change the WAF policy.'
    Write-Host 'To return to dry-run, redeploy with -AutoBlockEnabled $false and the same resource group and name prefix.'
}
else {
    Write-Host 'Dry-run is active. A matching incident records "Would block IP: <address>" and does not change the WAF policy.'
}
Write-Host 'Cleanup: ./scripts/cleanup.ps1 -ResourceGroupName' $ResourceGroupName
Write-Host 'Incident latency is usually 10 to 15 minutes: ingestion plus the analytics schedule.'
Write-Host 'The procedure is in docs/testing.md.'
