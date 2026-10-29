@description('Azure region of the Sentinel solution resource. Must match the workspace region.')
param location string

param workspaceName string

@description('Stable alias used by _GetWatchlist in the analytics rule.')
param watchlistAlias string

@description('CSV including the header row. Search key column is IPAddress.')
param allowlistCsv string

@description('ApplicationGateway or FrontDoor. Selects which KQL file is deployed.')
@allowed([
  'ApplicationGateway'
  'FrontDoor'
])
param wafProvider string

@description('Front Door log shape. Ignored for Application Gateway. ResourceSpecific is not configured by this repository.')
@allowed([
  'AzureDiagnostics'
  'ResourceSpecific'
])
param frontDoorLogDestination string

param blockRuleName string
param probeRuleName string
param probeMarker string

@minValue(1)
param detectionThreshold int

@description('Scheduled rule frequency in minutes. Sentinel minimum is 5. Must be less than or equal to queryLookbackMinutes.')
@minValue(5)
@maxValue(60)
param queryFrequencyMinutes int

@description('Observation window, in minutes. Must be greater than or equal to queryFrequencyMinutes.')
@minValue(5)
@maxValue(1440)
param queryLookbackMinutes int

@description('When true, the KQL does not drop built-in or watchlist ranges. The playbook has the same switch.')
param overrideProtectedRanges bool

param enableAnalyticsRule bool

param tags object

var analyticsRuleName = guid('ase-waf-malicious-source-ip', workspace.id)
var applicationGatewayQuery = loadTextContent('../../sentinel/analytics-rules/simulated-probe.application-gateway.kql')
var frontDoorDiagnosticsQuery = loadTextContent('../../sentinel/analytics-rules/simulated-probe.frontdoor.azurediagnostics.kql')
var frontDoorResourceSpecificQuery = loadTextContent('../../sentinel/analytics-rules/simulated-probe.frontdoor.resource-specific.kql')
var queryTemplate = wafProvider == 'FrontDoor'
  ? (frontDoorLogDestination == 'ResourceSpecific' ? frontDoorResourceSpecificQuery : frontDoorDiagnosticsQuery)
  : applicationGatewayQuery
var queryWithThreshold = replace(queryTemplate, '__THRESHOLD__', string(detectionThreshold))
var queryWithLookback = replace(queryWithThreshold, '__LOOKBACK__', '${queryLookbackMinutes}m')
var queryWithBlockRule = replace(queryWithLookback, '__BLOCK_RULE__', blockRuleName)
var queryWithProbeRule = replace(queryWithBlockRule, '__PROBE_RULE__', probeRuleName)
var queryWithProbeMarker = replace(queryWithProbeRule, '__PROBE_MARKER__', probeMarker)
var queryWithWatchlist = replace(queryWithProbeMarker, '__WATCHLIST__', watchlistAlias)
var analyticsQuery = replace(queryWithWatchlist, '__OVERRIDE_PROTECTED__', overrideProtectedRanges ? 'true' : 'false')

resource workspace 'Microsoft.OperationalInsights/workspaces@2023-09-01' existing = {
  name: workspaceName
}

resource sentinelSolution 'Microsoft.OperationsManagement/solutions@2015-11-01-preview' = {
  name: 'SecurityInsights(${workspaceName})'
  location: location
  tags: tags
  properties: {
    workspaceResourceId: workspace.id
  }
  plan: {
    name: 'SecurityInsights(${workspaceName})'
    publisher: 'Microsoft'
    product: 'OMSGallery/SecurityInsights'
    promotionCode: ''
  }
}

resource onboarding 'Microsoft.SecurityInsights/onboardingStates@2024-01-01-preview' = {
  name: 'default'
  scope: workspace
  dependsOn: [
    sentinelSolution
  ]
  properties: {
    customerManagedKey: false
  }
}

resource allowlist 'Microsoft.SecurityInsights/watchlists@2024-01-01-preview' = {
  name: watchlistAlias
  scope: workspace
  dependsOn: [
    onboarding
  ]
  properties: {
    displayName: 'ASE WAF protected IP ranges'
    watchlistAlias: watchlistAlias
    description: 'Built-in ranges plus the customer protectedIpRanges parameter. The analytics rule also hard-codes the built-in ranges, so editing this watchlist cannot remove loopback, RFC1918, link-local, CGNAT, or the Azure metadata address unless overrideProtectedRanges is true.'
    source: 'Local file'
    provider: 'ASE POC'
    itemsSearchKey: 'IPAddress'
    contentType: 'text/csv'
    numberOfLinesToSkip: 0
    rawContent: allowlistCsv
  }
}

resource analyticsRule 'Microsoft.SecurityInsights/alertRules@2024-01-01-preview' = {
  name: analyticsRuleName
  scope: workspace
  dependsOn: [
    onboarding
    allowlist
  ]
  kind: 'Scheduled'
  properties: {
    displayName: 'ASE POC - simulated WAF probe'
    description: 'POC only. This rule does not identify a malicious actor. It matches a deterministic simulated probe: WAF rows whose rule is ${probeRuleName} or whose request contains ${probeMarker}, at least ${detectionThreshold} times in the observation window. The ${blockRuleName} rule is excluded so a later block does not open another incident. Built-in protected ranges and the ${watchlistAlias} watchlist are excluded unless overrideProtectedRanges is true.'
    enabled: enableAnalyticsRule
    severity: 'Medium'
    query: analyticsQuery
    queryFrequency: 'PT${queryFrequencyMinutes}M'
    queryPeriod: 'PT${queryLookbackMinutes}M'
    triggerOperator: 'GreaterThan'
    triggerThreshold: 0
    suppressionEnabled: false
    suppressionDuration: 'PT1H'
    entityMappings: [
      {
        entityType: 'IP'
        fieldMappings: [
          {
            identifier: 'Address'
            columnName: 'ClientIp'
          }
        ]
      }
    ]
    customDetails: {
      EventCount: 'EventCountText'
      RuleIds: 'RuleIdList'
      Messages: 'MessageList'
      RequestUris: 'RequestUriList'
      Hosts: 'HostnameList'
      Actions: 'ActionList'
      FirstSeen: 'FirstSeenText'
      LastSeen: 'LastSeenText'
      ProbeMarker: 'ProbeMarkerText'
    }
    alertDetailsOverride: {
      alertDisplayNameFormat: 'ASE POC simulated WAF probe from {{ClientIp}}'
      // Sentinel allows at most three placeholders in the description.
      // Rule ids, requests, hosts, and timestamps stay on customDetails.
      alertDescriptionFormat: 'POC simulated probe, not an identified attacker. {{EventCountText}} matching WAF events from {{ClientIp}}. Actions: {{ActionList}}.'
    }
    eventGroupingSettings: {
      aggregationKind: 'AlertPerResult'
    }
    incidentConfiguration: {
      createIncident: true
      groupingConfiguration: {
        enabled: true
        reopenClosedIncident: false
        lookbackDuration: 'PT12H'
        matchingMethod: 'Selected'
        groupByEntities: [
          'IP'
        ]
        groupByAlertDetails: []
        groupByCustomDetails: []
      }
    }
  }
}

output analyticsRuleId string = analyticsRule.id
output analyticsRuleName string = analyticsRule.name
output watchlistAlias string = watchlistAlias
output detectionQueryKind string = wafProvider == 'FrontDoor'
  ? (frontDoorLogDestination == 'ResourceSpecific' ? 'FrontDoorResourceSpecific' : 'FrontDoorAzureDiagnostics')
  : 'ApplicationGatewayDedicated'
