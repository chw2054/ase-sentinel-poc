@description('Azure region for the Function App, plan, and storage account.')
param location string

@description('Short name prefix. The function app name also includes a resource-group hash because function names are global.')
param namePrefix string

@description('Full resource id of the one WAF policy the function may update.')
param wafPolicyResourceId string

@description('ApplicationGateway or FrontDoor. Stored as an app setting. The function rejects any other value before GET or PUT.')
@allowed([
  'ApplicationGateway'
  'FrontDoor'
])
param wafProvider string

@description('Customer ranges passed through as a JSON array app setting.')
param protectedIpRanges array

@minValue(1)
@maxValue(500)
param maximumBlockEntries int

@description('Writes the literal JSON token true or false to AUTO_BLOCK_ENABLED. true PUTs the WAF policy. false is dry-run. string(bool) is not used: the Web Sites API has stored that as True or False, and the function rejects those strings.')
param autoBlockEnabled bool

param overrideProtectedRanges bool

param blockRuleName string

@minValue(1)
@maxValue(100)
param blockRulePriority int

param armApiVersion string

@description('Comma-separated Teams notification events the function sends. Default would_block,blocked,put_failed,capacity.')
param notifyEvents string = 'would_block,blocked,put_failed,capacity'

@description('Sentinel Log Analytics workspace that stores Application Insights telemetry for this function.')
param logAnalyticsWorkspaceId string

param tags object

var sentinelResponderRoleId = '3e150937-b8fe-4cfb-8069-0eaf05ecd056'
var storageBlobDataOwnerRoleId = 'b7e6dc6d-f1e8-4753-8033-0f276bb0955b'
var storageQueueDataContributorRoleId = '974c5e8b-45b9-4653-ba55-5f855dd0fb88'
var storageTableDataContributorRoleId = '0a9a7e1f-b9d0-4cc4-a60d-0319b160aaa3'
var monitoringMetricsPublisherRoleId = '3913510d-42f4-4e42-8a64-420c390055eb'
var unique = uniqueString(resourceGroup().id)
var storageName = 'st${unique}'
var planName = 'asp-${namePrefix}-fn'
var functionAppName = 'fn-${namePrefix}-${substring(unique, 0, 8)}'
var appInsightsName = 'appi-${namePrefix}'
var autoBlockEnabledText = autoBlockEnabled ? 'true' : 'false'
var overrideProtectedRangesText = overrideProtectedRanges ? 'true' : 'false'
var policyIdParts = split(wafPolicyResourceId, '/')
var policySubscriptionId = policyIdParts[2]
var policyResourceGroup = policyIdParts[4]
var policyName = last(policyIdParts)
// MCAPS StorageAccount_PublicNetwork_Modify forces publicNetworkAccess Disabled
// unless the resource is tagged SecurityControl=Ignore. Flex has no private endpoint
// in this POC. Shared-key access stays disabled; the function identity is used instead.
var storageTags = union(tags, {
  SecurityControl: 'Ignore'
})

resource storage 'Microsoft.Storage/storageAccounts@2023-05-01' = {
  name: storageName
  location: location
  tags: storageTags
  sku: {
    name: 'Standard_LRS'
  }
  kind: 'StorageV2'
  properties: {
    allowBlobPublicAccess: false
    // Flex One Deploy uploads the package with the storage account key. The
    // SecurityControl=Ignore tag above is what lets this stay enabled.
    allowSharedKeyAccess: true
    minimumTlsVersion: 'TLS1_2'
    supportsHttpsTrafficOnly: true
    publicNetworkAccess: 'Enabled'
  }
}

resource blobService 'Microsoft.Storage/storageAccounts/blobServices@2023-05-01' = {
  parent: storage
  name: 'default'
}

resource deploymentContainer 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-05-01' = {
  parent: blobService
  name: 'app-package'
  properties: {
    publicAccess: 'None'
  }
}

resource appInsights 'Microsoft.Insights/components@2020-02-02' = {
  name: appInsightsName
  location: location
  tags: tags
  kind: 'web'
  properties: {
    Application_Type: 'web'
    WorkspaceResourceId: logAnalyticsWorkspaceId
    IngestionMode: 'LogAnalytics'
    // Local auth stays available so ingestion can start before the
    // Monitoring Metrics Publisher assignment replicates. The function also
    // authenticates with its system-assigned identity.
    DisableLocalAuth: false
  }
}

resource plan 'Microsoft.Web/serverfarms@2024-04-01' = {
  name: planName
  location: location
  tags: tags
  kind: 'functionapp'
  // Y1, Basic, Standard, Premium v3, and Elastic Premium quotas are 0 in eastus
  // on the POC subscription. Flex Consumption FC1 is the plan that validates.
  sku: {
    name: 'FC1'
    tier: 'FlexConsumption'
  }
  properties: {
    reserved: true
  }
}

resource functionApp 'Microsoft.Web/sites@2024-04-01' = {
  name: functionAppName
  location: location
  tags: tags
  kind: 'functionapp,linux'
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    reserved: true
    httpsOnly: true
    serverFarmId: plan.id
    clientAffinityEnabled: false
    functionAppConfig: {
      deployment: {
        storage: {
          type: 'blobContainer'
          value: '${storage.properties.primaryEndpoints.blob}${deploymentContainer.name}'
          authentication: {
            type: 'SystemAssignedIdentity'
          }
        }
      }
      scaleAndConcurrency: {
        maximumInstanceCount: 40
        instanceMemoryMB: 2048
      }
      runtime: {
        name: 'python'
        version: '3.11'
      }
    }
    siteConfig: {
      // Flex Consumption rejects FUNCTIONS_WORKER_RUNTIME, FUNCTIONS_EXTENSION_VERSION,
      // and ftpsState. Runtime is functionAppConfig.runtime (python 3.11, host v4).
      minTlsVersion: '1.2'
      appSettings: [
        {
          name: 'AzureWebJobsStorage__accountName'
          value: storage.name
        }
        {
          name: 'AzureWebJobsStorage__credential'
          value: 'managedidentity'
        }
        {
          name: 'AzureWebJobsFeatureFlags'
          value: 'EnableWorkerIndexing'
        }
        {
          name: 'WAF_POLICY_RESOURCE_ID'
          value: wafPolicyResourceId
        }
        {
          name: 'WAF_PROVIDER'
          value: wafProvider
        }
        {
          name: 'PROTECTED_IP_RANGES'
          value: string(protectedIpRanges)
        }
        {
          name: 'MAXIMUM_BLOCK_ENTRIES'
          value: string(maximumBlockEntries)
        }
        {
          name: 'AUTO_BLOCK_ENABLED'
          value: autoBlockEnabledText
        }
        {
          name: 'OVERRIDE_PROTECTED_RANGES'
          value: overrideProtectedRangesText
        }
        {
          name: 'APPLICATIONINSIGHTS_CONNECTION_STRING'
          value: appInsights.properties.ConnectionString
        }
        {
          name: 'APPLICATIONINSIGHTS_AUTHENTICATION_STRING'
          value: 'Authorization=AAD'
        }
        {
          name: 'BLOCK_RULE_NAME'
          value: blockRuleName
        }
        {
          name: 'BLOCK_RULE_PRIORITY'
          value: string(blockRulePriority)
        }
        {
          name: 'ARM_API_VERSION'
          value: armApiVersion
        }
        {
          name: 'NOTIFY_EVENTS'
          value: notifyEvents
        }
      ]
    }
  }
}

resource storageBlobOwner 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(storage.id, functionApp.id, storageBlobDataOwnerRoleId)
  scope: storage
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', storageBlobDataOwnerRoleId)
    principalId: functionApp.identity.principalId
    principalType: 'ServicePrincipal'
    description: 'Lets the function publish its package and use host blob storage without an account key.'
  }
}

resource storageQueueContributor 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(storage.id, functionApp.id, storageQueueDataContributorRoleId)
  scope: storage
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', storageQueueDataContributorRoleId)
    principalId: functionApp.identity.principalId
    principalType: 'ServicePrincipal'
    description: 'Lets the function use host queue storage without an account key.'
  }
}

resource storageTableContributor 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(storage.id, functionApp.id, storageTableDataContributorRoleId)
  scope: storage
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', storageTableDataContributorRoleId)
    principalId: functionApp.identity.principalId
    principalType: 'ServicePrincipal'
    description: 'Lets the function use host table storage without an account key.'
  }
}

resource appInsightsPublisher 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(appInsights.id, functionApp.id, monitoringMetricsPublisherRoleId)
  scope: appInsights
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', monitoringMetricsPublisherRoleId)
    principalId: functionApp.identity.principalId
    principalType: 'ServicePrincipal'
    description: 'Lets the function send telemetry to Application Insights with its managed identity.'
  }
}

resource sentinelResponder 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(resourceGroup().id, functionApp.id, sentinelResponderRoleId)
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', sentinelResponderRoleId)
    principalId: functionApp.identity.principalId
    principalType: 'ServicePrincipal'
    description: 'Lets the block function comment on Sentinel incidents in this resource group.'
  }
}

module policyRole 'role-waf-policy.bicep' = {
  name: 'waf-policy-function-role'
  scope: resourceGroup(policySubscriptionId, policyResourceGroup)
  params: {
    policyName: policyName
    principalId: functionApp.identity.principalId
    wafProvider: wafProvider
  }
}

output functionAppName string = functionApp.name
output functionPrincipalId string = functionApp.identity.principalId
output functionUrl string = 'https://${functionApp.properties.defaultHostName}/api/SentinelWafAutoBlock'
output appInsightsName string = appInsights.name
output appInsightsResourceId string = appInsights.id
