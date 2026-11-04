@description('Azure region for the Logic App and the Sentinel API connection.')
param location string

@description('Logic App workflow name. Sentinel shows this name as the playbook.')
param playbookName string

@description('ARM id of the one WAF policy this playbook reads and, when autoBlockEnabled is true, writes.')
param wafPolicyResourceId string

@description('ApplicationGateway or FrontDoor. The expression workflow rejects any other value and does not PUT.')
param wafProvider string

@description('Customer ranges the expression workflow must not block, in addition to the ranges it rejects in the workflow itself.')
param protectedIpRanges array

@description('true PUTs the block rule with no approval email. false comments and does not PUT.')
param autoBlockEnabled bool

@description('Skips the protected-range filter in the expression workflow. Invalid addresses are still rejected.')
param overrideProtectedRanges bool

param blockRuleName string
param blockRulePriority int

@description('Workspace resource id for playbook runtime logs.')
param logAnalyticsWorkspaceId string

param tags object

var connectionName = 'azuresentinel-${playbookName}'
var sentinelResponderRoleId = '3e150937-b8fe-4cfb-8069-0eaf05ecd056'
var armApiVersion = wafProvider == 'FrontDoor' ? '2024-02-01' : '2024-05-01'

resource sentinelConnection 'Microsoft.Web/connections@2016-06-01' = {
  name: connectionName
  location: location
  kind: 'V1'
  tags: tags
  properties: {
    displayName: connectionName
    api: {
      id: subscriptionResourceId('Microsoft.Web/locations/managedApis', location, 'azuresentinel')
    }
    customParameterValues: {}
    // Alternative plus ManagedServiceIdentity on the workflow is the managed-identity
    // Sentinel connection. No user OAuth secret is stored.
    parameterValueType: 'Alternative'
  }
}

resource playbook 'Microsoft.Logic/workflows@2019-05-01' = {
  name: playbookName
  location: location
  tags: tags
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    state: 'Enabled'
    definition: loadJsonContent('../../playbooks/block-malicious-ip/workflow.json')
    parameters: {
      '$connections': {
        value: {
          azuresentinel: {
            connectionId: sentinelConnection.id
            connectionName: sentinelConnection.name
            id: subscriptionResourceId('Microsoft.Web/locations/managedApis', location, 'azuresentinel')
            connectionProperties: {
              authentication: {
                type: 'ManagedServiceIdentity'
              }
            }
          }
        }
      }
      wafPolicyResourceId: {
        value: wafPolicyResourceId
      }
      wafProvider: {
        value: wafProvider
      }
      protectedIpRanges: {
        value: protectedIpRanges
      }
      autoBlockEnabled: {
        value: autoBlockEnabled
      }
      overrideProtectedRanges: {
        value: overrideProtectedRanges
      }
      blockRuleName: {
        value: blockRuleName
      }
      blockRulePriority: {
        value: blockRulePriority
      }
      armApiVersion: {
        value: armApiVersion
      }
    }
  }
}

resource playbookDiagnostics 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  name: 'diag-playbook-runtime'
  scope: playbook
  properties: {
    workspaceId: logAnalyticsWorkspaceId
    logs: [
      {
        category: 'WorkflowRuntime'
        enabled: true
      }
    ]
    metrics: [
      {
        category: 'AllMetrics'
        enabled: true
      }
    ]
  }
}

resource sentinelResponder 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(resourceGroup().id, playbook.id, sentinelResponderRoleId)
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', sentinelResponderRoleId)
    principalId: playbook.identity.principalId
    principalType: 'ServicePrincipal'
    description: 'Lets the full playbook read incident IP entities and write the decision comment. Network Contributor on the WAF policy is a separate assignment.'
  }
}

output playbookName string = playbook.name
output playbookResourceId string = playbook.id
output principalId string = playbook.identity.principalId
