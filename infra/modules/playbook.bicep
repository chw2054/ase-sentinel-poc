@description('Azure region for the Logic App and the Sentinel API connection.')
param location string

@description('Logic App workflow name. Sentinel shows this name as the playbook.')
param playbookName string

@description('HTTPS URL of POST /api/SentinelWafAutoBlock on the operations web app. Empty keeps the playbook from calling it. The workflow parameter name stays functionUrl.')
param functionUrl string

@description('Value of the web app setting BLOCK_API_KEY, sent as x-functions-key. Empty fails the HTTP call. The playbook does not log this value. The workflow parameter name stays functionKey.')
@secure()
param functionKey string

@description('Workspace resource id for playbook runtime logs.')
param logAnalyticsWorkspaceId string

@description('Approver for the Teams/email approval card. Empty stops the playbook before evaluation, fail-closed.')
param approverEmail string

param tags object

var connectionName = 'azuresentinel-${playbookName}'
var o365ConnectionName = 'office365-${playbookName}'
var sentinelResponderRoleId = '3e150937-b8fe-4cfb-8069-0eaf05ecd056'

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

resource office365Connection 'Microsoft.Web/connections@2016-06-01' = {
  name: o365ConnectionName
  location: location
  kind: 'V1'
  tags: tags
  properties: {
    displayName: o365ConnectionName
    api: {
      id: subscriptionResourceId('Microsoft.Web/locations/managedApis', location, 'office365')
    }
    // The office365 connector does not accept a managed identity and rejects
    // parameterValueType 'Alternative'. An operator must open this connection
    // in the portal once and choose Authorize with the approver's account
    // before the approval card can be delivered.
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
    definition: loadJsonContent('../../playbooks/block-malicious-ip/thin-workflow.json')
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
          office365: {
            connectionId: office365Connection.id
            connectionName: office365Connection.name
            id: subscriptionResourceId('Microsoft.Web/locations/managedApis', location, 'office365')
          }
        }
      }
      functionUrl: {
        value: functionUrl
      }
      functionKey: {
        value: functionKey
      }
      approverEmail: {
        value: approverEmail
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
    description: 'Lets the playbook read incident IP entities and comment when the block API call does not finish.'
  }
}

output playbookName string = playbook.name
output playbookResourceId string = playbook.id
output principalId string = playbook.identity.principalId
