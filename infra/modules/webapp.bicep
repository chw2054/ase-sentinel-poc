// App Service and its own Azure SQL database for the operations Web App.
// This module is not referenced by infra/main.bicep.
// It does not deploy the playbook, the Function, or the WAF policy.
// Azure SQL is Entra-only and has no public endpoint. The Web App reaches it
// through a private endpoint. Its managed identity is the Entra admin.
targetScope = 'resourceGroup'

@description('Globally unique App Service name. The SQL server name is this value plus -sql.')
param appName string

param location string = resourceGroup().location

@secure()
param appSecret string

@secure()
param integrationApiKey string

param sqlDatabaseName string = 'aseops'
param publicBaseUrl string
param approverEmail string
param pocAdminUsers string = ''
param maximumBlockEntries int = 100
param seedFixture string = 'true'

var sqlServerName = '${appName}-sql'
var databaseUrl = 'mssql+mssqlpython://@${sqlServerName}.database.windows.net:1433/${sqlDatabaseName}?authentication=ActiveDirectoryDefault&encrypt=yes'

resource plan 'Microsoft.Web/serverfarms@2023-12-01' = {
  name: '${appName}-plan'
  location: location
  sku: {
    name: 'P0v3'
    tier: 'Premium0V3'
    capacity: 1
  }
  kind: 'linux'
  properties: {
    reserved: true
  }
}

resource app 'Microsoft.Web/sites@2023-12-01' = {
  name: appName
  location: location
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    serverFarmId: plan.id
    httpsOnly: true
    siteConfig: {
      linuxFxVersion: 'PYTHON|3.11'
      ftpsState: 'Disabled'
      minTlsVersion: '1.2'
      appCommandLine: 'gunicorn -k uvicorn.workers.UvicornWorker -w 1 -b 0.0.0.0:8000 app.main:app'
      healthCheckPath: '/health'
      vnetRouteAllEnabled: true
      appSettings: [
        { name: 'APP_ENV', value: 'production' }
        { name: 'DATABASE_URL', value: databaseUrl }
        { name: 'APP_SECRET', value: appSecret }
        { name: 'INTEGRATION_API_KEY', value: integrationApiKey }
        { name: 'PUBLIC_BASE_URL', value: publicBaseUrl }
        { name: 'APPROVER_EMAIL', value: approverEmail }
        { name: 'POC_ADMIN_USERS', value: pocAdminUsers }
        { name: 'MAXIMUM_BLOCK_ENTRIES', value: string(maximumBlockEntries) }
        { name: 'REQUIRE_APPROVAL', value: 'true' }
        { name: 'SEED_FIXTURE', value: seedFixture }
        { name: 'SCM_DO_BUILD_DURING_DEPLOYMENT', value: 'true' }
        { name: 'WEBSITES_PORT', value: '8000' }
        { name: 'WEBSITE_VNET_ROUTE_ALL', value: '1' }
        { name: 'WEBSITE_DNS_SERVER', value: '168.63.129.16' }
      ]
    }
    virtualNetworkSubnetId: appSubnetId
  }
}

resource sql 'Microsoft.Sql/servers@2023-08-01-preview' = {
  name: sqlServerName
  location: location
  properties: {
    minimalTlsVersion: '1.2'
    publicNetworkAccess: 'Disabled'
    administrators: {
      administratorType: 'ActiveDirectory'
      principalType: 'Application'
      login: app.name
      sid: app.identity.principalId
      tenantId: subscription().tenantId
      azureADOnlyAuthentication: true
    }
  }
}

resource database 'Microsoft.Sql/servers/databases@2023-08-01-preview' = {
  parent: sql
  name: sqlDatabaseName
  location: location
  sku: {
    name: 'Basic'
    tier: 'Basic'
    capacity: 5
  }
  properties: {
    collation: 'SQL_Latin1_General_CP1_CI_AS'
  }
}

resource vnet 'Microsoft.Network/virtualNetworks@2023-11-01' = {
  name: 'vnet-${appName}'
  location: location
  properties: {
    addressSpace: {
      addressPrefixes: [
        '10.51.0.0/16'
      ]
    }
    subnets: [
      {
        name: 'snet-app'
        properties: {
          addressPrefix: '10.51.1.0/24'
          delegations: [
            {
              name: 'web'
              properties: {
                serviceName: 'Microsoft.Web/serverFarms'
              }
            }
          ]
        }
      }
      {
        name: 'snet-private-endpoint'
        properties: {
          addressPrefix: '10.51.2.0/24'
          privateEndpointNetworkPolicies: 'Disabled'
        }
      }
    ]
  }
}

var appSubnetId = '${vnet.id}/subnets/snet-app'
var privateEndpointSubnetId = '${vnet.id}/subnets/snet-private-endpoint'

resource sqlDns 'Microsoft.Network/privateDnsZones@2020-06-01' = {
  name: 'privatelink.database.windows.net'
  location: 'global'
}

resource sqlDnsLink 'Microsoft.Network/privateDnsZones/virtualNetworkLinks@2020-06-01' = {
  parent: sqlDns
  name: 'link-${appName}'
  location: 'global'
  properties: {
    registrationEnabled: false
    virtualNetwork: {
      id: vnet.id
    }
  }
}

resource sqlEndpoint 'Microsoft.Network/privateEndpoints@2023-11-01' = {
  name: 'pe-${sqlServerName}'
  location: location
  properties: {
    subnet: {
      id: privateEndpointSubnetId
    }
    privateLinkServiceConnections: [
      {
        name: 'sql'
        properties: {
          privateLinkServiceId: sql.id
          groupIds: [
            'sqlServer'
          ]
        }
      }
    ]
  }
}

resource sqlEndpointDns 'Microsoft.Network/privateEndpoints/privateDnsZoneGroups@2023-11-01' = {
  parent: sqlEndpoint
  name: 'sql'
  properties: {
    privateDnsZoneConfigs: [
      {
        name: 'sql'
        properties: {
          privateDnsZoneId: sqlDns.id
        }
      }
    ]
  }
  dependsOn: [
    sqlDnsLink
  ]
}

output principalId string = app.identity.principalId
output hostName string = app.properties.defaultHostName
output sqlServerName string = sql.name
