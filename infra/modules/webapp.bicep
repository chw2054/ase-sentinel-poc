// App Service for the operations Web App.
// This module is not referenced by infra/main.bicep.
// Do not deploy it onto the live resource group. Its appSettings list is not the live bag.
// It does not deploy the playbook, the Function, the WAF policy, or Azure SQL.
// The Web App keeps regional VNet integration on snet-app. That subnet is not a SQL endpoint.
targetScope = 'resourceGroup'

@description('Globally unique App Service name.')
param appName string

param location string = resourceGroup().location

@secure()
param appSecret string

param pocAdminUsers string = ''

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
        { name: 'APP_SECRET', value: appSecret }
        { name: 'POC_ADMIN_USERS', value: pocAdminUsers }
        { name: 'SCM_DO_BUILD_DURING_DEPLOYMENT', value: 'true' }
        { name: 'WEBSITES_PORT', value: '8000' }
        { name: 'WEBSITE_VNET_ROUTE_ALL', value: '1' }
      ]
    }
    virtualNetworkSubnetId: appSubnetId
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
    ]
  }
}

var appSubnetId = '${vnet.id}/subnets/snet-app'

output principalId string = app.identity.principalId
output hostName string = app.properties.defaultHostName
