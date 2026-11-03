using '../main.bicep'

param namePrefix = 'ase-sentinel-poc'
param wafProvider = 'ApplicationGateway'
param deployTestWaf = true
param frontDoorLogDestination = 'AzureDiagnostics'
param wafMode = 'Prevention'
param autoBlockEnabled = true
param overrideProtectedRanges = false
param protectedIpRanges = []
param detectionThreshold = 3
param queryFrequencyMinutes = 5
param queryLookbackMinutes = 30
param probeMarker = 'ase-poc-probe'
param probeRuleName = 'PocSimulatedProbe'
param probeRulePriority = 50
param blockRuleName = 'SentinelAutoBlock'
param appGatewayMinCapacity = 1
param appGatewayMaxCapacity = 2
