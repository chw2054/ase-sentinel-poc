# Local checks for protected-range canonicalization. No Azure connection.
. (Join-Path $PSScriptRoot 'ip-ranges.ps1')

$failures = [System.Collections.Generic.List[string]]::new()

function Assert-Equal {
    param($Name, $Actual, $Expected)
    if ($Actual -ne $Expected) {
        $script:failures.Add("${Name}: expected [$Expected] actual [$Actual]")
    }
}

function Assert-Throws {
    param($Name, [scriptblock] $Script)
    $threw = $false
    try { & $Script } catch { $threw = $true }
    if (-not $threw) { $script:failures.Add("${Name}: expected a throw") }
}

Assert-Equal 'v4 /8' (ConvertTo-CanonicalIpRange '10.0.0.0/8') '10.0.0.0/8'
Assert-Equal 'v4 host' (ConvertTo-CanonicalIpRange '192.0.2.10') '192.0.2.10'
Assert-Equal 'v4 /32' (ConvertTo-CanonicalIpRange '203.0.113.5/32') '203.0.113.5/32'
Assert-Throws 'v4 /12' { ConvertTo-CanonicalIpRange '172.16.0.0/12' }
Assert-Throws 'v4 /10' { ConvertTo-CanonicalIpRange '100.64.0.0/10' }
Assert-Throws 'v4 leading zero' { ConvertTo-CanonicalIpRange '192.168.001.1' }
Assert-Throws 'v4 space' { ConvertTo-CanonicalIpRange '192.0.2.10 ' }
Assert-Throws 'v6 compressed' { ConvertTo-CanonicalIpRange '2001:db8::1' }
Assert-Throws 'v6 prefix' { ConvertTo-CanonicalIpRange '2001:db8::/32' }
Assert-Throws 'mapped dotted' { ConvertTo-CanonicalIpRange '::ffff:192.0.2.1' }
Assert-Throws 'zone id' { ConvertTo-CanonicalIpRange 'fe80::1%12' }

Assert-Equal 'cgnat stays protected' (Get-AseBuiltInProtection '100.64.1.1') 'cgnat'
Assert-Equal 'public v4' (Get-AseBuiltInProtection '203.0.113.5') $null
Assert-Equal 'rfc1918' (Get-AseBuiltInProtection '10.1.2.3') 'rfc1918'
Assert-Equal 'v6 is not a built-in class' (Get-AseBuiltInProtection '2001:0db8:0000:0000:0000:0000:0000:0001') $null

Assert-Equal 'v4 /24' (Test-AseCustomerRangeCovers '203.0.113.5' '203.0.113.0/24') $true
Assert-Equal 'v4 /24 miss' (Test-AseCustomerRangeCovers '203.0.113.5' '203.0.114.0/24') $false
Assert-Equal 'v6 range does not cover' (Test-AseCustomerRangeCovers '203.0.113.5' '2001:0db8:0000:0000:0000:0000:0000:0000/32') $false

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$workflow = Get-Content -Raw (Join-Path $repoRoot 'playbooks/block-malicious-ip/workflow.json')
foreach ($marker in @(
        'parse_ipv6',
        'Initialize_unsupported_v6',
        'Append_candidate_v6',
        'Compose_unenforced_v6',
        'Check_IPv6_address',
        'Append_rejected_ipv6',
        'Filter_protected_v6',
        'IPv6 is not supported',
        'fe80',
        'fc00'
    )) {
    if ($workflow -like "*$marker*") { $failures.Add("workflow.json still contains $marker") }
}

$queries = Get-ChildItem (Join-Path $repoRoot 'sentinel/analytics-rules/*.kql')
foreach ($query in $queries) {
    $text = Get-Content -Raw $query.FullName
    if ($text -match 'parse_ipv6\(') { $failures.Add("$($query.Name) still calls parse_ipv6") }
    if ($text -match 'BuiltInProtectedV6') { $failures.Add("$($query.Name) still has an IPv6 built-in list") }
    if ($text -match 'not\(ClientIp has ":"\)') { $failures.Add("$($query.Name) still drops client addresses in a separate colon filter") }
    if ($text -notmatch 'not\(IPAddress has ":"\)') { $failures.Add("$($query.Name) can pass an unconverted watchlist row to ipv4_is_in_any_range") }
}

if ($failures.Count -gt 0) {
    $failures | ForEach-Object { Write-Error $_ }
    exit 1
}
Write-Output "ip range checks passed ($($queries.Count) analytics queries)"
