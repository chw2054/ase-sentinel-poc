# Canonical form for protected IPv4 ranges.
# The playbook in playbooks/block-malicious-ip/workflow.json accepts this same form.
# IPv4 stays dotted decimal with no leading zeros.

$script:AseIpRangeHelp = 'IPv4 entries must be a single canonical address or /8, /16, /24, or /32. 172.16.0.0/12 and 100.64.0.0/10 are already built in.'

function ConvertTo-CanonicalIpRange {
    param([Parameter(Mandatory)][AllowEmptyString()][string] $Entry)
    if ([string]::IsNullOrWhiteSpace($Entry) -or $Entry -match '[\s,%]') {
        throw "Protected range '$Entry' is not usable. $script:AseIpRangeHelp"
    }
    $pieces = $Entry.Split('/')
    if ($pieces.Count -gt 2 -or [string]::IsNullOrEmpty($pieces[0])) {
        throw "Protected range '$Entry' is not usable. $script:AseIpRangeHelp"
    }
    $addressText = $pieces[0]
    $prefix = $null
    if ($pieces.Count -eq 2) {
        if ($pieces[1] -notmatch '^(?:8|16|24|32)$') {
            throw "Protected range '$Entry' uses a prefix this playbook cannot compare. $script:AseIpRangeHelp"
        }
        $prefix = [int] $pieces[1]
    }
    $parsed = $null
    if (-not [System.Net.IPAddress]::TryParse($addressText, [ref] $parsed)) {
        throw "Protected range '$Entry' is not an IP address. $script:AseIpRangeHelp"
    }
    if ($parsed.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) {
        throw "Protected range '$Entry' is not usable. $script:AseIpRangeHelp"
    }
    $canonical = $parsed.ToString()
    if ($canonical -cne $addressText) {
        throw "Protected range '$Entry' is not a canonical IPv4 address. $script:AseIpRangeHelp"
    }
    if ($null -eq $prefix) { return $canonical }
    return "$canonical/$prefix"
}

function Get-AseBuiltInProtection {
    param([Parameter(Mandatory)][string] $CanonicalAddress)
    if ($CanonicalAddress -notmatch '^\d+\.\d+\.\d+\.\d+$') { return $null }
    $octets = $CanonicalAddress.Split('.')
    $first = [int] $octets[0]
    $second = [int] $octets[1]
    if ($first -eq 0) { return 'unspecified' }
    if ($first -eq 10 -or ($first -eq 172 -and $second -ge 16 -and $second -le 31) -or ($first -eq 192 -and $second -eq 168)) { return 'rfc1918' }
    if ($first -eq 127) { return 'loopback' }
    if ($first -eq 169 -and $second -eq 254) { return 'link-local' }
    if ($first -eq 100 -and $second -ge 64 -and $second -le 127) { return 'cgnat' }
    return $null
}

function Test-AseCustomerRangeCovers {
    param(
        [Parameter(Mandatory)][string] $CanonicalAddress,
        [Parameter(Mandatory)][string] $CanonicalRange
    )
    if ($CanonicalRange -eq $CanonicalAddress) { return $true }
    if ($CanonicalRange -notlike '*/*') { return $false }
    if ($CanonicalAddress -notmatch '^\d+\.\d+\.\d+\.\d+$') { return $false }
    $rangeAddress, $prefixText = $CanonicalRange.Split('/')
    if ($rangeAddress -notmatch '^\d+\.\d+\.\d+\.\d+$') { return $false }
    $prefix = [int] $prefixText
    $take = @{ 8 = 1; 16 = 2; 24 = 3; 32 = 4 }[$prefix]
    if (-not $take) { return $false }
    $left = ($CanonicalAddress.Split('.')[0..($take - 1)] -join '.')
    $right = ($rangeAddress.Split('.')[0..($take - 1)] -join '.')
    return $left -eq $right
}
