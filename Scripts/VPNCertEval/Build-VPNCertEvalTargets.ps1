<#
.SYNOPSIS
    Generates a STARTER "<Company>_EvalTargets.psd1" for Invoke-VPNCertEval.ps1 from a client's
    saved answers file (IPSEC AIO\ClientAnswers\<Abbrev>.json), optionally merging an existing
    User-UnitTests-style endpoint list.

.DESCRIPTION
    The answers file knows: the RADIUS group-pair labels, the DC / RDS / file-server member lists,
    and every CustomAppRule's literal destination IPs + service-group names. It does NOT know vendor
    hostnames, subnet sample hosts, or which TCP/UDP ports a named FortiGate service group maps to.

    So this writes a starter you then hand-edit:
      * Universal[]      - endpoints every connected VPN user should reach (domain controllers).
      * Groups[]         - one bucket per RADIUS group pair, with Endpoints[] derived from the
                           CustomAppRules whose UserGroupName matches that pair, plus a
                           CrossCheckBlocked[] list (other groups' Allow targets this group should
                           NOT reach - the teeth of the "what are my rights" check).
      * ServiceChecks{}  - the port catalogue (built-in, overridden/extended by -UnitTestsPath).

    Every derived entry carries a Source note; anything the answers can't resolve is emitted as a
    Notes = 'TODO ...' string so nothing is silently dropped.

.PARAMETER AnswersPath
    Path to ClientAnswers\<Abbrev>.json.

.PARAMETER UnitTestsPath
    Optional. A User-UnitTests-style .ps1 whose $Endpoints / $ServiceChecks are folded in.

.PARAMETER OutPath
    Output .psd1. Default: <answers folder>\<Company>_EvalTargets.psd1

.EXAMPLE
    .\Build-VPNCertEvalTargets.ps1 -AnswersPath '..\..\..\..\IPSEC AIO\ClientAnswers\ACME.json' `
        -UnitTestsPath '..\..\..\..\Examples_Sources\User-UnitTests (3).ps1'
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$AnswersPath,
    [string]$UnitTestsPath,
    [string]$OutPath,
    [switch]$Force
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'VPNCertEval.Common.ps1')

if (-not (Test-Path $AnswersPath)) { throw "Answers file not found: $AnswersPath" }
$a = Get-Content -Path $AnswersPath -Raw | ConvertFrom-Json

$company = if ($a.PSObject.Properties['Company_Name'] -and $a.Company_Name) { "$($a.Company_Name)" } else { [IO.Path]::GetFileNameWithoutExtension($AnswersPath) }
if (-not $OutPath) { $OutPath = Join-Path (Split-Path -Parent (Resolve-Path $AnswersPath)) ("{0}_EvalTargets.psd1" -f ($company -replace '[^A-Za-z0-9]', '')) }
if ((Test-Path $OutPath) -and -not $Force) { throw "$OutPath already exists - pass -Force to overwrite." }

# --- service catalogue (+ optional merge) --------------------------------------------------------
$catalog = Get-EvalServiceCatalog
$utEndpoints = $null
if ($UnitTestsPath) {
    if (-not (Test-Path $UnitTestsPath)) { throw "UnitTestsPath not found: $UnitTestsPath" }
    $ut = ConvertFrom-UnitTestsFile -Path $UnitTestsPath
    if ($ut.ServiceChecks) {
        foreach ($k in $ut.ServiceChecks.Keys) { $catalog[$k] = $ut.ServiceChecks[$k] }
    }
    $utEndpoints = $ut.Endpoints
}

# --- helper: attach an endpoint hashtable -------------------------------------------------------
function New-Endpoint {
    param([string]$EpHost, [string]$Name, [string[]]$Services, [string]$Expect = 'Allow', [string]$Source, [string]$Notes)
    $h = [ordered]@{ Host = $EpHost; Name = $Name; Services = @($Services); Expect = $Expect; Source = $Source }
    if ($Notes) { $h.Notes = $Notes }
    return $h
}

# --- Universal: domain controllers ------------------------------------------------------------
$universal = New-Object System.Collections.Generic.List[object]
$dcMembers = ConvertFrom-EvalQuotedList (Get-EvalProp $a 'IKEv2_DCMembers')
foreach ($dc in $dcMembers) {
    $universal.Add((New-Endpoint -EpHost $dc -Name "Domain Controller ($dc)" `
        -Services @('DNS', 'Kerberos', 'LDAP', 'LDAPS', 'GlobalCat', 'DCE-RPC', 'Ping') `
        -Expect 'Allow' -Source 'IKEv2_DCMembers'))
}
if ($universal.Count -eq 0) {
    $universal.Add((New-Endpoint -EpHost 'CHANGE-ME-DC.example.local' -Name 'Domain Controller (fill in)' `
        -Services @('DNS', 'Kerberos', 'Ping') -Expect 'Allow' -Source 'placeholder' -Notes 'TODO: IKEv2_DCMembers was empty in the answers'))
}

# --- shared internal endpoints (RDS / file servers) - attached per-group by name match --------
$rdsMembers = ConvertFrom-EvalQuotedList (Get-EvalProp $a 'IKEv2_RDSMembers')
$fsMembers  = ConvertFrom-EvalQuotedList (Get-EvalProp $a 'IKEv2_FileServerMembers')

# --- group pairs -----------------------------------------------------------------------------
$pairs = @(Get-EvalProp $a 'RadiusGroupPairs' @())
$appRules = @(Get-EvalProp $a 'CustomAppRules' @())

function Test-GroupMatchesRule {
    param($Pair, $Rule)
    $ruleGrp = "$(Get-EvalProp $Rule 'UserGroupName')"
    $names = @((Get-EvalProp $Pair 'UserGroupName'), (Get-EvalProp $Pair 'UserGroupValue'), (Get-EvalProp $Pair 'Label')) | Where-Object { $_ }
    foreach ($n in $names) {
        if ("$n" -ieq $ruleGrp) { return $true }
        if ($ruleGrp -and "$n" -and ($ruleGrp.ToLower().Contains("$n".ToLower()) -or "$n".ToLower().Contains($ruleGrp.ToLower()))) { return $true }
    }
    return $false
}

$groups = New-Object System.Collections.Generic.List[object]
foreach ($p in $pairs) {
    $eps = New-Object System.Collections.Generic.List[object]

    # CustomAppRules that belong to this pair
    foreach ($r in $appRules) {
        if (-not (Test-GroupMatchesRule -Pair $p -Rule $r)) { continue }
        $appName = "$(Get-EvalProp $r 'AppName' 'App')"
        $svcNames = @()
        foreach ($sg in (ConvertFrom-EvalQuotedList "$(Get-EvalProp $r 'ServiceNames')")) { $svcNames += Get-EvalServiceNamesForGroup -ServiceGroupName $sg }
        if ($svcNames.Count -eq 0) { $svcNames = @('Ping') }
        $svcNames = $svcNames | Select-Object -Unique

        $addrs = ConvertFrom-EvalQuotedList "$(Get-EvalProp $r 'AddressMembers')"
        foreach ($ip in $addrs) {
            $note = $null
            if ($ip -match '^(1\.1\.1\.1|0\.0\.0\.0|255\.)') { $note = 'TODO: placeholder address in the answers - replace with a real host' }
            $eps.Add((New-Endpoint -EpHost $ip -Name "$appName ($ip)" -Services $svcNames -Expect 'Allow' -Source "CustomAppRules[$appName]" -Notes $note))
        }
        foreach ($named in (ConvertFrom-EvalQuotedList "$(Get-EvalProp $r 'ExistingAddressNames')")) {
            $eps.Add((New-Endpoint -EpHost "RESOLVE-ME" -Name "$appName / $named" -Services $svcNames -Expect 'Allow' -Source "CustomAppRules[$appName]" -Notes "TODO: '$named' is a FortiGate address-object name - look up its IP/FQDN and set Host"))
        }
    }

    # RDS / file-server members for internal/corp-looking pairs
    $looksInternal = ("$(Get-EvalProp $p 'Label') $(Get-EvalProp $p 'UserGroupName') $(Get-EvalProp $p 'UserGroupValue')" -match 'intern|corp|corplan|\brds\b|\brdp\b|fileserv|\bsmb\b|domain')
    if ($looksInternal) {
        foreach ($m in $rdsMembers) { $eps.Add((New-Endpoint -EpHost $m -Name "RDS host ($m)" -Services @('RDP', 'Ping') -Expect 'Allow' -Source 'IKEv2_RDSMembers')) }
        foreach ($m in $fsMembers)  { $eps.Add((New-Endpoint -EpHost $m -Name "File server ($m)" -Services @('SMB', 'Kerberos', 'Ping') -Expect 'Allow' -Source 'IKEv2_FileServerMembers')) }
    }

    $note = $null
    if ($eps.Count -eq 0) { $note = 'TODO: no endpoints derived for this group - add the hosts this group is meant to reach' }
    $groups.Add([ordered]@{
        Label             = "$(Get-EvalProp $p 'Label')"
        UserGroupName     = "$(Get-EvalProp $p 'UserGroupName')"
        UserGroupValue    = "$(Get-EvalProp $p 'UserGroupValue')"
        Endpoints         = $eps.ToArray()   # NB: @($list-of-ordered) crashes the PS7 binder
        CrossCheckBlocked = @()               # filled below
        Notes             = $note
    })
}

# --- cross-group "should be BLOCKED" expectations ---------------------------------------------
$maxCross = 8
foreach ($g in $groups) {
    $mine = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($ep in $g.Endpoints) {
        $h = "$(Get-EvalProp $ep 'Host')"
        if ($h -and $h -ne 'RESOLVE-ME') { [void]$mine.Add($h) }
    }
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $blocked = New-Object System.Collections.Generic.List[object]
    foreach ($other in $groups) {
        if ("$($other['Label'])" -eq "$($g['Label'])") { continue }
        foreach ($ep in $other.Endpoints) {
            $h = "$(Get-EvalProp $ep 'Host')"
            if (-not $h -or $h -eq 'RESOLVE-ME') { continue }
            if ($mine.Contains($h) -or $seen.Contains($h)) { continue }
            if ($blocked.Count -ge $maxCross) { break }
            [void]$seen.Add($h)
            $blocked.Add((New-Endpoint -EpHost $h -Name "$(Get-EvalProp $ep 'Name') [expected BLOCK for $($g['Label'])]" -Services (Get-EvalProp $ep 'Services' @('Ping')) -Expect 'Block' -Source "cross-check vs $($other['Label'])"))
        }
        if ($blocked.Count -ge $maxCross) { break }
    }
    $g.CrossCheckBlocked = $blocked.ToArray()
}

# --- fold in a User-UnitTests endpoint list (as extra Universal Allow entries) ----------------
if ($utEndpoints) {
    $haveHosts = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($u in $universal) { $h = "$(Get-EvalProp $u 'Host')"; if ($h) { [void]$haveHosts.Add($h) } }
    foreach ($k in $utEndpoints.Keys) {
        if ($haveHosts.Contains("$k")) { continue }
        $universal.Add((New-Endpoint -EpHost "$k" -Name "$($utEndpoints[$k])" -Services (Get-EvalServicesForLabelText "$($utEndpoints[$k])") -Expect 'Allow' -Source 'UnitTestsFile' -Notes 'Review: from User-UnitTests file - confirm which group(s) this applies to'))
    }
}

# --- assemble + write ----------------------------------------------------------------------------
$root = [ordered]@{
    Company        = $company
    GeneratedUtc   = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    SourceAnswers  = (Split-Path -Leaf $AnswersPath)
    IssuingModel   = "$(Get-EvalProp $a 'CA_IssuingModel')"
    PeerSubjectDN  = "$(Get-EvalProp $a 'Cert_PeerSubjectFilter')"
    ServiceChecks  = $catalog
    Universal      = $universal.ToArray()
    Groups         = $groups.ToArray()
}

$header = @"
# ==============================================================================================
#  $company - VPN certificate evaluation targets  (STARTER - review before use)
#  Generated $(Get-Date) from $(Split-Path -Leaf $AnswersPath)
#
#  Consumed by Invoke-VPNCertEval.ps1 -TargetsPath <this file>.
#
#  BEFORE RUNNING:
#   * Replace every Host = 'RESOLVE-ME' / 'CHANGE-ME-*' and any Notes = 'TODO ...' entry.
#   * Sanity-check each endpoint's Services[] against what that group is really scoped to on
#     the FortiGate - the port catalogue is a guess from the service-group NAME.
#   * CrossCheckBlocked[] = endpoints this group should be DENIED. Trim/extend as needed.
#   * Add vendor hosts / subnet sample hosts the answers file has no way to know.
# ==============================================================================================

"@

$body = ConvertTo-EvalPsd1 -InputObject $root
Set-Content -Path $OutPath -Value ($header + $body + "`r`n") -Encoding UTF8

Write-Host "Wrote $OutPath" -ForegroundColor Green
Write-Host ("  Universal endpoints : {0}" -f $universal.Count) -ForegroundColor Gray
Write-Host ("  Groups              : {0}" -f $groups.Count) -ForegroundColor Gray
$todo = ([regex]::Matches($body, "TODO|RESOLVE-ME|CHANGE-ME")).Count
if ($todo) { Write-Host ("  Unresolved markers  : {0}  (search the file for TODO / RESOLVE-ME / CHANGE-ME)" -f $todo) -ForegroundColor Yellow }
