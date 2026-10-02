<#
.SYNOPSIS
    Read-only inventory of the Entra (Azure AD) Application Proxy apps that front a client's PKI -
    the CRL/AIA app and the OCSP app. Captures every value CA-Manager.ps1 needs to reproduce (or
    diff against) a hand-built App Proxy publishing setup. Nothing is created or changed.

.DESCRIPTION
    Run from any workstation with internet + the Microsoft.Graph.Authentication module. You sign in
    interactively as a Global Reader / Application Administrator (or higher). Read-only Graph scopes
    only. Writes a timestamped .txt (transcript) to -OutputDir.

    Dumps, in order:
      A. Tenant / signed-in context
      B. All App Proxy connector groups + every connector (machine, external IP, status, version)
      C. Every application that has onPremisesPublishing configured - narrowed to the PKI ones by
         -AppNameLike / -AppId (default: anything whose displayName or external/internal URL contains
         crl, ocsp, aia, pki, cert, or "certenroll"). For each:
           - onPremisesPublishing (v1.0 + beta): internalUrl, externalUrl, externalAuthenticationType
             (aadPreAuthentication = pre-auth / passthru = passthrough), server timeout, all the
             cookie / header-translation toggles, singleSignOnSettings, the custom-domain SSL cert
             metadata (subject / thumbprint / expiry), and (beta) segmentsConfiguration for wildcard
             apps
           - the connector group the app is assigned to
           - the app's identifierUris + web.redirectUris (pre-auth reply URLs)
           - its servicePrincipal: appRoleAssignmentRequired (true = only assigned principals get
             through pre-auth), accountEnabled, preferredSingleSignOnMode, loginUrl, notes, tags
           - appRoleAssignedTo: who (users / groups) is allowed through when pre-auth + assignment
             required

    Send the .txt back.

.PARAMETER AppNameLike
    Substring(s) matched (case-insensitive) against each onPrem-publishing app's displayName,
    externalUrl and internalUrl. Default covers the usual PKI naming. Pass your own to narrow/widen.

.PARAMETER AppId
    One or more application (client) IDs or directory object IDs - bypasses the name filter and
    dumps exactly those.

.PARAMETER OutputDir
    Where the timestamped .txt is written. Default C:\Admin\CAInventory.

.PARAMETER TenantId
    Optional - pass to force a specific tenant on Connect-MgGraph (useful for guest / multi-tenant
    accounts). Omit for your home tenant.

.NOTES
    Needs the Microsoft.Graph.Authentication module only (not the full Microsoft.Graph meta-module):
        Install-Module Microsoft.Graph.Authentication -Scope CurrentUser
    Scopes requested (all read-only): Application.Read.All, Directory.Read.All, Group.Read.All.
    Reading onPremisesPublishingProfiles also needs the account to be at least Global Reader.
#>

[CmdletBinding()]
param(
    [string[]]$AppNameLike = @('crl', 'ocsp', 'aia', 'pki', 'cert', 'certenroll', 'msappproxy'),
    [string[]]$AppId,
    [string]$OutputDir = "C:\Admin\CAInventory",
    [string]$TenantId
)

$ErrorActionPreference = 'Continue'

if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication)) {
    Write-Host "Microsoft.Graph.Authentication is not installed. Install it (no admin needed) with:" -ForegroundColor Yellow
    Write-Host "    Install-Module Microsoft.Graph.Authentication -Scope CurrentUser" -ForegroundColor Cyan
    return
}
Import-Module Microsoft.Graph.Authentication -ErrorAction Stop

if (-not (Test-Path $OutputDir)) { $null = New-Item -ItemType Directory -Path $OutputDir -Force }
$stamp   = Get-Date -Format 'yyyyMMdd_HHmmss'
$outFile = Join-Path $OutputDir "EntraProxyInventory_${stamp}.txt"
try { $null = Start-Transcript -Path $outFile -Force } catch { }

function Section { param([string]$Text)
    Write-Host ""; Write-Host ("=" * 78) -ForegroundColor Cyan
    Write-Host "  $Text" -ForegroundColor Cyan
    Write-Host ("=" * 78) -ForegroundColor Cyan }
function Sub  { param([string]$Text) Write-Host ""; Write-Host "--- $Text ---" -ForegroundColor Gray }
function Note { param([string]$Text) Write-Host "  [note] $Text" -ForegroundColor Yellow }
function Dump { param($Obj, [int]$Depth = 6)
    if ($null -eq $Obj) { Write-Host "  (null)"; return }
    $Obj | ConvertTo-Json -Depth $Depth | Write-Host }

# --- Graph GET wrappers ---------------------------------------------------------------
# Some of the App Proxy endpoints legitimately 404/400 for a given tenant/group type (e.g. asking
# a passthroughAuthentication group for /members). We don't want each of those to dump a full HTTP
# error block into the transcript, so - if the module build supports it - use -SkipHttpErrorCheck
# and inspect the status code instead of catching a thrown exception.
$script:GraphCanSkipErr = (Get-Command Invoke-MgGraphRequest).Parameters.ContainsKey('SkipHttpErrorCheck')

function Invoke-Graph {
    param([string]$Uri)
    if ($script:GraphCanSkipErr) {
        $sc = $null
        $b = Invoke-MgGraphRequest -Method GET -Uri $Uri -OutputType PSObject -SkipHttpErrorCheck -StatusCodeVariable sc -ErrorAction SilentlyContinue
        return [pscustomobject]@{ ok = ($sc -ge 200 -and $sc -lt 300); status = $sc; body = $b }
    }
    try {
        $b = Invoke-MgGraphRequest -Method GET -Uri $Uri -OutputType PSObject -ErrorAction Stop
        return [pscustomobject]@{ ok = $true; status = 200; body = $b }
    } catch {
        $code = $null; try { $code = [int]$_.Exception.Response.StatusCode.value__ } catch { }
        return [pscustomobject]@{ ok = $false; status = $code; body = $null }
    }
}
# follows @odata.nextLink; ENUMERATES the flattened .value set (call sites wrap in @() when they
# need a guaranteed array). Do NOT `,$items` here - when this function's output is piped, the
# outer wrapper unrolls and the downstream cmdlet receives the whole inner array as a single item.
function Get-GraphAll {
    param([string]$Uri, [switch]$Quiet)
    $items = @(); $next = $Uri
    while ($next) {
        $res = Invoke-Graph $next
        if (-not $res.ok) { if (-not $Quiet) { Write-Host "  (skip) $next -> HTTP $($res.status)" -ForegroundColor DarkYellow }; break }
        $b = $res.body
        if ($null -ne $b.value) { $items += $b.value } elseif ($b) { $items += $b }
        $next = $b.'@odata.nextLink'
    }
    $items
}
function Get-GraphOne {
    param([string]$Uri, [switch]$Quiet)
    $res = Invoke-Graph $Uri
    if ($res.ok) { return $res.body }
    if (-not $Quiet) { Write-Host "  (skip) $Uri -> HTTP $($res.status)" -ForegroundColor DarkYellow }
    return $null
}

# App Proxy (connector groups/connectors) and the full onPremisesPublishing object on applications
# live ONLY under the BETA endpoint - v1.0 returns "Resource not found for the segment
# 'onPremisesPublishingProfiles'" and doesn't populate application.onPremisesPublishing. Everything
# in sections B and C therefore uses beta.
$Beta = "https://graph.microsoft.com/beta"

# ---- connect --------------------------------------------------------------------------
$connectArgs = @{ Scopes = @('Application.Read.All', 'Directory.Read.All', 'Group.Read.All') }
if ($TenantId) { $connectArgs.TenantId = $TenantId }
try { $connectArgs.NoWelcome = $true; Connect-MgGraph @connectArgs -ErrorAction Stop }
catch {
    # older module builds don't have -NoWelcome
    [void]$connectArgs.Remove('NoWelcome')
    Connect-MgGraph @connectArgs -ErrorAction Stop
}

Write-Host "CA Manager - Entra Application Proxy inventory" -ForegroundColor Green
Write-Host "When   : $(Get-Date)"
Write-Host "Output : $outFile"
Note "Read-only. Nothing in Entra is created or changed by this script."

# =====================================================================================
Section "A. Tenant / signed-in context"
# =====================================================================================
$ctx = Get-MgContext
$ctx | Format-List Account, TenantId, Scopes, AppName, Environment | Out-String | Write-Host
$org = Get-GraphOne "https://graph.microsoft.com/v1.0/organization?`$select=displayName,id,verifiedDomains"
if ($org) { $org.value | ForEach-Object { Write-Host "  Tenant: $($_.displayName)  ($($_.id))"; $_.verifiedDomains | ForEach-Object { Write-Host "    domain: $($_.name)  default=$($_.isDefault)  initial=$($_.isInitial)" } } }

# =====================================================================================
Section "B. App Proxy connector groups + connectors  (beta)"
# =====================================================================================
Sub "connector groups"
$cgs = @()
try { $cgs = Get-GraphAll "$Beta/onPremisesPublishingProfiles/applicationProxy/connectorGroups" }
catch { Write-Host "  ERROR: $($_.Exception.Message)" -ForegroundColor Red }
foreach ($cg in $cgs) {
    Write-Host ""
    Write-Host "  [$($cg.name)]  id=$($cg.id)  region=$($cg.region)  default=$($cg.isDefault)  type=$($cg.connectorGroupType)"
    # /members and /applications only exist for applicationProxy-type groups - passthroughAuthentication /
    # exchangeOnline / adfs groups 404 on those sub-paths, so don't even ask.
    if ($cg.connectorGroupType -ne 'applicationProxy') { Write-Host "      (not an applicationProxy group - skipping members/apps)"; continue }
    foreach ($m in (Get-GraphAll "$Beta/onPremisesPublishingProfiles/applicationProxy/connectorGroups/$($cg.id)/members" -Quiet)) {
        Write-Host ("      connector: {0,-28} extIP={1,-16} status={2,-10} ver={3}" -f $m.machineName, $m.externalIp, $m.status, $m.version)
    }
    $apps = Get-GraphAll "$Beta/onPremisesPublishingProfiles/applicationProxy/connectorGroups/$($cg.id)/applications?`$select=id,displayName" -Quiet
    if ($apps) { Write-Host "      apps assigned: $(( $apps | ForEach-Object { $_.displayName }) -join ', ')" }
}
Sub "all connectors (whole tenant)"
try {
    Get-GraphAll "$Beta/onPremisesPublishingProfiles/applicationProxy/connectors" |
        ForEach-Object { Write-Host ("  {0,-28} extIP={1,-16} status={2,-10} ver={3}  id={4}" -f $_.machineName, $_.externalIp, $_.status, $_.version, $_.id) }
} catch { Write-Host "  ERROR: $($_.Exception.Message)" -ForegroundColor Red }

# =====================================================================================
Section "C. Application Proxy applications (PKI)"
# =====================================================================================
Sub "enumerating App Proxy apps via the servicePrincipal tag 'WindowsAzureActiveDirectoryOnPremApp'"
# The reliable enumeration path. (Beta /applications?$select=...onPremisesPublishing... on the
# COLLECTION throws InvalidGuid_BadRequest '[sourceEntityId]', and /applications(appId='x') as a
# key segment returns a raw IIS 404 on beta - so: tag-scan the SPs, then resolve each real
# application object by $filter=appId eq 'x'.)
$allSps = @(Get-GraphAll "$Beta/servicePrincipals?`$select=id,appId,displayName,tags&`$top=999")
$onpremSps = @($allSps | Where-Object { $_.tags -contains 'WindowsAzureActiveDirectoryOnPremApp' })
Write-Host "  servicePrincipals scanned: $($allSps.Count);  tagged as App Proxy: $($onpremSps.Count)"
foreach ($s in $onpremSps) { Write-Host ("    - {0,-30} appId={1}" -f $s.displayName, $s.appId) }

# IMPORTANT: never put onPremisesPublishing in a $select on the /applications COLLECTION (even with
# a $filter) - it throws InvalidGuid_BadRequest '[sourceEntityId]'. Resolve the app object id here
# with a safe select (v1.0 is fine and reliable for appId eq), then fetch onPremisesPublishing as a
# SINGLE-item read below.
$appSelect = 'id,appId,displayName,identifierUris,web,tags,createdDateTime'
$targets = foreach ($sp in $onpremSps) {
    $appObj = (Get-GraphOne "https://graph.microsoft.com/v1.0/applications?`$filter=appId eq '$($sp.appId)'&`$select=$appSelect").value | Select-Object -First 1
    if (-not $appObj) {
        $appObj = (Get-GraphOne "$Beta/applications?`$filter=appId eq '$($sp.appId)'&`$select=$appSelect").value | Select-Object -First 1
    }
    [pscustomobject]@{ Sp = $sp; App = $appObj }
}

# narrow to the PKI ones (match against SP displayName + appId + app displayName/URLs)
if ($AppId) {
    $picked = $targets | Where-Object { $AppId -contains $_.Sp.appId -or $AppId -contains $_.Sp.id -or $AppId -contains $_.App.id }
} else {
    $picked = $targets | Where-Object {
        $hay = (@($_.Sp.displayName, $_.App.displayName,
                  $_.App.onPremisesPublishing.externalUrl, $_.App.onPremisesPublishing.internalUrl) -join ' ').ToLower()
        $m = $false
        foreach ($n in $AppNameLike) { if ($hay -and $hay.Contains($n.ToLower())) { $m = $true; break } }
        $m
    }
    if (-not $picked) {
        Note "No app matched -AppNameLike ($($AppNameLike -join ', ')). Dumping ALL App Proxy apps so you can identify them."
        $picked = $targets
    }
}

foreach ($t in $picked) {
    $sp  = $t.Sp
    $app = $t.App
    Section "  APP: $($sp.displayName)"
    Write-Host "  appId (client id) : $($sp.appId)"
    Write-Host "  app object id     : $($app.id)"
    Write-Host "  sp  object id     : $($sp.id)"
    Write-Host "  created           : $($app.createdDateTime)"
    Write-Host "  identifierUris    : $($app.identifierUris -join ', ')"
    Write-Host "  web.redirectUris  : $($app.web.redirectUris -join ', ')"
    Write-Host "  web.homePageUrl   : $($app.web.homePageUrl)"
    Write-Host "  app tags          : $($app.tags -join ', ')"

    if (-not $app.id) {
        Note "Could not resolve the application object for appId $($sp.appId) - onPremisesPublishing / connectorGroup unavailable for this one. (servicePrincipal detail below is still valid.)"
    } else {
        Sub "onPremisesPublishing (the App Proxy config we need)"
        $full = Get-GraphOne "$Beta/applications/$($app.id)?`$select=id,displayName,identifierUris,web,onPremisesPublishing"
        $pub  = $full.onPremisesPublishing
        if (-not $pub) { $full = Get-GraphOne "$Beta/applications/$($app.id)"; $pub = $full.onPremisesPublishing }   # plain single-item GET
        if ($pub) { Dump $pub 12 } else { Write-Host "  (onPremisesPublishing still empty - dumping the whole application object)"; if ($full) { Dump $full 8 } }

        Sub "assigned connector group"
        $cg = Get-GraphOne "$Beta/applications/$($app.id)/connectorGroup"
        if ($cg) { Write-Host "  [$($cg.name)]  id=$($cg.id)  region=$($cg.region)  type=$($cg.connectorGroupType)" } else { Write-Host "  (none returned / default)" }
    }

    Sub "servicePrincipal"
    # re-fetch the SP as a single object with the full property set (the enumeration select was lean)
    $spFull = Get-GraphOne "$Beta/servicePrincipals/$($sp.id)?`$select=id,appId,displayName,accountEnabled,appRoleAssignmentRequired,preferredSingleSignOnMode,loginUrl,notificationEmailAddresses,preferredTokenSigningKeyThumbprint,tags,keyCredentials,samlSingleSignOnSettings"
    if (-not $spFull) { $spFull = $sp }
    $spFull | Select-Object id, displayName, accountEnabled, appRoleAssignmentRequired,
        preferredSingleSignOnMode, loginUrl,
        @{n='notificationEmailAddresses';e={ $_.notificationEmailAddresses -join ', ' }},
        preferredTokenSigningKeyThumbprint,
        @{n='tags';e={ $_.tags -join ', ' }} | Format-List | Out-String | Write-Host
    Note "appRoleAssignmentRequired = True => only assigned users/groups can reach it (only matters if externalAuthenticationType = aadPreAuthentication; for PKI it should be 'passthru')."

    Sub "appRoleAssignedTo (who is allowed through, if pre-auth)"
    $assigns = @(Get-GraphAll "$Beta/servicePrincipals/$($sp.id)/appRoleAssignedTo" -Quiet)
    if ($assigns) { foreach ($a in $assigns) { Write-Host ("    {0,-16} {1}" -f $a.principalType, $a.principalDisplayName) } }
    else { Write-Host "    (no explicit assignments)" }

    Sub "SSO / token config"
    $spFull | Select-Object `
        @{n='keyCredentials';e={ ($_.keyCredentials | ForEach-Object { "$($_.usage):$($_.displayName):exp=$($_.endDateTime)" }) -join ' | ' }},
        @{n='samlSingleSignOnSettings';e={ $_.samlSingleSignOnSettings | ConvertTo-Json -Compress -Depth 5 }} |
        Format-List | Out-String | Write-Host
}

Section "DONE"
Write-Host "Inventory written to:" -ForegroundColor Green
Write-Host "  $outFile" -ForegroundColor Green
Write-Host ""
Write-Host "Send that file back." -ForegroundColor Cyan
try { $null = Disconnect-MgGraph } catch { }
try { $null = Stop-Transcript } catch { }
Write-Host ""
Write-Host "(press Enter to close)"
try { $null = Read-Host } catch { }
