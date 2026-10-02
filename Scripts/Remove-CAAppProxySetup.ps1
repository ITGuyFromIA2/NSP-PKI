<#
.SYNOPSIS
    Tears down what CA-Manager menu 7 (App Proxy connector + Entra apps) and menu 5 (URL routing)
    created, so the whole flow can be re-run from a clean slate. Dev / re-test tool - NOT shipped in
    the client zip.

.DESCRIPTION
    Undoes, with a confirm before each destructive step:
      1. Entra apps 'CRL' + 'OCSP-Relay'                     (DELETE /applications, SP cascades)
      2. Entra connector group 'CertChecks'                  (connector moved back to 'Default' first)
      3. the Entra private-network connector on this box     (MSI uninstall; skip with -KeepConnector)
      4. the IIS /CertEnroll/ virtual directory              (role + MIME left; skip with -KeepIIS)
      5. the msappproxy CDP/AIA/OCSP entries in the CA's CRLPublicationURLs / CACertPublicationURLs
         (surgical - only the *.msappproxy.net lines are removed), then certutil -crl + restart CertSvc
      6. CA_AppProxyCrlFqdn / CA_AppProxyOcspFqdn / CA_MsAppProxyTenant in CAAnswers.json (blanked)

    App Proxy stays *enabled* in the tenant (a one-way first-connector side effect) - that does not
    affect a re-run.

.PARAMETER CrlAppName / OcspAppName / ConnectorGroupName
    Override the names to look for (defaults match CA-Manager's).

.PARAMETER KeepConnector
    Leave the connector installed + registered (re-run then just skips 7c). Recommended for a quick
    re-test - registration is the one genuinely manual step.

.PARAMETER KeepIIS
    Leave the /CertEnroll/ virtual directory in place.

.PARAMETER CAAnswersPath
    Path to CAAnswers.json to blank the resolved FQDNs in. Default: next to this script.

.PARAMETER WhatIf
    Print what would happen, change nothing.
#>
[CmdletBinding()]
param(
    [string]$CrlAppName          = 'CRL',
    [string]$OcspAppName         = 'OCSP-Relay',
    [string]$ConnectorGroupName  = 'CertChecks',
    [switch]$KeepConnector,
    [switch]$KeepIIS,
    [string]$CAAnswersPath,
    [switch]$WhatIf
)

$ErrorActionPreference = 'Stop'

# $PSScriptRoot is empty when this script is dot-sourced; fall back to the invocation path, then CWD.
$BaseDir = if ($PSScriptRoot) { $PSScriptRoot }
           elseif ($MyInvocation.MyCommand.Path) { Split-Path -Parent $MyInvocation.MyCommand.Path }
           else { (Get-Location).Path }
if (-not $CAAnswersPath) { $CAAnswersPath = Join-Path $BaseDir 'CAAnswers.json' }

. (Join-Path $BaseDir '..\Private\CACore.ps1')   # NSP.PKI: was Modules\
. (Join-Path $BaseDir '..\Private\CAGraph.ps1')   # NSP.PKI: was Modules\
. (Join-Path $BaseDir '..\Private\CAAppProxy.ps1')   # NSP.PKI: was Modules\
Repair-CAModulePath   # the connector installer/uninstaller can drop the CurrentUser module dir

function Confirm-Step {
    param([string]$Prompt)
    if ($WhatIf) { Write-Host "  [WHATIF] $Prompt" -ForegroundColor Cyan; return $false }
    $r = Read-Host "  $Prompt  [y/N]"
    return ($r -match '^(?i)y')
}

Write-Host ""
Write-Host "==== CA-Manager App Proxy teardown ====" -ForegroundColor Cyan
if ($WhatIf) { Write-Host "  (WhatIf - nothing will change)" -ForegroundColor Cyan }

# ---------------------------------------------------------------------------
# 1 + 2. Entra: apps, then connector group
# ---------------------------------------------------------------------------
$Beta = 'https://graph.microsoft.com/beta'
Write-Host "`n-- Entra --" -ForegroundColor White
$ctx = Connect-CAGraph
if (-not $ctx) { Write-Host "  Graph sign-in failed - skipping the Entra half." -ForegroundColor Yellow }
else {
    # An App Proxy "app" is an application + a servicePrincipal. DELETE /applications does NOT delete
    # the SP, and a lingering tagged SP still counts as "assigned" to the connector group
    # (ApplicationsOrConnectorsAssigned_BadRequest) even after /applications and /members read empty.
    # So: delete the SP, delete the application, then purge BOTH from the 30-day recycle bin.
    $names = @($CrlAppName, $OcspAppName)
    $sps = @((Invoke-CAGraph -Method GET -Uri "$Beta/servicePrincipals?`$select=id,appId,displayName,tags&`$top=999").body.value) |
        Where-Object { $_.tags -contains 'WindowsAzureActiveDirectoryOnPremApp' -and $_.displayName -in $names }
    foreach ($sp in $sps) {
        Write-Host "  App Proxy SP '$($sp.displayName)'  sp=$($sp.id)  appId=$($sp.appId)" -ForegroundColor Gray
        if (Confirm-Step "DELETE servicePrincipal + application for '$($sp.displayName)'?") {
            $r1 = Invoke-CAGraph -Method DELETE -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$($sp.id)"
            Write-Host $(if ($r1.ok) { "    SP deleted." } else { "    SP -> HTTP $($r1.status)" }) -ForegroundColor $(if ($r1.ok) { 'Green' } else { 'Yellow' })
            $appObj = (Invoke-CAGraph -Method GET -Uri "https://graph.microsoft.com/v1.0/applications?`$filter=appId eq '$($sp.appId)'&`$select=id").body.value | Select-Object -First 1
            if ($appObj) {
                $r2 = Invoke-CAGraph -Method DELETE -Uri "https://graph.microsoft.com/v1.0/applications/$($appObj.id)"
                Write-Host $(if ($r2.ok) { "    app deleted." } else { "    app -> HTTP $($r2.status)" }) -ForegroundColor $(if ($r2.ok) { 'Green' } else { 'Yellow' })
            }
        }
    }

    # purge the recycle bin - both apps AND servicePrincipals
    foreach ($t in @('microsoft.graph.application', 'microsoft.graph.servicePrincipal')) {
        $deleted = @((Invoke-CAGraph -Method GET -Uri "https://graph.microsoft.com/v1.0/directory/deletedItems/$t").body.value) |
            Where-Object { $_.displayName -in $names }
        foreach ($d in $deleted) {
            if (Confirm-Step "PERMANENTLY delete recycled $($t.Split('.')[-1]) '$($d.displayName)' ($($d.id))?") {
                $r = Invoke-CAGraph -Method DELETE -Uri "https://graph.microsoft.com/v1.0/directory/deletedItems/$($d.id)"
                Write-Host $(if ($r.ok) { "    purged." } else { "    -> HTTP $($r.status)" }) -ForegroundColor $(if ($r.ok) { 'Green' } else { 'Yellow' })
            }
        }
    }

    $grp = @(Get-CAGraphAll "$Beta/onPremisesPublishingProfiles/applicationProxy/connectorGroups" -Quiet) |
        Where-Object { $_.name -eq $ConnectorGroupName -and $_.connectorGroupType -eq 'applicationProxy' } | Select-Object -First 1
    if (-not $grp) { Write-Host "  connector group '$ConnectorGroupName' not found - already gone." -ForegroundColor Green }
    else {
        Write-Host "  connector group '$ConnectorGroupName'  id=$($grp.id)" -ForegroundColor Gray
        # move any members back to Default so the group can be deleted
        $default = @(Get-CAGraphAll "$Beta/onPremisesPublishingProfiles/applicationProxy/connectorGroups" -Quiet) |
            Where-Object { $_.isDefault } | Select-Object -First 1
        $members = @(Get-CAGraphAll "$Beta/onPremisesPublishingProfiles/applicationProxy/connectorGroups/$($grp.id)/members" -Quiet)
        if ($members -and $default -and (Confirm-Step "Move $($members.Count) connector(s) from '$ConnectorGroupName' back to 'Default'?")) {
            foreach ($m in $members) {
                $r = Invoke-CAGraph -Method POST -Uri "$Beta/onPremisesPublishingProfiles/applicationProxy/connectors/$($m.id)/memberOf/`$ref" `
                    -Body @{ '@odata.id' = "$Beta/onPremisesPublishingProfiles/applicationProxy/connectorGroups/$($default.id)" }
                if (-not $r.ok) { $r = Invoke-CAGraph -Method PUT -Uri "$Beta/onPremisesPublishingProfiles/applicationProxy/connectors/$($m.id)/memberOf/`$ref" -Body @{ '@odata.id' = "$Beta/onPremisesPublishingProfiles/applicationProxy/connectorGroups/$($default.id)" } }
                Write-Host $(if ($r.ok) { "    moved $($m.machineName)" } else { "    move $($m.machineName) -> HTTP $($r.status)" }) -ForegroundColor $(if ($r.ok) { 'Green' } else { 'Yellow' })
            }
        }
        $assigned = @((Invoke-CAGraph -Method GET -Uri "$Beta/onPremisesPublishingProfiles/applicationProxy/connectorGroups/$($grp.id)/applications?`$select=id,displayName").body.value)
        if ($assigned) {
            Write-Host "  still assigned to '$ConnectorGroupName': $((($assigned | ForEach-Object { $_.displayName }) -join ', '))" -ForegroundColor Yellow
            Write-Host "  (delete + purge those, or move them to 'Default', before the group will delete)" -ForegroundColor DarkGray
        }
        if (Confirm-Step "DELETE connector group '$ConnectorGroupName'?") {
            $r = $null
            for ($i = 0; $i -lt 4; $i++) {
                $r = Invoke-CAGraph -Method DELETE -Uri "$Beta/onPremisesPublishingProfiles/applicationProxy/connectorGroups/$($grp.id)"
                if ($r.ok -or $WhatIf) { break }
                Write-Host "    HTTP $($r.status) - the member move may still be propagating; retrying in 5s..." -ForegroundColor DarkYellow
                Start-Sleep -Seconds 5
            }
            Write-Host $(if ($r.ok) { "    deleted." } else { "    -> HTTP $($r.status)  (still has a member / is the default group - uninstall the connector, then re-run this script)" }) -ForegroundColor $(if ($r.ok) { 'Green' } else { 'Red' })
        }
    }

    if (-not $KeepConnector) {
        $me = try { [System.Net.Dns]::GetHostEntry($env:COMPUTERNAME).HostName } catch { $env:COMPUTERNAME }
        $conn = Get-CAAppProxyConnector -MachineName $me
        if (-not $conn) { Write-Host "  no tenant connector object for this box - already gone." -ForegroundColor Green }
        elseif (Confirm-Step "DELETE the tenant connector object for '$($conn.machineName)' (works only once the MSI is uninstalled)?") {
            $r = Invoke-CAGraph -Method DELETE -Uri "$Beta/onPremisesPublishingProfiles/applicationProxy/connectors/$($conn.id)"
            Write-Host $(if ($r.ok) { "    deleted." } else { "    -> HTTP $($r.status)  (still active - uninstall the connector below, reboot, then re-run this script)" }) -ForegroundColor $(if ($r.ok) { 'Green' } else { 'Yellow' })
        }
    }
    try { Disconnect-MgGraph 3>$null | Out-Null } catch { }
}

# ---------------------------------------------------------------------------
# 3. connector MSI uninstall
# ---------------------------------------------------------------------------
if (-not $KeepConnector) {
    Write-Host "`n-- connector --" -ForegroundColor White
    $svc = Get-Service -Name WAPCSvc -ErrorAction SilentlyContinue
    if (-not $svc) { Write-Host "  WAPCSvc not present - connector already uninstalled." -ForegroundColor Green }
    else {
        $ProgressPreference = 'SilentlyContinue'
        $entries = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
                                    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName -match '(?i)(Entra private network connector|Application Proxy Connector)' } |
            Sort-Object DisplayName, PSChildName -Unique
        if (-not $entries) { Write-Host "  No connector uninstall entry found - remove it via Settings > Apps by hand." -ForegroundColor Yellow }
        foreach ($e in $entries) {
            Write-Host "  $($e.DisplayName)  $($e.DisplayVersion)" -ForegroundColor Gray
            if (Confirm-Step "Uninstall '$($e.DisplayName)'?") {
                if ($e.PSChildName -match '^\{[0-9A-Fa-f-]+\}$') {
                    Start-Process msiexec.exe -ArgumentList "/x $($e.PSChildName) /qn /norestart" -Wait
                } elseif ($e.UninstallString) {
                    $u = $e.UninstallString
                    if ($u -match 'msiexec') { $u = ($u -replace '(?i)/I', '/X') + ' /qn /norestart'; Start-Process cmd.exe -ArgumentList "/c $u" -Wait }
                    else { Start-Process cmd.exe -ArgumentList "/c `"$u`" /quiet" -Wait }
                }
                Write-Host "    done (a reboot may be pending)." -ForegroundColor Green
            }
        }
        # NOTE: after this, re-run the Entra half (or this script again) to delete the now-inactive
        #       tenant connector object.
    }
}

# ---------------------------------------------------------------------------
# 4. IIS /CertEnroll/ virtual directory
# ---------------------------------------------------------------------------
if (-not $KeepIIS) {
    Write-Host "`n-- IIS --" -ForegroundColor White
    $appcmd = Join-Path $env:windir 'system32\inetsrv\appcmd.exe'
    $removed = $false
    try {
        Import-Module WebAdministration -ErrorAction Stop
        $vd = Get-WebVirtualDirectory -Site 'Default Web Site' -Name 'CertEnroll' -ErrorAction SilentlyContinue
        if (-not $vd) { Write-Host "  /CertEnroll/ vdir not present - already gone." -ForegroundColor Green; $removed = $true }
        elseif (Confirm-Step "Remove the IIS /CertEnroll/ virtual directory (Web-Server role + MIME maps kept)?") {
            Remove-WebVirtualDirectory -Site 'Default Web Site' -Name 'CertEnroll'
            Write-Host "    removed." -ForegroundColor Green; $removed = $true
        } else { $removed = $true }   # user declined
    } catch {
        Write-Host "  WebAdministration didn't load - trying appcmd.exe..." -ForegroundColor DarkYellow
    }
    if (-not $removed -and (Test-Path $appcmd)) {
        if (Confirm-Step "Remove /CertEnroll/ via appcmd.exe?") {
            & $appcmd delete vdir "Default Web Site/CertEnroll" 2>&1 | Out-String | Write-Host
        }
    } elseif (-not $removed) {
        Write-Host "  Remove it by hand: appcmd delete vdir `"Default Web Site/CertEnroll`"  (or IIS Manager)." -ForegroundColor Yellow
    }
}

# ---------------------------------------------------------------------------
# 5. CA URL routing - strip only the msappproxy entries
# ---------------------------------------------------------------------------
Write-Host "`n-- CA URL routing (menu 5 undo) --" -ForegroundColor White
function Get-RegMultiSz {
    param([string]$Key)
    $out = & certutil.exe -getreg $Key 2>&1 | Out-String
    $entries = @()
    foreach ($line in ($out -split "`r?`n")) {
        if ($line -match '^\s*\d+:\s*(\d+:\S.*?)\s*$') { $entries += $Matches[1] }
    }
    return $entries
}
foreach ($key in 'CA\CRLPublicationURLs', 'CA\CACertPublicationURLs') {
    $cur  = Get-RegMultiSz -Key $key
    $keep = $cur | Where-Object { $_ -notmatch '(?i)msappproxy\.net' }
    $drop = $cur | Where-Object { $_ -match  '(?i)msappproxy\.net' }
    if (-not $drop) { Write-Host "  $key : no msappproxy entries." -ForegroundColor Green; continue }
    Write-Host "  $key - would remove:" -ForegroundColor Gray
    $drop | ForEach-Object { Write-Host "    $_" -ForegroundColor DarkYellow }
    if (Confirm-Step "Rewrite $key without the msappproxy entries?") {
        & certutil.exe -setreg $key ($keep -join "\n") | Out-String | Write-Host
    }
}
$certsvc = Get-Service -Name CertSvc -ErrorAction SilentlyContinue
if ($certsvc -and (Confirm-Step "Restart CertSvc + republish the CRL?")) {
    Restart-Service -Name CertSvc -Force -ErrorAction SilentlyContinue
    for ($i = 0; $i -lt 10; $i++) {
        $certsvc = Get-Service -Name CertSvc -ErrorAction SilentlyContinue
        if ($certsvc.Status -eq 'Running') { break }
        Start-Sleep -Seconds 3
    }
    if ($certsvc.Status -eq 'Running') {
        $out = & certutil.exe -crl 2>&1 | Out-String
        Write-Host $out
        if ($LASTEXITCODE -ne 0) { Write-Host "  certutil -crl failed - run it by hand once the CA is settled (registry changes ARE applied)." -ForegroundColor Yellow }
    } else {
        Write-Host "  CertSvc did not come back Running (reboot pending?). Registry changes are applied - start CertSvc and run 'certutil -crl' after the reboot." -ForegroundColor Yellow
    }
}

# ---------------------------------------------------------------------------
# 6. CAAnswers.json - blank the resolved FQDNs
# ---------------------------------------------------------------------------
Write-Host "`n-- CAAnswers.json --" -ForegroundColor White
if (-not (Test-Path $CAAnswersPath)) { Write-Host "  $CAAnswersPath not found - skip." -ForegroundColor Yellow }
else {
    $ans = Get-Content $CAAnswersPath -Raw | ConvertFrom-Json
    $changed = $false
    foreach ($f in 'CA_AppProxyCrlFqdn', 'CA_AppProxyOcspFqdn', 'CA_MsAppProxyTenant') {
        if ($ans.PSObject.Properties[$f] -and -not [string]::IsNullOrWhiteSpace($ans.$f)) {
            Write-Host "  $f = '$($ans.$f)'" -ForegroundColor Gray; $changed = $true
        }
    }
    if (-not $changed) { Write-Host "  nothing to blank." -ForegroundColor Green }
    elseif (Confirm-Step "Blank those fields in $CAAnswersPath?") {
        foreach ($f in 'CA_AppProxyCrlFqdn', 'CA_AppProxyOcspFqdn', 'CA_MsAppProxyTenant') {
            if ($ans.PSObject.Properties[$f]) { $ans.$f = '' }
        }
        $json = ($ans | ConvertTo-Json -Depth 6) -replace "`r`n", "`n" -replace "`n", "`r`n"
        Set-Content -Path $CAAnswersPath -Value $json -Encoding UTF8
        Write-Host "    blanked." -ForegroundColor Green
    }
}

Write-Host "`n==== teardown pass complete ====" -ForegroundColor Cyan
Write-Host "If you uninstalled the connector, re-run this script (Entra half) once WAPCSvc is gone to"  -ForegroundColor Gray
Write-Host "delete the now-inactive tenant connector object, then re-run CA-Manager menu 7 from clean." -ForegroundColor Gray
