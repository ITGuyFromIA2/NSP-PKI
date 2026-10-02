<#
.SYNOPSIS
    CA Manager - the internal IIS endpoints the Entra Application Proxy forwards to (dashboard menu
    7, step 7b). Requires Modules\CACore.ps1 (Invoke-CAStep) and, to apply, the Windows Server IIS
    role + the WebAdministration provider.

.DESCRIPTION
    Get-CAWebEndpointPlan is PURE - it describes the `/CertEnroll/` virtual directory the App Proxy
    "CRL" app publishes: physical path (the CA's own CertEnroll dir, or CA_CrlSharePath when a CRL
    share is in play), directory browsing on, and the .crl / .crt static-content MIME types.

    Test-CAWebEndpoint is a read-only probe (feature installed? vdir present? MIME resolves? does
    http://localhost/CertEnroll/<caname>.crl answer 200?).

    Set-CAWebEndpoint is the engine - every mutation via Invoke-CAStep. Plain HTTP only, matching
    the reference client setup (the App Proxy connector forwards to local IIS over HTTP; externalAuthenticationType is
    passthru so there is no pre-auth and nothing to translate).

    The `/ocsp/` endpoint comes from the Online Responder role (menu 9) - it creates its own ISAPI
    app under the Default Web Site; nothing here touches it.
#>

# ---------------------------------------------------------------------------
function Get-CAWebEndpointPlan {
    <#
    .SYNOPSIS
        PURE. The CertEnroll virtual-directory plan. -PhysicalPath overrides the default
        (%windir%\System32\CertSrv\CertEnroll); pass CA_CrlSharePath for a CRL-share deployment.
    #>
    param(
        [string]$PhysicalPath = '%windir%\System32\CertSrv\CertEnroll',
        [string]$SiteName     = 'Default Web Site',
        [string]$VDirName     = 'CertEnroll',
        [string]$CACommonName
    )
    [pscustomobject]@{
        SiteName        = $SiteName
        VDirName        = $VDirName
        PhysicalPath    = $PhysicalPath
        DirectoryBrowse = $true
        MimeTypes       = @(
            [pscustomobject]@{ Ext = '.crl'; Mime = 'application/pkix-crl' }
            [pscustomobject]@{ Ext = '.crt'; Mime = 'application/x-x509-ca-cert' }
        )
        VerifyUrl       = "http://localhost/$VDirName/" + $(if ($CACommonName) { "$CACommonName.crl" } else { '' })
    }
}

# ---------------------------------------------------------------------------
function Show-CAWebEndpointPlan {
    param($Plan)
    Write-Host ""
    Write-Host ("  IIS virtual directory: {0} -> {1}" -f "/$($Plan.VDirName)/", $Plan.PhysicalPath) -ForegroundColor White
    Write-Host ("    site            : {0}" -f $Plan.SiteName) -ForegroundColor Gray
    Write-Host ("    directory browse: {0}" -f $Plan.DirectoryBrowse) -ForegroundColor Gray
    foreach ($m in $Plan.MimeTypes) { Write-Host ("    MIME            : {0} -> {1}" -f $m.Ext, $m.Mime) -ForegroundColor Gray }
    Write-Host  "    scheme          : plain HTTP (the App Proxy connector forwards over HTTP; passthru pre-auth)" -ForegroundColor DarkGray
    if ($Plan.VerifyUrl) { Write-Host ("    verify with     : {0}" -f $Plan.VerifyUrl) -ForegroundColor DarkGray }
}

# ---------------------------------------------------------------------------
function Test-CAWebEndpoint {
    <#
    .SYNOPSIS
        Read-only. Returns a [pscustomobject] of bools for the dashboard / menu-7 preview.
    #>
    param($Plan)
    $r = [ordered]@{
        IISInstalled       = $null
        VDirPresent        = $null
        VDirPathMatches    = $null
        CrlMimePresent     = $null
        AnswersHttp        = $null
    }
    try {
        if (Get-Command Get-WindowsFeature -ErrorAction SilentlyContinue) {
            $r.IISInstalled = [bool](Get-WindowsFeature -Name Web-Server -ErrorAction Stop).Installed
        }
    } catch { }

    if ($r.IISInstalled) {
        try { Import-Module WebAdministration -ErrorAction Stop } catch { }
        try {
            $vd = Get-WebVirtualDirectory -Site $Plan.SiteName -Name $Plan.VDirName -ErrorAction SilentlyContinue
            $r.VDirPresent = [bool]$vd
            if ($vd) {
                $want = [Environment]::ExpandEnvironmentVariables($Plan.PhysicalPath)
                $r.VDirPathMatches = ($vd.physicalPath -and ($vd.physicalPath.TrimEnd('\') -ieq $want.TrimEnd('\')))
            }
        } catch { }
        try {
            $mm = Get-WebConfigurationProperty -PSPath "IIS:\Sites\$($Plan.SiteName)\$($Plan.VDirName)" `
                -Filter "system.webServer/staticContent/mimeMap[@fileExtension='.crl']" -Name '.' -ErrorAction SilentlyContinue
            $r.CrlMimePresent = [bool]$mm
        } catch { }
    }

    if ($Plan.VerifyUrl -and $Plan.VerifyUrl -notmatch '/$') {
        try {
            $resp = Invoke-WebRequest -UseBasicParsing -Uri $Plan.VerifyUrl -TimeoutSec 10 -ErrorAction Stop
            $r.AnswersHttp = ($resp.StatusCode -eq 200)
        } catch { $r.AnswersHttp = $false }
    }
    return [pscustomobject]$r
}

# ---------------------------------------------------------------------------
function Set-CAWebEndpoint {
    <#
    .SYNOPSIS
        Ensures the IIS role + the CertEnroll virtual directory + MIME types + directory browsing.
        Every mutation via Invoke-CAStep. Idempotent.
    #>
    param([Parameter(Mandatory)]$Plan)

    if (-not (Get-Command Get-WindowsFeature -ErrorAction SilentlyContinue)) {
        Write-Host "  Server-Manager cmdlets missing - run menu 6 on the CA (a Windows Server)." -ForegroundColor Red
        return
    }

    $resolvedPath = [Environment]::ExpandEnvironmentVariables($Plan.PhysicalPath)

    # 1. IIS role
    if (-not (Get-WindowsFeature -Name Web-Server -ErrorAction SilentlyContinue).Installed) {
        Invoke-CAStep -Description "Install the Web Server (IIS) role" `
            -Commands @('Install-WindowsFeature -Name Web-Server -IncludeManagementTools') `
            -Action { Install-WindowsFeature -Name Web-Server -IncludeManagementTools | Out-String } | Out-Null
    } else {
        Write-Host "  Web-Server role already installed." -ForegroundColor Green
    }

    Import-Module WebAdministration -ErrorAction SilentlyContinue

    # 2. virtual directory
    $existingVd = $null
    try { $existingVd = Get-WebVirtualDirectory -Site $Plan.SiteName -Name $Plan.VDirName -ErrorAction SilentlyContinue } catch { }
    if (-not $existingVd) {
        Invoke-CAStep -Description "Create IIS virtual directory /$($Plan.VDirName)/ -> $resolvedPath" `
            -Commands @("New-WebVirtualDirectory -Site '$($Plan.SiteName)' -Name '$($Plan.VDirName)' -PhysicalPath '$resolvedPath'") `
            -Action { New-WebVirtualDirectory -Site $Plan.SiteName -Name $Plan.VDirName -PhysicalPath $resolvedPath | Out-Null } | Out-Null
    } else {
        Write-Host "  Virtual directory /$($Plan.VDirName)/ already exists ($($existingVd.physicalPath))." -ForegroundColor Green
    }

    # 3. directory browsing
    if ($Plan.DirectoryBrowse) {
        Invoke-CAStep -Description "Enable directory browsing on /$($Plan.VDirName)/" `
            -Commands @("Set-WebConfigurationProperty -PSPath 'IIS:\Sites\$($Plan.SiteName)\$($Plan.VDirName)' -Filter '/system.webServer/directoryBrowse' -Name enabled -Value `$true") `
            -Action {
                Set-WebConfigurationProperty -PSPath "IIS:\Sites\$($Plan.SiteName)\$($Plan.VDirName)" `
                    -Filter '/system.webServer/directoryBrowse' -Name enabled -Value $true
            } -ContinueOnError | Out-Null
    }

    # 4. MIME types (site level - inherited by the vdir; add each only if absent)
    foreach ($m in $Plan.MimeTypes) {
        $present = $false
        try {
            $mm = Get-WebConfigurationProperty -PSPath "IIS:\Sites\$($Plan.SiteName)" `
                -Filter "system.webServer/staticContent/mimeMap[@fileExtension='$($m.Ext)']" -Name '.' -ErrorAction SilentlyContinue
            $present = [bool]$mm
        } catch { }
        if ($present) { Write-Host "  MIME $($m.Ext) already mapped." -ForegroundColor Green; continue }
        Invoke-CAStep -Description "Map MIME type $($m.Ext) -> $($m.Mime)" `
            -Commands @("Add-WebConfigurationProperty -PSPath 'IIS:\Sites\$($Plan.SiteName)' -Filter 'system.webServer/staticContent' -Name '.' -Value @{fileExtension='$($m.Ext)'; mimeType='$($m.Mime)'}") `
            -Action {
                Add-WebConfigurationProperty -PSPath "IIS:\Sites\$($Plan.SiteName)" `
                    -Filter 'system.webServer/staticContent' -Name '.' `
                    -Value @{ fileExtension = $m.Ext; mimeType = $m.Mime }
            } -ContinueOnError | Out-Null
    }

    # 5. allowDoubleEscaping on /CertEnroll/. The App Proxy connector forwards the CRL path with the
    #    slash encoded (/CertEnroll%2fCLIENT-CA.crl); IIS request filtering rejects a double-escaped
    #    sequence with 404 by default. Also covers the '(' in a renewed CA's "CAName(1).crl".
    Invoke-CAStep -Description "Allow double-escaping on /$($Plan.VDirName)/ (App Proxy encodes the path slash; renewed-CA CRL names)" `
        -Commands @("Set-WebConfigurationProperty -PSPath 'IIS:\Sites\$($Plan.SiteName)\$($Plan.VDirName)' -Filter 'system.webServer/security/requestFiltering' -Name allowDoubleEscaping -Value `$true") `
        -Action {
            Set-WebConfigurationProperty -PSPath "IIS:\Sites\$($Plan.SiteName)\$($Plan.VDirName)" `
                -Filter 'system.webServer/security/requestFiltering' -Name allowDoubleEscaping -Value $true
        } -ContinueOnError | Out-Null

    # 6. verify (best-effort - the .crl may not exist until certutil -crl has run)
    if ($Plan.VerifyUrl -and $Plan.VerifyUrl -notmatch '/$' -and -not (Get-CADryRun)) {
        try {
            $resp = Invoke-WebRequest -UseBasicParsing -Uri $Plan.VerifyUrl -TimeoutSec 10 -ErrorAction Stop
            Write-Host ("  verify: {0} -> HTTP {1}  ({2})" -f $Plan.VerifyUrl, $resp.StatusCode, $resp.Headers['Content-Type']) -ForegroundColor Green
        } catch {
            Write-Host ("  verify: {0} did not answer 200 yet ({1}) - run 'certutil -crl' if the CRL file is missing." -f $Plan.VerifyUrl, $_.Exception.Message) -ForegroundColor Yellow
        }
    }
}
