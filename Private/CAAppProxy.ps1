<#
.SYNOPSIS
    CA Manager - Entra Application Proxy: the private-network connector on the CA box, a connector
    group, and the two published apps (CRL/AIA + OCSP) that expose the CA's revocation endpoints to
    the internet (dashboard menu 6, steps 6c-6f). Requires Modules\CACore.ps1 (Invoke-CAStep),
    Modules\CAGraph.ps1 (Connect-CAGraph + the request helpers), and the Microsoft.Graph.Authentication
    module. Applying the connector install also needs Application Administrator on the tenant.

.DESCRIPTION
    Reproduces a real client's hand-built setup (Get-CAManagerEntraProxyInventory.ps1): connector group
    "CertChecks", apps "CRL" + "OCSP-Relay", externalAuthenticationType=passthru, plain HTTP
    end-to-end, host-header translation on, links-in-body off, SSO none,
    appRoleAssignmentRequired=false (CRL/OCSP clients are anonymous).

    Pure helpers (Get-CAAppProxyFqdn / Get-CAUrlHost / Get-CAAppProxyPublishingBody /
    Get-CAAppProxyPlan) are unit-tested. Everything that mutates the tenant goes through
    Invoke-CAGraphStep (from CAGraph.ps1); the connector .exe download / silent install /
    RegisterConnector.ps1 go through Invoke-CAStep directly - so the whole of menu 6 walks
    end-to-end in DRY RUN on any box with Microsoft.Graph.Authentication + internet, changing nothing.

    The composed <prefix>-<tenant>.msappproxy.net hostname is a PLACEHOLDER only. Entra assigns the
    real externalUrl (it appends "-1" on a prefix collision, keeps the path, may use a vanity
    domain); menu 6 always reads it back and overwrites CA_AppProxyCrlFqdn / CA_AppProxyOcspFqdn.
#>

# =========================================================================
# PURE helpers
# =========================================================================
function Get-CAAppProxyFqdn {
    <#
    .SYNOPSIS
        Composes '<prefix>-<tenant>.msappproxy.net'. PLACEHOLDER only - the real host comes back from
        onPremisesPublishing.externalUrl after the app is created.
    #>
    param(
        [Parameter(Mandatory)][string]$Prefix,
        [Parameter(Mandatory)][string]$Tenant
    )
    $p = $Prefix.Trim().ToLower().Trim('-')
    $t = $Tenant.Trim().ToLower() -replace '(?i)\.onmicrosoft\.com$', '' -replace '(?i)\.msappproxy\.net$', ''
    $t = $t.Trim('-')
    return "$p-$t.msappproxy.net"
}

function Get-CAUrlHost {
    <#
    .SYNOPSIS
        'http://crl-x.msappproxy.net/CertEnroll/' -> 'crl-x.msappproxy.net'. Blank/no-scheme -> ''.
    #>
    param([string]$Url)
    if ([string]::IsNullOrWhiteSpace($Url)) { return '' }
    if ($Url -match '^(?i)https?://([^/]+)') { return $Matches[1] }
    return ($Url -replace '/.*$', '')
}

function Get-CAAppProxyPublishingBody {
    <#
    .SYNOPSIS
        PURE. The onPremisesPublishing PATCH body - the exact reference-client shape.
    #>
    param(
        [Parameter(Mandatory)][string]$InternalUrl,
        [Parameter(Mandatory)][string]$ExternalUrl,
        [bool]$BackendCertValidation
    )
    @{
        onPremisesPublishing = @{
            externalAuthenticationType            = 'passthru'
            internalUrl                           = $InternalUrl
            externalUrl                           = $ExternalUrl
            isOnPremPublishingEnabled             = $true
            isTranslateHostHeaderEnabled          = $true
            isTranslateLinksInBodyEnabled         = $false
            isBackendCertificateValidationEnabled = [bool]$BackendCertValidation
            applicationServerTimeout             = 'Default'
            singleSignOnSettings                 = @{ singleSignOnMode = 'none' }
        }
    }
}

function Get-CAAppProxyPlan {
    <#
    .SYNOPSIS
        PURE. The whole menu-7 App Proxy plan (connector group + the two app specs) from CAAnswers,
        the CA's own FQDN, and the msappproxy tenant label.
    #>
    param(
        $CAAnswers,
        [Parameter(Mandatory)][string]$CAHostFqdn,
        [Parameter(Mandatory)][string]$TenantLabel
    )
    $grp     = if ($CAAnswers.CA_AppProxyConnectorGroup) { $CAAnswers.CA_AppProxyConnectorGroup } else { 'CertChecks' }
    $crlName  = if ($CAAnswers.CA_AppProxyCrlAppName)     { $CAAnswers.CA_AppProxyCrlAppName }     else { 'CRL Relay' }
    $ocspName = if ($CAAnswers.CA_AppProxyOcspAppName)    { $CAAnswers.CA_AppProxyOcspAppName }    else { 'OCSP Relay' }

    # Prefer a prefix already implied by a saved FQDN ('crl-foo.msappproxy.net' -> 'crl'); else default.
    $crlPrefix  = 'crl'
    $ocspPrefix = 'ocsprelay'
    if ($CAAnswers.CA_AppProxyCrlFqdn  -match '^(?i)([a-z0-9]+)-') { $crlPrefix  = $Matches[1].ToLower() }
    if ($CAAnswers.CA_AppProxyOcspFqdn -match '^(?i)([a-z0-9]+)-') { $ocspPrefix = $Matches[1].ToLower() }

    [pscustomobject]@{
        ConnectorGroupName = $grp
        ConnectorMachine   = $CAHostFqdn
        Apps = @(
            [pscustomobject]@{
                Key = 'CRL'; DisplayName = $crlName; Prefix = $crlPrefix
                InternalUrl      = "http://$CAHostFqdn/CertEnroll/"
                ExternalUrlGuess = "http://$(Get-CAAppProxyFqdn -Prefix $crlPrefix -Tenant $TenantLabel)/CertEnroll/"
                BackendCertValidation = $true
            }
            [pscustomobject]@{
                Key = 'OCSP'; DisplayName = $ocspName; Prefix = $ocspPrefix
                InternalUrl      = "http://$CAHostFqdn/ocsp/"
                ExternalUrlGuess = "http://$(Get-CAAppProxyFqdn -Prefix $ocspPrefix -Tenant $TenantLabel)/ocsp/"
                BackendCertValidation = $false
            }
        )
    }
}

function Show-CAAppProxyPlan {
    param($Plan)
    Write-Host ""
    Write-Host ("  Connector group : {0}   (connector: {1})" -f $Plan.ConnectorGroupName, $Plan.ConnectorMachine) -ForegroundColor White
    foreach ($a in $Plan.Apps) {
        Write-Host ""
        Write-Host ("  App '{0}'  ({1})" -f $a.DisplayName, $a.Key) -ForegroundColor White
        Write-Host ("    internal : {0}" -f $a.InternalUrl) -ForegroundColor Gray
        Write-Host ("    external : {0}   (placeholder - Entra assigns the real host)" -f $a.ExternalUrlGuess) -ForegroundColor Gray
        Write-Host ("    publish  : passthru / HTTP / translate-host-header=on / links-in-body=off / SSO=none / anonymous") -ForegroundColor DarkGray
        Write-Host ("    backend cert validation : {0}" -f $a.BackendCertValidation) -ForegroundColor DarkGray
    }
}

# =========================================================================
# 7c - connector install + registration
# =========================================================================
function Get-CAConnectorPaths {
    <#
    .SYNOPSIS
        Read-only. Returns the install dir / RegisterConnector.ps1 path / PS module path+name for
        whichever connector generation is installed (or would be), or $null if neither dir exists.
        Legacy = "Microsoft AAD App Proxy Connector"; modern = "Microsoft Entra private network connector".
    #>
    $pf = ${env:ProgramFiles}
    $candidates = @(
        [pscustomobject]@{ InstallDir = Join-Path $pf 'Microsoft Entra private network connector'; ModuleName = 'MicrosoftEntraPrivateNetworkConnectorPSModule' }
        [pscustomobject]@{ InstallDir = Join-Path $pf 'Microsoft AAD App Proxy Connector';         ModuleName = 'AppProxyPSModule' }
    )
    foreach ($c in $candidates) {
        if (-not (Test-Path $c.InstallDir)) { continue }
        # newer builds move RegisterConnector.ps1 into a subfolder (\PowerShell\, \Modules\...) - search.
        $reg = Get-ChildItem -Path $c.InstallDir -Recurse -Filter 'RegisterConnector.ps1' -ErrorAction SilentlyContinue |
            Select-Object -First 1
        $modDir = Get-ChildItem -Path $c.InstallDir -Recurse -Directory -Filter 'Modules' -ErrorAction SilentlyContinue |
            Select-Object -First 1
        return [pscustomobject]@{
            InstallDir     = $c.InstallDir
            RegisterScript = if ($reg) { $reg.FullName } else { Join-Path $c.InstallDir 'RegisterConnector.ps1' }
            ModulePath     = if ($modDir) { $modDir.FullName } elseif ($reg) { Join-Path (Split-Path $reg.FullName) 'Modules' } else { Join-Path $c.InstallDir 'Modules' }
            ModuleName     = $c.ModuleName
            RegisterFound  = [bool]$reg
        }
    }
    return $null
}

function Get-CAConnectorRegistrationToken {
    <#
    .SYNOPSIS
        Acquires an INTERACTIVE token for the connector-REGISTRATION resource (NOT Microsoft Graph -
        different audience). Returns @{ Token; TenantId }, or $null so the caller falls back to
        -AuthenticationMode Credentials (Get-Credential).
    #>
    param([string]$TenantId)

    # public client + resource used by RegisterConnector.ps1's own interactive flow
    $connectorClientId = '55747057-9b5d-4bd4-b387-abf52a8bd489'
    $scope             = 'https://proxy.cloudwebappproxy.net/registerapp/user_impersonation'
    $authority         = if ($TenantId) { "https://login.microsoftonline.com/$TenantId" } else { 'https://login.microsoftonline.com/common' }

    # MSAL's embedded WebView is IE-based; on Windows Server it fails (blank window / no navigation)
    # while IE Enhanced Security Configuration is ON for the current user. Warn early - the fix is
    # Server Manager -> Local Server -> IE Enhanced Security Configuration -> Off for Administrators.
    try {
        $adminEsc = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}' -Name IsInstalled -ErrorAction Stop).IsInstalled
        if ($adminEsc -eq 1) {
            Write-Host "  NOTE: IE Enhanced Security Configuration is ON. If the sign-in window is blank, turn it" -ForegroundColor Yellow
            Write-Host "        off (Server Manager -> Local Server -> IE Enhanced Security Configuration -> Off)," -ForegroundColor Yellow
            Write-Host "        or answer 'n' at the next prompt to register with a username/password instead." -ForegroundColor Yellow
        }
    } catch { }

    try {
        $modBase = (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication | Select-Object -First 1).ModuleBase
        $dll = Get-ChildItem -Path $modBase -Recurse -Filter 'Microsoft.Identity.Client.dll' -ErrorAction SilentlyContinue | Select-Object -First 1
        if (-not $dll) { return $null }
        Add-Type -Path $dll.FullName -ErrorAction Stop

        $app = [Microsoft.Identity.Client.PublicClientApplicationBuilder]::Create($connectorClientId).
                    WithAuthority($authority).
                    WithDefaultRedirectUri().
                    Build()
        $result = $app.AcquireTokenInteractive([string[]]@($scope)).ExecuteAsync().GetAwaiter().GetResult()
        return @{ Token = $result.AccessToken; TenantId = $result.TenantId }
    } catch {
        Write-Host "  Could not acquire a registration token interactively ($($_.Exception.Message))." -ForegroundColor DarkYellow
        return $null
    }
}

function Assert-CAValidExe {
    <#
    .SYNOPSIS
        Throws (with an actionable message) unless $Path is a real Windows PE executable - guards
        against a redirect that saved an HTML page / a truncated or AV-locked download.
    #>
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path $Path)) { throw "installer not found at $Path" }
    $len = (Get-Item $Path).Length
    $mz = ''
    try { $fs = [IO.File]::OpenRead($Path); $b = New-Object byte[] 2; [void]$fs.Read($b, 0, 2); $fs.Close(); $mz = -join ([char[]]$b) } catch { }
    if ($len -lt 500KB -or $mz -ne 'MZ') {
        throw ("the downloaded file is not a valid installer (size $([math]::Round($len/1KB)) KB, header '$mz'). " +
               "The aka.ms link is likely blocked or served a page. Download it by hand from the Entra admin " +
               "center (Enterprise applications -> Application proxy -> Download connector service) and re-run " +
               "menu 6, or point Install-CAAppProxyConnector -InstallerPath at the .exe.")
    }
}

function Get-CAConnectorInstallerUrls {
    <#
    .SYNOPSIS
        Candidate download URLs for the connector installer, best first. The tenant-scoped
        download.msappproxy.net URL is what the portal's "Download connector service" button hits
        (plain GET, no auth); the aka.ms short links have historically redirected there but are
        unreliable (aka.ms/aadapplicationproxyconnector currently 302s to bing.com).
    #>
    param([string]$TenantId)
    $u = @()
    if ($TenantId) {
        $u += "https://download.msappproxy.net/Subscription/$TenantId/Connector/DownloadConnectorInstaller"
        $u += "https://download.msappproxy.net/Subscription/$TenantId/Connector/download"
    }
    $u += 'https://aka.ms/EntraPrivateNetworkConnector'
    $u += 'https://aka.ms/aadapplicationproxyconnector'
    return $u
}

function Get-CAConnectorInstaller {
    <#
    .SYNOPSIS
        Fetches the connector installer to -OutFile, trying each Get-CAConnectorInstallerUrls
        candidate with curl.exe -L (in-box, clean redirects) then Invoke-WebRequest. Validates each
        result is a real PE; throws an actionable message if none is.
    #>
    param(
        [Parameter(Mandatory)][string]$OutFile,
        [string]$TenantId,
        [string[]]$Url
    )
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    if (-not $Url) { $Url = Get-CAConnectorInstallerUrls -TenantId $TenantId }
    $curl = Get-Command curl.exe -ErrorAction SilentlyContinue

    foreach ($u in $Url) {
        Remove-Item $OutFile -ErrorAction SilentlyContinue
        Write-Host "  trying $u" -ForegroundColor DarkGray
        if ($curl) { & $curl.Source -sL --fail --retry 2 -o $OutFile $u 2>$null }
        if (-not (Test-Path $OutFile) -or (Get-Item $OutFile).Length -lt 500KB) {
            try { Invoke-WebRequest -UseBasicParsing -Uri $u -OutFile $OutFile -MaximumRedirection 8 -ErrorAction Stop } catch { }
        }
        try { Assert-CAValidExe -Path $OutFile; Write-Host "  got a valid installer from $u" -ForegroundColor Green; return }
        catch { }
    }
    throw ("None of the known download URLs returned a valid installer. Download it by hand from the " +
           "Entra admin center (Enterprise applications -> Application proxy -> Download connector service), " +
           "then re-run menu 6 and give 6c the path to the .exe.")
}

function Install-CAAppProxyConnector {
    <#
    .SYNOPSIS
        Downloads + silently installs the Entra private network connector and registers it to the
        tenant. Idempotent - skips when WAPCSvc is already Running. Every step via Invoke-CAStep.

    .PARAMETER InstallerPath
        Use an already-downloaded AADApplicationProxyConnectorInstaller.exe instead of fetching it
        (for when the aka.ms download is blocked / the box has no direct internet). Get it by hand
        from: Entra admin center -> Enterprise applications -> Application proxy -> Download connector service.
    #>
    param(
        [string]$TenantId,
        [string]$InstallerPath
    )

    $svc = Get-Service -Name WAPCSvc -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -eq 'Running') {
        Write-Host "  Connector already installed (WAPCSvc is Running) - skipping install/register." -ForegroundColor Green
        return
    }

    $installer = if ($InstallerPath) { $InstallerPath } else { Join-Path $env:TEMP 'AADApplicationProxyConnectorInstaller.exe' }

    if (-not $InstallerPath) {
        Invoke-CAStep -Description "Download the tenant-scoped connector installer" `
            -Commands @("curl.exe -L -o <tmp>  (download.msappproxy.net/Subscription/$TenantId/Connector/... then aka.ms/*)") `
            -Action { Get-CAConnectorInstaller -OutFile $installer -TenantId $TenantId } | Out-Null
    } elseif (-not (Test-Path $installer)) {
        throw "InstallerPath '$installer' does not exist."
    } else {
        Write-Host "  Using supplied installer: $installer" -ForegroundColor Gray
        Assert-CAValidExe -Path $installer
    }

    # The tenant-scoped installer from download.msappproxy.net has this tenant baked in and does the
    # registration IN its own setup wizard (interactive sign-in). Modern builds ship NO
    # RegisterConnector.ps1 / PS module, so there's nothing to call afterwards - the installer IS the
    # register step. Run it interactively (no /q); the tech completes the wizard + sign-in.
    $paths = Get-CAConnectorPaths
    if ($paths -and $paths.RegisterFound -and -not $svc) {
        # legacy "Microsoft AAD App Proxy Connector" generation - silent install + RegisterConnector.ps1
        Invoke-CAStep -Description "Silently install the connector (registration deferred)" `
            -Commands @("& '$installer' REGISTERCONNECTOR=`"false`" /q") `
            -Action {
                Assert-CAValidExe -Path $installer
                $p = Start-Process -FilePath $installer -ArgumentList 'REGISTERCONNECTOR="false"', '/q' -Wait -PassThru
                if ($p.ExitCode -ne 0) { throw "connector installer exited $($p.ExitCode)" }
            } | Out-Null
        $paths = Get-CAConnectorPaths
        $regCmd = "& '$($paths.RegisterScript)' -modulePath '$($paths.ModulePath)' -moduleName '$($paths.ModuleName)' -AuthenticationMode Interactive -Feature ApplicationProxy"
        Invoke-CAStep -Description "Register the connector (RegisterConnector.ps1, interactive sign-in)" `
            -Commands @($regCmd) `
            -Action {
                & $paths.RegisterScript -modulePath $paths.ModulePath -moduleName $paths.ModuleName -AuthenticationMode Interactive -Feature ApplicationProxy
                if ($LASTEXITCODE -ne 0) {
                    Write-Host "`n  RegisterConnector.ps1 exited $LASTEXITCODE. Run this here, sign in, then press Enter:" -ForegroundColor Yellow
                    Write-Host "    $regCmd" -ForegroundColor Cyan
                    Read-Host "  [Enter] once registered"
                }
            } -ContinueOnError | Out-Null
    }
    else {
        # modern "Microsoft Entra private network connector": no RegisterConnector.ps1 - the
        # tenant-scoped installer registers in its own setup. Try /passive first (it MAY
        # auto-register off the baked-in tenant); if WAPCSvc doesn't come up, run it interactively so
        # the tech completes the sign-in.
        Invoke-CAStep -Description "Install + register the connector (tenant-scoped installer)" `
            -Commands @("Start-Process '$installer' /passive   ; if not Running -> Start-Process '$installer'  (wizard sign-in)") `
            -Action {
                Assert-CAValidExe -Path $installer
                Write-Host "  trying /passive..." -ForegroundColor DarkGray
                Start-Process -FilePath $installer -ArgumentList '/passive' -Wait
                for ($i = 0; $i -lt 8; $i++) { if ((Get-Service WAPCSvc -ErrorAction SilentlyContinue).Status -eq 'Running') { break }; Start-Sleep 5 }
                if ((Get-Service WAPCSvc -ErrorAction SilentlyContinue).Status -ne 'Running') {
                    Write-Host "  /passive didn't register - launching the setup wizard; accept the EULA and sign in when prompted." -ForegroundColor Cyan
                    Start-Process -FilePath $installer -Wait
                    Read-Host "  [Enter] once the wizard has finished and you've signed in"
                }
            } -ContinueOnError | Out-Null
    }

    if (-not (Get-CADryRun)) {
        for ($i = 0; $i -lt 18; $i++) {
            $svc = Get-Service -Name WAPCSvc -ErrorAction SilentlyContinue
            if ($svc -and $svc.Status -eq 'Running') { break }
            Start-Sleep -Seconds 5
        }
        $ok = ($svc -and $svc.Status -eq 'Running')
        Write-Host ("  WAPCSvc: {0}" -f $(if ($svc) { $svc.Status } else { 'not found' })) -ForegroundColor $(if ($ok) { 'Green' } else { 'Yellow' })
        if (-not $ok) { Write-Host "  Connector not Running yet - it may still be registering; re-check, or re-run menu 6." -ForegroundColor Yellow }
    }
}

function Get-CAAppProxyConnector {
    <#
    .SYNOPSIS
        The tenant's connector object matching -MachineName (FQDN or NetBIOS, case-insensitive), or $null.
    #>
    param([Parameter(Mandatory)][string]$MachineName)
    $short = ($MachineName -split '\.')[0]
    $all = @(Get-CAGraphAll "$script:CAGraphBeta/onPremisesPublishingProfiles/applicationProxy/connectors" -Quiet)
    return ($all | Where-Object {
        $_.machineName -and (($_.machineName -ieq $MachineName) -or (($_.machineName -split '\.')[0] -ieq $short))
    } | Select-Object -First 1)
}

# =========================================================================
# 7d - connector group
# =========================================================================
function New-CAAppProxyConnectorGroup {
    <#
    .SYNOPSIS
        Ensures an applicationProxy connector group named -Name (reuse if present). Returns its id.
    #>
    param([Parameter(Mandatory)][string]$Name)
    $existing = @(Get-CAGraphAll "$script:CAGraphBeta/onPremisesPublishingProfiles/applicationProxy/connectorGroups" -Quiet) |
        Where-Object { $_.name -eq $Name -and $_.connectorGroupType -eq 'applicationProxy' } | Select-Object -First 1
    if ($existing) {
        Write-Host "  Connector group '$Name' already exists (id $($existing.id))." -ForegroundColor Green
        return $existing.id
    }
    $body = Invoke-CAGraphStep -Description "Create connector group '$Name'" -Method POST `
        -Uri "$script:CAGraphBeta/onPremisesPublishingProfiles/applicationProxy/connectorGroups" `
        -Body @{ name = $Name }
    if ($body) { return $body.id }
    if (Get-CADryRun) { return '<connectorGroupId>' }   # dry-run - so downstream steps still preview
    return $null
}

function Add-CAAppProxyConnectorToGroup {
    param(
        [Parameter(Mandatory)][string]$ConnectorId,
        [Parameter(Mandatory)][string]$GroupId
    )
    $member = Get-CAGraphOne "$script:CAGraphBeta/onPremisesPublishingProfiles/applicationProxy/connectors/$ConnectorId/memberOf" -Quiet
    if ($member -and (@($member.value).id -contains $GroupId)) {
        Write-Host "  Connector already in group $GroupId." -ForegroundColor Green
        return
    }
    $ref = @{ '@odata.id' = "$script:CAGraphBeta/onPremisesPublishingProfiles/applicationProxy/connectorGroups/$GroupId" }
    try {
        Invoke-CAGraphStep -Description "Add the connector to group $GroupId" -Method POST `
            -Uri "$script:CAGraphBeta/onPremisesPublishingProfiles/applicationProxy/connectors/$ConnectorId/memberOf/`$ref" `
            -Body $ref | Out-Null
    } catch {
        # some tenants/builds want PUT for the single-valued memberOf ref
        Invoke-CAGraphStep -Description "Add the connector to group $GroupId (PUT fallback)" -Method PUT `
            -Uri "$script:CAGraphBeta/onPremisesPublishingProfiles/applicationProxy/connectors/$ConnectorId/memberOf/`$ref" `
            -Body $ref | Out-Null
    }
}

# =========================================================================
# 7e - the two Entra apps
# =========================================================================
function Get-CAAppProxyApp {
    <#
    .SYNOPSIS
        Finds an App Proxy app by displayName via the servicePrincipal tag scan (the inventory
        script's proven path). Returns @{ AppObjectId; AppId; SpId } or $null.
    #>
    param([Parameter(Mandatory)][string]$DisplayName)
    $sps = @(Get-CAGraphAll "$script:CAGraphBeta/servicePrincipals?`$select=id,appId,displayName,tags&`$top=999" -Quiet)
    $sp = $sps | Where-Object { $_.tags -contains 'WindowsAzureActiveDirectoryOnPremApp' -and $_.displayName -eq $DisplayName } | Select-Object -First 1
    if (-not $sp) { return $null }
    $app = (Get-CAGraphOne "$script:CAGraphV1/applications?`$filter=appId eq '$($sp.appId)'&`$select=id,appId,displayName" -Quiet).value | Select-Object -First 1
    if (-not $app) { $app = (Get-CAGraphOne "$script:CAGraphBeta/applications?`$filter=appId eq '$($sp.appId)'&`$select=id,appId,displayName" -Quiet).value | Select-Object -First 1 }
    if (-not $app) { return $null }
    return @{ AppObjectId = $app.id; AppId = $sp.appId; SpId = $sp.id }
}

function New-CAAppProxyApp {
    <#
    .SYNOPSIS
        Instantiates the on-prem-app gallery template (creates application + servicePrincipal in one
        call). Reuses an existing app of the same displayName. Returns @{ AppObjectId; AppId; SpId }.
    #>
    param([Parameter(Mandatory)][string]$DisplayName)
    $hit = Get-CAAppProxyApp -DisplayName $DisplayName
    if ($hit) {
        Write-Host "  App '$DisplayName' already exists (appId $($hit.AppId))." -ForegroundColor Green
        return $hit
    }
    $tmpl = '8adf8e6e-67b2-4cf2-a259-e3dc5476c621'   # "on-premises application" App Proxy template
    $body = Invoke-CAGraphStep -Description "Instantiate App Proxy app '$DisplayName'" -Method POST `
        -Uri "$script:CAGraphV1/applicationTemplates/$tmpl/instantiate" `
        -Body @{ displayName = $DisplayName }
    if (-not $body) {
        # dry-run - hand back placeholders so the onPremisesPublishing / connectorGroup / SP steps still preview
        if (Get-CADryRun) { return @{ AppObjectId = '<new-app-object-id>'; AppId = '<new-app-id>'; SpId = '<new-sp-id>' } }
        return $null
    }
    Start-Sleep -Seconds 5             # replication settle before the PATCH
    $appId = $body.application.appId
    $spId  = Resolve-CAAppProxySpId -AppId $appId -Fallback $body.servicePrincipal.id
    return @{ AppObjectId = $body.application.id; AppId = $appId; SpId = $spId }
}

function Set-CAAppProxyPublishing {
    param(
        [Parameter(Mandatory)][string]$AppObjectId,
        [Parameter(Mandatory)]$Body
    )
    $attempt = 0
    while ($true) {
        $attempt++
        try {
            Invoke-CAGraphStep -Description "Set onPremisesPublishing on application $AppObjectId (attempt $attempt)" -Method PATCH `
                -Uri "$script:CAGraphBeta/applications/$AppObjectId" -Body $Body | Out-Null
            return
        } catch {
            if ($attempt -ge 3 -or (Get-CADryRun)) { throw }
            Write-Host "  onPremisesPublishing PATCH failed ($($_.Exception.Message)) - retrying in 5s..." -ForegroundColor DarkYellow
            Start-Sleep -Seconds 5
        }
    }
}

function Set-CAAppProxyAppConnectorGroup {
    param(
        [Parameter(Mandatory)][string]$AppObjectId,
        [Parameter(Mandatory)][string]$GroupId
    )
    Invoke-CAGraphStep -Description "Assign application $AppObjectId to connector group $GroupId" -Method PUT `
        -Uri "$script:CAGraphBeta/applications/$AppObjectId/connectorGroup/`$ref" `
        -Body @{ '@odata.id' = "$script:CAGraphBeta/onPremisesPublishingProfiles/applicationProxy/connectorGroups/$GroupId" } | Out-Null
}

function Resolve-CAAppProxySpId {
    <#
    .SYNOPSIS
        The current servicePrincipal object-id for an appId, polling past the replication window that
        follows applicationTemplates/instantiate (the id it hands back can 404 for a few seconds).
    #>
    param([Parameter(Mandatory)][string]$AppId, [string]$Fallback)
    for ($i = 0; $i -lt 8; $i++) {
        $sp = (Get-CAGraphOne "$script:CAGraphV1/servicePrincipals?`$filter=appId eq '$AppId'&`$select=id" -Quiet).value | Select-Object -First 1
        if ($sp -and $sp.id) { return $sp.id }
        if (Get-CADryRun) { return $Fallback }
        Start-Sleep -Seconds 5
    }
    return $Fallback
}

function Set-CAAppProxyServicePrincipal {
    <#
    .SYNOPSIS
        Anonymous (appRoleAssignmentRequired=false) + HideApp, keeping the App Proxy tag. Re-resolves
        the SP id from -AppId on a 404 (instantiate's id replicates a beat behind the application).
    #>
    param(
        [Parameter(Mandatory)][string]$SpId,
        [string]$AppId
    )
    $id = $SpId
    $attempt = 0
    while ($true) {
        $attempt++
        $cur = Get-CAGraphOne "$script:CAGraphBeta/servicePrincipals/$id?`$select=tags,appRoleAssignmentRequired" -Quiet
        $tags = @('WindowsAzureActiveDirectoryOnPremApp', 'HideApp')
        if ($cur -and $cur.tags) { $tags = @(@($cur.tags) + $tags | Select-Object -Unique) }
        try {
            Invoke-CAGraphStep -Description "Service principal $id : anonymous + hidden" -Method PATCH `
                -Uri "$script:CAGraphBeta/servicePrincipals/$id" `
                -Body @{ appRoleAssignmentRequired = $false; tags = $tags } | Out-Null
            return
        } catch {
            if ($attempt -ge 4 -or (Get-CADryRun) -or -not $AppId -or $_.Exception.Message -notmatch '404|ResourceNotFound') { throw }
            Write-Host "  SP $id not visible yet - re-resolving from appId and retrying..." -ForegroundColor DarkYellow
            Start-Sleep -Seconds 5
            $id = Resolve-CAAppProxySpId -AppId $AppId -Fallback $id
        }
    }
}

function Get-CAAppProxyExternalUrl {
    param([Parameter(Mandatory)][string]$AppObjectId)
    $full = Get-CAGraphOne "$script:CAGraphBeta/applications/$AppObjectId?`$select=id,onPremisesPublishing" -Quiet
    if ($full -and $full.onPremisesPublishing) { return $full.onPremisesPublishing.externalUrl }
    return $null
}

function Publish-CAAppProxyApp {
    <#
    .SYNOPSIS
        Full lifecycle for one app: instantiate/reuse -> onPremisesPublishing -> connector group ->
        SP flags -> read back the real external URL. Returns a result object.
    #>
    param(
        [Parameter(Mandatory)]$AppSpec,
        [Parameter(Mandatory)][string]$GroupId
    )
    $app = New-CAAppProxyApp -DisplayName $AppSpec.DisplayName
    $body = Get-CAAppProxyPublishingBody -InternalUrl $AppSpec.InternalUrl -ExternalUrl $AppSpec.ExternalUrlGuess -BackendCertValidation $AppSpec.BackendCertValidation

    if ($app -and $app.AppObjectId) {
        Set-CAAppProxyPublishing        -AppObjectId $app.AppObjectId -Body $body
        Set-CAAppProxyAppConnectorGroup -AppObjectId $app.AppObjectId -GroupId $GroupId
        try {
            Set-CAAppProxyServicePrincipal -SpId $app.SpId -AppId $app.AppId
        } catch {
            # the app is otherwise fully configured; the anonymous/hidden flags are recoverable by
            # re-running menu 6 (which reuses the app). Don't lose the external-URL write-back over this.
            Write-Host "  WARNING: could not set the SP flags ($($_.Exception.Message)). Re-run menu 6 to finish - the app itself is published." -ForegroundColor Yellow
        }
        $real = Get-CAAppProxyExternalUrl -AppObjectId $app.AppObjectId
    } else {
        # dry-run: nothing was created; report the guess
        $real = $null
    }

    $actual = if ($real) { $real } else { $AppSpec.ExternalUrlGuess }
    [pscustomobject]@{
        Key                  = $AppSpec.Key
        DisplayName          = $AppSpec.DisplayName
        AppId                = if ($app) { $app.AppId } else { $null }
        RequestedExternalUrl = $AppSpec.ExternalUrlGuess
        ActualExternalUrl    = $actual
        ActualHost           = (Get-CAUrlHost $actual)
    }
}
