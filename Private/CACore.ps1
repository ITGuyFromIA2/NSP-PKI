<#
.SYNOPSIS
    Shared engine for CA Manager - read-only status probes of a live AD CS deployment, console
    helpers, and (in later phases) the CA/OCSP/GPO/App-Proxy mutation functions.

.DESCRIPTION
    Phase 1 content only: Set-ConsoleFullScreen, Write-CAHeader, Get-CAStatus / Show-CAStatus, and
    the Invoke-CANotYetImplemented stub. Every probe in Get-CAStatus is individually wrapped and
    returns $null on any failure - $null means "couldn't determine", distinct from $false.

    The full one-shot inventory lives in the sibling Get-CAManagerInventory.ps1 (and the Entra side
    in Get-CAManagerEntraProxyInventory.ps1); Get-CAStatus is the lean always-on subset the
    dashboard header renders on every redraw.
#>

# ---------------------------------------------------------------------------
function Set-ConsoleFullScreen {
    <#
    .SYNOPSIS
        Best-effort maximizes THIS console window. Verbatim copy of NPSManager\Modules\NPSCore.ps1's
        own Set-ConsoleFullScreen (kept in both trees since neither dot-sources the other).

    .DESCRIPTION
        UI Automation's WindowPattern.SetWindowVisualState(Maximized) - deliberately NOT a
        P/Invoke / Add-Type DllImport block (that pattern was the confirmed sole cause of 2 of 7
        ATT&CK capabilities a real Microsoft Defender for Endpoint alert flagged against
        IPSec-MasterOrchestrator.ps1 - "Native API"/T1106, "Dynamic API Resolution"/T1027.007).
        UIAutomationClient/UIAutomationTypes are standard signed .NET Framework assemblies.

        FocusedElement resolves to a CHILD control inside the console that doesn't support
        WindowPattern, so this walks UP the automation tree until a Window-type ancestor is found,
        then calls WindowPattern on THAT. Wrapped so it can't throw or block - a host with no real
        console, no UI Automation, or pwsh/.NET just stays whatever size it already was.
    #>
    try {
        Add-Type -AssemblyName UIAutomationClient -ErrorAction Stop
        Add-Type -AssemblyName UIAutomationTypes -ErrorAction Stop

        $focused = [System.Windows.Automation.AutomationElement]::FocusedElement
        if ($focused) {
            $walker = [System.Windows.Automation.TreeWalker]::ControlViewWalker
            $current = $focused
            $windowElement = $null
            $hops = 0
            while ($current -and $hops -lt 15) {
                if ($current.Current.ControlType -eq [System.Windows.Automation.ControlType]::Window) {
                    $windowElement = $current
                    break
                }
                $current = $walker.GetParent($current)
                $hops++
            }
            if ($windowElement) {
                $patternObj = $null
                if ($windowElement.TryGetCurrentPattern([System.Windows.Automation.WindowPattern]::Pattern, [ref]$patternObj)) {
                    ([System.Windows.Automation.WindowPattern]$patternObj).SetWindowVisualState([System.Windows.Automation.WindowVisualState]::Maximized)
                }
            }
        }
    } catch {
        # Best-effort only.
    }
}

# ---------------------------------------------------------------------------
function Write-CAHeader {
    <#
    .SYNOPSIS
        Draws the "====" banner at the top of every screen and clears the screen first so scrollback
        from the previous screen doesn't pile up between transitions. Same shape as NPS Manager's
        Write-NPSHeader.
    #>
    param([string]$Title)
    try { Clear-Host } catch {}
    Write-Host ""
    Write-Host "======================================================" -ForegroundColor Cyan
    Write-Host "  $Title" -ForegroundColor Cyan
    Write-Host "======================================================" -ForegroundColor Cyan
    Write-Host ""
}

# ---------------------------------------------------------------------------
function Get-CAIEEnhancedSecurity {
    <#
    .SYNOPSIS
        Returns @{ Admin; User } - $true when IE Enhanced Security Configuration is ON for that
        class, $null if the key can't be read (not a Server SKU / not present).
    #>
    $keys = @{
        Admin = 'HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}'
        User  = 'HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}'
    }
    $out = @{}
    foreach ($k in $keys.Keys) {
        try { $out[$k] = ((Get-ItemProperty $keys[$k] -Name IsInstalled -ErrorAction Stop).IsInstalled -eq 1) }
        catch { $out[$k] = $null }
    }
    $out
}

function Set-CAIEEnhancedSecurity {
    <#
    .SYNOPSIS
        Turns IE Enhanced Security Configuration off (default) or on, for Admins and Users - the same
        two Active Setup IsInstalled flags Server Manager's toggle flips. MSAL's embedded browser
        (Connect-MgGraph, the connector installer's sign-in) goes blank on a server while ESC is on.
        Routes through Invoke-CAStep. Restarts explorer so it takes effect this session unless
        -NoExplorerRestart.
    #>
    param(
        [bool]$Enabled = $false,
        [switch]$NoExplorerRestart
    )
    $val   = if ($Enabled) { 1 } else { 0 }
    $state = if ($Enabled) { 'ON' } else { 'OFF' }
    $keys  = @(
        'HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}'  # Administrators
        'HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}'  # Users
    )
    Invoke-CAStep -Description "Turn IE Enhanced Security Configuration $state (Admins + Users)" `
        -Commands @($keys | ForEach-Object { "Set-ItemProperty '$_' -Name IsInstalled -Value $val" }) `
        -Action {
            foreach ($k in $keys) {
                if (Test-Path $k) { Set-ItemProperty -Path $k -Name IsInstalled -Value $val -Type DWord -Force }
            }
        } -ContinueOnError | Out-Null

    if (-not $NoExplorerRestart -and -not (Get-CADryRun)) {
        Invoke-CAStep -Description "Restart explorer so the ESC change applies to this session" `
            -Commands @('Stop-Process -Name explorer -Force  (auto-restarts)') `
            -Action {
                Get-Process -Name explorer -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
                Start-Sleep -Seconds 2
                if (-not (Get-Process -Name explorer -ErrorAction SilentlyContinue)) { Start-Process explorer.exe }
            } -ContinueOnError | Out-Null
    }
}

# ---------------------------------------------------------------------------
function Invoke-CANotYetImplemented {
    <#
    .SYNOPSIS
        Phase-1 placeholder for a dashboard action whose engine lands in a later phase. Mirrors NPS
        Manager's own Invoke-NotYetBuilt.
    #>
    param(
        [Parameter(Mandatory)][string]$Feature,
        [int]$Phase
    )
    Write-CAHeader $Feature
    $when = if ($Phase) { "planned for Phase $Phase" } else { "planned for a later build" }
    Write-Host "Not built yet - $when of the CA Manager build plan." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "For now, use Get-CAManagerInventory.ps1 (menu option R) for a full read-only" -ForegroundColor Gray
    Write-Host "picture of this deployment, and follow the by-hand runbook." -ForegroundColor Gray
    Read-Host "Press Enter to return to the menu" | Out-Null
}

# ---------------------------------------------------------------------------
# DRY RUN engine - extracted 2026-09-10 (Part A item 9) into a shared, tool-agnostic file so it's
# reusable outside CA-Manager, not just here. Invoke-CAStep/Get-CADryRun/Set-CADryRun (still under
# their existing CA-prefixed names - see the shared file's own header for why) come from there now;
# same "zip layout, then repo layout" candidate lookup already proven by Modules\CATestSuite.ps1's
# own Request-VPNCertCore.ps1 dot-source. Every mutating engine below (CAInstall / CATemplates /
# CAAutoEnrollGPO / CAUrls / ...) still just calls Invoke-CAStep exactly as before - only WHERE it's
# defined moved, not its name or behavior, so no other file in this tool needed to change at all.
# ---------------------------------------------------------------------------
$script:__caDryRunEngineLoaded = $false
# NSP.PKI: the module ships it as (only) Private\Engine\DryRunEngine.ps1.
foreach ($candidate in @(
    (Join-Path $PSScriptRoot "Engine\DryRunEngine.ps1")
)) {
    if (Test-Path $candidate) { . $candidate; $script:__caDryRunEngineLoaded = $true; break }
}
if (-not $script:__caDryRunEngineLoaded) {
    throw "DryRunEngine.ps1 was not found (expected next to CA-Manager.ps1 in a built CAManager.zip, or under IPSEC AIO\MiscTools\Shared\ when running from the repo) - CA-Manager cannot run without it."
}

# ---------------------------------------------------------------------------
function Invoke-CertUtilText {
    <#
    .SYNOPSIS
        Runs certutil with the given args and returns combined stdout/stderr as one string, or $null
        if certutil isn't present / the call blew up. Never throws.
    #>
    param([Parameter(Mandatory)][string[]]$Arguments)
    try {
        if (-not (Get-Command certutil.exe -ErrorAction SilentlyContinue)) { return $null }
        $out = & certutil.exe @Arguments 2>&1 | Out-String
        return $out
    } catch { return $null }
}

# ---------------------------------------------------------------------------
function ConvertFrom-CAPublicationUrls {
    <#
    .SYNOPSIS
        Parses a `certutil -getreg CA\CRLPublicationURLs` / `...\CACertPublicationURLs` dump into an
        array of [pscustomobject]@{ Flags; Url; RoutesExternally }. RoutesExternally is a heuristic:
        an http(s):// URL whose host is neither a %1-style placeholder nor localhost - i.e. one that
        actually leaves the box (the App Proxy / external CDP/AIA/OCSP hostnames).
    #>
    param([string]$DumpText)
    if ([string]::IsNullOrWhiteSpace($DumpText)) { return @() }
    $results = @()
    foreach ($line in ($DumpText -split "`r?`n")) {
        # e.g.  "    5: 6:http://CRL-contoso.msappproxy.net/CertEnroll/%3%8%9.crl"
        if ($line -match '^\s*\d+:\s*(\d+):(\S.*)$') {
            $flags = [int]$Matches[1]
            $url   = $Matches[2].Trim()
            $ext = $false
            if ($url -match '^(?i)https?://([^/]+)') {
                $urlHost = $Matches[1]
                if ($urlHost -notmatch '%\d' -and $urlHost -notmatch '^(?i)(localhost|127\.0\.0\.1)') { $ext = $true }
            }
            $results += [pscustomobject]@{ Flags = $flags; Url = $url; RoutesExternally = $ext }
        }
    }
    return $results
}

# ---------------------------------------------------------------------------
function Get-CAStatus {
    <#
    .SYNOPSIS
        Read-only snapshot of the local AD CS deployment for the dashboard header. Every field is
        $null-tolerant. Nothing here writes, publishes, or revokes anything.
    #>
    param(
        [string]$CAConfigName,
        # Template display names this deployment is expected to carry (from CAAnswers.json when
        # available). Defaults to the standard IKEv2-VPN set (2026-09-15: "InternalUsers", not an
        # earlier client-specific "CorpLAN"); some clients also add their own OCSP response-signing template.
        [string[]]$ExpectedTemplates = @('IKEv2VPN-InternalUsers', 'IKEv2VPN-InternalUsers-MANUAL', 'FortiGate')
    )

    $s = [ordered]@{
        CAConfigName             = $CAConfigName
        ADCSRoleInstalled        = $null
        CACommonName             = $null
        CAType                   = $null
        CAIsSubordinate          = $null
        ParentCAConfig           = $null
        CACertNotAfter           = $null
        CACertDaysLeft           = $null
        OCSPRoleInstalled        = $null
        OCSPServiceRunning       = $null
        OCSPRevocationConfigCount = $null
        PublishedTemplateCount   = $null
        ExpectedTemplateStatus   = @()
        CDPUrls                  = @()
        AIAUrls                  = @()
        HasExternalCDP           = $null
        HasExternalAIAorOCSP     = $null
        AutoEnrollPolicyPresent  = $null
        UmbrellaGroup            = $null
        CRLShareConfigured       = $null
        CRLSharePath             = $null
        CRLShareWriterGroup      = $null
        AppProxyConnectorInstalled = $null
        AppProxyConnectorStatus  = $null
        IISInstalled             = $null
        CertEnrollVDirPresent    = $null
        IssuanceReady            = $false
        Notes                    = @()
    }

    # --- ADCS role ---
    try {
        if (Get-Command Get-WindowsFeature -ErrorAction SilentlyContinue) {
            $f = Get-WindowsFeature -Name ADCS-Cert-Authority -ErrorAction Stop
            $s.ADCSRoleInstalled = [bool]$f.Installed
        }
    } catch { }

    # --- CA identity (certutil -cainfo) ---
    $caInfo = Invoke-CertUtilText -Arguments @('-cainfo')
    if ($caInfo) {
        if ($caInfo -match '(?m)^\s*CA name:\s*(.+?)\s*$')      { $s.CACommonName = $Matches[1] }
        if ($caInfo -match '(?m)^\s*CA type:\s*\d+\s*--\s*(.+?)\s*$') {
            $s.CAType = $Matches[1]
            $s.CAIsSubordinate = ($Matches[1] -match 'Subordinate')
        }
    }
    if (-not $s.CAConfigName) { $s.CAConfigName = $s.CACommonName }

    # --- parent CA (sub-CA only) ---
    $parentMachine = Invoke-CertUtilText -Arguments @('-getreg', 'CA\ParentCAMachine')
    $parentName    = Invoke-CertUtilText -Arguments @('-getreg', 'CA\ParentCAName')
    if ($parentMachine -match '(?m)ParentCAMachine\s+REG_SZ\s*=\s*(.+?)\s*$' -and $parentMachine -notmatch 'EMPTY') {
        $pm = $Matches[1]
        $pn = if ($parentName -match '(?m)ParentCAName\s+REG_SZ\s*=\s*(.+?)\s*$') { $Matches[1] } else { $null }
        $s.ParentCAConfig = if ($pn) { "$pm\$pn" } else { $pm }
    }

    # --- CA cert expiry ---
    try {
        if ($s.CACommonName) {
            $pat = [regex]::Escape("CN=$($s.CACommonName)")
            $caCert = Get-ChildItem Cert:\LocalMachine\CA, Cert:\LocalMachine\My -ErrorAction SilentlyContinue |
                Where-Object {
                    $_.Subject -match $pat -and
                    ($_.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.19' } | ForEach-Object { $_.CertificateAuthority }) -contains $true
                } | Sort-Object NotAfter -Descending | Select-Object -First 1
            if ($caCert) {
                $s.CACertNotAfter = $caCert.NotAfter
                $s.CACertDaysLeft = [int][math]::Round(($caCert.NotAfter - (Get-Date)).TotalDays)
            }
        }
    } catch { }

    # --- OCSP ---
    try {
        if (Get-Command Get-WindowsFeature -ErrorAction SilentlyContinue) {
            $of = Get-WindowsFeature -Name ADCS-Online-Cert -ErrorAction Stop
            $s.OCSPRoleInstalled = [bool]$of.Installed
        }
    } catch { }
    try {
        $svc = Get-Service -Name OCSPSvc -ErrorAction Stop
        $s.OCSPServiceRunning = ($svc.Status -eq 'Running')
    } catch { }
    try {
        $rk = 'HKLM:\SYSTEM\CurrentControlSet\Services\OCSPSvc\Responder'
        if (Test-Path $rk) {
            $s.OCSPRevocationConfigCount = @(Get-ChildItem -Path $rk -ErrorAction SilentlyContinue).Count
        }
    } catch { }

    # --- templates published on this CA ---
    $catmpl = Invoke-CertUtilText -Arguments @('-CATemplates')
    $names = @()
    if ($catmpl) {
        foreach ($line in ($catmpl -split "`r?`n")) {
            # e.g. "IKEv2VPN-CorpLAN: IKEv2 VPN - Corp LAN -- Auto-Enroll: Access is denied."
            # The trailing "Access is denied." is a NORMAL per-template annotation (the running user
            # just can't auto-enroll that one) - it is NOT a command failure.
            if ($line -match '^\s*([A-Za-z0-9][A-Za-z0-9 ._-]*):\s.*--') { $names += $Matches[1].Trim() }
        }
    }
    # certutil quirk: on a CA with ZERO templates published (LoadDefaultTemplates=0), `-CATemplates`
    # returns "command FAILED: 0x80070490 (ERROR_NOT_FOUND) / Element not found" - that is a valid
    # "nothing published" answer, not a read failure. A GENUINE read failure is RPC-unavailable, no
    # CA on the box, or an empty result.
    $catmplNoneYet   = $catmpl -match '(?i)(0x80070490|ERROR_NOT_FOUND|Element not found)'
    $catmplHardFail  = [string]::IsNullOrWhiteSpace($catmpl) -or
                       ($catmpl -match '(?i)(RPC server is unavailable|0x800706ba|cannot find the file specified|0x80070002)')
    $catmplOk = $catmplNoneYet -or (-not $catmplHardFail)
    if ($catmplNoneYet) { $names = @() }
    if ($catmplOk) {
        $s.PublishedTemplateCount = $names.Count
    }
    # `certutil -CATemplates` reports the template CN (first token). Menu 4 builds each CN by
    # stripping non-alphanumerics from the display name (IKEv2VPN-CorpLAN -> IKEv2VPNCorpLAN), so an
    # expected DISPLAY name won't literally equal a reported CN. Match on the stripped form too.
    $normPub = @($names | ForEach-Object { ($_ -replace '[^A-Za-z0-9]', '') })
    $s.ExpectedTemplateStatus = foreach ($t in $ExpectedTemplates) {
        $tn = ($t -replace '[^A-Za-z0-9]', '')
        [pscustomobject]@{ Name = $t; Published = ($catmplOk -and (($names -contains $t) -or ($normPub -contains $tn))) }
    }

    # --- CDP / AIA / OCSP publication URLs ---
    $s.CDPUrls = ConvertFrom-CAPublicationUrls (Invoke-CertUtilText -Arguments @('-getreg', 'CA\CRLPublicationURLs'))
    $s.AIAUrls = ConvertFrom-CAPublicationUrls (Invoke-CertUtilText -Arguments @('-getreg', 'CA\CACertPublicationURLs'))
    if ($s.CDPUrls.Count) { $s.HasExternalCDP = [bool]($s.CDPUrls | Where-Object RoutesExternally) }
    if ($s.AIAUrls.Count) {
        # AIA dump carries both the CA-cert URLs and the OCSP URL (flags 2 vs 32) - either external
        # entry means the external retrieval path exists.
        $s.HasExternalAIAorOCSP = [bool]($s.AIAUrls | Where-Object RoutesExternally)
    }

    # --- auto-enroll policy (cheap live-registry proxy; GPO module may be absent on a member server) ---
    try {
        $aeVal = $null
        foreach ($hive in 'HKCU:', 'HKLM:') {
            $p = "$hive\Software\Policies\Microsoft\Cryptography\AutoEnrollment"
            if (Test-Path $p) {
                $v = (Get-ItemProperty -Path $p -Name AEPolicy -ErrorAction SilentlyContinue).AEPolicy
                if ($null -ne $v) { $aeVal = $v; break }
            }
        }
        if ($null -ne $aeVal) {
            $s.AutoEnrollPolicyPresent = ($aeVal -band 0x1) -eq 0x1
        } elseif (-not (Get-Module -ListAvailable -Name GroupPolicy -ErrorAction SilentlyContinue)) {
            $s.Notes += "Auto-enroll GPO state unknown: GroupPolicy module not present on this box (normal for a member-server CA); no local AEPolicy value applied here either."
        } else {
            $s.AutoEnrollPolicyPresent = $false
        }
    } catch { }

    # --- umbrella group (from the auto template's AutoEnroll ACE) ---
    try {
        $autoTmpl = ($s.ExpectedTemplateStatus | Where-Object { $_.Published -and $_.Name -notmatch 'MANUAL' } | Select-Object -First 1).Name
        if ($autoTmpl -and (Get-Command Get-ADRootDSE -ErrorAction SilentlyContinue)) {
            $configNC = (Get-ADRootDSE -ErrorAction Stop).configurationNamingContext
            $dn = "CN=$autoTmpl,CN=Certificate Templates,CN=Public Key Services,CN=Services,$configNC"
            $autoEnrollGuid = [guid]'a05b8cc2-17bc-4802-a710-e7c15ab866a2'
            $acl = Get-Acl -Path ("AD:\" + $dn) -ErrorAction Stop
            $ace = $acl.Access | Where-Object {
                $_.AccessControlType -eq 'Allow' -and
                $_.ActiveDirectoryRights -match 'ExtendedRight' -and
                $_.ObjectType -eq $autoEnrollGuid -and
                $_.IdentityReference -notmatch '(?i)\\(Domain Admins|Enterprise Admins|Domain Users|Authenticated Users)$'
            } | Select-Object -First 1
            if ($ace) { $s.UmbrellaGroup = "$($ace.IdentityReference)" }
        }
    } catch { }

    # --- CRL distribution share (from an active UNC / file:// publish entry) ---
    try {
        $shareEntry = $s.CDPUrls | Where-Object {
            ($_.Flags -band 0x1) -and ($_.Url -match '^(?i)(file://\\\\|\\\\)' -or $_.Url -match '^(?i)file://[a-z]:/')
        } | Select-Object -First 1
        if ($shareEntry) {
            $s.CRLShareConfigured = $true
            $p = $shareEntry.Url -replace '^(?i)file://', ''
            $p = $p -replace '[\\/][^\\/]*%\d.*$', ''
            $s.CRLSharePath = $p
            if ($p -match '^\\\\' -and (Get-Command Get-Acl -ErrorAction SilentlyContinue)) {
                $acl = Get-Acl -LiteralPath $p -ErrorAction SilentlyContinue
                if ($acl) {
                    $w = $acl.Access | Where-Object {
                        $_.AccessControlType -eq 'Allow' -and $_.FileSystemRights -match 'FullControl' -and
                        $_.IdentityReference -notmatch '(?i)\\(SYSTEM|Administrators|Domain Admins|Enterprise Admins)$' -and
                        $_.IdentityReference -notmatch '(?i)^(CREATOR OWNER|NT AUTHORITY\\SYSTEM|BUILTIN\\Administrators)$'
                    } | Select-Object -First 1
                    if ($w) { $s.CRLShareWriterGroup = "$($w.IdentityReference)" }
                }
            }
        } else {
            $s.CRLShareConfigured = $false
        }
    } catch { }

    # --- App Proxy connector (local view) ---
    try {
        $wapc = Get-Service -Name WAPCSvc -ErrorAction Stop
        $s.AppProxyConnectorInstalled = $true
        $s.AppProxyConnectorStatus = "$($wapc.Status)"
    } catch { $s.AppProxyConnectorInstalled = $false }

    # --- IIS /CertEnroll/ endpoint (the App Proxy CRL app's backend) ---
    try {
        if (Get-Command Get-WindowsFeature -ErrorAction SilentlyContinue) {
            $s.IISInstalled = [bool](Get-WindowsFeature -Name Web-Server -ErrorAction Stop).Installed
        }
    } catch { }
    if ($s.IISInstalled) {
        try {
            Import-Module WebAdministration -ErrorAction Stop
            $s.CertEnrollVDirPresent = [bool](Get-WebVirtualDirectory -Site 'Default Web Site' -Name 'CertEnroll' -ErrorAction SilentlyContinue)
        } catch { }
    } else {
        $s.CertEnrollVDirPresent = $false
    }

    # --- derived readiness gate (menu item 8 checks this) ---
    $s.IssuanceReady = [bool](
        $s.HasExternalCDP -and
        $s.HasExternalAIAorOCSP -and
        $s.AppProxyConnectorInstalled -and
        $s.CertEnrollVDirPresent
    )

    return [pscustomobject]$s
}

# ---------------------------------------------------------------------------
function Show-CAStatus {
    <#
    .SYNOPSIS
        Renders a Get-CAStatus object as the colorized dashboard header.
    #>
    param([Parameter(Mandatory)]$Status)

    $yn  = { param($v) if ($null -eq $v) { 'Unknown' } elseif ($v) { 'Yes' } else { 'No' } }
    $W   = 27                       # label column width
    $L   = { param($t) ("{0,-$W}" -f $t) }
    $pad = ' ' * $W                 # continuation-line indent

    $roleColor = if ($Status.ADCSRoleInstalled) { 'Green' } elseif ($null -eq $Status.ADCSRoleInstalled) { 'Gray' } else { 'Yellow' }
    Write-Host ((& $L "AD CS role installed:") + (& $yn $Status.ADCSRoleInstalled)) -ForegroundColor $roleColor

    if ($Status.CACommonName) {
        Write-Host ((& $L "CA:") + ("{0}   ({1})" -f $Status.CACommonName, $(if ($Status.CAType) { $Status.CAType } else { 'type unknown' })))
        if ($Status.ParentCAConfig) {
            Write-Host ((& $L "  Subordinate to:") + $Status.ParentCAConfig) -ForegroundColor Gray
        }
        if ($Status.CACertNotAfter) {
            $cc = if ($Status.CACertDaysLeft -lt 30) { 'Red' } elseif ($Status.CACertDaysLeft -lt 90) { 'Yellow' } else { 'Green' }
            Write-Host ((& $L "  CA cert expires:") + ("{0:yyyy-MM-dd}  ({1} days left)" -f $Status.CACertNotAfter, $Status.CACertDaysLeft)) -ForegroundColor $cc
        }
    } else {
        Write-Host ((& $L "CA:") + "not detected (no CA on this box, or certutil -cainfo unavailable)") -ForegroundColor Yellow
    }

    $ocspColor = if ($Status.OCSPRoleInstalled -and $Status.OCSPServiceRunning) { 'Green' } elseif ($null -eq $Status.OCSPRoleInstalled) { 'Gray' } else { 'Yellow' }
    Write-Host ((& $L "OCSP responder:") + ("role {0}, service {1}{2}" -f (& $yn $Status.OCSPRoleInstalled), (& $yn $Status.OCSPServiceRunning),
        $(if ($Status.OCSPRevocationConfigCount) { " ($($Status.OCSPRevocationConfigCount) revocation config(s))" } else { '' }))) -ForegroundColor $ocspColor

    if ($null -ne $Status.PublishedTemplateCount) {
        $present = @($Status.ExpectedTemplateStatus | Where-Object Published).Count
        $total   = @($Status.ExpectedTemplateStatus).Count
        $tc = if ($present -eq $total -and $total -gt 0) { 'Green' } else { 'Yellow' }
        Write-Host ((& $L "Custom templates:") + ("{0} of {1} expected published (of {2} total on the CA)" -f $present, $total, $Status.PublishedTemplateCount)) -ForegroundColor $tc
        foreach ($t in $Status.ExpectedTemplateStatus) {
            Write-Host ("    {0} {1}" -f $(if ($t.Published) { '[x]' } else { '[ ]' }), $t.Name) -ForegroundColor $(if ($t.Published) { 'Gray' } else { 'DarkYellow' })
        }
    } else {
        Write-Host ((& $L "Custom templates:") + "could not read (certutil -CATemplates did not report success)") -ForegroundColor Gray
    }

    Write-Host ((& $L "AIA/CDP -> App Proxy:") + ("CDP external {0}, AIA/OCSP external {1}" -f (& $yn $Status.HasExternalCDP), (& $yn $Status.HasExternalAIAorOCSP))) `
        -ForegroundColor $(if ($Status.HasExternalCDP -and $Status.HasExternalAIAorOCSP) { 'Green' } else { 'Yellow' })

    if ($Status.CRLShareConfigured) {
        Write-Host ((& $L "CRL share:") + ("{0}{1}" -f $Status.CRLSharePath,
            $(if ($Status.CRLShareWriterGroup) { "   (writer: $($Status.CRLShareWriterGroup))" } else { '' }))) -ForegroundColor Gray
    } elseif ($false -eq $Status.CRLShareConfigured) {
        Write-Host ((& $L "CRL share:") + "none configured (single-tier CA - only needed for sub-CA / segregated proxy)") -ForegroundColor Gray
    }

    $aeColor = switch ($Status.AutoEnrollPolicyPresent) { $true { 'Green' } $false { 'Yellow' } default { 'Gray' } }
    Write-Host ((& $L "Auto-enroll policy:") + (& $yn $Status.AutoEnrollPolicyPresent)) -ForegroundColor $aeColor

    if ($Status.UmbrellaGroup) {
        Write-Host ((& $L "Auto-enroll umbrella grp:") + $Status.UmbrellaGroup) -ForegroundColor Gray
    }

    $connColor = if ($Status.AppProxyConnectorStatus -eq 'Running') { 'Green' } else { 'Yellow' }
    Write-Host ((& $L "App Proxy connector:") + $(if ($Status.AppProxyConnectorInstalled) { $Status.AppProxyConnectorStatus } else { 'not installed' })) -ForegroundColor $connColor

    if ($null -ne $Status.CertEnrollVDirPresent) {
        $ceColor = if ($Status.CertEnrollVDirPresent) { 'Green' } else { 'Yellow' }
        Write-Host ((& $L "IIS /CertEnroll/ endpoint:") + $(if ($Status.CertEnrollVDirPresent) { 'present' } else { 'not configured' })) -ForegroundColor $ceColor
    }

    Write-Host ""
    if ($Status.IssuanceReady) {
        Write-Host ((& $L "Issuance readiness:") + "READY - external revocation path + connector present") -ForegroundColor Green
    } else {
        Write-Host ((& $L "Issuance readiness:") + "NOT READY - route AIA/CDP/OCSP through the App Proxy and") -ForegroundColor Yellow
        Write-Host ($pad + "install the connector BEFORE issuing any certificates") -ForegroundColor Yellow
        Write-Host ($pad + "(issued certs bake their revocation URLs in permanently).") -ForegroundColor Yellow
    }
    foreach ($n in $Status.Notes) { Write-Host "  note: $n" -ForegroundColor DarkGray }
    Write-Host ""
}

# ---------------------------------------------------------------------------
function Get-CAManagementPrereqStatus {
    <#
    .SYNOPSIS
        Which PowerShell modules CA-Manager's own steps call, and whether they're present:
          ActiveDirectory              -> umbrella-group wizard (menu 5) + AD principal resolution
          GroupPolicy                  -> GPO reporting in the inventory (menu 14) - GPO CREATION
                                          itself moved to the new AD-Manager tool 2026-09-12 (was
                                          this dashboard's own menu 10), this module is still wanted
                                          here for the inventory's own read-only GPO report section
          Microsoft.Graph.Authentication -> App Proxy connector + Entra apps (menu 6)
    #>
    [pscustomobject]@{
        ActiveDirectory = [bool](Get-Module -ListAvailable -Name ActiveDirectory)
        GroupPolicy     = [bool](Get-Module -ListAvailable -Name GroupPolicy)
        GraphAuth       = [bool](Get-Module -ListAvailable -Name Microsoft.Graph.Authentication)
    }
}

# ---------------------------------------------------------------------------
function Save-CAAnswers {
    <#
    .SYNOPSIS
        Persists the in-memory $CAAnswers object back to CAAnswers.json next to the dashboard, so
        values a wizard resolves at run time (menu 6's real App Proxy external hostnames) survive to
        the next session and to menu 8. No-op if $Answers is $null. Routes through Invoke-CAStep.
    #>
    param(
        [Parameter(Mandatory)][string]$Path,
        $Answers
    )
    if ($null -eq $Answers) { return }
    Invoke-CAStep -Description "Save resolved answers to $Path" `
        -Commands @("`$CAAnswers | ConvertTo-Json -Depth 6 | Set-Content '$Path'") `
        -Action {
            $json = $Answers | ConvertTo-Json -Depth 6
            $json = ($json -replace "`r`n", "`n") -replace "`n", "`r`n"
            Set-Content -Path $Path -Value $json -Encoding UTF8
        } -ContinueOnError | Out-Null
}

# ---------------------------------------------------------------------------
function Install-CAGraphModule {
    <#
    .SYNOPSIS
        Installs Microsoft.Graph.Authentication machine-wide (-Scope AllUsers - CA-Manager always
        runs elevated, and the AllUsers module dir survives the PSModulePath rewrite the Entra
        connector installer does; CurrentUser does not). Bootstraps the two things a fresh Windows
        Server is usually missing first: TLS 1.2 for the PowerShell Gallery session and the NuGet
        package provider. Verifies the module is visible afterwards; throws loudly if not.
    .NOTES
        The "is PowerShellGet loadable" probe runs UNCONDITIONALLY, even in DRY RUN - it's a read-only
        Import-Module of an already-on-disk module, not a system mutation. Previously it lived inside
        an Invoke-CAStep -Action block, which SKIPS -Action entirely in dry-run - so the very next
        check (Get-Command Install-Module) always came back empty on a DRY RUN pass regardless of the
        box's actual state, and printed the "PowerShellGet is not present" fallback even when the
        module and PSModulePath were both completely fine (found live 2026-09-10 on a client's CA server - Server
        2022, module present on disk, PSModulePath correct, a real Import-Module succeeded by hand;
        only the DRY RUN pass inside CA-Manager reported it missing). Only the actually-mutating calls
        (Install-PackageProvider / Set-PSRepository / Install-Module) stay behind Invoke-CAStep.
    #>
    if (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication) {
        Write-Host "  Microsoft.Graph.Authentication already installed." -ForegroundColor Green
        return
    }

    # Re-assert PSModulePath right before the probe below, not just once at CA-Manager startup - an
    # installer run earlier in this same session (the Entra connector, TameMyCerts, a .NET runtime
    # install) can leave it malformed, and this rebuilds it from Test-Path-validated directories.
    if (Get-Command Repair-CAModulePath -ErrorAction SilentlyContinue) { Repair-CAModulePath }

    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

    $importErrors = New-Object System.Collections.Generic.List[string]
    foreach ($m in 'PackageManagement', 'PowerShellGet') {
        try { Import-Module $m -ErrorAction Stop }
        catch { $importErrors.Add("$m -> $($_.Exception.Message)") }
    }

    Invoke-CAStep -Description "Bootstrap the NuGet provider + trust the PSGallery repository" `
        -Commands @('Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force',
                    'Set-PSRepository -Name PSGallery -InstallationPolicy Trusted') `
        -Action {
            # PackageManagement may be absent entirely (stripped image); let Install-Module deal with
            # the NuGet provider itself in that case rather than aborting here.
            if (Get-Command Install-PackageProvider -ErrorAction SilentlyContinue) {
                try {
                    if (-not (Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue)) {
                        Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force | Out-Null
                    }
                } catch { Write-Host "  (NuGet provider bootstrap skipped: $($_.Exception.Message))" -ForegroundColor DarkYellow }
            } else {
                Write-Host "  (PackageManagement not available - Install-Module will bootstrap NuGet on its own)" -ForegroundColor DarkYellow
            }
            try { Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction Stop } catch { }
        } -ContinueOnError | Out-Null

    if (-not (Get-Command Install-Module -ErrorAction SilentlyContinue)) {
        Write-Host ""
        Write-Host "  PowerShellGet is not present / not loadable on this box - can't Install-Module anything." -ForegroundColor Yellow
        foreach ($e in $importErrors) { Write-Host "    $e" -ForegroundColor Yellow }
        Write-Host ("    LanguageMode              : {0}" -f $ExecutionContext.SessionState.LanguageMode) -ForegroundColor Gray
        Write-Host ("    PSModuleAutoLoadingPreference : {0}" -f $(if ($null -ne $PSModuleAutoLoadingPreference) { $PSModuleAutoLoadingPreference } else { '(unset - default All)' })) -ForegroundColor Gray
        Write-Host ("    PSModulePath              : {0}" -f $env:PSModulePath) -ForegroundColor Gray
        Write-Host "  Get Microsoft.Graph.Authentication on manually before menu 6:" -ForegroundColor Yellow
        Write-Host "    1. On a box that HAS PowerShellGet:" -ForegroundColor Gray
        Write-Host "         Save-Module Microsoft.Graph.Authentication -Path C:\temp\gmods" -ForegroundColor Gray
        Write-Host "    2. Copy  C:\temp\gmods\Microsoft.Graph.Authentication  to this box's" -ForegroundColor Gray
        Write-Host "         C:\Program Files\WindowsPowerShell\Modules\" -ForegroundColor Gray
        Write-Host "    3. Relaunch CA-Manager. (Menu 6 only.)" -ForegroundColor Gray
        return
    }

    Invoke-CAStep -Description "Install Microsoft.Graph.Authentication (AllUsers)" `
        -Commands @('Install-Module Microsoft.Graph.Authentication -Scope AllUsers -Force -AllowClobber') `
        -Action { Install-Module Microsoft.Graph.Authentication -Scope AllUsers -Force -AllowClobber -ErrorAction Stop | Out-String } | Out-Null

    if (-not (Get-CADryRun) -and -not (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication)) {
        throw "Install-Module reported no error but Microsoft.Graph.Authentication is still not visible. Check internet / proxy, then run 'Install-Module Microsoft.Graph.Authentication -Scope AllUsers -Force -Verbose' by hand."
    }
    Write-Host "  Microsoft.Graph.Authentication installed. Re-run menu 6." -ForegroundColor Green
}

# ---------------------------------------------------------------------------
function Install-CAManagementPrereqs {
    <#
    .SYNOPSIS
        Installs the RSAT tooling CA-Manager needs. On Windows Server -> Install-WindowsFeature
        (RSAT-AD-PowerShell + GPMC, optionally RSAT-ADCS-Mgmt / RSAT-Online-Responder); on a client
        OS -> Add-WindowsCapability -Online. Everything routes through Invoke-CAStep so DRY RUN just
        prints. Re-launch CA-Manager afterwards so the new modules import.
    #>
    param(
        [switch]$IncludeAdcsTools,
        [switch]$IncludeOcspTools
    )

    $isServer = $true
    try { $isServer = ((Get-CimInstance Win32_OperatingSystem -ErrorAction Stop).ProductType -ne 1) } catch { }

    if ($isServer -and (Get-Command Install-WindowsFeature -ErrorAction SilentlyContinue)) {
        $features = [System.Collections.Generic.List[string]]@('RSAT-AD-PowerShell', 'GPMC')
        if ($IncludeAdcsTools) { $features.Add('RSAT-ADCS-Mgmt') }
        if ($IncludeOcspTools) { $features.Add('RSAT-Online-Responder') }
        $need = @($features | Where-Object { -not (Get-WindowsFeature -Name $_ -ErrorAction SilentlyContinue).Installed })
        if (-not $need.Count) {
            Write-Host "  Already installed: $($features -join ', ')" -ForegroundColor Green
            return
        }
        Invoke-CAStep -Description "Install management features: $($need -join ', ')" `
            -Commands @("Install-WindowsFeature $($need -join ',') -IncludeManagementTools") `
            -Action { Install-WindowsFeature -Name $need -IncludeManagementTools | Out-String } | Out-Null
    }
    else {
        $caps = [System.Collections.Generic.List[string]]@(
            'Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0'
            'Rsat.GroupPolicy.Management.Tools~~~~0.0.1.0'
        )
        if ($IncludeAdcsTools -or $IncludeOcspTools) { $caps.Add('Rsat.CertificateServices.Tools~~~~0.0.1.0') }
        $need = @($caps | Where-Object { (Get-WindowsCapability -Online -Name $_ -ErrorAction SilentlyContinue).State -ne 'Installed' })
        if (-not $need.Count) {
            Write-Host "  All RSAT capabilities already installed." -ForegroundColor Green
            return
        }
        foreach ($c in $need) {
            $cap = $c
            Invoke-CAStep -Description "Add RSAT capability $cap" `
                -Commands @("Add-WindowsCapability -Online -Name $cap") `
                -Action { Add-WindowsCapability -Online -Name $cap | Out-String } | Out-Null
        }
    }
    Write-Host "  Re-launch CA-Manager so the new modules load." -ForegroundColor Cyan
}

# ---------------------------------------------------------------------------
function Invoke-CAManagerRelaunch {
    <#
    .SYNOPSIS
        Starts a fresh, elevated CA-Manager.ps1 process (so a just-installed RSAT module / a
        refreshed PSModulePath actually imports) and ends the current session. 2026-09-11: added
        after the maintainer asked for a "relaunch CA-Manager" option instead of having to close the window
        and double-click the script again by hand.

    .DESCRIPTION
        Mirrors CA-Manager.ps1's own top-of-file self-elevate relaunch exactly (same args, same
        Start-Process -Verb RunAs), so a tech gets a normal fresh session, not some other code path.
        Deliberately takes -ScriptPath/-ShimPath/-CAConfigName as EXPLICIT params rather than reading
        $PSCommandPath/$ShimPath itself - this function is dot-sourced into CA-Manager.ps1 from a
        module file, and a function's automatic variables do not reliably reflect the calling
        top-level script's own identity (same reasoning ShimEngine.ps1 documents for its own
        -ShimPath convention). Callers in CA-Manager.ps1 itself have all three directly in scope.
    #>
    param(
        [Parameter(Mandatory)][string]$ScriptPath,
        [string]$ShimPath,
        [string]$CAConfigName
    )
    # NSP.PKI: -ScriptPath is the module manifest - relaunch Start-NSPPkiManager in a new elevated
    # window, then end this dashboard by returning to its caller (Start-NSPPkiManager stops on the
    # NSP.PKI:Relaunched signal) rather than exiting the host, which may be the tech's own console.
    if ($ScriptPath -like '*.psd1') {
        $command = "Import-Module '$($ScriptPath.Replace("'", "''"))'; Start-NSPPkiManager"
        if (-not [string]::IsNullOrWhiteSpace($CAConfigName)) { $command += " -CAConfigName '$($CAConfigName.Replace("'", "''"))'" }
        $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
        Write-Host "  Relaunching PKI Manager..." -ForegroundColor Cyan
        Start-Process powershell.exe -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-NoExit', '-EncodedCommand', $encoded) -Verb RunAs
        throw (New-Object System.OperationCanceledException 'NSP.PKI:Relaunched')
    }
    $relaunchArgs = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$ScriptPath`"")
    if (-not [string]::IsNullOrWhiteSpace($ShimPath))     { $relaunchArgs += @('-ShimPath', "`"$ShimPath`"") }
    if (-not [string]::IsNullOrWhiteSpace($CAConfigName)) { $relaunchArgs += @('-CAConfigName', "`"$CAConfigName`"") }
    Write-Host "  Relaunching CA-Manager..." -ForegroundColor Cyan
    Start-Process powershell.exe -ArgumentList $relaunchArgs -Verb RunAs
    exit 0
}

# ---------------------------------------------------------------------------
function Invoke-CAManagerUpdate {
    <#
    .SYNOPSIS
        Re-runs the STAGED SHIM (not just this dashboard) so a tech gets the latest CAManager.zip
        without leaving the dashboard, manually re-downloading, or hand-copying files themselves.
        2026-09-15, per the maintainer - directly grew out of a same-day live debugging session where he had
        to be told, each time, to go re-copy specific fixed files onto his box by hand.

    .DESCRIPTION
        -Relaunch (menu R / Invoke-CAManagerRelaunch) only re-runs THIS SAME already-extracted
        CA-Manager.ps1 - it fixes a "just installed a module, need a fresh process" problem, but it
        can never pick up a code fix, because it never touches CAManager.zip at all. The shim
        (CA-Manager-Shim.ps1) is the ONLY thing that re-downloads the zip, extracts -Force over the
        current staging folder, reconciles CAAnswers.json, and self-updates its own template - so
        getting a genuine update means re-running THAT, not this dashboard.

        Only meaningful when this session was actually launched via a staged shim - $ShimPath is
        empty for a standalone/dev run (e.g. straight out of the repo), where there's no "latest zip"
        concept to re-fetch at all; the caller must check for that and tell the tech plainly rather
        than silently doing nothing.

        No -Verb RunAs on the relaunch - this process is already elevated, and a child process of an
        elevated process inherits that elevation on Windows (same reasoning CA-Manager-Shim.ps1's own
        STEP 1.5 self-update documents for its own relaunch).
    #>
    param(
        [Parameter(Mandatory)][string]$ShimPath
    )
    if ([string]::IsNullOrWhiteSpace($ShimPath) -or -not (Test-Path $ShimPath)) {
        throw "No staged shim path known for this session (`$ShimPath is blank, or '$ShimPath' no longer exists) - this looks like a standalone/dev run, not one launched via the staged CA-Manager.ps1 shim. Re-run through the shim to get updates."
    }
    Write-Host "  Re-running the shim to fetch the latest CAManager.zip..." -ForegroundColor Cyan
    Start-Process powershell.exe -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$ShimPath`"")
    exit 0
}

# ---------------------------------------------------------------------------
function Resolve-CAADPrincipalInteractive {
    <#
    .SYNOPSIS
        Resolves a typed name/wildcard search term to a real AD group OR computer account, returning
        a "DOMAIN\Name" string ready to feed straight into Grant-CATemplateEnrollment /
        Set-CATemplateAutoEnroll's -PrincipalName (a resolved computer account's Name already carries
        its trailing $, matching what NTAccount(...).Translate(...) expects for a machine principal).
        2026-09-11, per the maintainer: the OCSP-responder-host prompt (menu 4) used to just take whatever was
        typed verbatim, with no way to tell "OCSP-Host" apart from "OCSP-Host01" until the ACL grant
        itself failed later with an opaque "could not resolve to a security identifier" error.

    .DESCRIPTION
        Same 0/1/many-hit search UX already proven twice in this codebase (Invoke-CAMenuUmbrella's
        own inline nested-group picker right here in CATemplates.ps1; Resolve-NPSGroupInteractive in
        NPS-Manager) - exact name first (tried against BOTH Get-ADGroup and Get-ADComputer), falls
        back to a '*term*' wildcard search across both object types, auto-picks on exactly one
        combined hit, offers a numbered pick-list on multiple, and - unlike the NPS/umbrella pickers,
        which can offer to CREATE a missing group - just keeps the typed term as-is, unresolved, on
        zero hits or an explicit skip. An OCSP responder host is virtually always an EXISTING computer
        or group; offering to create one here would be the wrong default action for what this field
        is actually for.

        Tolerant of how the tech actually types it - a leading "DOMAIN\" prefix or a trailing "$" (the
        exact style the prompt's own example shows, e.g. "CONTOSO\CONTOSO-CA$") is stripped before
        searching, since Get-ADComputer's own Name property never carries the trailing $.
    #>
    param([Parameter(Mandatory)][string]$SearchTerm)

    if (-not (Get-Command Get-ADGroup -ErrorAction SilentlyContinue) -or -not (Get-Command Get-ADComputer -ErrorAction SilentlyContinue)) {
        Write-Host "  ActiveDirectory module not available - saving '$SearchTerm' as typed, unresolved. Run menu 1 (RSAT) to search AD next time." -ForegroundColor Yellow
        return $SearchTerm
    }

    $domain = $env:USERDOMAIN
    $term = $SearchTerm.Trim().TrimEnd('$')
    if ($term -match '^[^\\]+\\(.+)$') { $term = $Matches[1] }
    if ([string]::IsNullOrWhiteSpace($term)) { return $SearchTerm }
    $escaped = $term.Replace("'", "''")

    # Exact match first, against BOTH object types - only trusted when just ONE type matches exactly
    # (a same-named group AND computer both existing is rare but real; fall through to the wildcard
    # search + pick-list below rather than silently guessing which one was meant).
    $exactGroup    = @(Get-ADGroup    -Filter "Name -eq '$escaped'" -ErrorAction SilentlyContinue)
    $exactComputer = @(Get-ADComputer -Filter "Name -eq '$escaped'" -ErrorAction SilentlyContinue)
    if ($exactGroup.Count -eq 1 -and $exactComputer.Count -eq 0) {
        Write-Host "  Exact match: group '$($exactGroup[0].Name)'" -ForegroundColor Green
        return "$domain\$($exactGroup[0].Name)"
    }
    if ($exactComputer.Count -eq 1 -and $exactGroup.Count -eq 0) {
        Write-Host "  Exact match: computer '$($exactComputer[0].Name)`$'" -ForegroundColor Green
        return "$domain\$($exactComputer[0].SamAccountName)"
    }

    Write-Host "  Searching AD for groups/computers matching '*$term*'..." -ForegroundColor Cyan
    $groupHits = @(Get-ADGroup -Filter "Name -like '*$escaped*'" -ErrorAction SilentlyContinue | ForEach-Object {
        [pscustomobject]@{ Kind = 'Group'; Display = $_.Name; Value = "$domain\$($_.Name)" }
    })
    $computerHits = @(Get-ADComputer -Filter "Name -like '*$escaped*'" -ErrorAction SilentlyContinue | ForEach-Object {
        [pscustomobject]@{ Kind = 'Computer'; Display = "$($_.Name)`$"; Value = "$domain\$($_.SamAccountName)" }
    })
    $hits = @($groupHits + $computerHits | Sort-Object Kind, Display)

    if ($hits.Count -eq 0) {
        Write-Host "  No AD groups or computers found matching '*$term*' - saving '$SearchTerm' as typed, unresolved." -ForegroundColor Yellow
        return $SearchTerm
    }
    if ($hits.Count -eq 1) {
        Write-Host "  Matched exactly one: [$($hits[0].Kind)] $($hits[0].Display)" -ForegroundColor Green
        return $hits[0].Value
    }

    Write-Host "  '$term' matched $($hits.Count):" -ForegroundColor Cyan
    for ($i = 0; $i -lt $hits.Count; $i++) { Write-Host ("    {0}. [{1}] {2}" -f ($i + 1), $hits[$i].Kind, $hits[$i].Display) }
    $sel = Read-Host "  Select a number (blank to keep '$SearchTerm' as typed, unresolved)"
    $idx = ($sel -as [int]) - 1
    if ($idx -ge 0 -and $idx -lt $hits.Count) {
        Write-Host "  Resolved -> $($hits[$idx].Value)" -ForegroundColor Green
        return $hits[$idx].Value
    }
    Write-Host "  Kept '$SearchTerm' as typed, unresolved." -ForegroundColor Yellow
    return $SearchTerm
}
