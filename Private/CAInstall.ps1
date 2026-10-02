<#
.SYNOPSIS
    CA Manager - install / configure the CA (dashboard menu option 0). Requires Modules\CACore.ps1
    and, to actually install, the AD CS role binaries + the ADCSDeployment module.

.DESCRIPTION
    New-CACapolicyInf is a PURE generator - builds a capolicy.inf from the CA_* answer fields.
    Get-CAInstallPlan returns the Install-AdcsCertificationAuthority parameter set (enterprise root).
    Invoke-CAInstall writes the capolicy.inf, adds the role, and runs the install - through
    Invoke-CAStep, so dry-run just prints everything.

    SCOPE: the enterprise ROOT path is built (that's the fresh-client case - single-tier, shared-CA
    model). The subordinate path (request file -> submit to an online root -> install chain) throws
    a clear "not built yet" until there's a real two-tier client to build it against.
#>

# ---------------------------------------------------------------------------
function New-CACapolicyInf {
    <#
    .SYNOPSIS
        Builds capolicy.inf text from the CA_* answers. Pure - returns the string, writes nothing.
    #>
    param(
        [int]$RenewalKeyLength   = 4096,
        [int]$RenewalValidityYears = 10,
        [int]$CrlPeriodDays      = 7,
        [int]$CrlDeltaPeriodDays = 1,
        [bool]$LoadDefaultTemplates = $false,   # $false for a VPN-purpose CA - only our 4 templates
        [string]$CpsUrl,                        # optional certification-practice-statement URL
        [string]$CpsNotice = "All use of this Certification Authority is restricted to authorized purposes."
    )

    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add('[Version]')
    $lines.Add('Signature="$Windows NT$"')
    $lines.Add('')
    $lines.Add('[Certsrv_Server]')
    $lines.Add("RenewalKeyLength=$RenewalKeyLength")
    $lines.Add('RenewalValidityPeriod=Years')
    $lines.Add("RenewalValidityPeriodUnits=$RenewalValidityYears")
    $lines.Add('CRLPeriod=Days')
    $lines.Add("CRLPeriodUnits=$CrlPeriodDays")
    $lines.Add('CRLDeltaPeriod=Days')
    $lines.Add("CRLDeltaPeriodUnits=$CrlDeltaPeriodDays")
    $lines.Add("LoadDefaultTemplates=$([int][bool]$LoadDefaultTemplates)")
    $lines.Add('AlternateSignatureAlgorithm=0')
    if ($CpsUrl) {
        $lines.Add('')
        $lines.Add('[PolicyStatementExtension]')
        $lines.Add('Policies=InternalPolicy')
        $lines.Add('[InternalPolicy]')
        $lines.Add('OID=2.5.29.32.0')
        $lines.Add("Notice=`"$CpsNotice`"")
        $lines.Add("URL=$CpsUrl")
    }
    return ($lines -join "`r`n")
}

# ---------------------------------------------------------------------------
function Get-CAInstallPlan {
    <#
    .SYNOPSIS
        The Install-AdcsCertificationAuthority parameter set for an enterprise ROOT CA. Pure -
        returns a hashtable. Throws for anything but the enterprise-root case (see SCOPE above).
    #>
    param(
        [Parameter(Mandatory)][string]$CACommonName,
        [ValidateSet('EnterpriseRootCA', 'EnterpriseSubordinateCA')][string]$CAType = 'EnterpriseRootCA',
        [int]$KeyLength = 4096,
        [string]$HashAlgorithm = 'SHA256',
        [int]$ValidityYears = 10,
        [string]$CryptoProvider = 'RSA#Microsoft Software Key Storage Provider'
    )
    if ($CAType -ne 'EnterpriseRootCA') {
        throw "Get-CAInstallPlan: only EnterpriseRootCA is built (Phase 4). The subordinate path (CSR -> parent -> install chain) is pending a real two-tier client."
    }
    return @{
        CAType                    = 'EnterpriseRootCA'
        CACommonName              = $CACommonName
        KeyLength                 = $KeyLength
        HashAlgorithmName         = $HashAlgorithm
        CryptoProviderName        = $CryptoProvider
        ValidityPeriod            = 'Years'
        ValidityPeriodUnits       = $ValidityYears
        Force                     = $true
    }
}

# ---------------------------------------------------------------------------
function Show-CAInstallPlan {
    param($CAAnswers)
    $cn = if ($CAAnswers.CA_CommonName) { $CAAnswers.CA_CommonName } else { '<CA_CommonName - not set>' }
    $yrs = if ($CAAnswers.CA_ValidityYears -as [int]) { [int]$CAAnswers.CA_ValidityYears } else { 10 }
    $sub = ($CAAnswers.CA_IsSubordinate -match '^(?i)y')
    Write-Host ""
    if ($sub) {
        Write-Host "  CA_IsSubordinate = Yes - the subordinate install path is not built yet." -ForegroundColor Yellow
        Write-Host "  (Fresh single-tier clients use the enterprise-root path below.)" -ForegroundColor Yellow
        return
    }
    Write-Host "  Would install: Enterprise Root CA  '$cn'" -ForegroundColor White
    Write-Host ("    key {0}-bit RSA, SHA256, valid {1} years" -f 4096, $yrs) -ForegroundColor Gray
    Write-Host "    capolicy.inf ->" -ForegroundColor Gray
    $inf = New-CACapolicyInf -RenewalValidityYears $yrs `
        -CrlPeriodDays $(if ($CAAnswers.CA_CrlPeriodDays -as [int]) { [int]$CAAnswers.CA_CrlPeriodDays } else { 7 })
    foreach ($l in ($inf -split "`r?`n")) { Write-Host "      $l" -ForegroundColor DarkGray }
}

# ---------------------------------------------------------------------------
function Invoke-CAInstall {
    <#
    .SYNOPSIS
        Writes %windir%\capolicy.inf, adds the AD CS role, and installs an enterprise root CA. Every
        mutating step is an Invoke-CAStep (dry-run aware). Enterprise-root only.
    #>
    param(
        [Parameter(Mandatory)][string]$CACommonName,
        [int]$ValidityYears = 10,
        [int]$KeyLength = 4096,
        [int]$CrlPeriodDays = 7,
        [int]$CrlDeltaPeriodDays = 1,
        [string]$CpsUrl
    )

    # Stale AD objects from a decommissioned / snapshot-reverted CA of the same name block
    # Install-AdcsCertificationAuthority ("A certification authority with the same name was found in
    # the Active Directory."). Surface it up front with the fix rather than crashing mid-install.
    if (-not (Get-CADryRun) -and (Get-Command Get-ADObject -ErrorAction SilentlyContinue)) {
        try {
            $cnc = (Get-ADRootDSE -ErrorAction Stop).configurationNamingContext
            $es  = Get-ADObject -SearchBase "CN=Enrollment Services,CN=Public Key Services,CN=Services,$cnc" `
                     -Filter "Name -eq '$CACommonName'" -ErrorAction SilentlyContinue
            if ($es) {
                Write-Host ""
                Write-Host "  AD already has a CA registered as '$CACommonName' (CN=Enrollment Services)." -ForegroundColor Yellow
                Write-Host "  If that's a leftover from a decommissioned / reverted CA, clear it first:" -ForegroundColor Yellow
                Write-Host "    certutil -f -dsdel `"$CACommonName`"" -ForegroundColor Gray
                Write-Host "    Get-ADObject -SearchBase `"CN=Public Key Services,CN=Services,`$((Get-ADRootDSE).configurationNamingContext)`" ``" -ForegroundColor Gray
                Write-Host "      -Filter `"Name -eq '$CACommonName'`" -SearchScope Subtree | Remove-ADObject -Recursive -Confirm:`$false" -ForegroundColor Gray
                if ((Read-Host "  Type CONTINUE to run the install anyway (it will likely fail), anything else to stop") -cne 'CONTINUE') {
                    return
                }
            }
        } catch { }
    }

    $infText = New-CACapolicyInf -RenewalValidityYears $ValidityYears -CrlPeriodDays $CrlPeriodDays -CrlDeltaPeriodDays $CrlDeltaPeriodDays -CpsUrl $CpsUrl
    $infPath = Join-Path $env:windir 'capolicy.inf'

    Invoke-CAStep -Description "Write $infPath" `
        -Commands @("Set-Content -Path '$infPath' (capolicy.inf, $(($infText -split "`r?`n").Count) lines)") `
        -Action { Set-Content -Path $infPath -Value $infText -Encoding ASCII -Force } | Out-Null

    Invoke-CAStep -Description "Add the AD CS Certification Authority role feature (+ RSAT-ADCS-Mgmt)" `
        -Commands @("Install-WindowsFeature ADCS-Cert-Authority, RSAT-ADCS-Mgmt -IncludeManagementTools") `
        -Action {
            $r = Install-WindowsFeature -Name ADCS-Cert-Authority, RSAT-ADCS-Mgmt -IncludeManagementTools
            if ($r.RestartNeeded -and "$($r.RestartNeeded)" -ne 'No') {
                Write-Host "  NOTE: the feature install reports a RESTART is needed." -ForegroundColor Yellow
            }
            $r | Out-String
        } | Out-Null

    # Install-AdcsCertificationAuthority is in the ADCSDeployment module the feature above lays down.
    # A fresh Server usually needs a REBOOT before that module registers; and even after, PowerShell
    # won't see it mid-session if its dir wasn't on PSModulePath at launch. Try to load it (by name,
    # then by literal path); if neither works, bail with a clear next-step note instead of crashing.
    if (-not (Get-CADryRun)) {
        $adcsLoaded = $false
        foreach ($m in @('ADCSDeployment', (Join-Path $env:windir 'System32\WindowsPowerShell\v1.0\Modules\ADCSDeployment'))) {
            try { Import-Module $m -ErrorAction Stop; $adcsLoaded = $true; break } catch { }
        }
        if (-not $adcsLoaded) {
            Write-Host ""
            Write-Host "  The AD CS role feature is installed, but its ADCSDeployment PowerShell module" -ForegroundColor Yellow
            Write-Host "  can't be loaded yet. On a fresh server this needs a REBOOT. After rebooting:" -ForegroundColor Yellow
            Write-Host "    - relaunch CA-Manager and run menu 2 again (capolicy.inf + the feature are" -ForegroundColor Yellow
            Write-Host "      already in place, so it goes straight to Install-AdcsCertificationAuthority)." -ForegroundColor Yellow
            Write-Host "  If it still won't load after a reboot:  Install-WindowsFeature RSAT-ADCS-Mgmt" -ForegroundColor Gray
            return
        }
    }

    $plan = Get-CAInstallPlan -CACommonName $CACommonName -CAType EnterpriseRootCA -KeyLength $KeyLength -ValidityYears $ValidityYears
    # Preview string: render switch/bool params bare (-Force, not -Force 'True'); stable, readable order.
    $order = @('CAType', 'CACommonName', 'KeyLength', 'HashAlgorithmName', 'CryptoProviderName', 'ValidityPeriod', 'ValidityPeriodUnits', 'Force')
    $planStr = (@($order | Where-Object { $plan.ContainsKey($_) } | ForEach-Object {
        $v = $plan[$_]
        if ($v -is [bool]) { if ($v) { "-$_" } } else { "-$_ '$v'" }
    }) -join ' ')
    Invoke-CAStep -Description "Install enterprise root CA '$CACommonName'" `
        -Commands @("Import-Module ADCSDeployment", "Install-AdcsCertificationAuthority $planStr") `
        -Action {
            $litPath = Join-Path $env:windir 'System32\WindowsPowerShell\v1.0\Modules\ADCSDeployment'
            try { Import-Module ADCSDeployment -ErrorAction Stop }
            catch { Import-Module $litPath -ErrorAction Stop }   # broken PSModulePath fallback
            Install-AdcsCertificationAuthority @plan
        } | Out-Null
}
