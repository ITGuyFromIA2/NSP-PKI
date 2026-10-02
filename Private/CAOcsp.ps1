<#
.SYNOPSIS
    CA Manager - Online Responder (OCSP) install + one revocation configuration for the local
    single-tier CA (dashboard menu option 4). Requires Modules\CACore.ps1 (Invoke-CAStep) and, to
    apply, the AD CS Online Responder role binaries + the ADCSDeployment module. Run on the CA box.

.DESCRIPTION
    Get-CAOcspPlan is PURE - it turns the CA identity + CA_TemplateOcspSigning answer into the exact
    HKLM\...\OCSPSvc\Responder\<name> (+ \Provider) registry shape, transcribed from a real client's live
    responder (a captured CA inventory, section C):
    HashAlgorithmId=SHA256, ProviderCLSID={4956d17f-88fd-4198-b287-1e6e65883b19} (MS CRL-based),
    SigningFlags=861, ReminderDuration=90, Provider\RefreshTimeOut=300000. Every constant here is a
    captured fact - a wrong value is a one-line data fix.

    Install-CAOcspRole / New-CAOcspRevocationConfig / Confirm-CAOcspSigningCertificate are the
    engines - every mutation via Invoke-CAStep (dry-run aware). The revocation config is written by
    DIRECT REGISTRY writes (deterministic, previewable, testable, and exactly the reference-client shape);
    New-CAOcspRevocationConfigViaCom is a documented CertAdm.OCSPAdmin fallback, only used when
    New-CAOcspRevocationConfig -UseCom is passed.

    The responder auto-enrolls its short-lived signing cert from NSP-OCSPResponseSigning once OCSPSvc
    restarts (SigningFlags 861 includes AUTOENROLL/AUTODISCOVER; menu 4 already granted the responder
    host / its group Enroll on that template, and menu 15 - the enrollment gate - needs its AutoEnroll
    flipped on too). Confirm-CAOcspSigningCertificate nudges that along and is NON-FATAL if it hasn't
    landed yet.
#>

$script:CAOcspResponderKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\OCSPSvc\Responder'
$script:CAOcspProviderClsid = '{4956d17f-88fd-4198-b287-1e6e65883b19}'   # Microsoft CRL-based revocation provider

# =========================================================================
# PURE
# =========================================================================
function Get-CAOcspPlan {
    <#
    .SYNOPSIS
        PURE. The Online Responder revocation-config plan for the local CA. No I/O.
    .PARAMETER CACommonName   The CA common name ($Status.CACommonName).
    .PARAMETER CAMachineFqdn  The CA/responder box FQDN.
    .PARAMETER CASanitizedName The CA sanitized name (== %3 in the CRL filename).
    .PARAMETER ConfigNC       Configuration naming context, for the LDAP CDP URL; omit -> no ldap entry.
    #>
    param(
        $CAAnswers,
        [Parameter(Mandatory)][string]$CACommonName,
        [Parameter(Mandatory)][string]$CAMachineFqdn,
        [Parameter(Mandatory)][string]$CASanitizedName,
        [string]$ConfigNC,
        [bool]$DeltaCrl = $false,
        [bool]$ResponderColocated = $true,
        [string]$WindowsDir = $env:windir,
        # IIS request-filtering limits for the /ocsp app - base64-encoded OCSP GET tokens can get long
        # enough to exceed IIS's defaults (maxUrl 4096B / maxQueryString 2048B -> HTTP 404.14 / 404.15).
        # Defaults match what's been applied by hand in the field.
        [int]$OcspMaxUrlBytes = 16384,
        [int]$OcspMaxQueryStringBytes = 8192
    )

    # signing template - reuse the menu-4 collision guard (blank / literal 'OCSPResponseSigning' -> NSP-)
    $tmpl = if ($CAAnswers -and $CAAnswers.CA_TemplateOcspSigning) { "$($CAAnswers.CA_TemplateOcspSigning)" } else { '' }
    if ([string]::IsNullOrWhiteSpace($tmpl) -or $tmpl -eq 'OCSPResponseSigning') { $tmpl = 'NSP-OCSPResponseSigning' }
    # SigningCertificateTemplate in the registry is the template's CN (its AD 'name'), NOT the
    # displayName - the responder passes it straight to the auto-enroll API. Menu 4 / New-CAVpnTemplate
    # builds the CN by stripping non-alphanumerics from the display name, and the OCSP MMC wizard
    # writes the same CN form: 'NSP-OCSPResponseSigning' -> 'NSPOCSPResponseSigning'.
    $tmpl = ($tmpl -replace '[^A-Za-z0-9]', '')

    # The CRL-based provider does GETs - it needs real URLs (http:// or ldap://), NOT a bare
    # C:\...\CertEnroll\x.crl filesystem path (which it silently ignores -> no CRL loaded -> the
    # responder can't build a response -> HTTP 500 on /ocsp). Primary is the CA's OWN IIS
    # /CertEnroll/ vdir (menu 6) over http on this box - a real URL, served locally, no internet
    # round-trip. LDAP as backup. The App Proxy URL is added when known (matches a real client's live
    # responder, and covers the case where local IIS isn't up).
    $hostShort = ($CAMachineFqdn -split '\.')[0]
    $baseCrl   = New-Object System.Collections.Generic.List[string]
    # localhost first when the responder is co-located on the CA (our only supported topology - menu 9
    # installs the role on the CA box): same local IIS /CertEnroll/ vdir as the FQDN entry but with no
    # DNS lookup, no host-header/binding dependency, no name-mismatch risk. The FQDN / LDAP / App Proxy
    # entries stay as ordered fallbacks. A split/dedicated responder box has no /CertEnroll vdir, so
    # this is gated on -ResponderColocated.
    if ($ResponderColocated) { $baseCrl.Add("http://localhost/CertEnroll/$CASanitizedName.crl") }
    $baseCrl.Add("http://$CAMachineFqdn/CertEnroll/$CASanitizedName.crl")
    if (-not [string]::IsNullOrWhiteSpace($ConfigNC)) {
        # ${ConfigNC} braces required - PS7 eats "$ConfigNC?certificateRevocationList..." as a
        # null-conditional member chain otherwise.
        $baseCrl.Add("ldap:///CN=$CASanitizedName,CN=$hostShort,CN=CDP,CN=Public Key Services,CN=Services,${ConfigNC}?certificateRevocationList?base?objectClass=cRLDistributionPoint")
    }
    $appProxyCrl = if ($CAAnswers -and "$($CAAnswers.CA_AppProxyCrlFqdn)" -match '\.') { "$($CAAnswers.CA_AppProxyCrlFqdn)".Trim() } else { $null }
    if ($appProxyCrl) { $baseCrl.Add("http://$appProxyCrl/CertEnroll/$CASanitizedName.crl") }

    $deltaCrlUrls = @()
    if ($DeltaCrl) {
        $deltaCrlUrls = New-Object System.Collections.Generic.List[string]
        if ($ResponderColocated) { $deltaCrlUrls.Add("http://localhost/CertEnroll/$CASanitizedName+.crl") }
        $deltaCrlUrls.Add("http://$CAMachineFqdn/CertEnroll/$CASanitizedName+.crl")
        if ($appProxyCrl) { $deltaCrlUrls.Add("http://$appProxyCrl/CertEnroll/$CASanitizedName+.crl") }
        $deltaCrlUrls = @($deltaCrlUrls)
    }

    $configName = $CACommonName
    $caConfig   = "$CAMachineFqdn\$CACommonName"
    $ck  = "Responder\$configName"
    $pk  = "Responder\$configName\Provider"

    $regValues = @(
        [pscustomobject]@{ KeyPath = $ck; Name = 'CACertificate';              Type = 'Binary';      Value = '<PLACEHOLDER - DER of the CA cert, filled by the engine>' }
        [pscustomobject]@{ KeyPath = $ck; Name = 'CAConfig';                   Type = 'String';      Value = $caConfig }
        [pscustomobject]@{ KeyPath = $ck; Name = 'HashAlgorithmId';            Type = 'String';      Value = 'SHA256' }
        [pscustomobject]@{ KeyPath = $ck; Name = 'ProviderCLSID';              Type = 'String';      Value = $script:CAOcspProviderClsid }
        [pscustomobject]@{ KeyPath = $ck; Name = 'ReminderDuration';           Type = 'DWord';       Value = 90 }
        [pscustomobject]@{ KeyPath = $ck; Name = 'SigningCertificateTemplate'; Type = 'String';      Value = $tmpl }
        [pscustomobject]@{ KeyPath = $ck; Name = 'SigningFlags';               Type = 'DWord';       Value = 861 }
        [pscustomobject]@{ KeyPath = $pk; Name = 'BaseCrlUrls';                Type = 'MultiString'; Value = @($baseCrl) }
        [pscustomobject]@{ KeyPath = $pk; Name = 'DeltaCrlUrls';              Type = 'MultiString'; Value = $deltaCrlUrls }
        [pscustomobject]@{ KeyPath = $pk; Name = 'RefreshTimeOut';            Type = 'DWord';       Value = 300000 }
    )

    [pscustomobject]@{
        ConfigName                 = $configName
        CAConfig                   = $caConfig
        CACommonName               = $CACommonName
        HashAlgorithmId            = 'SHA256'
        ProviderCLSID              = $script:CAOcspProviderClsid
        SigningFlags               = 861
        ReminderDuration           = 90
        RefreshTimeOut             = 300000
        SigningCertificateTemplate = $tmpl
        BaseCrlUrls                = @($baseCrl)
        DeltaCrlUrls               = $deltaCrlUrls
        ResponderFqdn              = $CAMachineFqdn
        ResponderUrl               = "http://$CAMachineFqdn/ocsp"
        LocalVerifyUrl             = 'http://localhost/ocsp'
        RegistryValues             = $regValues
        # Online Responder auditing (ocsp.msc -> server node -> Properties -> Audit tab), stored as a
        # bitmask at the RESPONDER ROOT key (script:CAOcspResponderKey), not per-config:
        #   1 = Start/Stop the Online Responder Service, 2 = Configuration changes,
        #   4 = Requests submitted (per-query - deliberately excluded, floods the log),
        #   8 = Security settings changes. 1+2+8 = 11.
        # The registry bit alone does nothing without the OS-level "Certification Services" audit
        # subcategory also enabled (same requirement as the CA's own CA\AuditFilter).
        AuditFilterValue           = 11
        AuditFilterOsSubcategory   = 'Certification Services'
        OcspMaxUrlBytes            = $OcspMaxUrlBytes
        OcspMaxQueryStringBytes    = $OcspMaxQueryStringBytes
    }
}

# ---------------------------------------------------------------------------
function Show-CAOcspPlan {
    param($Plan)
    Write-Host ""
    Write-Host "  Online Responder role: ensure ADCS-Online-Cert + Install-AdcsOnlineResponder (creates /ocsp, starts OCSPSvc)" -ForegroundColor White
    Write-Host ""
    Write-Host ("  Revocation config: {0}" -f $Plan.ConfigName) -ForegroundColor White
    Write-Host ("    CAConfig                   : {0}" -f $Plan.CAConfig) -ForegroundColor Gray
    Write-Host ("    HashAlgorithmId            : {0}" -f $Plan.HashAlgorithmId) -ForegroundColor Gray
    Write-Host  "    SigningFlags               : 861 (0x35D = SILENT + RESPONDER_ID_KEYHASH + AUTODISCOVER + ALLOW_AUTORENEWAL + FORCE_ISSUER_ISCA + AUTOENROLL + ALLOW_NONCE)" -ForegroundColor Gray
    Write-Host ("    SigningCertificateTemplate : {0}" -f $Plan.SigningCertificateTemplate) -ForegroundColor Gray
    Write-Host ("    ProviderCLSID              : {0}  (Microsoft CRL-based revocation provider)" -f $Plan.ProviderCLSID) -ForegroundColor Gray
    Write-Host  "    ReminderDuration           : 90" -ForegroundColor Gray
    Write-Host ("    RefreshTimeOut             : {0} ms" -f $Plan.RefreshTimeOut) -ForegroundColor Gray
    Write-Host ""
    Write-Host "    CRL sources (Provider\BaseCrlUrls):" -ForegroundColor Gray
    foreach ($u in $Plan.BaseCrlUrls) { Write-Host "      $u" -ForegroundColor DarkGray }
    if ($Plan.DeltaCrlUrls) { foreach ($u in $Plan.DeltaCrlUrls) { Write-Host "      (delta) $u" -ForegroundColor DarkGray } }
    Write-Host ""
    Write-Host ("    Registry: {0} value(s) under {1}\{2}" -f $Plan.RegistryValues.Count, $script:CAOcspResponderKey, $Plan.ConfigName) -ForegroundColor DarkGray
    foreach ($r in $Plan.RegistryValues) {
        $shown = if ($r.Name -eq 'CACertificate') { "<byte[] DER of CN=$($Plan.CACommonName)>" }
                 elseif ($r.Value -is [array]) { '@(' + (($r.Value) -join '; ') + ')' }
                 else { "$($r.Value)" }
        $where = if ($r.KeyPath -match '\\Provider$') { 'Provider\' } else { '' }
        Write-Host ("      [{0,-11}] {1}{2} = {3}" -f $r.Type, $where, $r.Name, $shown) -ForegroundColor DarkGray
    }
    Write-Host ""
    Write-Host ("    The responder auto-enrolls '{0}' as {1}\{2}`$ once OCSPSvc restarts (menu 4 granted" -f `
        $Plan.SigningCertificateTemplate, $env:USERDOMAIN, (($Plan.ResponderFqdn -split '\.')[0])) -ForegroundColor DarkGray
    Write-Host "    that account Enroll; flip AutoEnroll on for it at menu 15, the enrollment gate, if you haven't already)." -ForegroundColor DarkGray
    Write-Host ("    Verify: {0}   (locally: {1})" -f $Plan.ResponderUrl, $Plan.LocalVerifyUrl) -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  Hardening:" -ForegroundColor White
    Write-Host ("    Auditing  : {0}\AuditFilter = {1}  (Start/Stop + Config + Security changes; OS subcategory '{2}')" -f $script:CAOcspResponderKey, $Plan.AuditFilterValue, $Plan.AuditFilterOsSubcategory) -ForegroundColor Gray
    Write-Host ("    IIS /ocsp : maxUrl {0} bytes, maxQueryString {1} bytes  (avoids 404.14/404.15 on long base64 OCSP GET tokens)" -f $Plan.OcspMaxUrlBytes, $Plan.OcspMaxQueryStringBytes) -ForegroundColor Gray
}

# ---------------------------------------------------------------------------
function Get-CAOcspCACertBytes {
    <#
    .SYNOPSIS
        The DER bytes of the CA certificate for CN=<CACommonName> from LocalMachine\CA or \My
        (same selector Get-CAStatus uses), or $null. Fallback: certutil -ca.cert.
    #>
    param([Parameter(Mandatory)][string]$CACommonName)
    try {
        $pat = [regex]::Escape("CN=$CACommonName")
        $c = Get-ChildItem Cert:\LocalMachine\CA, Cert:\LocalMachine\My -ErrorAction SilentlyContinue |
            Where-Object {
                $_.Subject -match $pat -and
                ($_.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.19' } | ForEach-Object { $_.CertificateAuthority }) -contains $true
            } | Sort-Object NotAfter -Descending | Select-Object -First 1
        if ($c) { return [byte[]]$c.RawData }
    } catch { }
    try {
        $tmp = Join-Path $env:TEMP ("_caocsp_{0}.cer" -f ([guid]::NewGuid().ToString('N')))
        & certutil.exe -ca.cert $tmp 2>&1 | Out-Null
        if (Test-Path $tmp) { $b = [System.IO.File]::ReadAllBytes($tmp); Remove-Item $tmp -ErrorAction SilentlyContinue; if ($b.Length) { return [byte[]]$b } }
    } catch { }
    return $null
}

# ---------------------------------------------------------------------------
function Test-CAOcspEndpoint {
    <#
    .SYNOPSIS
        [bool], never throws. Bare mode: a GET to /ocsp answering 200/400/405 == the ISAPI handler
        is alive (404 = app missing, refused = IIS down). -IssuedCertPath mode: certutil -verify
        -urlfetch on a real issued cert.

        Bare mode RETRIES: for ~15s the ISAPI returns HTTP 500 with win32 0x80004005 (E_FAIL) while
        OCSPSvc is mid-reload just after a service bounce / app-pool recycle - that is transient, not
        "dead", so a single probe in that window is misleading.
    #>
    param(
        [string]$Url = 'http://localhost/ocsp',
        [string]$IssuedCertPath,
        [string]$IssuerCertPath,
        [int]$RetrySeconds = 20
    )
    if ($IssuedCertPath) {
        try {
            $cuArgs = @('-verify', '-urlfetch', $IssuedCertPath)
            if ($IssuerCertPath) { $cuArgs += $IssuerCertPath }
            $out = & certutil.exe @cuArgs 2>&1 | Out-String
            return ($LASTEXITCODE -eq 0 -and $out -match '(?i)(Verified "OCSP"|OCSP.*(verified|passed|success)|revocation check passed)')
        } catch { return $false }
    }
    $deadline = (Get-Date).AddSeconds([Math]::Max(0, $RetrySeconds))
    do {
        $alive = $null   # $true = answered, $false = definitively dead (404 / refused), $null = retryable
        try {
            $resp = Invoke-WebRequest -UseBasicParsing -Method GET -Uri $Url -TimeoutSec 10 -ErrorAction Stop
            $alive = ($resp.StatusCode -eq 200)
        } catch [System.Net.WebException] {
            $sc = try { [int]$_.Exception.Response.StatusCode } catch { 0 }
            if     ($sc -eq 200 -or $sc -eq 400 -or $sc -eq 405) { $alive = $true }
            elseif ($sc -eq 404 -or $sc -eq 0)                   { $alive = $false }  # app missing / connection refused
            else                                                 { $alive = $null }   # 500/503/... - transient reload
        } catch { $alive = $null }
        if ($null -ne $alive) { return $alive }
        Start-Sleep -Seconds 3
    } while ((Get-Date) -lt $deadline)
    return $false
}

# ---------------------------------------------------------------------------
function Test-CAOcspWebApp {
    <#
    .SYNOPSIS
        [bool], read-only. Is the Online Responder's /ocsp IIS application present? The role's
        feature (ADCS-Online-Cert) and its service (OCSPSvc) can be up while the /ocsp web app is
        absent - it is created when the responder role is configured, and is lost if IIS is
        (re)installed afterwards. appcmd.exe ships with Web-Server; fall back to an HTTP probe (404 == missing).
    #>
    $appcmd = Join-Path $env:windir 'system32\inetsrv\appcmd.exe'
    if (Test-Path $appcmd) {
        try {
            $out = & $appcmd list app 2>$null | Out-String
            if ($out -match '(?im)"[^"]*/ocsp"') { return $true }
            if ($LASTEXITCODE -eq 0 -and $out)  { return $false }
        } catch { }
    }
    try {
        Invoke-WebRequest -UseBasicParsing -Method GET -Uri 'http://localhost/ocsp' -TimeoutSec 5 -ErrorAction Stop | Out-Null
        return $true
    } catch [System.Net.WebException] {
        $sc = try { [int]$_.Exception.Response.StatusCode } catch { 0 }
        return ($sc -ne 0 -and $sc -ne 404)
    } catch { return $false }
}

# ---------------------------------------------------------------------------
function Get-CAOcspWebAppPath {
    <#
    .SYNOPSIS
        Read-only. Returns the appcmd-style "<site>/ocsp" identifier for the Online Responder's IIS
        application (needed to target it with `appcmd set config`), or $null if appcmd/the app aren't
        found. Site name varies by box (usually "Default Web Site", not guaranteed), so this resolves
        it rather than assuming.
    #>
    $appcmd = Join-Path $env:windir 'system32\inetsrv\appcmd.exe'
    if (-not (Test-Path $appcmd)) { return $null }
    try {
        $out = & $appcmd list app 2>$null | Out-String
        $m = [regex]::Match($out, '(?im)APP\s+"([^"]*/ocsp)"')
        if ($m.Success) { return $m.Groups[1].Value }
    } catch { }
    return $null
}

# ---------------------------------------------------------------------------
function Set-CAOcspWebRequestLimits {
    <#
    .SYNOPSIS
        Raises IIS request-filtering limits (maxUrl / maxQueryString) on the /ocsp application.
        Base64-encoded OCSP GET request tokens can exceed IIS's defaults (maxUrl 4096 bytes,
        maxQueryString 2048 bytes), which IIS answers with HTTP 404.14 / 404.15 rather than passing
        the request to the ISAPI handler at all. Uses appcmd.exe (ships with Web-Server, no
        WebAdministration/PSModulePath dependency) rather than Set-WebConfigurationProperty.
    #>
    param([Parameter(Mandatory)]$Plan)

    $appPath = Get-CAOcspWebAppPath
    if (-not $appPath) {
        Write-Host "  /ocsp IIS application not found - run Install-CAOcspRole first (or apply this by hand once it exists)." -ForegroundColor Yellow
        return
    }
    $appcmd = Join-Path $env:windir 'system32\inetsrv\appcmd.exe'

    Invoke-CAStep -Description "Raise IIS request-filtering limits on '$appPath' (avoids 404.14/404.15 on long base64 OCSP GET tokens)" `
        -Commands @(
            "appcmd.exe set config `"$appPath`" -section:requestFiltering /requestLimits.maxUrl:$($Plan.OcspMaxUrlBytes) /commit:apphost",
            "appcmd.exe set config `"$appPath`" -section:requestFiltering /requestLimits.maxQueryString:$($Plan.OcspMaxQueryStringBytes) /commit:apphost"
        ) `
        -Action {
            & $appcmd set config $appPath -section:requestFiltering "/requestLimits.maxUrl:$($Plan.OcspMaxUrlBytes)" /commit:apphost | Out-Null
            if ($LASTEXITCODE -ne 0) { throw "appcmd set requestLimits.maxUrl failed (exit $LASTEXITCODE)" }
            & $appcmd set config $appPath -section:requestFiltering "/requestLimits.maxQueryString:$($Plan.OcspMaxQueryStringBytes)" /commit:apphost | Out-Null
            if ($LASTEXITCODE -ne 0) { throw "appcmd set requestLimits.maxQueryString failed (exit $LASTEXITCODE)" }
            "ok"
        } -ContinueOnError | Out-Null
}

# ---------------------------------------------------------------------------
function Set-CAOcspAuditing {
    <#
    .SYNOPSIS
        Enables Online Responder auditing for Start/Stop + Configuration changes + Security settings
        changes (registry bits 1+2+8=11) - deliberately NOT bit 4 ("requests submitted"), which logs
        one Security-log event per OCSP query and floods the log. Also enables the OS-level
        "Certification Services" audit subcategory, which the registry bit alone does not substitute
        for (same requirement as the CA's own CA\AuditFilter) - without it, nothing reaches the
        Security log regardless of this setting.
    .NOTES
        AuditFilter lives at the RESPONDER ROOT key (script:CAOcspResponderKey), a sibling of the
        per-CA-config \<name> subkeys, not inside one of them.
    #>
    param([Parameter(Mandatory)]$Plan)

    Invoke-CAStep -Description "Enable Online Responder auditing (Start/Stop + Config + Security changes; excludes per-request)" `
        -Commands @(
            "New-ItemProperty $script:CAOcspResponderKey -Name AuditFilter -PropertyType DWord -Value $($Plan.AuditFilterValue) -Force",
            "auditpol /set /subcategory:`"$($Plan.AuditFilterOsSubcategory)`" /success:enable /failure:enable",
            "Restart-Service OCSPSvc -Force"
        ) `
        -Action {
            New-ItemProperty -Path $script:CAOcspResponderKey -Name 'AuditFilter' -PropertyType DWord -Value $Plan.AuditFilterValue -Force | Out-Null
            $apOut = & auditpol.exe /set /subcategory:"$($Plan.AuditFilterOsSubcategory)" /success:enable /failure:enable 2>&1 | Out-String
            if ($LASTEXITCODE -ne 0) { throw "auditpol failed (exit $LASTEXITCODE): $($apOut.Trim())" }
            Restart-Service -Name OCSPSvc -Force -ErrorAction Stop
            "ok"
        } -ContinueOnError | Out-Null
}

# ---------------------------------------------------------------------------
function Test-CAOcsp {
    <#
    .SYNOPSIS
        Read-only. Returns a [pscustomobject] of bools for the menu-4 preview. Nothing writes.
    #>
    param(
        $Plan,
        [string]$ExpectedConfigName,
        [string]$ExpectedCAConfig
    )
    $r = [ordered]@{
        RoleInstalled             = $null
        ServiceRunning            = $null
        IsapiAppPresent           = $null
        RevocationConfigPresent   = $null
        RevocationConfigForThisCA = $null
        SigningCertAcquired       = $null
        EndpointAnswers           = $null
        AuditFilterValue          = $null
        AuditFilterOk             = $null
        IisMaxUrlBytes            = $null
        IisMaxQueryStringBytes    = $null
        IisLimitsOk               = $null
        Working                   = $false
        Notes                     = @()
    }
    try { if (Get-Command Get-WindowsFeature -ErrorAction SilentlyContinue) { $r.RoleInstalled = [bool](Get-WindowsFeature -Name ADCS-Online-Cert -ErrorAction Stop).Installed } } catch { }
    try { $r.ServiceRunning = ((Get-Service -Name OCSPSvc -ErrorAction Stop).Status -eq 'Running') } catch { $r.ServiceRunning = $false }

    $verifyUrl = if ($Plan -and $Plan.LocalVerifyUrl) { $Plan.LocalVerifyUrl } else { 'http://localhost/ocsp' }
    $r.IsapiAppPresent = Test-CAOcspWebApp
    $r.EndpointAnswers = Test-CAOcspEndpoint -Url $verifyUrl -RetrySeconds 6   # rides out a just-reloaded 500

    # A revocation config is matched by its CAConfig VALUE, not its key name - the OCSP MMC wizard
    # names configs arbitrarily (e.g. a short client nickname, not the CA common name), so a name lookup misses them.
    $wantCaConfig = if ($ExpectedCAConfig) { $ExpectedCAConfig } elseif ($Plan) { $Plan.CAConfig } else { $null }
    $wantName     = if ($ExpectedConfigName) { $ExpectedConfigName } elseif ($Plan) { $Plan.ConfigName } else { $null }
    if (Test-Path $script:CAOcspResponderKey) {
        $cfgs = @(Get-ChildItem -Path $script:CAOcspResponderKey -ErrorAction SilentlyContinue | ForEach-Object {
            $props = try { Get-ItemProperty -Path $_.PSPath -ErrorAction Stop } catch { $null }
            if ($props -and ($props.PSObject.Properties.Name -contains 'CAConfig')) {
                [pscustomobject]@{ Name = $_.PSChildName; CAConfig = "$($props.CAConfig)"; SigningCertificate = $props.SigningCertificate }
            }
        })
        $r.RevocationConfigPresent = ($cfgs.Count -gt 0)
        $match = $cfgs | Where-Object { $wantCaConfig -and $_.CAConfig -ieq $wantCaConfig } | Select-Object -First 1
        if (-not $match -and $wantName) { $match = $cfgs | Where-Object { $_.Name -ieq $wantName } | Select-Object -First 1 }
        if ($match) {
            $r.RevocationConfigForThisCA = if ($wantCaConfig) { $match.CAConfig -ieq $wantCaConfig } else { -not [string]::IsNullOrWhiteSpace($match.CAConfig) }
            $r.SigningCertAcquired = ($match.SigningCertificate -and @($match.SigningCertificate).Count -gt 0)
        }
    }
    if (-not $r.SigningCertAcquired -and $Plan) {
        try {
            $issuerPat = [regex]::Escape("CN=$($Plan.CACommonName)")
            $sc = Get-ChildItem Cert:\LocalMachine\My -ErrorAction SilentlyContinue | Where-Object {
                $_.Issuer -match $issuerPat -and
                ($_.EnhancedKeyUsageList.ObjectId -contains '1.3.6.1.5.5.7.3.9')
            } | Select-Object -First 1
            if ($sc) { $r.SigningCertAcquired = $true }
        } catch { }
    }

    # Hardening (auditing, IIS request limits) - informational only, NOT part of .Working: OCSP
    # answers fine without either, they just mean no audit trail / a 404.14-404.15 risk on long GET URLs.
    try {
        $af = (Get-ItemProperty -Path $script:CAOcspResponderKey -Name 'AuditFilter' -ErrorAction Stop).AuditFilter
        $r.AuditFilterValue = $af
        $want = if ($Plan -and $Plan.AuditFilterValue) { $Plan.AuditFilterValue } else { 11 }
        $r.AuditFilterOk = (([int]$af -band $want) -eq $want)
    } catch { $r.AuditFilterOk = $false }

    $appPath = Get-CAOcspWebAppPath
    if ($appPath) {
        try {
            $appcmd = Join-Path $env:windir 'system32\inetsrv\appcmd.exe'
            $cfgOut = & $appcmd list config $appPath -section:requestFiltering 2>$null | Out-String
            $mUrl = [regex]::Match($cfgOut, 'maxUrl="(\d+)"')
            $mQs  = [regex]::Match($cfgOut, 'maxQueryString="(\d+)"')
            if ($mUrl.Success) { $r.IisMaxUrlBytes = [int]$mUrl.Groups[1].Value }
            if ($mQs.Success)  { $r.IisMaxQueryStringBytes = [int]$mQs.Groups[1].Value }
            $wantUrl = if ($Plan -and $Plan.OcspMaxUrlBytes) { $Plan.OcspMaxUrlBytes } else { 16384 }
            $wantQs  = if ($Plan -and $Plan.OcspMaxQueryStringBytes) { $Plan.OcspMaxQueryStringBytes } else { 8192 }
            $r.IisLimitsOk = ($r.IisMaxUrlBytes -ge $wantUrl -and $r.IisMaxQueryStringBytes -ge $wantQs)
        } catch { $r.IisLimitsOk = $false }
    }

    $r.Working = [bool]($r.ServiceRunning -and $r.RevocationConfigForThisCA -and $r.SigningCertAcquired -and $r.EndpointAnswers)
    return [pscustomobject]$r
}

# =========================================================================
# ENGINES
# =========================================================================
function Install-CAOcspRole {
    <#
    .SYNOPSIS
        Ensures the ADCS-Online-Cert feature + Install-AdcsOnlineResponder + a running OCSPSvc.
        Idempotent. Every mutation via Invoke-CAStep.
    #>
    if (-not (Get-Command Get-WindowsFeature -ErrorAction SilentlyContinue)) {
        Write-Host "  Server-Manager cmdlets missing - run menu 4 on the CA (a Windows Server)." -ForegroundColor Red
        return
    }

    if (-not (Get-WindowsFeature -Name ADCS-Online-Cert -ErrorAction SilentlyContinue).Installed) {
        Invoke-CAStep -Description "Add the Online Responder role feature (ADCS-Online-Cert)" `
            -Commands @('Install-WindowsFeature -Name ADCS-Online-Cert -IncludeManagementTools') `
            -Action {
                $r = Install-WindowsFeature -Name ADCS-Online-Cert -IncludeManagementTools
                if (-not $r.Success) { throw "Install-WindowsFeature ADCS-Online-Cert failed (exit $($r.ExitCode))" }
                $r | Out-String
            } | Out-Null
    } else {
        Write-Host "  ADCS-Online-Cert feature already installed." -ForegroundColor Green
    }

    $svcPresent = [bool](Get-Service -Name OCSPSvc -ErrorAction SilentlyContinue)
    $respKey    = Test-Path $script:CAOcspResponderKey
    $webApp     = Test-CAOcspWebApp
    # "role configured" == the responder was set up at least once. Install-AdcsOnlineResponder REFUSES
    # ("already installed - uninstall first") when it thinks that's the case, so re-running it blindly
    # to repair a missing /ocsp app can hard-fail. OCSPSvc existing is the tell.
    $roleConfigured = $svcPresent -or $respKey

    if ($roleConfigured -and $webApp) {
        Write-Host "  Online Responder already configured (OCSPSvc + /ocsp app present)." -ForegroundColor Green
    } elseif ($roleConfigured -and -not $webApp) {
        Write-Host "  The Online Responder role is configured but its /ocsp IIS app is missing" -ForegroundColor Yellow
        Write-Host "  (IIS was likely (re)installed after the role). Trying to recreate it..." -ForegroundColor Yellow
        $repaired = $false
        Invoke-CAStep -Description "Recreate the /ocsp web app (Install-AdcsOnlineResponder -Force)" `
            -Commands @('Import-Module ADCSDeployment', 'Install-AdcsOnlineResponder -Force') `
            -Action {
                Import-Module ADCSDeployment -ErrorAction Stop
                $r = Install-AdcsOnlineResponder -Force -ErrorAction Stop
                if ($r -and $r.PSObject.Properties['ErrorId'] -and $r.ErrorId -and $r.ErrorId -ne 0) {
                    throw "Install-AdcsOnlineResponder: $($r.ErrorString) (ErrorId $($r.ErrorId))"
                }
                $r | Out-String
            } -ContinueOnError | Out-Null
        if (-not (Get-CADryRun)) { $repaired = Test-CAOcspWebApp }
        if (-not $repaired -and -not (Get-CADryRun)) {
            Write-Host ""
            Write-Host "  Could not recreate /ocsp automatically. Recover manually, then re-run menu 9:" -ForegroundColor Red
            Write-Host "    1. Import-Module ADCSDeployment; Uninstall-AdcsOnlineResponder -Force" -ForegroundColor Gray
            Write-Host "       Install-AdcsOnlineResponder -Force" -ForegroundColor Gray
            Write-Host "    2. if that also fails - feature-level reset:" -ForegroundColor Gray
            Write-Host "       Uninstall-WindowsFeature ADCS-Online-Cert -IncludeManagementTools ; Restart-Computer" -ForegroundColor Gray
            Write-Host "       then Install-WindowsFeature ADCS-Online-Cert -IncludeManagementTools ; Install-AdcsOnlineResponder -Force" -ForegroundColor Gray
            Write-Host "    (revocation configs live in the registry under OCSPSvc\Responder and are re-created by menu 9)" -ForegroundColor Gray
            return
        }
    } else {
        Invoke-CAStep -Description "Configure the Online Responder (creates /ocsp, starts OCSPSvc)" `
            -Commands @('Import-Module ADCSDeployment', 'Install-AdcsOnlineResponder -Force') `
            -Action {
                Import-Module ADCSDeployment -ErrorAction Stop
                $r = Install-AdcsOnlineResponder -Force
                if ($r -and $r.PSObject.Properties['ErrorId'] -and $r.ErrorId -and $r.ErrorId -ne 0) {
                    throw "Install-AdcsOnlineResponder: $($r.ErrorString) (ErrorId $($r.ErrorId))"
                }
                $r | Out-String
            } | Out-Null
    }

    Invoke-CAStep -Description "Start the Online Responder service (OCSPSvc, Automatic)" `
        -Commands @('Set-Service OCSPSvc -StartupType Automatic', 'Start-Service OCSPSvc') `
        -Action {
            Set-Service -Name OCSPSvc -StartupType Automatic -ErrorAction SilentlyContinue
            Start-Service -Name OCSPSvc -ErrorAction SilentlyContinue
            for ($i = 0; $i -lt 10; $i++) { if ((Get-Service OCSPSvc -ErrorAction SilentlyContinue).Status -eq 'Running') { break }; Start-Sleep -Seconds 3 }
            if ((Get-Service OCSPSvc -ErrorAction SilentlyContinue).Status -ne 'Running') { throw "OCSPSvc did not reach Running" }
        } | Out-Null
}

# ---------------------------------------------------------------------------
function New-CAOcspRevocationConfig {
    <#
    .SYNOPSIS
        Creates / updates ONE revocation configuration under HKLM\...\OCSPSvc\Responder\<name> from a
        Get-CAOcspPlan, by direct registry writes, then restarts OCSPSvc. Idempotent. -UseCom routes
        to the CertAdm.OCSPAdmin fallback instead.
    #>
    param(
        [Parameter(Mandatory)]$Plan,
        [switch]$UseCom
    )
    if (-not (Test-Path $script:CAOcspResponderKey)) {
        if (-not (Get-CADryRun)) {
            Write-Host "  ...\OCSPSvc\Responder not present - run the role install (Install-CAOcspRole) first." -ForegroundColor Red
            return
        }
        Write-Host "  (Responder key not present yet - the role install above would create it; previewing the config writes anyway.)" -ForegroundColor DarkGray
    }
    if ($UseCom) { New-CAOcspRevocationConfigViaCom -Plan $Plan; return }

    # 1. CA cert bytes
    $der = Get-CAOcspCACertBytes -CACommonName $Plan.CACommonName
    if (-not $der -and -not (Get-CADryRun)) {
        throw "Could not locate the CA certificate for CN=$($Plan.CACommonName) in LocalMachine\CA or \My."
    }

    # 2. idempotency - is there already a config (this name, or another) serving this CAConfig?
    $targetName = $Plan.ConfigName
    $existing = @()
    if (Test-Path $script:CAOcspResponderKey) {
        $existing = Get-ChildItem -Path $script:CAOcspResponderKey -ErrorAction SilentlyContinue | ForEach-Object {
            $cfg = try { (Get-ItemProperty -Path $_.PSPath -ErrorAction Stop).CAConfig } catch { $null }
            [pscustomobject]@{ Name = $_.PSChildName; CAConfig = $cfg }
        }
    }
    $sameCa = $existing | Where-Object { $_.CAConfig -and ("$($_.CAConfig)" -ieq $Plan.CAConfig) } | Select-Object -First 1
    $sameName = $existing | Where-Object { $_.Name -eq $targetName } | Select-Object -First 1

    if ($sameCa -and $sameCa.Name -ne $targetName) {
        Write-Host "  Existing revocation config '$($sameCa.Name)' already serves $($Plan.CAConfig) - updating it in place." -ForegroundColor Green
        $targetName = $sameCa.Name
    } elseif ($sameName -and $sameName.CAConfig -and "$($sameName.CAConfig)" -ne $Plan.CAConfig) {
        if (-not (Read-CAConfirm -Prompt "  Revocation config '$targetName' currently points at '$($sameName.CAConfig)'. Overwrite for '$($Plan.CAConfig)'?")) { return }
    }

    $ck = Join-Path $script:CAOcspResponderKey $targetName
    $pk = Join-Path $ck 'Provider'
    $configRows = $Plan.RegistryValues | Where-Object { $_.KeyPath -notmatch '\\Provider$' }
    $provRows   = $Plan.RegistryValues | Where-Object { $_.KeyPath -match  '\\Provider$' }

    if (Test-Path $ck) {
        # update-in-place: only the drifted non-CACertificate values
        $cur = try { Get-ItemProperty -Path $ck -ErrorAction Stop } catch { $null }
        $templateDrifted = $false
        foreach ($row in ($configRows | Where-Object { $_.Name -ne 'CACertificate' })) {
            $now = if ($cur) { $cur.$($row.Name) } else { $null }
            if ("$now" -ne "$($row.Value)") {
                if ($row.Name -eq 'SigningCertificateTemplate') { $templateDrifted = $true }
                Invoke-CAStep -Description "Update $($row.Name) on revocation config '$targetName' ($now -> $($row.Value))" `
                    -Commands @("New-ItemProperty -Path '$ck' -Name $($row.Name) -PropertyType $($row.Type) -Value $($row.Value) -Force") `
                    -Action { New-ItemProperty -Path $ck -Name $row.Name -PropertyType $row.Type -Value $row.Value -Force | Out-Null } | Out-Null
            }
        }
        if ($templateDrifted) {
            # The bound signer was enrolled from the OLD template name; leaving SigningCertificate /
            # SigningCertificateHash in place makes OCSPSvc log 0x80070490 "could not locate a signing
            # certificate" on the next load. Clear them so SigningFlags 861 (AUTOENROLL) re-binds.
            Invoke-CAStep -Description "Clear the stale signer binding on '$targetName' (template changed - force re-enroll)" `
                -Commands @("Remove-ItemProperty -Path '$ck' -Name SigningCertificate,SigningCertificateHash -Force") `
                -Action {
                    Remove-ItemProperty -Path $ck -Name 'SigningCertificate'     -Force -ErrorAction SilentlyContinue
                    Remove-ItemProperty -Path $ck -Name 'SigningCertificateHash' -Force -ErrorAction SilentlyContinue
                } | Out-Null
        }
        $curP = try { Get-ItemProperty -Path $pk -ErrorAction Stop } catch { $null }
        foreach ($row in $provRows) {
            $now = if ($curP) { $curP.$($row.Name) } else { $null }
            if (($now -join '|') -ne (@($row.Value) -join '|')) {
                Invoke-CAStep -Description "Update $($row.Name) on '$targetName\Provider'" `
                    -Commands @("New-ItemProperty -Path '$pk' -Name $($row.Name) -PropertyType $($row.Type) -Value <...> -Force") `
                    -Action { if (-not (Test-Path $pk)) { New-Item -Path $pk -Force | Out-Null }; New-ItemProperty -Path $pk -Name $row.Name -PropertyType $row.Type -Value $row.Value -Force | Out-Null } | Out-Null
            }
        }
        Write-Host "  Revocation config '$targetName' reconciled." -ForegroundColor Green
    } else {
        # create from scratch
        Invoke-CAStep -Description "Create OCSP revocation config '$targetName' (base values)" `
            -Commands @(
                "New-Item -Path '$ck' -Force"
                ($configRows | ForEach-Object { "New-ItemProperty -Path '$ck' -Name $($_.Name) -PropertyType $($_.Type) -Value $(if ($_.Name -eq 'CACertificate') { '<DER bytes>' } else { $_.Value }) -Force" })
            ) `
            -Action {
                New-Item -Path $ck -Force | Out-Null
                foreach ($row in $configRows) {
                    $val = if ($row.Name -eq 'CACertificate') { [byte[]]$der } else { $row.Value }
                    New-ItemProperty -Path $ck -Name $row.Name -PropertyType $row.Type -Value $val -Force | Out-Null
                }
            } | Out-Null

        Invoke-CAStep -Description "Create the Provider sub-key + CRL sources" `
            -Commands @(
                "New-Item -Path '$pk' -Force"
                ($provRows | ForEach-Object {
                    $shown = if ($_.Type -eq 'MultiString') { '@(' + ((@($_.Value)) -join '; ') + ')' } else { "$($_.Value)" }
                    "New-ItemProperty -Path '$pk' -Name $($_.Name) -PropertyType $($_.Type) -Value $shown -Force"
                })
            ) `
            -Action {
                New-Item -Path $pk -Force | Out-Null
                foreach ($row in $provRows) { New-ItemProperty -Path $pk -Name $row.Name -PropertyType $row.Type -Value $row.Value -Force | Out-Null }
            } | Out-Null
    }

    Invoke-CAStep -Description "Restart OCSPSvc so it loads the revocation config" `
        -Commands @('Restart-Service OCSPSvc -Force') `
        -Action {
            Restart-Service -Name OCSPSvc -Force
            for ($i = 0; $i -lt 10; $i++) { if ((Get-Service OCSPSvc -ErrorAction SilentlyContinue).Status -eq 'Running') { break }; Start-Sleep -Seconds 3 }
            if ((Get-Service OCSPSvc -ErrorAction SilentlyContinue).Status -ne 'Running') { throw "OCSPSvc did not return to Running after loading the config" }
        } | Out-Null

    # Registry writes + a service restart get OCSPSvc to load the config, but they do NOT signal the
    # responder ARRAY / the /ocsp web proxy to recompile and re-publish it - so the ISAPI can keep
    # serving a stale (or empty) view and answer HTTP 500. GetConfiguration+SetConfiguration through
    # the CertAdm.OCSPAdmin COM object (what ocsp.msc does on every OK) forces that push. NON-FATAL -
    # the config is already on disk; a manual `ocsp.msc` -> the array -> Refresh does the same thing.
    Publish-CAOcspConfig -ResponderFqdn $Plan.ResponderFqdn
}

# ---------------------------------------------------------------------------
function Publish-CAOcspConfig {
    <#
    .SYNOPSIS
        Forces OCSPSvc to recompile + re-publish its revocation configs to the responder array and
        the /ocsp web proxy, via CertAdm.OCSPAdmin GetConfiguration/SetConfiguration. NON-FATAL.
    #>
    param([string]$ResponderFqdn = "$env:COMPUTERNAME.$((Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue).Domain)")

    Invoke-CAStep -Description "Push the revocation config to the responder array + /ocsp proxy (CertAdm.OCSPAdmin SetConfiguration)" `
        -Commands @(
            "`$admin = New-Object -ComObject CertAdm.OCSPAdmin"
            "`$admin.GetConfiguration('$ResponderFqdn', `$true)"
            "`$admin.SetConfiguration('$ResponderFqdn', `$true)"
        ) `
        -Action {
            $admin = New-Object -ComObject 'CertAdm.OCSPAdmin'
            try {
                $admin.GetConfiguration($ResponderFqdn, $true) | Out-Null
                $admin.SetConfiguration($ResponderFqdn, $true)
            } finally {
                [void][System.Runtime.InteropServices.Marshal]::ReleaseComObject($admin)
            }
        } -ContinueOnError | Out-Null
}

# ---------------------------------------------------------------------------
function Confirm-CAOcspSigningCertificate {
    <#
    .SYNOPSIS
        Nudges the responder into acquiring its signing cert from the signing template (poll ->
        certutil -pulse -> restart OCSPSvc -> re-poll). NON-FATAL - prints a remediation block if it
        hasn't landed.
    #>
    param([Parameter(Mandatory)]$Plan)

    $probe = {
        $ck = Join-Path $script:CAOcspResponderKey $Plan.ConfigName
        $viaReg = $false
        try { $p = Get-ItemProperty -Path $ck -ErrorAction Stop; $viaReg = ($p.SigningCertificate -and @($p.SigningCertificate).Count -gt 0) } catch { }
        if ($viaReg) { return $true }
        try {
            $issuerPat = [regex]::Escape("CN=$($Plan.CACommonName)")
            return [bool](Get-ChildItem Cert:\LocalMachine\My -ErrorAction SilentlyContinue | Where-Object {
                $_.Issuer -match $issuerPat -and ($_.EnhancedKeyUsageList.ObjectId -contains '1.3.6.1.5.5.7.3.9')
            } | Select-Object -First 1)
        } catch { return $false }
    }

    if (-not (Get-CADryRun) -and (& $probe)) {
        Write-Host "  OCSP signing certificate already acquired." -ForegroundColor Green
        return
    }

    Invoke-CAStep -Description "Trigger machine certificate auto-enrollment (certutil -pulse)" `
        -Commands @('certutil -pulse') `
        -Action { & certutil.exe -pulse 2>&1 | Out-String; if ($LASTEXITCODE -ne 0) { throw "certutil -pulse failed (exit $LASTEXITCODE)" } } `
        -ContinueOnError | Out-Null

    Invoke-CAStep -Description "Restart OCSPSvc so it binds the freshly enrolled signing certificate" `
        -Commands @('Restart-Service OCSPSvc -Force') `
        -Action { Restart-Service -Name OCSPSvc -Force } -ContinueOnError | Out-Null

    if (Get-CADryRun) { return }
    $ok = $false
    for ($i = 0; $i -lt 12; $i++) { if (& $probe) { $ok = $true; break }; Start-Sleep -Seconds 5 }
    if ($ok) {
        Write-Host "  OCSP signing certificate acquired." -ForegroundColor Green
    } else {
        Write-Host "  Signing certificate not acquired yet. Check:" -ForegroundColor Yellow
        Write-Host "    - certutil -CATemplates  lists '$($Plan.SigningCertificateTemplate)'" -ForegroundColor Yellow
        Write-Host "    - the responder machine account ($env:USERDOMAIN\$(($Plan.ResponderFqdn -split '\.')[0])`$) or its group has Enroll on that template" -ForegroundColor Yellow
        Write-Host "      (re-run menu 4 supplying that principal for the OCSP template ACL; check menu 15 too - Enroll alone isn't enough for AutoEnroll)" -ForegroundColor Yellow
        Write-Host "    - the DC / CA is reachable; ocsp.msc will show 'Bad Signing Certificate' until this resolves" -ForegroundColor Yellow
    }
}

# ---------------------------------------------------------------------------
function New-CAOcspRevocationConfigViaCom {
    <#
    .SYNOPSIS
        DOCUMENTED FALLBACK (only via New-CAOcspRevocationConfig -UseCom). Creates the revocation
        config through the CertAdm.OCSPAdmin COM object (what ocsp.msc uses). Kept for the case where
        a hand-written registry config isn't fully consumed by OCSPSvc on a given build.
    #>
    param([Parameter(Mandatory)]$Plan)
    $der = Get-CAOcspCACertBytes -CACommonName $Plan.CACommonName
    if (-not $der -and -not (Get-CADryRun)) { throw "Could not locate the CA certificate for CN=$($Plan.CACommonName)." }

    Invoke-CAStep -Description "Create OCSP revocation config '$($Plan.ConfigName)' via CertAdm.OCSPAdmin" `
        -Commands @(
            "`$admin = New-Object -ComObject 'CertAdm.OCSPAdmin'"
            "`$admin.GetConfiguration('$($Plan.ResponderFqdn)', `$true)"
            "`$cfg = `$admin.OCSPCAConfigurationCollection.CreateCAConfiguration('$($Plan.ConfigName)', <DER bytes>)"
            "`$cfg.HashAlgorithm='SHA256'; `$cfg.SigningFlags=861; `$cfg.SigningCertificateTemplate='$($Plan.SigningCertificateTemplate)'; `$cfg.CAConfig='$($Plan.CAConfig)'; `$cfg.ProviderCLSID='$($Plan.ProviderCLSID)'"
            "`$props = New-Object -ComObject 'CertAdm.OCSPPropertyCollection'; `$props.CreateProperty('BaseCrlUrls', <string[]>); `$props.CreateProperty('RefreshTimeOut', 300000)"
            "`$cfg.ProviderProperties = `$props.GetAllProperties()"
            "`$admin.SetConfiguration('$($Plan.ResponderFqdn)', `$true)"
        ) `
        -Action {
            $admin = New-Object -ComObject 'CertAdm.OCSPAdmin'
            $admin.GetConfiguration($Plan.ResponderFqdn, $true)
            $cfg = $admin.OCSPCAConfigurationCollection.CreateCAConfiguration($Plan.ConfigName, [byte[]]$der)
            $cfg.HashAlgorithm              = $Plan.HashAlgorithmId
            $cfg.SigningFlags              = [int]$Plan.SigningFlags
            $cfg.SigningCertificateTemplate = $Plan.SigningCertificateTemplate
            $cfg.CAConfig                  = $Plan.CAConfig
            $cfg.ProviderCLSID            = $Plan.ProviderCLSID
            $props = New-Object -ComObject 'CertAdm.OCSPPropertyCollection'
            $props.CreateProperty('BaseCrlUrls', [string[]]$Plan.BaseCrlUrls)
            if ($Plan.DeltaCrlUrls) { $props.CreateProperty('DeltaCrlUrls', [string[]]$Plan.DeltaCrlUrls) }
            $props.CreateProperty('RefreshTimeOut', [int]$Plan.RefreshTimeOut)
            $cfg.ProviderProperties = $props.GetAllProperties()
            $admin.SetConfiguration($Plan.ResponderFqdn, $true)
        } | Out-Null
}
