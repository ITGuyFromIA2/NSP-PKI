<#
.SYNOPSIS
    CA Manager - AIA / CDP / OCSP publication-URL routing (dashboard menu option 5). Requires
    Modules\CACore.ps1 dot-sourced.

.DESCRIPTION
    Get-CAPublicationUrlPlan is a PURE function - it turns the CA_* answer fields into the exact
    CRLPublicationURLs / CACertPublicationURLs MULTI_SZ entries certutil -setreg expects, following
    the recipe captured from a real client's live issuing CA (see Examples_Sources\ for the captured recipe). It
    makes no assumptions beyond that captured recipe, so if any of it is wrong it's a one-line data
    fix here.

    Set-CAPublicationUrls applies the plan via certutil -setreg (behind Invoke-CAStep, so it honours
    dry-run), republishes the CRL, and restarts CertSvc.

    ORDER-CRITICAL: this must run BEFORE any certificate is issued - every issued cert bakes its
    CDP/AIA/OCSP URLs in permanently.

.NOTES
    certutil -setreg replacement tokens used below:
      %1 ServerDNSName   %2 ServerShortName   %3 CaName   %4 CertificateNameSuffix (renewal)
      %6 ConfigContainer %7 CATruncatedName   %8 CRLNameSuffix   %9 DeltaCRLAllowed
      %10 CDPObjectClass %11 CAObjectClass
    Flag values:
      1  ServerPublish    2  AddToCertCDP/AIA    4  AddToFreshestCRL    8  AddToCrlCDP
      32 AddToCertOCSP     64 ServerPublishDelta  128 AddToIDP
      -> 65 = ServerPublish + ServerPublishDelta ;  6 = AddToCertCDP + AddToFreshestCRL
#>

function Get-CAPublicationUrlPlan {
    <#
    .SYNOPSIS
        Builds the target CDP and AIA MULTI_SZ entry lists from the CA_* answers. Pure - no I/O.

    .PARAMETER CrlFqdn
        External hostname the App Proxy publishes for CRL + CA-cert (AIA) retrieval, e.g.
        'crl-<company>.msappproxy.net'.  (CA_AppProxyCrlFqdn)

    .PARAMETER OcspFqdn
        External hostname the App Proxy publishes for OCSP, e.g. 'ocsprelay-<company>.msappproxy.net'.
        (CA_AppProxyOcspFqdn)

    .PARAMETER DeltaCrl
        $true to publish delta CRLs (adds the ServerPublishDelta flag to the publish targets).

    .PARAMETER CrlSharePath
        UNC or local path of the CRL distribution share, or '' / $null for None. When set, an extra
        publish target is added for it. (CA_CrlSharePath, when CA_CrlShareMode is not None)
    #>
    param(
        [Parameter(Mandatory)][string]$CrlFqdn,
        [Parameter(Mandatory)][string]$OcspFqdn,
        [bool]$DeltaCrl = $true,
        [string]$CrlSharePath
    )

    $pub = if ($DeltaCrl) { 65 } else { 1 }   # ServerPublish (+ ServerPublishDelta)

    $cdp = @(
        "${pub}:%windir%\system32\CertSrv\CertEnroll\%3%8%9.crl"
        "${pub}:ldap:///CN=%7%8,CN=%2,CN=CDP,CN=Public Key Services,CN=Services,%6%10"
        "6:http://$CrlFqdn/CertEnroll/%3%8%9.crl"
    )
    if (-not [string]::IsNullOrWhiteSpace($CrlSharePath)) {
        $p = ($CrlSharePath.TrimEnd('\', '/')) -replace '\\', '/'
        $cdp += "${pub}:file://$p/%3%8%9.crl"
    }

    $aia = @(
        "1:%windir%\system32\CertSrv\CertEnroll\%1_%3%4.crt"
        "1:ldap:///CN=%7,CN=AIA,CN=Public Key Services,CN=Services,%6%11"
        # Filename MUST match the local-publish entry above (%1_%3%4.crt) - the CA only ever writes the
        # CA-cert file to disk under that name (server-DNS-name-prefixed, %4 disambiguates renewals).
        # That reference client's own live capture has this entry as bare "%3.crt", mismatched against
        # its own "%1_%3%4.crt" local-publish filename - a pre-existing bug
        # transcribed faithfully from that recipe, caught live on a client's CA server 2026-09-10 (external AIA
        # cert retrieval 404s while CDP, whose local/external filenames DO match - %3%8%9.crl both
        # places - works fine). Use the matching filename here instead of perpetuating it.
        "2:http://$CrlFqdn/CertEnroll/%1_%3%4.crt"
        "32:http://$OcspFqdn/ocsp"
    )

    return [pscustomobject]@{
        Cdp = $cdp
        Aia = $aia
        # the certutil -setreg argument form (entries joined with a literal \n)
        CdpSetRegValue = ($cdp -join "\n")
        AiaSetRegValue = ($aia -join "\n")
    }
}

function Set-CAPublicationUrls {
    <#
    .SYNOPSIS
        Applies a Get-CAPublicationUrlPlan result to the local CA: certutil -setreg for CDP + AIA,
        then certutil -crl (republish), then restart CertSvc. Every mutating call goes through
        Invoke-CAStep so dry-run just prints the commands.
    #>
    param(
        [Parameter(Mandatory)]$Plan,
        [switch]$SkipCrlRepublish,
        [switch]$SkipServiceRestart
    )

    # The CA only substitutes its %1-%12 tokens in these paths - it does NOT expand environment
    # variables like %windir%/%SystemRoot% (it strips the percents -> a bogus relative "windir\..."
    # path -> 0x8007010b ERROR_DIRECTORY at CRL-publish). AD CS's own install default writes the
    # literal path for this reason. Expand env vars here (this runs on the CA), leaving %1-%12 alone.
    $cdpVal = (($Plan.Cdp | ForEach-Object { [Environment]::ExpandEnvironmentVariables($_) }) -join "\n")
    $aiaVal = (($Plan.Aia | ForEach-Object { [Environment]::ExpandEnvironmentVariables($_) }) -join "\n")

    Invoke-CAStep -Description "Set CRL distribution points (CRLPublicationURLs)" `
        -Commands @("certutil -setreg CA\CRLPublicationURLs `"$cdpVal`"") `
        -Action {
            $o = & certutil.exe -setreg CA\CRLPublicationURLs $cdpVal 2>&1 | Out-String
            if ($LASTEXITCODE -ne 0) { throw "certutil -setreg CA\CRLPublicationURLs failed (exit $LASTEXITCODE): $o" }
            $o
        } | Out-Null

    Invoke-CAStep -Description "Set authority information access + OCSP (CACertPublicationURLs)" `
        -Commands @("certutil -setreg CA\CACertPublicationURLs `"$aiaVal`"") `
        -Action {
            $o = & certutil.exe -setreg CA\CACertPublicationURLs $aiaVal 2>&1 | Out-String
            if ($LASTEXITCODE -ne 0) { throw "certutil -setreg CA\CACertPublicationURLs failed (exit $LASTEXITCODE): $o" }
            $o
        } | Out-Null

    if (-not $SkipServiceRestart) {
        Invoke-CAStep -Description "Restart the CA service so the new URL registry values take effect" `
            -Commands @("Restart-Service CertSvc  (then wait for the CA's RPC endpoint via certutil -ping)") `
            -Action {
                Restart-Service -Name CertSvc -Force
                # 'Running' != RPC-ready - certutil -ping returns 0 only once the CA answers RPC.
                $rpcUp = $false
                for ($i = 0; $i -lt 20; $i++) {
                    & certutil.exe -ping 2>&1 | Out-Null
                    if ($LASTEXITCODE -eq 0) { $rpcUp = $true; break }
                    Start-Sleep -Seconds 3
                }
                if (-not $rpcUp) { throw "CertSvc restarted but the CA is not answering RPC (certutil -ping) after 60s" }
            } | Out-Null
    }

    if (-not $SkipCrlRepublish) {
        Invoke-CAStep -Description "Republish the CRL so the new CDP/AIA are reflected" `
            -Commands @("certutil -crl") `
            -Action {
                $o = ''
                for ($i = 1; $i -le 4; $i++) {
                    $o = & certutil.exe -crl 2>&1 | Out-String
                    if ($LASTEXITCODE -eq 0) { return $o }
                    if ($o -notmatch '0x800706ba|RPC server is unavailable|1722') { break }   # only retry the RPC-warmup race
                    Start-Sleep -Seconds 5
                }
                throw "certutil -crl failed (exit $LASTEXITCODE): $o"
            } -ContinueOnError | Out-Null
    }
}
