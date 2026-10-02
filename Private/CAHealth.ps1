<#
.SYNOPSIS
    CA Manager - menu 9 health check. Aggregates the read-only probes from Get-CAStatus / the
    per-menu Test-* functions into a PASS/WARN/FAIL report, and offers a targeted fix for each
    non-PASS row that has a clean single-engine remedy.

.DESCRIPTION
    Get-CAHealthReport is read-only. Each returned row carries a Fix (or $null): a { Label; Run }
    where Run is a scriptblock that calls the relevant engine (dry-run aware via Invoke-CAStep) or
    prints "run menu N". Invoke-CAMenuHealth renders the report and, per non-PASS row with a Fix,
    asks before running it and re-probes that one row.
#>

# ---------------------------------------------------------------------------
function New-CAHealthRow {
    param(
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][string]$Label,
        [ValidateSet('PASS', 'WARN', 'FAIL', 'SKIP')][string]$State = 'SKIP',
        [string]$Detail = '',
        $Fix = $null
    )
    [pscustomobject]@{ Id = $Id; Label = $Label; State = $State; Detail = $Detail; Fix = $Fix }
}

# ---------------------------------------------------------------------------
function Get-CAHealthReport {
    <#
    .SYNOPSIS
        Read-only. Returns an ordered [pscustomobject[]] of health rows. Nothing here writes.
    .PARAMETER SampleCertPath
        Optional path to a cert issued by this CA - enables the end-to-end
        `certutil -verify -urlfetch` (CRL + OCSP) check.
    #>
    param(
        [Parameter(Mandatory)]$CAAnswers,
        [Parameter(Mandatory)]$Status,
        [string]$SampleCertPath,
        # 2026-09-10, Part A item 8 - promotes menu 12's proven remote-client engines
        # (Get-CARenewalTemplateOid/Get-CARenewalTestCert, CARenewalTest.ps1) outward into the
        # health check, which had zero remote-client visibility before this. Both optional - SKIP
        # (not FAIL) when either is blank, same convention as -SampleCertPath above.
        [string]$RemoteClientComputerName,
        [string]$RemoteClientTemplateCn
    )
    $rows = New-Object System.Collections.Generic.List[object]

    # 1. CA service
    $svc = try { (Get-Service -Name CertSvc -ErrorAction Stop).Status } catch { $null }
    $rows.Add((New-CAHealthRow -Id 'ca-service' -Label 'AD CS service (CertSvc) running' `
        -State $(if ($svc -eq 'Running') { 'PASS' } elseif ($null -eq $svc) { 'SKIP' } else { 'FAIL' }) `
        -Detail "$svc" `
        -Fix $(if ($svc -and $svc -ne 'Running') { @{ Label = 'Start-Service CertSvc'; Run = {
            Invoke-CAStep -Description 'Start CertSvc' -Commands @('Start-Service CertSvc') -Action { Start-Service CertSvc } | Out-Null } } } else { $null })))

    # 2. custom templates published
    $tmplRows = @($Status.ExpectedTemplateStatus)
    $missing  = @($tmplRows | Where-Object { -not $_.Published })
    $rows.Add((New-CAHealthRow -Id 'templates' -Label 'Custom templates published on the CA' `
        -State $(if (-not $tmplRows.Count) { 'SKIP' } elseif (-not $missing.Count) { 'PASS' } else { 'FAIL' }) `
        -Detail $(if ($tmplRows.Count) { "$(($tmplRows | Where-Object Published).Count)/$($tmplRows.Count) published$(if ($missing.Count) { ' - missing: ' + ($missing.Name -join ', ') })" } else { 'could not read' }) `
        -Fix $(if ($missing.Count) { @{ Label = 'run menu 4 (Create / update certificate templates)'; Run = { Write-Host '    -> run menu 4, then menu 5 for permissions.' -ForegroundColor Cyan } } } else { $null })))

    # 3. auto-enrollment policy
    $rows.Add((New-CAHealthRow -Id 'autoenroll' -Label 'Auto-enrollment policy present (GPO applied)' `
        -State $(switch ($Status.AutoEnrollPolicyPresent) { $true { 'PASS' } $false { 'WARN' } default { 'SKIP' } }) `
        -Detail $(if ($Status.AutoEnrollPolicyPresent) { 'AEPolicy bit set' } else { 'not detected on this box (gpupdate may be pending, or (re)create the GPO via AD-Manager)' }) `
        -Fix $(if ($Status.AutoEnrollPolicyPresent -eq $false) { @{ Label = 'gpupdate /force  (or (re)create the GPO via AD-Manager - moved there 2026-09-12, was this dashboard''s own menu 10)'; Run = {
            Invoke-CAStep -Description 'gpupdate /force' -Commands @('gpupdate /force') -Action { & gpupdate.exe /force | Out-String } -ContinueOnError | Out-Null } } } else { $null })))

    # 4. CDP / AIA routed through the App Proxy
    $rows.Add((New-CAHealthRow -Id 'cdp-aia' -Label 'CDP + AIA/OCSP routed through the App Proxy' `
        -State $(if ($Status.HasExternalCDP -and $Status.HasExternalAIAorOCSP) { 'PASS' } elseif ($null -eq $Status.HasExternalCDP) { 'SKIP' } else { 'FAIL' }) `
        -Detail ("CDP external {0}, AIA/OCSP external {1}" -f $Status.HasExternalCDP, $Status.HasExternalAIAorOCSP) `
        -Fix $(if (-not ($Status.HasExternalCDP -and $Status.HasExternalAIAorOCSP)) { @{ Label = 'run menu 8 (Route AIA / CDP / OCSP through the App Proxy)'; Run = { Write-Host '    -> run menu 8.' -ForegroundColor Cyan } } } else { $null })))

    # 5. CRL fresh + present locally
    $sanitized = try { Get-CAActiveConfigName } catch { $Status.CACommonName }
    $crlFile   = Join-Path $env:windir "System32\CertSrv\CertEnroll\$sanitized.crl"
    $crlState = 'SKIP'; $crlDetail = 'no local CRL file'
    if (Test-Path $crlFile) {
        $nextUpd = $null
        try {
            $dump = & certutil.exe -dump $crlFile 2>&1 | Out-String
            if ($dump -match 'NextUpdate:\s*(.+)') { $nextUpd = [datetime]::Parse($Matches[1].Trim()) }
        } catch { }
        if ($nextUpd) {
            $crlState  = if ((Get-Date) -lt $nextUpd) { 'PASS' } else { 'FAIL' }
            $crlDetail = "NextUpdate $($nextUpd.ToString('yyyy-MM-dd HH:mm'))"
        } else { $crlState = 'WARN'; $crlDetail = 'present but NextUpdate not parsed' }
    }
    $rows.Add((New-CAHealthRow -Id 'crl-fresh' -Label 'Base CRL present and not expired' -State $crlState -Detail $crlDetail `
        -Fix $(if ($crlState -in @('FAIL', 'WARN')) { @{ Label = 'certutil -crl  (republish now)'; Run = {
            Invoke-CAStep -Description 'certutil -crl' -Commands @('certutil -crl') -Action { $o = & certutil.exe -crl 2>&1 | Out-String; if ($LASTEXITCODE -ne 0) { throw "certutil -crl exit $LASTEXITCODE`n$o" }; $o } -ContinueOnError | Out-Null } } } else { $null })))

    # 6. CRL reachable off-network (through the App Proxy)
    $crlUrl = if ($CAAnswers.CA_AppProxyCrlFqdn -and "$($CAAnswers.CA_AppProxyCrlFqdn)" -match '\.') {
        "http://$($CAAnswers.CA_AppProxyCrlFqdn)/CertEnroll/$sanitized.crl"
    } else { $null }
    $offState = 'SKIP'; $offDetail = 'CA_AppProxyCrlFqdn not resolved yet (menu 6)'
    if ($crlUrl) {
        try {
            $resp = Invoke-WebRequest -Uri $crlUrl -UseBasicParsing -TimeoutSec 15 -ErrorAction Stop
            $offState  = if ($resp.StatusCode -eq 200 -and $resp.RawContentLength -gt 0) { 'PASS' } else { 'WARN' }
            $offDetail = "HTTP $($resp.StatusCode), $($resp.RawContentLength) bytes"
        } catch {
            $offState  = 'FAIL'
            $offDetail = "$crlUrl -> $($_.Exception.Message)"
        }
    }
    $rows.Add((New-CAHealthRow -Id 'crl-offnet' -Label 'CRL reachable through the App Proxy (off-network)' -State $offState -Detail $offDetail `
        -Fix $(if ($offState -eq 'FAIL') { @{ Label = 'check menu 6 (App Proxy app) + menu 8 (URLs); a fresh App Proxy app needs ~10-15 min to provision'; Run = { Write-Host '    -> re-run menu 6, then menu 8.' -ForegroundColor Cyan } } } else { $null })))

    # 7. OCSP responder answering
    $ocspWorking = $false
    if (Get-Command Test-CAOcspEndpoint -ErrorAction SilentlyContinue) {
        $ocspWorking = Test-CAOcspEndpoint -Url 'http://localhost/ocsp' -RetrySeconds 10
    }
    $rows.Add((New-CAHealthRow -Id 'ocsp' -Label 'OCSP responder (/ocsp) answering' `
        -State $(if (-not $Status.OCSPRoleInstalled) { 'SKIP' } elseif ($ocspWorking) { 'PASS' } else { 'FAIL' }) `
        -Detail $(if (-not $Status.OCSPRoleInstalled) { 'role not installed' } elseif ($ocspWorking) { 'answered' } else { 'no answer on http://localhost/ocsp' }) `
        -Fix $(if ($Status.OCSPRoleInstalled -and -not $ocspWorking) { @{ Label = 're-push the config (Publish-CAOcspConfig) - or run menu 9'; Run = {
            if (Get-Command Publish-CAOcspConfig -ErrorAction SilentlyContinue) { Publish-CAOcspConfig } else { Write-Host '    -> run menu 9.' -ForegroundColor Cyan } } } } else { $null })))

    # 8. App Proxy connector
    $rows.Add((New-CAHealthRow -Id 'connector' -Label 'App Proxy connector running' `
        -State $(if ($Status.AppProxyConnectorStatus -eq 'Running') { 'PASS' } elseif (-not $Status.AppProxyConnectorInstalled) { 'SKIP' } else { 'FAIL' }) `
        -Detail $(if ($Status.AppProxyConnectorInstalled) { "$($Status.AppProxyConnectorStatus)" } else { 'not installed' }) `
        -Fix $(if ($Status.AppProxyConnectorInstalled -and $Status.AppProxyConnectorStatus -ne 'Running') { @{ Label = 'Start-Service WAPCSvc'; Run = {
            Invoke-CAStep -Description 'Start WAPCSvc' -Commands @('Start-Service WAPCSvc') -Action { Start-Service WAPCSvc } -ContinueOnError | Out-Null } } } else { $null })))

    # 9. end-to-end verify (optional - needs a real leaf cert)
    if ($SampleCertPath -and (Test-Path $SampleCertPath) -and (Get-Command Test-CAOcspEndpoint -ErrorAction SilentlyContinue)) {
        $ok = Test-CAOcspEndpoint -IssuedCertPath $SampleCertPath
        $rows.Add((New-CAHealthRow -Id 'verify' -Label "certutil -verify -urlfetch  ($([System.IO.Path]::GetFileName($SampleCertPath)))" `
            -State $(if ($ok) { 'PASS' } else { 'WARN' }) `
            -Detail $(if ($ok) { 'revocation check passed via CRL/OCSP' } else { 'did not confirm - inspect certutil -verify -urlfetch output manually' })))
    } else {
        $rows.Add((New-CAHealthRow -Id 'verify' -Label 'End-to-end certutil -verify -urlfetch' -State 'SKIP' -Detail 'pass -SampleCertPath <a cert issued by this CA> to run this'))
    }

    # 10. remote client actually holds a cert from this CA (optional - promoted from menu 12, item 8).
    # Needs WinRM reachable from wherever CA-Manager runs to the target client. A FortiGate's DEFAULT
    # posture only allows client-initiated traffic and does NOT create a reverse (CA -> client) rule,
    # so this may not answer at all over a real field VPN tunnel without that explicitly configured -
    # this check can't tell "no reverse rule" apart from "genuinely no cert issued yet" on its own; a
    # FAIL here is a starting point to investigate, not a definitive verdict either way.
    if ($RemoteClientComputerName -and $RemoteClientTemplateCn) {
        $label = "Remote client '$RemoteClientComputerName' holds a cert from '$RemoteClientTemplateCn'"
        if (-not (Get-Command Get-CARenewalTemplateOid -ErrorAction SilentlyContinue) -or -not (Get-Command Get-CARenewalTestCert -ErrorAction SilentlyContinue)) {
            $rows.Add((New-CAHealthRow -Id 'remote-cert' -Label $label -State 'SKIP' -Detail 'CARenewalTest.ps1 (Get-CARenewalTemplateOid/Get-CARenewalTestCert) not loaded'))
        } else {
            try {
                $oid  = Get-CARenewalTemplateOid -TemplateCn $RemoteClientTemplateCn
                $cert = Get-CARenewalTestCert -TemplateOid $oid -ComputerName $RemoteClientComputerName
                if (-not $cert) { $cert = Get-CARenewalTestCert -TemplateOid $oid -ComputerName $RemoteClientComputerName -StoreLocation LocalMachine }
                $rows.Add((New-CAHealthRow -Id 'remote-cert' -Label $label `
                    -State $(if ($cert) { 'PASS' } else { 'FAIL' }) `
                    -Detail $(if ($cert) { "thumbprint $($cert.Thumbprint), expires $($cert.NotAfter.ToString('yyyy-MM-dd'))" } else { 'no matching cert in CurrentUser or LocalMachine store - not necessarily a real problem, see the note above about FortiGate reverse rules' })))
            } catch {
                $rows.Add((New-CAHealthRow -Id 'remote-cert' -Label $label -State 'FAIL' -Detail "could not check: $($_.Exception.Message)"))
            }
        }
    } else {
        $rows.Add((New-CAHealthRow -Id 'remote-cert' -Label 'Remote client holds an issued VPN cert (optional)' -State 'SKIP' -Detail 'pass -RemoteClientComputerName + -RemoteClientTemplateCn to check a specific client'))
    }

    $rows.ToArray()
}

# ---------------------------------------------------------------------------
function Show-CAHealthReport {
    param([Parameter(Mandatory)]$Report)
    Write-Host ""
    foreach ($r in $Report) {
        $c = switch ($r.State) { 'PASS' { 'Green' } 'WARN' { 'Yellow' } 'FAIL' { 'Red' } default { 'DarkGray' } }
        Write-Host ("  [{0,-4}] {1,-48} {2}" -f $r.State, $r.Label, $r.Detail) -ForegroundColor $c
    }
    $fail = @($Report | Where-Object State -eq 'FAIL').Count
    $warn = @($Report | Where-Object State -eq 'WARN').Count
    Write-Host ""
    Write-Host ("  {0} PASS / {1} WARN / {2} FAIL / {3} SKIP" -f `
        @($Report | Where-Object State -eq 'PASS').Count, $warn, $fail, @($Report | Where-Object State -eq 'SKIP').Count) `
        -ForegroundColor $(if ($fail) { 'Red' } elseif ($warn) { 'Yellow' } else { 'Green' })
}

# ---------------------------------------------------------------------------
function Invoke-CAMenuHealth {
    <#
    .SYNOPSIS
        Menu 11 (2026-09-10 renumber - was menu 9). Runs Get-CAHealthReport, prints it, then offers
        each non-PASS row's fix. Optionally checks a real VPN client (over PS remoting) for an
        actually-issued cert from a named template - promoted from menu 12's proven remote-client
        engines (Part A item 8); needs WinRM reachable from this box to the client.
    #>
    param(
        $CAAnswers,
        [Parameter(Mandatory)]$Status
    )
    Write-CAHeader "Health check"
    if (-not $CAAnswers) { $CAAnswers = [pscustomobject]@{} }

    if (-not $Status.CACommonName) {
        Write-Host "  No local CA detected - run menu 2 on the CA box." -ForegroundColor Yellow
        Read-Host "`nPress Enter to return to the menu" | Out-Null; return
    }

    $sample = Read-Host "  Path to a cert issued by this CA for the end-to-end verify (optional, Enter to skip)"

    # Remote-client visibility (2026-09-10, Part A item 8) - both blank is the common case and just
    # SKIPs that one row; note up front that this needs WinRM reachable from this box to the client
    # (a FortiGate's default posture doesn't open a reverse rule for it - see the row's own detail
    # text if it FAILs).
    $remoteClient = Read-Host "  VPN client hostname to verify has a real issued cert (optional, Enter to skip)"
    $remoteTemplateCn = $null
    if (-not [string]::IsNullOrWhiteSpace($remoteClient)) {
        $defaultCn = if (-not [string]::IsNullOrWhiteSpace($CAAnswers.CA_TemplateAuto)) { ($CAAnswers.CA_TemplateAuto -replace '[^A-Za-z0-9]', '') } else { 'IKEv2VPNCorpLAN' }
        $remoteTemplateCn = Read-Host "  Template CN to check for on that client [$defaultCn]"
        if ([string]::IsNullOrWhiteSpace($remoteTemplateCn)) { $remoteTemplateCn = $defaultCn }
    }

    $report = Get-CAHealthReport -CAAnswers $CAAnswers -Status $Status -SampleCertPath $sample -RemoteClientComputerName $remoteClient -RemoteClientTemplateCn $remoteTemplateCn
    Show-CAHealthReport -Report $report

    $fixable = @($report | Where-Object { $_.State -in @('FAIL', 'WARN') -and $_.Fix })
    if (-not $fixable.Count) {
        Write-Host ""
        Write-Host "  Nothing to fix from here." -ForegroundColor Gray
        Read-Host "`nPress Enter to return to the menu" | Out-Null; return
    }

    foreach ($row in $fixable) {
        Write-Host ""
        Write-Host ("  [{0}] {1}" -f $row.State, $row.Label) -ForegroundColor Yellow
        Write-Host ("        fix: {0}" -f $row.Fix.Label) -ForegroundColor Gray
        if (Read-CAConfirm -Prompt "  attempt this fix?") {
            try { & $row.Fix.Run } catch { Write-Host "        fix errored: $($_.Exception.Message)" -ForegroundColor Red }
            Start-Sleep -Seconds 2
            $re = Get-CAHealthReport -CAAnswers $CAAnswers -Status $Status -SampleCertPath $sample -RemoteClientComputerName $remoteClient -RemoteClientTemplateCn $remoteTemplateCn | Where-Object Id -eq $row.Id
            if ($re) { Write-Host ("        now: [{0}] {1}" -f $re.State, $re.Detail) -ForegroundColor $(if ($re.State -eq 'PASS') { 'Green' } else { 'Yellow' }) }
        }
    }
    Read-Host "`nPress Enter to return to the menu" | Out-Null
}
