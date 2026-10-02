#region Standalone
<#
.SYNOPSIS
    Shared engine for VPN user-certificate requests. Pure functions, no top-level side effects -
    safe to dot-source.

.DESCRIPTION
    Dot-sourced by:
      - IPSEC AIO\MiscTools\Tools\Request-VPNCert.ps1        (interactive, one cert at a time)
      - PushableTools\CAManager\Modules\CATestSuite.ps1      (batch - a whole valid+revoked test
        suite; the CAManager.zip build copies THIS file in next to CA-Manager.ps1)

    Both entry points share the AD-user search, the Get-Certificate request/retrieve/export path,
    and (test-suite only) the certutil revoke + CRL republish - so the request shape (DnsName SAN =
    mail + DN, SubjectName = "E=<mail>, <DN>") can never drift between the two.

.NOTES
    Get-Certificate uses the machine's normal AD CS enrollment discovery - no CA URL needed unless
    -Url is supplied. If the template requires manager approval the request is left PENDING;
    Complete-VPNCertRequest must be called AFTER an admin issues it on the CA.
#>

function Find-VPNCertADUser {
    <#
    .SYNOPSIS
        Wildcard-searches AD for the target user and returns one AD user object
        (SamAccountName / UserPrincipalName / mail / DistinguishedName).

    .PARAMETER SearchTerm
        Partial SamAccountName to seed the search. If omitted (and -NonInteractive is not set), the
        user is prompted for it.

    .PARAMETER NonInteractive
        Batch mode: the search MUST resolve to exactly one user or this throws. No prompts.

    .PARAMETER ReturnNullOnNoMatch
        2026-09-15, per the maintainer (CA-Manager menu 11): when -SearchTerm was supplied by a caller that
        has its own retry/skip loop (New-CATestCertSuite's per-template username prompt), a 0-match
        search should just return $null so THAT caller's own "blank to skip this template" prompt
        gets control back - not loop forever inside here re-prompting with this function's own
        generic message. Only changes the 0-MATCH path; a 2+ match disambiguation picker still
        prompts here either way. Default ($false, the original behavior) still applies to
        Request-VPNCert.ps1's standalone interactive use, where re-prompting in place is correct.
    #>
    param(
        [string]$SearchTerm,
        [switch]$NonInteractive,
        [switch]$ReturnNullOnNoMatch
    )

    # Column table for the "more than one match" picker.
    function Show-VPNCertUserTable {
        param($UserList)
        $props = @('UserPrincipalName', 'SamAccountName')
        $widths = @{}
        foreach ($p in $props) {
            $widths[$p] = (($UserList | ForEach-Object { "$($_.$p)".Length }) | Sort-Object -Descending | Select-Object -First 1)
            if (-not $widths[$p] -or $widths[$p] -lt $p.Length) { $widths[$p] = $p.Length }
        }
        $fmt = "{0,-6}" + (($props | ForEach-Object { "{$([array]::IndexOf($props, $_) + 1),-$($widths[$_] + 3)}" }) -join '')
        # NOTE 2026-09-15, real bug hit live at a client: '-f' binds TIGHTER than '+' in PowerShell, so
        # "$fmt -f @('idx') + $props" was actually "($fmt -f @('idx')) + $props" - -f ran with only ONE
        # value against a 3-placeholder format string ("Index...must be...less than the size of the
        # argument list"). The array concatenation must be grouped BEFORE -f sees it.
        Write-Host ($fmt -f (@('idx') + $props))
        for ($i = 0; $i -lt $UserList.Count; $i++) {
            $vals = @("$i`:") + ($props | ForEach-Object { "$($UserList[$i].$_)" })
            Write-Host ($fmt -f $vals)
        }
    }

    $term = $SearchTerm
    while ($true) {
        if ([string]::IsNullOrWhiteSpace($term)) {
            if ($NonInteractive) { throw "Find-VPNCertADUser: -SearchTerm is required in -NonInteractive mode." }
            $term = Read-Host "AD username to issue a certificate for (partial is fine - wildcard search)"
            if ([string]::IsNullOrWhiteSpace($term)) { continue }
        }

        # Server-side wildcard filter (not a client-side Where-Object over the whole directory).
        # Single quotes doubled so they can't break the -Filter string.
        $safe = $term.Replace("'", "''")
        $found = @(Get-ADUser -Filter "SamAccountName -like '*$safe*'" -Properties mail)

        if ($found.Count -eq 1) {
            return $found[0]
        }
        if ($found.Count -eq 0) {
            if ($NonInteractive) { throw "Find-VPNCertADUser: no AD user matched '*$term*'." }
            Write-Host "No users matched '*$term*'." -ForegroundColor Yellow
            if ($ReturnNullOnNoMatch) { return $null }
            $term = $null
            continue
        }
        # more than one
        if ($NonInteractive) { throw "Find-VPNCertADUser: '*$term*' matched $($found.Count) users - be more specific for batch mode." }
        Write-Host "Matched $($found.Count) users:" -ForegroundColor Cyan
        Show-VPNCertUserTable -UserList $found
        while ($true) {
            $pick = Read-Host "`nWhich one? (0-$($found.Count - 1), or S to search again)"
            if ($pick -match '^(?i)s$') { $term = $null; break }
            $idx = 0
            if ([int]::TryParse($pick, [ref]$idx) -and $idx -ge 0 -and $idx -lt $found.Count) {
                return $found[$idx]
            }
            Write-Host "Enter a number between 0 and $($found.Count - 1), or S." -ForegroundColor Yellow
        }
    }
}

function Resolve-VPNCertTemplateName {
    <#
    .SYNOPSIS
        Get-Certificate -Template (CX509Enrollment::InitializeFromTemplateName) wants the template's
        CN, NOT its display name. `certutil -CATemplates` prints "CN: DisplayName -- ...". Given
        either form, return the CN the CA will accept. Falls back to the input unchanged if certutil
        can't be read (e.g. not on the CA / no enterprise CA reachable).
    #>
    param([Parameter(Mandatory)][string]$Name)
    $out = try { & certutil.exe -CATemplates 2>&1 | Out-String } catch { '' }
    if ([string]::IsNullOrWhiteSpace($out)) { return $Name }
    $rows = foreach ($line in ($out -split "`r?`n")) {
        if ($line -match '^\s*([A-Za-z0-9][\w.-]*):\s*(.+?)\s*--') {
            [pscustomobject]@{ Cn = $Matches[1].Trim(); Display = $Matches[2].Trim() }
        }
    }
    $hit = $rows | Where-Object { $_.Cn -ieq $Name -or $_.Display -ieq $Name } | Select-Object -First 1
    if ($hit) { return $hit.Cn }
    # not published under that name - try Menu 1's CN convention (display name minus non-alphanumerics)
    $stripped = ($Name -replace '[^A-Za-z0-9]', '')
    if ($rows | Where-Object { $_.Cn -ieq $stripped }) { return $stripped }
    return $Name
}

function New-VPNCertRequest {
    <#
    .SYNOPSIS
        Submits a certificate request for a resolved AD user against $TemplateName via Get-Certificate.
        Returns Get-Certificate's result object (its .Request member carries Thumbprint/Subject). The
        request is left PENDING if the template requires manager approval.
    #>
    param(
        [Parameter(Mandatory)]$ADUser,
        [Parameter(Mandatory)][string]$TemplateName,
        [string]$Url,
        [string]$CertStoreLocation = 'Cert:\CurrentUser\My'
    )

    # Get-Certificate wants the template CN, not the display name (IKEv2VPN-CorpLAN-MANUAL ->
    # IKEv2VPNCorpLANMANUAL). Resolve it against what the CA actually publishes.
    $TemplateName = Resolve-VPNCertTemplateName -Name $TemplateName

    # SAN = mail + DN, blanks filtered (a user with no 'mail' attribute would otherwise pass $null).
    $dnsName = @($ADUser.mail, $ADUser.DistinguishedName) | Where-Object { $_ }
    # 2026-09-15, real bug found live at a client (TameMyCerts's own CA-log entry showed 'E="", CN=...' -
    # an emailAddress RDN with an EMPTY value): a test account with no 'mail' attribute set (several
    # of that client's per-group test users - IV2.Plant, IV2.PSGI, IV2.Auditor) used to always get an
    # "E=$mail, " prefix even when $mail was $null/blank, producing a malformed empty-valued RDN.
    # Omit the E= RDN entirely when there's no mail attribute to put in it.
    $subject = if ($ADUser.mail) { "E=$($ADUser.mail), $($ADUser.DistinguishedName)" } else { "$($ADUser.DistinguishedName)" }

    $params = @{
        Template          = $TemplateName
        DnsName           = $dnsName          # [string[]] - passed directly, not pre-joined
        SubjectName       = $subject
        CertStoreLocation = $CertStoreLocation
    }
    if ($Url) { $params.Url = $Url }

    try {
        $result = Get-Certificate @params
    } catch {
        Write-Host "ERROR: certificate request failed - $($_.Exception.Message)" -ForegroundColor Red
        return $null
    }
    Write-Host ("Requested: subject '{0}', thumbprint {1}" -f $result.Request.Subject, $result.Request.Thumbprint) -ForegroundColor Green
    return $result
}

function Complete-VPNCertRequest {
    <#
    .SYNOPSIS
        Retrieves an approved request and exports a password-protected PFX, plus the public-key-only
        .cer alongside it. Returns [pscustomobject]@{ Status; Thumbprint; SerialNumber; PfxPath;
        CerPath }. Status is 'Issued' on success, otherwise whatever Get-Certificate reported (e.g.
        'Pending') or 'Error'.

    .NOTES
        2026-09-15, per the maintainer (re: CA-Manager menu 11's test-cert suite): "why didn't I have you do
        it during generation time" - export the .cer (public certificate, no private key) at the same
        moment the PFX is exported, rather than as a separate later step. CerPath is $null (not an
        error) if the .cer export fails but the PFX already succeeded - the tech still has a usable
        PFX either way, so a .cer hiccup doesn't blank out an otherwise-successful issuance.
    #>
    param(
        [Parameter(Mandatory)]$RequestObject,
        [Parameter(Mandatory)][string]$OutputDir,
        [Parameter(Mandatory)][securestring]$PfxPassword,
        # File name stem (no extension). Default: sanitized SamAccountName + date.
        [string]$FileNameStem,
        # Store the request/issued cert lives in. Cert:\LocalMachine\My for a machine-context enroll.
        [string]$CertStoreLocation = 'Cert:\CurrentUser\My'
    )

    if (-not (Test-Path $OutputDir)) { New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null }

    $out = [pscustomobject]@{ Status = 'Error'; Thumbprint = $null; SerialNumber = $null; PfxPath = $null; CerPath = $null }

    try {
        $retrieved = Get-Certificate -Request $RequestObject.Request
    } catch {
        Write-Host "ERROR: certificate retrieval failed - $($_.Exception.Message)" -ForegroundColor Red
        return $out
    }

    $out.Status = "$($retrieved.Status)"
    if ($retrieved.Status -ne 'Issued') {
        Write-Host "WARNING: request status is '$($retrieved.Status)', not 'Issued' - has it been approved on the CA yet?" -ForegroundColor Yellow
        return $out
    }

    $cert = $retrieved.Certificate
    $out.Thumbprint   = $cert.Thumbprint
    $out.SerialNumber = $cert.SerialNumber

    if (-not $FileNameStem) {
        $FileNameStem = ($RequestObject.Request.Subject -replace '[^A-Za-z0-9]', '') + "_" + (Get-Date -Format 'MM_dd_yyyy')
    }
    $pfxPath = Join-Path $OutputDir ($FileNameStem + ".pfx")
    $cerPath = Join-Path $OutputDir ($FileNameStem + ".cer")

    try {
        $store = $CertStoreLocation.TrimEnd('\')
        $certPath = if (Test-Path "$store\$($cert.Thumbprint)") { "$store\$($cert.Thumbprint)" }
                    elseif (Test-Path "Cert:\LocalMachine\My\$($cert.Thumbprint)") { "Cert:\LocalMachine\My\$($cert.Thumbprint)" }
                    else { "Cert:\CurrentUser\My\$($cert.Thumbprint)" }
        Export-PfxCertificate -Cert $certPath -FilePath $pfxPath -Password $PfxPassword | Out-Null
        $out.PfxPath = $pfxPath
        Write-Host "Exported: $pfxPath" -ForegroundColor Green

        # Public-key-only .cer alongside the PFX - no password, no private key, safe to hand to
        # anyone who just needs to import/trust/inspect the cert (e.g. pinning it into a FortiGate
        # peer, or a quick certutil -dump). A failure here doesn't blank out the PFX result above.
        try {
            Export-Certificate -Cert $certPath -FilePath $cerPath -Type CERT | Out-Null
            $out.CerPath = $cerPath
            Write-Host "Exported: $cerPath" -ForegroundColor Green
        } catch {
            Write-Host "WARNING: .cer export failed (PFX above is still good) - $($_.Exception.Message)" -ForegroundColor Yellow
        }
    } catch {
        Write-Host "ERROR: PFX export failed - $($_.Exception.Message)" -ForegroundColor Red
    }
    return $out
}

function Revoke-VPNCert {
    <#
    .SYNOPSIS
        Revokes an issued certificate by serial number via certutil, then (optionally) republishes
        the CRL so the revocation is picked up. Test-suite use only. Returns
        [pscustomobject]@{ Revoked; CrlRepublished; Detail }.
    #>
    param(
        [Parameter(Mandatory)][string]$SerialNumber,
        # certutil revoke reason: 0 = unspecified, 1 = key compromise, 3 = affiliation changed,
        # 4 = superseded, 5 = cessation of operation, 6 = certificate hold.
        [int]$ReasonCode = 0,
        [switch]$RepublishCrl
    )
    $out = [pscustomobject]@{ Revoked = $false; CrlRepublished = $false; Detail = $null }
    try {
        $r = & certutil.exe -revoke $SerialNumber $ReasonCode 2>&1 | Out-String
        $out.Detail = $r.Trim()
        $out.Revoked = ($r -match '(?i)completed successfully')
        if (-not $out.Revoked) { Write-Host "WARNING: certutil -revoke did not report success:`n$($out.Detail)" -ForegroundColor Yellow }
    } catch {
        $out.Detail = $_.Exception.Message
        Write-Host "ERROR: certutil -revoke failed - $($_.Exception.Message)" -ForegroundColor Red
        return $out
    }
    if ($RepublishCrl -and $out.Revoked) {
        try {
            $c = & certutil.exe -CRL 2>&1 | Out-String
            $out.CrlRepublished = ($c -match '(?i)completed successfully')
            if (-not $out.CrlRepublished) { Write-Host "WARNING: certutil -CRL did not report success:`n$($c.Trim())" -ForegroundColor Yellow }
        } catch {
            Write-Host "ERROR: certutil -CRL (CRL republish) failed - $($_.Exception.Message)" -ForegroundColor Red
        }
    }
    return $out
}
#endregion Standalone
