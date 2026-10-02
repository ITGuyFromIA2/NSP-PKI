<#
.SYNOPSIS
    CA Manager - test-certificate suite generator (menu option 8). Requires Modules\CACore.ps1,
    Modules\CATemplates.ps1 (Get-CAManualApprovalTemplates), and Modules\CAInteractive.ps1
    dot-sourced, plus Request-VPNCertCore.ps1 (bundled next to CA-Manager.ps1 by
    Build-CAManagerZip.ps1; dev-time fallback to the repo copy under IPSEC AIO\MiscTools\Tools\).

.DESCRIPTION
    Lists the "Manual approval" (PEND_ALL_REQUESTS) templates actually published on the CA and lets
    the tech pick one or more from a numbered list (2026-09-15, per the maintainer - replaces the old single
    free-typed template name, now that per-group manual templates exist alongside the shared one).
    For each PICKED TEMPLATE, prompts for one representative AD username and issues a SET of two
    certs against it: one left VALID and one immediately REVOKED (reason 0 / unspecified) with a
    CRL republish. All PFX files share one password. Writes a <Company>_CertTestSuite_<ts>.txt
    summary that also lists the FortiGate cache-refresh commands (a revoked cert can still pass on
    the FortiGate until its CRL/OCSP cache turns over).
#>

# --- locate + dot-source the shared request engine ---
$script:__caCoreLoaded = $false
# NSP.PKI: the module ships it as (only) Private\Engine\Request-VPNCertCore.ps1.
foreach ($candidate in @(
    (Join-Path $PSScriptRoot "Engine\Request-VPNCertCore.ps1")
)) {
    if (Test-Path $candidate) { . $candidate; $script:__caCoreLoaded = $true; break }
}

function New-CATestCertSuite {
    <#
    .SYNOPSIS
        Menu option 8. Iterates user types -> one valid + one revoked cert each.
    .PARAMETER Status
        The Get-CAStatus object (for the issuance-readiness gate).
    .PARAMETER CAAnswers
        Optional baked-in answers (Company_Name, CA_TemplateManual) from CAAnswers.json.
    #>
    param(
        [Parameter(Mandatory)]$Status,
        $CAAnswers
    )

    Write-CAHeader "Generate a test-certificate suite"

    if (-not $script:__caCoreLoaded) {
        Write-Host "Request-VPNCertCore.ps1 was not found - cannot issue certs." -ForegroundColor Red
        Write-Host "(Expected next to CA-Manager.ps1 in a built CAManager.zip, or under" -ForegroundColor Gray
        Write-Host " IPSEC AIO\MiscTools\Tools\ when running from the repo.)" -ForegroundColor Gray
        Read-Host "Press Enter to return to the menu" | Out-Null
        return
    }

    # --- order gate: issued certs bake in whatever revocation URLs are set right now ---
    if (-not $Status.IssuanceReady) {
        Write-Host "Issuance readiness is NOT READY." -ForegroundColor Yellow
        Write-Host "Any certificate issued now bakes in whatever AIA / CDP / OCSP URLs the CA" -ForegroundColor Yellow
        Write-Host "currently has - which won't be the App Proxy URLs yet. Test certs issued now" -ForegroundColor Yellow
        Write-Host "will not validate the same way real ones will after routing is finished." -ForegroundColor Yellow
        Write-Host ""
        $ack = Read-Host "Type YES (all caps) to issue test certs anyway, anything else to cancel"
        if ($ack -cne 'YES') { Write-Host "Cancelled." -ForegroundColor Gray; Read-Host "Press Enter" | Out-Null; return }
    }

    # --- template(s): numbered pick-list of published "Manual approval" templates -----------------
    # 2026-09-15, per the maintainer: used to be one free-typed name (always the single shared
    # IKEv2VPN-CorpLAN-MANUAL) - now that per-group manual templates exist (one per RadiusGroupPair,
    # Get-CAPerGroupManualTemplateSpec), show what's actually published and let the tech pick.
    $manualTemplates = @(Get-CAManualApprovalTemplates)
    if (-not $manualTemplates.Count) {
        Write-Host "No published templates with 'Manual approval' (PEND_ALL_REQUESTS) found on this CA." -ForegroundColor Yellow
        Write-Host "Run menu 4 first to create/publish a Manual (or per-group -MANUAL) template." -ForegroundColor Yellow
        Read-Host "Press Enter to return to the menu" | Out-Null
        return
    }
    Write-Host ""
    Write-Host "  Manual-approval templates published on this CA:" -ForegroundColor Cyan
    for ($i = 0; $i -lt $manualTemplates.Count; $i++) { Write-Host ("    [{0}] {1}" -f ($i + 1), $manualTemplates[$i].DisplayName) -ForegroundColor Gray }
    Write-Host ""
    # 2026-09-15, per the maintainer: "can we add a 'back'/'main menu' option here? and anywhere else we've
    # missed it" - this pick-list used to only cancel implicitly (blank/garbage input happened to
    # fall through to "no valid selection"), with no discoverable way to bail shown in the prompt
    # itself. 'B' is now explicit here and at every other prompt below in this function.
    $pickRaw = Read-Host "  Which template(s) to test? Comma-separated numbers, 'A' for all $($manualTemplates.Count), or 'B' to cancel and return to the menu"
    if ($pickRaw.Trim() -match '^(?i)b(ack)?$') { Write-Host "  Cancelled." -ForegroundColor Gray; return }
    $pickedTemplates = @(if ($pickRaw.Trim() -match '^(?i)a(ll)?$') {
        $manualTemplates
    } else {
        $pickRaw -split '[,\s]+' | Where-Object { $_ -match '^\d+$' } | ForEach-Object { [int]$_ - 1 } | Where-Object { $_ -ge 0 -and $_ -lt $manualTemplates.Count } | ForEach-Object { $manualTemplates[$_] }
    })
    if (-not $pickedTemplates.Count) {
        Write-Host "  No valid selection - cancelled." -ForegroundColor Yellow
        Read-Host "Press Enter to return to the menu" | Out-Null
        return
    }

    # --- output dir ---
    $outDir = Read-Host "Output directory for the PFX files [C:\Admin\TestPFX], or 'B' to cancel"
    if ($outDir.Trim() -match '^(?i)b(ack)?$') { Write-Host "  Cancelled." -ForegroundColor Gray; return }
    if ([string]::IsNullOrWhiteSpace($outDir)) { $outDir = 'C:\Admin\TestPFX' }
    if (-not (Test-Path $outDir)) { New-Item -ItemType Directory -Path $outDir -Force | Out-Null }

    # --- shared PFX password (asked once, confirmed) ---
    # 'B' is checked against the FIRST prompt only (decrypted just for this one comparison) - a real
    # PFX password being the literal single word "b"/"back" is vanishingly unlikely for an admin-only
    # test-cert tool, and matching every other prompt's cancel keyword here beats leaving this loop
    # as the one place in the whole wizard with no way out short of Ctrl+C.
    while ($true) {
        $pw1 = Read-Host "Shared PFX password for EVERY test cert (or 'B' to cancel)" -AsSecureString
        if (([System.Net.NetworkCredential]::new('', $pw1).Password) -match '^(?i)b(ack)?$') { Write-Host "  Cancelled." -ForegroundColor Gray; return }
        $pw2 = Read-Host "Confirm PFX password" -AsSecureString
        if (Test-SecureStringMatch $pw1 $pw2) { $pfxPassword = $pw1; break }
        Write-Host "Passwords did not match - try again." -ForegroundColor Yellow
    }

    # --- for each picked template, prompt for one representative AD username ---------------------
    # 2026-09-15, per the maintainer: "as it cycles through the picked ones we'll need to prompt for
    # username" - one username per SELECTED TEMPLATE (a per-group manual template already names its
    # own group in its DisplayName, so that IS the "type" now - no separate free-typed label needed).
    Write-Host ""
    Write-Host "For each selected template, one representative AD username - each set = one VALID cert" -ForegroundColor Cyan
    Write-Host "+ one REVOKED cert issued from THAT template." -ForegroundColor Cyan
    $types = @()
    foreach ($tmpl in $pickedTemplates) {
        Write-Host ""
        Write-Host ("--- $($tmpl.DisplayName) ---") -ForegroundColor White
        # 2026-09-15, live bug at a client + the maintainer's own follow-up: "if it finds 0, return and have the
        # tech re-do the search" - a 0-match search must NOT be treated the same as the tech
        # deliberately blanking out to skip this template. -ReturnNullOnNoMatch makes
        # Find-VPNCertADUser hand back $null (instead of looping with its own generic reprompt)
        # right after printing "No users matched" - so THIS loop re-shows the real "blank to skip
        # this template" prompt for the SAME template, rather than silently moving on.
        $user = $null
        $cancelled = $false
        while ($true) {
            $seed = Read-Host "  Representative AD username to search for (blank to skip this template, 'B' to cancel this whole run)"
            if ($seed.Trim() -match '^(?i)b(ack)?$') { Write-Host "  Cancelled." -ForegroundColor Gray; $cancelled = $true; break }
            if ([string]::IsNullOrWhiteSpace($seed)) { Write-Host "  Skipped." -ForegroundColor Gray; break }
            $user = Find-VPNCertADUser -SearchTerm $seed -ReturnNullOnNoMatch
            if ($user) { break }
        }
        if ($cancelled) { return }
        if (-not $user) { continue }
        Write-Host ("  -> {0}  ({1})" -f $user.SamAccountName, $user.UserPrincipalName) -ForegroundColor Gray
        $types += [pscustomobject]@{ Label = $tmpl.DisplayName; TemplateName = $tmpl.Cn; User = $user }
    }
    if (-not $types) { Write-Host "Nothing to do." -ForegroundColor Gray; Read-Host "Press Enter" | Out-Null; return }

    # --- PASS 1: submit every request, retrieve nothing yet -----------------------------------
    $results = New-Object System.Collections.Generic.List[object]
    $pending = New-Object System.Collections.Generic.List[object]
    foreach ($t in $types) {
        foreach ($kind in @('valid', 'revoked')) {
            Write-Host ""
            Write-Host ("=== {0} / {1} : submitting request for {2} ===" -f $t.Label, $kind, $t.User.SamAccountName) -ForegroundColor Cyan
            $req = New-VPNCertRequest -ADUser $t.User -TemplateName $t.TemplateName
            $row = [pscustomobject]@{
                Label = $t.Label; Kind = $kind; User = $t.User.SamAccountName
                Request = $req; Status = $(if ($req) { 'Submitted' } else { 'RequestFailed' })
                PfxPath = $null; CerPath = $null; Thumbprint = $null; SerialNumber = $null; Revoked = $false
            }
            $results.Add($row)
            if ($req) { $pending.Add($row) }
        }
    }

    # --- ONE approval pass --------------------------------------------------------------------
    if ($pending.Count) {
        Write-Host ""
        Write-Host "==================== APPROVE ALL OF THESE ====================" -ForegroundColor Yellow
        Write-Host ("  {0,-24} {1,-8} {2,-22} {3}" -f 'Template', 'Kind', 'User', 'Requested subject') -ForegroundColor Gray
        foreach ($r in $pending) {
            Write-Host ("  {0,-24} {1,-8} {2,-22} {3}" -f $r.Label, $r.Kind, $r.User, $r.Request.Request.Subject) -ForegroundColor Gray
        }
        Write-Host ""
        Write-Host "  certsrv.msc -> Pending Requests -> select all -> right-click -> All Tasks -> Issue" -ForegroundColor Yellow
        Read-Host "  Press Enter once ALL $($pending.Count) request(s) are issued" | Out-Null
    }

    # --- PASS 2: retrieve + export, then revoke the 'revoked' set, then ONE CRL republish -----
    $anyRevoked = $false
    foreach ($row in $pending) {
        $stem = "{0}_{1}_{2}" -f ($row.User -replace '[^A-Za-z0-9]', ''), ($row.Label -replace '[^A-Za-z0-9]', ''), $row.Kind
        $res = Complete-VPNCertRequest -RequestObject $row.Request -OutputDir $outDir -PfxPassword $pfxPassword -FileNameStem $stem
        $row.Status       = $res.Status
        $row.PfxPath      = $res.PfxPath
        $row.CerPath      = $res.CerPath
        $row.Thumbprint   = $res.Thumbprint
        $row.SerialNumber = $res.SerialNumber

        if ($row.Kind -eq 'revoked' -and $res.SerialNumber) {
            Write-Host ("Revoking serial {0} (reason 0 / unspecified)..." -f $res.SerialNumber) -ForegroundColor Yellow
            $rev = Revoke-VPNCert -SerialNumber $res.SerialNumber -ReasonCode 0
            $row.Revoked = [bool]$rev.Revoked
            if ($rev.Revoked) { $anyRevoked = $true }
            else { Write-Host "  (revoke did not confirm - see summary)" -ForegroundColor Yellow }
        }
    }
    if ($anyRevoked) {
        Write-Host "Republishing the CRL once for the whole revoked set..." -ForegroundColor Yellow
        & certutil.exe -crl 2>&1 | Out-String | Write-Verbose
        if ($LASTEXITCODE -ne 0) { Write-Host "  certutil -crl reported exit $LASTEXITCODE - republish the CRL by hand." -ForegroundColor Yellow }
    }
    # drop the transient Request handle before the summary
    foreach ($r in $results) { $r.PSObject.Properties.Remove('Request') }

    # --- summary file ---
    $company = if ($CAAnswers -and -not [string]::IsNullOrWhiteSpace($CAAnswers.Company_Name)) { $CAAnswers.Company_Name }
               elseif ($Status.CACommonName) { $Status.CACommonName } else { 'CA' }
    $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $summaryPath = Join-Path $outDir ("{0}_CertTestSuite_{1}.txt" -f ($company -replace '[^A-Za-z0-9]', ''), $stamp)

    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add("Certificate test suite - $company")
    $lines.Add("Generated: $(Get-Date)")
    $lines.Add("Templates: " + (($pickedTemplates | ForEach-Object { $_.DisplayName }) -join ', '))
    $lines.Add("Output   : $outDir   (all PFX files share the one password you entered)")
    $lines.Add("")
    $lines.Add(("{0,-24} {1,-8} {2,-22} {3,-9} {4,-8} {5}" -f 'Template', 'Kind', 'User', 'Status', 'Revoked', 'PFX'))
    $lines.Add(("-" * 110))
    foreach ($r in $results) {
        $lines.Add(("{0,-24} {1,-8} {2,-22} {3,-9} {4,-8} {5}" -f $r.Label, $r.Kind, $r.User, $r.Status, $r.Revoked, $(if ($r.PfxPath) { $r.PfxPath } else { '(not exported)' })))
        if ($r.SerialNumber) { $lines.Add(("{0,-24} {1,-8} serial {2}   thumbprint {3}" -f '', '', $r.SerialNumber, $r.Thumbprint)) }
        # 2026-09-15, per the maintainer: "why didn't I have you do it during generation time" - the public
        # .cer (no private key) is exported right alongside the PFX now (Complete-VPNCertRequest),
        # not as a separate later step. Listed here so the summary is the one place that names both.
        if ($r.CerPath) { $lines.Add(("{0,-24} {1,-8} cer {2}" -f '', '', $r.CerPath)) }
    }
    $lines.Add("")
    $lines.Add("=== FortiGate: after revoking, a revoked cert may still pass until the CRL/OCSP cache turns over ===")
    $lines.Add("  execute vpn certificate crl update <crl-name>     # force a fresh CRL download now")
    $lines.Add("  diagnose vpn ike gateway flush                    # drop cached IKE SAs (clients must reconnect)")
    $lines.Add("  # OCSP has its own cache - check 'config vpn certificate ocsp-server' timeout, or bounce the IKE daemon.")
    $lines.Add("Verify: reconnect with the REVOKED PFX - phase 1 should now fail with a certificate-revoked error.")
    Set-Content -Path $summaryPath -Value $lines -Encoding UTF8

    Write-Host ""
    Write-Host "Summary written: $summaryPath" -ForegroundColor Green
    $issued = @($results | Where-Object { $_.Status -eq 'Issued' }).Count
    $failed = @($results | Where-Object { $_.Status -notin @('Issued') }).Count
    $color  = if ($issued -eq $results.Count) { 'Green' } elseif ($issued) { 'Yellow' } else { 'Red' }
    Write-Host ("Issued {0} / {1} requested across {2} template(s){3}." -f $issued, $results.Count, $types.Count,
        $(if ($failed) { " - $failed failed, see the table above" })) -ForegroundColor $color
    Read-Host "Press Enter to return to the menu" | Out-Null
}
