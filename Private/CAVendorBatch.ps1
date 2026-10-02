<#
.SYNOPSIS
    CA Manager - Rollout: batch-request vendor certificates (menu 17). Requires Modules\CACore.ps1,
    Modules\CATemplates.ps1 (Get-CAManualApprovalTemplates), Modules\CAInteractive.ps1
    (Test-SecureStringMatch), and Request-VPNCertCore.ps1 - dot-sourced by Modules\CATestSuite.ps1,
    which CA-Manager.ps1 loads first.

.DESCRIPTION
    2026-09-30, per the maintainer: vendor rollout - a tech (Luke) issues a PFX per vendor account in one
    sitting, the same submit -> one approval pass -> retrieve/export shape as the test-certificate
    suite (menu 11). Asked ONCE per run: the output folder and a run password (confirmed). Then, per
    certificate: the template (numbered list, blank keeps the last one used this run), the AD user,
    and the PFX password (Enter re-uses the run password, N sets one just for this PFX). Each request
    is submitted as soon as it's entered, so a failure shows next to the vendor it belongs to.

    Nothing is remembered between runs (per the maintainer) - not the folder, template, or passwords. A
    summary file in the output folder lists every PFX and which password it got (run or its own),
    never the passwords themselves.
#>

function Read-CAVendorTemplateChoice {
    <#
    .SYNOPSIS
        One template prompt. Lists -Templates numbered (the current one marked) and returns the
        chosen template object, 'Done', or 'Cancel'. Blank keeps -Current; a number picks another.
        'D' (done) is offered only once -CanFinish; 'B' (cancel) only while -CanCancel.
    #>
    param(
        [Parameter(Mandatory)][object[]]$Templates,
        $Current,
        [switch]$CanFinish,
        [switch]$CanCancel
    )
    while ($true) {
        Write-Host ""
        Write-Host "  Manual-approval templates published on this CA:" -ForegroundColor Cyan
        for ($i = 0; $i -lt $Templates.Count; $i++) {
            $mark = if ($Current -and $Templates[$i].Cn -eq $Current.Cn) { '  (current)' } else { '' }
            Write-Host ("    [{0}] {1}{2}" -f ($i + 1), $Templates[$i].DisplayName, $mark) -ForegroundColor Gray
        }
        $options = @()
        if ($Current) { $options += "blank to keep '$($Current.DisplayName)'" }
        $options += "1-$($Templates.Count) to select$(if ($Current) { ' another' })"
        if ($CanFinish) { $options += "D when done" }
        if ($CanCancel) { $options += "B to cancel" }
        $answer = ([string](Read-Host "  Template ($($options -join ', '))")).Trim()

        if (-not $answer -and $Current) { return $Current }
        if ($CanFinish -and $answer -match '^(?i)d(one)?$') { return 'Done' }
        if ($CanCancel -and $answer -match '^(?i)b(ack)?$') { return 'Cancel' }
        $n = 0
        if ([int]::TryParse($answer, [ref]$n) -and $n -ge 1 -and $n -le $Templates.Count) { return $Templates[$n - 1] }
        Write-Host "  Enter one of: $($options -join '; ')." -ForegroundColor Yellow
    }
}

function Read-CAVendorPfxPassword {
    <#
    .SYNOPSIS
        The per-PFX password step: Enter re-uses -RunPassword (the one set at the start of the run),
        N types a new one (confirmed) for this PFX only. Returns @{ Password; Own }.
    #>
    param([Parameter(Mandatory)][securestring]$RunPassword)
    while ($true) {
        $answer = ([string](Read-Host "  PFX password: [Enter] re-use the password set at the beginning of the run, or N for a new one for this PFX")).Trim()
        if (-not $answer) { return [pscustomobject]@{ Password = $RunPassword; Own = $false } }
        if ($answer -match '^(?i)n(ew)?$') {
            while ($true) {
                $pw1 = Read-Host "  New password for this PFX only" -AsSecureString
                $pw2 = Read-Host "  Confirm it" -AsSecureString
                if (Test-SecureStringMatch $pw1 $pw2) { return [pscustomobject]@{ Password = $pw1; Own = $true } }
                Write-Host "  Passwords did not match - try again." -ForegroundColor Yellow
            }
        }
        Write-Host "  Press Enter to re-use the run password, or N for a new one." -ForegroundColor Yellow
    }
}

function Invoke-CAMenuVendorBatch {
    <#
    .SYNOPSIS
        Menu 17. Batch-request vendor certificates: template / user / password per PFX, one output
        folder and run password for the whole batch, one approval pass, then retrieve + export.
    .PARAMETER Status
        The Get-CAStatus object (for the issuance-readiness gate).
    .PARAMETER CAAnswers
        Optional; only Company_Name is read (summary file name).
    #>
    param(
        [Parameter(Mandatory)]$Status,
        $CAAnswers
    )

    Write-CAHeader "Batch-request vendor certificates"

    if (-not (Get-Command New-VPNCertRequest -ErrorAction SilentlyContinue)) {
        Write-Host "Request-VPNCertCore.ps1 was not found - cannot issue certs." -ForegroundColor Red
        Write-Host "(Expected next to CA-Manager.ps1 in a built CAManager.zip, or under" -ForegroundColor Gray
        Write-Host " IPSEC AIO\MiscTools\Tools\ when running from the repo.)" -ForegroundColor Gray
        Read-Host "Press Enter to return to the menu" | Out-Null
        return
    }

    # --- order gate: same as menu 11 - issued certs bake in whatever revocation URLs are live now ---
    if (-not $Status.IssuanceReady) {
        Write-Host "Issuance readiness is NOT READY." -ForegroundColor Yellow
        Write-Host "Any certificate issued now bakes in whatever AIA / CDP / OCSP URLs the CA currently" -ForegroundColor Yellow
        Write-Host "has - which won't be the App Proxy URLs yet, so vendor certs may fail revocation" -ForegroundColor Yellow
        Write-Host "checks later. Finish Setup (8, 9) first unless you know why not." -ForegroundColor Yellow
        Write-Host ""
        $ack = Read-Host "Type YES (all caps) to issue vendor certs anyway, anything else to cancel"
        if ($ack -cne 'YES') { Write-Host "Cancelled." -ForegroundColor Gray; Read-Host "Press Enter" | Out-Null; return }
    }

    $templates = @(Get-CAManualApprovalTemplates)
    if (-not $templates.Count) {
        Write-Host "No published templates with 'Manual approval' (PEND_ALL_REQUESTS) found on this CA." -ForegroundColor Yellow
        Write-Host "Run menu 4 (or 16) first to create/publish a manual template." -ForegroundColor Yellow
        Read-Host "Press Enter to return to the menu" | Out-Null
        return
    }

    Write-Host "Asked once for the whole run: where the PFX files go, and a password they share." -ForegroundColor Cyan
    Write-Host "Then, per vendor: template, AD user, and whether that PFX uses the run password." -ForegroundColor Cyan
    Write-Host ""

    # --- output folder (once) ---
    $outDir = ([string](Read-Host "Output folder for every PFX in this run [C:\Admin\VendorPFX], or 'B' to cancel")).Trim().Trim('"')
    if ($outDir -match '^(?i)b(ack)?$') { Write-Host "  Cancelled." -ForegroundColor Gray; return }
    if (-not $outDir) { $outDir = 'C:\Admin\VendorPFX' }
    if (-not (Test-Path $outDir)) { New-Item -ItemType Directory -Path $outDir -Force | Out-Null }

    # --- run password (once, confirmed) - 'B' at the first prompt cancels, same as menu 11 ---
    while ($true) {
        $pw1 = Read-Host "Password for this run's PFX files (or 'B' to cancel)" -AsSecureString
        if (([System.Net.NetworkCredential]::new('', $pw1).Password) -match '^(?i)b(ack)?$') { Write-Host "  Cancelled." -ForegroundColor Gray; return }
        $pw2 = Read-Host "Confirm it" -AsSecureString
        if (Test-SecureStringMatch $pw1 $pw2) { $runPassword = $pw1; break }
        Write-Host "Passwords did not match - try again." -ForegroundColor Yellow
    }

    # --- per vendor: template -> user -> password -> submit ------------------------------------------
    $batch = New-Object System.Collections.Generic.List[object]
    $currentTemplate = $null
    while ($true) {
        Write-Host ""
        Write-Host ("=== Certificate #{0} ===" -f ($batch.Count + 1)) -ForegroundColor White
        # Cancel only while nothing is submitted yet: after that, requests are already pending on the
        # CA and the tech needs the approval pass below, so 'D' (done) is the way out.
        $pick = Read-CAVendorTemplateChoice -Templates $templates -Current $currentTemplate -CanFinish:($batch.Count -gt 0) -CanCancel:($batch.Count -eq 0)
        if ($pick -eq 'Cancel') { Write-Host "  Cancelled - nothing was requested." -ForegroundColor Gray; return }
        if ($pick -eq 'Done') { break }
        $currentTemplate = $pick

        $user = $null
        while ($true) {
            $seed = ([string](Read-Host "  Vendor's AD username to search for (blank to go back to the template)")).Trim()
            if (-not $seed) { break }
            $user = Find-VPNCertADUser -SearchTerm $seed -ReturnNullOnNoMatch
            if ($user) { break }
        }
        if (-not $user) { continue }
        Write-Host ("  -> {0}  ({1})" -f $user.SamAccountName, $user.UserPrincipalName) -ForegroundColor Gray

        $pfxPassword = Read-CAVendorPfxPassword -RunPassword $runPassword

        Write-Host ("  Submitting {0} for {1}..." -f $currentTemplate.DisplayName, $user.SamAccountName) -ForegroundColor Cyan
        $request = New-VPNCertRequest -ADUser $user -TemplateName $currentTemplate.Cn
        if (-not $request) {
            Write-Host "  Request failed (see above) - not added to the batch. Pick the template again to retry." -ForegroundColor Yellow
            continue
        }
        $batch.Add([pscustomobject]@{
            Template = $currentTemplate.DisplayName; TemplateCn = $currentTemplate.Cn; User = $user.SamAccountName
            Subject = $request.Request.Subject; Request = $request; Password = $pfxPassword.Password; OwnPassword = $pfxPassword.Own
            Status = 'Submitted'; PfxPath = $null; CerPath = $null; Thumbprint = $null; SerialNumber = $null
        })
        Write-Host ("  Added. {0} request(s) in this batch." -f $batch.Count) -ForegroundColor Green
    }

    # --- one approval pass, then retrieve + export; unissued ones can be retried -------------------
    $stems = @{}
    foreach ($row in $batch) {
        $stem = "{0}_{1}_{2}" -f ($row.User -replace '[^A-Za-z0-9]', ''), ($row.TemplateCn -replace '[^A-Za-z0-9]', ''), (Get-Date -Format 'yyyyMMdd')
        # The same vendor twice on one template in one run would otherwise overwrite the first PFX.
        $n = 1; $unique = $stem
        while ($stems.ContainsKey($unique)) { $n++; $unique = "${stem}_$n" }
        $stems[$unique] = $true
        $row | Add-Member -NotePropertyName Stem -NotePropertyValue $unique
    }
    # .ToArray(), not @($batch): wrapping a generic List in @() throws "Argument types do not match" on PS 5.1.
    $waiting = $batch.ToArray()
    $firstPass = $true
    while ($waiting.Count) {
        Write-Host ""
        if ($firstPass) {
            Write-Host "==================== APPROVE ALL OF THESE ====================" -ForegroundColor Yellow
        } else {
            Write-Host "==================== STILL NOT ISSUED ====================" -ForegroundColor Yellow
        }
        Write-Host ("  {0,-32} {1,-22} {2}" -f 'Template', 'User', 'Requested subject') -ForegroundColor Gray
        foreach ($r in $waiting) { Write-Host ("  {0,-32} {1,-22} {2}" -f $r.Template, $r.User, $r.Subject) -ForegroundColor Gray }
        Write-Host ""
        Write-Host "  certsrv.msc -> Pending Requests -> select all -> right-click -> All Tasks -> Issue" -ForegroundColor Yellow
        if ($firstPass) {
            Read-Host "  Press Enter once ALL $($waiting.Count) request(s) are issued" | Out-Null
        } else {
            # One prompt per retry round: it is both "they're approved now" and the way out.
            $again = ([string](Read-Host "  Press Enter once they're issued to retry, or S to skip them")).Trim()
            if ($again -match '^(?i)s(kip)?$') { break }
        }
        $firstPass = $false

        foreach ($row in $waiting) {
            $res = Complete-VPNCertRequest -RequestObject $row.Request -OutputDir $outDir -PfxPassword $row.Password -FileNameStem $row.Stem
            $row.Status = $res.Status; $row.PfxPath = $res.PfxPath; $row.CerPath = $res.CerPath
            $row.Thumbprint = $res.Thumbprint; $row.SerialNumber = $res.SerialNumber
        }
        # Only still-pending requests come back round; a failed retrieval or export is final (summary).
        $waiting = @($batch.ToArray() | Where-Object { -not $_.PfxPath -and $_.Status -in @('Pending', 'Submitted') })
    }

    # --- summary file (no passwords - only which one each PFX got) --------------------------------
    $company = if ($CAAnswers -and $CAAnswers.PSObject.Properties['Company_Name'] -and -not [string]::IsNullOrWhiteSpace($CAAnswers.Company_Name)) { $CAAnswers.Company_Name }
               elseif ($Status.CACommonName) { $Status.CACommonName } else { 'CA' }
    $summaryPath = Join-Path $outDir ("{0}_VendorCerts_{1}.txt" -f ($company -replace '[^A-Za-z0-9]', ''), (Get-Date -Format 'yyyyMMdd_HHmmss'))
    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add("Vendor certificates - $company")
    $lines.Add("Generated: $(Get-Date)")
    $lines.Add("Output   : $outDir")
    $lines.Add("Password : 'run' = the password set at the start of this run; 'own' = set for that PFX alone.")
    $lines.Add("")
    $lines.Add(("{0,-32} {1,-22} {2,-9} {3,-8} {4}" -f 'Template', 'User', 'Status', 'Password', 'PFX'))
    $lines.Add(("-" * 110))
    foreach ($r in $batch) {
        $lines.Add(("{0,-32} {1,-22} {2,-9} {3,-8} {4}" -f $r.Template, $r.User, $r.Status, $(if ($r.OwnPassword) { 'own' } else { 'run' }), $(if ($r.PfxPath) { $r.PfxPath } else { '(not exported)' })))
        if ($r.SerialNumber) { $lines.Add(("{0,-32} {1,-22} serial {2}   thumbprint {3}" -f '', '', $r.SerialNumber, $r.Thumbprint)) }
        if ($r.CerPath) { $lines.Add(("{0,-32} {1,-22} cer {2}" -f '', '', $r.CerPath)) }
    }
    Set-Content -Path $summaryPath -Value $lines -Encoding UTF8

    Write-Host ""
    Write-Host "Summary written: $summaryPath" -ForegroundColor Green
    $issued = @($batch | Where-Object { $_.PfxPath }).Count
    $color = if ($issued -eq $batch.Count) { 'Green' } elseif ($issued) { 'Yellow' } else { 'Red' }
    Write-Host ("Exported {0} / {1} vendor PFX file(s) to {2}." -f $issued, $batch.Count, $outDir) -ForegroundColor $color
    Read-Host "Press Enter to return to the menu" | Out-Null
}
