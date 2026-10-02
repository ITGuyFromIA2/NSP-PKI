function Start-NSPPkiManager {
    <#
    .SYNOPSIS
        The PKI Manager dashboard (formerly CA-Manager): install the CA, TameMyCerts, certificate
        templates and permissions, App Proxy publishing of AIA/CDP/OCSP, OCSP, health checks, test
        and vendor certificates, the enrollment gate, and the hand-back to the Orchestrator.

    .DESCRIPTION
        Moved from the zip-era CA-Manager.ps1; the menus are unchanged and start in DRY RUN (D
        switches to APPLY). Relaunches elevated if needed. Answers live in the PKI work folder
        (Get-NSPToolWorkPath -Tool PKI): a launcher's -SeedAnswersJson is merged there, and a
        -CAConfigName given here is saved there for later starts (the zip-era launcher's
        $CAServerName). The first start on a server offers to move the zip-era CA-Manager's files
        into the work folder.

    .PARAMETER SeedAnswersJson
        Answers to merge in (plain JSON - see ConvertTo-NSPPkiAnswers - or a PKI Answers hand-off).

    .PARAMETER SeedOnly
        Merge -SeedAnswersJson and return without opening the dashboard.

    .PARAMETER CAConfigName
        The CA configuration to target. Saved for later starts; blank uses the saved one, then the
        answers' CA_CommonName, then the local CA.

    .PARAMETER NoElevate
        Do not relaunch elevated.

    .EXAMPLE
        Start-NSPPkiManager

    .EXAMPLE
        Start-NSPPkiManager -CAConfigName 'EXAMPLE-ISSUING-CA'
    #>
    [CmdletBinding()]
    param(
        [string]$SeedAnswersJson,
        [switch]$SeedOnly,
        [string]$CAConfigName,
        [switch]$NoElevate
    )

    Use-NSPPkiDependency

    if ($SeedOnly) {
        $null = Import-NSPToolSeedAnswers -Tool PKI -SeedAnswersJson $SeedAnswersJson
        return
    }

    $manifestPath = Join-Path $script:ModuleRoot 'NSP.PKI.psd1'
    if (-not $NoElevate) {
        $relaunch = "Import-Module '$($manifestPath.Replace("'", "''"))'; Start-NSPPkiManager"
        if ($PSBoundParameters.ContainsKey('CAConfigName')) { $relaunch += " -CAConfigName '$($CAConfigName.Replace("'", "''"))'" }
        if (Invoke-NSPElevated -Command $relaunch -NoExit) { return }
    }

    $null = Import-NSPToolSeedAnswers -Tool PKI -SeedAnswersJson $SeedAnswersJson

    # First start on this server: offer to bring over what the zip-era CA-Manager left behind.
    $marker = Join-Path (Get-NSPToolWorkPath -Tool PKI -Create) '.legacy-checked'
    if (-not (Test-Path -LiteralPath $marker)) {
        try {
            $summary = Move-NSPToolLegacyData -Tool PKI
            if ($summary.Found) { Read-Host "`nPress Enter to continue" | Out-Null }
        } catch { Write-Warning "Old CA-Manager files could not be checked: $($_.Exception.Message)" }
        Set-Content -LiteralPath $marker -Value (Get-Date -Format 's')
    }

    $answersFile = Join-Path (Get-NSPToolWorkPath -Tool PKI -Kind Answers -Create) 'Answers.json'
    if ($PSBoundParameters.ContainsKey('CAConfigName') -and -not [string]::IsNullOrWhiteSpace($CAConfigName)) {
        Set-PKIToolAnswerField -Path $answersFile -Field 'PKICAConfigName' -Value $CAConfigName
    }

    $script:CAManagerVersion = Get-NSPPkiModuleVersion
    $script:CAManagerVersionLabel = (Get-NSPToolVersionStatus -ToolKey 'NSP.PKI' -Version $script:CAManagerVersion).Label

    # ----- zip-era CA-Manager.ps1 startup block (CAAnswers.json -> the work folder's Answers.json) -----
    Repair-CAModulePath
    Set-ConsoleFullScreen
    Set-CADryRun -Enabled $true

    $script:CAAnswers = Repair-PKIAnswerField -CAAnswers (Get-NSPToolAnswers -Tool PKI)
    $expectedTemplates = Get-PKIExpectedTemplate -CAAnswers $script:CAAnswers
    if (-not $PSBoundParameters.ContainsKey('CAConfigName') -and $script:CAAnswers) {
        if ($script:CAAnswers.PSObject.Properties['PKICAConfigName'] -and -not [string]::IsNullOrWhiteSpace($script:CAAnswers.PKICAConfigName)) {
            $CAConfigName = [string]$script:CAAnswers.PKICAConfigName
        } elseif (-not [string]::IsNullOrWhiteSpace($script:CAAnswers.CA_CommonName)) {
            $CAConfigName = $script:CAAnswers.CA_CommonName
        }
    }

    # ----- zip-era CA-Manager.ps1 main menu loop (R/U relaunch the module; 'exit 0' -> 'return') -----
    :MainMenu while ($true) {
        Write-CAHeader "PKI Manager Dashboard  $script:CAManagerVersionLabel"

        $status = Get-CAStatus -CAConfigName $CAConfigName -ExpectedTemplates $expectedTemplates
        Show-CAStatus -Status $status

        if (Get-CADryRun) {
            Write-Host "  MODE: DRY RUN - actions print what they would do and change nothing. Press D to switch to APPLY." -ForegroundColor Cyan
        } else {
            Write-Host "  MODE: APPLY - actions will make real changes. Press D to switch back to DRY RUN." -ForegroundColor Red
        }
        Write-Host ""

        Write-Host "  --- Setup ---" -ForegroundColor DarkCyan
        Write-Host "  1. " -NoNewline -ForegroundColor Yellow; Write-Host " Install RSAT / management modules"
        Write-Host "  2. " -NoNewline -ForegroundColor Yellow; Write-Host " Install / configure the CA"
        Write-Host "  3. " -NoNewline -ForegroundColor Yellow; Write-Host " Subject-stamp policy module (TameMyCerts)"
        Write-Host "  4. " -NoNewline -ForegroundColor Yellow; Write-Host " Create / update certificate templates"
        Write-Host "  5. " -NoNewline -ForegroundColor Yellow; Write-Host " Set template permissions (umbrella group)"
        Write-Host "  6. " -NoNewline -ForegroundColor Yellow; Write-Host " App Proxy connector + Entra apps"
        Write-Host "  7. " -NoNewline -ForegroundColor Yellow; Write-Host " CRL distribution share + AD groups"
        Write-Host "  8. " -NoNewline -ForegroundColor Yellow; Write-Host " Route AIA / CDP / OCSP through the App Proxy"
        Write-Host "  9. " -NoNewline -ForegroundColor Yellow; Write-Host " Install / configure OCSP (Online Responder)"
        Write-Host ""
        Write-Host "  --- Toolkit ---" -ForegroundColor DarkCyan
        Write-Host "  10." -NoNewline -ForegroundColor Yellow; Write-Host " Health check"
        Write-Host "  11." -NoNewline -ForegroundColor Yellow; Write-Host " Generate a test-certificate suite"
        Write-Host "  12." -NoNewline -ForegroundColor Yellow; Write-Host " TameMyCerts renewal-idempotency test (PoC)"
        Write-Host "  13." -NoNewline -ForegroundColor Yellow; Write-Host " Hand back to the Orchestrator (CA data + FortiGate cert)"
        Write-Host "  14." -NoNewline -ForegroundColor Yellow; Write-Host " Re-run the full read-only inventory"
        Write-Host "  15." -NoNewline -ForegroundColor Yellow; Write-Host " The enrollment gate (AutoEnroll on/off, per group)"
        Write-Host "  16." -NoNewline -ForegroundColor Yellow; Write-Host " Add a new template ad-hoc"
        Write-Host ""
        Write-Host "  --- Rollout ---" -ForegroundColor DarkCyan
        Write-Host "  17." -NoNewline -ForegroundColor Yellow; Write-Host " Batch-request vendor certificates (PFX)"
        Write-Host ""
        Write-Host "  D. " -NoNewline -ForegroundColor Yellow; Write-Host " Toggle DRY RUN / APPLY mode"
        Write-Host "  R. " -NoNewline -ForegroundColor Yellow; Write-Host " Relaunch PKI Manager (e.g. after installing new modules in menu 1)"
        Write-Host "  U. " -NoNewline -ForegroundColor Yellow; Write-Host " Update NSP.PKI from the PowerShell Gallery"
        Write-Host "  ?. " -NoNewline -ForegroundColor Yellow; Write-Host " Why this order? (ordering rationale + the enrollment gate)"
        Write-Host "  Q. " -NoNewline -ForegroundColor Yellow; Write-Host " Quit"
        Write-Host ""
        if (-not (Test-CAHelpAcknowledged -CAAnswers $script:CAAnswers)) {
            Show-CAMenuHelp
            $script:CAAnswers = Set-CAHelpAcknowledged -CAAnswers $script:CAAnswers -Path $answersFile
            continue
        }
        $choice = Read-Host "Select an option"

        try {
            switch -Regex ($choice) {
                '^1$' { Invoke-CAMenuPrereqs -ScriptPath $manifestPath -CAConfigName $CAConfigName }
                '^2$' { Invoke-CAMenuInstall   -CAAnswers $script:CAAnswers }
                '^3$' { Invoke-CATameMyCertsMenu -CAAnswers $script:CAAnswers -Status $status }
                '^4$' { Invoke-CAMenuTemplates -CAAnswers $script:CAAnswers }
                '^5$' { Invoke-CAMenuUmbrella  -CAAnswers $script:CAAnswers }
                '^6$' { Invoke-CAMenuAppProxy -CAAnswers $script:CAAnswers -Status $status }
                '^7$' { Invoke-CAMenuCrlShare -CAAnswers $script:CAAnswers -Status $status }
                '^8$' { Invoke-CAMenuUrls      -CAAnswers $script:CAAnswers -Status $status }
                '^9$' { Invoke-CAMenuOcsp -CAAnswers $script:CAAnswers -Status $status }
                '^10$' { Invoke-CAMenuHealth -CAAnswers $script:CAAnswers -Status $status }
                '^11$' { New-CATestCertSuite -Status $status -CAAnswers $script:CAAnswers }
                '^12$' { Invoke-CAMenuRenewalTest -CAAnswers $script:CAAnswers -Status $status }
                '^13$' { Invoke-CAMenuHandoff -CAAnswers $script:CAAnswers -Status $status -CAManagerVersion $script:CAManagerVersion }
                '^15$' { Invoke-CAMenuAutoEnrollGate -CAAnswers $script:CAAnswers -Status $status }
                '^16$' { Invoke-CAMenuAdHocTemplate -CAAnswers $script:CAAnswers }
                '^17$' { Invoke-CAMenuVendorBatch -Status $status -CAAnswers $script:CAAnswers }
                '^\?$' { Show-CAMenuHelp }
                '^[Rr]$' {
                    if (Read-CAConfirm -Prompt "Relaunch PKI Manager now?" -DefaultYes) {
                        Invoke-CAManagerRelaunch -ScriptPath $manifestPath -CAConfigName $CAConfigName
                    }
                }
                '^[Uu]$' { Invoke-PKIModuleUpdate -CAConfigName $CAConfigName }
                '^[Dd]$' {
                    if (Get-CADryRun) {
                        Write-Host "`nSwitching to APPLY mode - actions will make real changes." -ForegroundColor Red
                        if ((Read-Host "Type APPLY to confirm") -ceq 'APPLY') { Set-CADryRun -Enabled $false }
                        else { Write-Host "Kept DRY RUN." -ForegroundColor Gray }
                    } else {
                        Set-CADryRun -Enabled $true
                        Write-Host "`nBack to DRY RUN." -ForegroundColor Cyan
                    }
                    Start-Sleep -Seconds 1
                }
                '^14$' { & (Join-Path $script:ModuleRoot 'Scripts\Get-CAManagerInventory.ps1') }
                '^[Qq]$' { Write-Host "Goodbye." -ForegroundColor Gray; return }
                default  { Write-Host "Invalid selection." -ForegroundColor Yellow }
            }
            # Centralized save after every menu item (DRY-RUN-aware; no-op on $null answers).
            Save-CAAnswers -Path $answersFile -Answers $script:CAAnswers
        } catch [System.OperationCanceledException] {
            if ($_.Exception.Message -eq 'NSP.PKI:Relaunched') { return }
            throw
        } catch {
            Write-Host "`nUNEXPECTED ERROR: $($_.Exception.Message)" -ForegroundColor Red
            Write-Host $_.ScriptStackTrace -ForegroundColor DarkGray
            Read-Host "Press Enter to return to the menu" | Out-Null
        }
    }
}
