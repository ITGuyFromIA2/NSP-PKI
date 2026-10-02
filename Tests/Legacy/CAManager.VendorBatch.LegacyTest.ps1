# Ported from NSP-FGTIPSecTools Tests\CAManager.VendorBatch.Tests.ps1 (2026-10-01): same assertions, paths re-pointed at
# this module's Private\ files. Run by Tests\Legacy.Tests.ps1 (Pester) in a child PowerShell.
<#
.SYNOPSIS
    Tests for CA Manager menu 17 (2026-09-30) - Modules\CAVendorBatch.ps1's Invoke-CAMenuVendorBatch:
    batch-request vendor certificates. Output folder + run password asked once; per certificate the
    template (blank keeps the last used this run), AD user, and PFX password (Enter re-uses the run
    password, N sets its own); one approval pass; retry of unissued requests; a summary that never
    holds a password; nothing remembered between runs.

    Repo convention (Tests\README.md / TestAssertions.ps1) - NOT Pester. AST-extract the functions,
    Invoke-Expression them, mock deps by defining same-named functions afterwards.
#>

. "$PSScriptRoot\..\Shared\TestAssertions.ps1"
$PKIModuleRoot = (Resolve-Path "$PSScriptRoot\..\..").Path
Reset-TestCounters

$Repo        = "C:\GitRepo\NSP-FGTIPSecTools"
$VendorBatch = Join-Path $PKIModuleRoot "Private\CAVendorBatch.ps1"
$Interactive = Join-Path $PKIModuleRoot "Private\CAInteractive.ps1"
$Dashboard   = Join-Path $PKIModuleRoot "Tests\Legacy\_CA-Manager.combined.ps1"

Test-ScriptParses -Path $VendorBatch -Because "CAVendorBatch.ps1 parses cleanly"
Test-ScriptParses -Path $Dashboard   -Because "CA-Manager.ps1 parses cleanly after wiring menu 17"

foreach ($fn in 'Read-CAVendorTemplateChoice', 'Read-CAVendorPfxPassword', 'Invoke-CAMenuVendorBatch') {
    Invoke-Expression (Get-FunctionSource -Path $VendorBatch -FunctionName $fn)
}
Invoke-Expression (Get-FunctionSource -Path $Interactive -FunctionName 'Test-SecureStringMatch')

# --- mocks --------------------------------------------------------------------------------------
function Write-CAHeader { param($Title) }
function Test-Path { param($Path) $true }
function New-Item { }
function Get-CAManualApprovalTemplates {
    @(
        [pscustomobject]@{ Cn = 'NSPIKEv2VendorsMANUAL';  DisplayName = 'NSP-IKEv2-Vendors-MANUAL' }
        [pscustomobject]@{ Cn = 'NSPIKEv2PartnerMANUAL'; DisplayName = 'NSP-IKEv2-Partner-MANUAL' }
    )
}
function Find-VPNCertADUser { param($SearchTerm, [switch]$ReturnNullOnNoMatch) if ($SearchTerm -eq 'nobody') { return $null } [pscustomobject]@{ SamAccountName = "v_$SearchTerm"; UserPrincipalName = "v_$SearchTerm@corp"; DistinguishedName = "CN=$SearchTerm" } }
$script:requests = New-Object System.Collections.Generic.List[string]
function New-VPNCertRequest { param($ADUser, $TemplateName) $script:requests.Add("$($ADUser.SamAccountName)|$TemplateName"); [pscustomobject]@{ Request = [pscustomobject]@{ Subject = "CN=$($ADUser.SamAccountName)" } } }
# Records the PLAINTEXT password each PFX was exported with; a stem listed in $script:pendingOnce comes
# back 'Pending' the first time (not yet approved), 'Issued' after.
$script:exports = New-Object System.Collections.Generic.List[string]
$script:pendingOnce = @{}
function Complete-VPNCertRequest {
    param($RequestObject, $OutputDir, $PfxPassword, $FileNameStem)
    if ($script:pendingOnce.ContainsKey($FileNameStem) -and $script:pendingOnce[$FileNameStem]) {
        $script:pendingOnce[$FileNameStem] = $false
        return [pscustomobject]@{ Status = 'Pending'; Thumbprint = $null; SerialNumber = $null; PfxPath = $null; CerPath = $null }
    }
    $script:exports.Add("$FileNameStem|$([System.Net.NetworkCredential]::new('', $PfxPassword).Password)")
    [pscustomobject]@{ Status = 'Issued'; Thumbprint = "TB"; SerialNumber = "SER"; PfxPath = (Join-Path $OutputDir "$FileNameStem.pfx"); CerPath = (Join-Path $OutputDir "$FileNameStem.cer") }
}
$script:summary = $null
function Set-Content { param($Path, $Value, $Encoding) $script:summary = [pscustomobject]@{ Path = $Path; Value = ($Value -join "`n") } }
# Queue-fed Read-Host; -AsSecureString answers come back as real SecureStrings, like the real prompt.
$script:rh = [System.Collections.Generic.Queue[string]]::new()
function Read-Host {
    param([string]$Prompt, [switch]$AsSecureString)
    if ($script:rh.Count -eq 0) { throw "Read-Host queue empty (prompt: '$Prompt')" }
    $v = $script:rh.Dequeue()
    if ($AsSecureString) { $s = New-Object System.Security.SecureString; foreach ($c in $v.ToCharArray()) { $s.AppendChar($c) }; return $s }
    $v
}
function Reset-Run { param([string[]]$Answers) $script:requests.Clear(); $script:exports.Clear(); $script:summary = $null; $script:rh.Clear(); foreach ($a in $Answers) { $script:rh.Enqueue($a) } }
$ready = [pscustomobject]@{ IssuanceReady = $true; CACommonName = 'CONTOSO-CA' }
$today = Get-Date -Format 'yyyyMMdd'

# --- 1. The full walk: folder + run password once; template sticks; per-PFX password choice ---------
Reset-Run @(
    'C:\Vendors',             # output folder (once)
    'runpw', 'typo',          # run password + a mismatched confirm -> asked again
    'runpw', 'runpw',         # run password + confirm
    'D',                      # cert 1: 'D' isn't offered with an empty batch -> re-asked
    '1',                      #   template 1
    'nobody', 'acme',         #   user: no match -> asked again -> acme
    '',                       #   PFX password: Enter = re-use the run password
    '',                       # cert 2: blank keeps template 1
    'globex',                 #   user
    'N', 'own1', 'own1',      #   PFX password: its own
    '2',                      # cert 3: template 2
    '',                       #   blank user -> back to the template prompt
    '',                       # cert 3 again: blank keeps template 2 (the last picked)
    'acme',                   #   user
    '',                       #   run password
    '',                       # cert 4: blank keeps template 2
    'acme',                   #   the same vendor on the same template again
    '',                       #   run password
    'D',                      # done
    '',                       # approval pass: Enter once all are issued
    ''                        # Press Enter to return
)
Invoke-CAMenuVendorBatch -Status $ready -CAAnswers ([pscustomobject]@{ Company_Name = 'Contoso Ltd' }) *> $null
Assert-Equal -Actual ($script:requests -join ',') -Expected 'v_acme|NSPIKEv2VendorsMANUAL,v_globex|NSPIKEv2VendorsMANUAL,v_acme|NSPIKEv2PartnerMANUAL,v_acme|NSPIKEv2PartnerMANUAL' -Because "blank keeps the last-used template; a number switches it; a blank user returns to the template prompt"
Assert-Equal -Actual ($script:exports -join ',') -Expected "vacme_NSPIKEv2VendorsMANUAL_$today|runpw,vglobex_NSPIKEv2VendorsMANUAL_$today|own1,vacme_NSPIKEv2PartnerMANUAL_$today|runpw,vacme_NSPIKEv2PartnerMANUAL_${today}_2|runpw" -Because "each PFX gets the run password unless N set its own; a repeat vendor/template gets a _2 file instead of overwriting"
Assert-Equal -Actual $script:rh.Count -Expected 0 -Because "every prompt was asked exactly as scripted (folder and run password only once)"
Assert-Match -Actual $script:summary.Path -Pattern '^C:\\Vendors\\ContosoLtd_VendorCerts_\d{8}_\d{6}\.txt$' -Because "the summary lands in the run's output folder"
Assert-Match -Actual $script:summary.Value -Pattern "v_globex\s+Issued\s+own\s+C:\\Vendors\\vglobex_" -Because "the summary says which PFX has its own password"
Assert-Match -Actual $script:summary.Value -Pattern "v_acme\s+Issued\s+run\s+" -Because "...and which use the run password"
Assert-NoMatch -Actual $script:summary.Value -Pattern 'runpw|own1' -Because "no password is ever written to the summary"

# --- 2. 'B' at the first template prompt cancels with nothing requested ---------------------------------
Reset-Run @('C:\Vendors', 'runpw', 'runpw', 'B')
Invoke-CAMenuVendorBatch -Status $ready -CAAnswers $null *> $null
Assert-Equal -Actual $script:requests.Count -Expected 0 -Because "cancel before the first request submits nothing"
Assert-Equal -Actual $script:summary -Expected $null -Because "...and writes no summary"

# --- 3. After a submit, 'B' is no longer offered (requests are pending on the CA) ------------------------
Reset-Run @('', 'runpw', 'runpw', '1', 'acme', '', 'B', 'D', '', '')
Invoke-CAMenuVendorBatch -Status $ready -CAAnswers $null *> $null
Assert-Equal -Actual $script:requests.Count -Expected 1 -Because "'B' after a submit is re-asked, and D finishes into the approval pass"
Assert-Match -Actual $script:summary.Path -Pattern '^C:\\Admin\\VendorPFX\\' -Because "a blank output folder defaults to C:\Admin\VendorPFX"

# --- 4. Not yet issued -> listed again for approval and retried ------------------------------------------
Reset-Run @('C:\Vendors', 'runpw', 'runpw', '1', 'acme', '', 'D', '', '', '')
$script:pendingOnce = @{ "vacme_NSPIKEv2VendorsMANUAL_$today" = $true }
Invoke-CAMenuVendorBatch -Status $ready -CAAnswers $null *> $null
Assert-Equal -Actual $script:exports.Count -Expected 1 -Because "a request still pending after the first approval pass is retried and exported"
Assert-Equal -Actual $script:rh.Count -Expected 0 -Because "the retry asks once more for approval, then finishes"

# --- 5. Issuance readiness gate ----------------------------------------------------------------------------
Reset-Run @('no', '')
Invoke-CAMenuVendorBatch -Status ([pscustomobject]@{ IssuanceReady = $false }) -CAAnswers $null *> $null
Assert-Equal -Actual $script:requests.Count -Expected 0 -Because "NOT READY + anything but YES cancels before any prompt for vendors"

# --- 6. Nothing persisted, and the dashboard wiring -----------------------------------------------------
$src = Get-Content -Path $VendorBatch -Raw
Assert-NoMatch -Actual $src -Pattern 'Save-CAAnswers|Add-Member -NotePropertyName CA_|\$CAAnswers\.\w+\s*=' -Because "menu 17 remembers nothing between runs (per the maintainer)"
$rawDash = Get-Content -Path $Dashboard -Raw
Assert-Match -Actual $rawDash -Pattern "--- Rollout ---" -Because "the dashboard has a Rollout section"
Assert-Match -Actual $rawDash -Pattern "'\^17\`$'\s*\{\s*Invoke-CAMenuVendorBatch -Status \`$status" -Because "menu 17 -> Invoke-CAMenuVendorBatch"
Assert-True -Condition (Test-Path "$PKIModuleRoot\Private\CAVendorBatch.ps1") -Because "NSP.PKI: the module loader dot-sources every Private\*.ps1 (was: the dashboard dot-sources CAVendorBatch.ps1)"

Remove-Item function:Read-Host, function:Set-Content, function:Test-Path, function:New-Item -ErrorAction SilentlyContinue
Write-TestSummary -Suite "CA-Manager - vendor certificate batch (menu 17)"
