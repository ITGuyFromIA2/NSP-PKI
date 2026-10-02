# Ported from NSP-FGTIPSecTools Tests\CAManager.MenuHelp.Tests.ps1 (2026-10-01): same assertions, paths re-pointed at
# this module's Private\ files. Run by Tests\Legacy.Tests.ps1 (Pester) in a child PowerShell.
<#
.SYNOPSIS
    Tests for CA Manager - terse surface / verbose on demand (2026-09-10, Part A item 6 - The maintainer:
    "I like the '?' for more info"): Show-CAMenuHelp (CAInteractive.ps1), the dashboard's one-line-
    per-item menu text, the auto-show-once behavior, and the '?' key wired into the dispatch switch.

    2026-09-11: the auto-show gate moved from a per-SESSION flag ($script:CAHelpShownThisSession,
    reset on every relaunch - including the new menu-1/'R' relaunch flow, so the intro reappeared
    every single time even on a box a tech already knew) to a PERSISTED one
    (Test-CAHelpAcknowledged/Set-CAHelpAcknowledged, CA_HelpAcknowledged in CAAnswers.json).

    Repo convention (Tests\README.md) - NOT Pester.
#>

. "$PSScriptRoot\..\Shared\TestAssertions.ps1"
$PKIModuleRoot = (Resolve-Path "$PSScriptRoot\..\..").Path
Reset-TestCounters

$Root = "C:\GitRepo\NSP-FGTIPSecTools"
$Mod  = "$PKIModuleRoot\Private"
$Dashboard = "$PKIModuleRoot\Tests\Legacy\_CA-Manager.combined.ps1"

Test-ScriptParses -Path "$Mod\CAInteractive.ps1" -Because "CAInteractive.ps1 parses after Show-CAMenuHelp"
Test-ScriptParses -Path $Dashboard               -Because "CA-Manager.ps1 parses after the terse/verbose pass"

. "$Mod\CACore.ps1"
. "$Mod\CAInteractive.ps1"

# ---------------------------------------------------------------------------
# 1. Show-CAMenuHelp exists and carries the ordering rationale + the gate explanation
# ---------------------------------------------------------------------------
Assert-True -Condition ([bool](Get-Command Show-CAMenuHelp -ErrorAction SilentlyContinue)) -Because "Show-CAMenuHelp is defined"
$srcHelp = (Get-Command Show-CAMenuHelp).Definition
Assert-Match -Actual $srcHelp -Pattern 'enrollment gate' -Because "the help text explains the gate (item 15) is the real safety mechanism, not step order"
Assert-Match -Actual $srcHelp -Pattern 'Read-Host' -Because "it pauses for the operator to dismiss it, rather than flashing by"

# ---------------------------------------------------------------------------
# 1b. 2026-09-14: renumbered for the GPO-menu removal (old menu 10 is gone, Toolkit shifted down one),
#     and gained its own AD-Manager cross-link section (the maintainer: cross-link AD-Manager from CA/NPS)
# ---------------------------------------------------------------------------
Assert-NoMatch -Actual $srcHelp -Pattern 'Setup''s order \(1-10\)' -Because "Setup is 1-9 now that the GPO push (old menu 10) moved out to AD-Manager entirely"
Assert-Match   -Actual $srcHelp -Pattern "Setup's order \(1-9\)" -Because "the ordering-rationale intro reflects the current Setup zone size"
Assert-NoMatch -Actual $srcHelp -Pattern 'item 16 alone \(see below\)' -Because "the enrollment gate is item 15 now (was 16 before the GPO menu's removal)"
Assert-Match   -Actual $srcHelp -Pattern 'item 15 alone \(see below\)' -Because "...and the intro text names the correct current item"
Assert-NoMatch -Actual $srcHelp -Pattern '10 links the auto-enrollment GPO' -Because "item 10 is Health now, not the GPO push - that bullet describing the old item 10 is gone"
Assert-Match   -Actual $srcHelp -Pattern 'AD-Manager' -Because "the help screen names AD-Manager explicitly - this is CA-Manager's single most-read piece of prose, so it's where a tech should actually learn the sibling tool exists"
Assert-Match   -Actual $srcHelp -Pattern 'VPN group/OU structure' -Because "the AD-Manager section explains what it's actually for (group/OU scaffold, GPO, WMI filters), not just a bare name-drop"
Assert-Match   -Actual $srcHelp -Pattern 'certificate auto-enrollment GPO' -Because "explicitly connects AD-Manager to the GPO push that used to live in this dashboard"

# ---------------------------------------------------------------------------
# 2. Dashboard menu text is terse - one line per item, no parenthetical rationale
# ---------------------------------------------------------------------------
$rawDash = Get-Content -Path $Dashboard -Raw
foreach ($stale in @(
    'Write-Host "  4\." -NoNewline -ForegroundColor Yellow; Write-Host " Create / update certificate templates   \(',
    'resolves the \*\.msappproxy', 'needs 6''s hostnames',
    'after 8, so its signer', 'forces \+ verifies the renewal paths', 'safe any time; nothing auto-enrolls'
)) {
    Assert-NoMatch -Actual $rawDash -Pattern $stale -Because "the old inline parenthetical rationale moved out of the dashboard's own ON-SCREEN menu text (Write-Host lines) and into Show-CAMenuHelp - the header .SYNOPSIS doc-comment listing is a different, non-runtime thing and can keep its own detail"
}
Assert-NoMatch -Actual $rawDash -Pattern 'First-run order' -Because "the old always-shown ordering hint block is gone from the terse dashboard text"

# ---------------------------------------------------------------------------
# 3. '?' is wired into the dispatch switch, and auto-shows until acknowledged (persisted)
# ---------------------------------------------------------------------------
Assert-Match -Actual $rawDash -Pattern "'\^\\\?\`$'\s*\{\s*Show-CAMenuHelp\s*\}" -Because "the '?' key dispatches to Show-CAMenuHelp on demand"
Assert-Match -Actual $rawDash -Pattern '\?\.' -Because "the ''?''' key itself is listed in the terse menu (findable without already knowing it exists)"
Assert-Match -Actual $rawDash -Pattern 'Test-CAHelpAcknowledged -CAAnswers \$script:CAAnswers' -Because "the auto-show gate checks the PERSISTED acknowledgment, not a session-only flag"
Assert-Match -Actual $rawDash -Pattern '(?s)if \(-not \(Test-CAHelpAcknowledged -CAAnswers \$script:CAAnswers\)\) \{[\s\S]*?Show-CAMenuHelp[\s\S]*?\$script:CAAnswers = Set-CAHelpAcknowledged -CAAnswers \$script:CAAnswers -Path \$answersFile[\s\S]*?continue' -Because "the auto-show records the acknowledgment (Set-CAHelpAcknowledged) and re-draws the (still-terse) menu before the first real prompt, rather than showing help AND asking for a choice in the same breath"
Assert-NoMatch -Actual $rawDash -Pattern 'CAHelpShownThisSession' -Because "the old session-only flag is gone - it reappeared on every relaunch (including the new menu-1/'R' relaunch flow), which is exactly what this fix addresses"

# ---------------------------------------------------------------------------
# 4. Test-CAHelpAcknowledged / Set-CAHelpAcknowledged - the persisted acknowledgment itself
# ---------------------------------------------------------------------------
Assert-False -Condition (Test-CAHelpAcknowledged -CAAnswers $null) -Because "no CAAnswers object at all - never acknowledged"
Assert-False -Condition (Test-CAHelpAcknowledged -CAAnswers ([pscustomobject]@{})) -Because "a CAAnswers object with no CA_HelpAcknowledged property at all - never acknowledged"
Assert-False -Condition (Test-CAHelpAcknowledged -CAAnswers ([pscustomobject]@{ CA_HelpAcknowledged = 'No' })) -Because "explicitly 'No' - not acknowledged"
Assert-True  -Condition (Test-CAHelpAcknowledged -CAAnswers ([pscustomobject]@{ CA_HelpAcknowledged = 'Yes' })) -Because "explicitly 'Yes' - acknowledged"
Assert-True  -Condition (Test-CAHelpAcknowledged -CAAnswers ([pscustomobject]@{ CA_HelpAcknowledged = 'yes' })) -Because "case-insensitive, same as every other Yes/No answer field in this codebase"

$tmpAnswersPath = Join-Path ([System.IO.Path]::GetTempPath()) ("CAHelpAckTest_" + [guid]::NewGuid().ToString('N') + ".json")
try {
    # Starting from $null (a fresh box, no CAAnswers.json yet at all) - must create the object AND the file
    $result = Set-CAHelpAcknowledged -CAAnswers $null -Path $tmpAnswersPath
    Assert-True  -Condition (Test-CAHelpAcknowledged -CAAnswers $result) -Because "Set-CAHelpAcknowledged's returned object is itself already acknowledged"
    Assert-True  -Condition (Test-Path $tmpAnswersPath) -Because "writes CAAnswers.json directly, even starting from nothing"
    $onDisk = Get-Content -Path $tmpAnswersPath -Raw | ConvertFrom-Json
    Assert-Equal -Actual "$($onDisk.CA_HelpAcknowledged)" -Expected 'Yes' -Because "the persisted file itself carries the acknowledgment - a fresh relaunch would read it back as acknowledged"

    # An existing CAAnswers object with OTHER real fields keeps them - this must not clobber anything
    $existing = [pscustomobject]@{ CA_CommonName = 'Contoso-CA'; CA_ValidityYears = '10' }
    $result2 = Set-CAHelpAcknowledged -CAAnswers $existing -Path $tmpAnswersPath
    Assert-Equal -Actual $result2.CA_CommonName -Expected 'Contoso-CA' -Because "an existing field survives untouched"
    Assert-True  -Condition (Test-CAHelpAcknowledged -CAAnswers $result2) -Because "and the acknowledgment is added alongside it"
} finally {
    Remove-Item -Path $tmpAnswersPath -Force -ErrorAction SilentlyContinue
}

$srcSet = (Get-Command Set-CAHelpAcknowledged).Definition
# NOTE: check the actual CALL SHAPE (function name immediately followed by a real parameter), not a
# bare substring match - this function's own doc comment mentions both names in prose to explain WHY
# it avoids them, and a bare substring check would false-fail on that explanatory text itself.
Assert-NoMatch -Actual $srcSet -Pattern 'Invoke-CAStep -Description|Save-CAAnswers -Path' -Because "deliberately bypasses the DRY-RUN-gated save path - CA-Manager starts every session in DRY RUN, so routing through Invoke-CAStep would mean the acknowledgment from the very first session (the one where the intro actually shows) could never actually persist"
Assert-Match -Actual $srcSet -Pattern 'Set-Content -Path \$Path' -Because "writes the file directly instead"

Write-TestSummary -Suite "CA-Manager Terse/Verbose Menu Help"
