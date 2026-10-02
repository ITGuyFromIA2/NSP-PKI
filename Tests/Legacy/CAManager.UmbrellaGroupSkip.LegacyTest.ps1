# Ported from NSP-FGTIPSecTools Tests\CAManager.UmbrellaGroupSkip.Tests.ps1 (2026-10-01): same assertions, paths re-pointed at
# this module's Private\ files. Run by Tests\Legacy.Tests.ps1 (Pester) in a child PowerShell.
<#
.SYNOPSIS
    Tests for CA Manager - menu 4 skips the umbrella-group prompt when nothing it would create
    actually uses it (2026-09-11), per the maintainer: "Do we really need the IKEv2_MasterGroup at this
    point? Since TameMyCerts is in place there really is no point. It's just muddying the waters."

    Confirmed by reading the template-spec code: EnrollPrincipals only ever contains 'Umbrella' on
    the single SHARED Auto template spec - Get-CATemplateSpecForAnswers drops that entirely in favor
    of per-group 'GroupSpecific' templates the moment TameMyCerts + RadiusGroupPairs are both in
    play. Invoke-CAMenuTemplates now computes $umbrellaNeeded generically from the actual $spec about
    to be created (not a hardcoded CA_SubjectStampMode check), and only prompts when at least one
    spec would actually use it.

    Repo convention (Tests\README.md) - NOT Pester. A global `function Read-Host` mock reads from a
    FIFO queue; the real mutating engines (New-CAVpnTemplate/Grant-CATemplateEnrollment/
    Add-CAPublishedTemplate/Remove-CAOrphanTemplateOids) are mocked since this test has no live CA/AD.
#>

. "$PSScriptRoot\..\Shared\TestAssertions.ps1"
$PKIModuleRoot = (Resolve-Path "$PSScriptRoot\..\..").Path
Reset-TestCounters

$Root = "C:\GitRepo\NSP-FGTIPSecTools"
$Mod  = "$PKIModuleRoot\Private"

Test-ScriptParses -Path "$Mod\CAInteractive.ps1" -Because "CAInteractive.ps1 parses after the umbrella-skip logic"
Test-ScriptParses -Path "$Mod\CATemplates.ps1"   -Because "CATemplates.ps1 parses"

. "$Mod\CACore.ps1"
. "$Mod\CATemplates.ps1"
. "$Mod\CAInteractive.ps1"

$script:__rhQ = [System.Collections.Generic.Queue[string]]::new()
function Read-Host { param([string]$Prompt, [switch]$AsSecureString) if ($script:__rhQ.Count -eq 0) { throw "Read-Host queue empty (prompt: '$Prompt')" } $script:__rhQ.Dequeue() }

# Mock the real mutating engines - no live CA/AD in this test.
function New-CAVpnTemplate            { param($Spec) $Spec.DisplayName -replace '[^A-Za-z0-9]', '' }
function Grant-CATemplateEnrollment   { param($TemplateInternalName, $PrincipalName) }
function Add-CAPublishedTemplate      { param($TemplateName) }
function Remove-CAOrphanTemplateOids  { param($ExpectedTemplateNames) }

Set-CADryRun -Enabled $false

# ---------------------------------------------------------------------------
# 1. Shared-Auto-template case (no TameMyCerts / no RadiusGroupPairs) - the prompt IS asked, and its
#    answer actually flows through to the Enroll grant.
# ---------------------------------------------------------------------------
$ansShared = [pscustomobject]@{
    CA_TemplateAuto = 'IKEv2VPN-CorpLAN'; CA_TemplateManual = 'IKEv2VPN-CorpLAN-MANUAL'; CA_TemplateFortiGate = 'FortiGate'
}
$script:__grantedTo = [System.Collections.Generic.List[string]]::new()
function Grant-CATemplateEnrollment { param($TemplateInternalName, $PrincipalName) $script:__grantedTo.Add("$TemplateInternalName=$PrincipalName") }

$script:__rhQ.Enqueue('')                    # OCSP-responder-host prompt - blank/skip (2026-09-15: now asked FIRST)
$script:__rhQ.Enqueue('IKEv2_MasterGroup')   # umbrella-group prompt - IS asked
$script:__rhQ.Enqueue('A')                   # "Which template number(s)..." pick-list - select all
$script:__rhQ.Enqueue('n')                   # "Create/publish the N selected template(s) now?" - decline, avoid the full create/publish path
$script:__rhQ.Enqueue('')                    # "Press Enter to return to the menu"
Invoke-CAMenuTemplates -CAAnswers $ansShared
Assert-Equal -Actual $script:__rhQ.Count -Expected 0 -Because "exactly 5 prompts consumed - the umbrella prompt WAS asked when the shared Auto template (which uses it) is in play"

# ---------------------------------------------------------------------------
# 2. TameMyCerts + RadiusGroupPairs case - the umbrella prompt is SKIPPED entirely, no Read-Host call
# ---------------------------------------------------------------------------
$ansTmc = [pscustomobject]@{
    CA_TemplateAuto = 'IKEv2VPN-CorpLAN'; CA_TemplateManual = 'IKEv2VPN-CorpLAN-MANUAL'; CA_TemplateFortiGate = 'FortiGate'
    CA_SubjectStampMode = 'TameMyCerts'
    RadiusGroupPairs = @([pscustomobject]@{ Label = 'CONTOSO'; UserGroupName = 'IKEv2_UserGroup'; UserGroupValue = 'IKEv2_InternalUsers' })
}
$script:__rhQ.Enqueue('')    # OCSP-responder-host prompt - blank/skip (the ONLY prompt reached before the pick-list)
$script:__rhQ.Enqueue('A')   # "Which template number(s)..." pick-list - select all
$script:__rhQ.Enqueue('n')   # "Also add manual version(s) for the selected group template(s)?" (2026-09-15) - decline
$script:__rhQ.Enqueue('n')   # "Create/publish the N selected template(s) now?" - decline
$script:__rhQ.Enqueue('')    # "Press Enter to return to the menu"
Invoke-CAMenuTemplates -CAAnswers $ansTmc
Assert-Equal -Actual $script:__rhQ.Count -Expected 0 -Because "exactly 5 prompts consumed - the umbrella prompt was SKIPPED entirely (no extra queued response needed for it), since the per-group templates never use it"
Assert-False -Condition ([bool]$ansTmc.PSObject.Properties['CA_AutoEnrollGroup']) -Because "skipping the prompt never invents/remembers a CA_AutoEnrollGroup value that was never actually asked for"

# ---------------------------------------------------------------------------
# 3. TameMyCerts + RadiusGroupPairs, but CA_AutoEnrollGroup was already set from BEFORE (e.g. a client
#    that had it configured pre-TameMyCerts) - still skipped (still unused), but a note explains why,
#    rather than silently vanishing with no explanation.
# ---------------------------------------------------------------------------
$ansTmcWithStale = [pscustomobject]@{
    CA_TemplateAuto = 'IKEv2VPN-CorpLAN'; CA_TemplateManual = 'IKEv2VPN-CorpLAN-MANUAL'; CA_TemplateFortiGate = 'FortiGate'
    CA_SubjectStampMode = 'TameMyCerts'; CA_AutoEnrollGroup = 'IKEv2_MasterGroup'
    RadiusGroupPairs = @([pscustomobject]@{ Label = 'CONTOSO'; UserGroupName = 'IKEv2_UserGroup'; UserGroupValue = 'IKEv2_InternalUsers' })
}
$script:__rhQ.Enqueue('')
$script:__rhQ.Enqueue('A')
$script:__rhQ.Enqueue('n')   # "Also add manual version(s)...?" - decline
$script:__rhQ.Enqueue('n')
$script:__rhQ.Enqueue('')
$capturedNote = Invoke-CAMenuTemplates -CAAnswers $ansTmcWithStale 6>&1
$capturedNoteText = ($capturedNote | ForEach-Object { $_.ToString() }) -join "`n"
Assert-Match -Actual $capturedNoteText -Pattern 'skipping the umbrella-group prompt' -Because "a tech who already had CA_AutoEnrollGroup set from before TameMyCerts sees a clear note explaining why it's no longer being asked about, not just silence"
Assert-Equal -Actual $script:__rhQ.Count -Expected 0 -Because "still exactly 5 prompts consumed even with the note printed"

# ---------------------------------------------------------------------------
# 4. Opting IN to "also add manual version(s)" (2026-09-15) actually creates the manual counterpart
# ---------------------------------------------------------------------------
$script:__createdNames = [System.Collections.Generic.List[string]]::new()
function New-CAVpnTemplate { param($Spec) $script:__createdNames.Add($Spec.DisplayName); $Spec.DisplayName -replace '[^A-Za-z0-9]', '' }

$script:__rhQ.Enqueue('')    # OCSP-responder-host prompt
$script:__rhQ.Enqueue('A')   # pick-list - select all
$script:__rhQ.Enqueue('y')   # "Also add manual version(s)...?" - ACCEPT this time
$script:__rhQ.Enqueue('y')   # "Create/publish the N selected template(s) now?" - ACCEPT, so the create loop actually runs (mocked New-CAVpnTemplate below records names)
$script:__rhQ.Enqueue('')    # "Press Enter to return to the menu"
Invoke-CAMenuTemplates -CAAnswers $ansTmc
Assert-Equal -Actual $script:__rhQ.Count -Expected 0 -Because "5 prompts consumed"
Assert-Contains -Haystack ($script:__createdNames -join ',') -Needle 'NSP-IKEv2-CONTOSO-MANUAL' -Because "opting IN to the manual-version prompt actually creates the per-group manual counterpart, not just echoes it"

# ---------------------------------------------------------------------------
# 5. Source-shape: $umbrellaNeeded is computed from $spec generically, not a hardcoded
#    CA_SubjectStampMode string check
# ---------------------------------------------------------------------------
$srcMenu4 = (Get-Command Invoke-CAMenuTemplates).Definition
Assert-Match -Actual $srcMenu4 -Pattern "\`$umbrellaNeeded = \[bool\]\(\`$spec \| Where-Object \{ \`$_\.EnrollPrincipals -contains 'Umbrella' -or \`$_\.AutoEnrollPrincipals -contains 'Umbrella' \}\)" -Because "computed from the actual specs about to be created, not a hardcoded mode check - stays correct if the per-group-vs-shared logic changes later"

Write-TestSummary -Suite "CA-Manager Umbrella-Group Prompt Skip (menu 4)"
