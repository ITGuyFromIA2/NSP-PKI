# Ported from NSP-FGTIPSecTools Tests\CAManager.AutoEnrollGate.Tests.ps1 (2026-10-01): same assertions, paths re-pointed at
# this module's Private\ files. Run by Tests\Legacy.Tests.ps1 (Pester) in a child PowerShell.
<#
.SYNOPSIS
    Tests for CA Manager - "the enrollment gate" (2026-09-10, Part A of the productionization plan):
    Test-CATemplateAutoEnroll / Set-CATemplateAutoEnroll (CATemplates.ps1), the menu wrapper
    Invoke-CAMenuAutoEnrollGate + its principal-resolution helper (CAInteractive.ps1), and that
    template creation (menu 1) no longer grants AutoEnroll directly.

    The design: Enroll is granted once, always, at template creation. AutoEnroll is a SEPARATE,
    deliberately-toggled ACE, fully decoupled from build order - nothing auto-enrolls until an
    operator explicitly flips this gate, so Setup-zone steps can be built/revisited in whatever
    order makes sense without risking a premature real enrollment mid-setup.

    Repo convention (Tests\README.md) - NOT Pester. Whole modules are dot-sourced (no top-level side
    effects beyond a couple of $script: constants).
#>

. "$PSScriptRoot\..\Shared\TestAssertions.ps1"
$PKIModuleRoot = (Resolve-Path "$PSScriptRoot\..\..").Path
Reset-TestCounters

$Root = "C:\GitRepo\NSP-FGTIPSecTools"
$Mod  = "$PKIModuleRoot\Private"
$Dashboard = "$PKIModuleRoot\Tests\Legacy\_CA-Manager.combined.ps1"

Test-ScriptParses -Path "$Mod\CATemplates.ps1"   -Because "CATemplates.ps1 parses after the gate functions"
Test-ScriptParses -Path "$Mod\CAInteractive.ps1" -Because "CAInteractive.ps1 parses after Invoke-CAMenuAutoEnrollGate"
Test-ScriptParses -Path "$Mod\CACore.ps1"        -Because "CACore.ps1 parses"
Test-ScriptParses -Path $Dashboard               -Because "CA-Manager.ps1 parses after wiring menu 15"

. "$Mod\CACore.ps1"
. "$Mod\CATemplates.ps1"
. "$Mod\CAInteractive.ps1"

# ---------------------------------------------------------------------------
# 1. Template creation (menu 1) grants Enroll only now - never AutoEnroll directly
# ---------------------------------------------------------------------------
$srcMenu1 = (Get-Command Invoke-CAMenuTemplates).Definition
Assert-NoMatch -Actual $srcMenu1 -Pattern 'Grant-CATemplateEnrollment[^\r\n]*-AutoEnroll' -Because "menu 1's call site no longer passes -AutoEnroll to Grant-CATemplateEnrollment - that's the gate's job now (the word can still appear in surrounding comments)"
Assert-Match   -Actual $srcMenu1 -Pattern 'Grant-CATemplateEnrollment -TemplateInternalName \$cn -PrincipalName \$who' -Because "menu 1 still grants Enroll unconditionally"

$dashSrc = Get-Content -Path $Dashboard -Raw
Assert-Match -Actual $dashSrc -Pattern "'\^15\`$'\s*\{" -Because "item 15 (2026-09-12 renumber - was item 16, shifted down after the GPO menu's removal) is wired into the dashboard switch"
Assert-Match -Actual $dashSrc -Pattern 'Invoke-CAMenuAutoEnrollGate' -Because "item 15 dispatches to the gate menu"

# ---------------------------------------------------------------------------
# 2. Test-CATemplateAutoEnroll - read-only, fails safe to $false (no live AD needed to test this)
# ---------------------------------------------------------------------------
$badBind = Test-CATemplateAutoEnroll -TemplateInternalName 'NoSuchTemplate' -PrincipalName 'Everyone' -ConfigNC 'CN=Configuration,DC=test,DC=local'
Assert-False -Condition $badBind -Because "an LDAP bind that can't reach a real directory fails closed (`$false`), not throws"

$badPrincipal = Test-CATemplateAutoEnroll -TemplateInternalName 'NoSuchTemplate' -PrincipalName 'ThisAccountDoesNotExist_zzz999' -ConfigNC 'CN=Configuration,DC=test,DC=local'
Assert-False -Condition $badPrincipal -Because "an unresolvable principal also fails closed rather than throwing - this is a status check, not an action"

# ---------------------------------------------------------------------------
# 3. Set-CATemplateAutoEnroll - SID resolution happens before Invoke-CAStep (same shape as
#    Grant-CATemplateEnrollment), so DRY RUN still surfaces a bad-principal error immediately
# ---------------------------------------------------------------------------
Set-CADryRun -Enabled $true
$threw = $false
try {
    Set-CATemplateAutoEnroll -TemplateInternalName 'NSPIKEv2CONTOSO' -PrincipalName 'ThisAccountDoesNotExist_zzz999' -Enabled $true -ConfigNC 'CN=Configuration,DC=test,DC=local'
} catch { $threw = $true; $gateErr = $_.Exception.Message }
Assert-True     -Condition $threw -Because "an unresolvable principal throws even in DRY RUN - SID resolution isn't gated behind Invoke-CAStep"
Assert-Contains -Haystack $gateErr -Needle 'ThisAccountDoesNotExist_zzz999' -Because "the error names the principal that failed to resolve"
Assert-Contains -Haystack $gateErr -Needle 'NSPIKEv2CONTOSO' -Because "and the template it was being gated on"

# a resolvable principal (a well-known local account, no real AD needed) sails through SID
# resolution; DRY RUN then means Invoke-CAStep never touches ADSI at all
$threw2 = $false
try {
    Set-CATemplateAutoEnroll -TemplateInternalName 'NSPIKEv2CONTOSO' -PrincipalName 'Everyone' -Enabled $true -ConfigNC 'CN=Configuration,DC=test,DC=local' | Out-Null
} catch { $threw2 = $true }
Assert-False -Condition $threw2 -Because "'Everyone' resolves to a real SID off-domain, so this must NOT throw a SID-resolution error (and DRY RUN means Invoke-CAStep never reaches the ADSI bind)"
Set-CADryRun -Enabled $false

# ---------------------------------------------------------------------------
# 4. Set-CATemplateAutoEnroll's .NOTES / body - documents itself as the gate, touches ONLY the
#    AutoEnroll GUID (never the Enroll GUID), and removes structurally rather than by reference
# ---------------------------------------------------------------------------
$srcSet = (Get-Command Set-CATemplateAutoEnroll).Definition
Assert-Match   -Actual $srcSet -Pattern 'the enrollment gate' -Because "Set-CATemplateAutoEnroll documents itself as THE mechanism, not just a nice-to-have toggle"
Assert-Match   -Actual $srcSet -Pattern "a05b8cc2-17bc-4802-a710-e7c15ab866a2" -Because "operates on the AutoEnroll extended-right GUID"
Assert-NoMatch -Actual $srcSet -Pattern "0e10c968-78fb-11d2-90d4-00c04f79dc55" -Because "never touches the Enroll GUID - that's Grant-CATemplateEnrollment's job, permanent once granted"
Assert-Match   -Actual $srcSet -Pattern 'AddAccessRule\(\$rule\)' -Because "enabling adds the AutoEnroll ACE"
Assert-Match   -Actual $srcSet -Pattern 'RemoveAccessRule\(\$rule\)' -Because "disabling removes it structurally (same rule shape used to add it)"

$srcTest = (Get-Command Test-CATemplateAutoEnroll).Definition
Assert-Match -Actual $srcTest -Pattern "a05b8cc2-17bc-4802-a710-e7c15ab866a2" -Because "Test-CATemplateAutoEnroll checks the same AutoEnroll GUID Set-CATemplateAutoEnroll writes"

# ---------------------------------------------------------------------------
# 5. Resolve-CAAutoEnrollGatePrincipal - mirrors Invoke-CAMenuTemplates' own EnrollPrincipals switch
# ---------------------------------------------------------------------------
$umbrellaAns = [pscustomobject]@{ CA_AutoEnrollGroup = 'DOMAIN\Umbrella_Group' }
Assert-Equal -Actual (Resolve-CAAutoEnrollGatePrincipal -Token 'Umbrella' -Spec $null -CAAnswers $umbrellaAns) -Expected 'DOMAIN\Umbrella_Group' -Because "'Umbrella' resolves from CA_AutoEnrollGroup"

$groupSpec = [pscustomobject]@{ GroupName = 'IKEv2_InternalUsers' }
Assert-Equal -Actual (Resolve-CAAutoEnrollGatePrincipal -Token 'GroupSpecific' -Spec $groupSpec -CAAnswers ([pscustomobject]@{})) -Expected 'IKEv2_InternalUsers' -Because "'GroupSpecific' resolves from the spec's own GroupName - the same field Invoke-CAMenuTemplates reads"

Assert-Equal -Actual (Resolve-CAAutoEnrollGatePrincipal -Token 'DomainAndEnterpriseAdmins' -Spec $null -CAAnswers ([pscustomobject]@{})) -Expected $null -Because "'DomainAndEnterpriseAdmins' resolves to null - nothing to gate, already enrolled via inherited ACEs"

Assert-Equal -Actual (Resolve-CAAutoEnrollGatePrincipal -Token 'DOMAIN\LiteralName' -Spec $null -CAAnswers ([pscustomobject]@{})) -Expected 'DOMAIN\LiteralName' -Because "an unrecognised token passes through literally (default case)"

# ---------------------------------------------------------------------------
# 6. Invoke-CAMenuAutoEnrollGate - source shape (no live console I/O harness in this test suite)
# ---------------------------------------------------------------------------
$srcGateMenu = (Get-Command Invoke-CAMenuAutoEnrollGate).Definition
Assert-Match -Actual $srcGateMenu -Pattern 'Get-CATemplateSpecForAnswers' -Because "the gate menu enumerates the SAME spec set menu 1 creates from"
Assert-Match -Actual $srcGateMenu -Pattern 'AutoEnrollPrincipals' -Because "only templates with an AutoEnroll principal configured are listed - nothing to gate on Manual/FortiGate"
Assert-Match -Actual $srcGateMenu -Pattern 'Test-CATemplateAutoEnroll' -Because "each row's current state comes from a real DACL read, not a guess"
Assert-Match -Actual $srcGateMenu -Pattern 'Set-CATemplateAutoEnroll' -Because "toggling a row calls the real gate engine"
Assert-Match -Actual $srcGateMenu -Pattern "-replace '\[\^A-Za-z0-9\]'" -Because "the template CN is derived the same way New-CAVpnTemplate/Get-CAPerGroupTemplateSpecs derive it - non-alphanumerics stripped from DisplayName"

# ---------------------------------------------------------------------------
# 7. Invoke-CAMenuUmbrella no longer claims it's where AutoEnroll gets granted
# ---------------------------------------------------------------------------
$srcUmbrella = (Get-Command Invoke-CAMenuUmbrella).Definition
Assert-NoMatch -Actual $srcUmbrella -Pattern 'Grant it Enroll \+ AutoEnroll' -Because "the old (now-inaccurate) informational text is gone"
Assert-Match   -Actual $srcUmbrella -Pattern 'enrollment gate' -Because "menu 2 now points at the gate as where AutoEnroll actually gets turned on"

Write-TestSummary -Suite "CA-Manager Enrollment Gate"
