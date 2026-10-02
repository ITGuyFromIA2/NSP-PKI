# Ported from NSP-FGTIPSecTools Tests\CAManager.AdHocTemplate.Tests.ps1 (2026-10-01): same assertions, paths re-pointed at
# this module's Private\ files. Run by Tests\Legacy.Tests.ps1 (Pester) in a child PowerShell.
<#
.SYNOPSIS
    Tests for CA Manager - ad-hoc template creation (2026-09-10, Part A item 5; renumbered to
    menu 16 on 2026-09-12 when the auto-enroll GPO push moved out to AD-Manager): menu 16,
    Get-CAAdHocTemplatePurposes / Get-CAAdHocTemplateSpec (CATemplates.ps1, PURE), and
    Invoke-CAMenuAdHocTemplate (CAInteractive.ps1) - a wizard OUTSIDE the RadiusGroupPairs-driven
    flow menu 4 owns, for the one-off "just need a template for X" ask.

    The maintainer's framing (2026-09-10): "we don't need the moon at this point, but the moon should fit
    in this room" - the purpose/EKU catalog is a lookup TABLE with exactly one entry today, shaped
    so a second purpose is additive later, not a rewrite.

    Repo convention (Tests\README.md) - NOT Pester. A global `function Read-Host` mock reads from a
    FIFO queue (same pattern as CAManager.TestCertSuite.Tests.ps1 / CAManager.BackNav.Tests.ps1).
#>

. "$PSScriptRoot\..\Shared\TestAssertions.ps1"
$PKIModuleRoot = (Resolve-Path "$PSScriptRoot\..\..").Path
Reset-TestCounters

$Root = "C:\GitRepo\NSP-FGTIPSecTools"
$Mod  = "$PKIModuleRoot\Private"
$Dashboard = "$PKIModuleRoot\Tests\Legacy\_CA-Manager.combined.ps1"

Test-ScriptParses -Path "$Mod\CATemplates.ps1"   -Because "CATemplates.ps1 parses after the ad-hoc spec functions"
Test-ScriptParses -Path "$Mod\CAInteractive.ps1" -Because "CAInteractive.ps1 parses after Invoke-CAMenuAdHocTemplate"
Test-ScriptParses -Path $Dashboard               -Because "CA-Manager.ps1 parses after wiring menu 16"

. "$Mod\CACore.ps1"
. "$Mod\CATemplates.ps1"
. "$Mod\CAInteractive.ps1"

$script:__rhQ = [System.Collections.Generic.Queue[string]]::new()
function Read-Host { param([string]$Prompt, [switch]$AsSecureString) if ($script:__rhQ.Count -eq 0) { throw "Read-Host queue empty (prompt: '$Prompt')" } $script:__rhQ.Dequeue() }

# ---------------------------------------------------------------------------
# 1. Get-CAAdHocTemplatePurposes - PURE, a table (extensible), exactly one entry today
# ---------------------------------------------------------------------------
$purposes = @(Get-CAAdHocTemplatePurposes)
Assert-Equal -Actual $purposes.Count -Expected 1 -Because "only VPN/Client-Auth is wired up today - the ONE purpose CA-Manager actually needs"
Assert-Equal -Actual $purposes[0].Key -Expected 'VpnClientAuth' -Because "its key"
Assert-Contains -Haystack ($purposes[0].EkuOids -join ',') -Needle '1.3.6.1.5.5.7.3.2' -Because "Client Authentication EKU"
$srcPurposes = (Get-Command Get-CAAdHocTemplatePurposes).Definition
Assert-NoMatch -Actual $srcPurposes -Pattern 'Invoke-CAStep|New-Item|certutil' -Because "Get-CAAdHocTemplatePurposes is PURE - just a data table"

# ---------------------------------------------------------------------------
# 2. Get-CAAdHocTemplateSpec - PURE, builds a Get-CAVpnTemplateSpec-shaped object
# ---------------------------------------------------------------------------
$spec = Get-CAAdHocTemplateSpec -DisplayName 'NSP-AdHoc-Test' -PurposeKey 'VpnClientAuth' -ValidityDays 180 -OverlapDays 30
Assert-Equal -Actual $spec.DisplayName -Expected 'NSP-AdHoc-Test' -Because "display name passes through"
Assert-Equal -Actual $spec.SchemaVersion -Expected 2 -Because "ad-hoc templates are schema v2, same baseline as Auto/Manual/FortiGate"
Assert-Equal -Actual $spec.ValidityDays -Expected 180 -Because "validity passes through"
Assert-Equal -Actual $spec.OverlapDays -Expected 30 -Because "overlap passes through"
Assert-Equal -Actual $spec.CertificateNameFlagHex -Expected '0x00000001' -Because "ENROLLEE_SUPPLIES_SUBJECT - admin-approved, same as the Manual template"
Assert-Equal -Actual $spec.EnrollmentFlagHex -Expected '0x0000000B' -Because "PEND_ALL_REQUESTS + PUBLISH_TO_DS - admin-approved, same as Manual"
Assert-Equal -Actual $spec.PrivateKeyFlagHex -Expected '0x06060000' -Because "non-exportable by default - the exact captured Auto-template value, not an invented combination"
Assert-Equal -Actual ($spec.EkuOids -join ',') -Expected '1.3.6.1.5.5.7.3.2' -Because "the purpose's EKU carries through"
Assert-Equal -Actual $spec.KeyUsageHex -Expected '0xA000' -Because "and its key usage"
Assert-Equal -Actual @($spec.EnrollPrincipals).Count -Expected 0 -Because "the wizard grants Enroll itself, directly by name - no token indirection needed for a single one-off template"

$specExportable = Get-CAAdHocTemplateSpec -DisplayName 'x' -PurposeKey 'VpnClientAuth' -ExportableKey
Assert-Equal -Actual $specExportable.PrivateKeyFlagHex -Expected '0x01010010' -Because "-ExportableKey uses the exact captured Manual-template value"

$specDefaults = Get-CAAdHocTemplateSpec -DisplayName 'x' -PurposeKey 'VpnClientAuth'
Assert-Equal -Actual $specDefaults.ValidityDays -Expected 365 -Because "default validity matches the other captured templates"
Assert-Equal -Actual $specDefaults.OverlapDays -Expected 42 -Because "default overlap matches the other captured templates"

$threw = $false
try { Get-CAAdHocTemplateSpec -DisplayName 'x' -PurposeKey 'NoSuchPurpose' } catch { $threw = $true; $purposeErr = $_.Exception.Message }
Assert-True     -Condition $threw -Because "an unknown purpose key throws rather than silently building a garbage spec"
Assert-Contains -Haystack $purposeErr -Needle 'NoSuchPurpose' -Because "the error names the bad key"

$srcSpec = (Get-Command Get-CAAdHocTemplateSpec).Definition
Assert-NoMatch -Actual $srcSpec -Pattern 'Invoke-CAStep|New-Item|certutil' -Because "Get-CAAdHocTemplateSpec is PURE - just builds a data object"

# ---------------------------------------------------------------------------
# 3. Invoke-CAMenuAdHocTemplate - source shape: reuses the real create/ACL/publish engines unchanged
# ---------------------------------------------------------------------------
$srcMenu16 = (Get-Command Invoke-CAMenuAdHocTemplate).Definition
Assert-Match -Actual $srcMenu16 -Pattern 'Get-CAAdHocTemplateSpec'      -Because "menu 16 builds its spec from the new ad-hoc function, not Get-CATemplateSpecForAnswers"
Assert-Match -Actual $srcMenu16 -Pattern 'New-CAVpnTemplate -Spec'      -Because "creation reuses the same engine every other template goes through"
Assert-Match -Actual $srcMenu16 -Pattern 'Grant-CATemplateEnrollment -TemplateInternalName \$cn -PrincipalName \$wiz\.EnrollPrincipal' -Because "grants Enroll only, directly by the typed principal name - no -AutoEnroll, matching menu 4's own post-gate behavior"
Assert-NoMatch -Actual $srcMenu16 -Pattern '-AutoEnroll' -Because "never grants AutoEnroll here either - that's the enrollment gate's (menu 15) job alone, for ad-hoc templates too"
Assert-Match -Actual $srcMenu16 -Pattern 'Add-CAPublishedTemplate -TemplateName @\(\$cn\)' -Because "publishes through the same single-write mechanism (not a per-template certutil loop)"
Assert-Match -Actual $srcMenu16 -Pattern 'Remove-CAOrphanTemplateOids' -Because "sweeps orphan OIDs from a failed attempt, same as menu 4"
Assert-Match -Actual $srcMenu16 -Pattern 'Invoke-CAWizardSteps' -Because "the prompt-gathering sequence is back-nav aware, same pattern as menu 14 / menu 6's 6a trio"
# 2026-09-11, per the maintainer's Y/N-defaults review - same idempotency reasoning as menu 4's batch
# create/publish prompt: New-CAVpnTemplate already skips a complete, already-existing template
# rather than erroring/duplicating, so defaulting to Yes here is safe too.
Assert-Match -Actual $srcMenu16 -Pattern 'Create/publish this template now\?" -DefaultYes' -Because "the ad-hoc create/publish confirm defaults to Yes"

# ---------------------------------------------------------------------------
# 4. Functional: the overlap>=validity guard actually adjusts rather than passing a bad spec through
# ---------------------------------------------------------------------------
$script:__rhQ.Enqueue('AdHocFunctionalTest')   # DisplayName
# PurposeKey step is auto-selected (only one purpose) - no prompt consumed
$script:__rhQ.Enqueue('100')                    # ValidityDays
$script:__rhQ.Enqueue('100')                    # OverlapDays == validity - triggers the adjust-down guard
$script:__rhQ.Enqueue('n')                      # ExportableKey
$script:__rhQ.Enqueue('')                       # EnrollPrincipal - skip
$script:__rhQ.Enqueue('n')                      # "Create/publish this template now?" -> decline, so nothing actually mutates
$script:__rhQ.Enqueue('')                       # "Press Enter to return to the menu"

Invoke-CAMenuAdHocTemplate -CAAnswers ([pscustomobject]@{})
Assert-Equal -Actual $script:__rhQ.Count -Expected 0 -Because "declining the final confirm consumes exactly the queued prompts above and returns cleanly, without needing any further mocked Read-Host calls (no ADSI/CA calls attempted)"

# ---------------------------------------------------------------------------
# 5. Dashboard wiring
# ---------------------------------------------------------------------------
$rawDash = Get-Content -Path $Dashboard -Raw
Assert-Match -Actual $rawDash -Pattern "'\^16\`$'\s*\{\s*Invoke-CAMenuAdHocTemplate" -Because "menu 16 dispatches to Invoke-CAMenuAdHocTemplate"
Assert-Match -Actual $rawDash -Pattern 'Add a new template ad-hoc' -Because "item 16 is listed in the terse on-screen menu"

Write-TestSummary -Suite "CA-Manager Ad-Hoc Template Creation"
