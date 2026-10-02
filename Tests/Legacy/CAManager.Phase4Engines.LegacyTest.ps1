# Ported from NSP-FGTIPSecTools Tests\CAManager.Phase4Engines.Tests.ps1 (2026-10-01): same assertions, paths re-pointed at
# this module's Private\ files. Run by Tests\Legacy.Tests.ps1 (Pester) in a child PowerShell.
<#
.SYNOPSIS
    Tests for CA Manager - Phase 4 scaffold: the dry-run engine (Invoke-CAStep), the PURE
    captured-data functions (Get-CAVpnTemplateSpec, ConvertTo-CAPkiPeriodBytes,
    Get-CAPublicationUrlPlan, New-CACapolicyInf, Get-CAInstallPlan), and
    the dashboard wiring for menu 0/1/2/3/5 + the D toggle.

    2026-09-12: Get-CAAutoEnrollGpoPlan (and the rest of CAAutoEnrollGPO.ps1) MOVED to the new
    AD-Manager tool - its own test coverage now lives in Tests\ADManager.*.Tests.ps1, not here.

    The captured-data functions transcribe CLIENTA's live CA (Examples_Sources\CLIENTA\CAInventory\) -
    these assertions are the guard that the transcription stays faithful.

    Repo convention (Tests\README.md) - NOT Pester. Whole modules are dot-sourced here (they have no
    top-level side effects - #region Standalone-style pure function libraries).
#>

. "$PSScriptRoot\..\Shared\TestAssertions.ps1"
$PKIModuleRoot = (Resolve-Path "$PSScriptRoot\..\..").Path
Reset-TestCounters

$Mod = "$PKIModuleRoot\Private"
$Dashboard = "$PKIModuleRoot\Tests\Legacy\_CA-Manager.combined.ps1"

Test-ScriptParses -Path "$Mod\CACore.ps1"         -Because "CACore.ps1 parses after Invoke-CAStep / dry-run helpers"
Test-ScriptParses -Path "$Mod\CAInstall.ps1"      -Because "CAInstall.ps1 parses"
Test-ScriptParses -Path "$Mod\CATemplates.ps1"    -Because "CATemplates.ps1 parses"
Test-ScriptParses -Path "$Mod\CAUrls.ps1"         -Because "CAUrls.ps1 parses"
Test-ScriptParses -Path "$Mod\CAInteractive.ps1"  -Because "CAInteractive.ps1 parses after the menu-action wrappers"
Test-ScriptParses -Path $Dashboard               -Because "CA-Manager.ps1 parses after wiring the Phase 4 engines"

# dot-source the pure libraries (no side effects)
. "$Mod\CACore.ps1"
. "$Mod\CAInstall.ps1"
. "$Mod\CATemplates.ps1"
. "$Mod\CAUrls.ps1"
. "$Mod\CAInteractive.ps1"

# ---------------------------------------------------------------------------
# 1. Invoke-CAStep / dry-run
# ---------------------------------------------------------------------------
Set-CADryRun -Enabled $true
Assert-True -Condition (Get-CADryRun) -Because "Set-CADryRun \$true is reflected by Get-CADryRun"
$script:__ran = $false
$r = Invoke-CAStep -Description "d" -Commands @("cmd") -Action { $script:__ran = $true; "output-value" }
Assert-False -Condition $script:__ran -Because "in DRY RUN, the action scriptblock is NOT executed"
Assert-False -Condition ([bool]$r.Ran) -Because "the result reports Ran = false in dry-run"
Assert-Equal -Actual $r.Output -Expected $null -Because "no output captured in dry-run"

Set-CADryRun -Enabled $false
$r2 = Invoke-CAStep -Description "d" -Commands @("cmd") -Action { $script:__ran = $true; "output-value" }
Assert-True  -Condition $script:__ran -Because "in APPLY mode the action runs"
Assert-True  -Condition ([bool]$r2.Ran) -Because "the result reports Ran = true"
Assert-Equal -Actual $r2.Output -Expected "output-value" -Because "the action's output is captured"

$threw = $false
try { Invoke-CAStep -Description "boom" -Commands @() -Action { throw "kaboom" } } catch { $threw = $true }
Assert-True -Condition $threw -Because "a throwing action re-throws by default"
$rc = Invoke-CAStep -Description "boom" -Commands @() -Action { throw "kaboom" } -ContinueOnError
Assert-Match -Actual $rc.Error -Pattern 'kaboom' -Because "-ContinueOnError swallows the throw and records .Error"
Set-CADryRun -Enabled $true

# ---------------------------------------------------------------------------
# 2. ConvertTo-CAPkiPeriodBytes - round-trips to the CLIENTA raw-tick values
# ---------------------------------------------------------------------------
foreach ($case in @(@{ d = 365; t = -315360000000000 }, @{ d = 42; t = -36288000000000 },
                    @{ d = 14; t = -12096000000000 }, @{ d = 2; t = -1728000000000 })) {
    $b = ConvertTo-CAPkiPeriodBytes -Days $case.d
    Assert-Equal -Actual $b.Length -Expected 8 -Because "$($case.d)d -> an 8-byte value"
    Assert-Equal -Actual ([System.BitConverter]::ToInt64($b, 0)) -Expected $case.t -Because "$($case.d)d round-trips to $($case.t) (matches the CLIENTA inventory raw ticks)"
}

# ---------------------------------------------------------------------------
# 3. Get-CAVpnTemplateSpec - the four templates' captured flag values
# ---------------------------------------------------------------------------
$spec = Get-CAVpnTemplateSpec
Assert-Equal -Actual $spec.Count -Expected 4 -Because "four templates"
$auto = $spec | Where-Object Key -eq 'Auto'
Assert-Equal -Actual $auto.SchemaVersion -Expected 2 -Because "Auto template is schema v2 (matches CLIENTA's live IKEv2VPN-CorpLAN)"
Assert-True  -Condition (@($auto.DefaultCsps).Count -eq 0) -Because "DefaultCsps is empty by default - a v2 template pinned to a CNG KSP only fails enrollment with CRYPT_E_NO_PROVIDER"
Assert-Equal -Actual ($auto.EkuOids -join ',') -Expected '1.3.6.1.5.5.7.3.2' -Because "Auto template EKU = Client Authentication"
Assert-Equal -Actual $auto.CertificateNameFlagHex -Expected '0x82000000' -Because "Auto template default (shared-CA model) = DIRECTORY_PATH subject + UPN SAN, so 'OU=<vpn ou>' lands in the subject for the FortiGate peer filter"
$autoDed = (Get-CAVpnTemplateSpec -IssuingModel 'DedicatedIssuingCA') | Where-Object Key -eq 'Auto'
Assert-Equal -Actual $autoDed.CertificateNameFlagHex -Expected '0xA6000000' -Because "DedicatedIssuingCA keeps the CLIENTA-verbatim name-flag - no subject filter needed"
$autoShared = (Get-CAVpnTemplateSpec -IssuingModel 'SharedCAWithSubjectFilter') | Where-Object Key -eq 'Auto'
Assert-Equal -Actual $autoShared.CertificateNameFlagHex -Expected '0x82000000' -Because "SharedCAWithSubjectFilter forces the DIRECTORY_PATH subject"
$autoFromAns = (Get-CATemplateSpecForAnswers ([pscustomobject]@{ CA_IssuingModel = 'DedicatedIssuingCA' })) | Where-Object Key -eq 'Auto'
Assert-Equal -Actual $autoFromAns.CertificateNameFlagHex -Expected '0xA6000000' -Because "Get-CATemplateSpecForAnswers threads CA_IssuingModel through to the spec"
Assert-Equal -Actual $auto.EnrollmentFlagHex -Expected '0x00000029' -Because "Auto template Enrollment-Flag = autoenroll + publish-to-DS (captured)"
Assert-Contains -Haystack ($auto.AutoEnrollPrincipals -join ',') -Needle 'Umbrella' -Because "only the umbrella group gets AutoEnroll on the Auto template"

$manual = $spec | Where-Object Key -eq 'Manual'
Assert-Equal -Actual $manual.CertificateNameFlagHex -Expected '0x00000001' -Because "Manual template = ENROLLEE_SUPPLIES_SUBJECT (captured)"
Assert-Equal -Actual $manual.EnrollmentFlagHex -Expected '0x0000000B' -Because "Manual template pends all requests (0x2, captured)"
Assert-Equal -Actual $manual.PrivateKeyFlagHex -Expected '0x01010010' -Because "Manual template private key is EXPORTABLE (0x10, captured verbatim from CLIENTA)"
Assert-True  -Condition ($manual.AutoEnrollPrincipals.Count -eq 0) -Because "the Manual template is not auto-enrolled"

$fg = $spec | Where-Object Key -eq 'FortiGate'
Assert-Equal -Actual $fg.SchemaVersion -Expected 2 -Because "FortiGate template stays v2 (CLIENTA's is v4; v2 is equivalent for a CSR-supplied key and stays raw-ADSI-authorable)"
$ocspSpec = $spec | Where-Object Key -eq 'OcspSigning'
Assert-Equal -Actual $ocspSpec.SchemaVersion -Expected 3 -Because "OCSP signing template MUST be schema v3 - the Online Responder wizard rejects v2/bare-v3 with 0x80070490"
Assert-Equal -Actual $auto.SchemaVersion -Expected 2 -Because "the user templates stay v2 (only the OCSP signer needs v3)"
Assert-True  -Condition ([bool]$ocspSpec.MachineType) -Because "OCSP signer enrolls as the computer account -> CT_FLAG_MACHINE_TYPE (0x40) in flags"
Assert-Match -Actual $ocspSpec.RaApplicationPoliciesRaw -Pattern 'msPKI-Asymmetric-Algorithm.PZPWSTR.RSA' -Because "v3 template carries the CNG-params blob for msPKI-RA-Application-Policies (verbatim from built-in OCSPResponseSigning)"
Assert-Match -Actual $ocspSpec.RaApplicationPoliciesRaw -Pattern 'S-1-5-80-3804348527-3718992918-2141599610-3686422417-2726379419' -Because "the blob's key-security-SD grants the Online Responder service read on the signing key"
Assert-True  -Condition ($null -eq $auto.RaApplicationPoliciesRaw) -Because "the v2 user templates carry no RA-Application-Policies blob"

# ---------------------------------------------------------------------------
# 3b. Get-CAPerGroupTemplateSpecs + Get-CATemplateSpecForAnswers swap (TameMyCerts model)
# ---------------------------------------------------------------------------
$tmcAns = [pscustomobject]@{
    CA_SubjectStampMode = 'TameMyCerts'
    RadiusGroupPairs = @(
        [pscustomobject]@{ Label = 'PSGI';  UserGroupName = 'IKEv2_PSGI_Users' }
        [pscustomobject]@{ Label = 'Audit'; UserGroupName = 'IKEv2_Audit_Users' }
        # real CONTOSO shape (2026-09-10 live bug): UserGroupName is a friendlier label, NOT reliably a
        # real AD group - Grant-CATemplateEnrollment failed to resolve it to a SID; UserGroupValue is
        # the actual AD security group and must be what's used for the ACL grant.
        [pscustomobject]@{ Label = 'CONTOSO'; UserGroupName = 'IKEv2_UserGroup'; UserGroupValue = 'IKEv2_InternalUsers' }
    )
}
$pg = @(Get-CAPerGroupTemplateSpecs -CAAnswers $tmcAns)
Assert-Equal -Actual $pg.Count -Expected 3 -Because "one per-group Auto spec per RadiusGroupPairs entry"
$pgPsgi = $pg | Where-Object { $_.Key -eq 'Group_PSGI' }
Assert-Equal -Actual $pgPsgi.DisplayName -Expected 'NSP-IKEv2-PSGI' -Because "DisplayName = <prefix><label>"
Assert-Equal -Actual $pgPsgi.GroupName -Expected 'IKEv2_PSGI_Users' -Because "GroupName falls back to UserGroupName when UserGroupValue is absent"
$pgContoso = $pg | Where-Object { $_.Key -eq 'Group_CONTOSO' }
Assert-Equal -Actual $pgContoso.GroupName -Expected 'IKEv2_InternalUsers' -Because "GroupName prefers UserGroupValue (the real AD group) over UserGroupName when both are present"
Assert-Equal -Actual $pgPsgi.CertificateNameFlagHex -Expected '0x42000000' -Because "per-group templates are CN-only + UPN SAN (TameMyCerts adds the OU) - real AD OU path never leaks"
Assert-Equal -Actual $pgPsgi.EnrollmentFlagHex -Expected '0x00000029' -Because "still auto-enroll + publish-to-DS like the base Auto"
Assert-Equal -Actual $pgPsgi.SchemaVersion -Expected 2 -Because "per-group templates stay v2"
Assert-Contains -Haystack ($pgPsgi.EnrollPrincipals -join ',') -Needle 'GroupSpecific' -Because "Enroll goes to the pair's own group, not the umbrella"
Assert-Contains -Haystack ($pgPsgi.AutoEnrollPrincipals -join ',') -Needle 'GroupSpecific' -Because "and so does AutoEnroll"

Assert-Equal -Actual (@(Get-CAPerGroupTemplateSpecs -CAAnswers ([pscustomobject]@{ RadiusGroupPairs = $tmcAns.RadiusGroupPairs })).Count) -Expected 0 -Because "no per-group specs unless CA_SubjectStampMode = TameMyCerts"
Assert-Equal -Actual (@(Get-CAPerGroupTemplateSpecs -CAAnswers ([pscustomobject]@{ CA_SubjectStampMode = 'TameMyCerts' })).Count) -Expected 0 -Because "no per-group specs without RadiusGroupPairs"

$swapped = @(Get-CATemplateSpecForAnswers -CAAnswers $tmcAns)
Assert-True  -Condition (-not ($swapped | Where-Object { $_.Key -eq 'Auto' })) -Because "TameMyCerts mode drops the single shared Auto template"
Assert-True  -Condition ([bool]($swapped | Where-Object { $_.Key -eq 'Group_PSGI' })) -Because "and adds the per-group ones instead"
# 2026-09-15, per the maintainer (live, looking at CLIENTA's own menu 4 pick-list): "can we drop the 'manual'
# one from CLIBuilder?... since we're autocreating manual ones anyway" - the shared Manual template
# is now ALSO dropped in TameMyCerts mode, same reasoning as Auto - every per-group Auto template
# already gets its own -MANUAL counterpart on request (Group_PSGI_Manual etc.), so the extra
# non-scoped shared Manual template was pure noise on the pick-list, not a real added capability.
Assert-True  -Condition (-not ($swapped | Where-Object { $_.Key -eq 'Manual' })) -Because "TameMyCerts mode now drops the shared Manual template too - redundant once per-group manual counterparts exist"
Assert-True  -Condition ([bool]($swapped | Where-Object { $_.Key -eq 'FortiGate' }))    -Because "FortiGate is unaffected - it isn't a per-group-anything concept"
Assert-True  -Condition ([bool]($swapped | Where-Object { $_.Key -eq 'OcspSigning' })) -Because "OcspSigning still present"

# ...but a NON-TameMyCerts client (no per-group alternative exists) keeps the shared Manual template -
# only the TameMyCerts branch drops it.
$notSwapped = @(Get-CATemplateSpecForAnswers -CAAnswers ([pscustomobject]@{ CA_IssuingModel = 'SharedCAWithSubjectFilter' }))
Assert-True -Condition ([bool]($notSwapped | Where-Object { $_.Key -eq 'Manual' })) -Because "a client with no RadiusGroupPairs/TameMyCerts mode has no per-group alternative - the shared Manual template stays"

$srcPg = (Get-Command Get-CAPerGroupTemplateSpecs).Definition
Assert-NoMatch -Actual $srcPg -Pattern 'Invoke-CAStep|New-Item|Set-ItemProperty|certutil' -Because "Get-CAPerGroupTemplateSpecs is PURE"

# ---------------------------------------------------------------------------
# 3c. Get-CAPerGroupManualTemplateSpec (2026-09-15) - the admin-approved manual counterpart to a
#     per-group Auto template, per the maintainer: "for any 'template' we generate, we also need to allow a
#     manual admin request against it"
# ---------------------------------------------------------------------------
$pgManualPsgi = Get-CAPerGroupManualTemplateSpec -GroupSpec $pgPsgi
Assert-Equal -Actual $pgManualPsgi.DisplayName -Expected 'NSP-IKEv2-PSGI-MANUAL' -Because "the manual counterpart's DisplayName is the Auto template's own name, suffixed -MANUAL"
Assert-Equal -Actual $pgManualPsgi.Key -Expected 'Group_PSGI_Manual' -Because "keyed off the Auto spec's own Key, distinctly"
Assert-Equal -Actual $pgManualPsgi.GroupName -Expected $pgPsgi.GroupName -Because "carries the SAME group reference as its Auto counterpart - it exists to test/troubleshoot that specific group's cert shape"
Assert-Equal -Actual $pgManualPsgi.SchemaVersion -Expected 2 -Because "stays schema v2, same as every other user/FortiGate template"
Assert-Equal -Actual $pgManualPsgi.CertificateNameFlagHex -Expected '0x00000001' -Because "ENROLLEE_SUPPLIES_SUBJECT - same as the shared Manual template, NOT the per-group Auto's CN-only+TameMyCerts-OU shape"
Assert-Equal -Actual $pgManualPsgi.EnrollmentFlagHex -Expected '0x0000000B' -Because "admin-approved (PEND_ALL_REQUESTS), same as the shared Manual template"
Assert-Equal -Actual $pgManualPsgi.PrivateKeyFlagHex -Expected '0x01010010' -Because "exportable, same captured value as the shared Manual template"
Assert-Contains -Haystack ($pgManualPsgi.EnrollPrincipals -join ',') -Needle 'DomainAndEnterpriseAdmins' -Because "Enroll goes to Domain/Enterprise Admins (an admin manually requests it), same as the shared Manual template - not the per-group AD group itself"
Assert-Equal -Actual $pgManualPsgi.AutoEnrollPrincipals.Count -Expected 0 -Because "never auto-enrolled - this is the one-off/troubleshooting path"
Assert-Equal -Actual $pgManualPsgi.EkuOids -Expected $pgPsgi.EkuOids -Because "same EKU (Client Authentication) as its Auto counterpart"

$manualThrew = $false
try { Get-CAPerGroupManualTemplateSpec -GroupSpec ([pscustomobject]@{ Key = 'Auto'; DisplayName = 'IKEv2VPN-CorpLAN' }) } catch { $manualThrew = $true }
Assert-True -Condition $manualThrew -Because "throws loudly if handed something that isn't a per-group spec (Key not like 'Group_*') - never silently builds a nonsensical manual template off the SHARED Auto spec"

$srcPgManual = (Get-Command Get-CAPerGroupManualTemplateSpec).Definition
Assert-NoMatch -Actual $srcPgManual -Pattern 'Invoke-CAStep|New-Item|Set-ItemProperty|certutil' -Because "Get-CAPerGroupManualTemplateSpec is PURE too - no mutation, just builds a spec object"
$srcNewOcsp = (Get-Command New-CAVpnTemplate).Definition
Assert-Match -Actual $srcNewOcsp -Pattern "msPKI-RA-Application-Policies'\]\.Value" -Because "New-CAVpnTemplate writes msPKI-RA-Application-Policies when the spec (v3+) supplies it"
Assert-Match -Actual $srcNewOcsp -Pattern '\$Spec\.MachineType.*-bor 0x40' -Because "New-CAVpnTemplate ORs CT_FLAG_MACHINE_TYPE into flags for a MachineType spec"
$srcNewCsp = (Get-Command New-CAVpnTemplate).Definition
Assert-NoMatch -Actual $srcNewCsp -Pattern "pKIDefaultCSPs'\]\.Value\s*=\s*\[string\[\]\]@\('1,Microsoft Software Key Storage Provider" -Because "New-CAVpnTemplate no longer hardcodes the CNG KSP into pKIDefaultCSPs"
Assert-NotEqual -Actual $ocspSpec.DisplayName -NotExpected 'OCSPResponseSigning' -Because "default OCSP template name must not collide with the built-in 'OCSPResponseSigning'"
Assert-Match -Actual $ocspSpec.DisplayName -Pattern 'OCSP' -Because "the default is still recognisably an OCSP signing template (NSP-OCSPResponseSigning)"
Assert-Equal -Actual ($fg.EkuOids -join ',') -Expected '1.3.6.1.5.5.7.3.1' -Because "FortiGate template EKU = Server Authentication (captured)"
Assert-Equal -Actual $fg.ValidityDays -Expected 730 -Because "FortiGate template is 2-year (captured)"
Assert-Equal -Actual $fg.PrivateKeyFlagHex -Expected '0x06060110' -Because "FortiGate key is EXPORTABLE (0x10) - menu F generates it CA-side and exports a PFX for the gate"
Assert-True  -Condition (((ConvertFrom-CAHexToInt32 $fg.PrivateKeyFlagHex) -band 0x10) -eq 0x10) -Because "the EXPORTABLE_KEY bit is set"

$ocsp = $spec | Where-Object Key -eq 'OcspSigning'
Assert-Equal -Actual ($ocsp.EkuOids -join ',') -Expected '1.3.6.1.5.5.7.3.9' -Because "OCSP signing EKU (captured)"
Assert-Equal -Actual $ocsp.ValidityDays -Expected 14 -Because "OCSP signing template is 14-day short-lived (captured)"
Assert-Equal -Actual $ocsp.EnrollmentFlagHex -Expected '0x00005020' -Because "OCSP signing Enrollment-Flag = autoenroll + OCSP-nocheck + no-SID-extension (captured)"

$named = Get-CAVpnTemplateSpec -AutoName 'FOO-Auto' -ManualName 'FOO-Manual' -FortiGateName 'FOO-FG' -OcspName 'FOO-OCSP'
Assert-Equal -Actual ($named | Where-Object Key -eq 'Auto').DisplayName -Expected 'FOO-Auto' -Because "display names are parameterized (client prefix at create time)"

# --- template attribute encoders (pure, deterministic) ---
Assert-Equal -Actual ([System.BitConverter]::ToString((ConvertFrom-CAKeyUsageHex '0xA000'))) -Expected 'A0-00' -Because "pKIKeyUsage 0xA000 -> bytes A0 00 (digitalSignature + keyEncipherment, matches CLIENTA)"
Assert-Equal -Actual ([System.BitConverter]::ToString((ConvertFrom-CAKeyUsageHex '0x8000'))) -Expected '80-00' -Because "pKIKeyUsage 0x8000 -> bytes 80 00 (digitalSignature only, the OCSP signer)"
Assert-Equal -Actual (ConvertFrom-CAHexToInt32 '0xA6000000') -Expected -1509949440 -Because "0xA6000000 name-flag stores as its two's-complement int32 (high bit set)"
Assert-Equal -Actual (ConvertFrom-CAHexToInt32 '0x00000029') -Expected 41 -Because "0x29 enrollment-flag -> 41"
Assert-Equal -Actual (ConvertFrom-CAHexToInt32 '0x01010010') -Expected 16842768 -Because "0x01010010 private-key-flag (exportable) -> 16842768"
Assert-Equal -Actual (ConvertFrom-CAHexToInt32 '0x00005020') -Expected 20512 -Because "0x5020 OCSP enrollment-flag -> 20512"

# create-mechanism functions are built now (raw ADSI) - they exist and won't run without a live
# directory, but they must NOT still be the "not built yet" stubs
Assert-True -Condition ([bool](Get-Command New-CAVpnTemplate -ErrorAction SilentlyContinue)) -Because "New-CAVpnTemplate is defined"
Assert-True -Condition ([bool](Get-Command Grant-CATemplateEnrollment -ErrorAction SilentlyContinue)) -Because "Grant-CATemplateEnrollment is defined"
# 2026-09-10 live bug: an unresolvable principal (wrong name / missing domain prefix / genuinely
# doesn't exist in AD) threw a bare, unhelpful .NET exception ("Some or all identity references
# could not be translated") naming neither the principal nor the template. -ConfigNC bypasses the
# real AD RootDSE bind so this is testable off-domain; the bogus name still fails SID translation.
try {
    Grant-CATemplateEnrollment -TemplateInternalName 'NSPIKEv2CONTOSO' -PrincipalName 'ThisAccountDoesNotExist_zzz999' -ConfigNC 'CN=Configuration,DC=test,DC=local'
    Assert-True -Condition $false -Because "an unresolvable principal name should throw, not silently succeed"
} catch {
    Assert-Contains -Haystack $_.Exception.Message -Needle 'ThisAccountDoesNotExist_zzz999' -Because "the error names the principal that failed to resolve"
    Assert-Contains -Haystack $_.Exception.Message -Needle 'NSPIKEv2CONTOSO' -Because "and the template it was being granted on"
    Assert-Match -Actual $_.Exception.Message -Pattern "DOMAIN" -Because "and hints that a missing domain prefix could be the cause"
}
$srcNew = (Get-Command New-CAVpnTemplate).Definition
Assert-NoMatch -Actual $srcNew -Pattern 'not built yet' -Because "New-CAVpnTemplate is no longer a stub"
Assert-Match   -Actual $srcNew -Pattern "pKICertificateTemplate" -Because "New-CAVpnTemplate creates a pKICertificateTemplate object"
Assert-Match   -Actual $srcNew -Pattern "New-CATemplateOid" -Because "New-CAVpnTemplate allocates a template OID first"
Assert-NoMatch -Actual $srcNew -Pattern "CN=User" -Because "legacy flags/critExt are derived from the spec now, not cloned from CN=User"
Assert-Match   -Actual $srcNew -Pattern "legacyFlags" -Because "legacy CT_FLAG_* value is derived from the spec's enrollment/private-key flags"

# publish is a SINGLE union-write, not a per-template certutil loop (the loop loses all but the
# last entry on a single DC)
Assert-True  -Condition ([bool](Get-Command Add-CAPublishedTemplate -ErrorAction SilentlyContinue)) -Because "Add-CAPublishedTemplate is defined"
$srcPub = (Get-Command Add-CAPublishedTemplate).Definition
Assert-Match -Actual $srcPub -Pattern "certificateTemplates" -Because "Add-CAPublishedTemplate writes the enrollment-service certificateTemplates attribute directly"
Assert-Match -Actual $srcPub -Pattern "Restart-Service certsvc" -Because "the CA is restarted once so it re-reads the published list"
$srcMenu = (Get-Command Invoke-CAMenuTemplates).Definition
Assert-Match -Actual $srcMenu -Pattern "Add-CAPublishedTemplate" -Because "menu 1 publishes the whole batch in one write"
Assert-NoMatch -Actual $srcMenu -Pattern "Publish-CATemplateToCA" -Because "menu 1 no longer publishes per-template"

# incomplete-husk guard
Assert-True  -Condition ([bool](Get-Command Test-CATemplateComplete -ErrorAction SilentlyContinue)) -Because "Test-CATemplateComplete is defined"
Assert-Match -Actual $srcNew -Pattern "Test-CATemplateComplete" -Because "New-CAVpnTemplate probes an existing CN for completeness before publishing it"

# orphan-OID sweep
Assert-True  -Condition ([bool](Get-Command Remove-CAOrphanTemplateOids -ErrorAction SilentlyContinue)) -Because "Remove-CAOrphanTemplateOids is defined"
$srcSweep = (Get-Command Remove-CAOrphanTemplateOids).Definition
Assert-Match -Actual $srcSweep -Pattern "DeleteTree" -Because "orphan OID objects are removed via DeleteTree on the raw DirectoryEntry"

# RSAT / management-module installer
Assert-True  -Condition ([bool](Get-Command Install-CAManagementPrereqs -ErrorAction SilentlyContinue)) -Because "Install-CAManagementPrereqs is defined"
Assert-True  -Condition ([bool](Get-Command Get-CAManagementPrereqStatus -ErrorAction SilentlyContinue)) -Because "Get-CAManagementPrereqStatus is defined"
$srcRsat = (Get-Command Install-CAManagementPrereqs).Definition
Assert-Match -Actual $srcRsat -Pattern "RSAT-AD-PowerShell" -Because "installs the ActiveDirectory RSAT feature on Windows Server"
Assert-Match -Actual $srcRsat -Pattern "GPMC" -Because "installs the GroupPolicy RSAT feature on Windows Server"
Assert-Match -Actual $srcRsat -Pattern "Add-WindowsCapability" -Because "falls back to Add-WindowsCapability on client OS"

# ---------------------------------------------------------------------------
# 3d. Get-CAManualApprovalTemplates (2026-09-15) - menu 11's pick-list source: published templates
#     whose msPKI-Enrollment-Flag has PEND_ALL_REQUESTS (0x2) set. Per the established convention
#     for raw-ADSI functions in this file (section 3, "won't run without a live directory"), the
#     AD-bind portion is verified via source-text pattern matches, not by invoking it against a real
#     directory (this dev box happens to be domain-joined, so a full functional call would silently
#     succeed/fail depending on what's actually published there - not a deterministic test). The two
#     early-return paths (empty/unparseable certutil output) DO run before any AD touch at all, so
#     those are exercised for real.
# ---------------------------------------------------------------------------
Assert-True -Condition ([bool](Get-Command Get-CAManualApprovalTemplates -ErrorAction SilentlyContinue)) -Because "Get-CAManualApprovalTemplates is defined"

function certutil.exe { $global:LASTEXITCODE = 0; '' }
Assert-Equal -Actual (@(Get-CAManualApprovalTemplates)).Count -Expected 0 -Because "empty certutil -CATemplates output -> empty array, returned before Get-CAConfigNamingContext / any AD bind is ever attempted"
Remove-Item function:certutil.exe -ErrorAction SilentlyContinue

function certutil.exe { $global:LASTEXITCODE = 0; "garbage output with no colon-dash shape`r`nmore garbage" }
Assert-Equal -Actual (@(Get-CAManualApprovalTemplates)).Count -Expected 0 -Because "certutil output that parses to zero published-template rows also returns empty before touching AD"
Remove-Item function:certutil.exe -ErrorAction SilentlyContinue

$srcManualTpl = (Get-Command Get-CAManualApprovalTemplates).Definition
Assert-Match -Actual $srcManualTpl -Pattern 'certutil\.exe -CATemplates' -Because "sources the published-template list the same way Resolve-VPNCertTemplateName does"
Assert-Match -Actual $srcManualTpl -Pattern "Get-CAConfigNamingContext" -Because "resolves the Configuration NC for the raw-ADSI template read, same pattern as every other template function in this file"
Assert-Match -Actual $srcManualTpl -Pattern "CN=Certificate Templates,CN=Public Key Services,CN=Services" -Because "reads each published template from the real AD templates container"
Assert-Match -Actual $srcManualTpl -Pattern "msPKI-Enrollment-Flag" -Because "checks the enrollment-flag attribute"
Assert-Match -Actual $srcManualTpl -Pattern '-band 0x2\b' -Because "filters on CT_FLAG_PEND_ALL_REQUESTS (0x2) - 'Manual approval', not just any published template"
Assert-Match -Actual $srcManualTpl -Pattern '(?s)try\s*\{.*catch' -Because "an unreadable/unresolvable single template (built-in stored elsewhere, transient AD hiccup) is skipped, not fatal to the whole listing"

# ---------------------------------------------------------------------------
# 4. Get-CAPublicationUrlPlan - the CLIENTA CDP/AIA recipe
# ---------------------------------------------------------------------------
$p = Get-CAPublicationUrlPlan -CrlFqdn 'crl-acme.msappproxy.net' -OcspFqdn 'ocsp-acme.msappproxy.net' -DeltaCrl $true -CrlSharePath 'C:\CRLShare'
Assert-Contains -Haystack ($p.Cdp -join ' | ') -Needle '6:http://crl-acme.msappproxy.net/CertEnroll/%3%8%9.crl' -Because "external CDP entry with flags 6 (AddToCertCDP + AddToFreshestCRL)"
Assert-Contains -Haystack ($p.Cdp -join ' | ') -Needle '65:%windir%\system32\CertSrv\CertEnroll\%3%8%9.crl' -Because "local publish + delta (flags 65) when DeltaCrl"
Assert-Contains -Haystack ($p.Cdp -join ' | ') -Needle '65:file://C:/CRLShare/%3%8%9.crl' -Because "a CRL-share publish target is added when CrlSharePath is given"
Assert-Contains -Haystack ($p.Aia -join ' | ') -Needle '2:http://crl-acme.msappproxy.net/CertEnroll/%1_%3%4.crt' -Because "external AIA (CA-cert) entry with flag 2 - filename MUST match the local-publish entry's %1_%3%4.crt (bare %3.crt 404s: the CA never writes a file under that name - live bug found 2026-09-10 on Contoso-CA, traced to a mismatch faithfully transcribed from CLIENTA's own live capture)"
Assert-Contains -Haystack ($p.Aia -join ' | ') -Needle '32:http://ocsp-acme.msappproxy.net/ocsp' -Because "external OCSP URL in the AIA extension with flag 32"
Assert-Contains -Haystack ($p.Aia -join ' | ') -Needle '1:ldap:///CN=%7,CN=AIA' -Because "LDAP AIA publish is kept"
$aiaLocal = @($p.Aia | Where-Object { $_ -match '^\d+:%windir%' })[0]
$aiaExternal = @($p.Aia | Where-Object { $_ -match '^\d+:http://crl-acme' })[0]
Assert-Match -Actual $aiaLocal -Pattern '%1_%3%4\.crt$' -Because "sanity: the local-publish filename token"
Assert-Equal -Actual ($aiaLocal -replace '^.*(%1_%3%4\.crt)$', '$1') -Expected ($aiaExternal -replace '^.*(%1_%3%4\.crt)$', '$1') -Because "the external URL's filename token must be identical to the local-publish one - that's the actual bug class, not just this one literal string"
Assert-Equal -Actual ($p.CdpSetRegValue -split '\\n').Count -Expected $p.Cdp.Count -Because "CdpSetRegValue joins the entries with a literal backslash-n for certutil -setreg"

$pnd = Get-CAPublicationUrlPlan -CrlFqdn 'c' -OcspFqdn 'o' -DeltaCrl $false
Assert-Contains    -Haystack ($pnd.Cdp -join ' | ') -Needle '1:%windir%\system32\CertSrv\CertEnroll\%3%8%9.crl' -Because "no-delta uses publish flag 1, not 65"
Assert-NotContains -Haystack ($pnd.Cdp -join ' | ') -Needle 'file://' -Because "no CRL-share entry when no path is given"

# ---------------------------------------------------------------------------
# 5. New-CACapolicyInf
# ---------------------------------------------------------------------------
$inf = New-CACapolicyInf -RenewalKeyLength 4096 -RenewalValidityYears 12 -CrlPeriodDays 5 -CrlDeltaPeriodDays 2
Assert-Match    -Actual $inf -Pattern '(?m)^\[Certsrv_Server\]\s*$' -Because "capolicy.inf has the Certsrv_Server section"
Assert-Contains -Haystack $inf -Needle 'RenewalKeyLength=4096' -Because "key length is written"
Assert-Contains -Haystack $inf -Needle 'RenewalValidityPeriodUnits=12' -Because "CA cert lifetime is written"
Assert-Contains -Haystack $inf -Needle 'CRLPeriodUnits=5' -Because "CRL period is written"
Assert-Contains -Haystack $inf -Needle 'CRLDeltaPeriodUnits=2' -Because "delta CRL period is written"
Assert-Contains -Haystack $inf -Needle 'LoadDefaultTemplates=0' -Because "a VPN-purpose CA does not load the default templates"
Assert-NoMatch  -Actual $inf -Pattern '(?m)^\[PolicyStatementExtension\]\s*$' -Because "no CPS section unless -CpsUrl is given"
$infCps = New-CACapolicyInf -CpsUrl 'https://pki.example/cps'
Assert-Match    -Actual $infCps -Pattern '(?m)^\[PolicyStatementExtension\]\s*$' -Because "-CpsUrl adds the policy-statement section"
Assert-Contains -Haystack $infCps -Needle 'URL=https://pki.example/cps' -Because "the CPS URL is written"

# ---------------------------------------------------------------------------
# 7. Get-CAInstallPlan
# ---------------------------------------------------------------------------
$plan = Get-CAInstallPlan -CACommonName 'ACME Issuing CA' -ValidityYears 8 -KeyLength 4096
Assert-Equal -Actual $plan.CAType -Expected 'EnterpriseRootCA' -Because "the built path is an enterprise root"
Assert-Equal -Actual $plan.CACommonName -Expected 'ACME Issuing CA' -Because "CN passes through"
Assert-Equal -Actual $plan.KeyLength -Expected 4096 -Because "key length passes through"
Assert-Equal -Actual $plan.ValidityPeriodUnits -Expected 8 -Because "validity years passes through"
Assert-Equal -Actual $plan.HashAlgorithmName -Expected 'SHA256' -Because "SHA256"
$subThrew = $false
try { Get-CAInstallPlan -CACommonName 'x' -CAType EnterpriseSubordinateCA } catch { $subThrew = ($_.Exception.Message -match 'only EnterpriseRootCA') }
Assert-True -Condition $subThrew -Because "the subordinate install path throws 'not built yet' rather than a half-baked plan"

Write-TestSummary -Suite "CA Manager - Phase 4 engines (dry-run + captured-data scaffold)"
