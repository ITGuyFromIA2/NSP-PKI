# Ported from NSP-FGTIPSecTools Tests\CAManager.Health.Tests.ps1 (2026-10-01): same assertions, paths re-pointed at
# this module's Private\ files. Run by Tests\Legacy.Tests.ps1 (Pester) in a child PowerShell.
<#
.SYNOPSIS
    Tests for CA Manager - menu 10 (2026-09-12 renumber - was menu 11, shifted down after the GPO
    menu's removal) health check. Get-CAHealthReport is exercised against synthetic
    Get-CAStatus / CAAnswers objects; the fix-dispatch wiring is source-introspected.

    Repo convention (Tests\README.md) - NOT Pester.
#>

. "$PSScriptRoot\..\Shared\TestAssertions.ps1"
$PKIModuleRoot = (Resolve-Path "$PSScriptRoot\..\..").Path
Reset-TestCounters

$Root = "C:\GitRepo\NSP-FGTIPSecTools"
$Mod  = "$PKIModuleRoot\Private"
$Dashboard = "$PKIModuleRoot\Tests\Legacy\_CA-Manager.combined.ps1"

Test-ScriptParses -Path "$Mod\CAHealth.ps1" -Because "CAHealth.ps1 parses"
Test-ScriptParses -Path $Dashboard          -Because "CA-Manager.ps1 parses after wiring menu 10"

. "$Mod\CACore.ps1"
. "$Mod\CATemplates.ps1"
. "$Mod\CAOcsp.ps1"
. "$Mod\CAInteractive.ps1"
. "$Mod\CAHealth.ps1"

# ---------------------------------------------------------------------------
# 1. Get-CAHealthReport - row shape, states, fixes
# ---------------------------------------------------------------------------
$ans = [pscustomobject]@{ CA_AppProxyCrlFqdn = ''; CA_AppProxyOcspFqdn = '' }

# a "healthy" status: everything green, no App Proxy FQDNs (so off-net check SKIPs)
$statusGood = [pscustomobject]@{
    CACommonName            = 'Contoso-CA'
    ExpectedTemplateStatus  = @(
        [pscustomobject]@{ Name = 'IKEv2VPN-CorpLAN'; Published = $true }
        [pscustomobject]@{ Name = 'FortiGate';        Published = $true }
    )
    AutoEnrollPolicyPresent = $true
    HasExternalCDP          = $true
    HasExternalAIAorOCSP    = $true
    OCSPRoleInstalled       = $true
    AppProxyConnectorInstalled = $true
    AppProxyConnectorStatus = 'Running'
}
$report = Get-CAHealthReport -CAAnswers $ans -Status $statusGood
Assert-True -Condition ($report.Count -ge 8) -Because "at least 8 checks run"
foreach ($needId in 'ca-service','templates','autoenroll','cdp-aia','crl-fresh','crl-offnet','ocsp','connector','verify') {
    Assert-True -Condition ([bool]($report | Where-Object Id -eq $needId)) -Because "the report includes the '$needId' check"
}
$tmplRow = $report | Where-Object Id -eq 'templates'
Assert-Equal -Actual $tmplRow.State -Expected 'PASS' -Because "all expected templates published -> PASS"
Assert-True  -Condition ($null -eq $tmplRow.Fix) -Because "a PASS row has no fix"
$aeRow = $report | Where-Object Id -eq 'autoenroll'
Assert-Equal -Actual $aeRow.State -Expected 'PASS' -Because "AutoEnrollPolicyPresent true -> PASS"
Assert-Equal -Actual ($report | Where-Object Id -eq 'crl-offnet').State -Expected 'SKIP' -Because "no CA_AppProxyCrlFqdn -> off-network check skipped"
Assert-Equal -Actual ($report | Where-Object Id -eq 'verify').State -Expected 'SKIP' -Because "no -SampleCertPath -> end-to-end verify skipped"

# a "broken" status: templates missing, autoenroll off, CDP not external, connector stopped
$statusBad = [pscustomobject]@{
    CACommonName            = 'Contoso-CA'
    ExpectedTemplateStatus  = @(
        [pscustomobject]@{ Name = 'IKEv2VPN-CorpLAN'; Published = $true }
        [pscustomobject]@{ Name = 'FortiGate';        Published = $false }
    )
    AutoEnrollPolicyPresent = $false
    HasExternalCDP          = $false
    HasExternalAIAorOCSP    = $false
    OCSPRoleInstalled       = $true
    AppProxyConnectorInstalled = $true
    AppProxyConnectorStatus = 'Stopped'
}
$reportBad = Get-CAHealthReport -CAAnswers $ans -Status $statusBad
$tb = $reportBad | Where-Object Id -eq 'templates'
Assert-Equal -Actual $tb.State -Expected 'FAIL' -Because "a missing template -> FAIL"
Assert-Match -Actual $tb.Detail -Pattern 'FortiGate' -Because "the missing template is named in the detail"
Assert-True  -Condition ($null -ne $tb.Fix) -Because "a FAIL row offers a fix"
Assert-Match -Actual $tb.Fix.Label -Pattern 'menu 4' -Because "the templates fix points at menu 4 (was menu 1)"
Assert-Equal -Actual ($reportBad | Where-Object Id -eq 'cdp-aia').State -Expected 'FAIL' -Because "CDP/AIA not external -> FAIL"
Assert-Equal -Actual ($reportBad | Where-Object Id -eq 'autoenroll').State -Expected 'WARN' -Because "no auto-enroll policy -> WARN (gpupdate may be pending)"
$cr = $reportBad | Where-Object Id -eq 'connector'
Assert-Equal -Actual $cr.State -Expected 'FAIL' -Because "connector installed but not Running -> FAIL"
Assert-Match -Actual $cr.Fix.Label -Pattern 'WAPCSvc' -Because "the connector fix starts WAPCSvc"

# ---------------------------------------------------------------------------
# 2. Get-CAHealthReport is read-only; fixes live in the returned scriptblocks
# ---------------------------------------------------------------------------
$src = (Get-Command Get-CAHealthReport).Definition
Assert-NoMatch -Actual $src -Pattern '(?m)^\s*(Start-Service|Restart-Service|New-ItemProperty|Install-)' -Because "Get-CAHealthReport itself performs no mutations - only its Fix scriptblocks do"
Assert-Match   -Actual $src -Pattern 'Invoke-CAStep' -Because "the fix scriptblocks route mutations through Invoke-CAStep"

$srcMenu = (Get-Command Invoke-CAMenuHealth).Definition
Assert-Match -Actual $srcMenu -Pattern 'Get-CAHealthReport' -Because "the menu builds the report"
Assert-Match -Actual $srcMenu -Pattern 'Show-CAHealthReport' -Because "the menu renders the report"
Assert-Match -Actual $srcMenu -Pattern 'Read-CAConfirm -Prompt "  attempt this fix\?"' -Because "each fix is gated behind a confirm"
Assert-Match -Actual $srcMenu -Pattern '& \$row\.Fix\.Run' -Because "the confirmed fix scriptblock is invoked"

# ---------------------------------------------------------------------------
# 3. Dashboard wiring
# ---------------------------------------------------------------------------
$rawDash = Get-Content $Dashboard -Raw
Assert-True -Condition (Test-Path "$PKIModuleRoot\Private\CAHealth.ps1") -Because "NSP.PKI: the module loader dot-sources every Private\*.ps1 (was: the dashboard dot-sources CAHealth)"
Assert-Match   -Actual $rawDash -Pattern "'\^10\`$'\s*\{[\s\S]{0,80}?Invoke-CAMenuHealth" -Because "menu 10 (2026-09-12 renumber - was menu 11) dispatches to Invoke-CAMenuHealth"
Assert-NoMatch -Actual $rawDash -Pattern "'\^10\`$'\s*\{\s*Invoke-CANotYetImplemented" -Because "menu 10 is no longer a stub"

Write-TestSummary -Suite "CA Manager - menu 10 (health check)"
