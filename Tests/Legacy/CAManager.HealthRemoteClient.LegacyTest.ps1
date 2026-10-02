# Ported from NSP-FGTIPSecTools Tests\CAManager.HealthRemoteClient.Tests.ps1 (2026-10-01): same assertions, paths re-pointed at
# this module's Private\ files. Run by Tests\Legacy.Tests.ps1 (Pester) in a child PowerShell.
<#
.SYNOPSIS
    Tests for CA Manager - health check's remote-client visibility (2026-09-10, Part A item 8):
    promotes menu 13's proven remote-client engines (Get-CARenewalTemplateOid/Get-CARenewalTestCert,
    CARenewalTest.ps1) outward into Get-CAHealthReport / Invoke-CAMenuHealth (menu 11), which had
    zero remote-client visibility before this.

    Repo convention (Tests\README.md) - NOT Pester. Mocks Get-CARenewalTemplateOid/
    Get-CARenewalTestCert directly (same-named function defined after CAHealth.ps1 is dot-sourced -
    "later definition wins") rather than loading the real CARenewalTest.ps1 and its own dependencies.
#>

. "$PSScriptRoot\..\Shared\TestAssertions.ps1"
$PKIModuleRoot = (Resolve-Path "$PSScriptRoot\..\..").Path
Reset-TestCounters

$Root = "C:\GitRepo\NSP-FGTIPSecTools"
$Mod  = "$PKIModuleRoot\Private"

Test-ScriptParses -Path "$Mod\CAHealth.ps1" -Because "CAHealth.ps1 parses after the remote-client row"

. "$Mod\CACore.ps1"
. "$Mod\CATemplates.ps1"
. "$Mod\CAOcsp.ps1"
. "$Mod\CAInteractive.ps1"
. "$Mod\CAHealth.ps1"

$baseAnswers = [pscustomobject]@{}
$baseStatus  = [pscustomobject]@{ CACommonName = 'Contoso-CA'; AutoEnrollPolicyPresent = $true; HasExternalCDP = $true; HasExternalAIAorOCSP = $true; OCSPRoleInstalled = $false; AppProxyConnectorInstalled = $false; AppProxyConnectorStatus = $null }

# ---------------------------------------------------------------------------
# 1. Both blank - SKIP, doesn't touch the remote engines at all
# ---------------------------------------------------------------------------
$r1 = @(Get-CAHealthReport -CAAnswers $baseAnswers -Status $baseStatus) | Where-Object Id -eq 'remote-cert'
Assert-Equal -Actual $r1.State -Expected 'SKIP' -Because "no client hostname / template CN given -> SKIP, same convention as -SampleCertPath"
Assert-Match -Actual $r1.Detail -Pattern 'RemoteClientComputerName' -Because "the SKIP detail tells the operator how to actually run this check"

# ---------------------------------------------------------------------------
# 2. Remote engines not loaded - SKIP with a clear reason, not a crash
# ---------------------------------------------------------------------------
Remove-Item function:Get-CARenewalTemplateOid, function:Get-CARenewalTestCert -ErrorAction SilentlyContinue
$r2 = @(Get-CAHealthReport -CAAnswers $baseAnswers -Status $baseStatus -RemoteClientComputerName 'VPNCLIENT01' -RemoteClientTemplateCn 'NSPIKEv2CONTOSO') | Where-Object Id -eq 'remote-cert'
Assert-Equal -Actual $r2.State -Expected 'SKIP' -Because "CARenewalTest.ps1 isn't loaded in this session - fails safe to SKIP, not an unhandled 'command not found'"
Assert-Match -Actual $r2.Detail -Pattern 'not loaded' -Because "the detail names the real reason"

# ---------------------------------------------------------------------------
# 3. Mocked remote engines - PASS when a cert is found
# ---------------------------------------------------------------------------
function Get-CARenewalTemplateOid { param([string]$TemplateCn) "1.3.6.1.4.1.311.21.8.$TemplateCn.test-oid" }
function Get-CARenewalTestCert {
    param([string]$TemplateOid, [string]$StoreLocation = 'CurrentUser', [string]$ComputerName)
    $script:__lastTestCertCall = @{ TemplateOid = $TemplateOid; StoreLocation = $StoreLocation; ComputerName = $ComputerName }
    if ($script:__mockCertFound) { [pscustomobject]@{ Thumbprint = 'ABCDEF1234567890'; NotAfter = (Get-Date).AddDays(300) } } else { $null }
}

$script:__mockCertFound = $true
$r3 = @(Get-CAHealthReport -CAAnswers $baseAnswers -Status $baseStatus -RemoteClientComputerName 'VPNCLIENT01' -RemoteClientTemplateCn 'NSPIKEv2CONTOSO') | Where-Object Id -eq 'remote-cert'
Assert-Equal -Actual $r3.State -Expected 'PASS' -Because "a matching cert on the remote client -> PASS"
Assert-Match -Actual $r3.Detail -Pattern 'ABCDEF1234567890' -Because "the thumbprint is surfaced in the detail"
Assert-Equal -Actual $script:__lastTestCertCall.ComputerName -Expected 'VPNCLIENT01' -Because "the client hostname is actually threaded through to Get-CARenewalTestCert"
Assert-Match -Actual $script:__lastTestCertCall.TemplateOid -Pattern 'NSPIKEv2CONTOSO' -Because "the template CN is resolved to its OID via Get-CARenewalTemplateOid first (matching on OID, not CN/display name, per that function's own documented reasoning)"

# ---------------------------------------------------------------------------
# 4. No cert found - FAIL, but the detail explicitly does NOT claim a definitive verdict (the
#    FortiGate reverse-rule caveat means this can't tell "no rule" apart from "genuinely no cert")
# ---------------------------------------------------------------------------
$script:__mockCertFound = $false
$r4 = @(Get-CAHealthReport -CAAnswers $baseAnswers -Status $baseStatus -RemoteClientComputerName 'VPNCLIENT01' -RemoteClientTemplateCn 'NSPIKEv2CONTOSO') | Where-Object Id -eq 'remote-cert'
Assert-Equal -Actual $r4.State -Expected 'FAIL' -Because "no matching cert -> FAIL"
Assert-Match -Actual $r4.Detail -Pattern 'FortiGate' -Because "the FAIL detail flags the reverse-rule caveat inline, rather than presenting this as an unambiguous verdict"

# both CurrentUser and LocalMachine are tried before giving up
Assert-Equal -Actual $script:__lastTestCertCall.StoreLocation -Expected 'LocalMachine' -Because "when CurrentUser comes back empty, LocalMachine is tried too before concluding FAIL (machine-type templates enroll there, not CurrentUser)"

# ---------------------------------------------------------------------------
# 5. A throwing remote call (e.g. WinRM unreachable) -> FAIL with the real error, not a crash
# ---------------------------------------------------------------------------
function Get-CARenewalTestCert { param([string]$TemplateOid, [string]$StoreLocation = 'CurrentUser', [string]$ComputerName) throw "Could not query the cert store on '$ComputerName' via PowerShell remoting - WinRM unreachable" }
$r5 = @(Get-CAHealthReport -CAAnswers $baseAnswers -Status $baseStatus -RemoteClientComputerName 'VPNCLIENT01' -RemoteClientTemplateCn 'NSPIKEv2CONTOSO') | Where-Object Id -eq 'remote-cert'
Assert-Equal -Actual $r5.State -Expected 'FAIL' -Because "a remoting failure still produces a row, not an unhandled exception that kills the whole health check"
Assert-Match -Actual $r5.Detail -Pattern 'WinRM unreachable' -Because "the real underlying error reaches the operator"

# ---------------------------------------------------------------------------
# 6. Invoke-CAMenuHealth - prompts for the client/template and threads them through
# ---------------------------------------------------------------------------
$srcMenu11 = (Get-Command Invoke-CAMenuHealth).Definition
Assert-Match -Actual $srcMenu11 -Pattern 'VPN client hostname to verify' -Because "menu 11 prompts for the optional remote client hostname"
Assert-Match -Actual $srcMenu11 -Pattern '-RemoteClientComputerName \$remoteClient -RemoteClientTemplateCn \$remoteTemplateCn' -Because "and threads both through to Get-CAHealthReport - checked twice: once for the report shown, once again after a fix runs"
$threadCount = ([regex]::Matches($srcMenu11, [regex]::Escape('-RemoteClientComputerName $remoteClient -RemoteClientTemplateCn $remoteTemplateCn'))).Count
Assert-Equal -Actual $threadCount -Expected 2 -Because "both the initial report and the post-fix re-check pass the same remote-client answers, not just one of them"

Write-TestSummary -Suite "CA-Manager Health Check Remote-Client Visibility"
