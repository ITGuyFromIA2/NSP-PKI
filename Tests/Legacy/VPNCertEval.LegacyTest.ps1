# Ported from NSP-FGTIPSecTools Tests\VPNCertEval.Tests.ps1 (2026-10-01): same assertions, paths re-pointed at
# this module's Private\ files. Run by Tests\Legacy.Tests.ps1 (Pester) in a child PowerShell.
<#
.SYNOPSIS
    Tests for the VPN certificate evaluation harness under
    PushableTools\CAManager\Tools\VPNCertEval\ - the pure helpers in VPNCertEval.Common.ps1 and an
    end-to-end run of Build-VPNCertEvalTargets.ps1 against a real answers file (NSP-FGTIPSecTools only).

    Repo convention (Tests\README.md) - NOT Pester.
#>

. "$PSScriptRoot\..\Shared\TestAssertions.ps1"
$PKIModuleRoot = (Resolve-Path "$PSScriptRoot\..\..").Path
Reset-TestCounters

$Root  = "C:\GitRepo\NSP-FGTIPSecTools"
$Tool  = "$PKIModuleRoot\Scripts\VPNCertEval"
$Common = "$Tool\VPNCertEval.Common.ps1"
$Build  = "$Tool\Build-VPNCertEvalTargets.ps1"
$Runner = "$Tool\Invoke-VPNCertEval.ps1"



# ---------------------------------------------------------------------------
# 0. Parse
# ---------------------------------------------------------------------------
Test-ScriptParses -Path $Common -Because "VPNCertEval.Common.ps1 parses"
Test-ScriptParses -Path $Build  -Because "Build-VPNCertEvalTargets.ps1 parses"
Test-ScriptParses -Path $Runner -Because "Invoke-VPNCertEval.ps1 parses"

. $Common

# ---------------------------------------------------------------------------
# 1. ConvertFrom-EvalPfxStem
# ---------------------------------------------------------------------------
$s1 = ConvertFrom-EvalPfxStem -Stem 'hsimpson_Internal_valid'
Assert-Equal -Actual $s1.User  -Expected 'hsimpson' -Because "stem user parsed"
Assert-Equal -Actual $s1.Label -Expected 'Internal' -Because "stem label parsed"
Assert-Equal -Actual $s1.Kind  -Expected 'valid'    -Because "stem kind parsed"
$s2 = ConvertFrom-EvalPfxStem -Stem 'jdoe_VendorA_revoked'
Assert-Equal -Actual $s2.Kind  -Expected 'revoked'  -Because "revoked kind parsed"
Assert-True  -Condition ($null -eq (ConvertFrom-EvalPfxStem -Stem 'not-a-suite-file')) -Because "non-matching stem -> null"
Assert-True  -Condition ($null -eq (ConvertFrom-EvalPfxStem -Stem 'a_b_pending')) -Because "unknown kind -> null"

# ---------------------------------------------------------------------------
# 2. ConvertFrom-EvalQuotedList
# ---------------------------------------------------------------------------
$q1 = ConvertFrom-EvalQuotedList '"10.0.15.201" "10.0.15.202" "10.0.15.135"'
Assert-Equal -Actual $q1.Count -Expected 3 -Because "three quoted items"
Assert-Equal -Actual $q1[1] -Expected '10.0.15.202' -Because "second quoted item"
$q2 = ConvertFrom-EvalQuotedList 'bare1 bare2'
Assert-Equal -Actual $q2.Count -Expected 2 -Because "whitespace fallback when unquoted"
Assert-Equal -Actual (ConvertFrom-EvalQuotedList '').Count -Expected 0 -Because "empty string -> empty"
Assert-Equal -Actual (ConvertFrom-EvalQuotedList $null).Count -Expected 0 -Because "null -> empty"

# ---------------------------------------------------------------------------
# 3. Get-CertSubjectOU
# ---------------------------------------------------------------------------
$ou = Get-CertSubjectOU -Subject 'CN=Homer Simpson, OU=Sales, OU=VPN Users, DC=corp, DC=local'
Assert-Equal -Actual $ou.Count -Expected 2 -Because "two OU RDNs"
Assert-Equal -Actual $ou[0] -Expected 'Sales' -Because "outermost OU first (as X.500 prints)"
Assert-Equal -Actual $ou[1] -Expected 'VPN Users' -Because "second OU"
Assert-Equal -Actual (Get-CertSubjectOU -Subject 'CN=nobody, DC=x').Count -Expected 0 -Because "no OU -> empty"

# ---------------------------------------------------------------------------
# 4. Get-CertUtilRevocationVerdict
# ---------------------------------------------------------------------------
$goodTxt = @'
  Issuer: CN=Contoso-CA, DC=Contoso, DC=local
  ----------------  Verifying CRL  ----------------
  Verified "Base CRL (05)" Time: 0
  ---- OCSP URL ----  http://ocsp.example/ocsp
  Verified "OCSP" Time: 0
  Leaf certificate revocation check passed
CertUtil: -verify command completed successfully.
'@
$v = Get-CertUtilRevocationVerdict -Text $goodTxt
Assert-Equal -Actual $v.Verdict -Expected 'Good' -Because "clean chain -> Good"
Assert-True  -Condition $v.CrlChecked  -Because "a CRL was verified"
Assert-True  -Condition $v.OcspChecked -Because "an OCSP responder was verified"

$revTxt = @'
  ERROR: Verifying leaf certificate revocation status returned The certificate is revoked. 0x80092010 (-2146885616 CRYPT_E_REVOKED)
  CertUtil: -verify command FAILED: 0x80092010 (-2146885616)
'@
$vr = Get-CertUtilRevocationVerdict -Text $revTxt
Assert-Equal -Actual $vr.Verdict -Expected 'Revoked' -Because "CRYPT_E_REVOKED -> Revoked"
Assert-True  -Condition $vr.Revoked -Because "revoked flag set"

$offTxt = @'
  ERROR: The revocation function was unable to check revocation because the revocation server was offline. 0x80092013 (CRYPT_E_REVOCATION_OFFLINE)
'@
$vo = Get-CertUtilRevocationVerdict -Text $offTxt
Assert-Equal -Actual $vo.Verdict -Expected 'Undetermined' -Because "offline responder -> Undetermined (not Good, not Revoked)"
Assert-True  -Condition $vo.Offline -Because "offline flag set"
Assert-Equal -Actual (Get-CertUtilRevocationVerdict -Text '').Verdict -Expected 'Undetermined' -Because "empty text -> Undetermined"

# ---------------------------------------------------------------------------
# 5. Service catalogue + name heuristics
# ---------------------------------------------------------------------------
$cat = Get-EvalServiceCatalog
Assert-True  -Condition (@($cat['RDP'].TCP) -contains 3389) -Because "RDP catalogue entry is TCP 3389"
Assert-True  -Condition ($cat.Contains('Ping')) -Because "Ping is a catalogue key (special-cased to ICMP)"
Assert-True  -Condition (@(Get-EvalServiceNamesForGroup -ServiceGroupName 'IKEv2_AS400_Services') -contains 'RDP') -Because "AS400 service group -> RDP"
$unk = Get-EvalServiceNamesForGroup -ServiceGroupName 'Totally_Unknown_Group'
Assert-True  -Condition (@($unk) -contains 'Ping') -Because "unknown service group falls back to Ping"

# ---------------------------------------------------------------------------
# 6. ConvertTo-EvalPsd1 round-trips through Import-PowerShellDataFile
# ---------------------------------------------------------------------------
$sample = [ordered]@{
    Company = "Acme's Co"
    Count   = 3
    Flag    = $true
    Empty   = @()
    Svc     = [ordered]@{ RDP = @{ TCP = @(3389); UDP = @() } }
    List    = @( [ordered]@{ Host = '10.0.0.1'; Services = @('RDP', 'Ping'); Expect = 'Allow' } )
}
$psd1Text = ConvertTo-EvalPsd1 -InputObject $sample
$tmp = Join-Path $env:TEMP ("evalpsd1_{0}.psd1" -f ([guid]::NewGuid().ToString('N')))
Set-Content -Path $tmp -Value $psd1Text -Encoding UTF8
$back = Import-PowerShellDataFile -Path $tmp
Remove-Item $tmp -Force
Assert-Equal -Actual $back.Company -Expected "Acme's Co" -Because "apostrophe survives the round trip"
Assert-Equal -Actual $back.Count -Expected 3 -Because "int survives"
Assert-Equal -Actual $back.Flag -Expected $true -Because "bool survives"
Assert-Equal -Actual @($back.Empty).Count -Expected 0 -Because "empty array survives"
Assert-Equal -Actual (@($back.Svc.RDP.TCP)[0]) -Expected 3389 -Because "nested port survives"
Assert-Equal -Actual $back.List[0].Host -Expected '10.0.0.1' -Because "nested list-of-hashtable survives"
Assert-Equal -Actual @($back.List[0].Services).Count -Expected 2 -Because "nested services array survives"

# ---------------------------------------------------------------------------
# 7. Invoke-EvalReachabilityMatrix (probe override - no real sockets)
# ---------------------------------------------------------------------------
$sc = Get-EvalServiceCatalog
$eps = @(
    [ordered]@{ Host = '10.0.0.1'; Name = 'allow-hit';  Services = @('RDP');  Expect = 'Allow' }
    [ordered]@{ Host = '10.0.0.9'; Name = 'block-clean'; Services = @('RDP');  Expect = 'Block' }
    [ordered]@{ Host = '10.0.0.1'; Name = 'block-leak';  Services = @('RDP');  Expect = 'Block' }
    [ordered]@{ Host = '10.0.0.5'; Name = 'ping-only';   Services = @('Ping'); Expect = 'Allow' }
)
$override = { param($h, $proto, $port) ($h -eq '10.0.0.1') }   # only .1 answers anything
$mx = Invoke-EvalReachabilityMatrix -Endpoints $eps -ServiceChecks $sc -ProbeOverride $override
Assert-Equal -Actual $mx[0].Verdict -Expected 'Allow' -Because "reachable Allow endpoint -> Allow"
Assert-True  -Condition $mx[0].Match -Because "Allow endpoint reachable -> Match"
Assert-Equal -Actual $mx[1].Verdict -Expected 'Block' -Because "unreachable Block endpoint -> Block"
Assert-True  -Condition $mx[1].Match -Because "Block endpoint unreachable -> Match"
Assert-Equal -Actual $mx[2].Verdict -Expected 'Allow' -Because "reachable but expected Block -> Allow verdict"
Assert-False -Condition $mx[2].Match -Because "reachable Block endpoint -> Match FALSE (leak)"
Assert-Equal -Actual $mx[3].Verdict -Expected 'Block' -Because "ping-only endpoint not answering -> Block"

# ---------------------------------------------------------------------------
# NSP.PKI: sections 8-9 (ConvertFrom-UnitTestsFile and Build-VPNCertEvalTargets end to end) read real
# client data from NSP-FGTIPSecTools (Examples_Sources\, ClientAnswers\) - they stay in that repo's copy.
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# 10. Runner source-introspection - the shape we promised
# ---------------------------------------------------------------------------
$runSrc = Get-Content $Runner -Raw
Assert-Match -Actual $runSrc -Pattern 'Import-PfxCertificate' -Because "runner imports each PFX"
Assert-Match -Actual $runSrc -Pattern 'certutil\.exe -f -urlfetch -verify' -Because "runner does an offline CRL/OCSP verify"
Assert-Match -Actual $runSrc -Pattern 'Remove-Item .*Cert:\\' -Because "runner cleans up the imported cert unless -KeepCerts"
Assert-Match -Actual $runSrc -Pattern 'Wait-EvalTunnel' -Because "runner auto-detects tunnel up/down"
Assert-Match -Actual $runSrc -Pattern 'Disconnect FortiClient' -Because "runner has the manual disconnect gate"
Assert-Match -Actual $runSrc -Pattern 'ImportExcel' -Because "runner writes xlsx when ImportExcel is available"
Assert-NoMatch -Actual $runSrc -Pattern 'Read-Host .*[Pp]assword.*User|username.*password' -Because "runner does NOT prompt for / inject VPN credentials (MFA is interactive)"

Write-TestSummary -Suite "VPN cert evaluation harness"
