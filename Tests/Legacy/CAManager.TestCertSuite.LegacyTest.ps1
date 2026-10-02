# Ported from NSP-FGTIPSecTools Tests\CAManager.TestCertSuite.Tests.ps1 (2026-10-01): same assertions, paths re-pointed at
# this module's Private\ files. Run by Tests\Legacy.Tests.ps1 (Pester) in a child PowerShell.
<#
.SYNOPSIS
    Tests for CA Manager - Phase 2: the shared Request-VPNCertCore.ps1 engine (extracted from
    Request-VPNCert.ps1), the thin Request-VPNCert.ps1 wrapper, and Modules\CATestSuite.ps1's
    New-CATestCertSuite (menu option 8 - per user type, one valid + one revoked cert).

    Repo convention (Tests\README.md / TestAssertions.ps1) - NOT Pester. AST-extract one function,
    Invoke-Expression it, mock deps by defining same-named functions afterwards.
#>

. "$PSScriptRoot\..\Shared\TestAssertions.ps1"
$PKIModuleRoot = (Resolve-Path "$PSScriptRoot\..\..").Path
Reset-TestCounters

$Repo        = "C:\GitRepo\NSP-FGTIPSecTools"
$Core        = Join-Path $PKIModuleRoot "Private\Engine\Request-VPNCertCore.ps1"
$Wrapper     = Join-Path $Repo "IPSEC AIO\MiscTools\Tools\Request-VPNCert.ps1"
$TestSuite   = Join-Path $PKIModuleRoot "Private\CATestSuite.ps1"
$Interactive = Join-Path $PKIModuleRoot "Private\CAInteractive.ps1"
$BuildZip    = Join-Path $PKIModuleRoot "Build-CAManagerZip.ps1"
$Dashboard   = Join-Path $PKIModuleRoot "Tests\Legacy\_CA-Manager.combined.ps1"

# ---------------------------------------------------------------------------
# 1. Parse checks
# ---------------------------------------------------------------------------
Test-ScriptParses -Path $Core        -Because "Request-VPNCertCore.ps1 parses cleanly"
# NSP.PKI: the wrapper and the zip build stay in NSP-FGTIPSecTools - checked there.
# Test-ScriptParses -Path $Wrapper     -Because "Request-VPNCert.ps1 (thin wrapper) parses cleanly"
Test-ScriptParses -Path $TestSuite   -Because "CATestSuite.ps1 parses cleanly"
Test-ScriptParses -Path $Interactive -Because "CAInteractive.ps1 parses cleanly after Test-SecureStringMatch"
# Test-ScriptParses -Path $BuildZip    -Because "Build-CAManagerZip.ps1 parses cleanly after the core-bundle step"
Test-ScriptParses -Path $Dashboard   -Because "CA-Manager.ps1 parses cleanly after wiring option 8"

# ---------------------------------------------------------------------------
# 2. Request-VPNCert.ps1 - thin wrapper: params + dot-sources core, no inline request logic
# ---------------------------------------------------------------------------
<# NSP.PKI: checked in NSP-FGTIPSecTools
$rawWrap = Get-Content -Path $Wrapper -Raw
Assert-Match    -Actual $rawWrap -Pattern "\`$TemplateName = 'IKEv2VPN-InternalUsers-MANUAL'" -Because "wrapper keeps the manual template as the default (2026-09-15: renamed from the CLIENTA-specific 'IKEv2VPN-CorpLAN-MANUAL')"
Assert-Match    -Actual $rawWrap -Pattern "\`$OutputDir\s*=\s*'C:\\admin'"              -Because "OutputDir is a parameter with the historical default, not a hardcoded literal mid-script"
Assert-Match    -Actual $rawWrap -Pattern "\[string\]\`$UserName"                        -Because "wrapper exposes -UserName to seed the AD search"
Assert-Match    -Actual $rawWrap -Pattern "\. \(Join-Path \`$PSScriptRoot 'Request-VPNCertCore\.ps1'\)" -Because "wrapper dot-sources the shared engine"
Assert-Match    -Actual $rawWrap -Pattern "Find-VPNCertADUser|New-VPNCertRequest|Complete-VPNCertRequest" -Because "wrapper drives the shared engine functions"
Assert-NoMatch  -Actual $rawWrap -Pattern "Template\s*=\s*'IKEv2VPN-InternalUsers-MANUAL'" -Because "the request-params hashtable with a hardcoded template moved into the core (parameterized)"
#>

# ---------------------------------------------------------------------------
# 3. Request-VPNCertCore.ps1 - exposes the four engine functions
# ---------------------------------------------------------------------------
$coreAst = [System.Management.Automation.Language.Parser]::ParseFile($Core, [ref]$null, [ref]$null)
$coreFns = $coreAst.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true) | ForEach-Object { $_.Name }
foreach ($fn in @('Find-VPNCertADUser', 'New-VPNCertRequest', 'Complete-VPNCertRequest', 'Revoke-VPNCert')) {
    Assert-True -Condition ([bool]($coreFns -contains $fn)) -Because "Request-VPNCertCore.ps1 defines $fn"
}

# ---------------------------------------------------------------------------
# 4. New-VPNCertRequest - request shape (DnsName = mail+DN, SubjectName = "E=<mail>, <DN>", template passed through)
# ---------------------------------------------------------------------------
Invoke-Expression (Get-FunctionSource -Path $Core -FunctionName 'New-VPNCertRequest')
Invoke-Expression (Get-FunctionSource -Path $Core -FunctionName 'Resolve-VPNCertTemplateName')
$script:__gcParams = $null
function Get-Certificate {
    param($Template, $DnsName, $SubjectName, $CertStoreLocation, $Url, $Request)
    $script:__gcParams = $PSBoundParameters
    [pscustomobject]@{ Request = [pscustomobject]@{ Subject = 'CN=test'; Thumbprint = 'THUMB1' } }
}
# certutil returns nothing here -> Resolve-VPNCertTemplateName passes the name through unchanged
function certutil.exe { $global:LASTEXITCODE = 1; '' }
$fakeUser = [pscustomobject]@{ mail = 'jdoe@corp.example'; DistinguishedName = 'CN=John Doe,OU=Users,DC=corp,DC=example'; SamAccountName = 'jdoe' }
$req = New-VPNCertRequest -ADUser $fakeUser -TemplateName 'MyManualTemplate'
Assert-Equal    -Actual $script:__gcParams['Template'] -Expected 'MyManualTemplate' -Because "the resolved template CN is passed to Get-Certificate (unchanged here - certutil unavailable in the test)"
Assert-Equal    -Actual ($script:__gcParams['DnsName'] -join '|') -Expected 'jdoe@corp.example|CN=John Doe,OU=Users,DC=corp,DC=example' -Because "DnsName SAN = mail then DN"
Assert-Equal    -Actual $script:__gcParams['SubjectName'] -Expected 'E=jdoe@corp.example, CN=John Doe,OU=Users,DC=corp,DC=example' -Because "SubjectName is the historical 'E=<mail>, <DN>' shape"
Assert-Equal    -Actual $req.Request.Thumbprint -Expected 'THUMB1' -Because "returns Get-Certificate's result object"

# --- 2026-09-15 live bug at CLIENTA: a user with no 'mail' attribute set (several of CLIENTA's own
#     per-group test accounts) used to get a malformed "E=, CN=..." subject (an empty-valued
#     emailAddress RDN) - TameMyCerts's own CA-log entry showed it verbatim as 'E="", CN=...'. The
#     E= RDN must be omitted entirely, not emitted with an empty value, when there's no mail attribute ---
$noMailUser = [pscustomobject]@{ mail = $null; DistinguishedName = 'CN=Plant Tester,OU=Test,DC=corp,DC=example'; SamAccountName = 'plant' }
New-VPNCertRequest -ADUser $noMailUser -TemplateName 'MyManualTemplate' | Out-Null
Assert-Equal -Actual $script:__gcParams['SubjectName'] -Expected 'CN=Plant Tester,OU=Test,DC=corp,DC=example' -Because "no 'E=' prefix at all when mail is blank - not 'E=, CN=...'"
Assert-Equal -Actual ($script:__gcParams['DnsName'] -join '|') -Expected 'CN=Plant Tester,OU=Test,DC=corp,DC=example' -Because "DnsName SAN still drops the blank mail entry (unchanged, pre-existing behavior)"

# --- Resolve-VPNCertTemplateName maps display name -> CN from certutil -CATemplates ---
function certutil.exe {
    @('IKEv2VPNCorpLANMANUAL: IKEv2VPN-CorpLAN-MANUAL -- Auto-Enroll',
      'FortiGate: FortiGate -- Auto-Enroll') -join "`r`n"
}
Assert-Equal -Actual (Resolve-VPNCertTemplateName -Name 'IKEv2VPN-CorpLAN-MANUAL') -Expected 'IKEv2VPNCorpLANMANUAL' -Because "a display name resolves to the CN certutil reports"
Assert-Equal -Actual (Resolve-VPNCertTemplateName -Name 'IKEv2VPNCorpLANMANUAL')  -Expected 'IKEv2VPNCorpLANMANUAL' -Because "a name that's already a CN is returned as-is"
Assert-Equal -Actual (Resolve-VPNCertTemplateName -Name 'FortiGate')              -Expected 'FortiGate'              -Because "CN == display name still works"
Assert-Equal -Actual (Resolve-VPNCertTemplateName -Name 'NoSuchTemplate')         -Expected 'NoSuchTemplate'         -Because "an unknown name is passed through unchanged"

Remove-Item function:Get-Certificate, function:New-VPNCertRequest, function:Resolve-VPNCertTemplateName, function:certutil.exe -ErrorAction SilentlyContinue

# ---------------------------------------------------------------------------
# 5. Complete-VPNCertRequest - Issued -> exports PFX + a public-key-only .cer + returns serial;
#    not-Issued -> neither is exported
#
#    2026-09-15, per the maintainer (re: menu 11): "why didn't I have you do it during generation time" -
#    the .cer (public cert, no private key) is now exported in the SAME step as the PFX, not a
#    separate later pass.
# ---------------------------------------------------------------------------
Invoke-Expression (Get-FunctionSource -Path $Core -FunctionName 'Complete-VPNCertRequest')
function Test-Path { return $true }
function New-Item  { }
$script:__pfxArgs = $null
function Export-PfxCertificate { param($Cert, $FilePath, $Password) $script:__pfxArgs = $PSBoundParameters }
$script:__cerArgs = $null
function Export-Certificate { param($Cert, $FilePath, $Type) $script:__cerArgs = $PSBoundParameters }
function Get-Certificate {
    param($Request)
    [pscustomobject]@{ Status = 'Issued'; Certificate = [pscustomobject]@{ Thumbprint = 'TB99'; SerialNumber = 'AB12CD34' } }
}
$sec = ConvertTo-SecureString 'pw' -AsPlainText -Force
$done = Complete-VPNCertRequest -RequestObject ([pscustomobject]@{ Request = 'r' }) -OutputDir 'C:\out' -PfxPassword $sec -FileNameStem 'jdoe_Internal_valid'
Assert-Equal -Actual $done.Status       -Expected 'Issued'   -Because "reports the issued status"
Assert-Equal -Actual $done.SerialNumber -Expected 'AB12CD34' -Because "captures the serial number (needed for a later revoke)"
Assert-Match -Actual $done.PfxPath      -Pattern 'jdoe_Internal_valid\.pfx$' -Because "PFX path uses the supplied file-name stem"
Assert-Match -Actual $done.CerPath      -Pattern 'jdoe_Internal_valid\.cer$' -Because "the .cer is exported alongside the PFX, same file-name stem"
Assert-Match -Actual "$($script:__pfxArgs['Cert'])" -Pattern 'Cert:\\CurrentUser\\My\\TB99' -Because "exports the retrieved cert by thumbprint"
Assert-Match -Actual "$($script:__cerArgs['Cert'])" -Pattern 'Cert:\\CurrentUser\\My\\TB99' -Because "the .cer export uses the SAME resolved cert path as the PFX export - not re-derived separately"
Assert-Equal -Actual "$($script:__cerArgs['Type'])" -Expected 'CERT' -Because "public-key-only .cer, not a PKCS7 (.p7b) bundle or serialized store (.sst)"

# --- a .cer export failure doesn't blank out an already-successful PFX export ---
function Export-Certificate { param($Cert, $FilePath, $Type) throw "disk full" }
$cerFail = Complete-VPNCertRequest -RequestObject ([pscustomobject]@{ Request = 'r' }) -OutputDir 'C:\out' -PfxPassword $sec -FileNameStem 'jdoe_cerfail'
Assert-Equal -Actual $cerFail.Status  -Expected 'Issued' -Because "a failed .cer export doesn't demote an already-Issued/exported result"
Assert-Match -Actual $cerFail.PfxPath -Pattern 'jdoe_cerfail\.pfx$' -Because "the PFX is still exported and reported even if the .cer export throws"
Assert-Equal -Actual $cerFail.CerPath -Expected $null -Because "CerPath is null (not a fabricated path) when the .cer export itself failed"
function Export-Certificate { param($Cert, $FilePath, $Type) $script:__cerArgs = $PSBoundParameters }

function Get-Certificate { [pscustomobject]@{ Status = 'Pending'; Certificate = $null } }
$pending = Complete-VPNCertRequest -RequestObject ([pscustomobject]@{ Request = 'r' }) -OutputDir 'C:\out' -PfxPassword $sec -FileNameStem 'x'
Assert-Equal -Actual $pending.Status  -Expected 'Pending' -Because "a not-yet-approved request reports its status"
Assert-Equal -Actual $pending.PfxPath -Expected $null     -Because "nothing is exported for a non-Issued request"
Assert-Equal -Actual $pending.CerPath -Expected $null     -Because "including no .cer"
Remove-Item function:Get-Certificate, function:Export-PfxCertificate, function:Export-Certificate, function:Test-Path, function:New-Item, function:Complete-VPNCertRequest -ErrorAction SilentlyContinue

# ---------------------------------------------------------------------------
# 6. Revoke-VPNCert - certutil -revoke <serial> <reason>, then certutil -CRL when -RepublishCrl
# ---------------------------------------------------------------------------
Invoke-Expression (Get-FunctionSource -Path $Core -FunctionName 'Revoke-VPNCert')
$script:__cu = New-Object System.Collections.Generic.List[string]
function certutil.exe { $script:__cu.Add(($args -join ' ')); "CertUtil: command completed successfully." }
$rev = Revoke-VPNCert -SerialNumber 'AB12CD34' -ReasonCode 4 -RepublishCrl
Assert-True  -Condition ([bool]$rev.Revoked)        -Because "a 'completed successfully' from certutil -revoke marks it revoked"
Assert-True  -Condition ([bool]$rev.CrlRepublished) -Because "-RepublishCrl runs certutil -CRL after a successful revoke"
Assert-Contains -Haystack ($script:__cu -join ' || ') -Needle "-revoke AB12CD34 4" -Because "revoke passes the serial and the numeric reason code"
Assert-Contains -Haystack ($script:__cu -join ' || ') -Needle "-CRL"               -Because "the CRL republish call is made"
Remove-Item function:certutil.exe, function:Revoke-VPNCert -ErrorAction SilentlyContinue

# ---------------------------------------------------------------------------
# 6b. Find-VPNCertADUser - two real live bugs at CLIENTA, 2026-09-15:
#     (a) the multi-match picker table CRASHED ("Index (zero based) must be...") - '-f' binds
#         TIGHTER than '+' in PowerShell, so the header row's format call ran with only ONE value
#         against a 3-placeholder format string.
#     (b) "if it finds 0, return and have the tech re-do the search" - a 0-match search needed a way
#         to hand control back to a CALLER with its own retry/skip prompt (menu 11), instead of
#         always looping forever inside here with this function's own generic message.
# ---------------------------------------------------------------------------
Invoke-Expression (Get-FunctionSource -Path $Core -FunctionName 'Find-VPNCertADUser')

# --- exactly one match -> returned directly, no prompt at all ---
function Get-ADUser { param($Filter, $Properties) @([pscustomobject]@{ SamAccountName = 'jdoe'; UserPrincipalName = 'jdoe@corp'; mail = 'jdoe@corp'; DistinguishedName = 'CN=jdoe' }) }
$one = Find-VPNCertADUser -SearchTerm 'jdoe'
Assert-Equal -Actual $one.SamAccountName -Expected 'jdoe' -Because "a single match is returned with no prompt"

# --- zero matches + -ReturnNullOnNoMatch: returns $null immediately, no internal reprompt ---
function Get-ADUser { param($Filter, $Properties) @() }
function Read-Host { param($Prompt) throw "Read-Host should not be called - ReturnNullOnNoMatch must return before any reprompt (prompt was: '$Prompt')" }
$zero = Find-VPNCertADUser -SearchTerm 'nobody' -ReturnNullOnNoMatch
Assert-Equal -Actual $zero -Expected $null -Because "0 matches + -ReturnNullOnNoMatch -> returns null immediately, letting the CALLER (menu 11's per-template loop) redo the search with its own 'blank to skip' prompt"
Remove-Item function:Read-Host -ErrorAction SilentlyContinue

# --- zero matches, NonInteractive: still throws regardless of -ReturnNullOnNoMatch (batch mode has
#     no caller to hand control back to) ---
$niThrew = $false
try { Find-VPNCertADUser -SearchTerm 'nobody' -NonInteractive -ReturnNullOnNoMatch } catch { $niThrew = $true }
Assert-True -Condition $niThrew -Because "-NonInteractive still throws on 0 matches even with -ReturnNullOnNoMatch set - batch mode has no interactive caller to redo the search"

# --- zero matches, DEFAULT (no -ReturnNullOnNoMatch): loops internally, re-prompting with its own
#     generic message - Request-VPNCert.ps1's standalone interactive behavior, unchanged ---
$script:__rhQ = [System.Collections.Generic.Queue[string]]::new()
@('jdoe') | ForEach-Object { $script:__rhQ.Enqueue($_) }
function Get-ADUser { param($Filter) if ($Filter -match 'typo') { @() } else { @([pscustomobject]@{ SamAccountName = 'jdoe'; UserPrincipalName = 'jdoe@corp'; mail = 'jdoe@corp'; DistinguishedName = 'CN=jdoe' }) } }
function Read-Host { param($Prompt) $script:__rhQ.Dequeue() }
$retried = Find-VPNCertADUser -SearchTerm 'typo'
Remove-Item function:Read-Host -ErrorAction SilentlyContinue
Assert-Equal -Actual $retried.SamAccountName -Expected 'jdoe' -Because "default behavior (no -ReturnNullOnNoMatch) still re-prompts internally until a match is found - Request-VPNCert.ps1's standalone flow is unchanged"

# --- multi-match: the picker table must render WITHOUT throwing (the real live crash) ---
function Get-ADUser { param($Filter) @(
    [pscustomobject]@{ SamAccountName = 'jdoe1'; UserPrincipalName = 'jdoe1@corp'; mail = 'a@corp'; DistinguishedName = 'CN=a' }
    [pscustomobject]@{ SamAccountName = 'jdoe2'; UserPrincipalName = 'jdoe2@corp'; mail = 'b@corp'; DistinguishedName = 'CN=b' }
) }
function Read-Host { param($Prompt) '1' }
$threwOnTable = $false
$picked = $null
try { $picked = Find-VPNCertADUser -SearchTerm 'jdoe' } catch { $threwOnTable = $true }
Remove-Item function:Read-Host -ErrorAction SilentlyContinue
Assert-False -Condition $threwOnTable -Because "the multi-match picker table must render without throwing 'Index (zero based) must be...' - this is the exact crash hit live at CLIENTA with 2 and 5 matches"
Assert-Equal -Actual $picked.SamAccountName -Expected 'jdoe2' -Because "index 1 of the 2 matches is picked correctly once the table renders"

Remove-Item function:Get-ADUser, function:Find-VPNCertADUser -ErrorAction SilentlyContinue

# ---------------------------------------------------------------------------
# 7. New-CATestCertSuite - order gate, numbered pick-list of manual-approval templates
#    (2026-09-15, per the maintainer: "list the available 'Manual approval' certs and let me pick from a
#    numbered list? Then as it cycles through the picked ones we'll need to prompt for username"),
#    then 1 valid + 1 revoked per PICKED TEMPLATE + summary file
# ---------------------------------------------------------------------------
Invoke-Expression (Get-FunctionSource -Path $TestSuite -FunctionName 'New-CATestCertSuite')

# common mocks
function Write-CAHeader { param($Title) }
function Test-SecureStringMatch { param($A, $B) $true }
function Test-Path { param($Path) $true }
function New-Item  { }
function Get-CAManualApprovalTemplates {
    @(
        [pscustomobject]@{ Cn = 'IKEv2VPNCorpLANMANUAL'; DisplayName = 'IKEv2VPN-CorpLAN-MANUAL' }
        [pscustomobject]@{ Cn = 'NSPIKEv2PSGIMANUAL';    DisplayName = 'NSP-IKEv2-PSGI-MANUAL' }
    )
}
function Find-VPNCertADUser { param($SearchTerm) if ([string]::IsNullOrWhiteSpace($SearchTerm)) { return $null } [pscustomobject]@{ SamAccountName = "u_$SearchTerm"; UserPrincipalName = "u_$SearchTerm@corp"; mail = "$SearchTerm@corp"; DistinguishedName = "CN=$SearchTerm" } }
function New-VPNCertRequest { param($ADUser, $TemplateName) [pscustomobject]@{ Request = [pscustomobject]@{ Subject = "CN=$($ADUser.SamAccountName)"; Thumbprint = 'T' } } }
function Complete-VPNCertRequest { param($RequestObject, $OutputDir, $PfxPassword, $FileNameStem) [pscustomobject]@{ Status = 'Issued'; Thumbprint = "TB_$FileNameStem"; SerialNumber = "SER_$FileNameStem"; PfxPath = (Join-Path $OutputDir "$FileNameStem.pfx"); CerPath = (Join-Path $OutputDir "$FileNameStem.cer") } }
$script:__revokeCalls = New-Object System.Collections.Generic.List[string]
function Revoke-VPNCert { param($SerialNumber, $ReasonCode, [switch]$RepublishCrl) $script:__revokeCalls.Add("$SerialNumber/$ReasonCode/$RepublishCrl"); [pscustomobject]@{ Revoked = $true; CrlRepublished = $false } }
$script:__certutilCalls = New-Object System.Collections.Generic.List[string]
function certutil.exe { $script:__certutilCalls.Add(($args -join ' ')); $global:LASTEXITCODE = 0; '' }
$script:__summary = $null
function Set-Content { param($Path, $Value, $Encoding) $script:__summary = [pscustomobject]@{ Path = $Path; Value = ($Value -join "`n") } }
$script:__caCoreLoaded = $true

# local Read-Host mock that tolerates -AsSecureString (Use-QueuedReadHost's only declares -Prompt)
$script:__rhQ = [System.Collections.Generic.Queue[string]]::new()
function Read-Host { param([string]$Prompt, [switch]$AsSecureString) if ($script:__rhQ.Count -eq 0) { throw "Read-Host queue empty (prompt: '$Prompt')" } $script:__rhQ.Dequeue() }

# --- 7a: order gate - NOT ready + a non-YES answer aborts before issuing anything (and before the
#     pick-list is even shown - Get-CAManualApprovalTemplates is mocked but must not need to be called) ---
$script:__summary = $null
@('nope', '') | ForEach-Object { $script:__rhQ.Enqueue($_) }   # YES prompt, then "Press Enter"
New-CATestCertSuite -Status ([pscustomobject]@{ IssuanceReady = $false; CACommonName = 'CONTOSO-VPN' }) -CAAnswers $null
Assert-Equal -Actual $script:__summary -Expected $null -Because "issuance NOT ready + answer != 'YES' -> aborts, no summary written, no certs issued"

# --- 7b: no published manual-approval templates at all -> a clear message, no prompts consumed ---
$script:__summary = $null
$script:__rhQ.Clear()
@('') | ForEach-Object { $script:__rhQ.Enqueue($_) }   # "Press Enter to return to the menu"
function Get-CAManualApprovalTemplates { @() }
New-CATestCertSuite -Status ([pscustomobject]@{ IssuanceReady = $true; CACommonName = 'CONTOSO-VPN' }) -CAAnswers $null
Assert-Equal -Actual $script:__summary -Expected $null -Because "no published manual-approval templates -> bails before any pick-list/password/username prompt"
function Get-CAManualApprovalTemplates {
    @(
        [pscustomobject]@{ Cn = 'IKEv2VPNCorpLANMANUAL'; DisplayName = 'IKEv2VPN-CorpLAN-MANUAL' }
        [pscustomobject]@{ Cn = 'NSPIKEv2PSGIMANUAL';    DisplayName = 'NSP-IKEv2-PSGI-MANUAL' }
    )
}

# --- 7c: ready -> pick ONE (by number) of the two published templates -> 1 valid + 1 revoked,
#     summary lists the FortiGate refresh cmds and the picked template's own DisplayName ---
$script:__revokeCalls.Clear()
$script:__certutilCalls.Clear()
$script:__summary = $null
$script:__rhQ.Clear()
@(
    '1',           # pick-list: template #1 only (IKEv2VPN-CorpLAN-MANUAL)
    '',            # output dir -> default
    'pw', 'pw',    # PFX password + confirm (Test-SecureStringMatch mocked true)
    'jdoe',        # representative username for the one picked template
    '',            # ONE "approve ALL then Enter"
    ''             # "Press Enter to return"
) | ForEach-Object { $script:__rhQ.Enqueue($_) }
New-CATestCertSuite -Status ([pscustomobject]@{ IssuanceReady = $true; CACommonName = 'CONTOSO-VPN' }) -CAAnswers ([pscustomobject]@{ Company_Name = 'CLIENTA' })

Assert-Equal    -Actual $script:__revokeCalls.Count -Expected 1 -Because "exactly one cert per picked template is revoked (the 'revoked' half of the set)"
Assert-Contains -Haystack $script:__revokeCalls[0] -Needle "/0/" -Because "revoke uses reason 0 (unspecified)"
Assert-Equal    -Actual (@($script:__certutilCalls | Where-Object { $_ -eq '-crl' }).Count) -Expected 1 -Because "the CRL is republished exactly ONCE for the whole revoked set (not per cert)"
Assert-True     -Condition ([bool]$script:__summary) -Because "a summary file is written"
Assert-Match    -Actual $script:__summary.Path  -Pattern 'CLIENTA_CertTestSuite_\d{8}_\d{6}\.txt$' -Because "summary is named <Company>_CertTestSuite_<timestamp>.txt"
Assert-Contains -Haystack $script:__summary.Value -Needle "execute vpn certificate crl update" -Because "summary hands the tech the FortiGate CRL-refresh command"
Assert-Contains -Haystack $script:__summary.Value -Needle "certificate-revoked" -Because "summary explains the expected post-revoke FortiGate behaviour"
Assert-Contains -Haystack $script:__summary.Value -Needle "IKEv2VPN-CorpLAN-MANUAL" -Because "summary lists the picked template's DisplayName"
Assert-NotContains -Haystack $script:__summary.Value -Needle "NSP-IKEv2-PSGI-MANUAL" -Because "only the PICKED template appears - the unpicked second published template is not touched"
Assert-Contains -Haystack $script:__summary.Value -Needle "SER_ujdoe_IKEv2VPNCorpLANMANUAL_revoked" -Because "summary records the revoked cert's serial (file-name stem = user_templateCN_kind, sanitized to [A-Za-z0-9])"
Assert-Match -Actual $script:__summary.Value -Pattern 'cer .*ujdoe_IKEv2VPNCorpLANMANUAL_valid\.cer' -Because "summary also lists the public-key-only .cer path exported alongside each PFX - The maintainer: 'why didn't I have you do it during generation time'"

# --- 7d: comma-separated multi-pick (both templates) -> one username prompt per picked template,
#     in list order; a blank username for one skips just that template's pair, not the whole run ---
$script:__revokeCalls.Clear()
$script:__certutilCalls.Clear()
$script:__summary = $null
$script:__rhQ.Clear()
@(
    '1,2',         # pick-list: both templates, comma-separated
    '',            # output dir -> default
    'pw', 'pw',    # PFX password + confirm
    'jdoe',        # username for template #1 (IKEv2VPN-CorpLAN-MANUAL)
    '',            # blank username for template #2 -> skipped
    '',            # ONE "approve ALL then Enter" (only template #1's pair is pending)
    ''             # "Press Enter to return"
) | ForEach-Object { $script:__rhQ.Enqueue($_) }
New-CATestCertSuite -Status ([pscustomobject]@{ IssuanceReady = $true; CACommonName = 'CONTOSO-VPN' }) -CAAnswers ([pscustomobject]@{ Company_Name = 'CLIENTA' })
Assert-Contains -Haystack $script:__summary.Value -Needle "IKEv2VPN-CorpLAN-MANUAL, NSP-IKEv2-PSGI-MANUAL" -Because "the summary's Templates: header lists every PICKED template, even one whose username prompt was skipped"
Assert-Equal    -Actual $script:__revokeCalls.Count -Expected 1 -Because "a blank username at the per-template prompt skips that template's cert pair entirely - only the CorpLAN pair (username given) was actually issued, PSGI's was not"

# --- 7e: 'A' selects every published template ---
$script:__revokeCalls.Clear()
$script:__certutilCalls.Clear()
$script:__summary = $null
$script:__rhQ.Clear()
@(
    'A',                # pick-list: all
    '',                 # output dir -> default
    'pw', 'pw',         # PFX password + confirm
    'jdoe',             # username for template #1
    'asmith',           # username for template #2
    '',                 # ONE "approve ALL then Enter"
    ''                  # "Press Enter to return"
) | ForEach-Object { $script:__rhQ.Enqueue($_) }
New-CATestCertSuite -Status ([pscustomobject]@{ IssuanceReady = $true; CACommonName = 'CONTOSO-VPN' }) -CAAnswers ([pscustomobject]@{ Company_Name = 'CLIENTA' })
Assert-Equal -Actual $script:__revokeCalls.Count -Expected 2 -Because "'A' picks both published templates, each getting its own valid+revoked pair"

# ---------------------------------------------------------------------------
# 7f-7i: 'B' (back / cancel to the menu) at every prompt point in this function - 2026-09-15, per
# The maintainer: "can we add a 'back'/'main menu' option here? and anywhere else we've missed it" - each
# point below now bails out cleanly, case-insensitively, and none of them ever reach certutil/
# Revoke-VPNCert/the summary file once cancelled.
# ---------------------------------------------------------------------------
# 7f: 'B' at the template pick-list prompt itself
$script:__revokeCalls.Clear(); $script:__certutilCalls.Clear(); $script:__summary = $null; $script:__rhQ.Clear()
@('b') | ForEach-Object { $script:__rhQ.Enqueue($_) }
New-CATestCertSuite -Status ([pscustomobject]@{ IssuanceReady = $true; CACommonName = 'CONTOSO-VPN' }) -CAAnswers ([pscustomobject]@{ Company_Name = 'CLIENTA' })
Assert-Equal -Actual $script:__summary -Expected $null -Because "'B' (case-insensitive, no confirmation prompt needed) at the template pick-list cancels immediately - no output dir/password/username prompts, no summary"
Assert-Equal -Actual $script:__rhQ.Count -Expected 0 -Because "exactly one prompt was consumed - cancelling doesn't fall through to any later prompt"

# 7g: 'BACK' (the longer form) at the output-directory prompt
$script:__summary = $null; $script:__rhQ.Clear()
@('1', 'Back') | ForEach-Object { $script:__rhQ.Enqueue($_) }
New-CATestCertSuite -Status ([pscustomobject]@{ IssuanceReady = $true; CACommonName = 'CONTOSO-VPN' }) -CAAnswers ([pscustomobject]@{ Company_Name = 'CLIENTA' })
Assert-Equal -Actual $script:__summary -Expected $null -Because "the longer 'Back' form is also accepted, at the output-directory prompt too"
Assert-Equal -Actual $script:__rhQ.Count -Expected 0 -Because "cancels before ever reaching the password prompt"

# 7h: 'B' at the PFX password prompt (decrypted just for this one comparison)
$script:__summary = $null; $script:__rhQ.Clear()
@('1', '', 'B') | ForEach-Object { $script:__rhQ.Enqueue($_) }
New-CATestCertSuite -Status ([pscustomobject]@{ IssuanceReady = $true; CACommonName = 'CONTOSO-VPN' }) -CAAnswers ([pscustomobject]@{ Company_Name = 'CLIENTA' })
Assert-Equal -Actual $script:__summary -Expected $null -Because "'B' as the PFX password itself cancels - never reaches the 'confirm password' prompt"
Assert-Equal -Actual $script:__rhQ.Count -Expected 0 -Because "the confirm-password prompt is never asked once the first one is 'B'"

# 7i: 'B' at the per-template username prompt cancels the WHOLE run, distinct from blank (skip just
#     this one template) - picking BOTH templates, then bailing on the FIRST one's username prompt,
#     must not fall through to prompting for the second template's username at all.
$script:__summary = $null; $script:__rhQ.Clear()
@('A', '', 'pw', 'pw', 'back') | ForEach-Object { $script:__rhQ.Enqueue($_) }
New-CATestCertSuite -Status ([pscustomobject]@{ IssuanceReady = $true; CACommonName = 'CONTOSO-VPN' }) -CAAnswers ([pscustomobject]@{ Company_Name = 'CLIENTA' })
Assert-Equal -Actual $script:__summary -Expected $null -Because "'B' at a per-template username prompt cancels the ENTIRE run (not just that one template) - no summary, no certs for either template"
Assert-Equal -Actual $script:__rhQ.Count -Expected 0 -Because "never falls through to a second template's own username prompt after cancelling"

Remove-Item function:Read-Host -ErrorAction SilentlyContinue
Remove-Item `
    function:Write-CAHeader, function:Test-SecureStringMatch, function:Test-Path, function:New-Item, `
    function:Get-CAManualApprovalTemplates, function:Find-VPNCertADUser, function:New-VPNCertRequest, `
    function:Complete-VPNCertRequest, function:Revoke-VPNCert, `
    function:certutil.exe, function:Set-Content, function:New-CATestCertSuite -ErrorAction SilentlyContinue

# ---------------------------------------------------------------------------
# 8. Build-CAManagerZip.ps1 bundles the shared engine; CATestSuite.ps1 locates it
# ---------------------------------------------------------------------------
<# NSP.PKI: the zip build and the zip/repo engine fallbacks are gone - the module ships the engine in Private\Engine\.
$rawBuild = Get-Content -Path $BuildZip -Raw
Assert-Match -Actual $rawBuild -Pattern '\$CoreScriptPath'                                      -Because "Build-CAManagerZip has a CoreScriptPath parameter"
Assert-Match -Actual $rawBuild -Pattern '\.\.\\\.\.\\IPSEC AIO\\MiscTools\\Tools\\Request-VPNCertCore\.ps1' -Because "it pulls the canonical Request-VPNCertCore.ps1 from MiscTools\Tools"
Assert-Match -Actual $rawBuild -Pattern 'Destination \(Join-Path \$stagingTarget "Request-VPNCertCore\.ps1"\)' -Because "it copies the engine into the zip root"

$rawSuite = Get-Content -Path $TestSuite -Raw
Assert-Match -Actual $rawSuite -Pattern 'Join-Path \$PSScriptRoot "\.\.\\Request-VPNCertCore\.ps1"' -Because "CATestSuite.ps1 finds the engine at the zip layout (peer of CA-Manager.ps1)"
Assert-Match -Actual $rawSuite -Pattern 'IPSEC AIO\\MiscTools\\Tools\\Request-VPNCertCore\.ps1'     -Because "CATestSuite.ps1 has a dev-time fallback to the repo copy"
#>
$rawSuite = Get-Content -Path $TestSuite -Raw
Assert-Match -Actual $rawSuite -Pattern 'Join-Path \$PSScriptRoot "Engine\\Request-VPNCertCore\.ps1"' -Because "NSP.PKI: CATestSuite.ps1 finds the engine the module ships in Private\Engine\"
Assert-NoMatch -Actual $rawSuite -Pattern 'Join-Path \$PSScriptRoot "\.\.\\' -Because "NSP.PKI: no zip-layout or repo-layout fallback paths"

# --- batch flow: submit-all, then ONE approval, then retrieve-all ---
$srcSuite = (Get-Command New-CATestCertSuite -ErrorAction SilentlyContinue)
if (-not $srcSuite) { Invoke-Expression (Get-FunctionSource -Path $TestSuite -FunctionName 'New-CATestCertSuite') }
$srcBody = (Get-FunctionSource -Path $TestSuite -FunctionName 'New-CATestCertSuite')
Assert-Match   -Actual $srcBody -Pattern 'PASS 1[\s\S]*?New-VPNCertRequest[\s\S]*?APPROVE ALL[\s\S]*?PASS 2[\s\S]*?Complete-VPNCertRequest' -Because "the flow is submit-all -> one approval gate -> retrieve-all"
Assert-Match   -Actual $srcBody -Pattern 'Press Enter once ALL' -Because "one approval prompt covers every request"
Assert-Match   -Actual $srcBody -Pattern 'Republishing the CRL once' -Because "one CRL republish for the whole revoked set"
Assert-NoMatch -Actual $srcBody -Pattern 'Revoke-VPNCert[^\r\n]*-RepublishCrl' -Because "revoke no longer republishes per-cert"

Write-TestSummary -Suite "CA Manager - Phase 2 (Request-VPNCert engine + test-cert suite)"
