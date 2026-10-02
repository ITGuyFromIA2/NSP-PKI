# Ported from NSP-FGTIPSecTools Tests\CAManager.TameMyCerts.Tests.ps1 (2026-10-01): same assertions, paths re-pointed at
# this module's Private\ files. Run by Tests\Legacy.Tests.ps1 (Pester) in a child PowerShell.
<#
.SYNOPSIS
    Tests for CA Manager - menu S (TameMyCerts subject-stamp policy module). PURE Get-CATameMyCertsPlan
    (template<->group derivation, OU-token sanitising, policy XML shape), read-only Test-CATameMyCerts,
    engine source-introspection, and dashboard / CLIBuilder wiring.

    Repo convention (Tests\README.md) - NOT Pester.
#>

. "$PSScriptRoot\..\Shared\TestAssertions.ps1"
$PKIModuleRoot = (Resolve-Path "$PSScriptRoot\..\..").Path
Reset-TestCounters

$Root      = "C:\GitRepo\NSP-FGTIPSecTools"
$Mod       = "$PKIModuleRoot\Private\CATameMyCerts.ps1"
$Dashboard = "$PKIModuleRoot\Tests\Legacy\_CA-Manager.combined.ps1"
$CliBuilder = "$Root\IPSEC AIO\CLIBuilder\Interactive - IPSec_IKEV2- CLI Builder V2.ps1"
$FieldMeta  = "$Root\IPSEC AIO\CLIBuilder\Modules\FieldMetadata.ps1"

Test-ScriptParses -Path $Mod       -Because "CATameMyCerts.ps1 parses"
Test-ScriptParses -Path $Dashboard -Because "CA-Manager.ps1 parses after wiring menu S"

. $Mod

# ---------------------------------------------------------------------------
# 1. ConvertTo-CATameMyCertsToken - the DN/FortiOS-safe sanitiser
# ---------------------------------------------------------------------------
Assert-Equal -Actual (ConvertTo-CATameMyCertsToken 'IKEv2_PSGI_Users') -Expected 'IKEv2_PSGI_Users' -Because "already-safe name is unchanged"
Assert-Equal -Actual (ConvertTo-CATameMyCertsToken "O'Brien Contractors") -Expected 'OBrienContractors' -Because "apostrophe + spaces stripped"
Assert-Equal -Actual (ConvertTo-CATameMyCertsToken 'Cote & R&D') -Expected 'CoteRD' -Because "ampersand + spaces stripped"
Assert-Equal -Actual (ConvertTo-CATameMyCertsToken '.foo.') -Expected 'foo' -Because "leading/trailing separators trimmed"
Assert-Equal -Actual (ConvertTo-CATameMyCertsToken '') -Expected 'VPN' -Because "empty -> VPN fallback"
Assert-Equal -Actual (ConvertTo-CATameMyCertsToken $null) -Expected 'VPN' -Because "null -> VPN fallback"
Assert-Equal -Actual (ConvertTo-CATameMyCertsToken ('x' * 80)).Length -Expected 64 -Because "capped at 64 (RDN limit for organizationalUnitName)"
Assert-Match -Actual (ConvertTo-CATameMyCertsToken 'Weird %*() Name!') -Pattern '^[A-Za-z0-9._-]+$' -Because "output is always DN/FortiOS-safe"

# ---------------------------------------------------------------------------
# 2. Get-CATameMyCertsPolicyXml - inbound Subject/SAN allow-list + the outbound OU= rewrite
#
#    2026-09-15, real live bug at CLIENTA: every per-group MANUAL template was denied with
#    CERT_E_INVALID_NAME the instant a policy file matched it - TameMyCerts's own Application-log
#    entry named the cause verbatim: "The emailAddress/commonName/organizationalUnitName/
#    domainComponent/dNSName field is not allowed." TameMyCerts is deny-by-default on every RDN/SAN
#    type actually PRESENT in the request the moment ANY policy file matches the template - this
#    session's prior assumption ("no <Subject> section => no inbound validation at all") was wrong.
#    That part of the fix (the allow-list) is confirmed live-correct. A same-day SECOND live test
#    disproved a follow-on change tried from GitHub's <Overwrite> example at the "1.8.1871.683" tag -
#    CLIENTA's actual installed module rejected it outright ("Unknown XML element Overwrite"), so
#    whatever's really running there doesn't match what's committed under that tag name upstream.
#    Reverted to <Force>, which never once threw an unknown-element error across this entire session
#    and is confirmed live-correct for the Auto per-group templates
#    (project_clienta_ikev2_corplan_peer_debug.md) - see Get-CATameMyCertsPolicyXml's own .DESCRIPTION.
# ---------------------------------------------------------------------------
$xml = Get-CATameMyCertsPolicyXml -OuValue 'PSGI'
$null = [xml]$xml   # throws if not well-formed
Assert-Contains -Haystack $xml -Needle '<Field>organizationalUnitName</Field>' -Because "stamps the OU RDN"
Assert-Contains -Haystack $xml -Needle '<Value>PSGI</Value>' -Because "with the configured token"
Assert-Contains -Haystack $xml -Needle '<Force>true</Force>' -Because "Force=true (NOT <Overwrite> - tried live at CLIENTA, the real installed module rejected it as an unknown element) => exactly one OU regardless of what subject the CA/tech already supplied (renewal idempotency)"
Assert-NoMatch  -Actual $xml -Pattern '<Overwrite>' -Because "the element that CLIENTA's real installed module actually rejected must not reappear"
Assert-Contains -Haystack $xml -Needle '<OutboundSubject>' -Because "outbound rewrite section present"
foreach ($f in @('commonName', 'organizationalUnitName', 'domainComponent', 'emailAddress')) {
    Assert-Match -Actual $xml -Pattern "(?s)<Subject>.*<Field>$f</Field>.*</Subject>" -Because "the <Subject> allow-list explicitly permits '$f' - TameMyCerts denies every field a request actually carries unless it's listed here, confirmed live (CLIENTA request 185's own TameMyCerts log line named exactly these four DN fields as 'not allowed')"
}
Assert-Match -Actual $xml -Pattern "(?s)<SubjectAlternativeName>.*<Field>dNSName</Field>.*</SubjectAlternativeName>" -Because "dNSName is allow-listed in <SubjectAlternativeName> (a DIFFERENT section than <Subject> - TameMyCerts's own maintainer: SAN fields and Subject DN fields are validated in different places) - New-VPNCertRequest's DnsName param puts both mail and the user's DN into dNSName-type SAN entries, and TameMyCerts's log named 'dNSName' as denied too"
$subjIdx = $xml.IndexOf('<Subject>')
$sanIdx  = $xml.IndexOf('<SubjectAlternativeName>')
$outIdx  = $xml.IndexOf('<OutboundSubject>')
Assert-True -Condition ($subjIdx -ge 0 -and $subjIdx -lt $sanIdx -and $sanIdx -lt $outIdx) -Because "<Subject>, then <SubjectAlternativeName>, then <OutboundSubject> - the element ORDER the pinned-tag example file uses (TameMyCerts's XML (de)serializer is sequence-sensitive)"

# ---------------------------------------------------------------------------
# 3. Get-CATameMyCertsPlan - derivation from RadiusGroupPairs
# ---------------------------------------------------------------------------
$answers = [pscustomobject]@{
    CA_SubjectStampMode = 'TameMyCerts'
    CA_TemplateAuto     = 'IKEv2VPN-CorpLAN'
    CA_AutoEnrollGroup  = 'IKEv2_MasterGroup'
    RadiusGroupPairs    = @(
        [pscustomobject]@{ Label = 'PSGI';  UserGroupName = 'IKEv2_PSGI_Users' }
        [pscustomobject]@{ Label = 'PRDP';  UserGroupName = 'IKEv2_PlantDT_RDP_1' }
        [pscustomobject]@{ Label = 'Audit'; UserGroupName = 'IKEv2_Audit_Users'; CertSubjectOu = 'AUD' }
        # real CONTOSO shape (2026-09-10 live bug): UserGroupName is a friendlier label, NOT reliably a
        # real AD group - UserGroupValue is the actual AD security group. Both populated here.
        [pscustomobject]@{ Label = 'CONTOSO'; UserGroupName = 'IKEv2_UserGroup'; UserGroupValue = 'IKEv2_InternalUsers' }
    )
}

$plan = Get-CATameMyCertsPlan -CAAnswers $answers
Assert-True  -Condition $plan.Applicable -Because "CA_SubjectStampMode=TameMyCerts -> applicable"
Assert-Equal -Actual $plan.Version -Expected '1.8.1871.683' -Because "pinned TameMyCerts community version"
Assert-Equal -Actual $plan.ActiveProgId -Expected 'TameMyCerts.Policy' -Because "the ProgID install.ps1 repoints PolicyModules\\Active to"
Assert-Equal -Actual $plan.DefaultProgId -Expected 'CertificateAuthority_MicrosoftDefault.Policy' -Because "the MS default it daisy-chains / reverts to"
Assert-Equal -Actual $plan.DotNetMajor -Expected 10 -Because "1.8 requires the .NET 10 Desktop Runtime"
Assert-Equal -Actual @($plan.TemplatePolicies).Count -Expected 8 -Because "TWO policy files per RADIUS group pair now (2026-09-15) - the Auto template AND its manual counterpart (the maintainer: 'wire this in to TameMyCerts. Same flow.') - 4 pairs x 2"

$contosoAuto = @($plan.TemplatePolicies | Where-Object { $_.GroupLabel -eq 'CONTOSO' -and $_.TemplateDisplayName -notlike '*-MANUAL' })[0]
Assert-Equal -Actual $contosoAuto.UserGroupName -Expected 'IKEv2_InternalUsers' -Because "UserGroupVALUE wins over UserGroupName - it's the real AD group (live bug 2026-09-10: 'IKEv2_UserGroup' doesn't resolve to a SID, 'IKEv2_InternalUsers' does)"
Assert-Equal -Actual $contosoAuto.OuValue -Expected 'IKEv2_InternalUsers' -Because "and the OU stamp reflects the same real group, not the friendlier label"

$psgi = @($plan.TemplatePolicies | Where-Object { $_.GroupLabel -eq 'PSGI' -and $_.TemplateDisplayName -notlike '*-MANUAL' })[0]
Assert-Equal -Actual $psgi.TemplateDisplayName -Expected 'NSP-IKEv2-PSGI' -Because "DisplayName = <prefix><sanitised label>"
Assert-Equal -Actual $psgi.TemplateCn -Expected 'NSPIKEv2PSGI' -Because "CN = the display name with non-alphanumerics stripped (matches New-CAVpnTemplate)"
Assert-Equal -Actual $psgi.OuValue -Expected 'IKEv2_PSGI_Users' -Because "OU token defaults to the sanitised UserGroupName"
Assert-Equal -Actual $psgi.FileName -Expected 'NSPIKEv2PSGI.xml' -Because "policy file is named after the template CN"
Assert-Contains -Haystack $psgi.Xml -Needle '<Value>IKEv2_PSGI_Users</Value>' -Because "the XML carries that token"
Assert-Contains -Haystack "$($psgi.FilePath)" -Needle 'C:\PolicyFiles\NSPIKEv2PSGI.xml' -Because "default policy directory"

$aud = @($plan.TemplatePolicies | Where-Object { $_.GroupLabel -eq 'Audit' -and $_.TemplateDisplayName -notlike '*-MANUAL' })[0]
Assert-Equal -Actual $aud.OuValue -Expected 'AUD' -Because "per-pair CertSubjectOu overrides the derived token"

# ---------------------------------------------------------------------------
# 3a. 2026-09-15 - the manual counterpart's own policy entry: SAME OU, distinct CN/FileName, matching
#     Get-CAPerGroupManualTemplateSpec's own DisplayName convention exactly (CATemplates.ps1)
# ---------------------------------------------------------------------------
$psgiManual = @($plan.TemplatePolicies | Where-Object { $_.GroupLabel -eq 'PSGI' -and $_.TemplateDisplayName -like '*-MANUAL' })[0]
Assert-True  -Condition ([bool]$psgiManual) -Because "a manual-counterpart policy entry exists for every RADIUS group pair, not just the Auto template"
Assert-Equal -Actual $psgiManual.TemplateDisplayName -Expected 'NSP-IKEv2-PSGI-MANUAL' -Because "matches Get-CAPerGroupManualTemplateSpec's own '<Auto DisplayName>-MANUAL' convention exactly - the policy file MUST be named after the real template's real CN"
Assert-Equal -Actual $psgiManual.TemplateCn -Expected 'NSPIKEv2PSGIMANUAL' -Because "CN = the manual display name with non-alphanumerics stripped, same convention as every other template CN in this codebase"
Assert-Equal -Actual $psgiManual.FileName -Expected 'NSPIKEv2PSGIMANUAL.xml' -Because "policy file named after the manual template's own CN, distinct from the Auto template's file"
Assert-Equal -Actual $psgiManual.OuValue -Expected $psgi.OuValue -Because "stamps the IDENTICAL OU as its Auto counterpart - same group, same flow, just admin-approved instead of auto-enrolled"
Assert-Contains -Haystack $psgiManual.Xml -Needle '<Value>IKEv2_PSGI_Users</Value>' -Because "the manual policy's own XML carries the same OU token"

# custom directory + prefix
$plan2 = Get-CATameMyCertsPlan -CAAnswers $answers -PolicyDirectory 'D:\CAPol' -TemplatePrefix 'ACME-'
$p2 = @($plan2.TemplatePolicies | Where-Object { $_.GroupLabel -eq 'PSGI' -and $_.TemplateDisplayName -notlike '*-MANUAL' })[0]
Assert-Equal -Actual $p2.TemplateDisplayName -Expected 'ACME-PSGI' -Because "-TemplatePrefix honoured"
Assert-Equal -Actual $p2.TemplateCn -Expected 'ACMEPSGI' -Because "CN strips the prefix hyphen"
Assert-Contains -Haystack "$($p2.FilePath)" -Needle 'D:\CAPol\ACMEPSGI.xml' -Because "-PolicyDirectory honoured"

# gate: absent CA_SubjectStampMode
$plan3 = Get-CATameMyCertsPlan -CAAnswers ([pscustomobject]@{ RadiusGroupPairs = @() })
Assert-False -Condition $plan3.Applicable -Because "no CA_SubjectStampMode -> not applicable (menu still lets a pilot proceed)"
Assert-Equal -Actual @($plan3.TemplatePolicies).Count -Expected 1 -Because "no RadiusGroupPairs -> single-template fallback"
Assert-Equal -Actual $plan3.TemplatePolicies[0].OuValue -Expected 'IKEv2_MasterGroup' -Because "fallback stamps the master auto-enroll group's token"

# ---------------------------------------------------------------------------
# 4. Get-CATameMyCertsPlan / Test-CATameMyCerts are pure / read-only
# ---------------------------------------------------------------------------
$planSrc = (Get-Command Get-CATameMyCertsPlan).Definition
Assert-NoMatch -Actual $planSrc -Pattern 'Invoke-CAStep|Stop-Service|Start-Service|regsvr32|Start-Process|Set-ItemProperty|Expand-Archive|Unblock-File' -Because "Get-CATameMyCertsPlan is PURE"

$testSrc = (Get-Command Test-CATameMyCerts).Definition
Assert-NoMatch -Actual $testSrc -Pattern 'Invoke-CAStep|Set-ItemProperty|New-ItemProperty|Stop-Service|Start-Process|regsvr32|Expand-Archive' -Because "Test-CATameMyCerts is read-only"
Assert-Match  -Actual $testSrc -Pattern 'PolicyModules' -Because "it reads PolicyModules\\Active"
Assert-Match  -Actual $testSrc -Pattern 'PolicyDirectory' -Because "and the PolicyDirectory registry value"

# ---------------------------------------------------------------------------
# 5. Engine source-introspection - every mutation via Invoke-CAStep
# ---------------------------------------------------------------------------
$instSrc = (Get-Command Install-CATameMyCerts).Definition
Assert-Match -Actual $instSrc -Pattern 'Invoke-CAStep' -Because "install routes through the dry-run engine"
Assert-Match -Actual $instSrc -Pattern 'install\.ps1' -Because "it runs the vendor installer script"
Assert-Match -Actual $instSrc -Pattern '-PolicyDirectory' -Because "passing the policy directory"
Assert-Match -Actual $instSrc -Pattern 'Expand-Archive' -Because "extracts the pinned community zip"
Assert-Match -Actual $instSrc -Pattern 'Unblock-File' -Because "unblocks downloaded files (MOTW)"
Assert-Match -Actual $instSrc -Pattern 'CaType' -Because "guards on Enterprise Root/Sub CA type"
Assert-Match -Actual $instSrc -Pattern 'Install-CATameMyCertsDotNet' -Because "installs the .NET prereq if missing"
# 2026-09-10 live bug: $StagingDir only got created inside the zip-download step, AFTER
# Install-CATameMyCertsDotNet already needed it to exist to write the runtime installer into -
# masqueraded as a download/network failure ("Could not find a part of the path ...\TmcInstall_...").
$mkdirIdx = $instSrc.IndexOf('New-Item -ItemType Directory -Path $StagingDir')
$dotNetCallIdx = $instSrc.IndexOf('Install-CATameMyCertsDotNet -Plan')
Assert-True -Condition ($mkdirIdx -ge 0 -and $dotNetCallIdx -ge 0 -and $mkdirIdx -lt $dotNetCallIdx) -Because "the staging directory is created BEFORE Install-CATameMyCertsDotNet is called, not just before the zip download"

$dnSrc = (Get-Command Install-CATameMyCertsDotNet).Definition
Assert-Match -Actual $dnSrc -Pattern 'Invoke-CAStep' -Because "the .NET install is dry-run aware"
Assert-Match -Actual $dnSrc -Pattern '/install.*/quiet|/quiet.*/install|/install./quiet' -Because "silent runtime install"
# 2026-09-10 live incident (Contoso-CA): both curl.exe and Invoke-WebRequest failed against the
# aka.ms redirector with the real error swallowed by a bare try/catch - no way to tell why. Every
# attempted method's error must now be captured and surfaced, and a stable manual-drop path must
# exist for a box with no route to aka.ms at all (mirrors the PowerShellGet Save-Module workaround).
Assert-Match -Actual $dnSrc -Pattern '\$errs\.Add' -Because "captures the real error from each download attempt instead of a bare catch {}"
Assert-Match -Actual $dnSrc -Pattern "ProgramData 'NSP\\CAManager\\windowsdesktop-runtime-10-x64\.exe'" -Because "checks a stable, well-known cache path before attempting any download"
Assert-Match -Actual $dnSrc -Pattern 'Side-load instead' -Because "the failure message tells the tech how to side-load it if the box can't reach the internet"
# 2026-09-11, per the maintainer: the cache is now SELF-POPULATING - a successful download gets copied into
# the same ProgramData\NSP\CAManager\ path, so a second box (or a re-run) never re-downloads either.
Assert-Match -Actual $dnSrc -Pattern 'Copy-Item -LiteralPath \$exe -Destination \$cachedCopy -Force' -Because "copies a successful download into the cache path for future runs"
Assert-Match -Actual $dnSrc -Pattern "(?s)Copy-Item -LiteralPath \`$exe -Destination \`$cachedCopy -Force[\s\S]{0,250}?\} catch \{" -Because "the cache-copy is wrapped in its own try/catch"
Assert-Match -Actual $dnSrc -Pattern 'WARNING: could not cache the installer' -Because "a failed cache-copy warns rather than failing the (already-successful) download/install"
Assert-Match -Actual $dnSrc -Pattern "if \(-not \(Test-Path -LiteralPath \`$cacheDir\)\) \{ New-Item -ItemType Directory -Path \`$cacheDir -Force \| Out-Null \}" -Because "creates C:\\ProgramData\\NSP\\CAManager\\ if it doesn't exist yet - the cache path is not assumed to pre-exist"
# 2026-09-10 live incident (Contoso-CA): the installer succeeded, but this already-running elevated
# process's $env:PATH snapshot pre-dated the install, so `dotnet` still wasn't resolvable - and the
# vendor install.ps1's own internal `Get-Command dotnet` check (run in this SAME process) then failed
# with ".NET 10 Runtime is not installed! Aborting." right after our own install step reported success.
Assert-Match -Actual $dnSrc -Pattern "GetEnvironmentVariable\('PATH', 'Machine'\)" -Because "re-pulls PATH from the registry after a successful install, since this process's own snapshot predates it"
Assert-Match -Actual $dnSrc -Pattern "GetEnvironmentVariable\('PATH', 'User'\)" -Because "both Machine and User scope, in case dotnet installed per-user"
Assert-Match -Actual $dnSrc -Pattern 'Get-Command dotnet -ErrorAction SilentlyContinue' -Because "re-verifies dotnet actually resolves after the PATH refresh before declaring success"

# ---------------------------------------------------------------------------
# 2b. Get-CAAnswerOrPrompt -Default - blank Enter must accept a stated default
# ---------------------------------------------------------------------------
. "$PKIModuleRoot\Private\CACore.ps1"
. "$PKIModuleRoot\Private\CAInteractive.ps1"
# 2026-09-10 live bug: menu S's prompt showed "[C:\PolicyFiles]" but blank Enter looped with
# "A value is required." - Get-CAAnswerOrPrompt built the bracket into the prompt TEXT only and
# never passed a real default through to Read-CANonEmpty, which is the only place blank is honoured.
Use-QueuedReadHost -Responses @('')
$defaulted = Get-CAAnswerOrPrompt -CAAnswers ([pscustomobject]@{}) -Field 'CA_TameMyCertsPolicyDir' -Prompt "Policy directory [C:\PolicyFiles]" -Default 'C:\PolicyFiles'
Restore-RealReadHost
Assert-Equal -Actual $defaulted -Expected 'C:\PolicyFiles' -Because "blank Enter accepts -Default instead of re-prompting"

Use-QueuedReadHost -Responses @('D:\Custom')
$typed = Get-CAAnswerOrPrompt -CAAnswers ([pscustomobject]@{}) -Field 'CA_TameMyCertsPolicyDir' -Prompt "Policy directory [C:\PolicyFiles]" -Default 'C:\PolicyFiles'
Restore-RealReadHost
Assert-Equal -Actual $typed -Expected 'D:\Custom' -Because "typing a value still overrides the default"

$wrSrc = (Get-Command Write-CATameMyCertsPolicies).Definition
Assert-Match -Actual $wrSrc -Pattern 'Invoke-CAStep' -Because "policy-file writes are dry-run aware"
Assert-Match -Actual $wrSrc -Pattern 'WriteAllText' -Because "writes the XML explicitly (UTF-8, no BOM)"
Assert-Match -Actual $wrSrc -Pattern 'UTF8Encoding' -Because "UTF-8 encoding for special characters"
Assert-Match -Actual $wrSrc -Pattern 'TemplatePolicies' -Because "loops the plan's policy list"

$rmSrc = (Get-Command Remove-CATameMyCerts).Definition
Assert-Match -Actual $rmSrc -Pattern 'Invoke-CAStep' -Because "teardown is dry-run aware"
Assert-Match -Actual $rmSrc -Pattern '-Uninstall' -Because "re-runs install.ps1 -Uninstall so the registry hive is copied back"
Assert-Match -Actual $rmSrc -Pattern 'DefaultProgId' -Because "the fallback manual revert names the MS default ProgID"

# ---------------------------------------------------------------------------
# 6. Dashboard wiring
# ---------------------------------------------------------------------------
$rawDash = Get-Content -Path $Dashboard -Raw
Assert-True -Condition (Test-Path "$PKIModuleRoot\Private\CATameMyCerts.ps1") -Because "NSP.PKI: the module loader dot-sources every Private\*.ps1 (was: the dashboard dot-sources CATameMyCerts)"
Assert-Match -Actual $rawDash -Pattern "'\^3\`$'\s*\{[\s\S]*?Invoke-CATameMyCertsMenu" -Because "menu 3 (2026-09-10 renumber - was letter-key S) dispatches to Invoke-CATameMyCertsMenu"
$rawHelp = Get-Content -Path "$PKIModuleRoot\Private\CAInteractive.ps1" -Raw
Assert-Match -Actual $rawHelp -Pattern '\[3\]' -Because "Show-CAMenuHelp's ordering-rationale hint marks item 3 (TameMyCerts) as optional - moved out of the dashboard's own terse menu text in the 2026-09-10 terse/verbose pass, see CAManager.MenuHelp.Tests.ps1 for the rest of that feature"

# ---------------------------------------------------------------------------
# 7. CLIBuilder field
# ---------------------------------------------------------------------------
$rawCli = Get-Content -Path $CliBuilder -Raw
Assert-Match -Actual $rawCli -Pattern 'CA_SubjectStampMode\s*=\s*@\{' -Because "the CLIBuilder \$Config carries CA_SubjectStampMode"
Assert-Match -Actual $rawCli -Pattern "CA_SubjectStampMode[\s\S]{0,200}Value\s*=\s*`"None`"" -Because "it defaults to None"
Assert-Match -Actual $rawCli -Pattern "CA_SubjectStampMode[\s\S]{0,400}Order\s*=\s*112" -Because "ordered after the other CA_ template fields"
$rawFm = Get-Content -Path $FieldMeta -Raw
Assert-Match -Actual $rawFm -Pattern "Certificate Authority[\s\S]{0,600}'CA_SubjectStampMode'" -Because "FieldMetadata lists it under the Certificate Authority group"

Write-TestSummary -Suite "CA Manager - menu S (TameMyCerts subject-stamp)"
