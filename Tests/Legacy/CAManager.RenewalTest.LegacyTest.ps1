# Ported from NSP-FGTIPSecTools Tests\CAManager.RenewalTest.Tests.ps1 (2026-10-01): same assertions, paths re-pointed at
# this module's Private\ files. Run by Tests\Legacy.Tests.ps1 (Pester) in a child PowerShell.
<#
.SYNOPSIS
    Tests for CA Manager - menu T (TameMyCerts renewal-idempotency test harness, CARenewalTest.ps1).
    Pure period-byte round trip, the OU-subject pass/fail engine, and source-introspection for the
    ADSI/AD-touching engines (can't safely execute those in a bare test environment) plus dashboard
    wiring and the DRY RUN refusal guard.

    Repo convention (Tests\README.md) - NOT Pester.
#>

. "$PSScriptRoot\..\Shared\TestAssertions.ps1"
$PKIModuleRoot = (Resolve-Path "$PSScriptRoot\..\..").Path
Reset-TestCounters

$Root = "C:\GitRepo\NSP-FGTIPSecTools"
$Mod  = "$PKIModuleRoot\Private\CARenewalTest.ps1"

Test-ScriptParses -Path $Mod -Because "CARenewalTest.ps1 parses"

. $Mod

# ---------------------------------------------------------------------------
# 1. Period byte encoding round-trips (pKIExpirationPeriod / pKIOverlapPeriod)
# ---------------------------------------------------------------------------
foreach ($h in @(2, 2.5, 24, 8760, 0.5)) {
    $bytes = ConvertTo-CARenewalPeriodBytes -Hours $h
    # Checking .GetType() directly (not just .Length) matters: PowerShell enumerates/flattens an array
    # left as a function's unreturned last expression onto the output pipeline, re-boxing it into a
    # generic System.Object[] when captured - found live 2026-09-10 on Contoso-CA (a real byte[] got
    # silently stringified into ADSI instead of written as raw bytes). ConvertFrom-CARenewalPeriodBytes's
    # own [byte[]]-typed parameter would silently COERCE a wrong Object[] back to a real byte[] before
    # use, masking this exact bug in a plain round-trip test - Set-CARenewalTemplateAttribute's $Value
    # has no such type constraint (it must also accept plain ints), so nothing there corrects it.
    Assert-Equal -Actual $bytes.GetType().FullName -Expected 'System.Byte[]' -Because "$h h returns a REAL byte[], not a re-boxed Object[] (the class of bug that broke Set-CARenewalTemplateAttribute's byte[]-vs-string branch)"
    Assert-Equal -Actual $bytes.Length -Expected 8 -Because "$h h encodes to an 8-byte FILETIME duration"
    $back = ConvertFrom-CARenewalPeriodBytes -Bytes $bytes
    Assert-Equal -Actual $back -Expected $h -Because "$h h round-trips through ConvertTo/From-CARenewalPeriodBytes"
}
$twoHourBytes = ConvertTo-CARenewalPeriodBytes -Hours 2
$ticks = [BitConverter]::ToInt64($twoHourBytes, 0)
Assert-True -Condition ($ticks -lt 0) -Because "period durations are NEGATIVE FILETIME ticks (same encoding as maxPwdAge etc.)"
Assert-Equal -Actual $ticks -Expected ([int64](-2 * 3600 * 1e7)) -Because "2h = -2*3600*10,000,000 ticks exactly"

# ---------------------------------------------------------------------------
# 2. Test-CARenewalCertOuSubject - the actual pass/fail engine for every renewal path
# ---------------------------------------------------------------------------
function New-FakeCert { param([string]$Subject, [string]$Thumb = 'ABC123') [pscustomobject]@{ Subject = $Subject; Thumbprint = $Thumb; NotBefore = (Get-Date) } }

$r1 = Test-CARenewalCertOuSubject -Cert (New-FakeCert 'CN=Jane Smith, OU=IKEv2_InternalUsers, DC=contoso, DC=local') -ExpectedOu 'IKEv2_InternalUsers'
Assert-True  -Condition $r1.Pass -Because "exactly one OU= RDN matching the expected token -> PASS"
Assert-Equal -Actual $r1.OuCount -Expected 1 -Because "single OU= RDN counted"

$r2 = Test-CARenewalCertOuSubject -Cert (New-FakeCert 'CN=Jane Smith, OU=IKEv2_InternalUsers, OU=IKEv2_InternalUsers, DC=contoso') -ExpectedOu 'IKEv2_InternalUsers'
Assert-False -Condition $r2.Pass -Because "a DUPLICATE OU= RDN (the exact 12-month failure mode) is a FAIL even though both values are correct"
Assert-Equal -Actual $r2.OuCount -Expected 2 -Because "duplicate RDN is counted, not deduplicated"

$r3 = Test-CARenewalCertOuSubject -Cert (New-FakeCert 'CN=Jane Smith, OU=SomeOtherGroup, DC=contoso') -ExpectedOu 'IKEv2_InternalUsers'
Assert-False -Condition $r3.Pass -Because "a wrong/drifted OU value is a FAIL"

$r4 = Test-CARenewalCertOuSubject -Cert (New-FakeCert 'CN=Jane Smith, DC=contoso') -ExpectedOu 'IKEv2_InternalUsers'
Assert-False -Condition $r4.Pass -Because "no OU= RDN at all (TameMyCerts didn't fire) is a FAIL"
Assert-Equal -Actual $r4.OuCount -Expected 0 -Because "zero OU= RDNs counted"

# ---------------------------------------------------------------------------
# 2b. Get-CARenewalTestCert - the LOCAL path (mocked Get-ChildItem), proving the shared lookup
#     scriptblock actually filters/matches for real, not just "looks right" by source inspection.
#     Found live 2026-09-10 on Contoso-CA, TWO separate bugs stacked on top of each other:
#       1. This function silently checked the CA's OWN cert store the whole time (CA-Manager runs
#          there), never the separate VPN client the test cert actually lands on.
#       2. Even after fixing #1 (via -ComputerName remoting), it STILL found nothing - because
#          .Format($true) on the Template Information extension embeds the template's DISPLAY NAME
#          ("NSP-IKEv2-CONTOSO", hyphens) not its CN ("NSPIKEv2CONTOSO", no hyphens), so a CN match can
#          never succeed against that text (the real live capture: "Template=NSP-IKEv2-CONTOSO(1.3.6.1.
#          4.1.311.21.8.6279881...)"). Fixed by matching on the template's own OID instead - unique,
#          appears verbatim regardless of CN/display-name conventions.
#     Every PASS/FAIL in the harness was meaningless until BOTH were fixed.
# ---------------------------------------------------------------------------
$realTemplateOid = '1.3.6.1.4.1.311.21.8.6279881.4007032.12992906.11776932.11403965.117.81377787.62435497'
function New-FakeTemplateExtension {
    param([string]$FormattedText)
    $ext = [pscustomobject]@{ Oid = [pscustomobject]@{ Value = '1.3.6.1.4.1.311.21.7' } }
    $ext | Add-Member -MemberType ScriptMethod -Name Format -Value ({ $FormattedText }).GetNewClosure()
    $ext
}
function New-FakeStoreCert {
    param([string]$Subject, [string]$Thumb, [datetime]$NotBefore, [string]$TemplateText)
    $cert = [pscustomobject]@{ Subject = $Subject; Thumbprint = $Thumb; NotBefore = $NotBefore }
    $cert | Add-Member -MemberType NoteProperty -Name Extensions -Value @((New-FakeTemplateExtension -FormattedText $TemplateText))
    $cert
}
function Get-ChildItem {
    param($Path, $ErrorAction)
    if ($Path -eq 'Cert:\CurrentUser\My') {
        @(
            (New-FakeStoreCert -Subject 'CN=Jane Smith, OU=IKEv2_InternalUsers' -Thumb 'MATCHOLD' -NotBefore (Get-Date).AddHours(-3) -TemplateText "Template=NSP-IKEv2-CONTOSO($realTemplateOid)`nMajor Version Number=100`nMinor Version Number=5")
            (New-FakeStoreCert -Subject 'CN=Jane Smith, OU=IKEv2_InternalUsers' -Thumb 'MATCHNEW' -NotBefore (Get-Date) -TemplateText "Template=NSP-IKEv2-CONTOSO($realTemplateOid)`nMajor Version Number=100`nMinor Version Number=5")
            (New-FakeStoreCert -Subject 'CN=Other User' -Thumb 'NOMATCH' -NotBefore (Get-Date) -TemplateText 'Template=SomeUnrelatedTemplate(1.2.3.4.5)')
        )
    } else { @() }
}
$localFound = @(Get-CARenewalTestCert -TemplateOid $realTemplateOid -StoreLocation 'CurrentUser')
Assert-Equal -Actual $localFound.Count -Expected 2 -Because "only certs whose Template extension text matches the OID are returned - the unrelated-template cert is excluded"
Assert-Equal -Actual $localFound[0].Thumbprint -Expected 'MATCHNEW' -Because "results are sorted NotBefore-descending, so the newest matching cert comes first"
Assert-Equal -Actual (@(Get-CARenewalTestCert -TemplateOid '1.2.3.4.5.6.7.8.9' -StoreLocation 'CurrentUser')).Count -Expected 0 -Because "a template OID with no matching certs returns an empty result, not an error"
Assert-Equal -Actual (@(Get-CARenewalTestCert -TemplateOid 'NSPIKEv2CONTOSO' -StoreLocation 'CurrentUser')).Count -Expected 0 -Because "REGRESSION GUARD for the 2026-09-10 live bug: matching on the CN ('NSPIKEv2CONTOSO', no hyphens) finds nothing against display-name text ('NSP-IKEv2-CONTOSO', hyphens) - proves the OID match is genuinely required, not optional"
Remove-Item function:Get-ChildItem, function:New-FakeTemplateExtension, function:New-FakeStoreCert -ErrorAction SilentlyContinue

# ---------------------------------------------------------------------------
# 2c. Test-CARenewalUserHasPrivilegedGroup - the group-safety-net pre-check (mocked Get-ADUser)
#     Found live 2026-09-10 on Contoso-CA: menu 6 kept "failing" (enrollment succeeded despite group
#     removal) because the test user was ALSO a Domain Admins member - not a bug in the removal logic,
#     just an invalid test subject. This check catches that up front instead of wasting more cycles.
# ---------------------------------------------------------------------------
function Import-Module { param($Name, $ErrorAction) }
function Get-ADUser {
    param($Identity, $Properties, $ErrorAction)
    if ($Identity -eq 'privilegeduser') {
        [pscustomobject]@{ MemberOf = @('CN=Domain Admins,CN=Users,DC=contoso,DC=local', 'CN=IKEv2_InternalUsers,OU=Groups,DC=contoso,DC=local') }
    } else {
        [pscustomobject]@{ MemberOf = @('CN=IKEv2_InternalUsers,OU=Groups,DC=contoso,DC=local') }
    }
}
$privResult = Test-CARenewalUserHasPrivilegedGroup -TestUser 'privilegeduser'
Assert-True -Condition $privResult.IsPrivileged -Because "a user directly in Domain Admins is flagged as privileged"
Assert-Contains -Haystack ($privResult.MatchedGroups -join ',') -Needle 'Domain Admins' -Because "names which privileged group actually matched"

$plainResult = Test-CARenewalUserHasPrivilegedGroup -TestUser 'plainuser'
Assert-False -Condition $plainResult.IsPrivileged -Because "a user with no Domain Admins/Enterprise Admins membership is NOT flagged"
Assert-Equal -Actual $plainResult.MatchedGroups.Count -Expected 0 -Because "no matched groups for a non-privileged user"
Remove-Item function:Import-Module, function:Get-ADUser -ErrorAction SilentlyContinue

# ---------------------------------------------------------------------------
# 3. Results table bookkeeping
# ---------------------------------------------------------------------------
$results = New-Object System.Collections.Generic.List[object]
Add-CARenewalResult -Results $results -Step 'test step' -Pass $true -Detail 'ok'
Add-CARenewalResult -Results $results -Step 'test step 2' -Pass $false -Detail 'bad'
Assert-Equal -Actual $results.Count -Expected 2 -Because "each Add-CARenewalResult call appends one row"
Assert-Equal -Actual $results[1].Pass -Expected $false -Because "pass/fail is recorded per step"

# Show-CARenewalResultsTable must accept a genuinely EMPTY List[object] without throwing - a Mandatory
# collection-typed parameter otherwise rejects an empty collection outright, and $results legitimately
# starts empty every session until the first step completes (found live 2026-09-10 on Contoso-CA on the
# very first Invoke-CARenewalStep call: "Cannot bind argument... because it is an empty collection").
$emptyResults = New-Object System.Collections.Generic.List[object]
$threwOnEmpty = $false
try { Show-CARenewalResultsTable -Results $emptyResults | Out-Null } catch { $threwOnEmpty = $true }
Assert-False -Condition $threwOnEmpty -Because "Show-CARenewalResultsTable accepts an empty results list without throwing"

# ---------------------------------------------------------------------------
# 3a. Domain-FQDN-from-DN derivation - the exact expression Set-CARenewalTemplateAttribute uses to
#     build the LdapConnection target (pure regex logic, testable standalone)
# ---------------------------------------------------------------------------
$sampleDn = 'CN=NSPIKEv2CONTOSO,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=Contoso,DC=local'
$domainFqdn = ([regex]::Matches($sampleDn, 'DC=([^,]+)') | ForEach-Object { $_.Groups[1].Value }) -join '.'
Assert-Equal -Actual $domainFqdn -Expected 'Contoso.local' -Because "extracts and dot-joins the DC= components of a template's DN into its domain FQDN"

# ---------------------------------------------------------------------------
# 3b. Set-CARenewalTemplateValidity - the overlap-must-be-less-than-validity precondition (2026-09-10
#     live bug: AD rejected an overlap>=validity combination with a bare E_FAIL, no permissions issue
#     behind it). This check runs BEFORE any ADSI call, so it's exercisable without a real AD/template.
# ---------------------------------------------------------------------------
$threwEqual = $false
try { Set-CARenewalTemplateValidity -TemplateCn 'DOES-NOT-MATTER' -ValidityHours 2 -OverlapHours 2 } catch { $threwEqual = $true; $eqMsg = $_.Exception.Message }
Assert-True -Condition $threwEqual -Because "overlap == validity is rejected up front, before ever touching ADSI"
Assert-Match -Actual $eqMsg -Pattern 'must be LESS than' -Because "the precondition error explains why, not just that it failed"

$threwGreater = $false
try { Set-CARenewalTemplateValidity -TemplateCn 'DOES-NOT-MATTER' -ValidityHours 2 -OverlapHours 3 } catch { $threwGreater = $true }
Assert-True -Condition $threwGreater -Because "overlap > validity is rejected up front too"

# ---------------------------------------------------------------------------
# 4. Source-introspection - engines that touch ADSI/AD, the every-step try/catch, and the
#    DRY-RUN refusal guard (can't safely exercise these live in a bare test environment)
# ---------------------------------------------------------------------------
$raw = Get-Content -Path $Mod -Raw

Assert-Match -Actual $raw -Pattern "(?s)function ConvertTo-CARenewalPeriodBytes.*?,\(\[BitConverter\]::GetBytes\(\`$ticks\)\)" -Because "regression guard: the leading comma preventing pipeline-enumeration re-boxing must stay (found live 2026-09-10: without it, a real byte[] became Object[] and got silently stringified into ADSI)"
Assert-Match -Actual $raw -Pattern 'function Get-CARenewalTemplateAdsi[\s\S]*?CN=Certificate Templates,CN=Public Key Services,CN=Services' -Because "template lookup binds under the standard PKI Services container"
Assert-Match -Actual $raw -Pattern '(?s)function Invoke-CARenewalStep.*?\[Parameter\(Mandatory\)\]\[AllowEmptyCollection\(\)\]\[System\.Collections\.Generic\.List\[object\]\]\$Results' -Because "Invoke-CARenewalStep's \$Results must allow an empty list too (same bug, same fix, as Show-CARenewalResultsTable) - it's the very first call to mutate \$results in a session"
Assert-Match -Actual $raw -Pattern "(?s)function Set-CARenewalTemplateValidity.*?pKIExpirationPeriod.*?pKIOverlapPeriod.*?msPKI-Template-Minor-Revision" -Because "setting validity also bumps the minor revision (matches what certtmpl.msc itself does on any edit) - order between the two period attributes is now conditional (see the write-order tests below), so this only checks all three are referenced somewhere in the function"
Assert-Match -Actual $raw -Pattern "(?s)function Set-CARenewalTemplateValidity.*?try \{.*?Set-CARenewalTemplateAttribute -Adsi \`$t -Name 'msPKI-Template-Minor-Revision'.*?\} catch \{" -Because "the minor-revision bump is non-fatal - a separate failure there must not undo/block the validity+overlap change that already succeeded (2026-09-10 live: period attrs wrote fine, only the minor-rev bump failed)"
Assert-Match -Actual $raw -Pattern '\(APPLIED\)' -Because "still reports the validity/overlap change as applied even when the minor-rev bump fails"

# --- Set-CARenewalTemplateAttribute - the 3-path write helper (2026-09-10 live E_FAIL saga) ---
Assert-Match -Actual $raw -Pattern '(?s)function Set-CARenewalTemplateAttribute.*?System\.DirectoryServices\.Protocols.*?LdapConnection.*?ModifyRequest.*?SendRequest' -Because "tries a raw LDAP modify via System.DirectoryServices.Protocols FIRST - proven live to succeed where both ADSI paths fail identically"
Assert-NoMatch -Actual $raw -Pattern '(New-Object|::new\(\)).{0,40}LdapDirectoryIdentifier' -Because "regression guard: LdapDirectoryIdentifier proved to be a dead end on this runtime - neither New-Object(\$null) (ambiguous overload) nor the zero-arg ::new() (no such overload here at all) actually worked live; LdapConnection takes a plain domain-name string directly instead"
Assert-Match -Actual $raw -Pattern "\[regex\]::Matches\(.*distinguishedName.*'DC=\(\[\^,\]\+\)'\)" -Because "derives the domain FQDN from the object's own DN (DC= components) instead of hardcoding a domain name"
Assert-Match -Actual $raw -Pattern 'New-Object System\.DirectoryServices\.Protocols\.LdapConnection\(\$domainFqdn\)' -Because "LdapConnection is constructed with a plain domain-name string - exactly what the manually-verified working diagnostic script used"
Assert-Match -Actual $raw -Pattern '\$ldap\.AuthType = \[System\.DirectoryServices\.Protocols\.AuthType\]::Negotiate' -Because "matches the exact auth type used in the manually-verified working diagnostic script, not left to an implicit default"
Assert-Match -Actual $raw -Pattern '(?s)function Set-CARenewalTemplateAttribute.*?LdapConnection.*?\.Put\(\$Name, \$Value\).*?\.SetInfo\(\)' -Because "falls back to the classic .Put()/.SetInfo() ADSI path only if the LDAP path throws"
Assert-Match -Actual $raw -Pattern '(?s)function Set-CARenewalTemplateAttribute.*?\.Put\(\$Name, \$Value\).*?\.Properties\[\$Name\]\.Value = \$Value.*?\.CommitChanges\(\)' -Because "falls back to the .Properties[]/.CommitChanges() path last (a genuinely different ADSI code path, not just a retry)"
Assert-Match -Actual $raw -Pattern '(?s)function Set-CARenewalTemplateAttribute.*?throw \(' -Because "only throws (combining all 3 attempts' detail) after every write path fails"
Assert-Match -Actual $raw -Pattern "if \(\`$Value -is \[byte\[\]\]\) \{ \`$mod\.Add\(\[byte\[\]\]\`$Value\) \| Out-Null \} else \{ \`$mod\.Add\(\[string\]\`$Value\) \| Out-Null \}" -Because "DirectoryAttributeModification.Add() only accepts byte[]/string/Uri - an int (minor-revision) must go in as its string form, not a raw object"
Assert-Match -Actual $raw -Pattern '\(,\$mod\)' -Because "the leading comma forces a true one-element array without enumerating \$mod (it's itself enumerable - a bare @(\$mod) flattens it into its own values, a real bug hit live while building this)"
Assert-NoMatch -Actual $raw -Pattern 'dsacls' -Because "dsacls proved unreliable (false NO_OBJECT on a confirmed-real object) during live debugging and is no longer referenced as a diagnostic"
Assert-Match -Actual $raw -Pattern '(?s)function Set-CARenewalTemplateValidity.*?Set-CARenewalTemplateAttribute -Adsi \$t -Name ''pKIExpirationPeriod''' -Because "validity is written through the shared 3-path helper, not a raw .Put() (regression guard for the 2026-09-10 E_FAIL bug)"
Assert-Match -Actual $raw -Pattern '(?s)function Step-CARenewalBumpTemplateVersion.*?Set-CARenewalTemplateAttribute -Adsi \$t -Name ''msPKI-Template-Minor-Revision''' -Because "the version-bump step also goes through the shared 3-path helper, not a duplicated raw .Put()"
Assert-Match -Actual $raw -Pattern "(?s)function Step-CARenewalBumpTemplateVersion.*?Set-CARenewalTemplateAttribute -Adsi \`$t -Name 'revision' -Value \(\`$major \+ 1\)" -Because "bumps 'revision' (Major Version Number), not just the minor field - found live 2026-09-10 that a minor-only bump (5->7, confirmed real on AD) did NOT trigger autoenrollment to reenroll a still-valid cert; bumping revision (major) did, immediately - matches Microsoft's own major/minor semantics (minor = no reenroll required, major = reenroll regardless of the renewal window)"
Assert-Match -Actual $raw -Pattern "(?s)\`$major = \[int\]\`$t\.Properties\['revision'\]\[0\][\s\S]*?\`$minor = \[int\]\`$t\.Properties\['msPKI-Template-Minor-Revision'\]\[0\]" -Because "reads the CURRENT major/minor values before bumping either, so the +1 is relative to what's actually on the object"
Assert-Match -Actual $raw -Pattern 'function Backup-CARenewalTemplateValidity[\s\S]{0,400}Test-Path \$backupPath' -Because "backup refuses to clobber an existing backup (protects the REAL original values across repeated runs)"
Assert-Match -Actual $raw -Pattern '(?s)function Restore-CARenewalTemplateValidity.*?Remove-Item \$backupPath' -Because "restore deletes its own backup file once applied"
Assert-Match -Actual $raw -Pattern "Revision\s*=\s*\[int\]\`$t\.Properties\['revision'\]\[0\]" -Because "Get-CARenewalTemplateValidity captures 'revision' (Major Version Number) too, now that Step-CARenewalBumpTemplateVersion mutates it"
Assert-Match -Actual $raw -Pattern "(?s)function Restore-CARenewalTemplateValidity.*?Set-CARenewalTemplateAttribute -Adsi \`$t -Name 'revision' -Value \(\[int\]\`$orig\.Revision\)" -Because "restore forces 'revision' back to its exact backed-up value too, not just validity/overlap - Set-CARenewalTemplateValidity's own minor-rev bump is a same-session side-effect, not a restore, and never touches revision at all"
Assert-Match -Actual $raw -Pattern "(?s)function Restore-CARenewalTemplateValidity.*?if \(\`$orig\.PSObject\.Properties\['Revision'\] -and \`$null -ne \`$orig\.Revision\)" -Because "guards against an OLD backup file (predating Revision tracking) writing [int]\$null (0) to a template's major version - a genuinely corrupting value, not just a missing nice-to-have"

Assert-Match -Actual $raw -Pattern "(?s)\`$script:CARenewalCertLookupScript.*?Oid\.Value -in '1\.3\.6\.1\.4\.1\.311\.21\.7', '1\.3\.6\.1\.4\.1\.311\.20\.2'" -Because "cert lookup matches on the Template Information/Name extension OIDs"
Assert-Match -Actual $raw -Pattern "(?s)function Get-CARenewalTestCert.*?\[string\]\`$ComputerName.*?Invoke-Command -ComputerName \`$ComputerName -ScriptBlock \`$script:CARenewalCertLookupScript" -Because "when -ComputerName is set, the cert store is queried on that REMOTE machine via PS remoting - not the local one CA-Manager runs on (2026-09-10 live bug: every PASS/FAIL was checking the wrong machine)"
Assert-Match -Actual $raw -Pattern "(?s)function Get-CARenewalTestCert.*?if \(\[string\]::IsNullOrWhiteSpace\(\`$ComputerName\)\) \{\s*& \`$script:CARenewalCertLookupScript" -Because "local (no -ComputerName) and remote paths share the SAME lookup logic - one scriptblock, not two copies"
Assert-Match -Actual $raw -Pattern "function Get-CARenewalTemplateOid[\s\S]*?msPKI-Cert-Template-OID" -Because "the OID (the real match key) is read from the template's own msPKI-Cert-Template-OID attribute"
Assert-Match -Actual $raw -Pattern "(?s)function Invoke-CARenewalTestSession.*?\`$templateOid = Get-CARenewalTemplateOid -TemplateCn \`$TemplateCn" -Because "the OID is resolved ONCE per session (the template doesn't change mid-session), not re-derived on every cert check"
Assert-NoMatch -Actual $raw -Pattern "function Get-CARenewalTestCert[\s\S]{0,200}\[Parameter\(Mandatory\)\]\[string\]\`$TemplateCn" -Because "regression guard: Get-CARenewalTestCert must take -TemplateOid, not -TemplateCn, as its match key (the 2026-09-10 live bug)"
Assert-Match -Actual $raw -Pattern 'Enable-PSRemoting -Force' -Because "the remote-query failure message tells the operator how to fix a WinRM-not-reachable case, not just that it failed"
Assert-Match -Actual $raw -Pattern "\[string\]\`$ClientComputerName" -Because "Invoke-CARenewalStep and Invoke-CARenewalTestSession both accept a client computer name to thread through to the cert lookup"
Assert-Match -Actual $raw -Pattern "(?s)function Invoke-CAMenuRenewalTest.*?Test-WSMan -ComputerName \`$clientComputerName" -Because "the menu wrapper checks WinRM reachability up front when a client hostname is given, rather than only failing deep inside the first step"

# --- Step-CARenewalPulseClient - drives certutil -pulse (and gpupdate first) remotely instead of leaving it manual ---
Assert-Match -Actual $raw -Pattern "(?s)function Step-CARenewalPulseClient.*?if \(\[string\]::IsNullOrWhiteSpace\(\`$ComputerName\)\) \{.*?return" -Because "falls back to a manual instruction when no client hostname is set (local-only sessions)"
Assert-Match -Actual $raw -Pattern "(?s)function Step-CARenewalPulseClient.*?Invoke-Command -ComputerName \`$ComputerName -ScriptBlock \{ gpupdate /force.*?certutil -pulse" -Because "runs gpupdate /force BEFORE certutil -pulse - found live 2026-09-10 that a bare pulse alone didn't pick up a template version bump, since the autoenrollment client's view of the template refreshes via the Group Policy CSE, not via certutil -pulse itself"
Assert-Equal -Actual (@([regex]::Matches($raw, 'Step-CARenewalPulseClient -ComputerName \$ClientComputerName')).Count) -Expected 6 -Because "every one of the 6 checklist steps that needs a client-side pulse (4.1, 4.2, 4.4, 4.5, 4.6a, 4.6b) now drives it remotely instead of just printing a manual instruction"
Assert-NoMatch -Actual $raw -Pattern "Write-Host `"  On the CLIENT: certutil -pulse`"" -Because "regression guard: no leftover manual-only pulse instruction remains where the remote helper should be used instead"

# --- Step-CARenewalDeleteClientCert - drives the 4.5 cert deletion remotely too, since we're already remoting ---
Assert-Match -Actual $raw -Pattern "(?s)function Step-CARenewalDeleteClientCert.*?if \(\[string\]::IsNullOrWhiteSpace\(\`$ComputerName\)\) \{.*?return" -Because "falls back to a manual delete+confirm prompt when no client hostname is set"
Assert-Match -Actual $raw -Pattern "(?s)function Step-CARenewalDeleteClientCert.*?Invoke-Command -ComputerName \`$ComputerName -ScriptBlock \{[\s\S]*?Remove-Item -LiteralPath \`$path -Force" -Because "deletes the cert remotely by exact thumbprint path, not a bulk/wildcard removal"
Assert-Match -Actual $raw -Pattern "(?s)'\^5\$'[\s\S]*?Step-CARenewalDeleteClientCert -Thumbprint \`$cur\.Thumbprint" -Because "item 4.5 now drives the delete itself instead of asking the operator to do it by hand and press Enter"
Assert-Match -Actual $raw -Pattern "(?s)'\^5\$'[\s\S]*?if \(-not \`$cur\) \{" -Because "handles the no-existing-cert case (nothing to delete) instead of assuming one is always present"

Assert-Match -Actual $raw -Pattern 'function Step-CARenewalRemoveFromGroup[\s\S]{0,300}Read-CAConfirm[\s\S]{0,300}Remove-ADGroupMember' -Because "group removal is confirmed before mutating, and uses the real ActiveDirectory cmdlet (not a duplicated helper)"
Assert-Match -Actual $raw -Pattern "(?s)'\^6\$'[\s\S]*?Test-CARenewalUserHasPrivilegedGroup -TestUser \`$TestUser" -Because "item 6 checks the test user for Domain/Enterprise Admins membership BEFORE removing them from the group, instead of only discovering the false result after the fact"
Assert-Match -Actual $raw -Pattern "(?s)'\^6\$'[\s\S]*?if \(\`$priv\.IsPrivileged\) \{[\s\S]*?Read-CAConfirm -Prompt `"Proceed anyway" -Because "warns clearly and requires an explicit confirm before running a test that's very likely to give a false result"
Assert-Match -Actual $raw -Pattern "(?s)'\^6\$'[\s\S]*?if \(\`$okToRun\) \{" -Because "the actual removal+step only runs if the operator confirmed (or the user wasn't privileged to begin with)"
Assert-Match -Actual $raw -Pattern 'function Step-CARenewalAddToGroup[\s\S]{0,400}Add-ADGroupMember' -Because "group addition uses the real ActiveDirectory cmdlet"
Assert-NoMatch -Actual $raw -Pattern 'function Confirm-CAAction' -Because "reuses the shared Read-CAConfirm helper instead of a duplicated embedded confirm function"

Assert-Match -Actual $raw -Pattern 'function Invoke-CARenewalTestSession[\s\S]*?try \{[\s\S]*?switch -Regex \(\$choice\)[\s\S]*?\} catch \{' -Because "every menu action is wrapped in try/catch so one failing step can't kill the whole dashboard session (the 2026-09-10 live bug)"

# --- Wait-CARenewalClientEvent - polls the client's real completion signal instead of a blind Read-Host ---
Assert-Match -Actual $raw -Pattern "function Wait-CARenewalClientEvent[\s\S]*?Get-WinEvent -LogName 'Microsoft-Windows-CertificateServicesClient-Lifecycle-User/Operational'" -Because "polls the actual cert-lifecycle log, not a fixed sleep, for the real signal that async enrollment finished"
Assert-Match -Actual $raw -Pattern "(?s)function Wait-CARenewalClientEvent.*?while \(\(Get-Date\) -lt \`$deadline\)" -Because "polls in a loop up to the timeout rather than checking only once"
Assert-Match -Actual $raw -Pattern "(?s)function Invoke-CARenewalStep.*?if \(\[string\]::IsNullOrWhiteSpace\(\`$ClientComputerName\)\) \{[\s\S]*?Read-Host[\s\S]*?\} else \{[\s\S]*?Wait-CARenewalClientEvent -ComputerName \`$ClientComputerName -Since \`$stepStart" -Because "every step (not just certreq) now auto-waits on the client's real event log when remoting is set, instead of a blind Press-Enter - falls back to the manual gate only when there's no client to poll"
Assert-Match -Actual $raw -Pattern "\`$stepStart = Get-Date[\s\S]{0,40}& \`$Instructions" -Because "the wait window starts BEFORE Instructions runs, so a fast event isn't missed, and the timeout is measured from when triggering the action began"

# --- Step-CARenewalCertReqOnClient - CONFIRMED positional syntax, run via a TIME-BOUNDED remote job ---
Assert-Match -Actual $raw -Pattern "(?s)function Step-CARenewalCertReqOnClient\b(?:(?!\r?\nfunction ).)*?if \(\[string\]::IsNullOrWhiteSpace\(\`$ComputerName\)\) \{.*?return" -Because "falls back to a manual instruction+prompt when no client hostname is set"
Assert-Match -Actual $raw -Pattern "(?s)function Step-CARenewalCertReqOnClient\b(?:(?!\r?\nfunction ).)*?-AsJob -ErrorAction Stop" -Because "runs certreq as a background job, not a blocking Invoke-Command - found live 2026-09-10 it can intermittently hang on an interactive prompt, and a blocking call would hang this whole dashboard session with no way out"
Assert-Match -Actual $raw -Pattern "(?s)function Step-CARenewalCertReqOnClient\b(?:(?!\r?\nfunction ).)*?Wait-Job -Job \`$job -Timeout \`$TimeoutSeconds" -Because "bounds the wait with an actual timeout instead of blocking indefinitely"
Assert-Match -Actual $raw -Pattern "(?s)function Step-CARenewalCertReqOnClient\b(?:(?!\r?\nfunction ).)*?stuck on an interactive prompt" -Because "on timeout, tells the operator what's likely wrong and hands control back instead of just failing silently"
Assert-Match -Actual $raw -Pattern "(?s)function Step-CARenewalCertReqOnClient\b(?:(?!\r?\nfunction ).)*?finally \{[\s\S]*?Remove-Job -Job \`$job -Force" -Because "always cleans up the local job object (in a finally), regardless of which path was taken"
Assert-Match -Actual $raw -Pattern "(?s)'\^3\$'[\s\S]*?if \(-not \`$curForRenew\) \{" -Because "item 3 guards the no-existing-cert case before trying to renew something that doesn't exist"
Assert-Match -Actual $raw -Pattern "(?s)'\^3\$'[\s\S]*?Read-CAConfirm -Prompt `"Test the SAME-key pass now" -Because "lets the operator choose which key-mode pass this invocation tests, matching the existing repeat-for-the-other-mode flow"
Assert-Match -Actual $raw -Pattern "(?s)'\^3\$'[\s\S]*?Step-CARenewalCertReqOnClient -Thumbprint \`$curForRenew\.Thumbprint -ReuseKeys:\`$sameKeyPass" -Because "item 3 now drives certreq itself instead of just printing the command for the operator to copy-paste"

Assert-Match -Actual $raw -Pattern '(?s)function Invoke-CAMenuRenewalTest.*?Get-CADryRun.*?return' -Because "the entry point refuses to run while the dashboard is in DRY RUN, rather than silently pretending that toggle protects a live-mutating test tool"
Assert-Match -Actual $raw -Pattern 'function Invoke-CAMenuRenewalTest[\s\S]*?Get-CATameMyCertsPlan' -Because "template/OU choices are sourced from the real TameMyCerts plan, not re-typed by hand"

# --- overlap/validity write-order selection (2026-09-10 live bug) ---
Assert-Match -Actual $raw -Pattern "(?s)function Set-CARenewalTemplateValidity.*?if \(\`$OverlapHours -ge \`$ValidityHours\) \{.*?throw" -Because "refuses an invalid target pair immediately, instead of letting AD reject it deep inside a write"
Assert-Match -Actual $raw -Pattern "(?s)if \(\`$current\.ValidityHours -gt \`$OverlapHours\)[\s\S]*?pKIOverlapPeriod[\s\S]*?pKIExpirationPeriod" -Because "when the OLD validity already exceeds the NEW overlap, shrinks overlap before validity (never an invalid intermediate state)"
Assert-Match -Actual $raw -Pattern "(?s)elseif \(\`$ValidityHours -gt \`$current\.OverlapHours\)[\s\S]*?pKIExpirationPeriod[\s\S]*?pKIOverlapPeriod" -Because "otherwise (growing back up, e.g. Restore), grows validity before overlap"
Assert-Match -Actual $raw -Pattern 'No safe write order found' -Because "the (believed impossible in practice) unsafe-either-way case still fails loudly with both old/new values named, not silently"
Assert-Match -Actual $raw -Pattern '\[double\]\$TestOverlapHours = 1' -Because "the session default overlap (1h) is strictly less than the default validity (2h) - equal defaults were the original live bug"
Assert-Match -Actual $raw -Pattern "(?s)while \(\`$true\)[\s\S]*?Read-Host `"Test overlap hours - must be LESS than validity[\s\S]*?if \(\`$overlapHours -lt \`$validityHours\) \{ break \}" -Because "the interactive prompt validates overlap < validity up front too, not just the session default"

# certreq has NO top-level "-Renew" switch (confirmed live 2026-09-10 - certreq.exe itself said
# "Unknown argument: -Renew" and dumped its real, positional syntax instead). Regression guard: never
# go back to asserting/running the wrong "-Renew -?" form.
Assert-NoMatch -Actual $raw -Pattern "certreq\.exe -Renew -\?" -Because "regression guard: certreq has no top-level -Renew switch - running '-Renew -?' just errors, confirmed live"
Assert-Match -Actual $raw -Pattern 'no top-level "-Renew" switch' -Because "explains why this isn't the guessed '-Renew' flag form, for anyone reading the transcript/output later"

Write-TestSummary -Suite "CA Manager - menu T (TameMyCerts renewal-idempotency test harness)"
