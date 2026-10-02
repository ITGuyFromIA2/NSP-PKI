<#
.SYNOPSIS
    CA Manager - menu option T. TameMyCerts renewal-idempotency test harness (TameMyCerts-PoC.md
    section 4). Folded into the shipped toolset (previously a standalone, zip-excluded script) so it
    travels with CAManager.zip like every other menu. Requires Modules\CACore.ps1, CAInteractive.ps1,
    and CATameMyCerts.ps1 (for Get-CATameMyCertsPlan) dot-sourced first.

.DESCRIPTION
    Walks the "set validity short, walk every renewal path, certutil-dump + diff the Subject" checklist:
    backs up + shortens the chosen template's pKIExpirationPeriod/pKIOverlapPeriod, snapshots the test
    cert before/after each path, asserts the resulting Subject carries EXACTLY ONE correct `OU=<token>`
    RDN (TameMyCerts' Force=true guarantee - no duplicate, no drift), drives the AD-group safety-net
    pair, and can show recent TameMyCerts event-log hits. Restores the template when done.

    Deliberately does NOT guess `certreq -Renew`'s exact CLI flags (they vary by Windows build) - that
    step runs `certreq -Renew -?` for you to read and leaves the actual command to you; it still does
    the before/after cert diff.

    SAFETY: mutates a REAL template object's validity/overlap/minor-version and REAL AD group
    membership. Refuses to run while the dashboard is in DRY RUN (menu D) - that toggle doesn't gate
    anything in here, so pretending it does would be worse than just refusing outright. Every step
    is wrapped in try/catch so one failing action returns you to this menu instead of killing the
    whole dashboard session (found live 2026-09-10: an unhandled exception with no per-step trap took
    the entire session down over a single bad step).
#>

$script:CARenewalTestBackupDir = Join-Path $env:ProgramData 'NSP\CAManager'

# --------------------------------------------------------------------------------------------------
# Template validity/overlap (pKIExpirationPeriod / pKIOverlapPeriod are little-endian 8-byte negative
# FILETIME durations in 100ns units - the same encoding certtmpl.msc's Validity/Renewal period fields
# write; standard, widely-published ADSI technique, unrelated to the certreq CLI syntax this module
# deliberately does not guess elsewhere).
# --------------------------------------------------------------------------------------------------
function ConvertTo-CARenewalPeriodBytes {
    <#
    .NOTES
        The leading comma is REQUIRED, not decorative - the same class of bug as the `(,$mod)` fix
        elsewhere in this file, via a different mechanism: PowerShell enumerates/flattens an array left
        as a function's unreturned last expression onto the output pipeline, and a caller capturing that
        back into a variable gets a re-boxed generic `System.Object[]`, NOT the original `System.Byte[]`.
        Found live 2026-09-10 on a client's CA server the hard way: the 2-hour test validity got silently
        stringified ("0 48 119 60 239 255 255 255", 27 ASCII bytes) instead of written as 8 raw bytes,
        because Set-CARenewalTemplateAttribute's `$Value -is [byte[]]` check saw an Object[] and took
        the wrong (string) write branch - the VALUE was correct the whole time, only its .NET type
        after passing through this function wasn't. `,(...)` forces a true single-element array so the
        one element (our real byte[]) survives pipeline unrolling intact instead of being re-boxed.
    #>
    param([Parameter(Mandatory)][double]$Hours)
    $ticks = [int64](-1 * $Hours * 3600 * 1e7)
    ,([BitConverter]::GetBytes($ticks))
}
function ConvertFrom-CARenewalPeriodBytes {
    param([Parameter(Mandatory)][byte[]]$Bytes)
    $ticks = [BitConverter]::ToInt64($Bytes, 0)
    [math]::Round((-1 * $ticks) / 1e7 / 3600, 3)
}

function Get-CARenewalConfigNC { ([ADSI]'LDAP://RootDSE').Properties['configurationNamingContext'][0] }

function Get-CARenewalTemplateAdsi {
    param([Parameter(Mandatory)][string]$TemplateCn)
    $configNC = Get-CARenewalConfigNC
    $obj = [ADSI]"LDAP://CN=$TemplateCn,CN=Certificate Templates,CN=Public Key Services,CN=Services,$configNC"
    if (-not $obj.distinguishedName) {
        throw "Template CN=$TemplateCn not found under Certificate Templates - check the exact CN (certutil -CATemplates), not the display name."
    }
    $obj
}

function Get-CARenewalTemplateOid {
    <#
    .SYNOPSIS
        The template's own msPKI-Cert-Template-OID - a unique, unambiguous string that appears
        VERBATIM in an issued cert's Template Information extension text (see Get-CARenewalTestCert's
        .NOTES for why matching on this instead of the CN/display name is the correct fix).
    #>
    param([Parameter(Mandatory)][string]$TemplateCn)
    $t = Get-CARenewalTemplateAdsi -TemplateCn $TemplateCn
    "$($t.Properties['msPKI-Cert-Template-OID'][0])"
}

function Get-CARenewalTemplateValidity {
    param([Parameter(Mandatory)][string]$TemplateCn)
    $t = Get-CARenewalTemplateAdsi -TemplateCn $TemplateCn
    [pscustomobject]@{
        TemplateCn    = $TemplateCn
        ValidityHours = ConvertFrom-CARenewalPeriodBytes ([byte[]]$t.Properties['pKIExpirationPeriod'][0])
        OverlapHours  = ConvertFrom-CARenewalPeriodBytes ([byte[]]$t.Properties['pKIOverlapPeriod'][0])
        Revision      = [int]$t.Properties['revision'][0]
        MinorRevision = [int]$t.Properties['msPKI-Template-Minor-Revision'][0]
    }
}

function Set-CARenewalTemplateAttribute {
    <#
    .SYNOPSIS
        Writes ONE attribute on a template object. Tries a raw LDAP modify via
        System.DirectoryServices.Protocols FIRST, falling back to the classic ADSI .Put()/.SetInfo()
        and then .Properties[name].Value/.CommitChanges() paths only if that throws.
    .NOTES
        Live-diagnosed on a client's CA server 2026-09-10 through a long process of elimination - object existence,
        AD delegation/ACL (confirmed via a real ObjectSecurity.Access dump: the account running this,
        a Domain Admins + Enterprise Admins member, has GenericAll), and overlap/validity write-order
        semantics were each independently ruled OUT with hard evidence, yet BOTH ADSI write mechanisms
        (.Put()/.SetInfo() and .Properties[name].Value/.CommitChanges()) kept failing identically with
        a bare "Unspecified error (0x80004005 E_FAIL)" - no useful detail, on every attribute, every
        write order, both APIs. The clincher: a RAW LDAP modify of the exact same attribute/value via
        System.DirectoryServices.Protocols.LdapConnection/ModifyRequest SUCCEEDED on the first try. So
        this is a genuine defect/quirk in the ADSI COM layer on that box (or an environment-specific
        ADSI bind-mode issue) - not AD, not permissions, not value semantics - and the fix is to bypass
        ADSI for the write entirely rather than keep guessing why it fails. The two ADSI paths stay as
        fallbacks (harmless, and might still work in some other environment) but are no longer trusted
        as primary.
        DirectoryAttributeModification.Add() only has byte[]/string/Uri overloads - a plain [int] (e.g.
        msPKI-Template-Minor-Revision) must be sent as its string form, matching how LDAP
        represents Integer-syntax attributes on the wire.
        `(,$mod)` is deliberate, not decorative: DirectoryAttributeModification is itself enumerable
        (CollectionBase), so a bare `@($mod)` FLATTENS it into its own held values instead of wrapping
        it as one array element - hit live while building this fix (ModifyRequest's constructor then
        tries to convert those raw values into DirectoryAttributeModification and throws). The leading
        comma forces a true one-element array without enumerating $mod.

        CORRECTION to the paragraph above: once pKIExpirationPeriod/pKIOverlapPeriod both started
        writing fine via the LDAP path, msPKI-Template-Minor-Revision KEPT failing (all 3 paths) with a
        DIFFERENT, more specific error - ERROR_DS_NO_ATTRIBUTE_OR_VALUE. Root cause: the attribute name
        used everywhere in this file used to be "msPKI-Template-Minor-Revision-Number" - THAT NAME DOES
        NOT EXIST. The real schema attribute is "msPKI-Template-Minor-Revision" (no "-Number" suffix) -
        confirmed by dumping $t.Properties.PropertyNames on the live object. The earlier "successful
        read" of this (wrong) name returning 0 was NEVER real data - ADSI's forgiving indexer let
        `.Properties['<nonexistent-name>'][0]` silently coerce to `[int]$null -> 0` instead of throwing,
        which is why the bug hid behind 3 separate write-path failures and multiple wrong theories
        (permissions, USN rollback, write ordering) before anyone actually checked whether the attribute
        NAME itself was real. Lesson: when ADSI write failures don't match documented AD semantics,
        verify exact attribute names against the live object's own PropertyNames FIRST, before reasoning
        about permissions/replication/ordering.
    #>
    param([Parameter(Mandatory)]$Adsi, [Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)]$Value)
    $errs = New-Object System.Collections.Generic.List[string]

    try {
        Add-Type -AssemblyName System.DirectoryServices.Protocols -ErrorAction Stop
        # LdapDirectoryIdentifier turned out to be a dead end on this runtime - neither New-Object
        # ...($null) (ambiguous overload) nor the zero-arg ::new() (this runtime's DirectoryServices.
        # Protocols build has no such overload at all - "argument count: 0", found live 2026-09-10)
        # actually work here. LdapConnection also just accepts a plain domain-name STRING directly
        # (exactly what the manually-verified working diagnostic script used) - derive it from the DN
        # we already have (its trailing DC=x,DC=y components) instead of hardcoding a domain name.
        $domainFqdn = ([regex]::Matches("$($Adsi.distinguishedName)", 'DC=([^,]+)') | ForEach-Object { $_.Groups[1].Value }) -join '.'
        if ([string]::IsNullOrWhiteSpace($domainFqdn)) { throw "could not derive a domain FQDN from '$($Adsi.distinguishedName)' - no DC= components found" }
        $ldap = New-Object System.DirectoryServices.Protocols.LdapConnection($domainFqdn)
        $ldap.AuthType = [System.DirectoryServices.Protocols.AuthType]::Negotiate
        $ldap.SessionOptions.ProtocolVersion = 3
        $mod = New-Object System.DirectoryServices.Protocols.DirectoryAttributeModification
        $mod.Name = $Name
        $mod.Operation = [System.DirectoryServices.Protocols.DirectoryAttributeOperation]::Replace
        if ($Value -is [byte[]]) { $mod.Add([byte[]]$Value) | Out-Null } else { $mod.Add([string]$Value) | Out-Null }
        $req = New-Object System.DirectoryServices.Protocols.ModifyRequest("$($Adsi.distinguishedName)", (,$mod))
        $ldap.SendRequest($req) | Out-Null
        return
    } catch {
        $detail = if ($_.Exception.Response) { "$($_.Exception.Response.ResultCode): $($_.Exception.Response.ErrorMessage)" } else { $_.Exception.Message }
        $errs.Add("LdapConnection/ModifyRequest: $detail")
    }

    try {
        $Adsi.Put($Name, $Value)
        $Adsi.SetInfo()
        Write-Host "    (wrote '$Name' via the classic .Put()/.SetInfo() path - the LDAP path failed first, see above)" -ForegroundColor DarkYellow
        return
    } catch {
        $hr = if ($_.Exception.InnerException) { $_.Exception.InnerException.HResult } else { $_.Exception.HResult }
        $errs.Add((".Put()/.SetInfo(): 0x{0:X8} - {1}" -f $hr, $_.Exception.Message))
    }
    try {
        $Adsi.Properties[$Name].Value = $Value
        $Adsi.CommitChanges()
        Write-Host "    (wrote '$Name' via the .Properties[]/.CommitChanges() fallback - both other paths failed first, see above)" -ForegroundColor DarkYellow
        return
    } catch {
        $hr = if ($_.Exception.InnerException) { $_.Exception.InnerException.HResult } else { $_.Exception.HResult }
        $errs.Add((".Properties[]/.CommitChanges(): 0x{0:X8} - {1}" -f $hr, $_.Exception.Message))
    }
    throw ("could not write '$Name' on '$($Adsi.distinguishedName)' by any of 3 write paths (LDAP + 2 ADSI):`n" +
        (($errs | ForEach-Object { "    $_" }) -join "`n") +
        "`n  Object existence, ACL/permissions, and value semantics have all been independently ruled out" +
        "`n  as causes for this specific template before (see this function's .NOTES) - if you're hitting" +
        "`n  this fresh on a DIFFERENT template/box, don't assume the same root cause; start over with the" +
        "`n  actual LDAP-side error text above rather than re-deriving conclusions from the ADSI ones.")
}

function Set-CARenewalTemplateValidity {
    <#
    .NOTES
        pKIOverlapPeriod must stay STRICTLY LESS than pKIExpirationPeriod at all times, INCLUDING at
        every intermediate step while getting from the old pair to the new one - AD appears to reject
        a write that would (even momentarily) leave overlap >= validity (found live 2026-09-10 on
        a client's CA server: writing pKIExpirationPeriod down to a small test value FIRST, while the old large
        pKIOverlapPeriod was still in place, threw a bare E_FAIL from BOTH ADSI write paths - the ACL
        was confirmed fine, so this is the real cause, not permissions). Refuses ValidityHours <=
        OverlapHours outright (that target state can never be valid) and picks whichever write ORDER
        keeps the pair valid at every step: if the OLD validity is big enough to still exceed the NEW
        overlap, shrink overlap first, then validity; otherwise (growing back to bigger values, e.g.
        Restore) grow validity first, then overlap.
    #>
    param([Parameter(Mandatory)][string]$TemplateCn, [Parameter(Mandatory)][double]$ValidityHours, [Parameter(Mandatory)][double]$OverlapHours)
    if ($OverlapHours -ge $ValidityHours) {
        throw "OverlapHours ($OverlapHours) must be LESS than ValidityHours ($ValidityHours) - AD rejects an overlap >= validity combination outright, it's not a valid template state."
    }
    $t = Get-CARenewalTemplateAdsi -TemplateCn $TemplateCn
    $current = Get-CARenewalTemplateValidity -TemplateCn $TemplateCn

    $expBytes = ConvertTo-CARenewalPeriodBytes $ValidityHours
    $ovlBytes = ConvertTo-CARenewalPeriodBytes $OverlapHours
    if ($current.ValidityHours -gt $OverlapHours) {
        # old validity already exceeds the new (smaller) overlap - safe to shrink overlap first
        Set-CARenewalTemplateAttribute -Adsi $t -Name 'pKIOverlapPeriod'    -Value $ovlBytes
        Set-CARenewalTemplateAttribute -Adsi $t -Name 'pKIExpirationPeriod' -Value $expBytes
    } elseif ($ValidityHours -gt $current.OverlapHours) {
        # new validity already exceeds the old overlap - safe to grow validity first
        Set-CARenewalTemplateAttribute -Adsi $t -Name 'pKIExpirationPeriod' -Value $expBytes
        Set-CARenewalTemplateAttribute -Adsi $t -Name 'pKIOverlapPeriod'    -Value $ovlBytes
    } else {
        throw "No safe write order found: old (validity=$($current.ValidityHours)h, overlap=$($current.OverlapHours)h) -> new (validity=${ValidityHours}h, overlap=${OverlapHours}h) - both intermediate states would leave overlap >= validity. Pick a new-value pair closer to the current one, or apply the change in two smaller steps."
    }

    # Non-fatal: the validity/overlap change above (the actual point of this function) already
    # succeeded by the time we get here - a separate problem writing the minor-revision bump (found
    # live 2026-09-10 on a client's CA server: ERROR_DS_NO_ATTRIBUTE_OR_VALUE on this one specific attribute,
    # still under investigation) should warn, not undo/block that already-applied change.
    $minor = [int]$t.Properties['msPKI-Template-Minor-Revision'][0]
    try {
        Set-CARenewalTemplateAttribute -Adsi $t -Name 'msPKI-Template-Minor-Revision' -Value ($minor + 1)
        Write-Host "  Template '$TemplateCn': validity -> ${ValidityHours}h, overlap -> ${OverlapHours}h, minor rev -> $($minor + 1)." -ForegroundColor Gray
    } catch {
        Write-Host "  Template '$TemplateCn': validity -> ${ValidityHours}h, overlap -> ${OverlapHours}h (APPLIED)." -ForegroundColor Gray
        Write-Host "  WARNING: minor-revision bump did NOT apply - $($_.Exception.Message)" -ForegroundColor Yellow
        Write-Host "  Validity/overlap themselves are still live and testable; the version bump is a separate, secondary concern used by menu items 2/4 later." -ForegroundColor DarkYellow
    }
}

function Backup-CARenewalTemplateValidity {
    param([Parameter(Mandatory)][string]$TemplateCn)
    $backupPath = Join-Path $script:CARenewalTestBackupDir "TmcRenewalTest_$TemplateCn.json"
    if (Test-Path $backupPath) {
        Write-Host "  Backup already exists at $backupPath - not overwriting (assuming a prior run's ORIGINAL values). Delete it by hand if this is wrong." -ForegroundColor DarkYellow
        return
    }
    New-Item -ItemType Directory -Path $script:CARenewalTestBackupDir -Force -ErrorAction SilentlyContinue | Out-Null
    $orig = Get-CARenewalTemplateValidity -TemplateCn $TemplateCn
    $orig | ConvertTo-Json | Set-Content -Path $backupPath -Encoding UTF8
    Write-Host "  Backed up original validity/overlap/minor-rev to $backupPath" -ForegroundColor Gray
    $orig
}

function Restore-CARenewalTemplateValidity {
    <#
    .NOTES
        Set-CARenewalTemplateValidity's own minor-revision bump is a side-effect (always current+1,
        marking that ITS OWN edit happened) - it's not a restore to the ORIGINAL captured value, and it
        never touches 'revision' (Major Version Number) at all. Since Step-CARenewalBumpTemplateVersion
        now also mutates 'revision' (found live 2026-09-10 that only a MAJOR version bump reliably
        forces reenrollment - see its .NOTES), Restore must explicitly force both back to their exact
        backed-up values, not just call Set-CARenewalTemplateValidity and assume that's sufficient.
    #>
    param([Parameter(Mandatory)][string]$TemplateCn)
    $backupPath = Join-Path $script:CARenewalTestBackupDir "TmcRenewalTest_$TemplateCn.json"
    if (-not (Test-Path $backupPath)) { Write-Host "  No backup found at $backupPath - nothing to restore." -ForegroundColor Yellow; return }
    $orig = Get-Content $backupPath -Raw | ConvertFrom-Json
    Set-CARenewalTemplateValidity -TemplateCn $TemplateCn -ValidityHours $orig.ValidityHours -OverlapHours $orig.OverlapHours
    $t = Get-CARenewalTemplateAdsi -TemplateCn $TemplateCn
    # A backup file written before 'Revision' was added to this schema has no captured value - [int]$null
    # would be 0, a genuinely bad thing to write to a template's major version. Skip it, warn, rather
    # than silently corrupt 'revision' from an incomplete old backup.
    if ($orig.PSObject.Properties['Revision'] -and $null -ne $orig.Revision) {
        Set-CARenewalTemplateAttribute -Adsi $t -Name 'revision' -Value ([int]$orig.Revision)
    } else {
        Write-Host "  WARNING: this backup predates 'Revision' (major version) tracking - leaving 'revision' as-is. Check/restore it by hand if menu 2/4 bumped it this session." -ForegroundColor Yellow
    }
    Set-CARenewalTemplateAttribute -Adsi $t -Name 'msPKI-Template-Minor-Revision' -Value ([int]$orig.MinorRevision)
    Remove-Item $backupPath -Force
    Write-Host "  Restored '$TemplateCn' to its original validity ($($orig.ValidityHours)h) / overlap ($($orig.OverlapHours)h)$(if ($orig.PSObject.Properties['Revision']) { " / version ($($orig.Revision).$($orig.MinorRevision))" })." -ForegroundColor Green
}

function Step-CARenewalBumpTemplateVersion {
    <#
    .NOTES
        Bumps BOTH `revision` (the "Major Version Number" shown in a cert's Template Information
        extension) and `msPKI-Template-Minor-Revision` ("Minor Version Number") - NOT just the minor
        field alone, which is what this originally did.
        Found live 2026-09-10 on a client's CA server: bumping ONLY msPKI-Template-Minor-Revision (5 -> 7, real,
        confirmed on AD, CertSvc restart ruled out as a factor) did NOT trigger autoenrollment to
        reenroll an existing, still-valid cert on the next gpupdate+pulse - nothing happened, no error,
        no event log entry, repeatedly. Bumping `revision` (Major Version Number) INSTEAD did trigger
        it immediately. This matches Microsoft's own major/minor semantics for certificate templates: a
        minor bump signals a change that does NOT require existing holders to reenroll (e.g. ACL/
        permission edits); only a major bump is treated as "this cert is now out of date, reenroll
        regardless of the renewal/overlap window." Bump both here so this function reliably forces
        reenrollment for both menu items that use it (4.2 "new key via version bump", 4.4 "superseded
        template") - both are testing "force reenrollment independent of the window", which needs
        `revision`, not just the minor field.
    #>
    param([Parameter(Mandatory)][string]$TemplateCn)
    $t = Get-CARenewalTemplateAdsi -TemplateCn $TemplateCn
    $major = [int]$t.Properties['revision'][0]
    $minor = [int]$t.Properties['msPKI-Template-Minor-Revision'][0]
    Set-CARenewalTemplateAttribute -Adsi $t -Name 'revision' -Value ($major + 1)
    Set-CARenewalTemplateAttribute -Adsi $t -Name 'msPKI-Template-Minor-Revision' -Value ($minor + 1)
    Write-Host "  '$TemplateCn' version bumped to $($major + 1).$($minor + 1) (major.minor) - re-run CA-Manager menu 4 so the CA republishes it, then pulse the client." -ForegroundColor Gray
}

# --------------------------------------------------------------------------------------------------
# Cert lookup / subject verification - the actual pass/fail engine for every renewal path
# --------------------------------------------------------------------------------------------------
$script:CARenewalCertLookupScript = {
    param([string]$TemplateOid, [string]$StoreLocation)
    Get-ChildItem "Cert:\$StoreLocation\My" -ErrorAction SilentlyContinue | Where-Object {
        $tplExt = $_.Extensions | Where-Object { $_.Oid.Value -in '1.3.6.1.4.1.311.21.7', '1.3.6.1.4.1.311.20.2' }
        $tplExt | ForEach-Object { $_.Format($true) } | Where-Object { $_ -match [regex]::Escape($TemplateOid) }
    } | Sort-Object NotBefore -Descending | ForEach-Object {
        # Only plain properties, deliberately - a remote Invoke-Command call deserializes the return
        # value, which strips live .NET methods (.Extensions, .Format(), etc.) from an X509Certificate2;
        # Test-CARenewalCertOuSubject only ever needs .Subject/.Thumbprint/.NotBefore, so returning a
        # flat pscustomobject keeps local and remote callers identical instead of needing 2 code paths.
        [pscustomobject]@{ Subject = $_.Subject; Thumbprint = $_.Thumbprint; NotBefore = $_.NotBefore }
    }
}

function Get-CARenewalTestCert {
    <#
    .SYNOPSIS
        Matches the Certificate Template Information (1.3.6.1.4.1.311.21.7) or the older Certificate
        Template Name (1.3.6.1.4.1.311.20.2) extension's formatted text against the template's OWN OID
        (msPKI-Cert-Template-OID, from Get-CARenewalTemplateOid) - NOT its CN or display name.
    .NOTES
        Originally matched against the template CN (e.g. "NSPIKEv2VPN") - WRONG. Found live
        2026-09-10 on a client's CA server: `.Format($true)` embeds the template's DISPLAY NAME
        ("NSP-IKEv2-VPN", with hyphens), never the CN, so a CN match against that text can never
        succeed (the hyphens break substring continuity) - every cert lookup silently returned nothing,
        making every PASS/FAIL meaningless, even once the remoting fix (below) was in place and
        genuinely working. The template's own OID is unique and appears VERBATIM in that formatted
        text regardless of CN/display-name conventions, so it's the only reliable match key.
    .PARAMETER ComputerName
        When supplied, queries that machine's cert store via PowerShell remoting instead of the LOCAL
        one. Required for the realistic topology (CA-Manager runs on the CA; the actual test cert lives
        on a separate VPN client) - found live 2026-09-10 on a client's CA server: every "Cert before/after" check
        was silently checking the CA server's OWN cert store, which never has the test cert, making
        every PASS/FAIL in this harness meaningless until this was added. Needs WinRM reachable/trusted
        between this box and the target (domain-joined defaults just work via Kerberos).
    #>
    param([Parameter(Mandatory)][string]$TemplateOid, [ValidateSet('CurrentUser', 'LocalMachine')][string]$StoreLocation = 'CurrentUser', [string]$ComputerName)
    if ([string]::IsNullOrWhiteSpace($ComputerName)) {
        & $script:CARenewalCertLookupScript $TemplateOid $StoreLocation
    } else {
        try {
            Invoke-Command -ComputerName $ComputerName -ScriptBlock $script:CARenewalCertLookupScript -ArgumentList $TemplateOid, $StoreLocation -ErrorAction Stop
        } catch {
            throw "Could not query the cert store on '$ComputerName' via PowerShell remoting - $($_.Exception.Message)`n  Confirm WinRM is enabled there (Enable-PSRemoting -Force, run on '$ComputerName') and reachable from this box (Test-WSMan -ComputerName '$ComputerName')."
        }
    }
}

function Test-CARenewalCertOuSubject {
    param([Parameter(Mandatory)]$Cert, [Parameter(Mandatory)][string]$ExpectedOu)
    $subject = $Cert.Subject
    $ouMatches = [regex]::Matches($subject, 'OU=([^,]+)')
    $pass = ($ouMatches.Count -eq 1) -and ($ouMatches[0].Groups[1].Value -eq $ExpectedOu)
    [pscustomobject]@{
        Subject    = $subject
        OuCount    = $ouMatches.Count
        OuValues   = @($ouMatches | ForEach-Object { $_.Groups[1].Value })
        Pass       = $pass
        Thumbprint = $Cert.Thumbprint
        NotBefore  = $Cert.NotBefore
    }
}

function Add-CARenewalResult {
    param([System.Collections.Generic.List[object]]$Results, [string]$Step, [bool]$Pass, [string]$Detail)
    $Results.Add([pscustomobject]@{ Step = $Step; Pass = $Pass; Detail = $Detail; At = Get-Date })
}

function Wait-CARenewalClientEvent {
    <#
    .SYNOPSIS
        Polls the VPN client's certificate lifecycle event log (over the same remoting used
        everywhere else) for up to -TimeoutSeconds, looking for anything timestamped after -Since,
        instead of blindly asking the operator to press Enter and hope the async enrollment finished.
    .NOTES
        The commands that trigger enrollment (gpupdate, certutil -pulse, certreq) are synchronous and
        return well before the AutoEnrollment client-side extension actually finishes acting on them -
        this closes that gap by watching for the real completion signal (an actual lifecycle event)
        instead of guessing at a fixed sleep. Falls back to nothing (caller does its own Read-Host) when
        no -ComputerName is given - there's no log to poll for a check against the local machine.
    #>
    param(
        [Parameter(Mandatory)][string]$ComputerName,
        [Parameter(Mandatory)][datetime]$Since,
        [int]$TimeoutSeconds = 45,
        [int]$PollIntervalSeconds = 3
    )
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    Write-Host "  Waiting up to ${TimeoutSeconds}s for a cert-lifecycle event on '$ComputerName'..." -ForegroundColor Gray -NoNewline
    while ((Get-Date) -lt $deadline) {
        try {
            $found = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
                param($Since)
                Get-WinEvent -LogName 'Microsoft-Windows-CertificateServicesClient-Lifecycle-User/Operational' -MaxEvents 20 -ErrorAction SilentlyContinue |
                    Where-Object { $_.TimeCreated -gt $Since } | Sort-Object TimeCreated |
                    ForEach-Object {
                        $action = try { ([xml]$_.ToXml()).Event.UserData.CertNotificationData.Action } catch { $null }
                        [pscustomobject]@{ TimeCreated = $_.TimeCreated; Id = $_.Id; Action = $action }
                    }
            } -ArgumentList $Since -ErrorAction Stop
        } catch {
            Write-Host ""
            Write-Host "  (could not poll the event log remotely - $($_.Exception.Message))" -ForegroundColor DarkYellow
            return @()
        }
        if ($found) {
            Write-Host " done." -ForegroundColor Gray
            foreach ($f in $found) { Write-Host "  Event: $($f.TimeCreated)  Id=$($f.Id)  Action=$($f.Action)" -ForegroundColor DarkGray }
            return @($found)
        }
        Write-Host "." -ForegroundColor Gray -NoNewline
        Start-Sleep -Seconds $PollIntervalSeconds
    }
    Write-Host ""
    Write-Host "  No cert-lifecycle event seen within ${TimeoutSeconds}s - may still be pending, or genuinely nothing changed." -ForegroundColor Yellow
    return @()
}

function Invoke-CARenewalStep {
    <# Snapshot -> trigger the real action -> wait for the client to actually finish (event-log poll
       when remoting, a manual Read-Host gate otherwise) -> diff + verify. Shared engine behind every
       "walk this path, certutil -dump after" checklist bullet. #>
    param(
        # AllowEmptyCollection is required, not decorative - a Mandatory collection-typed parameter
        # otherwise rejects an empty List[object] outright ("Cannot bind argument... because it is an
        # empty collection"), and $results legitimately starts empty until the first step completes -
        # found live 2026-09-10 on a client's CA server on the very first Invoke-CARenewalStep call of a session.
        [Parameter(Mandatory)][AllowEmptyCollection()][System.Collections.Generic.List[object]]$Results,
        [Parameter(Mandatory)][string]$StepName,
        [Parameter(Mandatory)][scriptblock]$Instructions,
        [Parameter(Mandatory)][string]$TemplateCn,
        [Parameter(Mandatory)][string]$TemplateOid,   # the actual cert-store match key - see Get-CARenewalTestCert's .NOTES (matching on the CN/display name doesn't work)
        [Parameter(Mandatory)][string]$ExpectedOu,
        [string]$CertStore = 'CurrentUser',
        [string]$ClientComputerName,   # blank = check the LOCAL machine's store (only correct if CA-Manager itself runs where the cert lands)
        [bool]$ExpectChange = $true    # $false for the "removed from group -> should NOT get a fresh cert" safety-net check
    )
    Write-Host "`n=== $StepName ===" -ForegroundColor Cyan
    $before = Get-CARenewalTestCert -TemplateOid $TemplateOid -StoreLocation $CertStore -ComputerName $ClientComputerName | Select-Object -First 1
    Write-Host ("  Cert before: {0}" -f $(if ($before) { "$($before.Thumbprint)  (NotBefore $($before.NotBefore))" } else { '(none found)' })) -ForegroundColor Gray

    $stepStart = Get-Date
    & $Instructions
    if ([string]::IsNullOrWhiteSpace($ClientComputerName)) {
        Read-Host "  Press Enter once that's done (and the client has actually attempted the enrollment/renewal)" | Out-Null
    } else {
        Wait-CARenewalClientEvent -ComputerName $ClientComputerName -Since $stepStart -TimeoutSeconds 45 | Out-Null
    }

    $after = Get-CARenewalTestCert -TemplateOid $TemplateOid -StoreLocation $CertStore -ComputerName $ClientComputerName | Select-Object -First 1
    $changed = ($before.Thumbprint -ne $after.Thumbprint)

    if (-not $ExpectChange) {
        $pass = -not $changed
        $detail = if ($pass) { 'no new cert issued - consistent with a denied enrollment (confirm you also saw a denial, not silence, on the client)' } else { "a NEW cert was issued anyway ($($after.Thumbprint)) - the ACL removal did NOT block enrollment" }
        Write-Host ("  {0}" -f $detail) -ForegroundColor $(if ($pass) { 'Green' } else { 'Red' })
        Add-CARenewalResult -Results $Results -Step $StepName -Pass $pass -Detail $detail
        return
    }

    if (-not $after) {
        Write-Host "  FAIL - no certificate found for template '$TemplateCn' after the step." -ForegroundColor Red
        Add-CARenewalResult -Results $Results -Step $StepName -Pass $false -Detail 'no cert found after the step'
        return
    }
    $subjTest = Test-CARenewalCertOuSubject -Cert $after -ExpectedOu $ExpectedOu
    $pass = $subjTest.Pass -and $changed
    $color = if ($pass) { 'Green' } else { 'Red' }
    Write-Host ("  Cert after : {0}  (changed: {1})" -f $after.Thumbprint, $changed) -ForegroundColor Gray
    Write-Host ("  Subject    : {0}" -f $subjTest.Subject) -ForegroundColor Gray
    Write-Host ("  OU count   : {0}  (values: {1}; expected: {2})" -f $subjTest.OuCount, ($subjTest.OuValues -join ', '), $ExpectedOu) -ForegroundColor $color
    if (-not $changed) { Write-Host "  NOTE: thumbprint didn't change - was this actually a renewal, or the same cert re-read?" -ForegroundColor DarkYellow }
    Write-Host ("  => {0}" -f $(if ($pass) { 'PASS - single, correct OU=, and a new cert was actually issued' } else { 'FAIL - check for duplicate/drifted/missing OU or a no-op' })) -ForegroundColor $color
    Add-CARenewalResult -Results $Results -Step $StepName -Pass $pass -Detail $subjTest.Subject
}

# --------------------------------------------------------------------------------------------------
# Client-side pulse - now that -ClientComputerName remoting is proven live, drive certutil -pulse
# itself instead of leaving it as a manual "go run this on the client" instruction.
# --------------------------------------------------------------------------------------------------
function Step-CARenewalCertReqOnClient {
    <#
    .SYNOPSIS
        Runs `certreq -enroll -cert <thumbprint> Renew [ReuseKeys]` on the VPN client (the CONFIRMED,
        not guessed, positional syntax - certreq.exe has no top-level "-Renew" switch at all; see menu
        item 3's own comments for how this was determined live 2026-09-10) via a TIME-BOUNDED remote
        job, falling back to a manual instruction+prompt if no -ComputerName is set, if it doesn't
        finish within the timeout, or if the remote call fails outright.
    .NOTES
        Found live 2026-09-10 on a client's test VPN client machine that this SAME command intermittently pops an interactive
        prompt (signing cert/CSP-related) with nowhere to go over a non-interactive WinRM session - one
        pass hung and needed the operator to kill an orphaned certreq.exe by hand; the very next pass
        completed cleanly in seconds. Since it's not reliably safe OR reliably unsafe, this runs it as
        an -AsJob with a bounded Wait-Job timeout instead of either a blocking Invoke-Command (which
        can hang this whole dashboard session indefinitely, not just the client) or going fully manual
        (which throws away the common case where it just works). On timeout, the job is left running
        server-side (Invoke-Command jobs don't reliably kill a stuck remote process on stop) and control
        hands back to the operator to check/kill it on the client themselves.
    #>
    param([Parameter(Mandatory)][string]$Thumbprint, [switch]$ReuseKeys, [string]$StoreLocation = 'CurrentUser', [string]$ComputerName, [int]$TimeoutSeconds = 25)
    $keyArgs = if ($ReuseKeys) { @('Renew', 'ReuseKeys') } else { @('Renew') }
    $cmdText = "certreq -enroll -cert $Thumbprint $($keyArgs -join ' ')" + $(if ($StoreLocation -eq 'LocalMachine') { ' -machine' } else { '' })
    if ([string]::IsNullOrWhiteSpace($ComputerName)) {
        Write-Host "  Run this on the CLIENT: $cmdText" -ForegroundColor Yellow
        Read-Host "  Press Enter once that's done" | Out-Null
        return
    }
    Write-Host "  Running remotely on '$ComputerName' (up to ${TimeoutSeconds}s): $cmdText" -ForegroundColor Gray
    $job = $null
    try {
        $job = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            param($Thumbprint, $KeyArgs, $Machine)
            $argList = @('-enroll', '-cert', $Thumbprint) + $KeyArgs
            if ($Machine) { $argList += '-machine' }
            & certreq.exe @argList 2>&1 | Out-String
        } -ArgumentList $Thumbprint, $keyArgs, ($StoreLocation -eq 'LocalMachine') -AsJob -ErrorAction Stop
        if (Wait-Job -Job $job -Timeout $TimeoutSeconds) {
            $out = Receive-Job -Job $job -ErrorAction SilentlyContinue
            if ($out) { Write-Host "  $(($out | Out-String).Trim())" -ForegroundColor DarkGray }
        } else {
            Write-Host "  Still running after ${TimeoutSeconds}s - it may be stuck on an interactive prompt (signing cert/CSP selection) that has nowhere to go over remoting." -ForegroundColor Red
            Write-Host "  Go check the client (Task Manager -> certreq.exe - answer the prompt or kill it), or just run it yourself: $cmdText" -ForegroundColor Yellow
            Read-Host "  Press Enter once you've handled it on the client" | Out-Null
        }
    } catch {
        Write-Host "  Could not run certreq remotely on '$ComputerName' - $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "  Run it manually on the client instead: $cmdText" -ForegroundColor Yellow
        Read-Host "  Press Enter once that's done" | Out-Null
    } finally {
        if ($job) { Remove-Job -Job $job -Force -ErrorAction SilentlyContinue }
    }
}

function Step-CARenewalDeleteClientCert {
    <#
    .SYNOPSIS
        Deletes one cert (by thumbprint) from the VPN client's store via the same PS remoting already
        used for cert-store checks and pulsing, so item 4.5 (delete + re-issue fresh) doesn't require a
        manual certmgr.msc trip either. Falls back to a manual prompt when no -ComputerName was given.
    #>
    param([Parameter(Mandatory)][string]$Thumbprint, [string]$StoreLocation = 'CurrentUser', [string]$ComputerName)
    if ([string]::IsNullOrWhiteSpace($ComputerName)) {
        Write-Host "  Delete it now on the CLIENT: Remove-Item Cert:\$StoreLocation\My\$Thumbprint (or via certmgr.msc)." -ForegroundColor Yellow
        Read-Host "  Press Enter once you've deleted it" | Out-Null
        return
    }
    Write-Host "  Deleting $Thumbprint remotely on '$ComputerName'..." -ForegroundColor Gray
    try {
        Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            param($Thumbprint, $StoreLocation)
            $path = "Cert:\$StoreLocation\My\$Thumbprint"
            if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path -Force; "deleted" } else { "not found - already gone?" }
        } -ArgumentList $Thumbprint, $StoreLocation -ErrorAction Stop | ForEach-Object { Write-Host "  $_" -ForegroundColor DarkGray }
    } catch {
        Write-Host "  Could not delete $Thumbprint remotely on '$ComputerName' - $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "  Delete it manually instead: Remove-Item Cert:\$StoreLocation\My\$Thumbprint" -ForegroundColor Yellow
        Read-Host "  Press Enter once you've deleted it" | Out-Null
    }
}

function Step-CARenewalPulseClient {
    <#
    .SYNOPSIS
        Runs `gpupdate /force` then `certutil -pulse` on the VPN client via the same PS remoting
        already used for cert-store checks, so the operator doesn't have to alt-tab to the client for
        every single step. Falls back to printing the manual instructions when no -ClientComputerName
        was given (local-only sessions).
    .NOTES
        gpupdate /force first is required, not just belt-and-suspenders - found live 2026-09-10 on
        a client's CA server: a bare certutil -pulse alone did not pick up a template's minor-version bump (item
        4.2's whole point), because the autoenrollment client's view of which template version applies
        is refreshed via the Group Policy CSE, not by certutil -pulse itself. Running gpupdate first
        makes every step correct, including the plain-renewal ones (1, 4.5, 4.6a/b) where it's a no-op.
    #>
    param([string]$ComputerName)
    if ([string]::IsNullOrWhiteSpace($ComputerName)) {
        Write-Host "  On the CLIENT: gpupdate /force, then certutil -pulse" -ForegroundColor Yellow
        return
    }
    Write-Host "  Refreshing policy + pulsing autoenrollment remotely on '$ComputerName' (gpupdate /force, then certutil -pulse)..." -ForegroundColor Gray
    try {
        $out = Invoke-Command -ComputerName $ComputerName -ScriptBlock { gpupdate /force 2>&1 | Out-String; certutil -pulse 2>&1 | Out-String } -ErrorAction Stop
        if ($out) { Write-Host "  $(($out | Out-String).Trim())" -ForegroundColor DarkGray }
    } catch {
        Write-Host "  Could not run gpupdate/certutil -pulse remotely on '$ComputerName' - $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "  Run it manually on the client instead: gpupdate /force, then certutil -pulse" -ForegroundColor Yellow
    }
}

# --------------------------------------------------------------------------------------------------
# Event log (did TameMyCerts even see the request?)
# --------------------------------------------------------------------------------------------------
function Get-CARenewalTameMyCertsEvents {
    param([datetime]$Since = (Get-Date).AddHours(-6))
    Get-WinEvent -FilterHashtable @{ LogName = 'Application'; StartTime = $Since } -ErrorAction SilentlyContinue |
        Where-Object { $_.Message -match 'TameMyCerts' -or $_.ProviderName -match 'TameMyCerts' } |
        Select-Object TimeCreated, Id, ProviderName, LevelDisplayName, Message |
        Sort-Object TimeCreated
}

# --------------------------------------------------------------------------------------------------
# Group-change safety net
# --------------------------------------------------------------------------------------------------
function Test-CARenewalUserHasPrivilegedGroup {
    <#
    .SYNOPSIS
        Read-only. Checks whether $TestUser is a DIRECT member of Domain Admins or Enterprise Admins -
        both typically carry GenericAll (and therefore implicit Enroll/AutoEnroll) on every certificate
        template by default AD CS delegation, entirely independent of any RADIUS/VPN group's own ACL.
    .NOTES
        Found live 2026-09-10 on a client's CA server: menu item 6 (group-removal safety net) kept showing
        "enrollment succeeded anyway" no matter how many times the test user was removed from
        PrimaryGroup - because that user (nspadmin) is ALSO a Domain Admins/Enterprise Admins member,
        and those groups' rights on the template have nothing to do with PrimaryGroup membership. Not
        a bug in the removal/ACL logic - the chosen test user just can't validly be denied this way.
        Only checks these two specific, extremely common groups by name - a pragmatic catch for the
        exact case hit live, not a full cross-reference of every group the user belongs to against the
        template's actual ACL.
    #>
    param([Parameter(Mandatory)][string]$TestUser)
    try {
        Import-Module ActiveDirectory -ErrorAction Stop
        $groups = @((Get-ADUser -Identity $TestUser -Properties MemberOf -ErrorAction Stop).MemberOf)
        $hits = @($groups | Where-Object { $_ -match '^CN=(Domain Admins|Enterprise Admins),' } | ForEach-Object { ($_ -split ',')[0] -replace '^CN=' })
        [pscustomobject]@{ IsPrivileged = [bool]$hits.Count; MatchedGroups = $hits }
    } catch {
        [pscustomobject]@{ IsPrivileged = $false; MatchedGroups = @() }
    }
}

function Step-CARenewalRemoveFromGroup {
    param([Parameter(Mandatory)][string]$TestUser, [Parameter(Mandatory)][string]$Group)
    if (-not (Read-CAConfirm -Prompt "Remove '$TestUser' from '$Group' now?")) { return }
    Import-Module ActiveDirectory -ErrorAction Stop
    Remove-ADGroupMember -Identity $Group -Members $TestUser -Confirm:$false
    Write-Host "  Removed. AD group membership is cached in the user's Kerberos ticket - on the CLIENT, run 'klist purge' (or log off/on) before the next enrollment attempt, or the old membership may still apply." -ForegroundColor Yellow
}
function Step-CARenewalAddToGroup {
    param([Parameter(Mandatory)][string]$TestUser, [Parameter(Mandatory)][string]$Group, [switch]$Confirm)
    if ($Confirm -and -not (Read-CAConfirm -Prompt "Add '$TestUser' to '$Group' now?")) { return }
    Import-Module ActiveDirectory -ErrorAction Stop
    Add-ADGroupMember -Identity $Group -Members $TestUser
    Write-Host "  Added '$TestUser' to '$Group'. Same Kerberos-ticket caveat as removal applies." -ForegroundColor Yellow
}

# --------------------------------------------------------------------------------------------------
# session menu (the checklist walkthrough)
# --------------------------------------------------------------------------------------------------
function Show-CARenewalResultsTable {
    param([Parameter(Mandatory)][AllowEmptyCollection()][System.Collections.Generic.List[object]]$Results)
    if (-not $Results.Count) { Write-Host "  (no steps run yet)" -ForegroundColor DarkGray; return }
    Write-Host ""
    Write-Host ("  {0,-55} {1,-6} {2}" -f 'Step', 'Pass', 'Detail') -ForegroundColor DarkGray
    Write-Host ("  " + ('-' * 100)) -ForegroundColor DarkGray
    foreach ($r in $Results) {
        Write-Host ("  {0,-55} {1,-6} {2}" -f $r.Step, $(if ($r.Pass) { 'PASS' } else { 'FAIL' }), $r.Detail) -ForegroundColor $(if ($r.Pass) { 'Green' } else { 'Red' })
    }
}

function Invoke-CARenewalTestSession {
    param(
        [Parameter(Mandatory)][string]$TemplateCn,
        [Parameter(Mandatory)][string]$ExpectedOu,
        [Parameter(Mandatory)][string]$TestUser,
        [string]$PrimaryGroup,
        [string]$AlternateGroup,
        [string]$AlternateOu,
        [string]$CertStore = 'CurrentUser',
        # Blank = check the LOCAL machine's cert store (only correct if CA-Manager itself runs on the
        # box holding the test cert). Set this to the VPN client's hostname for the realistic topology
        # (CA-Manager on the CA, test cert on a separate client) - found live 2026-09-10 on a client's CA server:
        # every before/after check was silently looking at the CA's OWN store, so every PASS/FAIL was
        # meaningless until this was wired up. Needs WinRM reachable/trusted to that client.
        [string]$ClientComputerName,
        [double]$TestValidityHours = 2,
        [double]$TestOverlapHours = 1   # must stay < TestValidityHours - see Set-CARenewalTemplateValidity's .NOTES
    )

    $results = New-Object System.Collections.Generic.List[object]
    # Resolved ONCE - the template doesn't change mid-session, and every cert lookup below needs this
    # exact OID (not the CN/display name - see Get-CARenewalTestCert's .NOTES for why that never matched).
    $templateOid = Get-CARenewalTemplateOid -TemplateCn $TemplateCn
    Write-Host "`nTameMyCerts renewal-idempotency session - template '$TemplateCn' (OID $templateOid), expected OU '$ExpectedOu', user '$TestUser'" -ForegroundColor Cyan
    if ($ClientComputerName) {
        Write-Host "Checking the cert store on '$ClientComputerName' via PowerShell remoting (WinRM must be reachable/trusted there)." -ForegroundColor DarkGray
    } else {
        Write-Host "No -ClientComputerName set - checking the LOCAL machine's cert store. If the test cert actually lands on a separate client, every PASS/FAIL below will be meaningless." -ForegroundColor Yellow
    }

    while ($true) {
        Write-Host ""
        Write-Host "  0) Backup + shorten validity/overlap ($TestValidityHours h / $TestOverlapHours h) - do this FIRST" -ForegroundColor White
        Write-Host "  1) 4.1 Autoenrollment renewal - SAME key (pulse the client, no version bump)"
        Write-Host "  2) 4.2 Autoenrollment renewal - NEW key (bump minor version, then pulse the client)"
        Write-Host "  3) 4.3 certreq -Renew (manual) - shows 'certreq -Renew ?' help, you run the actual command"
        Write-Host "  4) 4.4 Superseded template - bump version again, re-publish via CA-Manager menu 4, pulse"
        Write-Host "  5) 4.5 Delete cert -> autoenroll re-issues fresh"
        Write-Host "  6) 4.6a Group safety net - remove from PrimaryGroup, expect enrollment DENIED"
        Write-Host "  7) 4.6b Group safety net - add to AlternateGroup, expect a clean enroll with a DIFFERENT OU"
        Write-Host "  8) 4.7 Show TameMyCerts event-log entries since a given time"
        Write-Host "  T) Show results table so far"
        Write-Host "  R) Restore template validity/overlap + re-add to PrimaryGroup, then exit"
        Write-Host "  Q) Quit (leaves the template SHORTENED - remember to come back and Restore)"
        $choice = Read-Host "Choice"

        try {
            switch -Regex ($choice) {
                '^0$' {
                    Backup-CARenewalTemplateValidity -TemplateCn $TemplateCn | Out-Null
                    Set-CARenewalTemplateValidity -TemplateCn $TemplateCn -ValidityHours $TestValidityHours -OverlapHours $TestOverlapHours
                }
                '^1$' {
                    Invoke-CARenewalStep -Results $results -StepName '4.1 Autoenroll renewal (same key)' -TemplateCn $TemplateCn -TemplateOid $templateOid -ExpectedOu $ExpectedOu -CertStore $CertStore -ClientComputerName $ClientComputerName -Instructions {
                        Write-Host "  (validity/overlap were shortened in step 0, so the renewal window should already be open)" -ForegroundColor DarkGray
                        Step-CARenewalPulseClient -ComputerName $ClientComputerName
                    }
                }
                '^2$' {
                    if (Read-CAConfirm -Prompt "Bump '$TemplateCn' minor version now (forces a new-key reenrollment)?") { Step-CARenewalBumpTemplateVersion -TemplateCn $TemplateCn }
                    Invoke-CARenewalStep -Results $results -StepName '4.2 Autoenroll renewal (new key / version bump)' -TemplateCn $TemplateCn -TemplateOid $templateOid -ExpectedOu $ExpectedOu -CertStore $CertStore -ClientComputerName $ClientComputerName -Instructions {
                        Step-CARenewalPulseClient -ComputerName $ClientComputerName
                    }
                }
                '^3$' {
                    # certreq.exe has NO top-level "-Renew" switch - confirmed live 2026-09-10 (running
                    # "-Renew -?" just dumps the full general help then errors "Unknown argument:
                    # -Renew"). The real form, from that same help dump, is positional:
                    #   CertReq -Enroll -cert CertId [Options] Renew [ReuseKeys]
                    # i.e. "-cert <thumbprint>", then the literal keyword "Renew", then optionally the
                    # literal keyword "ReuseKeys" for a same-key renewal (its absence = new key).
                    $curForRenew = Get-CARenewalTestCert -TemplateOid $templateOid -StoreLocation $CertStore -ComputerName $ClientComputerName | Select-Object -First 1
                    if (-not $curForRenew) {
                        Write-Host "  No current cert found for this template - run menu item 1 or 5 first to get one to renew." -ForegroundColor Yellow
                    } else {
                        $sameKeyPass = Read-CAConfirm -Prompt "Test the SAME-key pass now? (No = new-key pass)" -DefaultYes
                        Invoke-CARenewalStep -Results $results -StepName "4.3 certreq -Renew (confirmed syntax, $(if ($sameKeyPass) { 'same key' } else { 'new key' }))" -TemplateCn $TemplateCn -TemplateOid $templateOid -ExpectedOu $ExpectedOu -CertStore $CertStore -ClientComputerName $ClientComputerName -Instructions {
                            Step-CARenewalCertReqOnClient -Thumbprint $curForRenew.Thumbprint -ReuseKeys:$sameKeyPass -StoreLocation $CertStore -ComputerName $ClientComputerName
                        }
                        Write-Host "  Repeat this menu item for the $(if ($sameKeyPass) { 'new' } else { 'same' })-key pass too." -ForegroundColor DarkGray
                    }
                }
                '^4$' {
                    if (Read-CAConfirm -Prompt "Bump '$TemplateCn' minor version again (supersede)?") { Step-CARenewalBumpTemplateVersion -TemplateCn $TemplateCn }
                    Invoke-CARenewalStep -Results $results -StepName '4.4 Superseded template' -TemplateCn $TemplateCn -TemplateOid $templateOid -ExpectedOu $ExpectedOu -CertStore $CertStore -ClientComputerName $ClientComputerName -Instructions {
                        Write-Host "  Re-run CA-Manager menu 4 to republish the bumped template first." -ForegroundColor Yellow
                        Read-Host "  Press Enter once menu 1 has republished it" | Out-Null
                        Step-CARenewalPulseClient -ComputerName $ClientComputerName
                    }
                }
                '^5$' {
                    $cur = Get-CARenewalTestCert -TemplateOid $templateOid -StoreLocation $CertStore -ComputerName $ClientComputerName | Select-Object -First 1
                    if (-not $cur) {
                        Write-Host "  No current cert found for this template - nothing to delete. Pulsing to issue a fresh one anyway." -ForegroundColor Yellow
                    }
                    Invoke-CARenewalStep -Results $results -StepName '4.5 Delete + re-issue fresh' -TemplateCn $TemplateCn -TemplateOid $templateOid -ExpectedOu $ExpectedOu -CertStore $CertStore -ClientComputerName $ClientComputerName -Instructions {
                        if ($cur) { Step-CARenewalDeleteClientCert -Thumbprint $cur.Thumbprint -StoreLocation $CertStore -ComputerName $ClientComputerName }
                        Step-CARenewalPulseClient -ComputerName $ClientComputerName
                    }
                }
                '^6$' {
                    if (-not $PrimaryGroup) { Write-Host "  No PrimaryGroup set for this session - skipping." -ForegroundColor Yellow }
                    else {
                        $priv = Test-CARenewalUserHasPrivilegedGroup -TestUser $TestUser
                        $okToRun = $true
                        if ($priv.IsPrivileged) {
                            Write-Host "  WARNING: '$TestUser' is ALSO a member of $($priv.MatchedGroups -join ', ') - those typically carry" -ForegroundColor Red
                            Write-Host "  independent Enroll/AutoEnroll rights on EVERY template by default, regardless of PrimaryGroup" -ForegroundColor Red
                            Write-Host "  membership. Removing them from PrimaryGroup will very likely NOT deny enrollment - this test needs" -ForegroundColor Red
                            Write-Host "  a test user with NO other privileged group memberships to be meaningful (found live 2026-09-10)." -ForegroundColor Red
                            $okToRun = Read-CAConfirm -Prompt "Proceed anyway?"
                        }
                        if ($okToRun) {
                            Step-CARenewalRemoveFromGroup -TestUser $TestUser -Group $PrimaryGroup
                            Invoke-CARenewalStep -Results $results -StepName '4.6a Removed from group - expect DENIAL' -TemplateCn $TemplateCn -TemplateOid $templateOid -ExpectedOu $ExpectedOu -CertStore $CertStore -ClientComputerName $ClientComputerName -ExpectChange $false -Instructions {
                                Step-CARenewalPulseClient -ComputerName $ClientComputerName
                                Write-Host "  ALSO check the client's Applications and Services Logs > Microsoft > Windows >" -ForegroundColor Yellow
                                Write-Host "  CertificateServicesClient-CertEnroll log for an explicit denial (not just silence)." -ForegroundColor Yellow
                            }
                        }
                    }
                }
                '^7$' {
                    if (-not $AlternateGroup -or -not $AlternateOu) {
                        Write-Host "  No AlternateGroup/AlternateOu set for this session - nothing to verify." -ForegroundColor Yellow
                    } else {
                        Step-CARenewalAddToGroup -TestUser $TestUser -Group $AlternateGroup -Confirm
                        Invoke-CARenewalStep -Results $results -StepName '4.6b Added to AlternateGroup - expect clean enroll, different OU' -TemplateCn $TemplateCn -TemplateOid $templateOid -ExpectedOu $AlternateOu -CertStore $CertStore -ClientComputerName $ClientComputerName -Instructions {
                            Write-Host "  (enrolling whichever template maps to $AlternateGroup)" -ForegroundColor DarkGray
                            Step-CARenewalPulseClient -ComputerName $ClientComputerName
                        }
                    }
                }
                '^8$' {
                    $hrs = Read-Host "  Look back how many hours? [6]"
                    if ([string]::IsNullOrWhiteSpace($hrs)) { $hrs = 6 }
                    $ev = Get-CARenewalTameMyCertsEvents -Since (Get-Date).AddHours(-[double]$hrs)
                    if ($ev) { $ev | Format-Table -AutoSize -Wrap | Out-Host } else { Write-Host "  No TameMyCerts entries found in that window." -ForegroundColor Yellow }
                }
                '^[Tt]$' { Show-CARenewalResultsTable -Results $results }
                '^[Rr]$' {
                    Restore-CARenewalTemplateValidity -TemplateCn $TemplateCn
                    if ($PrimaryGroup) { Step-CARenewalAddToGroup -TestUser $TestUser -Group $PrimaryGroup }
                    Show-CARenewalResultsTable -Results $results
                    return
                }
                '^[Qq]$' {
                    Write-Host "  Exiting WITHOUT restoring - the template is still on the shortened test validity/overlap. Come back and pick R when you're done." -ForegroundColor DarkYellow
                    Show-CARenewalResultsTable -Results $results
                    return
                }
                default { Write-Host "  Unrecognized choice." -ForegroundColor Red }
            }
        } catch {
            # A step throwing should never kill the whole dashboard session - print the real error
            # (incl. any COM/ADSI inner exception, which carries the actual HRESULT reason) and loop.
            Write-Host "`n  ERROR in that step: $($_.Exception.Message)" -ForegroundColor Red
            if ($_.Exception.InnerException) { Write-Host "    inner: $($_.Exception.InnerException.Message)" -ForegroundColor DarkRed }
            Write-Host "    at: $($_.InvocationInfo.PositionMessage)" -ForegroundColor DarkGray
        }
    }
}

# --------------------------------------------------------------------------------------------------
# menu wrapper (dashboard entry point)
# --------------------------------------------------------------------------------------------------
function Invoke-CAMenuRenewalTest {
    param($CAAnswers, $Status)

    Write-CAHeader "TameMyCerts renewal-idempotency test (PoC)"

    if (Get-CADryRun) {
        Write-Host "  This is a live-testing tool - it mutates a REAL template's validity/overlap and REAL AD" -ForegroundColor Yellow
        Write-Host "  group membership regardless of this dashboard's DRY RUN toggle, so it refuses to run" -ForegroundColor Yellow
        Write-Host "  while DRY RUN is on (pretending that toggle protects you here would be worse than just" -ForegroundColor Yellow
        Write-Host "  refusing). Press D on the main menu to switch to APPLY, then come back here." -ForegroundColor Yellow
        Read-Host "Press Enter to return to the menu" | Out-Null
        return
    }

    $plan = Get-CATameMyCertsPlan -CAAnswers $CAAnswers
    if (-not $plan.TemplatePolicies -or -not $plan.TemplatePolicies.Count) {
        Write-Host "  No per-template TameMyCerts policies in the current plan - run menu 3 first." -ForegroundColor Yellow
        Read-Host "Press Enter to return to the menu" | Out-Null
        return
    }

    Write-Host ""
    Write-Host "  Templates currently under TameMyCerts:" -ForegroundColor Gray
    for ($i = 0; $i -lt $plan.TemplatePolicies.Count; $i++) {
        $tp = $plan.TemplatePolicies[$i]
        Write-Host ("    [{0}] {1,-24} OU={2,-24} group={3}" -f $i, $tp.TemplateCn, $tp.OuValue, $tp.UserGroupName)
    }
    $idxRaw = Read-Host "Pick the PRIMARY template to test [0]"
    $idx = if ([string]::IsNullOrWhiteSpace($idxRaw)) { 0 } else { [int]$idxRaw }
    if ($idx -lt 0 -or $idx -ge $plan.TemplatePolicies.Count) { Write-Host "  Out of range." -ForegroundColor Red; Read-Host "Press Enter to return" | Out-Null; return }
    $primary = $plan.TemplatePolicies[$idx]

    $alt = $null
    if ($plan.TemplatePolicies.Count -gt 1) {
        $altIdxRaw = Read-Host "Pick an ALTERNATE template for the group-change safety net (blank to skip)"
        if (-not [string]::IsNullOrWhiteSpace($altIdxRaw)) {
            $altIdx = [int]$altIdxRaw
            if ($altIdx -ge 0 -and $altIdx -lt $plan.TemplatePolicies.Count -and $altIdx -ne $idx) { $alt = $plan.TemplatePolicies[$altIdx] }
            else { Write-Host "  Invalid/duplicate alternate index - skipping the group safety-net step." -ForegroundColor Yellow }
        }
    }

    $testUser = Read-Host "Pilot test user (sAMAccountName)"
    if ([string]::IsNullOrWhiteSpace($testUser)) { Write-Host "  A test user is required." -ForegroundColor Red; Read-Host "Press Enter to return" | Out-Null; return }

    $certStoreChoice = Read-Host "Cert store to inspect - CurrentUser or LocalMachine [CurrentUser]"
    $certStore = if ($certStoreChoice -match '(?i)^LocalMachine$') { 'LocalMachine' } else { 'CurrentUser' }

    # Blank = check THIS box's (the CA's) own cert store, which only has the test cert if CA-Manager is
    # somehow running on the same machine the user enrolls from - not the realistic topology. Give the
    # VPN client's hostname to check IT instead, over PowerShell remoting.
    $clientComputerName = Read-Host "VPN client's hostname to check for the test cert over PS remoting (blank = check THIS machine instead)"
    if (-not [string]::IsNullOrWhiteSpace($clientComputerName)) {
        try {
            Test-WSMan -ComputerName $clientComputerName -ErrorAction Stop | Out-Null
            Write-Host "  '$clientComputerName' answered WinRM - remoting should work." -ForegroundColor Gray
        } catch {
            Write-Host "  WARNING: could not reach '$clientComputerName' over WinRM right now ($($_.Exception.Message))." -ForegroundColor Yellow
            Write-Host "  Enable-PSRemoting -Force on that machine if it hasn't been done, then re-check. Proceeding anyway - every cert check below will fail clearly until this is fixed." -ForegroundColor Yellow
        }
    }

    # AD rejects overlap >= validity outright (see Set-CARenewalTemplateValidity's .NOTES - found live
    # 2026-09-10 as a bare E_FAIL from ADSI, NOT a permissions issue) - validate here, up front, rather
    # than let a bad pair fail deep inside the write with a cryptic COM error. Defaults are 2h/1h (not
    # 2h/2h) for the same reason - overlap must stay strictly less, even at the default.
    $validityRaw = Read-Host "Test validity hours [2]"
    $validityHours = if ([string]::IsNullOrWhiteSpace($validityRaw)) { 2 } else { [double]$validityRaw }
    while ($true) {
        $overlapRaw = Read-Host "Test overlap hours - must be LESS than validity [1]"
        $overlapHours = if ([string]::IsNullOrWhiteSpace($overlapRaw)) { 1 } else { [double]$overlapRaw }
        if ($overlapHours -lt $validityHours) { break }
        Write-Host "  Overlap ($overlapHours h) must be less than validity ($validityHours h) - AD won't accept that combination. Try again." -ForegroundColor Red
    }

    Invoke-CARenewalTestSession -TemplateCn $primary.TemplateCn -ExpectedOu $primary.OuValue -TestUser $testUser `
        -PrimaryGroup $primary.UserGroupName `
        -AlternateGroup $(if ($alt) { $alt.UserGroupName } else { $null }) `
        -AlternateOu $(if ($alt) { $alt.OuValue } else { $null }) `
        -CertStore $certStore -ClientComputerName $clientComputerName -TestValidityHours $validityHours -TestOverlapHours $overlapHours
}
