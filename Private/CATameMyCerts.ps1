<#
.SYNOPSIS
    CA Manager - menu option S. Deploys the TameMyCerts policy module on the issuing CA and writes
    one per-template policy file that stamps a single static OU= RDN into every certificate the
    template issues, so a FortiGate `config user peer` can key on `set subject "OU=<group>"`.

.DESCRIPTION
    TameMyCerts (https://github.com/Sleepw4lker/TameMyCerts, Apache-2.0) is an open-source ADCS
    policy module that *daisy-chains* the Windows Default policy module - templates without a policy
    XML behave exactly as before it was installed. For each RADIUS group pair we emit
    `<PolicyDirectory>\<TemplateCn>.xml` containing a permissive <Subject>/<SubjectAlternativeName>
    allow-list (see Get-CATameMyCertsPolicyXml's own .DESCRIPTION for why this is required - TameMyCerts
    denies every RDN/SAN type actually present in a request unless it's explicitly allow-listed, the
    moment ANY policy file matches the template) plus the actual rewrite rule:

        <OutboundSubject>
          <OutboundSubjectRule>
            <Field>organizationalUnitName</Field>
            <Value>PSGI</Value>
            <Force>true</Force>
          </OutboundSubjectRule>
        </OutboundSubject>

    `Force=true` guarantees exactly one OU=<token> regardless of what the CA-built (or, for a
    MANUAL template, tech-supplied) subject already contained (renewal idempotency). Policy XMLs are
    hot-loaded - no certsvc restart to add/change one.

    Pinned to TameMyCerts community 1.8.1871.683, which requires the .NET 10 Desktop Runtime. The
    vendor install.ps1 registers the COM module, repoints PolicyModules\Active to TameMyCerts.Policy,
    copies the MS-default registry hive across, and restarts certsvc. Teardown (Remove-CATameMyCerts)
    re-runs it with -Uninstall so the hive is copied back and Active returns to the MS default.

.NOTES
    Constants transcribed from the 1.8.1871.683 install.ps1 / user-guide - a wrong value is a
    one-line data fix. Pure Get-*Plan + read-only Test-* + Invoke-CAStep-routed engines, same shape
    as CAOcsp.ps1 / CACrlShare.ps1.
#>

$script:TmcVersion        = '1.8.1871.683'
$script:TmcZipUrl         = "https://github.com/Sleepw4lker/TameMyCerts/releases/download/$($script:TmcVersion)/TameMyCerts_community_$($script:TmcVersion).zip"
$script:TmcActiveProgId   = 'TameMyCerts.Policy'
$script:TmcDefaultProgId  = 'CertificateAuthority_MicrosoftDefault.Policy'
$script:TmcInstallDir     = Join-Path $env:ProgramFiles 'TameMyCerts'
$script:TmcCaRegRoot      = 'HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration'
$script:TmcDotNetMajor    = 10
$script:TmcDotNetUrl      = 'https://aka.ms/dotnet/10.0/windowsdesktop-runtime-win-x64.exe'
$script:TmcDotNetPage     = 'https://dotnet.microsoft.com/download/dotnet/10.0'
$script:TmcDefaultPolicyDir     = 'C:\PolicyFiles'
$script:TmcDefaultTemplatePrefix = 'NSP-IKEv2-'

# --------------------------------------------------------------------------------------------------
# PURE helpers
# --------------------------------------------------------------------------------------------------
function ConvertTo-CATameMyCertsToken {
    <#
    .SYNOPSIS
        Sanitizes an AD group name into an OU= token that is safe in a DN and predictable for a
        FortiOS substring match: keep [A-Za-z0-9._-], trim leading/trailing separators, cap at 64.
    #>
    param([AllowNull()][AllowEmptyString()][string]$Name)
    if ([string]::IsNullOrWhiteSpace($Name)) { return 'VPN' }
    $t = ($Name -replace '[^A-Za-z0-9._-]', '')
    $t = $t.Trim('._-')
    if ($t.Length -gt 64) { $t = $t.Substring(0, 64) }
    if ([string]::IsNullOrWhiteSpace($t)) { return 'VPN' }
    return $t
}

function Get-CATameMyCertsPolicyXml {
    <#
    .SYNOPSIS
        The full per-template policy XML that stamps exactly one static OU= RDN.

    .DESCRIPTION
        2026-09-15, real live bug at a client: every per-group MANUAL template (ENROLLEE_SUPPLIES_SUBJECT
        - the CSR carries a real, tech-supplied subject) was denied with CERT_E_INVALID_NAME the
        moment a policy file existed for it, even though the file only had an <OutboundSubject>
        rewrite and no <Subject> section. TameMyCerts's own Application-log entry named the exact
        cause: "The emailAddress/commonName/organizationalUnitName/domainComponent/dNSName field is
        not allowed." - this session's original assumption ("no <Subject> section => no inbound
        validation") was WRONG. TameMyCerts is deny-by-default on every RDN/SAN type PRESENT in the
        request: as soon as ANY policy file matches a template, every field the CSR actually carries
        must be explicitly allow-listed here or the request is denied outright - confirmed against
        the project's own examples/Sample_Offline_User_StaticSubject.xml at the EXACT pinned tag
        (1.8.1871.683). The per-group AUTO templates never hit this because CT_FLAG_SUBJECT_ALT_
        REQUIRE_DIRECTORY_PATH means the CA builds their subject FROM AD, not from anything the
        enrollee submitted - nothing for TameMyCerts's inbound Subject/SAN validation to see.

        2026-09-15 correction, same day: GitHub's examples/Sample_Offline_User_StaticSubject.xml at
        the "1.8.1871.683" TAG shows <Overwrite>, not <Force> - tried that live at a client's CA and the
        CA denied EVERY request with "Unknown XML element Overwrite" (a real strict-schema rejection,
        not a silent drop). So whatever build is actually installed on that CA does NOT match
        what's committed under that tag name in TameMyCerts's own repo (a docs/release drift, not
        something guessable from source alone) - <Force> is what that real, running module
        actually accepts, confirmed by two independent facts: it never once threw "Unknown XML
        element Force" across this whole debugging session, and the Auto per-group templates' OU
        stamp was already confirmed live-correct at a client site.
        Reverted to <Force>. Whether <Force> truly REPLACES a pre-existing OU RDN (vs. only
        inserting when absent) is still UNCONFIRMED either way for a MANUAL template's CSR, which
        does carry a real pre-existing OU chain (e.g. "OU=Test Main, OU=Corp, OU=Contoso,
        OU=DD TS Users") unlike the Auto templates - worth the maintainer actually inspecting one issued
        Manual-template cert's decoded subject to confirm only ONE OU RDN survived, next time he's
        testing this live. If it doesn't, this is where to look first.

        The allow-list rules below are intentionally permissive (Mandatory=false, "^.*$" patterns) -
        these are internal admin-issued/auto-enrolled VPN certs, not public-facing enrollment; the
        real security boundary is Windows's own ENROLL ACL on the template plus the OutboundSubject
        stamp itself, not a narrow per-value regex here.
    #>
    param([Parameter(Mandatory)][string]$OuValue)
    @"
<?xml version="1.0" encoding="utf-8"?>
<!-- Generated by CA-Manager (menu 3). Stamps OU=$OuValue into every certificate this template issues. -->
<CertificateRequestPolicy xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">
  <Subject>
    <SubjectRule>
      <Field>commonName</Field>
      <Mandatory>false</Mandatory>
      <MaxOccurrences>1</MaxOccurrences>
      <MaxLength>128</MaxLength>
      <Patterns><Pattern><Expression>^.*$</Expression></Pattern></Patterns>
    </SubjectRule>
    <SubjectRule>
      <Field>organizationalUnitName</Field>
      <Mandatory>false</Mandatory>
      <MaxOccurrences>10</MaxOccurrences>
      <MaxLength>64</MaxLength>
      <Patterns><Pattern><Expression>^.*$</Expression></Pattern></Patterns>
    </SubjectRule>
    <SubjectRule>
      <Field>domainComponent</Field>
      <Mandatory>false</Mandatory>
      <MaxOccurrences>10</MaxOccurrences>
      <MaxLength>64</MaxLength>
      <Patterns><Pattern><Expression>^.*$</Expression></Pattern></Patterns>
    </SubjectRule>
    <SubjectRule>
      <Field>emailAddress</Field>
      <Mandatory>false</Mandatory>
      <MaxOccurrences>1</MaxOccurrences>
      <MaxLength>128</MaxLength>
      <Patterns><Pattern><Expression>^.*$</Expression></Pattern></Patterns>
    </SubjectRule>
  </Subject>
  <SubjectAlternativeName>
    <SubjectRule>
      <Field>dNSName</Field>
      <Mandatory>false</Mandatory>
      <MaxOccurrences>10</MaxOccurrences>
      <MaxLength>256</MaxLength>
      <Patterns><Pattern><Expression>^.*$</Expression></Pattern></Patterns>
    </SubjectRule>
  </SubjectAlternativeName>
  <OutboundSubject>
    <OutboundSubjectRule>
      <Field>organizationalUnitName</Field>
      <Value>$OuValue</Value>
      <Force>true</Force>
    </OutboundSubjectRule>
  </OutboundSubject>
</CertificateRequestPolicy>
"@
}

function Get-CATameMyCertsPlan {
    <#
    .SYNOPSIS
        PURE. Resolves the install parameters plus one policy-file spec per RADIUS group pair.
    .PARAMETER CAAnswers
        The CAAnswers.json object. Reads CA_SubjectStampMode (gate), RadiusGroupPairs (the 1:1
        template<->group set), CA_TemplateAuto / CA_AutoEnrollGroup (single-template fallback).
    #>
    param(
        $CAAnswers,
        [string]$PolicyDirectory,
        [string]$TemplatePrefix
    )

    $mode = if ($CAAnswers -and $CAAnswers.PSObject.Properties['CA_SubjectStampMode'] -and -not [string]::IsNullOrWhiteSpace($CAAnswers.CA_SubjectStampMode)) {
        "$($CAAnswers.CA_SubjectStampMode)".Trim()
    } else { 'None' }

    $polDir = if (-not [string]::IsNullOrWhiteSpace($PolicyDirectory)) { $PolicyDirectory.Trim() }
              elseif ($CAAnswers -and -not [string]::IsNullOrWhiteSpace($CAAnswers.CA_TameMyCertsPolicyDir)) { "$($CAAnswers.CA_TameMyCertsPolicyDir)".Trim() }
              else { $script:TmcDefaultPolicyDir }

    $prefix = if (-not [string]::IsNullOrWhiteSpace($TemplatePrefix)) { $TemplatePrefix }
              elseif ($CAAnswers -and -not [string]::IsNullOrWhiteSpace($CAAnswers.CA_TameMyCertsTemplatePrefix)) { "$($CAAnswers.CA_TameMyCertsTemplatePrefix)" }
              else { $script:TmcDefaultTemplatePrefix }

    $policies = New-Object System.Collections.Generic.List[object]
    $pairs = @()
    if ($CAAnswers -and $CAAnswers.PSObject.Properties['RadiusGroupPairs'] -and $CAAnswers.RadiusGroupPairs) {
        $pairs = @($CAAnswers.RadiusGroupPairs)
    }

    if ($pairs.Count) {
        foreach ($p in $pairs) {
            $label = if ($p.PSObject.Properties['Label']) { "$($p.Label)" } else { '' }
            # UserGroupValue is the actual AD security group's real name (matches how
            # Get-CAPerGroupTemplateSpecs / CATemplates.ps1 resolves it for the ACL grant);
            # UserGroupName is a friendlier label used elsewhere for firewall-rule naming and is NOT
            # reliably a real AD group. The .GroupName / .UserGroupName fields below are named after
            # this object's own shape, not the source JSON field of the same name.
            $grp = if ($p.PSObject.Properties['UserGroupValue'] -and -not [string]::IsNullOrWhiteSpace($p.UserGroupValue)) { "$($p.UserGroupValue)" }
                   elseif ($p.PSObject.Properties['UserGroupName']) { "$($p.UserGroupName)" }
                   else { '' }
            $ou    = if ($p.PSObject.Properties['CertSubjectOu'] -and -not [string]::IsNullOrWhiteSpace($p.CertSubjectOu)) {
                        ConvertTo-CATameMyCertsToken $p.CertSubjectOu
                     } else {
                        ConvertTo-CATameMyCertsToken $(if ($grp) { $grp } else { $label })
                     }
            # DisplayName '<prefix><token>'; CN = that with non-alphanumerics stripped - MUST match
            # New-CAVpnTemplate / Get-CAPerGroupTemplateSpecs (CATemplates.ps1), since the policy file
            # is named after the template CN.
            $display = "$prefix$(ConvertTo-CATameMyCertsToken $(if ($label) { $label } else { $grp }))"
            $tcn = ($display -replace '[^A-Za-z0-9]', '')
            $policies.Add([pscustomobject]@{
                GroupLabel          = $label
                UserGroupName       = $grp
                TemplateDisplayName = $display
                TemplateCn          = $tcn
                OuValue             = $ou
                FileName            = "$tcn.xml"
                FilePath            = (Join-Path $polDir "$tcn.xml")
                Xml                 = (Get-CATameMyCertsPolicyXml -OuValue $ou)
            })

            # 2026-09-15, per the maintainer: "for any 'template' we generate, we also need to allow a manual
            # admin request against it... wire this in to TameMyCerts. Same flow." - a manually-approved
            # cert issued from this pair's own manual counterpart (Get-CAPerGroupManualTemplateSpec,
            # CATemplates.ps1 - DisplayName = "<this Auto template's DisplayName>-MANUAL") needs the
            # IDENTICAL OU=<token> stamp the Auto template gets, or it can't actually be used to test/
            # troubleshoot that group's FortiGate peer-subject-filter match. TameMyCerts's own
            # <OutboundSubject Force="true"> rewrite operates purely by matching the REQUESTING
            # TEMPLATE's CN, independent of how the request was submitted (auto vs admin-approved
            # manual) - so this needs nothing more than a second policy file, same OU value, named
            # after the manual template's own CN. The manual spec's own ENROLLEE_SUPPLIES_SUBJECT flag
            # is UNCHANGED (an admin can still supply whatever CN they need for testing) - TameMyCerts's
            # Force=true rule still overrides just the OU RDN on top of that, same as it does for the
            # Auto template. "Templates without a matching policy file are left completely untouched" -
            # see Show-CATameMyCertsPlan's own note - so this is harmless even before/unless the manual
            # template has actually been created.
            $manualDisplay = "$display-MANUAL"
            $manualTcn = ($manualDisplay -replace '[^A-Za-z0-9]', '')
            $policies.Add([pscustomobject]@{
                GroupLabel          = $label
                UserGroupName       = $grp
                TemplateDisplayName = $manualDisplay
                TemplateCn          = $manualTcn
                OuValue             = $ou
                FileName            = "$manualTcn.xml"
                FilePath            = (Join-Path $polDir "$manualTcn.xml")
                Xml                 = (Get-CATameMyCertsPolicyXml -OuValue $ou)
            })
        }
    } else {
        # single-template fallback: stamp the master auto-enroll group's token onto CA_TemplateAuto.
        # CN = the display name with non-alphanumerics stripped (New-CAVpnTemplate does the same).
        $disp = if ($CAAnswers -and -not [string]::IsNullOrWhiteSpace($CAAnswers.CA_TemplateAuto)) { "$($CAAnswers.CA_TemplateAuto)" } else { 'IKEv2VPN-InternalUsers' }
        $tcn = ($disp -replace '[^A-Za-z0-9]', '')
        $ou  = ConvertTo-CATameMyCertsToken $(if ($CAAnswers -and $CAAnswers.CA_AutoEnrollGroup) { "$($CAAnswers.CA_AutoEnrollGroup)" } else { 'IKEv2_MasterGroup' })
        $policies.Add([pscustomobject]@{
            GroupLabel = '(fallback)'; UserGroupName = $(if ($CAAnswers) { "$($CAAnswers.CA_AutoEnrollGroup)" } else { '' })
            TemplateDisplayName = $disp
            TemplateCn = $tcn; OuValue = $ou; FileName = "$tcn.xml"
            FilePath = (Join-Path $polDir "$tcn.xml"); Xml = (Get-CATameMyCertsPolicyXml -OuValue $ou)
        })
    }

    [pscustomobject]@{
        Mode            = $mode
        Applicable      = ($mode -ieq 'TameMyCerts')
        Version         = $script:TmcVersion
        ZipUrl          = $script:TmcZipUrl
        ZipName         = "TameMyCerts_community_$($script:TmcVersion).zip"
        InstallDir      = $script:TmcInstallDir
        PolicyDirectory = $polDir
        TemplatePrefix  = $prefix
        ActiveProgId    = $script:TmcActiveProgId
        DefaultProgId   = $script:TmcDefaultProgId
        CaRegRoot       = $script:TmcCaRegRoot
        DotNetMajor     = $script:TmcDotNetMajor
        DotNetUrl       = $script:TmcDotNetUrl
        DotNetPage      = $script:TmcDotNetPage
        TemplatePolicies = $policies.ToArray()   # NB: @($list) inside a literal that also has a "$(...)" trips the PS7 binder
    }
}

function Show-CATameMyCertsPlan {
    param([Parameter(Mandatory)]$Plan)
    Write-Host ""
    Write-Host "  TameMyCerts policy module (subject-stamp)" -ForegroundColor Cyan
    Write-Host ("    Mode              : {0}{1}" -f $Plan.Mode, $(if (-not $Plan.Applicable) { '   (CA_SubjectStampMode is not TameMyCerts - pilot: proceed anyway to test)' } else { '' })) -ForegroundColor $(if ($Plan.Applicable) { 'Gray' } else { 'DarkYellow' })
    Write-Host ("    Version           : {0}   ({1})" -f $Plan.Version, $Plan.ZipUrl) -ForegroundColor Gray
    Write-Host ("    .NET requirement  : Desktop Runtime {0}.x   ({1})" -f $Plan.DotNetMajor, $Plan.DotNetPage) -ForegroundColor Gray
    Write-Host ("    Install dir       : {0}" -f $Plan.InstallDir) -ForegroundColor Gray
    Write-Host ("    Policy directory  : {0}" -f $Plan.PolicyDirectory) -ForegroundColor Gray
    Write-Host ("    Active module ->  : {0}   (chains {1})" -f $Plan.ActiveProgId, $Plan.DefaultProgId) -ForegroundColor Gray
    Write-Host ""
    Write-Host ("    {0,-32} {1,-24} {2}" -f 'Policy file', 'stamps', 'from group') -ForegroundColor DarkGray
    Write-Host ("    " + ('-' * 92)) -ForegroundColor DarkGray
    foreach ($tp in $Plan.TemplatePolicies) {
        Write-Host ("    {0,-32} OU={1,-21} {2}" -f $tp.FileName, $tp.OuValue, $(if ($tp.UserGroupName) { $tp.UserGroupName } else { $tp.GroupLabel })) -ForegroundColor Gray
    }
    Write-Host ""
    Write-Host "    Templates without a matching policy file are left completely untouched." -ForegroundColor DarkGray
}

# --------------------------------------------------------------------------------------------------
# read-only probes
# --------------------------------------------------------------------------------------------------
function Get-CATameMyCertsDotNetStatus {
    <# Read-only: is a .NET >=10 (WindowsDesktop) runtime present? #>
    $installed = $false
    $detail = 'dotnet not found on PATH'
    try {
        $rt = & dotnet --list-runtimes 2>$null
        if ($LASTEXITCODE -eq 0 -and $rt) {
            $wd = $rt | Where-Object { $_ -match '^Microsoft\.WindowsDesktop\.App\s+(\d+)\.' -and [int]$Matches[1] -ge $script:TmcDotNetMajor }
            if ($wd) { $installed = $true; $detail = ($wd | Select-Object -First 1) }
            else { $detail = "no Microsoft.WindowsDesktop.App >= $($script:TmcDotNetMajor).x  (have: " + (($rt | Where-Object { $_ -match 'WindowsDesktop' }) -join '; ') + ")" }
        }
    } catch { $detail = "dotnet query failed: $($_.Exception.Message)" }
    [pscustomobject]@{ Installed = $installed; Detail = $detail }
}

function Test-CATameMyCerts {
    <# Read-only. Never mutates. #>
    param($Plan)

    $polDir = if ($Plan) { $Plan.PolicyDirectory } else { $script:TmcDefaultPolicyDir }
    $notes = New-Object System.Collections.Generic.List[string]

    $dn = Get-CATameMyCertsDotNetStatus
    $dllPresent = Test-Path (Join-Path $script:TmcInstallDir 'TameMyCerts.comhost.dll')
    $comReg = $false
    try { $comReg = [bool](Test-Path 'Registry::HKEY_CLASSES_ROOT\TameMyCerts.Policy') } catch {}

    $caCfg = $null; $activeModule = $null; $polDirReg = $null; $tmcFlags = $null; $caType = $null
    try { $caCfg = (Get-ItemProperty $script:TmcCaRegRoot -Name Active -ErrorAction Stop).Active } catch { $notes.Add('CA configuration key not found - run menu 3 on the CA box') }
    if ($caCfg) {
        try { $activeModule = (Get-ItemProperty "$script:TmcCaRegRoot\$caCfg\PolicyModules" -Name Active -ErrorAction Stop).Active } catch {}
        try { $polDirReg = (Get-ItemProperty "$script:TmcCaRegRoot\$caCfg\PolicyModules\$($script:TmcActiveProgId)" -Name PolicyDirectory -ErrorAction Stop).PolicyDirectory } catch {}
        try { $tmcFlags = (Get-ItemProperty "$script:TmcCaRegRoot\$caCfg\PolicyModules\$($script:TmcActiveProgId)" -Name TmcFlags -ErrorAction Stop).TmcFlags } catch {}
        try { $caType = (Get-ItemProperty "$script:TmcCaRegRoot\$caCfg" -Name CaType -ErrorAction Stop).CaType } catch {}
    }
    $activeIsTmc = ($activeModule -eq $script:TmcActiveProgId)

    $svcRunning = $false
    try { $svcRunning = ((Get-Service -Name certsvc -ErrorAction Stop).Status -eq 'Running') } catch {}

    $files = [ordered]@{}
    if ($Plan) {
        foreach ($tp in $Plan.TemplatePolicies) { $files[$tp.FileName] = (Test-Path (Join-Path $polDir $tp.FileName)) }
    }

    if (-not $dn.Installed) { $notes.Add(".NET Desktop Runtime $($script:TmcDotNetMajor).x missing - $($dn.Detail)") }
    if ($dllPresent -and -not $activeIsTmc) { $notes.Add("module files present but PolicyModules\Active is '$activeModule' - install did not complete / was reverted") }
    if ($activeIsTmc -and -not $polDirReg) { $notes.Add("Active is TameMyCerts but PolicyDirectory registry value is unset") }
    if ($null -ne $caType -and $caType -notin 0, 1) { $notes.Add("CaType=$caType - TameMyCerts supports Enterprise Root/Sub only") }

    [pscustomobject]@{
        DotNetOk            = $dn.Installed
        DotNetDetail        = $dn.Detail
        DllPresent          = $dllPresent
        ComRegistered       = $comReg
        CaConfigName        = $caCfg
        CaType              = $caType
        ActiveModule        = $activeModule
        ActiveIsTmc         = $activeIsTmc
        PolicyDirRegistered = [bool]$polDirReg
        PolicyDirRegValue   = $polDirReg
        TmcFlags            = $tmcFlags
        CertSvcRunning      = $svcRunning
        PolicyFiles         = $files
        Working             = ($dn.Installed -and $dllPresent -and $activeIsTmc -and [bool]$polDirReg -and $svcRunning)
        Notes               = $notes.ToArray()
    }
}

function Show-CATameMyCertsTest {
    param([Parameter(Mandatory)]$Result, $Plan)
    Write-Host ""
    Write-Host "  Current state" -ForegroundColor Cyan
    Write-Host ("    .NET Desktop Runtime {0}.x : {1}" -f $script:TmcDotNetMajor, $(if ($Result.DotNetOk) { 'present' } else { "MISSING - $($Result.DotNetDetail)" })) -ForegroundColor $(if ($Result.DotNetOk) { 'Green' } else { 'Yellow' })
    Write-Host ("    Module files              : {0}" -f $(if ($Result.DllPresent) { 'present' } else { 'not installed' })) -ForegroundColor $(if ($Result.DllPresent) { 'Green' } else { 'Yellow' })
    Write-Host ("    PolicyModules\Active      : {0}" -f $(if ($Result.ActiveModule) { $Result.ActiveModule } else { '(unknown)' })) -ForegroundColor $(if ($Result.ActiveIsTmc) { 'Green' } else { 'Yellow' })
    Write-Host ("    PolicyDirectory (reg)     : {0}" -f $(if ($Result.PolicyDirRegValue) { $Result.PolicyDirRegValue } else { '(unset)' })) -ForegroundColor $(if ($Result.PolicyDirRegistered) { 'Green' } else { 'Yellow' })
    Write-Host ("    certsvc                   : {0}" -f $(if ($Result.CertSvcRunning) { 'Running' } else { 'NOT running' })) -ForegroundColor $(if ($Result.CertSvcRunning) { 'Green' } else { 'Red' })
    if ($Plan -and $Result.PolicyFiles.Count) {
        Write-Host "    Policy files:" -ForegroundColor Gray
        foreach ($k in $Result.PolicyFiles.Keys) {
            Write-Host ("      {0,-34} {1}" -f $k, $(if ($Result.PolicyFiles[$k]) { 'present' } else { 'missing' })) -ForegroundColor $(if ($Result.PolicyFiles[$k]) { 'Green' } else { 'DarkYellow' })
        }
    }
    foreach ($n in $Result.Notes) { Write-Host ("    ! $n") -ForegroundColor DarkYellow }
    Write-Host ("    => {0}" -f $(if ($Result.Working) { 'Working' } else { 'Not fully configured yet' })) -ForegroundColor $(if ($Result.Working) { 'Green' } else { 'Yellow' })
}

# --------------------------------------------------------------------------------------------------
# engines (all mutations via Invoke-CAStep => dry-run aware)
# --------------------------------------------------------------------------------------------------
function Install-CATameMyCertsDotNet {
    <#
    .SYNOPSIS
        Downloads + silently installs the .NET Desktop Runtime the module needs.
    .NOTES
        Checks a stable, well-known cache path first (C:\ProgramData\NSP\CAManager\
        windowsdesktop-runtime-10-x64.exe) so a CA box with no outbound route to aka.ms can be
        side-loaded once - same pattern as the PowerShellGet Save-Module workaround. -StagingDir is a
        fresh per-run GUID folder (Install-CATameMyCerts), so it is NOT a place to hand-drop a file for
        reuse across runs; the ProgramData path is.

        2026-09-11, per the maintainer: this cache is now SELF-POPULATING, not manual-drop-only - after a real
        download succeeds, the file is copied into the same ProgramData\NSP\CAManager\ cache path
        (creating the folder if needed) before installing, so the SECOND box (or a re-run after a
        failed install) never re-downloads at all. A copy failure is non-fatal (warns, keeps going
        with the already-downloaded staging copy) - caching is a nicety, not something worth failing
        an otherwise-successful download over.

        On download failure, every attempted method's real error is surfaced (found live 2026-09-10 on
        a client's CA server: both curl.exe and Invoke-WebRequest failed against the aka.ms redirector with no
        diagnosable reason under the old bare try/catch - could be a redirector-specific block, DNS,
        TLS, or a general egress restriction on the CA box; the real error tells you which).
    #>
    param([Parameter(Mandatory)]$Plan, [string]$StagingDir = $env:TEMP)

    # Defensive - this function is called by Install-CATameMyCerts (which already creates $StagingDir)
    # but is also independently callable, and writing to a non-existent directory fails with a
    # misleading "could not download" error that isn't actually a network problem.
    if (-not (Test-Path -LiteralPath $StagingDir)) { New-Item -ItemType Directory -Path $StagingDir -Force -ErrorAction SilentlyContinue | Out-Null }

    $cachedCopy = Join-Path $env:ProgramData 'NSP\CAManager\windowsdesktop-runtime-10-x64.exe'
    $exe = Join-Path $StagingDir 'windowsdesktop-runtime-10-x64.exe'

    Invoke-CAStep -Description ".NET Desktop Runtime $($Plan.DotNetMajor).x - use a cached installer if present, else download + silent install (caching it for next time)" `
        -Commands @(
            "if exists '$cachedCopy' use it directly (no download)",
            "else: curl.exe -L -o `"$exe`" `"$($Plan.DotNetUrl)`"  (falls back to Invoke-WebRequest)",
            "  then copy the successful download to '$cachedCopy' for future runs",
            "<installer> /install /quiet /norestart"
        ) `
        -Action {
            $useExe = $exe
            if (Test-Path -LiteralPath $cachedCopy) {
                $useExe = $cachedCopy
            } else {
                $ok = $false
                $errs = New-Object System.Collections.Generic.List[string]
                try {
                    $curlOut = & curl.exe -sS -L -o $exe $Plan.DotNetUrl 2>&1 | Out-String
                    if ($LASTEXITCODE -ne 0) { $errs.Add("curl.exe exit $LASTEXITCODE : $($curlOut.Trim())") }
                    elseif ((Test-Path $exe) -and (Get-Item $exe).Length -gt 1mb) { $ok = $true }
                    else { $errs.Add("curl.exe reported success but the file is missing/too small ($(if (Test-Path $exe) { (Get-Item $exe).Length } else { 0 }) bytes)") }
                } catch { $errs.Add("curl.exe threw: $($_.Exception.Message)") }
                if (-not $ok) {
                    try {
                        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
                        Invoke-WebRequest -UseBasicParsing -Uri $Plan.DotNetUrl -OutFile $exe -MaximumRedirection 8 -ErrorAction Stop
                        if ((Get-Item $exe).Length -gt 1mb) { $ok = $true } else { $errs.Add("Invoke-WebRequest wrote a too-small file") }
                    } catch { $errs.Add("Invoke-WebRequest: $($_.Exception.Message)") }
                }
                if (-not $ok) {
                    throw ("could not download the .NET runtime from $($Plan.DotNetUrl):`n" +
                        (($errs | ForEach-Object { "    $_" }) -join "`n") +
                        "`n  Side-load instead: on a box WITH internet, download the .NET $($Plan.DotNetMajor).0 Desktop Runtime (x64) from $($Plan.DotNetPage)," +
                        "`n  copy the installer to THIS box as '$cachedCopy' (create the folder if needed), then re-run menu 3.")
                }
                # Cache the good download for next time - non-fatal if this fails (e.g. permissions);
                # the install itself still proceeds off the staging copy either way.
                try {
                    $cacheDir = Split-Path -Parent $cachedCopy
                    if (-not (Test-Path -LiteralPath $cacheDir)) { New-Item -ItemType Directory -Path $cacheDir -Force | Out-Null }
                    Copy-Item -LiteralPath $exe -Destination $cachedCopy -Force
                    Write-Host "    Cached the downloaded installer to $cachedCopy for future runs." -ForegroundColor DarkGray
                } catch {
                    Write-Host "    WARNING: could not cache the installer to $cachedCopy ($($_.Exception.Message)) - will re-download next time." -ForegroundColor Yellow
                }
            }
            $p = Start-Process -FilePath $useExe -ArgumentList '/install', '/quiet', '/norestart' -Wait -PassThru
            if ($p.ExitCode -notin 0, 3010) { throw "runtime installer ($useExe) exit $($p.ExitCode)" }

            # The installer just persisted 'dotnet' onto the MACHINE (and possibly per-user) PATH, but
            # THIS already-running elevated process took its $env:PATH snapshot at its own startup and
            # never sees that change on its own - found live 2026-09-10 on a client's CA server: the install step
            # reported success, then the vendor install.ps1's own `Get-Command dotnet` check (which
            # runs in this SAME process, not a fresh one) still failed with ".NET 10 Runtime is not
            # installed! Aborting." Re-pull PATH from the registry so it resolves immediately, for both
            # our own re-check below and install.ps1's later invocation in this same process.
            $env:PATH = @([Environment]::GetEnvironmentVariable('PATH', 'Machine'), [Environment]::GetEnvironmentVariable('PATH', 'User')) -join ';'
            if (-not (Get-Command dotnet -ErrorAction SilentlyContinue)) {
                throw "the .NET runtime installer reported success (exit $($p.ExitCode)) but 'dotnet' still isn't resolvable even after refreshing PATH from the registry - if the exit code was 3010, a reboot is pending and required; otherwise check $env:ProgramFiles\dotnet exists and PATH was actually updated."
            }
            "installed from $useExe (exit $($p.ExitCode))"
        } | Out-Null
}

function Install-CATameMyCerts {
    <#
    .SYNOPSIS
        Downloads the pinned TameMyCerts community zip, unblocks it, ensures the policy directory,
        and runs the vendor install.ps1 (which registers the COM module, repoints
        PolicyModules\Active, copies the MS-default hive across, and restarts certsvc).
    #>
    param([Parameter(Mandatory)]$Plan, [string]$StagingDir)

    if (-not $StagingDir) { $StagingDir = Join-Path $env:TEMP ("TmcInstall_" + [guid]::NewGuid().ToString('N')) }
    # Create it NOW, unconditionally (a scratch temp dir isn't a mutation worth dry-run-gating) - it
    # used to only get created inside the zip-download step further down, AFTER
    # Install-CATameMyCertsDotNet already needed it to exist to write the runtime installer into
    # (found live 2026-09-10: "Could not find a part of the path ...\TmcInstall_<guid>\..." - masqueraded
    # as a download/network failure when it was really just a missing directory).
    New-Item -ItemType Directory -Path $StagingDir -Force -ErrorAction SilentlyContinue | Out-Null

    # --- guards -------------------------------------------------------------------------------
    if (-not (Get-Command certutil.exe -ErrorAction SilentlyContinue) -or -not (Test-Path $Plan.CaRegRoot)) {
        Write-Host "  No certification authority detected on this box - run menu 3 on the issuing CA." -ForegroundColor Red
        return
    }
    $t0 = Test-CATameMyCerts -Plan $Plan
    if ($null -ne $t0.CaType -and $t0.CaType -notin 0, 1) {
        Write-Host "  CaType=$($t0.CaType): TameMyCerts supports Enterprise Root / Enterprise Sub CAs only. Aborting." -ForegroundColor Red
        return
    }

    # --- .NET prereq -----------------------------------------------------------------------------
    if (-not $t0.DotNetOk) { Install-CATameMyCertsDotNet -Plan $Plan -StagingDir $StagingDir }

    # --- download + extract --------------------------------------------------------------------
    $zip = Join-Path $StagingDir $Plan.ZipName
    $ext = Join-Path $StagingDir 'tmc'
    Invoke-CAStep -Description "Download + extract TameMyCerts $($Plan.Version)" `
        -Commands @(
            "New-Item -ItemType Directory -Force '$StagingDir'",
            "curl.exe -L -o '$zip' '$($Plan.ZipUrl)'",
            "Expand-Archive '$zip' -DestinationPath '$ext'",
            "Get-ChildItem '$ext' -Recurse | Unblock-File"
        ) `
        -Action {
            New-Item -ItemType Directory -Path $StagingDir -Force -ErrorAction SilentlyContinue | Out-Null
            $ok = $false
            try { & curl.exe -L -s -o $zip $Plan.ZipUrl; if ((Test-Path $zip) -and (Get-Item $zip).Length -gt 50kb) { $ok = $true } } catch {}
            if (-not $ok) {
                try { Invoke-WebRequest -UseBasicParsing -Uri $Plan.ZipUrl -OutFile $zip -MaximumRedirection 8 -ErrorAction Stop; if ((Get-Item $zip).Length -gt 50kb) { $ok = $true } } catch {}
            }
            if (-not $ok) { throw "could not download $($Plan.ZipUrl)" }
            if (Test-Path $ext) { Remove-Item $ext -Recurse -Force -ErrorAction SilentlyContinue }
            Expand-Archive -Path $zip -DestinationPath $ext -Force
            Get-ChildItem -Path $ext -Recurse | Unblock-File -ErrorAction SilentlyContinue
            if (-not (Test-Path (Join-Path $ext 'install.ps1'))) { throw "install.ps1 not found after extract - archive layout changed?" }
            "extracted to $ext"
        } | Out-Null

    # --- policy directory --------------------------------------------------------------------
    Invoke-CAStep -Description "Ensure policy directory '$($Plan.PolicyDirectory)'" `
        -Commands @("New-Item -ItemType Directory -Force '$($Plan.PolicyDirectory)'") `
        -Action { New-Item -ItemType Directory -Path $Plan.PolicyDirectory -Force | Out-Null; "ok" } | Out-Null

    # --- vendor installer (restarts certsvc itself) -----------------------------------------
    $installPs1 = Join-Path $ext 'install.ps1'
    Invoke-CAStep -Description "Run vendor install.ps1 (registers COM, repoints PolicyModules\Active -> $($Plan.ActiveProgId), restarts certsvc)" `
        -Commands @("& '$installPs1' -PolicyDirectory '$($Plan.PolicyDirectory)'") `
        -Action {
            $r = & $installPs1 -PolicyDirectory $Plan.PolicyDirectory
            if (-not ($r -and $r.Success)) { throw "install.ps1 did not report success: $($r | Out-String)" }
            "$($r.Message)"
        } | Out-Null

    # --- verify ------------------------------------------------------------------------------
    $t1 = Test-CATameMyCerts -Plan $Plan
    Show-CATameMyCertsTest -Result $t1 -Plan $Plan
    if (-not (Get-CADryRun) -and -not $t1.ActiveIsTmc) {
        Write-Host "  WARNING: PolicyModules\Active is still '$($t1.ActiveModule)'. Check the CA event log and certsrv.msc." -ForegroundColor Yellow
    }
}

function Write-CATameMyCertsPolicies {
    <# Writes one <TemplateCn>.xml per plan entry into the policy directory. Hot-loaded - no restart. #>
    param([Parameter(Mandatory)]$Plan)

    Invoke-CAStep -Description "Ensure policy directory '$($Plan.PolicyDirectory)'" `
        -Commands @("New-Item -ItemType Directory -Force '$($Plan.PolicyDirectory)'") `
        -Action { New-Item -ItemType Directory -Path $Plan.PolicyDirectory -Force | Out-Null; "ok" } | Out-Null

    foreach ($tp in $Plan.TemplatePolicies) {
        $path = Join-Path $Plan.PolicyDirectory $tp.FileName
        Invoke-CAStep -Description "Write policy '$($tp.FileName)'  (stamps OU=$($tp.OuValue))" `
            -Commands @("Set-Content '$path'  (<OutboundSubject> organizationalUnitName = $($tp.OuValue), Force=true)") `
            -Action {
                [System.IO.File]::WriteAllText($path, $tp.Xml, (New-Object System.Text.UTF8Encoding($false)))
                "wrote $path"
            } | Out-Null
    }
    Write-Host ""
    Write-Host "  Policy files are hot-loaded on the next request for each template - no certsvc restart needed." -ForegroundColor DarkGray
}

function Remove-CATameMyCerts {
    <#
    .SYNOPSIS
        Teardown. Re-downloads the pinned zip for its install.ps1, runs it with -Uninstall (copies
        the registry hive back to the MS default, repoints Active, unregisters COM, restarts certsvc),
        then optionally deletes the generated policy XMLs. Does NOT remove the .NET runtime.
    #>
    param([Parameter(Mandatory)]$Plan, [switch]$KeepPolicyFiles, [string]$StagingDir)

    if (-not $StagingDir) { $StagingDir = Join-Path $env:TEMP ("TmcRemove_" + [guid]::NewGuid().ToString('N')) }
    $zip = Join-Path $StagingDir $Plan.ZipName
    $ext = Join-Path $StagingDir 'tmc'

    Invoke-CAStep -Description "Download TameMyCerts $($Plan.Version) (for its uninstall script)" `
        -Commands @("curl.exe -L -o '$zip' '$($Plan.ZipUrl)'", "Expand-Archive '$zip' -DestinationPath '$ext'") `
        -Action {
            New-Item -ItemType Directory -Path $StagingDir -Force -ErrorAction SilentlyContinue | Out-Null
            $ok = $false
            try { & curl.exe -L -s -o $zip $Plan.ZipUrl; if ((Test-Path $zip) -and (Get-Item $zip).Length -gt 50kb) { $ok = $true } } catch {}
            if (-not $ok) { try { Invoke-WebRequest -UseBasicParsing -Uri $Plan.ZipUrl -OutFile $zip -MaximumRedirection 8 -ErrorAction Stop; $ok = $true } catch {} }
            if (-not $ok) { throw "could not download $($Plan.ZipUrl) - to revert by hand: certutil -setreg CA\PolicyModules\Active `"$($Plan.DefaultProgId)`" ; net stop certsvc ; net start certsvc" }
            if (Test-Path $ext) { Remove-Item $ext -Recurse -Force -ErrorAction SilentlyContinue }
            Expand-Archive -Path $zip -DestinationPath $ext -Force
            "ok"
        } | Out-Null

    $installPs1 = Join-Path $ext 'install.ps1'
    Invoke-CAStep -Description "Run vendor install.ps1 -Uninstall (Active -> $($Plan.DefaultProgId), restarts certsvc)" `
        -Commands @("& '$installPs1' -Uninstall") `
        -Action {
            $r = & $installPs1 -Uninstall
            if (-not ($r -and $r.Success)) { throw "uninstall did not report success: $($r | Out-String)" }
            "$($r.Message)"
        } | Out-Null

    if (-not $KeepPolicyFiles) {
        foreach ($tp in $Plan.TemplatePolicies) {
            $path = Join-Path $Plan.PolicyDirectory $tp.FileName
            Invoke-CAStep -Description "Delete policy file '$($tp.FileName)'" -Commands @("Remove-Item '$path'") `
                -Action { if (Test-Path $path) { Remove-Item $path -Force }; "ok" } -ContinueOnError | Out-Null
        }
    }
}

# --------------------------------------------------------------------------------------------------
# menu wrapper
# --------------------------------------------------------------------------------------------------
function Invoke-CATameMyCertsMenu {
    param($CAAnswers, $Status)

    Write-CAHeader "Subject-stamp policy module (TameMyCerts)"

    $polDir = Get-CAAnswerOrPrompt -CAAnswers $CAAnswers -Field 'CA_TameMyCertsPolicyDir' `
        -Prompt "Policy directory for per-template XML [$($script:TmcDefaultPolicyDir)]" -Default $script:TmcDefaultPolicyDir -Remember
    if ([string]::IsNullOrWhiteSpace($polDir)) { $polDir = $script:TmcDefaultPolicyDir }

    $plan = Get-CATameMyCertsPlan -CAAnswers $CAAnswers -PolicyDirectory $polDir
    Show-CATameMyCertsPlan -Plan $plan

    $t = Test-CATameMyCerts -Plan $plan
    Show-CATameMyCertsTest -Result $t -Plan $plan

    Write-Host ""
    if (-not (Read-CAConfirm -Prompt "Proceed?" -DefaultYes)) {
        Read-Host "Press Enter to return to the menu" | Out-Null
        return
    }

    if (-not $t.Working -or -not $t.ActiveIsTmc) {
        Install-CATameMyCerts -Plan $plan
    } else {
        Write-Host "  Module already active - skipping install, just (re)writing policy files." -ForegroundColor Gray
    }

    Write-CATameMyCertsPolicies -Plan $plan

    $t2 = Test-CATameMyCerts -Plan $plan
    Show-CATameMyCertsTest -Result $t2 -Plan $plan
    Write-Host ""
    Write-Host "  Next: publish/enroll the templates named above; a `certutil -dump` of an issued cert" -ForegroundColor DarkGray
    Write-Host "  should now show the OU= RDN, and a FortiGate 'config user peer / set subject `"OU=<token>`"' will match." -ForegroundColor DarkGray
    Read-Host "Press Enter to return to the menu" | Out-Null
}
