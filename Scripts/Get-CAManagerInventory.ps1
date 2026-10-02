<#
.SYNOPSIS
    Read-only inventory of an existing AD CS deployment - captures every value CA-Manager.ps1 will
    need to reproduce (or diff against) a hand-built CA/OCSP/App-Proxy/auto-enroll setup. Nothing is
    created, changed, published, or revoked - safe to run on a production CA.

.DESCRIPTION
    Run this ON the issuing CA (elevated - it self-elevates). If the deployment is two-tier (an
    online root that issued the issuing CA's own cert - the opt-in "dedicated sub-CA" model), run it
    a SECOND time on the root and send both files: the root's CRL/AIA config is part of what has to
    be reachable through the App Proxy.

    Dumps, in order, to a timestamped .txt under -OutputDir:

      A. Host / role / CA identity      - OS, domain, ADCS role features, certutil -cainfo,
                                          certutil -getreg CA (full), CA cert(s) + expiry, and
                                          whether this CA is a root or a subordinate (+ its parent).
      B. AIA / CDP / OCSP publication   - Get-CAAuthorityInformationAccess / Get-CACrlDistributionPoint
                                          (falls back to certutil -getreg), CRL/delta/overlap periods,
                                          the CRL files currently in CertEnroll\ + the newest one's
                                          ThisUpdate/NextUpdate/NextCRLPublish, and URL-flag decoding.
      C. OCSP / Online Responder       - role feature, OCSPSvc state, the full
                                          HKLM\...\Services\OCSPSvc\Responder registry subtree
                                          (revocation configs, signing cert, CRL URLs), OCSP signing
                                          certs in LocalMachine\My.
      D. Certificate templates         - certutil -CATemplates (published list), and for the custom
                                          template(s) - full AD definition (name flags, enrollment
                                          flags, EKU, key usage, validity/overlap, schema version,
                                          RA signatures) + the template object's ACL with Enroll /
                                          AutoEnroll ACEs called out by name (this is where the
                                          umbrella group shows up).
      E. Auto-enrollment GPO           - Default Domain Policy's Public Key Policies section, a scan
                                          of every other GPO for AutoEnrollment / AEPolicy, and the
                                          live AEPolicy / OfflineExpirationPercent registry values
                                          under both HKLM and HKCU policy hives.
      F. CRL share                     - if -CrlSharePath is given (or a UNC / file:// entry is found
                                          in the CA's CRLPublicationURLs): Get-SmbShare / share ACL /
                                          NTFS ACL / the .crl files sitting there + timestamps.
      G. App Proxy connector           - WAPCSvc / WAPCUpdaterSvc state + installed connector version.
                                          (The Entra published-app config - App-CRL, App-OCSP: their
                                          external/internal URLs and pre-auth mode - is NOT readable
                                          locally; pull it from the Entra portal or Graph by hand.)
      H. Umbrella / master AD group    - -MasterGroupName if given, else a wildcard search for
                                          *Master* / *IKEv2* groups; direct + recursive membership
                                          and any nested groups.

    Send the .txt file back (and the root's copy, for a two-tier deployment).

.PARAMETER OutputDir
    Where the timestamped inventory .txt is written. Default C:\Admin\CAInventory.

.PARAMETER TemplateName
    Display name(s) or internal name(s) of the custom cert template(s) to deep-dive in section D.
    Accepts partial / wildcard matches. If omitted, section D deep-dives every template on this CA
    whose EKU includes Client Authentication (that will include the built-ins - noisy but complete).

.PARAMETER CrlSharePath
    UNC path of the CRL distribution share, if one exists. If omitted, section F still runs against
    any UNC / file:// entry discovered in the CA's own CRLPublicationURLs.

.PARAMETER MasterGroupName
    Name of the auto-enrollment umbrella group (e.g. "IKEv2_MasterGroup"). If omitted, section H
    does a wildcard AD search instead.

.NOTES
    Needs, where present: the ADCSAdministration, ActiveDirectory and GroupPolicy modules (all
    standard on a domain CA). Every block is wrapped - a missing module or cmdlet degrades that
    block to a note, it does not stop the run.
#>

[CmdletBinding()]
param(
    [string]$OutputDir = "C:\Admin\CAInventory",
    [string[]]$TemplateName,
    [string]$CrlSharePath,
    [string]$MasterGroupName
)

# --- self-elevate (certutil -getreg CA, the OCSPSvc registry subtree, and some template ACLs all
# want admin), passing every bound param through so the elevated instance doesn't fall back to
# defaults - same pattern as NPS-Manager.ps1 / FortiClient_Kickstart.ps1. ---
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    $relaunchArgs = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"")
    if ($PSBoundParameters.ContainsKey('OutputDir'))      { $relaunchArgs += @('-OutputDir', "`"$OutputDir`"") }
    if ($PSBoundParameters.ContainsKey('TemplateName'))   { $relaunchArgs += @('-TemplateName', ($TemplateName -join ',')) }
    if ($PSBoundParameters.ContainsKey('CrlSharePath'))   { $relaunchArgs += @('-CrlSharePath', "`"$CrlSharePath`"") }
    if ($PSBoundParameters.ContainsKey('MasterGroupName')){ $relaunchArgs += @('-MasterGroupName', "`"$MasterGroupName`"") }
    Start-Process powershell.exe -ArgumentList $relaunchArgs -Verb RunAs
    exit
}

$ErrorActionPreference = 'Continue'

if (-not (Test-Path $OutputDir)) { New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null }
$stamp    = Get-Date -Format 'yyyyMMdd_HHmmss'
$hostTag  = $env:COMPUTERNAME
$outFile  = Join-Path $OutputDir "CAInventory_${hostTag}_${stamp}.txt"

try { Start-Transcript -Path $outFile -Force | Out-Null } catch { }

function Section {
    param([string]$Text)
    Write-Host ""
    Write-Host ("=" * 78) -ForegroundColor Cyan
    Write-Host "  $Text" -ForegroundColor Cyan
    Write-Host ("=" * 78) -ForegroundColor Cyan
}
function Sub {
    param([string]$Text)
    Write-Host ""
    Write-Host "--- $Text ---" -ForegroundColor Gray
}
function Note {
    param([string]$Text)
    Write-Host "  [note] $Text" -ForegroundColor Yellow
}
function Try-Block {
    param([string]$Label, [scriptblock]$Body)
    Sub $Label
    try { & $Body } catch { Write-Host "  ERROR: $($_.Exception.Message)" -ForegroundColor Red }
}

# FILETIME-style pKIExpirationPeriod / pKIOverlapPeriod: 8-byte LE, negative 100ns intervals.
function ConvertFrom-PkiPeriod {
    param($ByteArray)
    if (-not $ByteArray) { return "(none)" }
    try {
        $ticks = [BitConverter]::ToInt64([byte[]]$ByteArray, 0)   # negative
        $span  = [TimeSpan]::FromSeconds([math]::Abs($ticks) / 1e7)
        $days  = [math]::Round($span.TotalDays, 2)
        $yrs   = [math]::Round($span.TotalDays / 365.25, 3)
        return "$days days  (~$yrs years)  [raw ticks $ticks]"
    } catch { return "(unparseable: $($_.Exception.Message))" }
}

Write-Host "CA Manager - deployment inventory" -ForegroundColor Green
Write-Host "Host    : $hostTag"
Write-Host "When    : $(Get-Date)"
Write-Host "Run by  : $env:USERDOMAIN\$env:USERNAME"
Write-Host "Output  : $outFile"
Note "Read-only. Nothing is created, changed, published, or revoked by this script."

# Module availability (informational - blocks below each guard themselves too)
Sub "PowerShell modules present"
foreach ($m in 'ADCSAdministration','ActiveDirectory','GroupPolicy','PKI') {
    $have = [bool](Get-Module -ListAvailable -Name $m -ErrorAction SilentlyContinue)
    Write-Host ("  {0,-22} {1}" -f $m, $(if ($have) { 'yes' } else { 'MISSING' }))
}
foreach ($m in 'ADCSAdministration','ActiveDirectory','GroupPolicy') {
    try { Import-Module $m -ErrorAction Stop } catch { }
}

# =====================================================================================
Section "A. Host / role / CA identity"
# =====================================================================================
Try-Block "OS / domain" {
    Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, OSArchitecture, CSName | Format-List | Out-String | Write-Host
    Get-CimInstance Win32_ComputerSystem  | Select-Object Domain, DomainRole, PartOfDomain        | Format-List | Out-String | Write-Host
}
Try-Block "ADCS role features installed" {
    if (Get-Command Get-WindowsFeature -ErrorAction SilentlyContinue) {
        Get-WindowsFeature -Name ADCS-* | Where-Object Installed |
            Select-Object Name, DisplayName, InstallState | Format-Table -AutoSize | Out-String | Write-Host
    } else { Note "Get-WindowsFeature not available (not a Windows Server SKU?)." }
}
Try-Block "certutil -cainfo" {
    (& certutil -cainfo 2>&1 | Out-String).Trim() | Write-Host
}
Try-Block "certutil -getreg CA  (full CA registry dump)" {
    (& certutil -getreg CA 2>&1 | Out-String).Trim() | Write-Host
}
Try-Block "CA certificate(s) in LocalMachine\CA and LocalMachine\My  (subject / issuer / validity)" {
    foreach ($store in 'Cert:\LocalMachine\CA', 'Cert:\LocalMachine\My') {
        Write-Host "  store: $store"
        Get-ChildItem $store -ErrorAction SilentlyContinue |
            Select-Object Subject, Issuer, NotBefore, NotAfter,
                @{n='DaysLeft';e={[math]::Round(($_.NotAfter - (Get-Date)).TotalDays)}},
                @{n='IsCA';e={ ($_.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.19' } | ForEach-Object { $_.CertificateAuthority }) -contains $true }},
                @{n='SelfSigned';e={$_.Subject -eq $_.Issuer}},
                Thumbprint |
            Format-List | Out-String | Write-Host
    }
    Note "SelfSigned=True on the CA cert => this is a ROOT. SelfSigned=False => SUBORDINATE; 'Issuer' above is the parent CA - run this script there too."
}

# =====================================================================================
Section "B. AIA / CDP / OCSP publication + CRL timing"
# =====================================================================================
Try-Block "Get-CAAuthorityInformationAccess" {
    if (Get-Command Get-CAAuthorityInformationAccess -ErrorAction SilentlyContinue) {
        Get-CAAuthorityInformationAccess | Format-List * | Out-String | Write-Host
    } else { Note "cmdlet not present - see certutil CACertPublicationURLs below." }
}
Try-Block "Get-CACrlDistributionPoint" {
    if (Get-Command Get-CACrlDistributionPoint -ErrorAction SilentlyContinue) {
        Get-CACrlDistributionPoint | Format-List * | Out-String | Write-Host
    } else { Note "cmdlet not present - see certutil CRLPublicationURLs below." }
}
Try-Block "certutil -getreg CA\CACertPublicationURLs" {
    (& certutil -getreg CA\CACertPublicationURLs 2>&1 | Out-String).Trim() | Write-Host
}
Try-Block "certutil -getreg CA\CRLPublicationURLs" {
    (& certutil -getreg CA\CRLPublicationURLs 2>&1 | Out-String).Trim() | Write-Host
}
Sub "URL-flag quick reference (the number: prefix on each URL above)"
@'
   1  = Publish to this location (CDP: publish CRLs / AIA: publish CA cert)
   2  = Include in the CDP extension of issued certs
   4  = Include in CRLs (to find delta CRL locations)
   8  = Include in the CDP extension of issued CRLs
  32  = Publish delta CRLs to this location
  64  = Include in the IDP extension of issued CRLs
 128  = (AIA) Include in the OCSP extension (AuthorityInfoAccess = OCSP)
 e.g. "65" = 1 + 64,  "3" = 1 + 2,  "6" = 2 + 4,  "134" = 2 + 4 + 128
'@ | Write-Host
Try-Block "CRL period / delta / overlap" {
    foreach ($k in 'CRLPeriod','CRLPeriodUnits','CRLDeltaPeriod','CRLDeltaPeriodUnits','CRLOverlapPeriod','CRLOverlapUnits','CRLNextPublish','ValidityPeriod','ValidityPeriodUnits') {
        Write-Host ("  {0,-22} {1}" -f $k, ((& certutil -getreg "CA\$k" 2>&1 | Select-String -Pattern '=\s*(.+)$' | ForEach-Object { $_.Matches[0].Groups[1].Value }) -join ' '))
    }
}
Try-Block "Published CRL files in CertEnroll\  + newest CRL dump" {
    $certEnroll = Join-Path $env:SystemRoot 'System32\CertSrv\CertEnroll'
    if (Test-Path $certEnroll) {
        $crls = Get-ChildItem $certEnroll -Filter *.crl -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending
        $crls | Select-Object Name, Length, LastWriteTime | Format-Table -AutoSize | Out-String | Write-Host
        Get-ChildItem $certEnroll -Filter *.crt -ErrorAction SilentlyContinue |
            Select-Object Name, Length, LastWriteTime | Format-Table -AutoSize | Out-String | Write-Host
        if ($crls) {
            Sub "certutil -dump `"$($crls[0].FullName)`"  (ThisUpdate / NextUpdate / NextCRLPublish)"
            (& certutil -dump $crls[0].FullName 2>&1 | Out-String).Trim() | Write-Host
        }
    } else { Note "$certEnroll not found." }
}

# =====================================================================================
Section "C. OCSP / Online Responder"
# =====================================================================================
Try-Block "Online Responder role feature + service state" {
    if (Get-Command Get-WindowsFeature -ErrorAction SilentlyContinue) {
        Get-WindowsFeature -Name ADCS-Online-Cert | Select-Object Name, DisplayName, InstallState | Format-List | Out-String | Write-Host
    }
    Get-Service -Name OCSPSvc, CertSvc -ErrorAction SilentlyContinue |
        Select-Object Name, Status, StartType, DisplayName | Format-Table -AutoSize | Out-String | Write-Host
}
Try-Block "HKLM\SYSTEM\CurrentControlSet\Services\OCSPSvc\Responder  (full subtree - revocation configs)" {
    $ocspKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\OCSPSvc\Responder'
    if (Test-Path $ocspKey) {
        Get-ChildItem -Path $ocspKey -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
            Write-Host ""
            Write-Host "  [key] $($_.PSPath -replace '^.*::','')"
            $props = Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue
            if ($props) {
                $props.PSObject.Properties |
                    Where-Object { $_.Name -notmatch '^PS(Path|ParentPath|ChildName|Provider|Drive)$' } |
                    ForEach-Object {
                        $v = $_.Value
                        if ($v -is [byte[]]) { $v = "<byte[$($v.Length)]> " + ([BitConverter]::ToString($v)) }
                        Write-Host ("      {0,-28} {1}" -f $_.Name, $v)
                    }
            }
        }
        # also dump the Responder key's own values (not just children)
        $root = Get-ItemProperty -Path $ocspKey -ErrorAction SilentlyContinue
        if ($root) {
            Write-Host ""
            Write-Host "  [key] $ocspKey (root values)"
            $root.PSObject.Properties |
                Where-Object { $_.Name -notmatch '^PS(Path|ParentPath|ChildName|Provider|Drive)$' } |
                ForEach-Object { Write-Host ("      {0,-28} {1}" -f $_.Name, $_.Value) }
        }
    } else { Note "$ocspKey not present - Online Responder role not installed on this box (may be on a separate server)." }
}
Try-Block "OCSP signing certificate(s) in LocalMachine\My  (EKU 1.3.6.1.5.5.7.3.9)" {
    $all = @(Get-ChildItem Cert:\LocalMachine\My -ErrorAction SilentlyContinue)
    $ocsp = $all | Where-Object {
        $_.EnhancedKeyUsageList.ObjectId -contains '1.3.6.1.5.5.7.3.9' -or
        (($_.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.37' } | ForEach-Object { $_.Format($false) }) -match 'OCSP')
    }
    if ($ocsp) {
        $ocsp | Select-Object Subject, Issuer, NotBefore, NotAfter,
            @{n='DaysLeft';e={[math]::Round(($_.NotAfter - (Get-Date)).TotalDays)}}, Thumbprint |
            Format-List | Out-String | Write-Host
    } else {
        Note "Nothing in LocalMachine\My matched the OCSP-Signing EKU. Full LocalMachine\My inventory (eyeball for a short-lived cert issued by one of the CAs, EKU 'OCSP Signing'):"
        $all | Select-Object Subject, Issuer, NotAfter,
            @{n='EKU';e={ ($_.EnhancedKeyUsageList | ForEach-Object { $_.FriendlyName }) -join ', ' }}, Thumbprint |
            Format-Table -AutoSize | Out-String | Write-Host
        Note "OCSP signing certs may instead live in a per-service store or be auto-rotated - the OCSPSvc\Responder\*\SigningCertificate blobs above are the authoritative copy."
    }
}

# =====================================================================================
Section "D. Certificate templates"
# =====================================================================================
Try-Block "certutil -CATemplates  (templates published on THIS CA)" {
    (& certutil -CATemplates 2>&1 | Out-String).Trim() | Write-Host
}
Try-Block "Get-CATemplate" {
    if (Get-Command Get-CATemplate -ErrorAction SilentlyContinue) {
        Get-CATemplate | Format-Table -AutoSize | Out-String | Write-Host
    } else { Note "Get-CATemplate not present." }
}
Try-Block "Custom template definition(s) from AD  +  Enroll / AutoEnroll ACL" {
    $configNC = $null
    try { $configNC = (Get-ADRootDSE -ErrorAction Stop).configurationNamingContext } catch { }
    if (-not $configNC) { Note "Could not read configurationNamingContext (ActiveDirectory module / DC reachability). Skipping AD template dump."; return }

    $tmplBase = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$configNC"
    $allTmpl  = Get-ADObject -SearchBase $tmplBase -LDAPFilter '(objectClass=pKICertificateTemplate)' -Properties * -ErrorAction Stop

    $enrollGuid     = [guid]'0e10c968-78fb-11d2-90d4-00c04f79dc55'   # Enroll extended right
    $autoEnrollGuid = [guid]'a05b8cc2-17bc-4802-a710-e7c15ab866a2'   # AutoEnroll extended right

    # Which templates to deep-dive
    if ($TemplateName) {
        $picked = foreach ($pat in $TemplateName) {
            $allTmpl | Where-Object { $_.displayName -like "*$pat*" -or $_.Name -like "*$pat*" -or $_.'msPKI-Cert-Template-OID' -eq $pat }
        }
        $picked = $picked | Sort-Object DistinguishedName -Unique
    } else {
        Note "No -TemplateName given - deep-diving every template whose EKU includes Client Authentication (1.3.6.1.5.5.7.3.2). Expect built-ins in the list."
        $picked = $allTmpl | Where-Object { $_.pKIExtendedKeyUsage -contains '1.3.6.1.5.5.7.3.2' }
    }
    if (-not $picked) { Note "No templates matched."; return }

    foreach ($t in $picked) {
        Write-Host ""
        Write-Host ("  ============ {0}  (cn={1}) ============" -f $t.displayName, $t.Name) -ForegroundColor White
        [pscustomobject]@{
            displayName                    = $t.displayName
            name                           = $t.Name
            'msPKI-Template-Schema-Version' = $t.'msPKI-Template-Schema-Version'
            revision                       = $t.revision
            'msPKI-Template-Minor-Revision' = $t.'msPKI-Template-Minor-Revision'
            'msPKI-Cert-Template-OID'       = $t.'msPKI-Cert-Template-OID'
            'msPKI-Minimal-Key-Size'       = $t.'msPKI-Minimal-Key-Size'
            'msPKI-RA-Signature'           = $t.'msPKI-RA-Signature'
            'pKIDefaultKeySpec'            = $t.pKIDefaultKeySpec
            EKU                            = ($t.pKIExtendedKeyUsage -join ', ')
            'pKIKeyUsage(hex)'             = $(if ($t.pKIKeyUsage) { '0x' + ([BitConverter]::ToString([byte[]]$t.pKIKeyUsage) -replace '-','') } else { $null })
            'Certificate-Name-Flag(hex)'   = ('0x{0:X8}' -f ([int]$t.'msPKI-Certificate-Name-Flag'))
            'Enrollment-Flag(hex)'         = ('0x{0:X8}' -f ([int]$t.'msPKI-Enrollment-Flag'))
            'Private-Key-Flag(hex)'        = ('0x{0:X8}' -f ([int]$t.'msPKI-Private-Key-Flag'))
            'msPKI-Certificate-Application-Policy' = ($t.'msPKI-Certificate-Application-Policy' -join ', ')
            ExpirationPeriod               = ConvertFrom-PkiPeriod $t.pKIExpirationPeriod
            OverlapPeriod                  = ConvertFrom-PkiPeriod $t.pKIOverlapPeriod
        } | Format-List | Out-String | Write-Host

        Sub "ACL for $($t.Name)  (Enroll / AutoEnroll ACEs highlighted)"
        try {
            $acl = Get-Acl -Path ("AD:\" + $t.DistinguishedName) -ErrorAction Stop
            foreach ($ace in $acl.Access) {
                $rightNote = ''
                if ($ace.ActiveDirectoryRights -match 'ExtendedRight') {
                    if ($ace.ObjectType -eq $enrollGuid)     { $rightNote = '  <== ENROLL' }
                    elseif ($ace.ObjectType -eq $autoEnrollGuid) { $rightNote = '  <== AUTOENROLL' }
                    elseif ($ace.ObjectType -eq [guid]::Empty)   { $rightNote = '  <== (all extended rights)' }
                }
                Write-Host ("    {0,-45} {1,-22} {2}{3}" -f $ace.IdentityReference, $ace.ActiveDirectoryRights, $ace.AccessControlType, $rightNote)
            }
        } catch { Write-Host "    ERROR reading ACL: $($_.Exception.Message)" -ForegroundColor Red }
    }
}

# =====================================================================================
Section "E. Auto-enrollment GPO + live policy registry values"
# =====================================================================================
Try-Block "Default Domain Policy - Public Key Policies section of the GPO report" {
    if (-not (Get-Command Get-GPOReport -ErrorAction SilentlyContinue)) { Note "GroupPolicy module not available."; return }
    $xml = Get-GPOReport -Name 'Default Domain Policy' -ReportType Xml -ErrorAction Stop
    $m = [regex]::Matches($xml, '(?s)<PublicKeyPolicies>.*?</PublicKeyPolicies>')
    if ($m.Count) { $m | ForEach-Object { Write-Host $_.Value } }
    else {
        Note "No <PublicKeyPolicies> block in Default Domain Policy. Scanning it for AutoEnrollment / AEPolicy anyway:"
        [regex]::Matches($xml, '(?s).{120}(AutoEnrollment|AEPolicy|Cryptography).{240}') | ForEach-Object { Write-Host "..."; Write-Host $_.Value; Write-Host "..." }
    }
}
Try-Block "Every GPO - which ones mention AutoEnrollment / AEPolicy" {
    if (-not (Get-Command Get-GPO -ErrorAction SilentlyContinue)) { return }
    foreach ($g in (Get-GPO -All | Sort-Object DisplayName)) {
        try {
            $rx = Get-GPOReport -Guid $g.Id -ReportType Xml -ErrorAction Stop
            if ($rx -match 'AutoEnrollment|AEPolicy|PublicKeyPolicies|Certificate Services Client') {
                Write-Host ("  * {0}    {{{1}}}" -f $g.DisplayName, $g.Id)
            }
        } catch { }
    }
    Note "For each GPO flagged above, CA-Manager will want its full <PublicKeyPolicies> block - re-run Get-GPOReport -Name '<that GPO>' -ReportType Xml if it isn't Default Domain Policy (already dumped above)."
}
Try-Block "Live policy registry values (this machine / current user)" {
    $paths = @(
        'HKLM:\Software\Policies\Microsoft\Cryptography\AutoEnrollment',
        'HKCU:\Software\Policies\Microsoft\Cryptography\AutoEnrollment',
        'HKLM:\Software\Policies\Microsoft\Cryptography\PolicyServers',
        'HKCU:\Software\Policies\Microsoft\Cryptography\PolicyServers'
    )
    foreach ($p in $paths) {
        Write-Host "  $p"
        if (Test-Path $p) {
            Get-ItemProperty -Path $p -ErrorAction SilentlyContinue |
                Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider,PSDrive |
                Format-List | Out-String | Write-Host
            Get-ChildItem -Path $p -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
                Write-Host "    [subkey] $($_.PSChildName)"
                Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue |
                    Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider,PSDrive |
                    Format-List | Out-String | Write-Host
            }
        } else { Write-Host "    (absent)" }
    }
    Note "AEPolicy bitmask: 0x1 enrolled + 0x2 renew/update/remove-revoked + 0x4 update-templates => 0x7 (7) = all three boxes. OfflineExpirationPercent = 10 matches 'log expiry events at 10%'."
}

# =====================================================================================
Section "F. CRL distribution share"
# =====================================================================================
Try-Block "Resolve the share path" {
    $paths = @()
    if ($CrlSharePath) { $paths += $CrlSharePath }
    # discover UNC / file:// publication targets from the CA registry
    $crlUrls = (& certutil -getreg CA\CRLPublicationURLs 2>&1 | Out-String)
    foreach ($line in ($crlUrls -split "`r?`n")) {
        if ($line -match '(file://|\\\\)[^\r\n"]+') {
            $u = $Matches[0].Trim().TrimEnd('\')
            $u = $u -replace '^file://',''
            $u = $u -replace '%SystemRoot%', $env:SystemRoot -replace '%windir%', $env:windir
            # strip the %3/%8-style certutil filename tokens down to a directory
            $u = $u -replace '\\[^\\]*%\d.*$',''
            if ($u -match '^\\\\' -and $paths -notcontains $u) { $paths += $u }
        }
    }
    if (-not $paths) { Note "No -CrlSharePath given and no UNC/file:// entry in CRLPublicationURLs. Section F skipped."; return }

    foreach ($sp in ($paths | Sort-Object -Unique)) {
        Write-Host ""
        Write-Host "  path: $sp" -ForegroundColor White
        Sub "reachable?"
        Write-Host "    $([bool](Test-Path -LiteralPath $sp))"
        Sub "SMB share (if this box hosts it)"
        try {
            $leaf     = ($sp -replace '^\\\\[^\\]+\\','').TrimEnd('\')   # UNC -> share leaf; local path stays as-is
            $allShares = @(Get-SmbShare -ErrorAction SilentlyContinue)
            $match = $allShares | Where-Object {
                $_.Path -and (
                    ($_.Path.TrimEnd('\') -ieq $sp.TrimEnd('\')) -or        # share backs this exact local path
                    ($leaf -ieq $_.Name) -or                                # UNC leaf == share name
                    ($sp -ilike ("*\" + $_.Name))
                )
            }
            if ($match) {
                $match | ForEach-Object {
                    $_ | Select-Object Name, Path, Description, ScopeName | Format-List | Out-String | Write-Host
                    Sub "share-level ACL (Get-SmbShareAccess $($_.Name))"
                    Get-SmbShareAccess -Name $_.Name -ErrorAction SilentlyContinue |
                        Select-Object Name, AccountName, AccessControlType, AccessRight | Format-Table -AutoSize | Out-String | Write-Host
                }
            } else {
                Write-Host "    No share matched '$sp' by name or backing path. All shares on this box:"
                $allShares | Select-Object Name, Path, Description | Format-Table -AutoSize | Out-String | Write-Host
            }
        } catch { Write-Host "    (Get-SmbShare unavailable: $($_.Exception.Message))" }
        Sub "NTFS ACL"
        try {
            (Get-Acl -LiteralPath $sp).Access |
                Select-Object IdentityReference, FileSystemRights, AccessControlType, IsInherited |
                Format-Table -AutoSize | Out-String | Write-Host
        } catch { Write-Host "    ERROR: $($_.Exception.Message)" -ForegroundColor Red }
        Sub ".crl / .crt files present"
        try {
            Get-ChildItem -LiteralPath $sp -Include *.crl,*.crt -Recurse -ErrorAction SilentlyContinue |
                Select-Object FullName, Length, LastWriteTime | Format-Table -AutoSize | Out-String | Write-Host
        } catch { }
    }
}

# =====================================================================================
Section "G. Azure App Proxy connector (local view only)"
# =====================================================================================
Try-Block "connector services + installed version" {
    Get-Service -Name 'WAPCSvc','WAPCUpdaterSvc' -ErrorAction SilentlyContinue |
        Select-Object Name, Status, StartType, DisplayName | Format-Table -AutoSize | Out-String | Write-Host
    $keys = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
            'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    Get-ItemProperty $keys -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName -match 'Application Proxy|App Proxy' } |
        Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Format-List | Out-String | Write-Host
}
Note "The Entra published-app side (App-CRL: external+internal URL, pre-auth mode; App-OCSP: same) is NOT readable from this box."
Note "Pull it by hand: Entra portal > Enterprise apps > (each app) > Application proxy;  or Graph: GET /applications + onPremisesPublishing."

# =====================================================================================
Section "H. Auto-enrollment umbrella / master AD group"
# =====================================================================================
Try-Block "locate the umbrella group + its membership" {
    if (-not (Get-Command Get-ADGroup -ErrorAction SilentlyContinue)) { Note "ActiveDirectory module unavailable."; return }
    $groups = @()
    if ($MasterGroupName) {
        $groups = @(Get-ADGroup -Filter "Name -eq '$MasterGroupName'" -Properties Description, member, memberOf -ErrorAction SilentlyContinue)
        if (-not $groups) { Note "No group named exactly '$MasterGroupName' - falling back to wildcard search." }
    }
    if (-not $groups) {
        $groups = @(Get-ADGroup -LDAPFilter '(|(name=*Master*)(name=*IKEv2*)(name=*VPN*Enroll*)(name=*AutoEnroll*))' -Properties Description, member, memberOf -ErrorAction SilentlyContinue)
        Note "Wildcard match (*Master* / *IKEv2* / *VPN*Enroll* / *AutoEnroll*) - the real umbrella is whichever one is used in the section D template ACLs."
    }
    if (-not $groups) { Note "No candidate groups found."; return }
    foreach ($g in $groups) {
        Write-Host ""
        Write-Host "  ===== $($g.Name) =====" -ForegroundColor White
        Write-Host "    DN          : $($g.DistinguishedName)"
        Write-Host "    Description : $($g.Description)"
        Write-Host "    memberOf    : $($g.memberOf -join '; ')"
        Sub "direct members"
        Get-ADGroupMember -Identity $g -ErrorAction SilentlyContinue |
            Select-Object objectClass, name, distinguishedName | Format-Table -AutoSize | Out-String | Write-Host
        Sub "nested group members only (these are the 'primary' VPN user groups nested into the umbrella)"
        Get-ADGroupMember -Identity $g -ErrorAction SilentlyContinue | Where-Object objectClass -eq 'group' |
            Select-Object name, distinguishedName | Format-Table -AutoSize | Out-String | Write-Host
        Sub "recursive member count"
        try { Write-Host "    $((Get-ADGroupMember -Identity $g -Recursive -ErrorAction SilentlyContinue | Measure-Object).Count) principals (recursive)" } catch { }
    }
}

Section "DONE"
Write-Host "Inventory written to:" -ForegroundColor Green
Write-Host "  $outFile" -ForegroundColor Green
Write-Host ""
Write-Host "Send that file back. For a two-tier (dedicated sub-CA) deployment, run this on the ROOT too." -ForegroundColor Cyan

try { Stop-Transcript | Out-Null } catch { }
Write-Host ""
Write-Host "(press Enter to close)"
try { Read-Host | Out-Null } catch { }
