<#
.SYNOPSIS
    CA Manager - FortiGate certificate hand-off (menu option F). Requires Modules\CACore.ps1,
    Modules\CAInteractive.ps1, Modules\CAOcsp.ps1 (for Get-CAOcspCACertBytes), Modules\CATameMyCerts.ps1
    (for ConvertTo-CATameMyCertsToken - see Get-CAFortiGatePeerPlan below) dot-sourced, plus
    Request-VPNCertCore.ps1 (bundled next to CA-Manager.ps1 by Build-CAManagerZip.ps1; dev-time
    fallback to the repo copy under IPSEC AIO\MiscTools\Tools\). CA-Manager.ps1's own dot-source order
    loads CATameMyCerts.ps1 AFTER this file, but every module finishes loading before the dashboard
    shows its first menu, so the dependency is real (needed at menu-13 RUN time) without needing the
    load order itself changed.

.DESCRIPTION
    The roll-out philosophy (the maintainer, 2026-09-08): a Certificate-auth client is NOT deployed until
    the CA side is fully built. The MasterOrchestrator stages this tool, HALTS the client, and waits
    for a <Company>_CAResponse.json to be copied back. This module produces:

      <Company>_CAResponse.json  - DATA only (Schema 4, 2026-09-30): the issuing CA cert + parent
                                   chain, resolved object names, peer plan, revocation URLs, and the
                                   FortiGate identity cert (PFX embedded as base64, or the CSR-signed
                                   cert as PEM). No CLI: CLIBuilder renders the CA/peer block from
                                   these fields, and the Orchestrator writes the identity-cert import
                                   note (00_APPLY_FIRST_FortiGate_CertSetup.txt) itself.
      <Company>_FortiGate.pfx    - the FortiGate's identity cert + key (password-protected), when
                                   CA-Manager generated the key; also embedded in the JSON.

    The FortiGate identity key is generated here in PowerShell (the maintainer's call - no CSR round-trip,
    no FortiGate API creds on the CA box) against the CA_TemplateFortiGate server-auth template, or
    signed from a FortiGate CSR. Re-running menu 13 offers to REUSE the identity cert already in the
    output folder's hand-back (Get-CAHandoffIdentity), so everything else can be rebuilt without a
    new request + approval.
#>

# --- locate + dot-source the shared request engine (same pattern as CATestSuite.ps1) ---
$script:__caHandoffCoreLoaded = $false
# NSP.PKI: the module ships it as (only) Private\Engine\Request-VPNCertCore.ps1.
foreach ($candidate in @(
    (Join-Path $PSScriptRoot "Engine\Request-VPNCertCore.ps1")
)) {
    if (Test-Path $candidate) { . $candidate; $script:__caHandoffCoreLoaded = $true; break }
}

# Schema 2 (2026-09-11) - additive only: FortiGateCertSetupText + FortiGatePfxBase64 embed the
# sibling .txt/.pfx files' own content directly in the JSON, so a tech can copy back just the ONE
# _CAResponse.json file instead of all 3 - IPSec-MasterOrchestrator.ps1's Restore-CAHandoffArtifacts
# reconstitutes the sibling files on the receiving end if they weren't also copied back. A Schema-1
# response (missing these two fields) still works exactly as before - nothing here is removed.
#
# Schema 3 (2026-09-15) - additive only again: CACertChain (Get-CAFortiGateParentCertChain) carries
# the parent CA cert(s) above the issuing CA, for a subordinate-CA client - empty array (unchanged
# rendered output) for the common root/standalone-CA case. A Schema-1/2 response (missing this field)
# still works exactly as before.
#
# Schema 4 (2026-09-30, per the maintainer - CLI generation moved to CLIBuilder): FortiGateCertSetupText is
# gone and no _FortiGate_CertSetup.txt is written. The Orchestrator accepts a Schema 4 hand-back as
# complete with just the JSON (+ PFX), and still ingests Schema 1-3 files.
$script:CAHandoffResponseSchema = 4

# ---------------------------------------------------------------------------
function ConvertTo-CAPem {
    <#
    .SYNOPSIS
        DER byte[] -> a PEM block (64-char-wrapped base64 between -----BEGIN/END <Label>-----).
        PURE.
    #>
    param(
        [Parameter(Mandatory)][byte[]]$DerBytes,
        [string]$Label = 'CERTIFICATE'
    )
    $b64 = [Convert]::ToBase64String($DerBytes)
    $sb  = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine("-----BEGIN $Label-----")
    for ($i = 0; $i -lt $b64.Length; $i += 64) {
        [void]$sb.AppendLine($b64.Substring($i, [Math]::Min(64, $b64.Length - $i)))
    }
    [void]$sb.Append("-----END $Label-----")
    $sb.ToString()
}

# ---------------------------------------------------------------------------
function Get-CAFortiGateParentCertChain {
    <#
    .SYNOPSIS
        PARENT CA certificate(s) only - NOT the issuing CA's own cert (the caller already has that via
        Get-CAOcspCACertBytes/CACertPem). Walks up from the issuing CA's cert to the self-signed root,
        one entry per tier in between, in leaf-to-root order. Empty array for a root/standalone issuing
        CA (the common case) - purely additive, changes nothing for a client that doesn't need it.

        2026-09-15, per the maintainer: "We need to capture the whole chain (public certs) for the issuing CA
        (so if it's subordinate, get the parent CA cert too, make sure it's the latest cert)." The
        "latest cert" selection itself is Get-CAOcspCACertBytes's job (Sort-Object NotAfter
        -Descending against the issuing CA's own CN, already established for the OCSP responder) -
        this function takes that ALREADY-RESOLVED cert as input rather than re-deriving "latest"
        again here, so there's exactly one place that decision is made, not two that could drift.

    .PARAMETER IssuingCert
        The issuing CA's own X509Certificate2 - build this from the SAME bytes
        Get-CAOcspCACertBytes -CACommonName <Status.CACommonName> already selected.

    .OUTPUTS
        Array of pscustomobject { Name; Pem }. Name is "CA_<sanitized subject CN>", falling back to
        "CA_Parent<N>" if a tier's CN can't be extracted (still unique per tier, still safe to use as
        a FortiGate object name). Pem is that tier's public cert.

    .NOTES
        Read-only: X509Chain.Build() over the LOCAL machine's cert stores only - RevocationMode is
        explicitly NoCheck (this captures the STRUCTURAL chain of public certs to import, it is not a
        revocation check) and VerificationFlags allows an unknown/untrusted root so an internal PKI's
        own root (never in the Windows trusted-root store) still resolves. Fails soft to an empty
        array (never throws) if the parent isn't installed locally / the chain can't be built at all -
        the hand-off is then no worse than before this function existed (issuing CA cert alone).
    #>
    param([Parameter(Mandatory)][System.Security.Cryptography.X509Certificates.X509Certificate2]$IssuingCert)

    if ($IssuingCert.Subject -eq $IssuingCert.Issuer) { return @() }   # self-signed - it IS the root, nothing above it

    try {
        $chain = [System.Security.Cryptography.X509Certificates.X509Chain]::new()
        $chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
        $chain.ChainPolicy.VerificationFlags = [System.Security.Cryptography.X509Certificates.X509VerificationFlags]::AllowUnknownCertificateAuthority
        [void]$chain.Build($IssuingCert)
    } catch { return @() }

    $parents = New-Object System.Collections.Generic.List[object]
    # ChainElements[0] is the issuing cert itself (what Build() was called with) - the caller already
    # has that one (CACertPem/CACertNameOnGate); only tiers ABOVE it are new here.
    for ($i = 1; $i -lt $chain.ChainElements.Count; $i++) {
        $cert = $chain.ChainElements[$i].Certificate
        $cn = try { $cert.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false) } catch { $null }
        $token = if (-not [string]::IsNullOrWhiteSpace($cn)) { ($cn -replace '[^A-Za-z0-9]', '') } else { '' }
        $name = if ($token) { "CA_$token" } else { "CA_Parent$i" }
        $parents.Add([pscustomobject]@{
            Name = $name
            Pem  = ConvertTo-CAPem -DerBytes ([byte[]]$cert.RawData) -Label 'CERTIFICATE'
        })
    }
    return $parents.ToArray()
}

# ---------------------------------------------------------------------------
function Get-CAResponseObject {
    <#
    .SYNOPSIS
        PURE. Builds the <Company>_CAResponse.json content object from the resolved inputs. No I/O.
    .PARAMETER CAAnswers
        The CAAnswers.json object (Company_Name, Cert_CertificateName, Cert_PeerName, CA_* fields).
    .PARAMETER CACommonName / CAConfigString / CASanitizedName
        Resolved CA identity.
    .PARAMETER CACertPem
        The CA public certificate as a PEM string.
    .PARAMETER CACertChain
        2026-09-15 addition (Schema 3, additive) - array of { Name; Pem } for every PARENT CA
        certificate above the issuing CA (see Get-CAFortiGateParentCertChain) - empty/omitted for a
        root/standalone issuing CA, the common case. NOT the issuing CA's own cert, which stays in
        CACertPem/CACertNameOnGate exactly as before this addition.
    .PARAMETER FgCert
        The { PfxPath; Password; Thumbprint; SerialNumber } from New-CAFortiGateIdentityCert
        (or $null in a dry run).
    .PARAMETER PeerSubjectFilter
        The 'set subject' substring, or '' / $null for none.
    .PARAMETER FortiGatePfxBase64
        2026-09-11 addition (Schema 2) - the PFX file's own bytes, base64-encoded, when
        New-CAFortiGateIdentityCert actually generated one (the "blank -> CA-Manager generates a
        keypair + PFX" path only; the CSR/import paths have no PFX, just FortiGateCertPem, already
        inline). This function stays PURE (no I/O) - the CALLER reads the PFX bytes and passes the
        base64 string in; Get-CAResponseObject never touches the filesystem itself. Lets the whole
        hand-back travel as ONE file (this JSON) instead of needing the sibling .pfx copied back too
        - see Write-CAHandoffFiles' own note and IPSec-MasterOrchestrator.ps1's
        Restore-CAHandoffArtifacts for the other end of this.
    #>
    param(
        $CAAnswers,
        [Parameter(Mandatory)][string]$CACommonName,
        [string]$CAConfigString,
        [Parameter(Mandatory)][string]$CASanitizedName,
        [string]$CACertPem,
        $CACertChain,
        $FgCert,
        [string]$PeerSubjectFilter,
        [string]$CAManagerVersion,
        [string]$FortiGatePfxBase64
    )

    $issuingModel = if ($CAAnswers.CA_IssuingModel) { "$($CAAnswers.CA_IssuingModel)" } else { 'SharedCAWithSubjectFilter' }
    $company      = if ($CAAnswers.Company_Name)    { "$($CAAnswers.Company_Name)" }    else { $CACommonName }
    $fgCertName   = if ($CAAnswers.Cert_CertificateName) { "$($CAAnswers.Cert_CertificateName)" } else { "$CASanitizedName-FGT" }
    $peerName     = if ($CAAnswers.Cert_PeerName)   { "$($CAAnswers.Cert_PeerName)" }   else { "$CASanitizedName-peer" }
    $caCertName   = "CA_$CASanitizedName"

    $crlUrl = if ($CAAnswers.CA_AppProxyCrlFqdn -and "$($CAAnswers.CA_AppProxyCrlFqdn)" -match '\.') {
        "http://$($CAAnswers.CA_AppProxyCrlFqdn)/CertEnroll/$CASanitizedName.crl"
    } else { $null }
    $ocspUrl = if ($CAAnswers.CA_AppProxyOcspFqdn -and "$($CAAnswers.CA_AppProxyOcspFqdn)" -match '\.') {
        "http://$($CAAnswers.CA_AppProxyOcspFqdn)/ocsp"
    } else { $null }

    # 2026-09-15, per the maintainer (live client troubleshooting - a hand-typed 'IKEv2_CorpLAN' peer had two
    # real bugs found only via live FortiGate debug logs): for a TameMyCerts + RadiusGroupPairs client,
    # generate one config user peer per pair instead of leaving this entirely manual.
    $peerPlan = Get-CAFortiGatePeerPlan -CAAnswers $CAAnswers

    $out = [ordered]@{
        Schema                   = $script:CAHandoffResponseSchema
        GeneratedUtc             = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        CAManagerVersion         = $CAManagerVersion
        Company                  = $company
        IssuingModel             = $issuingModel
        CACommonName             = $CACommonName
        CAConfigString           = $CAConfigString
        CASanitizedName          = $CASanitizedName
        CACertNameOnGate         = $caCertName
        CACertPem                = $CACertPem
        # NOT a bare @($CACertChain) - wrapping a $null scalar in @() produces a 1-element array
        # holding $null (Count 1), not an empty array. The caller omits -CACertChain entirely for the
        # common root/standalone-CA case, so this must explicitly collapse a null/absent value to a
        # real empty array or CLIBuilder's "any parents?" check would misfire.
        CACertChain              = if ($CACertChain) { @($CACertChain) } else { @() }
        FortiGateCertName        = $fgCertName
        FortiGatePeerName        = $peerName
        FortiGatePfxFile         = if ($FgCert -and $FgCert.PfxPath) { Split-Path $FgCert.PfxPath -Leaf } else { $null }
        FortiGatePfxPassword     = if ($FgCert) { $FgCert.Password } else { $null }
        FortiGatePfxBase64       = if (-not [string]::IsNullOrWhiteSpace($FortiGatePfxBase64)) { $FortiGatePfxBase64 } else { $null }
        FortiGateCertPem         = if ($FgCert -and $FgCert.PSObject.Properties['CertPem']) { $FgCert.CertPem } else { $null }
        FortiGateCertThumbprint  = if ($FgCert) { $FgCert.Thumbprint } else { $null }
        PeerSubjectFilter        = if ([string]::IsNullOrWhiteSpace($PeerSubjectFilter)) { '' } else { $PeerSubjectFilter.Trim() }
        PeerPlan                 = $peerPlan
        AppProxyCrlUrl           = $crlUrl
        AppProxyOcspUrl          = $ocspUrl
        AutoEnrollGpo            = if ($CAAnswers.CA_AutoEnrollGPOName) { "$($CAAnswers.CA_AutoEnrollGPOName)" } else { $null }
        TemplatesPublished       = @(
            $CAAnswers.CA_TemplateAuto, $CAAnswers.CA_TemplateManual, $CAAnswers.CA_TemplateFortiGate
        ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
    }
    # Schema 4 (2026-09-30): no rendered CLI any more (Schema 2-3's FortiGateCertSetupText). CLIBuilder
    # renders the CA cert / chain / peer block from these fields once the Orchestrator folds them into
    # the client's answers, and the Orchestrator writes the identity-cert import note itself.
    return $out
}

# ---------------------------------------------------------------------------
function Get-CAFortiGatePeerPlan {
    <#
    .SYNOPSIS
        PURE. One 'config user peer' object per RadiusGroupPair (TameMyCerts model), bundled into one
        'config user peergrp', instead of the single hand-typed peer a real client's own live setup had -
        which shipped with two real bugs (a bare 'set subject' value with no RDN attribute name, and
        an mfa-mode that triggered a RADIUS auth method NPS's policy didn't allow) neither of which any
        tooling would have caught, since nothing generated this block at all before now.

        EXCLUDES any pair with IncludeInNPSImport explicitly $false - the SAME signal
        OrchestratorImport.ps1's own NPS-Manager import already uses to skip these (CLIBuilder's
        Custom App-Access Rules flow defaults new VPNFW/firewall-scoping-purpose pairs to this) -
        The maintainer, 2026-09-15: "I want a peer for each of the groups, but NOT the VPNFW groups." These
        aren't standalone tunnel identities, they ride along via firewall rules once a user's PRIMARY
        group already has a peer/cert - giving them their own peer object would be noise, not signal.

        Each peer's OU token is derived via the EXACT SAME ConvertTo-CATameMyCertsToken function
        TameMyCerts itself uses (CATameMyCerts.ps1) for its own policy XML - the peer's 'set subject'
        can never drift from what's actually stamped into the cert, unlike a hand-typed value.

        Deliberately never sets 'mfa-mode' - confirmed live against a real client's FortiGate that
        'subject-identity' MFA mode sends a RADIUS request NPS-Manager's own generated Network
        Policies don't allow (PEAP-only) - a peer this function builds authenticates on the
        certificate + subject match alone.
    .PARAMETER CAAnswers
        The CAAnswers.json object (CA_SubjectStampMode, RadiusGroupPairs).
    .PARAMETER PeerPrefix
        Default 'P_IKEv2_DIv2_' - 'P_' (the maintainer, 2026-09-15) marks it as a 'config user peer' object at
        a glance on the gate, same spirit as the 'CA_' prefix on CA-certificate objects; DIv2 =
        Dialup-IKEv2, the tunnel these peers gate. A pair's own Label occasionally already carries a
        'DIv2-'/'DIv2_' marker of its own (a RadiusGroupPairs labeling convention that predates this
        feature, e.g. 'DIv2-RedStone') - stripped from the LABEL before appending it here, so the
        result is 'P_IKEv2_DIv2_RedStone', not the redundant 'P_IKEv2_DIv2_DIv2-RedStone'.
    .PARAMETER PeerGroupName
        Default 'IKEv2_DIv2_AllowedPeers' (the maintainer's own naming, 2026-09-15) - a 'config user peergrp'
        object, not an individual peer, so it deliberately does NOT get the 'P_' prefix.
    .OUTPUTS
        pscustomobject: Applicable (bool - TameMyCerts mode AND at least one qualifying pair);
        PeerGroupName; Peers (array of { GroupLabel; UserGroupName; PeerName; OuValue }).
    #>
    param(
        $CAAnswers,
        [string]$PeerPrefix = 'P_IKEv2_DIv2_',
        [string]$PeerGroupName = 'IKEv2_DIv2_AllowedPeers'
    )

    $mode = if ($CAAnswers -and -not [string]::IsNullOrWhiteSpace($CAAnswers.CA_SubjectStampMode)) { "$($CAAnswers.CA_SubjectStampMode)".Trim() } else { 'None' }
    $pairs = @()
    if ($CAAnswers -and $CAAnswers.PSObject.Properties['RadiusGroupPairs'] -and $CAAnswers.RadiusGroupPairs) { $pairs = @($CAAnswers.RadiusGroupPairs) }

    $peers = New-Object System.Collections.Generic.List[object]
    if ($mode -eq 'TameMyCerts' -and $pairs.Count) {
        foreach ($p in $pairs) {
            # Same exclusion signal OrchestratorImport.ps1's own NPS import already uses - a pair from
            # CLIBuilder's Custom App-Access Rules flow (VPNFW/firewall-scoping groups) defaults this
            # to $false; a pair saved before this field existed, or explicitly $true, is included.
            if ($p.PSObject.Properties['IncludeInNPSImport'] -and $null -ne $p.IncludeInNPSImport -and -not [bool]$p.IncludeInNPSImport) { continue }

            $label = if ($p.PSObject.Properties['Label']) { "$($p.Label)" } else { '' }
            # Same UserGroupValue-over-UserGroupName preference as Get-CAPerGroupTemplateSpecs/
            # Get-CATameMyCertsPlan - UserGroupValue is the real AD group; UserGroupName is a friendlier
            # label not reliably a real AD group (2026-09-10 live bug, see those functions' own notes).
            $grp = if ($p.PSObject.Properties['UserGroupValue'] -and -not [string]::IsNullOrWhiteSpace($p.UserGroupValue)) { "$($p.UserGroupValue)" }
                   elseif ($p.PSObject.Properties['UserGroupName']) { "$($p.UserGroupName)" }
                   else { '' }
            if (-not $label -and -not $grp) { continue }

            $ou = if ($p.PSObject.Properties['CertSubjectOu'] -and -not [string]::IsNullOrWhiteSpace($p.CertSubjectOu)) {
                      ConvertTo-CATameMyCertsToken $p.CertSubjectOu
                  } else {
                      ConvertTo-CATameMyCertsToken $(if ($grp) { $grp } else { $label })
                  }

            $labelToken = ConvertTo-CATameMyCertsToken $(if ($label) { $label } else { $grp })
            $labelToken = $labelToken -replace '^DIv2[-_]', ''
            $peerName = "$PeerPrefix$labelToken"

            $peers.Add([pscustomobject]@{
                GroupLabel    = $label
                UserGroupName = $grp
                PeerName      = $peerName
                OuValue       = $ou
            })
        }
    }

    [pscustomobject]@{
        Applicable    = [bool]$peers.Count
        PeerGroupName = $PeerGroupName
        Peers         = $peers.ToArray()
    }
}

# ---------------------------------------------------------------------------
function Get-CAHandoffIdentity {
    <#
    .SYNOPSIS
        The FortiGate identity certificate carried by an earlier <Company>_CAResponse.json in
        -OutputDir, so menu 13 can re-run without issuing a new one; $null when there is none.
    .DESCRIPTION
        2026-09-30, per the maintainer: "not being able to hit the other items without re-requesting a
        FortiGate cert is my main concern." Everything else in the hand-back (CA cert + chain, names,
        peer plan, URLs) is rebuilt from the CA and the answers on every run; only the identity cert
        costs a request + approval. Returns the same shape New-CAFortiGateIdentityCert /
        New-CAFortiGateCertFromCsr do (PfxPath; Password; CertPem; Thumbprint; SerialNumber; Status),
        plus Subject / NotAfter / Kind ('PFX' or 'Cert') / PfxBase64 for the reuse prompt and checks.
        A PFX embedded only as base64 is written back out next to the JSON so PfxPath is real.
    #>
    param(
        [Parameter(Mandatory)][string]$OutputDir,
        [Parameter(Mandatory)][string]$CompanyStem
    )
    # NSP.PKI: the hand-off file (<Company>_PKI_Response.json, payload unwrapped) first, then the
    # zip-era <stem>_CAResponse.json.
    $old = $null
    # Matched on the header's Company (the hand-off file name keeps '-' and '_'; -CompanyStem doesn't).
    if (Get-Command Import-NSPHandoff -ErrorAction SilentlyContinue) {
        foreach ($candidate in @(Get-ChildItem -Path $OutputDir -Filter '*_PKI_Response.json' -File -ErrorAction SilentlyContinue)) {
            try { $h = Import-NSPHandoff -Path $candidate.FullName -Tool PKI -Kind Response } catch { continue }
            if (("$($h.Company)" -replace '[^A-Za-z0-9]', '') -ne $CompanyStem) { continue }
            $old = $h.Payload; $jsonPath = $candidate.FullName; break
        }
    }
    if (-not $old) {
        $jsonPath = Join-Path $OutputDir "${CompanyStem}_CAResponse.json"
        if (-not (Test-Path $jsonPath)) { return $null }
        try { $old = Get-Content -Path $jsonPath -Raw | ConvertFrom-Json } catch { return $null }
    }

    $cert = $null
    $out = [pscustomobject]@{
        Kind = $null; PfxPath = $null; Password = $null; PfxBase64 = $null; CertPem = $null
        Thumbprint = $old.FortiGateCertThumbprint; SerialNumber = $null; Subject = $null; NotAfter = $null; Status = 'Issued'
    }
    try {
        if ($old.FortiGatePfxBase64 -or $old.FortiGatePfxFile) {
            $pfxPath = if ($old.FortiGatePfxFile) { Join-Path $OutputDir $old.FortiGatePfxFile } else { Join-Path $OutputDir "${CompanyStem}_FortiGate.pfx" }
            # [byte[]]-typed: an if-expression unrolls a byte array into object[], and X509Certificate2 then
            # binds its (fileName, password) overload instead - 'path too long'.
            [byte[]]$bytes = if (Test-Path $pfxPath) { [System.IO.File]::ReadAllBytes($pfxPath) } elseif ($old.FortiGatePfxBase64) { [Convert]::FromBase64String($old.FortiGatePfxBase64) } else { $null }
            if (-not $bytes) { return $null }
            if (-not (Test-Path $pfxPath)) { [System.IO.File]::WriteAllBytes($pfxPath, $bytes) }
            $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($bytes, [string]$old.FortiGatePfxPassword)
            $out.Kind = 'PFX'; $out.PfxPath = $pfxPath; $out.Password = $old.FortiGatePfxPassword; $out.PfxBase64 = [Convert]::ToBase64String($bytes)
        } elseif ($old.FortiGateCertPem) {
            $b64 = ("$($old.FortiGateCertPem)" -replace '-----(BEGIN|END) CERTIFICATE-----', '') -replace '\s', ''
            $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new([Convert]::FromBase64String($b64))
            $out.Kind = 'Cert'; $out.CertPem = $old.FortiGateCertPem
        } else { return $null }
    } catch {
        Write-Host "  WARNING: the FortiGate cert in $jsonPath could not be read ($($_.Exception.Message)) - a new one is needed." -ForegroundColor Yellow
        return $null
    }
    $out.Thumbprint = $cert.Thumbprint; $out.SerialNumber = $cert.SerialNumber; $out.Subject = $cert.Subject; $out.NotAfter = $cert.NotAfter
    return $out
}

function Get-CAHandoffIdentityWarnings {
    <#
    .SYNOPSIS
        PURE. Reasons to think twice before reusing -Identity (Get-CAHandoffIdentity): its CN is not
        the FortiGate cert name phase1 references, it has expired, or it expires within 30 days.
        -Revoked ($true from Test-CAHandoffCertRevoked) adds a revocation warning. Warn-and-continue
        (per the maintainer) - the caller shows these, it never refuses the reuse.
    #>
    param(
        [Parameter(Mandatory)]$Identity,
        [string]$CertName,
        [datetime]$Now = (Get-Date),
        [bool]$Revoked = $false
    )
    $warnings = @()
    if ($CertName -and $Identity.Subject -and $Identity.Subject -notmatch ('(^|,\s*)CN=' + [regex]::Escape($CertName) + '(,|$)')) {
        $warnings += "Its subject ($($Identity.Subject)) is not CN=$CertName, the FortiGate certificate name phase1 uses."
    }
    if ($Identity.NotAfter) {
        if ($Identity.NotAfter -lt $Now) { $warnings += "It expired on $($Identity.NotAfter.ToString('yyyy-MM-dd'))." }
        elseif ($Identity.NotAfter -lt $Now.AddDays(30)) { $warnings += "It expires on $($Identity.NotAfter.ToString('yyyy-MM-dd')), within 30 days." }
    }
    if ($Revoked) { $warnings += "This CA lists it as REVOKED." }
    return $warnings
}

function Test-CAHandoffCertRevoked {
    <#
    .SYNOPSIS
        $true when this CA's database shows -SerialNumber revoked (disposition 21), $false when it's
        there and not revoked, $null when unknown (not issued by this CA, or certutil unavailable).
    #>
    param([Parameter(Mandatory)][string]$SerialNumber)
    $text = Invoke-CertUtilText -Arguments @('-view', '-restrict', "SerialNumber=$SerialNumber", '-out', 'Request.Disposition', 'csv')
    if (-not $text) { return $null }
    $rows = @($text -split "`r?`n" | Where-Object { $_ -match '^"' } | Select-Object -Skip 1)
    if (-not $rows.Count) { return $null }
    return [bool](@($rows | Where-Object { $_ -match '\b21\b|Revoked' }).Count)
}

# ---------------------------------------------------------------------------
function New-CAFortiGateIdentityCert {
    <#
    .SYNOPSIS
        ENGINE. Generates the FortiGate identity keypair + submits a request against the server-auth
        template, waits for manual approval, retrieves, and exports a password-protected PFX.
        Returns [pscustomobject]@{ PfxPath; Password; Thumbprint; SerialNumber; Status }.
        Every mutation goes through Invoke-CAStep.
    #>
    param(
        [Parameter(Mandatory)]$CAAnswers,
        [Parameter(Mandatory)][string]$OutputDir,
        [Parameter(Mandatory)][string]$CASanitizedName,
        [string]$FortiGateFqdn
    )
    if (-not $script:__caHandoffCoreLoaded) {
        throw "Request-VPNCertCore.ps1 not found (expected next to CA-Manager.ps1 in a built zip, or under IPSEC AIO\MiscTools\Tools\)."
    }

    $template = if (-not [string]::IsNullOrWhiteSpace($CAAnswers.CA_TemplateFortiGate)) { "$($CAAnswers.CA_TemplateFortiGate)" } else { 'FortiGate' }
    # Get-Certificate wants the template CN, not the display name (see Resolve-VPNCertTemplateName).
    if (Get-Command Resolve-VPNCertTemplateName -ErrorAction SilentlyContinue) { $template = Resolve-VPNCertTemplateName -Name $template }
    $certName = if (-not [string]::IsNullOrWhiteSpace($CAAnswers.Cert_CertificateName)) { "$($CAAnswers.Cert_CertificateName)" } else { "$CASanitizedName-FGT" }
    $subject  = "CN=$certName"
    $dnsNames = @($FortiGateFqdn, $certName) | Where-Object { $_ } | Select-Object -Unique

    $company  = if ($CAAnswers.Company_Name) { ($CAAnswers.Company_Name -replace '[^A-Za-z0-9]', '') } else { $CASanitizedName }
    $password = New-CAHandoffPassword
    $securePw = ConvertTo-SecureString $password -AsPlainText -Force

    $out = [pscustomobject]@{ PfxPath = $null; Password = $password; Thumbprint = $null; SerialNumber = $null; Status = 'NotRun' }

    if (Get-CADryRun) {
        Write-Host "  [DRY RUN] would request '$template' (subject '$subject', SAN $($dnsNames -join ', ')), wait for approval, export a PFX to $OutputDir." -ForegroundColor DarkGray
        $out.Status = 'DryRun'
        return $out
    }

    # Try user context first; an existing FortiGate template with CT_FLAG_MACHINE_TYPE ("issued only
    # to a computer") needs machine context - retry from Cert:\LocalMachine\My (menu 13 is elevated).
    $req = $null
    $store = 'Cert:\CurrentUser\My'
    foreach ($try in @('Cert:\CurrentUser\My', 'Cert:\LocalMachine\My')) {
        $script:__caFgReq = $null
        try {
            Invoke-CAStep -Description "Request the FortiGate identity certificate ('$template', subject '$subject')$(if ($try -match 'LocalMachine') { ' [machine context]' })" `
                -Commands @("Get-Certificate -Template '$template' -SubjectName '$subject' -DnsName $($dnsNames -join ',') -CertStoreLocation $try") `
                -Action {
                    $p = @{ Template = $template; SubjectName = $subject; CertStoreLocation = $try }
                    if ($dnsNames) { $p.DnsName = [string[]]$dnsNames }
                    $script:__caFgReq = Get-Certificate @p
                } | Out-Null
            $store = $try
            break
        } catch {
            if ($try -eq 'Cert:\CurrentUser\My' -and "$($_.Exception.Message)" -match 'issued only to a computer|CONTEXT_E_ROLENOTFOUND|0x8004e00c') {
                Write-Host "  '$template' is a machine template - retrying from the computer account..." -ForegroundColor DarkYellow
                continue
            }
            throw
        }
    }
    $req = $script:__caFgReq
    if (-not $req -or -not $req.Request) {
        Write-Host "  Could not submit the request against '$template' (user or machine context)." -ForegroundColor Red
        Write-Host "  If this CA is already deployed, set CA_Deployed = Yes and skip menu 13. Otherwise" -ForegroundColor Gray
        Write-Host "  check that '$template' grants Enroll to $(if ($store -match 'LocalMachine') { "$env:COMPUTERNAME`$" } else { $env:USERNAME })." -ForegroundColor Gray
        $out.Status = 'RequestFailed'
        return $out
    }

    Write-Host ""
    Write-Host "  Request submitted (thumbprint $($req.Request.Thumbprint), $(if ($store -match 'LocalMachine') { 'machine' } else { 'user' }) context)." -ForegroundColor Cyan
    Write-Host "  Approve it on the CA:  certsrv.msc -> Pending Requests -> right-click -> All Tasks -> Issue" -ForegroundColor Yellow
    Read-Host "  Press Enter once it is issued" | Out-Null

    $stem = "${company}_FortiGate"
    $res = Complete-VPNCertRequest -RequestObject $req -OutputDir $OutputDir -PfxPassword $securePw -FileNameStem $stem -CertStoreLocation $store
    $out.Status       = $res.Status
    $out.Thumbprint   = $res.Thumbprint
    $out.SerialNumber = $res.SerialNumber
    $out.PfxPath      = $res.PfxPath
    if ($res.Status -ne 'Issued') {
        Write-Host "  Retrieval reported '$($res.Status)' - re-run menu 13 once the request is issued." -ForegroundColor Yellow
    }
    return $out
}

# ---------------------------------------------------------------------------
function Read-CAX509 {
    <#
    .SYNOPSIS
        Loads an X509Certificate2 from a DER .cer OR a base64 PEM file. WinPS 5.1's
        X509Certificate2(string) constructor only handles DER, so PEM is decoded by hand.
        Returns $null if the file isn't a certificate (e.g. it's a CSR).
    #>
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path $Path)) { return $null }
    try { return [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($Path) } catch { }
    try {
        $raw = Get-Content -Path $Path -Raw
        if ($raw -match '(?s)-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----') {
            $b64 = ($Matches[1] -replace '\s', '')
            return [System.Security.Cryptography.X509Certificates.X509Certificate2]::new([Convert]::FromBase64String($b64))
        }
    } catch { }
    return $null
}

function Test-CAIsCsr {
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path $Path)) { return $false }
    try { return ((Get-Content -Path $Path -Raw) -match 'BEGIN (NEW )?CERTIFICATE REQUEST') } catch { return $false }
}

# ---------------------------------------------------------------------------
function Import-CAFortiGateIssuedCert {
    <#
    .SYNOPSIS
        Wraps an ALREADY-ISSUED FortiGate cert (.cer / .crt / base64 .pem) into the same shape
        New-CAFortiGateCertFromCsr returns - for re-building the hand-off around a cert issued by
        hand (e.g. re-processing an existing client). The gate keeps its own key -> no PFX.
    #>
    param(
        [Parameter(Mandatory)][string]$CertPath,
        [Parameter(Mandatory)][string]$OutputDir,
        [string]$FileStem = 'FortiGate'
    )
    $out = [pscustomobject]@{ CertPem = $null; CertPath = $null; Thumbprint = $null; SerialNumber = $null; Status = 'NotRun'; PfxPath = $null; Password = $null }
    if (-not (Test-Path $CertPath)) { Write-Host "  Cert not found: $CertPath" -ForegroundColor Red; $out.Status = 'NoCert'; return $out }
    $c = Read-CAX509 -Path $CertPath
    if (-not $c) { Write-Host "  Not a readable certificate (DER .cer or base64 PEM): $CertPath" -ForegroundColor Red; $out.Status = 'BadCert'; return $out }
    try {
        if (-not (Test-Path $OutputDir)) { New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null }
        $dest = Join-Path $OutputDir "$FileStem.cer"
        [System.IO.File]::WriteAllBytes($dest, $c.RawData)
        $out.CertPem      = ConvertTo-CAPem -DerBytes $c.RawData -Label 'CERTIFICATE'
        $out.CertPath     = $dest
        $out.Thumbprint   = $c.Thumbprint
        $out.SerialNumber = $c.SerialNumber
        $out.Status       = 'Issued'
        Write-Host "  Using issued cert: CN $($c.Subject), thumbprint $($c.Thumbprint), NotAfter $($c.NotAfter)" -ForegroundColor Green
    } catch {
        Write-Host "  Not a readable certificate: $($_.Exception.Message)" -ForegroundColor Red
        $out.Status = 'BadCert'
    }
    return $out
}

# ---------------------------------------------------------------------------
function New-CAFortiGateCertFromCsr {
    <#
    .SYNOPSIS
        ENGINE. Submits a CSR generated ON the FortiGate against the FortiGate template (via
        certreq, so it runs under the admin's creds - works for a machine-type / admin-only template
        that Get-Certificate can't touch), waits for approval, retrieves the signed cert, and returns
        it as PEM. The private key never leaves the gate - so no PFX, no password.
        Returns [pscustomobject]@{ CertPem; CertPath; Thumbprint; SerialNumber; Status; PfxPath=$null; Password=$null }.
    #>
    param(
        [Parameter(Mandatory)][string]$CsrPath,
        [Parameter(Mandatory)][string]$Template,
        [Parameter(Mandatory)][string]$OutputDir,
        [string]$FileStem = 'FortiGate',
        # "<CA server FQDN>\<CA common name>" - passed as certreq -config so it submits DIRECTLY
        # (no CA-picker GUI, which drops the -attrib -> CERTSRV_E_NO_CERT_TYPE).
        [string]$CAConfig
    )
    $out = [pscustomobject]@{ CertPem = $null; CertPath = $null; Thumbprint = $null; SerialNumber = $null; Status = 'NotRun'; PfxPath = $null; Password = $null }
    if (-not (Test-Path $CsrPath)) { Write-Host "  CSR not found: $CsrPath" -ForegroundColor Red; $out.Status = 'NoCsr'; return $out }
    $cfgArgs = if (-not [string]::IsNullOrWhiteSpace($CAConfig)) { @('-config', $CAConfig) } else { @() }

    if (Get-CADryRun) {
        Write-Host "  [DRY RUN] would: certreq -submit $($cfgArgs -join ' ') -attrib 'CertificateTemplate:$Template' '$CsrPath' -> approve -> certreq -retrieve <id> -> PEM." -ForegroundColor DarkGray
        $out.Status = 'DryRun'; return $out
    }
    if (-not (Test-Path $OutputDir)) { New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null }
    $cerPath = Join-Path $OutputDir "$FileStem.cer"

    $reqId = $null
    Invoke-CAStep -Description "Submit the FortiGate CSR against '$Template' (certreq$(if ($cfgArgs) { " -config $CAConfig" }))" `
        -Commands @("certreq -submit $($cfgArgs -join ' ') -attrib `"CertificateTemplate:$Template`" `"$CsrPath`" `"$cerPath`"") `
        -Action {
            $o = & certreq.exe -submit @cfgArgs -attrib "CertificateTemplate:$Template" $CsrPath $cerPath 2>&1 | Out-String
            Write-Host $o -ForegroundColor DarkGray
            if ($o -match 'RequestId:\s*"?(\d+)"?') { $script:__caFgCsrReqId = $Matches[1] }
        } | Out-Null
    $reqId = $script:__caFgCsrReqId

    if ((Test-Path $cerPath) -and (Get-Item $cerPath).Length -gt 0) {
        # auto-issued (no pending) - certreq wrote the cert straight out
    } elseif ($reqId) {
        Write-Host ""
        Write-Host "  Request $reqId is PENDING. Approve it:  certsrv.msc -> Pending Requests -> Issue" -ForegroundColor Yellow
        Read-Host "  Press Enter once it is issued" | Out-Null
        Invoke-CAStep -Description "Retrieve issued request $reqId" `
            -Commands @("certreq -retrieve $($cfgArgs -join ' ') $reqId `"$cerPath`"") `
            -Action { & certreq.exe -retrieve @cfgArgs $reqId $cerPath 2>&1 | Out-String | Write-Host -ForegroundColor DarkGray } | Out-Null
    } else {
        Write-Host "  certreq -submit did not return a RequestId and wrote no cert - check the output above." -ForegroundColor Red
        $out.Status = 'SubmitFailed'; return $out
    }

    if (-not (Test-Path $cerPath) -or (Get-Item $cerPath).Length -eq 0) {
        Write-Host "  No issued certificate at $cerPath - approve the request and re-run menu 13 with the same CSR." -ForegroundColor Yellow
        $out.Status = 'Pending'; return $out
    }

    try {
        $c = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($cerPath)
        $out.CertPem      = ConvertTo-CAPem -DerBytes $c.RawData -Label 'CERTIFICATE'
        $out.CertPath     = $cerPath
        $out.Thumbprint   = $c.Thumbprint
        $out.SerialNumber = $c.SerialNumber
        $out.Status       = 'Issued'
        Write-Host "  Issued: $cerPath  (CN $($c.Subject), thumbprint $($c.Thumbprint))" -ForegroundColor Green
    } catch {
        Write-Host "  Could not read the issued cert: $($_.Exception.Message)" -ForegroundColor Red
        $out.Status = 'BadCert'
    }
    return $out
}

# ---------------------------------------------------------------------------
function New-CAHandoffPassword {
    <#
    .SYNOPSIS
        A 20-char random password for the FortiGate PFX. Letters+digits+a few safe symbols only
        (kept shell/CLI-paste friendly). PURE (uses RNGCryptoServiceProvider).
    #>
    $alphabet = (([char[]](48..57)) + ([char[]](65..90)) + ([char[]](97..122)) + [char[]]'!@#%^*-_=+')
    $bytes = New-Object 'byte[]' 20
    (New-Object System.Security.Cryptography.RNGCryptoServiceProvider).GetBytes($bytes)
    -join ($bytes | ForEach-Object { $alphabet[$_ % $alphabet.Length] })
}

# ---------------------------------------------------------------------------
function Write-CAHandoffFiles {
    <#
    .SYNOPSIS
        ENGINE. Writes <Company>_CAResponse.json into $OutputDir from a Get-CAResponseObject. Routes
        through Invoke-CAStep. Returns @{ JsonPath }. Schema 4 (2026-09-30) writes no CLI file, and
        removes a <Company>_FortiGate_CertSetup.txt an earlier run left in the folder so it can't be
        copied back and applied by mistake - CLIBuilder's output is the CLI now.
    #>
    param(
        [Parameter(Mandatory)]$Response,
        [Parameter(Mandatory)][string]$OutputDir
    )
    $companyStem = ($Response.Company -replace '[^A-Za-z0-9]', '')
    $jsonPath = Join-Path $OutputDir "${companyStem}_CAResponse.json"
    $staleTxt = Join-Path $OutputDir "${companyStem}_FortiGate_CertSetup.txt"

    # NSP.PKI: written as a PKI Response hand-off (NSP.Toolkit shared header around the same Schema 4
    # payload, PFX and its password still embedded) - <Company>_PKI_Response.json, for the
    # Orchestrator's Staging\<Abbrev>\Inbox\. The zip-era <stem>_CAResponse.json is only written when
    # NSP.Toolkit is unavailable.
    if (Get-Command New-NSPHandoff -ErrorAction SilentlyContinue) {
        $handoffDir = $OutputDir
        $handoff = New-NSPHandoff -Kind Response -Tool PKI -Company "$($Response.Company)" -Payload ([pscustomobject]$Response) `
            -PayloadSchema ([int]$Response.Schema) -ToolVersion "$($Response.CAManagerVersion)" -GeneratedBy "NSP.PKI $($Response.CAManagerVersion)"
        $handoffStem = [regex]::Replace("$($Response.Company)", '[^A-Za-z0-9_-]', ''); if (-not $handoffStem) { $handoffStem = 'Unknown' }
        $jsonPath = Join-Path $OutputDir "${handoffStem}_PKI_Response.json"   # Export-NSPHandoff's file name
        Invoke-CAStep -Description "Write $jsonPath" `
            -Commands @("Export-NSPHandoff -Handoff `$handoff -Directory '$OutputDir'") `
            -Action { $null = Export-NSPHandoff -Handoff $handoff -Directory $handoffDir } | Out-Null
        if (Test-Path $staleTxt) {
            Invoke-CAStep -Description "Remove $staleTxt (old CLI file - CLIBuilder renders the CA/peer CLI now)" `
                -Commands @("Remove-Item '$staleTxt'") `
                -Action { Remove-Item -Path $staleTxt -Force } | Out-Null
        }
        return [pscustomobject]@{ JsonPath = $jsonPath }
    }

    Invoke-CAStep -Description "Write $jsonPath" `
        -Commands @("`$Response | ConvertTo-Json -Depth 6 | Set-Content '$jsonPath'") `
        -Action {
            if (-not (Test-Path $OutputDir)) { New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null }
            $json = [pscustomobject]$Response | ConvertTo-Json -Depth 6
            $json = ($json -replace "`r`n", "`n") -replace "`n", "`r`n"
            Set-Content -Path $jsonPath -Value $json -Encoding UTF8
        } | Out-Null

    if (Test-Path $staleTxt) {
        Invoke-CAStep -Description "Remove $staleTxt (old CLI file - CLIBuilder renders the CA/peer CLI now)" `
            -Commands @("Remove-Item '$staleTxt'") `
            -Action { Remove-Item -Path $staleTxt -Force } | Out-Null
    }

    [pscustomobject]@{ JsonPath = $jsonPath }
}

# ---------------------------------------------------------------------------
function Invoke-CAMenuHandoff {
    <#
    .SYNOPSIS
        Menu 13. Builds the <Company>_CAResponse.json hand-back the MasterOrchestrator ingests: the CA
        cert + chain, names, peer plan, URLs, and the FortiGate identity cert - reused from the last
        hand-back in the output folder when the tech accepts, otherwise generated / CSR-signed / imported.
        Run it after menus 1-9 are green; re-run it freely (2026-09-30).
    #>
    param(
        $CAAnswers,
        [Parameter(Mandatory)]$Status,
        [string]$CAManagerVersion
    )
    Write-CAHeader "Hand back to the Orchestrator (CA data + FortiGate cert)"
    if (-not $CAAnswers) { $CAAnswers = [pscustomobject]@{} }

    if (-not $Status.CACommonName) {
        Write-Host "  No local CA detected - run menu 13 on the CA box." -ForegroundColor Yellow
        Read-Host "`nPress Enter to return to the menu" | Out-Null; return
    }
    if (-not $Status.IssuanceReady) {
        Write-Host "  Issuance readiness is NOT READY - the FortiGate cert would bake in the wrong" -ForegroundColor Yellow
        Write-Host "  AIA/CDP/OCSP URLs. Finish menus 1-7 first." -ForegroundColor Yellow
        if ((Read-Host "  Type YES to continue anyway") -cne 'YES') { Read-Host "`nPress Enter" | Out-Null; return }
    }

    $sanitized = try { Get-CAActiveConfigName } catch { $Status.CACommonName }
    $company   = $CAAnswers.Company_Name
    if ([string]::IsNullOrWhiteSpace($company)) {
        # 2026-09-15, per the maintainer: "can we add a 'back'/'main menu' option here? and anywhere else
        # we've missed it" - this is the wizard's own very first prompt (only reached when
        # Company_Name isn't already known/staged), so there's nothing earlier to step back to
        # WITHIN the wizard - -AllowBack here means "cancel out of menu 13 entirely."
        $company = Read-CANonEmpty -Prompt "Company name (for the file names)" -AllowBack
        if (Test-CABackSignal $company) { Write-Host "  Cancelled." -ForegroundColor Gray; return }
    }
    # write it back so Get-CAResponseObject / the file names use it, not the CA common name
    if ("$($CAAnswers.Company_Name)" -ne "$company") {
        $CAAnswers | Add-Member -NotePropertyName Company_Name -NotePropertyValue $company -Force
    }
    $companyStem = ($company -replace '[^A-Za-z0-9]', '')

    $issuingModel = if ($CAAnswers.CA_IssuingModel) { "$($CAAnswers.CA_IssuingModel)" } else { 'SharedCAWithSubjectFilter' }
    # 2026-09-15: resolved early (same reasoning as $issuingModel itself) so the PeerName step below
    # can suggest the peer GROUP name, not a single peer, when TameMyCerts + RadiusGroupPairs are
    # both in play - see Get-CAFortiGatePeerPlan's own header for the full reasoning.
    $peerPlanPreview = Get-CAFortiGatePeerPlan -CAAnswers $CAAnswers
    if ($peerPlanPreview.Applicable) {
        Write-Host "  TameMyCerts per-group mode - will generate $($peerPlanPreview.Peers.Count) 'config user peer' object(s)" -ForegroundColor Gray
        Write-Host "  bundled into peer group '$($peerPlanPreview.PeerGroupName)' (one per qualifying RADIUS group pair)." -ForegroundColor Gray
    } elseif ($issuingModel -ne 'SharedCAWithSubjectFilter') {
        Write-Host "  Dedicated issuing CA - no 'set subject' filter (every cert from this CA is a VPN cert)." -ForegroundColor Gray
    }

    # Back-navigation (2026-09-10, Part A item 3 - see Invoke-CAWizardSteps, CAInteractive.ps1): this
    # run of prompts is a clean, undo-able SEQUENCE with no mutating action interleaved between them -
    # nothing touches the FortiGate identity cert until after every answer below is collected - so
    # it's one of the two wizards the plan named for the first back-nav rollout. Company (above) is
    # resolved eagerly, outside this array, purely so $companyStem is a fixed value the later steps'
    # prompt text can safely reference (a plain scriptblock literal already closes over THIS
    # function's own local variables lazily by reference - no need for anything more than that).
    #
    # 2026-09-15, real live bug at a client: each step below used to end in `.GetNewClosure()`.
    # GetNewClosure() detaches a scriptblock into its OWN private session state that only chains up
    # to GLOBAL scope (plus its captured variable snapshot) - it does NOT chain up through an
    # intermediate SCRIPT scope the way a plain scriptblock does. That's invisible when CA-Manager.ps1
    # is dot-sourced or run directly, but the real shim (CA-Manager-Shim.ps1) launches the staged
    # dashboard via the CALL operator (`& $RealDashboard`, MiscTools\CA-Manager-Shim.ps1) - a genuine
    # extra scope boundary - and under that real invocation path, every GetNewClosure()'d step here
    # threw "Get-CAAnswerOrPrompt is not recognized" (a function from a DIFFERENT dot-sourced module,
    # CAInteractive.ps1, called from within the closure) even though Invoke-CAWizardSteps itself
    # (defined in that SAME file, called normally - no GetNewClosure()) resolved fine. Reproduced and
    # confirmed under real Windows PowerShell 5.1 with a 3-file repro matching this exact shape
    # (dot-sourced modules + `&`-wrapped entry script); removing GetNewClosure() fixed it in the same
    # repro. Every step below is a plain scriptblock now - none of them needed the "snapshot a
    # variable at definition time, immune to later mutation" behavior GetNewClosure() actually exists
    # for; they just needed to read THIS function's stable local variables at invocation time, which a
    # plain scriptblock already does correctly regardless of how the dashboard was launched.
    $steps = @(
        @{ Name = 'CertName'; Run = {
            param($CanGoBack)
            Get-CAAnswerOrPrompt -CAAnswers $CAAnswers -Field 'Cert_CertificateName' -Prompt "FortiGate local certificate name (must match the CLIBuilder output)" -Remember -AllowBack:$CanGoBack
        } }
        @{ Name = 'PeerName'; Run = {
            param($CanGoBack)
            if ($peerPlanPreview.Applicable) {
                Get-CAAnswerOrPrompt -CAAnswers $CAAnswers -Field 'Cert_PeerName' `
                    -Prompt "FortiGate PEER GROUP name (bundles the $($peerPlanPreview.Peers.Count) per-group peers below - must match the CLIBuilder output) [$($peerPlanPreview.PeerGroupName)]" `
                    -Default $peerPlanPreview.PeerGroupName -Remember -AllowBack:$CanGoBack
            } else {
                Get-CAAnswerOrPrompt -CAAnswers $CAAnswers -Field 'Cert_PeerName' -Prompt "FortiGate user peer object name (must match the CLIBuilder output)" -Remember -AllowBack:$CanGoBack
            }
        } }
        @{ Name = 'PeerFilter'; Run = {
            param($CanGoBack)
            if ($issuingModel -ne 'SharedCAWithSubjectFilter') { return '' }
            # 2026-09-30: the staged answers already carry the filter (blank is a real answer - "accept
            # any cert from this CA"), so it's only asked when the field isn't there at all.
            if ($CAAnswers.PSObject.Properties['Cert_PeerSubjectFilter']) { return "$($CAAnswers.Cert_PeerSubjectFilter)" }
            Read-CAOptional -Prompt "  FortiGate 'set subject' filter (shared CA) - blank to accept any cert from this CA" -AllowBack:$CanGoBack
        } }
        @{ Name = 'OutDir'; Run = {
            param($CanGoBack)
            # NSP.PKI: defaults to the PKI work folder's Responses\ (Administrators and SYSTEM only).
            $defaultOut = if (Get-Command Get-NSPToolWorkPath -ErrorAction SilentlyContinue) { Get-NSPToolWorkPath -Tool PKI -Kind Responses } else { "C:\Admin\Handoff\$companyStem" }
            $r = Read-CAOptional -Prompt "  Output directory for the hand-back [$defaultOut]" -AllowBack:$CanGoBack
            if ((Test-CABackSignal $r) -or -not [string]::IsNullOrWhiteSpace($r)) { $r } else { $defaultOut }
        } }
    )
    $wiz = Invoke-CAWizardSteps -Steps $steps
    $peerFilter = $wiz.PeerFilter
    $outDir     = $wiz.OutDir

    $fgTemplate = if (-not [string]::IsNullOrWhiteSpace($CAAnswers.CA_TemplateFortiGate)) { "$($CAAnswers.CA_TemplateFortiGate)" } else { 'FortiGate' }
    if (Get-Command Resolve-VPNCertTemplateName -ErrorAction SilentlyContinue) { $fgTemplate = Resolve-VPNCertTemplateName -Name $fgTemplate }

    # --- FortiGate identity cert: reuse the one from the last hand-back, or make a new one ----------
    # 2026-09-30, per the maintainer: re-running 13 must not force a new FortiGate cert. Warn-and-continue on
    # a CN mismatch / expiry / revocation - the tech decides.
    $fg = $null
    $fgPfxBase64 = $null
    $previous = Get-CAHandoffIdentity -OutputDir $outDir -CompanyStem $companyStem
    if ($previous) {
        $revoked = if ($previous.SerialNumber) { Test-CAHandoffCertRevoked -SerialNumber $previous.SerialNumber } else { $null }
        $warnings = @(Get-CAHandoffIdentityWarnings -Identity $previous -CertName "$($CAAnswers.Cert_CertificateName)" -Revoked ([bool]$revoked))
        Write-Host ""
        Write-Host "  FortiGate identity certificate from the last hand-back:" -ForegroundColor Cyan
        Write-Host ("    {0}   thumbprint {1}   expires {2:yyyy-MM-dd}   ({3})" -f $previous.Subject, $previous.Thumbprint, $previous.NotAfter, $(if ($previous.Kind -eq 'PFX') { 'PFX' } else { 'signed from a FortiGate CSR' }))
        foreach ($w in $warnings) { Write-Host "    WARNING: $w" -ForegroundColor Yellow }
        $choice = ([string](Read-Host "  [Enter] Reuse it    [N] New certificate (CSR / issued cert / generate)")).Trim()
        if ($choice -notmatch '^(?i)n(ew)?$') {
            $fg = $previous
            $fgPfxBase64 = $previous.PfxBase64
            Write-Host "  Reusing it - no request or approval needed." -ForegroundColor Green
        }
    }

    if (-not $fg) {
        Write-Host ""
        Write-Host "  FortiGate identity cert - give ONE of:" -ForegroundColor Cyan
        Write-Host "    - a CSR generated on the FortiGate (.csr / .req)  -> submitted here, key stays on" -ForegroundColor Gray
        Write-Host "      the gate; required for a machine-type / admin-only template." -ForegroundColor Gray
        Write-Host "      FortiGate:  config vpn certificate local / edit <name> / (generate) -> download the .csr" -ForegroundColor DarkGray
        Write-Host "    - an already-issued cert (.cer / .crt / .pem)     -> wrapped into the hand-back as-is" -ForegroundColor Gray
        Write-Host "    - blank                                           -> CA-Manager generates a keypair + PFX" -ForegroundColor Gray
        $inPath = ([string](Read-CAOptional -Prompt "  Path (blank = generate a PFX)")).Trim('"', ' ')

        if ([string]::IsNullOrWhiteSpace($inPath)) {
            # The SAN FQDN only matters for a cert generated here, so it's only asked on this path.
            $fgFqdn = Read-CAOptional -Prompt "  FortiGate FQDN for the cert SAN (optional, e.g. vpn.$companyStem.com)"
            $fg = New-CAFortiGateIdentityCert -CAAnswers $CAAnswers -OutputDir $outDir -CASanitizedName $sanitized -FortiGateFqdn $fgFqdn
        } elseif (Test-Path $inPath) {
            # CSR markers win; otherwise anything that parses as a cert (DER or PEM) is an issued cert.
            if (-not (Test-CAIsCsr -Path $inPath) -and (Read-CAX509 -Path $inPath)) {
                $fg = Import-CAFortiGateIssuedCert -CertPath $inPath -OutputDir $outDir -FileStem "${companyStem}_FortiGate"
            } else {
                $caFqdnLocal = try { [System.Net.Dns]::GetHostEntry($env:COMPUTERNAME).HostName } catch { $env:COMPUTERNAME }
                $caConfigDefault = "$caFqdnLocal\$($Status.CACommonName)"
                $caConfigForCsr = Read-Host "  CA config to submit to (`"<server-fqdn>\<CA name>`") [$caConfigDefault]"
                if ([string]::IsNullOrWhiteSpace($caConfigForCsr)) { $caConfigForCsr = $caConfigDefault }
                $fg = New-CAFortiGateCertFromCsr -CsrPath $inPath -Template $fgTemplate -OutputDir $outDir -FileStem "${companyStem}_FortiGate" -CAConfig $caConfigForCsr
            }
        } else {
            Write-Host "  Path not found: $inPath" -ForegroundColor Red
            Read-Host "`nPress Enter to return to the menu" | Out-Null; return
        }

        # Embed the PFX bytes (base64) in the JSON when one was generated, so the JSON alone travels.
        if ($fg -and $fg.PSObject.Properties['PfxPath'] -and $fg.PfxPath -and (Test-Path $fg.PfxPath)) {
            try {
                $fgPfxBase64 = [Convert]::ToBase64String([System.IO.File]::ReadAllBytes($fg.PfxPath))
            } catch {
                Write-Host "  WARNING: could not read the PFX to embed it in the hand-back JSON ($($_.Exception.Message)) - the loose .pfx file is still required." -ForegroundColor Yellow
            }
        }
    }

    $caCertPem = $null
    $caCertChain = @()
    $der = Get-CAOcspCACertBytes -CACommonName $Status.CACommonName
    if ($der) {
        $caCertPem = ConvertTo-CAPem -DerBytes $der -Label 'CERTIFICATE'
        # 2026-09-15, per the maintainer: "capture the whole chain... if it's subordinate, get the parent CA
        # cert too, make sure it's the latest cert." "Latest" is Get-CAOcspCACertBytes's own job
        # (already Sort-Object NotAfter -Descending against this CN) - reuse THAT resolved cert as the
        # chain-walk's starting point rather than re-deriving "latest" a second time.
        try {
            $issuingCert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new([byte[]]$der)
            $caCertChain = @(Get-CAFortiGateParentCertChain -IssuingCert $issuingCert)
            if ($caCertChain.Count) {
                Write-Host "  Subordinate CA - capturing $($caCertChain.Count) parent cert(s) too: $(($caCertChain | ForEach-Object { $_.Name }) -join ', ')" -ForegroundColor Gray
            }
        } catch {
            Write-Host "  WARNING: could not walk the CA chain ($($_.Exception.Message)) - only the issuing CA's own cert will be in the hand-back." -ForegroundColor Yellow
        }
    } else {
        Write-Host "  WARNING: could not read the CA cert - CACertPem left empty in the hand-back." -ForegroundColor Yellow
    }

    $caConfig = try { "$((Get-CAActiveConfigName))" } catch { $null }

    $resp = Get-CAResponseObject -CAAnswers $CAAnswers -CACommonName $Status.CACommonName `
        -CAConfigString $caConfig -CASanitizedName $sanitized -CACertPem $caCertPem -CACertChain $caCertChain `
        -FgCert $fg -PeerSubjectFilter $peerFilter -CAManagerVersion $CAManagerVersion -FortiGatePfxBase64 $fgPfxBase64

    $written = Write-CAHandoffFiles -Response $resp -OutputDir $outDir

    Write-Host ""
    Write-Host "  Hand-back:" -ForegroundColor Green
    Write-Host "    $($written.JsonPath)   <- copy this ONE file back (the PFX, if any, is embedded in it)" -ForegroundColor Green
    if ($fg -and $fg.PfxPath) { Write-Host "    $($fg.PfxPath)   (same PFX, loose copy; its password is in the JSON)" -ForegroundColor Gray }
    elseif ($fg -and $fg.PSObject.Properties['CertPath'] -and $fg.CertPath) { Write-Host "    $($fg.CertPath)   (signed cert; the gate keeps its own key)" -ForegroundColor Gray }
    Write-Host ""
    Write-Host "  Next: copy the JSON into the client's Staging\<Abbrev>\Inbox\ folder on the build box, then re-run" -ForegroundColor Cyan   # NSP.PKI: Inbox
    Write-Host "  IPSec-MasterOrchestrator.ps1 Step 5. CLIBuilder renders the FortiGate CA/peer CLI from it." -ForegroundColor Cyan
    Write-Host "  Re-run this menu any time: it offers to reuse the FortiGate cert above." -ForegroundColor Cyan
    # NSP.PKI: open the folder for the tech to copy the file from (nothing is written on a dry run).
    if ($written.JsonPath -and (Test-Path -LiteralPath $written.JsonPath) -and (Get-Command Open-NSPOutputFolder -ErrorAction SilentlyContinue)) {
        Write-Host "  Opening the folder in Explorer (accept the access prompt if one appears)." -ForegroundColor Gray
        Open-NSPOutputFolder -Path $written.JsonPath
    }
    Read-Host "`nPress Enter to return to the menu" | Out-Null
}
