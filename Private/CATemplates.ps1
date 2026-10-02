<#
.SYNOPSIS
    CA Manager - certificate templates + auto-enrollment umbrella group (dashboard menu options 1
    and 2). Requires Modules\CACore.ps1 (and, for the umbrella wizard, the ActiveDirectory module).

.DESCRIPTION
    Get-CAVpnTemplateSpec is PURE DATA - the four custom templates transcribed attribute-for-attribute
    from a real client's live CA (see Examples_Sources\ for the captured inventory). Every msPKI-* flag value here is a
    captured fact, not an assumption.

    ConvertTo-CAPkiPeriodBytes is the pure validity/overlap -> FILETIME byte[8] helper.

    Show-CATemplatePlan renders what would be created/published.

    Resolve-CAUmbrellaGroup is the "prompt for an existing master group, else create it and nest the
    VPN user groups" wizard (menu 5). AD group ops only - safe and stable.

    New-CAVpnTemplate / Publish-CATemplateToCA / Grant-CATemplateEnrollment are the CREATE mechanism.
    They are DELIBERATELY not implemented against a live directory yet - the exact route (raw LDAP
    under CN=Certificate Templates,..., vs PSPKI, vs an ldifde/certutil approach, plus OID allocation)
    is the one piece worth pinning down against a real fresh CA before committing code to it. The
    spec they'd consume (Get-CAVpnTemplateSpec) is ready; only the plumbing is pending.
#>

# ---------------------------------------------------------------------------
function ConvertTo-CAPkiPeriodBytes {
    <#
    .SYNOPSIS
        Converts a validity/overlap duration to the pKIExpirationPeriod / pKIOverlapPeriod form:
        an 8-byte little-endian NEGATIVE 100-nanosecond FILETIME interval.
    .PARAMETER Days
        Duration in days (365 = "1 year", 42 = "6 weeks", 14, 2, ...).
    #>
    param([Parameter(Mandatory)][int]$Days)
    # 1 day = 24*3600 seconds * 1e7 (100-ns units) = 864000000000
    $ticks = [int64]([int64]$Days * -864000000000)
    return [byte[]][System.BitConverter]::GetBytes($ticks)
}

# ---------------------------------------------------------------------------
function Get-CAVpnTemplateSpec {
    <#
    .SYNOPSIS
        The four custom templates, exactly as captured from a real client. Returns an array of specs; each:
          Key, DisplayName, SchemaVersion, MinimalKeySize, KeySpec, EkuOids[], KeyUsageHex,
          CertificateNameFlagHex, EnrollmentFlagHex, PrivateKeyFlagHex, ValidityDays, OverlapDays,
          MachineType (bool -> CT_FLAG_MACHINE_TYPE in `flags`),
          RaApplicationPoliciesRaw (v3+ CNG-params string for msPKI-RA-Application-Policies, or $null),
          EnrollPrincipals[]   ('Umbrella' / 'DomainAndEnterpriseAdmins' / 'OcspResponderHost'),
          AutoEnrollPrincipals[], Notes
        DisplayName defaults come from the CA_Template* answer fields; a client prefix (e.g. some clients'
        own short abbreviation) is the tech's choice at create time.
    #>
    param(
        # 2026-09-15, per the maintainer: the shared default used to be "IKEv2VPN-CorpLAN"/"-MANUAL" - lifted
        # straight from a real client's own setup, not a generic starting point. "InternalUsers" is this
        # codebase's own established generic name for the primary IKEv2 VPN AD group (AD-Manager's own
        # scaffold creates "IKEv2_InternalUsers" - project_ad_manager.md) - only the DISPLAY NAME
        # changed here; every captured flag/schema value below is still verbatim from that client's real
        # templates, unaffected by this rename.
        [string]$AutoName      = 'IKEv2VPN-InternalUsers',
        [string]$ManualName    = 'IKEv2VPN-InternalUsers-MANUAL',
        [string]$FortiGateName = 'FortiGate',
        # NOT "OCSPResponseSigning" - that collides with the built-in v3 template. A distinct name
        # lets us create one WITH the ocsp-nocheck + no-SID-extension enrollment flags.
        [string]$OcspName      = 'NSP-OCSPResponseSigning',
        # SharedCAWithSubjectFilter (default) | DedicatedIssuingCA. Only affects the Auto template's
        # subject-name flags - see $autoNameFlag below.
        [string]$IssuingModel  = 'SharedCAWithSubjectFilter'
    )

    # Auto template subject-name flags.
    #   Dedicated CA: reference-client-verbatim 0xA6000000 = DIRECTORY_PATH + REQUIRE_EMAIL + ALT_REQUIRE_EMAIL
    #                 + ALT_REQUIRE_UPN. Every cert from a dedicated issuing CA is a VPN cert, so the
    #                 FortiGate peer needs no subject filter - shape doesn't matter for routing.
    #   Shared CA:   0x82000000 = DIRECTORY_PATH (0x80000000) + ALT_REQUIRE_UPN (0x02000000). The
    #                 cert's Subject DN becomes the enrollee's full LDAP path, so if VPN users are
    #                 parked under one OU subtree the FortiGate `config user peer` can gate on
    #                 `set subject "OU=<that OU>"` (substring). REQUIRE_EMAIL is dropped - a mail-less
    #                 account would otherwise fail enrollment - and the UPN stays in the SAN for the
    #                 EAP identity. This is the "OU in the subject" trick (the maintainer, 2026-09-08).
    $autoNameFlag = if ($IssuingModel -eq 'DedicatedIssuingCA') { '0xA6000000' } else { '0x82000000' }

    # The user templates (Auto / Manual) and FortiGate are schema v2 - matches a real client's live
    # IKEv2VPN-CorpLAN / -MANUAL, which auto-enroll in production. DefaultCsps is left EMPTY so the
    # enrolling client picks a working provider itself (a v2 template pinned to a CNG *KSP* only ->
    # CRYPT_E_NO_PROVIDER on the legacy enrollment path). A v4 template is NOT raw-ADSI-authorable:
    # its msPKI-RA-Application-Policies blob must also carry co-sign policy OIDs, and a v4 template
    # missing that is rejected by the CA policy module (CERTSRV_E_UNSUPPORTED_CERT_TYPE).
    #
    # OcspSigning is the exception: it MUST be schema v3. The Online Responder's "add revocation
    # configuration" wizard filters candidate signing templates and rejects anything that (a) is
    # schema < 3 or (b) has msPKI-RA-Application-Policies unset - a v2 or a bare-v3 template fails
    # enrollment with 0x80070490 "a template ... could not be retrieved". On a v3 template that attr
    # holds only CNG key parameters (algorithm / hash / key-protection SD / key-usage), NOT co-sign
    # OIDs, so raw ADSI CAN write it - it's a plain unicode string. RaApplicationPoliciesRaw below is
    # transcribed verbatim from the box's built-in OCSPResponseSigning (v3) template; the SD grants
    # the Online Responder service read on the signing key. MachineType ORs CT_FLAG_MACHINE_TYPE
    # (0x40) into `flags` - OCSP signers enroll as the computer account, and the wizard checks it.
    @(
        [pscustomobject]@{
            Key = 'Auto'; DisplayName = $AutoName
            SchemaVersion = 2; MinimalKeySize = 2048; KeySpec = 1; DefaultCsps = @()
            RaApplicationPoliciesRaw = $null; MachineType = $false
            EkuOids = @('1.3.6.1.5.5.7.3.2')                        # Client Authentication
            KeyUsageHex = '0xA000'                                  # digitalSignature + keyEncipherment
            CertificateNameFlagHex = $autoNameFlag                  # issuing-model-aware - see $autoNameFlag note above
            EnrollmentFlagHex = '0x00000029'                        # INCLUDE_SYMMETRIC + PUBLISH_TO_DS + AUTO_ENROLLMENT
            PrivateKeyFlagHex = '0x06060000'                        # non-exportable (captured verbatim)
            ValidityDays = 365; OverlapDays = 42
            EnrollPrincipals = @('Umbrella'); AutoEnrollPrincipals = @('Umbrella')
            Notes = 'Auto-enrolled user VPN cert. Only the umbrella group gets Enroll+AutoEnroll.'
        }
        [pscustomobject]@{
            Key = 'Manual'; DisplayName = $ManualName
            SchemaVersion = 2; MinimalKeySize = 2048; KeySpec = 1; DefaultCsps = @()
            RaApplicationPoliciesRaw = $null; MachineType = $false
            EkuOids = @('1.3.6.1.5.5.7.3.2')
            KeyUsageHex = '0xA000'
            CertificateNameFlagHex = '0x00000001'                   # ENROLLEE_SUPPLIES_SUBJECT
            EnrollmentFlagHex = '0x0000000B'                        # INCLUDE_SYMMETRIC + PEND_ALL_REQUESTS + PUBLISH_TO_DS
            PrivateKeyFlagHex = '0x01010010'                        # EXPORTABLE_KEY (captured verbatim)
            ValidityDays = 365; OverlapDays = 42
            EnrollPrincipals = @('DomainAndEnterpriseAdmins'); AutoEnrollPrincipals = @()
            Notes = 'Admin-approved, exportable. Request-VPNCert.ps1 / the test-cert suite use this.'
        }
        [pscustomobject]@{
            Key = 'FortiGate'; DisplayName = $FortiGateName
            SchemaVersion = 2; MinimalKeySize = 2048; KeySpec = 1; DefaultCsps = @()
            RaApplicationPoliciesRaw = $null; MachineType = $false
            EkuOids = @('1.3.6.1.5.5.7.3.1')                        # Server Authentication
            KeyUsageHex = '0xA000'
            CertificateNameFlagHex = '0x00000001'                   # ENROLLEE_SUPPLIES_SUBJECT (menu 13 supplies CN=<Cert_CertificateName>)
            EnrollmentFlagHex = '0x0000000A'                        # PEND_ALL_REQUESTS + PUBLISH_TO_DS (admin-approved)
            PrivateKeyFlagHex = '0x06060110'                        # + EXPORTABLE_KEY (0x10) - menu 13 generates the key CA-side and hands the FortiGate a PFX
            ValidityDays = 730; OverlapDays = 42
            EnrollPrincipals = @('DomainAndEnterpriseAdmins'); AutoEnrollPrincipals = @()
            Notes = 'The FortiGate''s own identity cert (Cert_CertificateName). CA-Manager menu 13 generates the keypair, gets it issued (admin-approved), and exports a PFX for the gate.'
        }
        [pscustomobject]@{
            Key = 'OcspSigning'; DisplayName = $OcspName
            SchemaVersion = 3; MinimalKeySize = 2048; KeySpec = 2; DefaultCsps = @()   # v3 required - see the comment above; v2/bare-v3 -> wizard 0x80070490
            EkuOids = @('1.3.6.1.5.5.7.3.9')                        # OCSP Signing
            KeyUsageHex = '0x8000'                                  # digitalSignature only
            CertificateNameFlagHex = '0x18000000'                   # DNS name from AD
            EnrollmentFlagHex = '0x00005020'                        # AUTO_ENROLLMENT + ADD_OCSP_NOCHECK + NO_SECURITY_EXTENSION
            PrivateKeyFlagHex = '0x06060000'
            MachineType = $true                                     # -> CT_FLAG_MACHINE_TYPE (0x40) in `flags`; responder enrolls as the computer account
            # Verbatim from the built-in OCSPResponseSigning (v3). Backtick-delimited; the SD grants
            # the Online Responder service GENERIC_READ on the signing key. Without this the OCSP
            # "add revocation configuration" wizard reports 0x80070490 "template could not be retrieved".
            RaApplicationPoliciesRaw = 'msPKI-Asymmetric-Algorithm`PZPWSTR`RSA`msPKI-Hash-Algorithm`PZPWSTR`SHA1`msPKI-Key-Security-Descriptor`PZPWSTR`D:P(A;;FA;;;BA)(A;;FA;;;SY)(A;;GR;;;S-1-5-80-3804348527-3718992918-2141599610-3686422417-2726379419)`msPKI-Key-Usage`DWORD`2`'
            ValidityDays = 14; OverlapDays = 2
            EnrollPrincipals = @('OcspResponderHost'); AutoEnrollPrincipals = @('OcspResponderHost')
            Notes = 'Short-lived, auto-renewed by the Online Responder. Enroll goes to the responder box''s own group/account.'
        }
    )
}

# ---------------------------------------------------------------------------
function Get-CAAdHocTemplatePurposes {
    <#
    .SYNOPSIS
        PURE. The purpose/EKU catalog the ad-hoc template wizard (menu 16, Invoke-CAMenuAdHocTemplate)
        offers - a lookup TABLE, deliberately, not a hardcoded single path. The maintainer, 2026-09-10: "we
        don't need the moon at this point, but the moon should fit in this room" - only the VPN/
        Client-Authentication case is wired up today (the one CA-Manager actually needs), but adding a
        second purpose later (web server, code signing, whatever comes up) is just a new entry here,
        not a rewrite of the wizard itself.
    #>
    @(
        [pscustomobject]@{
            Key         = 'VpnClientAuth'
            Label       = 'VPN / Client Authentication'
            EkuOids     = @('1.3.6.1.5.5.7.3.2')   # Client Authentication
            KeyUsageHex = '0xA000'                  # digitalSignature + keyEncipherment
        }
    )
}

# ---------------------------------------------------------------------------
function Get-CAAdHocTemplateSpec {
    <#
    .SYNOPSIS
        PURE. Builds a single Get-CAVpnTemplateSpec-shaped object for the ad-hoc template wizard -
        outside the RadiusGroupPairs-driven flow entirely (New-CAVpnTemplate/Grant-CATemplateEnrollment
        don't care which caller built the spec, so this reuses both unchanged). Admin-approved
        (ENROLLEE_SUPPLIES_SUBJECT + PEND_ALL_REQUESTS), schema v2, same crypto baseline as the
        Auto/Manual/FortiGate templates - the exact captured PrivateKeyFlagHex values from those (not
        an invented bitwise combination) depending on -ExportableKey.
    #>
    param(
        [Parameter(Mandatory)][string]$DisplayName,
        [Parameter(Mandatory)][string]$PurposeKey,
        [int]$ValidityDays = 365,
        [int]$OverlapDays = 42,
        [switch]$ExportableKey
    )
    $purpose = @(Get-CAAdHocTemplatePurposes) | Where-Object { $_.Key -eq $PurposeKey }
    if (-not $purpose) {
        throw "Unknown ad-hoc template purpose '$PurposeKey' - see Get-CAAdHocTemplatePurposes for the valid keys."
    }

    [pscustomobject]@{
        Key = 'AdHoc'; DisplayName = $DisplayName
        SchemaVersion = 2; MinimalKeySize = 2048; KeySpec = 1; DefaultCsps = @()
        RaApplicationPoliciesRaw = $null; MachineType = $false
        EkuOids = $purpose.EkuOids
        KeyUsageHex = $purpose.KeyUsageHex
        CertificateNameFlagHex = '0x00000001'                   # ENROLLEE_SUPPLIES_SUBJECT
        EnrollmentFlagHex = '0x0000000B'                        # INCLUDE_SYMMETRIC + PEND_ALL_REQUESTS + PUBLISH_TO_DS (admin-approved, same as Manual)
        PrivateKeyFlagHex = if ($ExportableKey) { '0x01010010' } else { '0x06060000' }   # exact captured Manual/Auto values, not an invented combination
        ValidityDays = $ValidityDays; OverlapDays = $OverlapDays
        EnrollPrincipals = @(); AutoEnrollPrincipals = @()   # the wizard grants Enroll itself, directly by name - no token indirection needed for a single one-off template
        Notes = "Ad-hoc $($purpose.Label) template, created outside the RadiusGroupPairs flow (menu 16)."
    }
}

# ---------------------------------------------------------------------------
function Get-CATemplateSpecForAnswers {
    <#
    .SYNOPSIS
        Resolves the 4 template DisplayNames from a CAAnswers object (falling back to the
        Get-CAVpnTemplateSpec defaults) and returns the spec array. Guards the OCSP name against the
        built-in 'OCSPResponseSigning' collision - a blank OR literal-'OCSPResponseSigning' answer is
        forced to the safe default.
    #>
    param($CAAnswers)
    $ov = @{}
    if ($CAAnswers.CA_TemplateAuto)      { $ov.AutoName      = $CAAnswers.CA_TemplateAuto }
    if ($CAAnswers.CA_TemplateManual)    { $ov.ManualName    = $CAAnswers.CA_TemplateManual }
    if ($CAAnswers.CA_TemplateFortiGate) { $ov.FortiGateName = $CAAnswers.CA_TemplateFortiGate }
    if ($CAAnswers.CA_IssuingModel -in @('SharedCAWithSubjectFilter', 'DedicatedIssuingCA')) {
        $ov.IssuingModel = $CAAnswers.CA_IssuingModel
    }
    $ocsp = $CAAnswers.CA_TemplateOcspSigning
    if ($ocsp -and $ocsp -ne 'OCSPResponseSigning') {
        $ov.OcspName = $ocsp
    } elseif ($ocsp -eq 'OCSPResponseSigning') {
        Write-Host "  note: CA_TemplateOcspSigning is 'OCSPResponseSigning', which collides with the built-in" -ForegroundColor DarkYellow
        Write-Host "        template - using 'NSP-OCSPResponseSigning' instead. (Fix CAAnswers.json to silence this.)" -ForegroundColor DarkYellow
    }

    $base = @(Get-CAVpnTemplateSpec @ov)

    # TameMyCerts subject-stamp model: swap the single shared Auto template for one Auto template per
    # RADIUS group pair, each ACL'd (Enroll+AutoEnroll) to just that group and each with a CN-only
    # subject (TameMyCerts menu 3 stamps OU=<group> on top - the user's real AD OU path never goes on
    # the wire). The base Auto is dropped so a user doesn't auto-enroll two VPN certs.
    #
    # 2026-09-15, per the maintainer (live, looking at a client's own menu 4 pick-list - "can we drop the
    # 'manual' one from CLIBuilder?... since we're autocreating manual ones anyway"): the single
    # shared Manual template is now ALSO redundant in this mode, the same way Auto already was -
    # every per-group Auto template gets its own dedicated -MANUAL counterpart on request
    # (Get-CAPerGroupManualTemplateSpec, the "Also add manual version(s)" opt-in prompt), so having
    # the CN-only per-group Manual templates AND one extra shared, non-scoped Manual template was
    # just noise on the pick-list, not a real additional capability. Dropped alongside Auto - Manual
    # stays in the base spec for a NON-TameMyCerts (shared-CA-with-subject-filter/dedicated) client,
    # where there IS no per-group alternative.
    $perGroup = @(Get-CAPerGroupTemplateSpecs -CAAnswers $CAAnswers)
    if ($perGroup.Count) {
        return @(@($base | Where-Object { $_.Key -notin @('Auto', 'Manual') }) + $perGroup)
    }
    return $base
}

function Get-CAPerGroupTemplateSpecs {
    <#
    .SYNOPSIS
        PURE. When CA_SubjectStampMode = 'TameMyCerts' and RadiusGroupPairs is populated, returns one
        Auto-template spec per group pair: schema v2, same crypto as the base Auto spec, DisplayName
        '<CA_TameMyCertsTemplatePrefix><sanitised label>' (CN = that with non-alphanumerics stripped,
        matching New-CAVpnTemplate), CN-only subject-name flag (0x42000000 = SUBJECT_REQUIRE_COMMON_NAME
        + SUBJECT_ALT_REQUIRE_UPN), and Enroll+AutoEnroll granted to the pair's own AD group
        (EnrollPrincipals = @('GroupSpecific'), GroupName carrying the DOMAIN\group). Empty array when
        the mode isn't TameMyCerts or there are no pairs.
    .NOTES
        The CN this produces MUST equal what CATameMyCerts.ps1 Get-CATameMyCertsPlan derives for the
        policy-file name - both strip non-alphanumerics from '<prefix><token>'.
    #>
    param($CAAnswers)

    $mode = if ($CAAnswers -and -not [string]::IsNullOrWhiteSpace($CAAnswers.CA_SubjectStampMode)) { "$($CAAnswers.CA_SubjectStampMode)".Trim() } else { 'None' }
    if ($mode -ne 'TameMyCerts') { return @() }

    $pairs = @()
    if ($CAAnswers -and $CAAnswers.PSObject.Properties['RadiusGroupPairs'] -and $CAAnswers.RadiusGroupPairs) { $pairs = @($CAAnswers.RadiusGroupPairs) }
    if (-not $pairs.Count) { return @() }

    $prefix = if ($CAAnswers -and -not [string]::IsNullOrWhiteSpace($CAAnswers.CA_TameMyCertsTemplatePrefix)) { "$($CAAnswers.CA_TameMyCertsTemplatePrefix)" } else { 'NSP-IKEv2-' }

    $out = New-Object System.Collections.Generic.List[object]
    foreach ($p in $pairs) {
        $label = if ($p.PSObject.Properties['Label']) { "$($p.Label)" } else { '' }
        # UserGroupValue is the actual AD security group's real name (what NPS/RADIUS matches
        # membership against); UserGroupName is a friendlier label used elsewhere for firewall-rule
        # naming and is NOT reliably a real AD group - found live 2026-09-10 on a client's CA server,
        # Grant-CATemplateEnrollment failed to resolve 'IKEv2_UserGroup' (UserGroupName) to a SID
        # because the actual AD group is 'IKEv2_InternalUsers' (UserGroupValue).
        $grp = if ($p.PSObject.Properties['UserGroupValue'] -and -not [string]::IsNullOrWhiteSpace($p.UserGroupValue)) { "$($p.UserGroupValue)" }
               elseif ($p.PSObject.Properties['UserGroupName']) { "$($p.UserGroupName)" }
               else { '' }
        $token = (($(if ($label) { $label } else { $grp })) -replace '[^A-Za-z0-9._-]', '').Trim('._-')
        if ([string]::IsNullOrWhiteSpace($token)) { continue }
        $display = "$prefix$token"
        $out.Add([pscustomobject]@{
            Key = "Group_$token"; DisplayName = $display; GroupName = $grp
            SchemaVersion = 2; MinimalKeySize = 2048; KeySpec = 1; DefaultCsps = @()
            RaApplicationPoliciesRaw = $null; MachineType = $false
            EkuOids = @('1.3.6.1.5.5.7.3.2')                         # Client Authentication
            KeyUsageHex = '0xA000'                                   # digitalSignature + keyEncipherment
            CertificateNameFlagHex = '0x42000000'                    # SUBJECT_REQUIRE_COMMON_NAME + SUBJECT_ALT_REQUIRE_UPN - CN-only, TameMyCerts adds OU=<token>
            EnrollmentFlagHex = '0x00000029'                         # INCLUDE_SYMMETRIC + PUBLISH_TO_DS + AUTO_ENROLLMENT (same as base Auto)
            PrivateKeyFlagHex = '0x06060000'                         # non-exportable
            ValidityDays = 365; OverlapDays = 42
            EnrollPrincipals = @('GroupSpecific'); AutoEnrollPrincipals = @('GroupSpecific')
            Notes = "Per-group auto-enroll VPN cert. Enroll -> '$grp' (AutoEnroll is separate now - menu 15, the enrollment gate); TameMyCerts menu 3 stamps OU=$token."
        })
    }
    return $out.ToArray()   # NB: @($list) trips the PS7 binder ("Argument types do not match")
}

# ---------------------------------------------------------------------------
function Get-CAPerGroupManualTemplateSpec {
    <#
    .SYNOPSIS
        PURE. Given one per-group Auto template spec (one row from Get-CAPerGroupTemplateSpecs), builds
        its admin-approved, exportable MANUAL counterpart - same crypto/EKU baseline, DisplayName
        suffixed "-MANUAL" (mirrors the existing shared IKEv2VPN-CorpLAN / -MANUAL pairing, just
        per-group instead of once). 2026-09-15, per the maintainer: "for any 'template' we generate, we also
        need to allow a manual admin request against it" - lets a tech manually request/troubleshoot
        ONE specific group's VPN cert shape (e.g. testing a particular client's own subject/OU requirements) without
        only having the single generic shared Manual template to fall back on for every group.
    .PARAMETER GroupSpec
        One entry from Get-CAPerGroupTemplateSpecs (Key like 'Group_<token>').
    .NOTES
        2026-09-15, per the maintainer ("wire this in to TameMyCerts. Same flow."): IS wired into TameMyCerts's
        own per-group OU-stamping policy - Get-CATameMyCertsPlan (CATameMyCerts.ps1) emits a SECOND
        policy XML per RadiusGroupPair, named after THIS spec's own CN ("<Auto DisplayName>-MANUAL"),
        stamping the identical OU=<token> the Auto template gets. TameMyCerts's <OutboundSubject
        Force="true"> rewrite matches purely by requesting-template CN, independent of how the request
        was submitted - so a manually-approved cert from this template gets the same OU stamp an
        auto-enrolled one would, without needing this spec's own CertificateNameFlagHex to change.
        ENROLLEE_SUPPLIES_SUBJECT is kept (below) specifically so an admin can still supply whatever CN
        they need to troubleshoot with - TameMyCerts's Force=true rule overrides just the OU RDN on top
        of that, same as it does for the Auto template.
    #>
    param([Parameter(Mandatory)]$GroupSpec)
    if ("$($GroupSpec.Key)" -notlike 'Group_*') {
        throw "Get-CAPerGroupManualTemplateSpec expects a per-group Auto spec (Key like 'Group_*') - got '$($GroupSpec.Key)'."
    }
    [pscustomobject]@{
        Key = "$($GroupSpec.Key)_Manual"; DisplayName = "$($GroupSpec.DisplayName)-MANUAL"; GroupName = $GroupSpec.GroupName
        SchemaVersion = 2; MinimalKeySize = 2048; KeySpec = 1; DefaultCsps = @()
        RaApplicationPoliciesRaw = $null; MachineType = $false
        EkuOids = @('1.3.6.1.5.5.7.3.2')                        # Client Authentication - same as the per-group Auto template
        KeyUsageHex = '0xA000'
        CertificateNameFlagHex = '0x00000001'                   # ENROLLEE_SUPPLIES_SUBJECT - same as the shared Manual template
        EnrollmentFlagHex = '0x0000000B'                        # INCLUDE_SYMMETRIC + PEND_ALL_REQUESTS + PUBLISH_TO_DS (admin-approved)
        PrivateKeyFlagHex = '0x01010010'                        # EXPORTABLE_KEY - captured value, same as the shared Manual template
        ValidityDays = 365; OverlapDays = 42
        EnrollPrincipals = @('DomainAndEnterpriseAdmins'); AutoEnrollPrincipals = @()
        Notes = "Admin-approved, exportable manual counterpart to '$($GroupSpec.DisplayName)' - for one-off/troubleshooting requests against this specific group's cert shape (e.g. Request-VPNCert.ps1 -TemplateName '$($GroupSpec.DisplayName)-MANUAL'). TameMyCerts stamps the SAME OU as the Auto template (menu 3) - same flow, just admin-approved."
    }
}

# ---------------------------------------------------------------------------
function Show-CATemplatePlan {
    <#
    .SYNOPSIS
        Prints what Create/Update templates (menu 4) would do, for the dry-run walkthrough.
    .PARAMETER Numbered
        2026-09-15, per the maintainer: menu 4 used to be all-or-nothing ("create/publish the N template(s)
        now?"). Prefixes each entry with "[N]" (matching $spec's own array order 1:1) so the caller can
        show this SAME detailed rendering as a pick-list instead of a second, redundant plain-name
        list - see Invoke-CAMenuTemplates's own selection step.
    #>
    param($CAAnswers, [switch]$Numbered)

    $spec = Get-CATemplateSpecForAnswers -CAAnswers $CAAnswers

    $umbrella = if ($CAAnswers.CA_AutoEnrollGroup) { $CAAnswers.CA_AutoEnrollGroup } else { '<CA_AutoEnrollGroup - not set>' }

    for ($__i = 0; $__i -lt $spec.Count; $__i++) {
        $t = $spec[$__i]
        Write-Host ""
        $numberPrefix = if ($Numbered) { "[$($__i + 1)] " } else { "" }
        Write-Host ("  {0}Template: {1}   (schema v{2})" -f $numberPrefix, $t.DisplayName, $t.SchemaVersion) -ForegroundColor White
        Write-Host ("    key {0}-bit, KeySpec {1}   EKU {2}" -f $t.MinimalKeySize, $t.KeySpec, ($t.EkuOids -join ', ')) -ForegroundColor Gray
        Write-Host ("    KeyUsage {0}  Name-Flag {1}  Enrollment-Flag {2}  PrivateKey-Flag {3}" -f $t.KeyUsageHex, $t.CertificateNameFlagHex, $t.EnrollmentFlagHex, $t.PrivateKeyFlagHex) -ForegroundColor Gray
        Write-Host ("    validity {0}d / overlap {1}d" -f $t.ValidityDays, $t.OverlapDays) -ForegroundColor Gray
        $enroll = ($t.EnrollPrincipals | ForEach-Object { if ($_ -eq 'Umbrella') { $umbrella } elseif ($_ -eq 'DomainAndEnterpriseAdmins') { 'Domain Admins + Enterprise Admins' } elseif ($_ -eq 'OcspResponderHost') { 'OCSP responder host group' } elseif ($_ -eq 'GroupSpecific') { $t.GroupName } else { $_ } }) -join ', '
        $ae = if ($t.AutoEnrollPrincipals -contains 'Umbrella') { $umbrella } elseif ($t.AutoEnrollPrincipals -contains 'GroupSpecific') { $t.GroupName } elseif ($t.AutoEnrollPrincipals) { ($t.AutoEnrollPrincipals -join ', ') } else { '(none)' }
        Write-Host ("    Enroll -> {0}    AutoEnroll -> {1}" -f $enroll, $ae) -ForegroundColor Gray
        Write-Host ("    {0}" -f $t.Notes) -ForegroundColor DarkGray
    }
    Write-Host ""
    Write-Host "  Each would be created under CN=Certificate Templates,CN=Public Key Services,CN=Services,<configNC>" -ForegroundColor DarkGray
    Write-Host "  then published to the CA (certutil -SetCATemplates +<name>)." -ForegroundColor DarkGray
}

# ---------------------------------------------------------------------------
function Resolve-CAUmbrellaGroup {
    <#
    .SYNOPSIS
        Menu 5 (2026-09-10 renumber - was menu 2) helper. Finds the auto-enrollment umbrella group
        (the ONE group that gets Enroll on the auto template at creation - every VPN user group
        nests into it; AutoEnroll itself is a separate, deliberate switch now, see menu 15). Prompts for an
        existing group name; if none exists, offers to create it and multi-select AD groups to nest
        into it. Multiple searches / multi-select supported. Returns the group's DN, or $null.

        See also: PushableTools\ADManager\ (menu 2, the VPN group/OU scaffold) - the fuller,
        OU-browsable tool for standing up group structure from scratch. This function's own inline
        create-a-group flow (a raw typed OU distinguishedName, no browser) stays as the quick path for
        "I just need one umbrella group and everything else already exists."

    .PARAMETER SuggestedName
        From CA_AutoEnrollGroup, if set.
    #>
    param([string]$SuggestedName)

    if (-not (Get-Command Get-ADGroup -ErrorAction SilentlyContinue)) {
        Write-Host "  ActiveDirectory module not available - use dashboard menu 1 (Install RSAT / management" -ForegroundColor Red
        Write-Host "  modules), or run this on a box with RSAT-AD-PowerShell, then re-launch CA-Manager." -ForegroundColor Red
        return $null
    }

    while ($true) {
        $name = Read-CANonEmpty -Prompt "Auto-enrollment umbrella group name" -CurrentValue $SuggestedName
        $existing = @(Get-ADGroup -Filter "Name -eq '$($name.Replace("'","''"))'" -ErrorAction SilentlyContinue)
        if ($existing.Count -eq 1) {
            Write-Host ("  Found existing group: {0}" -f $existing[0].DistinguishedName) -ForegroundColor Green
            return $existing[0].DistinguishedName
        }

        Write-Host "  No group named '$name' exists." -ForegroundColor Yellow
        Write-Host "  Tip: for a full VPN group/OU scaffold (not just this one umbrella group), consider" -ForegroundColor DarkGray
        Write-Host "  the AD-Manager tool instead (menu 2 there) - this wizard only creates a single" -ForegroundColor DarkGray
        Write-Host "  group in an OU you type by hand." -ForegroundColor DarkGray
        if (-not (Read-CAConfirm -Prompt "  Create it now?" -DefaultYes)) { return $null }

        $ouDn = Read-CANonEmpty -Prompt "  OU to create the group in (distinguishedName)"
        $newGroupDn = Invoke-CAStep -Description "Create umbrella group '$name' in $ouDn" `
            -Commands @("New-ADGroup -Name '$name' -GroupScope Global -Path '$ouDn'") `
            -Action { (New-ADGroup -Name $name -GroupScope Global -Path $ouDn -PassThru).DistinguishedName }

        # nest the VPN user groups
        Write-Host ""
        Write-Host "  Now nest the 'primary' VPN user groups into it. Search, pick, repeat; blank search to finish." -ForegroundColor Cyan
        $picked = New-Object System.Collections.Generic.List[string]
        while ($true) {
            $term = Read-Host "  Group name search (blank to finish)"
            if ([string]::IsNullOrWhiteSpace($term)) { break }
            $hits = @(Get-ADGroup -Filter "Name -like '*$($term.Replace("'","''"))*'" -ErrorAction SilentlyContinue | Sort-Object Name)
            if (-not $hits) { Write-Host "    (no matches)" -ForegroundColor Yellow; continue }
            for ($i = 0; $i -lt $hits.Count; $i++) { Write-Host ("    {0}: {1}" -f $i, $hits[$i].Name) }
            $sel = Read-Host "    Numbers to nest (comma-separated), or blank to skip"
            foreach ($n in ($sel -split '[,\s]+' | Where-Object { $_ -match '^\d+$' })) {
                $idx = [int]$n
                if ($idx -ge 0 -and $idx -lt $hits.Count -and $picked -notcontains $hits[$idx].DistinguishedName) {
                    $picked.Add($hits[$idx].DistinguishedName)
                    Write-Host ("      + {0}" -f $hits[$idx].Name) -ForegroundColor Green
                }
            }
        }
        if ($picked.Count) {
            Invoke-CAStep -Description "Nest $($picked.Count) group(s) into '$name'" `
                -Commands ($picked | ForEach-Object { "Add-ADGroupMember -Identity '$name' -Members '$_'" }) `
                -Action { Add-ADGroupMember -Identity $name -Members $picked } | Out-Null
        }
        return $newGroupDn.Output
    }
}

# ---------------------------------------------------------------------------
# CREATE MECHANISM - raw System.DirectoryServices against the Configuration NC (no RSAT / PSPKI).
# Approach: allocate a template OID (msPKI-Enterprise-Oid object), CLONE the built-in "User" template
# as a known-good structural base (flags / pKICriticalExtensions / pKIMaxIssuingDepth), then override
# every value the spec dictates (schema version, EKU, key usage, validity, the three msPKI-*-Flag
# ints), publish via certutil -SetCATemplates, and set the Enroll/AutoEnroll DACL. Being iterated
# live against a client's CA server - the captured spec values are settled; only the plumbing here is new.
# ---------------------------------------------------------------------------

function Get-CAConfigNamingContext {
    return ([ADSI]"LDAP://RootDSE").Get('configurationNamingContext')
}

# ---------------------------------------------------------------------------
function Get-CAManualApprovalTemplates {
    <#
    .SYNOPSIS
        Read-only. Templates actually PUBLISHED on this CA (certutil -CATemplates) whose
        msPKI-Enrollment-Flag has CT_FLAG_PEND_ALL_REQUESTS (0x2) set - i.e. admin-approved / "Manual
        approval" templates, the shape menu 11's test-cert suite (and Request-VPNCert.ps1) issue
        against. 2026-09-15, per the maintainer: menu 11 used to take a free-typed template name (one default,
        the single shared IKEv2VPN-CorpLAN-MANUAL) - now that per-group manual templates exist
        (Get-CAPerGroupManualTemplateSpec, one per RadiusGroupPair), a tech needs to actually SEE
        what's published and pick from a numbered list instead of guessing/remembering exact names.

        Read via raw ADSI against the Configuration NC (same "no RSAT/PSPKI dependency" convention
        every other AD-template read/write in this file already uses), keyed off certutil's own
        published-name list (same parsing shape as Request-VPNCertCore.ps1's own
        Resolve-VPNCertTemplateName) so a template merely DEFINED in AD but never actually published to
        THIS CA is excluded - a tech should only ever be offered something they can actually issue from.
    .OUTPUTS
        Array of pscustomobject: Cn; DisplayName. Empty array if certutil reports nothing, or nothing
        published happens to be admin-approved.
    #>
    $out = & certutil.exe -CATemplates 2>&1 | Out-String
    if ([string]::IsNullOrWhiteSpace($out)) { return @() }
    $published = foreach ($line in ($out -split "`r?`n")) {
        if ($line -match '^\s*([A-Za-z0-9][\w.-]*):\s*(.+?)\s*--') {
            [pscustomobject]@{ Cn = $Matches[1].Trim(); DisplayName = $Matches[2].Trim() }
        }
    }
    if (-not $published) { return @() }

    $configNC = Get-CAConfigNamingContext
    $manual = New-Object System.Collections.Generic.List[object]
    foreach ($row in $published) {
        try {
            $t = [ADSI]"LDAP://CN=$($row.Cn),CN=Certificate Templates,CN=Public Key Services,CN=Services,$configNC"
            $flag = 0
            if ($t.Properties['msPKI-Enrollment-Flag'].Value) { $flag = [int]$t.Properties['msPKI-Enrollment-Flag'].Value }
            if (($flag -band 0x2) -eq 0x2) { $manual.Add($row) }
        } catch {
            # A published name certutil lists that doesn't resolve under the Templates container
            # (a built-in template stored elsewhere, a transient AD hiccup) - skip it silently rather
            # than fail the whole listing over one unreadable entry.
        }
    }
    return $manual.ToArray()
}

function ConvertFrom-CAKeyUsageHex {
    <#
    .SYNOPSIS
        '0xA000' -> [byte[]](0xA0, 0x00) - the pKIKeyUsage attribute's stored form.
    #>
    param([Parameter(Mandatory)][string]$Hex)
    $h = $Hex -replace '^0x', ''
    if ($h.Length % 2) { $h = "0$h" }
    $bytes = for ($i = 0; $i -lt $h.Length; $i += 2) { [Convert]::ToByte($h.Substring($i, 2), 16) }
    return [byte[]]$bytes
}

function ConvertFrom-CAHexToInt32 {
    <#
    .SYNOPSIS
        '0xA6000000' -> -1509949440. The msPKI-*-Flag attributes are 32-bit SIGNED integers in the
        schema, so a high-bit-set flag like 0xA6000000 is stored as its two's-complement negative.
        Deterministic (does not rely on PowerShell's [int]-cast overflow behaviour).
    #>
    param([Parameter(Mandatory)][string]$Hex)
    $u = [Convert]::ToUInt32(($Hex -replace '^0x', ''), 16)
    return [System.BitConverter]::ToInt32([System.BitConverter]::GetBytes($u), 0)
}

function New-CATemplateOid {
    <#
    .SYNOPSIS
        Allocates a new template OID under CN=OID,... : reads the forest's base
        (msPKI-Cert-Template-OID on the OID container), appends two random arcs, and creates the
        matching msPKI-Enterprise-Oid object. Returns the full OID string. Behind Invoke-CAStep.
    #>
    param([Parameter(Mandatory)][string]$DisplayName, [Parameter(Mandatory)][string]$ConfigNC)

    $oidContainerDn = "CN=OID,CN=Public Key Services,CN=Services,$ConfigNC"
    $baseOid = ([ADSI]"LDAP://$oidContainerDn").Get('msPKI-Cert-Template-OID')

    do {
        $a = Get-Random -Minimum 10000000 -Maximum 99999999
        $b = Get-Random -Minimum 10000000 -Maximum 99999999
        $oidCn  = "$a.$b"
        $newOid = "$baseOid.$a.$b"
        $exists = [bool][ADSI]::Exists("LDAP://CN=$oidCn,$oidContainerDn")
    } while ($exists)

    Invoke-CAStep -Description "Allocate template OID $newOid (CN=$oidCn)" `
        -Commands @("New msPKI-Enterprise-Oid  CN=$oidCn  msPKI-Cert-Template-OID=$newOid  flags=1  DisplayName='$DisplayName'") `
        -Action {
            # Two-phase (see New-CAVpnTemplate): a not-yet-committed DirectoryEntry rejects every
            # write style. Create bare + commit, then re-bind and populate.
            $parent = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$oidContainerDn")
            $bare = $parent.Children.Add("CN=$oidCn", 'msPKI-Enterprise-Oid')
            $bare.CommitChanges()

            $o = New-Object System.DirectoryServices.DirectoryEntry("LDAP://CN=$oidCn,$oidContainerDn")
            $o.Properties['DisplayName'].Value = $DisplayName
            $o.Properties['flags'].Value = 1
            $o.Properties['msPKI-Cert-Template-OID'].Value = $newOid
            $o.CommitChanges()
        } | Out-Null
    return $newOid
}

function Set-CAEntryOctet {
    <#
    .SYNOPSIS
        Sets a single octet-string (byte[]) attribute on a DirectoryEntry. `.Properties[x].Value =
        <byte[]>` gets ENUMERATED into N single-byte values (a schema violation for a single-valued
        octet string -> "Unspecified error" on commit); `.Add(<byte[]>)` stores it as one value.
    #>
    param([Parameter(Mandatory)]$Entry, [Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][byte[]]$Bytes)
    $Entry.Properties[$Name].Clear()
    [void]$Entry.Properties[$Name].Add($Bytes)
}

function Test-CATemplateComplete {
    <#
    .SYNOPSIS
        Returns the list of REQUIRED attributes missing from an existing pKICertificateTemplate.
        An empty list == a fully-populated template. A non-empty list == a leftover husk from a
        failed create run (its bare CN object committed, but Phase 2 never ran) - such an object
        must NOT be published to the CA.
    #>
    param([Parameter(Mandatory)][string]$TemplateDn)

    $required = @(
        'displayName', 'msPKI-Template-Schema-Version', 'msPKI-Cert-Template-OID',
        'pKIExtendedKeyUsage', 'pKIExpirationPeriod', 'pKIOverlapPeriod', 'pKIKeyUsage',
        'msPKI-Certificate-Name-Flag', 'msPKI-Enrollment-Flag'
    )
    $de = [ADSI]"LDAP://$TemplateDn"
    $missing = foreach ($attr in $required) {
        $v = $null
        try { $v = $de.psbase.Properties[$attr].Value } catch { }
        if ($null -eq $v -or ($v -is [string] -and [string]::IsNullOrWhiteSpace($v))) { $attr }
    }
    return @($missing)
}

function New-CAVpnTemplate {
    <#
    .SYNOPSIS
        Creates one pKICertificateTemplate from a Get-CAVpnTemplateSpec entry. Returns the internal
        CN (== spec.DisplayName with non-alphanumerics stripped, unless -InternalName given).
    #>
    param(
        [Parameter(Mandatory)]$Spec,
        [string]$InternalName,
        [string]$ConfigNC
    )
    if (-not $ConfigNC) { $ConfigNC = Get-CAConfigNamingContext }
    if (-not $InternalName) { $InternalName = ($Spec.DisplayName -replace '[^A-Za-z0-9]', '') }

    $templateDn = "CN=$InternalName,CN=Certificate Templates,CN=Public Key Services,CN=Services,$ConfigNC"

    if ([ADSI]::Exists("LDAP://$templateDn")) {
        $missing = Test-CATemplateComplete -TemplateDn $templateDn
        if ($missing.Count) {
            throw ("Template CN=$InternalName already exists but is INCOMPLETE (missing: $($missing -join ', ')) - " +
                   "a leftover from a failed create run. Delete it and re-run:  certutil -SetCATemplates -$InternalName ; certutil -DeleteTemplate $InternalName")
        }
        Write-Host "  Template CN=$InternalName already exists and looks complete - skipping create (delete it first to re-create)." -ForegroundColor Yellow
        return $InternalName
    }

    $oid = New-CATemplateOid -DisplayName $Spec.DisplayName -ConfigNC $ConfigNC

    $expBytes = ConvertTo-CAPkiPeriodBytes -Days $Spec.ValidityDays
    $ovlBytes = ConvertTo-CAPkiPeriodBytes -Days $Spec.OverlapDays
    $kuBytes  = ConvertFrom-CAKeyUsageHex -Hex $Spec.KeyUsageHex
    $nameFlag  = ConvertFrom-CAHexToInt32 -Hex $Spec.CertificateNameFlagHex
    $enrFlag   = ConvertFrom-CAHexToInt32 -Hex $Spec.EnrollmentFlagHex
    $pkFlag    = ConvertFrom-CAHexToInt32 -Hex $Spec.PrivateKeyFlagHex

    # Legacy `flags` (CT_FLAG_*): for a schema-v2+ template the CA honours the msPKI-*-Flag
    # attributes, not this field - but it still shows in ADSI Edit / certutil, so derive it from the
    # spec's own intent rather than cloning the built-in User template (which drags in a stray
    # EXPORTABLE_KEY + ADD_EMAIL and a "User" description). ADD_TEMPLATE_NAME(0x200) always; PUBLISH_TO_DS(0x8) /
    # AUTO_ENROLLMENT(0x20) mirror the enrollment flag; EXPORTABLE_KEY(0x10) mirrors the private-key
    # flag; MACHINE_TYPE(0x40) when the spec says so (OCSP signers enroll as the computer account,
    # and the Online Responder wizard checks this bit).
    $legacyFlags = 0x200
    if ($enrFlag -band 0x8)  { $legacyFlags = $legacyFlags -bor 0x8 }
    if ($enrFlag -band 0x20) { $legacyFlags = $legacyFlags -bor 0x20 }
    if ($pkFlag  -band 0x10) { $legacyFlags = $legacyFlags -bor 0x10 }
    if ($Spec.MachineType)   { $legacyFlags = $legacyFlags -bor 0x40 }
    $baseCritExt  = [string[]]@('2.5.29.15')   # Key Usage marked critical (matches the built-in client-auth templates)
    $baseMaxDepth = 0
    $descText     = "$($Spec.DisplayName) - created by CA-Manager. $($Spec.Notes)"
    if ($descText.Length -gt 1024) { $descText = $descText.Substring(0, 1024) }

    $templatesContainerDn = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$ConfigNC"

    Invoke-CAStep -Description "Create template CN=$InternalName ('$($Spec.DisplayName)') schema v$($Spec.SchemaVersion)" `
        -Commands @(
            "New pKICertificateTemplate  $templateDn"
            "  displayName='$($Spec.DisplayName)'  msPKI-Cert-Template-OID=$oid  msPKI-Template-Schema-Version=$($Spec.SchemaVersion)"
            "  pKIExtendedKeyUsage=$($Spec.EkuOids -join ',')  msPKI-Certificate-Application-Policy=$($Spec.EkuOids -join ',')"
            "  msPKI-Certificate-Name-Flag=$($Spec.CertificateNameFlagHex)  msPKI-Enrollment-Flag=$($Spec.EnrollmentFlagHex)  msPKI-Private-Key-Flag=$($Spec.PrivateKeyFlagHex)"
            "  msPKI-Minimal-Key-Size=$($Spec.MinimalKeySize)  pKIDefaultKeySpec=$($Spec.KeySpec)  validity=$($Spec.ValidityDays)d / overlap=$($Spec.OverlapDays)d"
            "  pKIDefaultCSPs=$(if ($Spec.DefaultCsps) { ($Spec.DefaultCsps -join '; ') } else { '(unset - client picks)' })  flags=$legacyFlags (derived from spec)  description='$descText'"
            "  msPKI-RA-Application-Policies=$(if ($Spec.SchemaVersion -ge 3 -and $Spec.RaApplicationPoliciesRaw) { 'v3 CNG-params blob (verbatim from built-in OCSPResponseSigning)' } else { '(unset - v2 template)' })"
        ) `
        -Action {
            # TWO-PHASE. A DirectoryEntry from .Children.Add() (or [ADSI].Create()) rejects EVERY
            # write style before its first commit - .Put, .PutEx(2), .PutEx(3), and
            # .Properties[x].Value all throw "Unspecified error". So: create the bare object and
            # commit it, then RE-BIND (now it has a real server-side property cache) and populate.
            $parent = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$templatesContainerDn")
            $bare = $parent.Children.Add("CN=$InternalName", 'pKICertificateTemplate')
            $bare.CommitChanges()

            $t = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$templateDn")
            $t.Properties['displayName'].Value                         = $Spec.DisplayName
            $t.Properties['description'].Value                         = $descText
            $t.Properties['flags'].Value                               = $legacyFlags
            $t.Properties['revision'].Value                            = 100
            $t.Properties['msPKI-Cert-Template-OID'].Value             = $oid
            $t.Properties['msPKI-Template-Schema-Version'].Value        = [int]$Spec.SchemaVersion
            $t.Properties['msPKI-Template-Minor-Revision'].Value        = 0
            $t.Properties['msPKI-RA-Signature'].Value                  = 0
            $t.Properties['msPKI-Minimal-Key-Size'].Value              = [int]$Spec.MinimalKeySize
            $t.Properties['msPKI-Certificate-Name-Flag'].Value         = $nameFlag
            $t.Properties['msPKI-Enrollment-Flag'].Value               = $enrFlag
            $t.Properties['msPKI-Private-Key-Flag'].Value              = $pkFlag
            $t.Properties['pKIDefaultKeySpec'].Value                   = [int]$Spec.KeySpec
            $t.Properties['pKIMaxIssuingDepth'].Value                  = $baseMaxDepth
            $t.Properties['pKICriticalExtensions'].Value               = $baseCritExt
            $t.Properties['pKIExtendedKeyUsage'].Value                 = [string[]]$Spec.EkuOids
            $t.Properties['msPKI-Certificate-Application-Policy'].Value = [string[]]$Spec.EkuOids
            # Only pin pKIDefaultCSPs if the spec names one. Empty -> the client chooses a provider
            # (like the built-in User template). A v2 template pinned to a CNG *KSP* only fails
            # enrollment with CRYPT_E_NO_PROVIDER on the legacy CryptoAPI path.
            if ($Spec.DefaultCsps -and @($Spec.DefaultCsps).Count) {
                $t.Properties['pKIDefaultCSPs'].Value = [string[]]@($Spec.DefaultCsps)
            }
            # v3+ templates must carry msPKI-RA-Application-Policies. For the OCSP signer it holds only
            # CNG key parameters (no co-sign OIDs), so it's a writable unicode string - unlike a v4
            # template's, which also needs policy OIDs and is not raw-ADSI-authorable. Absent it, the
            # Online Responder wizard fails with 0x80070490 "template ... could not be retrieved".
            if ($Spec.SchemaVersion -ge 3 -and $Spec.RaApplicationPoliciesRaw) {
                $t.Properties['msPKI-RA-Application-Policies'].Value = [string]$Spec.RaApplicationPoliciesRaw
            }
            Set-CAEntryOctet -Entry $t -Name 'pKIExpirationPeriod' -Bytes $expBytes
            Set-CAEntryOctet -Entry $t -Name 'pKIOverlapPeriod'    -Bytes $ovlBytes
            Set-CAEntryOctet -Entry $t -Name 'pKIKeyUsage'         -Bytes $kuBytes
            $t.CommitChanges()
        } | Out-Null

    return $InternalName
}

function Get-CAActiveConfigName {
    <#
    .SYNOPSIS
        The local CA's config/sanitized name (== the CN of its pKIEnrollmentService object).
    #>
    (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration' -Name Active -ErrorAction Stop).Active
}

function Publish-CATemplateToCA {
    <#
    .SYNOPSIS
        Publishes ONE template via `certutil -SetCATemplates +<name>`, checking the exit code (a
        native-exe failure otherwise slips past Invoke-CAStep's "didn't throw == done"). Prefer
        Add-CAPublishedTemplate for the multi-template case - running this in a loop on a single DC
        loses all but the last entry (each certutil call read-modify-writes certificateTemplates and
        the prior write may not have replicated back yet).
    #>
    param([Parameter(Mandatory)][string]$TemplateName)
    Invoke-CAStep -Description "Publish template '$TemplateName' to the CA" `
        -Commands @("certutil -SetCATemplates +$TemplateName") `
        -Action {
            $out = & certutil.exe -SetCATemplates "+$TemplateName" 2>&1 | Out-String
            if ($LASTEXITCODE -ne 0) { throw "certutil -SetCATemplates +$TemplateName failed (exit $LASTEXITCODE): $out" }
            $out
        } | Out-Null
}

function Add-CAPublishedTemplate {
    <#
    .SYNOPSIS
        Publishes one or more templates to the CA in a SINGLE write: unions their CNs into the
        certificateTemplates attribute of the CA's pKIEnrollmentService object via ADSI, commits
        once, then restarts CertSvc so the running CA re-reads the list. Replaces a per-template
        `certutil -SetCATemplates +X` loop (see Publish-CATemplateToCA remarks).
    #>
    param(
        [Parameter(Mandatory)][string[]]$TemplateName,
        [string]$CAName,
        [string]$ConfigNC
    )
    if (-not $ConfigNC) { $ConfigNC = Get-CAConfigNamingContext }
    if (-not $CAName)   { $CAName   = Get-CAActiveConfigName }
    $esDn = "CN=$CAName,CN=Enrollment Services,CN=Public Key Services,CN=Services,$ConfigNC"

    Invoke-CAStep -Description "Publish $($TemplateName.Count) template(s) to CA '$CAName'" `
        -Commands @(
            "Union into certificateTemplates on $esDn (one write):"
            ($TemplateName | ForEach-Object { "    + $_" })
            "Restart-Service certsvc   (CA re-reads the published list)"
        ) `
        -Action {
            $es = [ADSI]"LDAP://$esDn"
            $current = @($es.psbase.Properties['certificateTemplates'].Value)
            $want = @(($current + $TemplateName) | Where-Object { $_ } | Select-Object -Unique)
            $es.psbase.Properties['certificateTemplates'].Clear()
            foreach ($n in $want) { [void]$es.psbase.Properties['certificateTemplates'].Add($n) }
            $es.psbase.CommitChanges()
            Restart-Service certsvc -Force
        } | Out-Null
}

function Grant-CATemplateEnrollment {
    <#
    .SYNOPSIS
        Adds Allow-Read + Allow-Enroll (and optionally Allow-AutoEnroll) for $PrincipalName on the
        template object's DACL, via System.DirectoryServices. Behind Invoke-CAStep.
    #>
    param(
        [Parameter(Mandatory)][string]$TemplateInternalName,
        [Parameter(Mandatory)][string]$PrincipalName,     # DOMAIN\name or a group name
        [switch]$AutoEnroll,
        [string]$ConfigNC
    )
    if (-not $ConfigNC) { $ConfigNC = Get-CAConfigNamingContext }
    $templateDn = "CN=$TemplateInternalName,CN=Certificate Templates,CN=Public Key Services,CN=Services,$ConfigNC"

    $enrollRight     = [guid]'0e10c968-78fb-11d2-90d4-00c04f79dc55'
    $autoEnrollRight = [guid]'a05b8cc2-17bc-4802-a710-e7c15ab866a2'
    try {
        $sid = (New-Object System.Security.Principal.NTAccount($PrincipalName)).Translate([System.Security.Principal.SecurityIdentifier])
    } catch {
        # The raw .NET exception ("Some or all identity references could not be translated") names
        # neither the principal nor a next step - live 2026-09-10 on a client's CA server, a RadiusGroupPairs
        # UserGroupName that was never actually created in AD produced exactly this, indistinguishable
        # at a glance from a typo or a missing domain prefix.
        throw "Could not resolve '$PrincipalName' to a security identifier for CN=$TemplateInternalName - does that user/group exist in AD (check spelling/case), and does it need a 'DOMAIN\' prefix? ($($_.Exception.Message))"
    }

    $desc = "Grant $PrincipalName  Read + Enroll" + $(if ($AutoEnroll) { " + AutoEnroll" } else { "" }) + " on CN=$TemplateInternalName"
    Invoke-CAStep -Description $desc `
        -Commands @("Set DACL on $templateDn  ($PrincipalName : GenericRead, ExtendedRight Enroll$(if ($AutoEnroll) { ', AutoEnroll' }))") `
        -Action {
            # .psbase - PowerShell's [ADSI] adapter shadows ObjectSecurity / CommitChanges on the
            # PSObject; the real DirectoryEntry members are under .psbase.
            $de = [ADSI]"LDAP://$templateDn"
            $de.psbase.Options.SecurityMasks = [System.DirectoryServices.SecurityMasks]::Dacl
            $ns = 'System.DirectoryServices'
            $sec = $de.psbase.ObjectSecurity
            $sec.AddAccessRule((New-Object "$ns.ActiveDirectoryAccessRule"($sid, [System.DirectoryServices.ActiveDirectoryRights]::GenericRead, 'Allow')))
            $sec.AddAccessRule((New-Object "$ns.ActiveDirectoryAccessRule"($sid, [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight, 'Allow', $enrollRight)))
            if ($AutoEnroll) {
                $sec.AddAccessRule((New-Object "$ns.ActiveDirectoryAccessRule"($sid, [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight, 'Allow', $autoEnrollRight)))
            }
            $de.psbase.ObjectSecurity = $sec
            $de.psbase.CommitChanges()
        } | Out-Null
}

function Test-CATemplateAutoEnroll {
    <#
    .SYNOPSIS
        Read-only. Is $PrincipalName currently granted the AutoEnroll extended right on this
        template's DACL? Says nothing about Enroll - a principal can have Enroll without AutoEnroll
        (the whole point of "the enrollment gate", see Set-CATemplateAutoEnroll).
    #>
    param(
        [Parameter(Mandatory)][string]$TemplateInternalName,
        [Parameter(Mandatory)][string]$PrincipalName,
        [string]$ConfigNC
    )
    if (-not $ConfigNC) { $ConfigNC = Get-CAConfigNamingContext }
    $templateDn = "CN=$TemplateInternalName,CN=Certificate Templates,CN=Public Key Services,CN=Services,$ConfigNC"
    $autoEnrollRight = [guid]'a05b8cc2-17bc-4802-a710-e7c15ab866a2'
    try {
        $sid = (New-Object System.Security.Principal.NTAccount($PrincipalName)).Translate([System.Security.Principal.SecurityIdentifier])
    } catch { return $false }
    try {
        $sec = ([ADSI]"LDAP://$templateDn").psbase.ObjectSecurity
        $hit = @($sec.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) | Where-Object {
            $_.AccessControlType -eq 'Allow' -and
            $_.ActiveDirectoryRights -match 'ExtendedRight' -and
            $_.ObjectType -eq $autoEnrollRight -and
            $_.IdentityReference -eq $sid
        }
        [bool]$hit
    } catch { $false }
}

function Set-CATemplateAutoEnroll {
    <#
    .SYNOPSIS
        "The enrollment gate" - adds or removes JUST the AutoEnroll extended-right ACE for
        $PrincipalName on the template's DACL. Read + Enroll (granted once at template creation via
        Grant-CATemplateEnrollment, WITHOUT -AutoEnroll now - see Invoke-CAMenuTemplates) are left
        untouched either way.
    .NOTES
        Nothing actually auto-enrolls for a group until this is explicitly flipped on - decouples
        "does the template/ACL/TameMyCerts policy exist and look right" from "is this group live",
        so templates/TameMyCerts/App Proxy/OCSP/GPO can be built or revisited in whatever order makes
        sense for a given engagement without ever risking a premature real enrollment mid-setup.
        RemoveAccessRule matches by reconstructing the IDENTICAL rule shape used to add it (same SID,
        rights, ObjectType, default InheritanceType/flags) - .NET's ActiveDirectorySecurity compares
        access rules structurally, not by reference, so this removes cleanly without needing to look
        up and re-supply whatever the exact stored ACE instance was.
    #>
    param(
        [Parameter(Mandatory)][string]$TemplateInternalName,
        [Parameter(Mandatory)][string]$PrincipalName,
        [Parameter(Mandatory)][bool]$Enabled,
        [string]$ConfigNC
    )
    if (-not $ConfigNC) { $ConfigNC = Get-CAConfigNamingContext }
    $templateDn = "CN=$TemplateInternalName,CN=Certificate Templates,CN=Public Key Services,CN=Services,$ConfigNC"
    $autoEnrollRight = [guid]'a05b8cc2-17bc-4802-a710-e7c15ab866a2'
    try {
        $sid = (New-Object System.Security.Principal.NTAccount($PrincipalName)).Translate([System.Security.Principal.SecurityIdentifier])
    } catch {
        throw "Could not resolve '$PrincipalName' to a security identifier for CN=$TemplateInternalName - does that user/group exist in AD (check spelling/case), and does it need a 'DOMAIN\' prefix? ($($_.Exception.Message))"
    }
    $verb = if ($Enabled) { 'Grant' } else { 'Revoke' }
    Invoke-CAStep -Description "$verb AutoEnroll for $PrincipalName on CN=$TemplateInternalName" `
        -Commands @("$verb ExtendedRight AutoEnroll on $templateDn for $PrincipalName") `
        -Action {
            $de = [ADSI]"LDAP://$templateDn"
            $de.psbase.Options.SecurityMasks = [System.DirectoryServices.SecurityMasks]::Dacl
            $ns = 'System.DirectoryServices'
            $sec = $de.psbase.ObjectSecurity
            $rule = New-Object "$ns.ActiveDirectoryAccessRule"($sid, [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight, 'Allow', $autoEnrollRight)
            if ($Enabled) { $sec.AddAccessRule($rule) } else { $sec.RemoveAccessRule($rule) | Out-Null }
            $de.psbase.ObjectSecurity = $sec
            $de.psbase.CommitChanges()
        } | Out-Null
}

# ---------------------------------------------------------------------------
function Remove-CAOrphanTemplateOids {
    <#
    .SYNOPSIS
        Deletes stray msPKI-Enterprise-Oid objects left behind by failed template-create runs -
        each aborted New-CATemplateOid commits the OID object before New-CAVpnTemplate fails, so the
        CN=OID container accumulates entries no live pKICertificateTemplate references.

        Conservative by default: only removes template OIDs (flags=1, msPKI-Cert-Template-OID set)
        whose DisplayName matches one of -DisplayNameFilter AND which no published/unpublished
        template currently points at. Runs behind Invoke-CAStep so dry-run lists them first.

    .PARAMETER DisplayNameFilter
        OID DisplayNames eligible for cleanup. Defaults to the four CA-Manager template names, so a
        client CA's unrelated OIDs are never touched.
    #>
    param(
        [string[]]$DisplayNameFilter = @((Get-CAVpnTemplateSpec).DisplayName),
        [string]$ConfigNC
    )
    if (-not $ConfigNC) { $ConfigNC = Get-CAConfigNamingContext }

    $oidContainerDn      = "CN=OID,CN=Public Key Services,CN=Services,$ConfigNC"
    $templatesContainerDn = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$ConfigNC"

    # OIDs currently claimed by a real template
    $liveOids = @(
        ([ADSI]"LDAP://$templatesContainerDn").psbase.Children |
            ForEach-Object { "$($_.Properties['msPKI-Cert-Template-OID'].Value)" } |
            Where-Object { $_ }
    )

    # .psbase.Children yields RAW System.DirectoryServices.DirectoryEntry objects - use them
    # directly ($o.DeleteTree()); $o.psbase on a raw DirectoryEntry is a non-IADs PSObject wrapper.
    $orphans = @(
        ([ADSI]"LDAP://$oidContainerDn").psbase.Children | Where-Object {
            $_.SchemaClassName -eq 'msPKI-Enterprise-Oid' -and
            "$($_.Properties['flags'].Value)" -eq '1' -and
            $_.Properties['msPKI-Cert-Template-OID'].Value -and
            ("$($_.Properties['DisplayName'].Value)" -in $DisplayNameFilter) -and
            ("$($_.Properties['msPKI-Cert-Template-OID'].Value)" -notin $liveOids)
        }
    )

    if (-not $orphans.Count) {
        Write-Host "  No orphaned template OIDs to clean up." -ForegroundColor Green
        return 0
    }

    Write-Host ("  {0} orphaned template OID object(s) found:" -f $orphans.Count) -ForegroundColor Yellow
    foreach ($o in $orphans) {
        Write-Host ("    {0}   DisplayName='{1}'   {2}" -f $o.Properties['cn'].Value, $o.Properties['DisplayName'].Value, $o.Properties['msPKI-Cert-Template-OID'].Value) -ForegroundColor Gray
    }

    Invoke-CAStep -Description "Delete $($orphans.Count) orphaned template OID object(s)" `
        -Commands ($orphans | ForEach-Object { "Remove  CN=$($_.Properties['cn'].Value),$oidContainerDn" }) `
        -Action {
            foreach ($o in $orphans) {
                try { $o.DeleteTree() }
                catch { Write-Host ("    could not delete CN={0}: {1}" -f $o.Properties['cn'].Value, $_.Exception.Message) -ForegroundColor DarkYellow }
            }
        } | Out-Null
    return $orphans.Count
}
