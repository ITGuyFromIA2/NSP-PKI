# Ported from NSP-FGTIPSecTools Tests\CAManager.Ocsp.Tests.ps1 (2026-10-01): same assertions, paths re-pointed at
# this module's Private\ files. Run by Tests\Legacy.Tests.ps1 (Pester) in a child PowerShell.
<#
.SYNOPSIS
    Tests for CA Manager - menu 9 (2026-09-10 renumber - was menu 4; Online Responder / OCSP): the
    PURE Get-CAOcspPlan (registry shape
    transcribed from CLIENTA's live responder), and source-introspection that the engines route
    through Invoke-CAStep, use direct registry writes (not `reg add`), surface role-install
    failures, and that the read-only probes stay read-only.

    Repo convention (Tests\README.md) - NOT Pester. Whole modules are dot-sourced (no top-level side
    effects beyond a couple of $script: constants).
#>

. "$PSScriptRoot\..\Shared\TestAssertions.ps1"
$PKIModuleRoot = (Resolve-Path "$PSScriptRoot\..\..").Path
Reset-TestCounters

$Root = "C:\GitRepo\NSP-FGTIPSecTools"
$Mod  = "$PKIModuleRoot\Private"
$Dashboard = "$PKIModuleRoot\Tests\Legacy\_CA-Manager.combined.ps1"

Test-ScriptParses -Path "$Mod\CAOcsp.ps1"        -Because "CAOcsp.ps1 parses"
Test-ScriptParses -Path "$Mod\CAInteractive.ps1" -Because "CAInteractive.ps1 parses after Invoke-CAMenuOcsp"
Test-ScriptParses -Path "$Mod\CACore.ps1"        -Because "CACore.ps1 parses"
Test-ScriptParses -Path $Dashboard               -Because "CA-Manager.ps1 parses after wiring menu 9"

. "$Mod\CACore.ps1"
. "$Mod\CATemplates.ps1"
. "$Mod\CAOcsp.ps1"
. "$Mod\CAInteractive.ps1"

# ---------------------------------------------------------------------------
# 1. Get-CAOcspPlan - PURE, the CLIENTA-verbatim shape
# ---------------------------------------------------------------------------
$ans = [pscustomobject]@{ CA_TemplateOcspSigning = 'NSP-OCSPResponseSigning'; CA_DeltaCrl = 'No' }
$p = Get-CAOcspPlan -CAAnswers $ans -CACommonName 'Contoso-CA' -CAMachineFqdn 'Contoso-CA.Contoso.local' `
        -CASanitizedName 'Contoso-CA' -ConfigNC 'CN=Configuration,DC=Contoso,DC=local' -DeltaCrl $false

Assert-Equal -Actual $p.ConfigName -Expected 'Contoso-CA' -Because "the Responder\<name> key == the CA common name"
Assert-Equal -Actual $p.CAConfig -Expected 'Contoso-CA.Contoso.local\Contoso-CA' -Because "CAConfig = <machineFQDN>\<CAName>"
Assert-Equal -Actual $p.HashAlgorithmId -Expected 'SHA256' -Because "SHA256 (CLIENTA)"
Assert-Equal -Actual $p.SigningFlags -Expected 861 -Because "SigningFlags 861 (CLIENTA verbatim)"
Assert-Equal -Actual $p.ProviderCLSID -Expected '{4956d17f-88fd-4198-b287-1e6e65883b19}' -Because "Microsoft CRL-based revocation provider CLSID"
Assert-Equal -Actual $p.RefreshTimeOut -Expected 300000 -Because "Provider RefreshTimeOut 300000 (CLIENTA)"
Assert-Equal -Actual $p.ReminderDuration -Expected 90 -Because "ReminderDuration 90 (CLIENTA)"
Assert-Equal -Actual $p.SigningCertificateTemplate -Expected 'NSPOCSPResponseSigning' -Because "the Menu-1 signing template CN - non-alphanumerics stripped, matching New-CAVpnTemplate and the OCSP wizard's own registry value"
Assert-Equal -Actual $p.ResponderUrl -Expected 'http://Contoso-CA.Contoso.local/ocsp' -Because "the responder URL"
Assert-Equal -Actual $p.LocalVerifyUrl -Expected 'http://localhost/ocsp' -Because "the local verify URL"

# --- hardening: auditing + IIS request-filtering limits (2026-09-10, the maintainer's field-verified values) ---
Assert-Equal -Actual $p.AuditFilterValue -Expected 11 -Because "Start/Stop(1) + Config changes(2) + Security changes(8) = 11 - NOT bit 4 (per-request, floods the Security log)"
Assert-Equal -Actual $p.AuditFilterOsSubcategory -Expected 'Certification Services' -Because "the registry bit alone does nothing without this OS-level audit subcategory enabled too"
Assert-Equal -Actual $p.OcspMaxUrlBytes -Expected 16384 -Because "default matches what's been applied by hand in the field (avoids HTTP 404.14)"
Assert-Equal -Actual $p.OcspMaxQueryStringBytes -Expected 8192 -Because "default matches what's been applied by hand in the field (avoids HTTP 404.15)"
$pCustomLimits = Get-CAOcspPlan -CAAnswers $ans -CACommonName 'Contoso-CA' -CAMachineFqdn 'Contoso-CA.Contoso.local' `
        -CASanitizedName 'Contoso-CA' -OcspMaxUrlBytes 8192 -OcspMaxQueryStringBytes 4096
Assert-Equal -Actual $pCustomLimits.OcspMaxUrlBytes -Expected 8192 -Because "-OcspMaxUrlBytes overrides the default"
Assert-Equal -Actual $pCustomLimits.OcspMaxQueryStringBytes -Expected 4096 -Because "-OcspMaxQueryStringBytes overrides the default"

$baseJoined = ($p.BaseCrlUrls -join '|')
Assert-Equal     -Actual $p.BaseCrlUrls[0] -Expected 'http://localhost/CertEnroll/Contoso-CA.crl' -Because "co-located responder: localhost first (no DNS / host-header / name-mismatch risk)"
Assert-Contains  -Haystack $baseJoined -Needle 'http://Contoso-CA.Contoso.local/CertEnroll/Contoso-CA.crl' -Because "the CRL-based provider needs a real URL - the CA's own IIS /CertEnroll/ over http (a bare C:\ path is silently ignored -> /ocsp 500)"
Assert-Contains  -Haystack $baseJoined -Needle 'ldap:///CN=Contoso-CA,' -Because "the LDAP CDP is the secondary source"
$pSplit = Get-CAOcspPlan -CAAnswers $ans -CACommonName 'Contoso-CA' -CAMachineFqdn 'Contoso-CA.Contoso.local' -CASanitizedName 'Contoso-CA' -ConfigNC 'CN=Configuration,DC=Contoso,DC=local' -ResponderColocated $false
Assert-NotContains -Haystack ($pSplit.BaseCrlUrls -join '|') -Needle 'localhost' -Because "a split/dedicated responder box has no /CertEnroll vdir - no localhost entry"
Assert-NotContains -Haystack $baseJoined -Needle 'C:\\' -Because "no bare filesystem path - the provider does GETs"
Assert-NotContains -Haystack $baseJoined -Needle 'msappproxy' -Because "no App Proxy URL unless CA_AppProxyCrlFqdn is set on the answers"
Assert-Equal -Actual $p.DeltaCrlUrls.Count -Expected 0 -Because "no delta URL when CA_DeltaCrl is off"

# App Proxy CRL URL is added as a fallback when the fqdn answer is present (matches CLIENTA's live responder)
$pAP = Get-CAOcspPlan -CAAnswers ([pscustomobject]@{ CA_AppProxyCrlFqdn = 'crl-contoso.msappproxy.net' }) `
    -CACommonName 'Contoso-CA' -CAMachineFqdn 'Contoso-CA.Contoso.local' -CASanitizedName 'Contoso-CA' -ConfigNC 'CN=Configuration,DC=Contoso,DC=local'
Assert-Contains -Haystack ($pAP.BaseCrlUrls -join '|') -Needle 'http://crl-contoso.msappproxy.net/CertEnroll/Contoso-CA.crl' -Because "the resolved App Proxy CRL URL is included as a backup"
Assert-Contains -Haystack ($pAP.BaseCrlUrls -join '|') -Needle 'http://Contoso-CA.Contoso.local/CertEnroll/' -Because "the local IIS URL is still first"

$pDelta = Get-CAOcspPlan -CAAnswers ([pscustomobject]@{ CA_TemplateOcspSigning=''; CA_DeltaCrl='Yes' }) `
    -CACommonName 'Contoso-CA' -CAMachineFqdn 'Contoso-CA.Contoso.local' -CASanitizedName 'Contoso-CA' -ConfigNC 'CN=Configuration,DC=Contoso,DC=local' -DeltaCrl $true
Assert-Contains -Haystack ($pDelta.DeltaCrlUrls -join '|') -Needle 'http://Contoso-CA.Contoso.local/CertEnroll/Contoso-CA+.crl' -Because "delta CRL URL is the +.crl over http when CA_DeltaCrl is on"
Assert-Equal    -Actual $pDelta.DeltaCrlUrls[0] -Expected 'http://localhost/CertEnroll/Contoso-CA+.crl' -Because "delta list also leads with localhost for the co-located responder"
Assert-Equal -Actual $pDelta.SigningCertificateTemplate -Expected 'NSPOCSPResponseSigning' -Because "blank CA_TemplateOcspSigning coerces to the NSPOCSPResponseSigning CN"

$pColl = Get-CAOcspPlan -CAAnswers ([pscustomobject]@{ CA_TemplateOcspSigning='OCSPResponseSigning' }) `
    -CACommonName 'Contoso-CA' -CAMachineFqdn 'Contoso-CA.Contoso.local' -CASanitizedName 'Contoso-CA'
Assert-Equal -Actual $pColl.SigningCertificateTemplate -Expected 'NSPOCSPResponseSigning' -Because "literal 'OCSPResponseSigning' (built-in collision) is coerced to the NSPOCSPResponseSigning CN"

# no ldap entry when ConfigNC omitted
$pNoNc = Get-CAOcspPlan -CAAnswers $ans -CACommonName 'Contoso-CA' -CAMachineFqdn 'Contoso-CA.Contoso.local' -CASanitizedName 'Contoso-CA'
Assert-NotContains -Haystack ($pNoNc.BaseCrlUrls -join '|') -Needle 'ldap:///' -Because "no LDAP CDP entry when the configuration NC isn't known"

# RegistryValues rows
$rv = @{}; foreach ($r in $p.RegistryValues) { $rv["$($r.KeyPath)|$($r.Name)"] = $r }
Assert-Equal -Actual $rv['Responder\Contoso-CA|CAConfig'].Type -Expected 'String' -Because "CAConfig is a REG_SZ"
Assert-Equal -Actual $rv['Responder\Contoso-CA|SigningFlags'].Type -Expected 'DWord' -Because "SigningFlags is a REG_DWORD"
Assert-Equal -Actual $rv['Responder\Contoso-CA|SigningFlags'].Value -Expected 861 -Because "SigningFlags 861"
Assert-Equal -Actual $rv['Responder\Contoso-CA|CACertificate'].Type -Expected 'Binary' -Because "CACertificate is a REG_BINARY"
Assert-Equal -Actual $rv['Responder\Contoso-CA|HashAlgorithmId'].Value -Expected 'SHA256' -Because "HashAlgorithmId row"
Assert-Equal -Actual $rv['Responder\Contoso-CA|ProviderCLSID'].Value -Expected '{4956d17f-88fd-4198-b287-1e6e65883b19}' -Because "ProviderCLSID row"
Assert-Equal -Actual $rv['Responder\Contoso-CA\Provider|BaseCrlUrls'].Type -Expected 'MultiString' -Because "BaseCrlUrls is a REG_MULTI_SZ"
Assert-Equal -Actual $rv['Responder\Contoso-CA\Provider|RefreshTimeOut'].Value -Expected 300000 -Because "Provider RefreshTimeOut row"

# ---------------------------------------------------------------------------
# 2. Get-CAOcspPlan is PURE (no I/O)
# ---------------------------------------------------------------------------
$srcPlan = (Get-Command Get-CAOcspPlan).Definition
Assert-NoMatch -Actual $srcPlan -Pattern 'Invoke-CAStep|Get-Service|Get-ChildItem|certutil|New-Item|Restart-Service|Install-' -Because "Get-CAOcspPlan does no I/O"

# ---------------------------------------------------------------------------
# 3. Engine source-introspection
# ---------------------------------------------------------------------------
$srcRole = (Get-Command Install-CAOcspRole).Definition
Assert-Match   -Actual $srcRole -Pattern 'Invoke-CAStep' -Because "role install is dry-run aware"
Assert-Match   -Actual $srcRole -Pattern 'ADCS-Online-Cert' -Because "installs the Online Responder feature"
Assert-Match   -Actual $srcRole -Pattern 'Install-AdcsOnlineResponder' -Because "configures the responder role"
Assert-Match   -Actual $srcRole -Pattern 'ADCSDeployment' -Because "imports the ADCSDeployment module"
Assert-Match   -Actual $srcRole -Pattern '\.Success|ErrorId' -Because "a feature / role-config failure is surfaced, not silently -> done"
Assert-Match   -Actual $srcRole -Pattern 'Get-WindowsFeature' -Because "skips the install when the feature is already present"
Assert-Match   -Actual $srcRole -Pattern 'Test-CAOcspWebApp' -Because "the 'already configured' guard also checks the /ocsp IIS app - a running OCSPSvc alone is not enough (IIS reinstalled after the role drops the web app)"
Assert-Match   -Actual $srcRole -Pattern '\$roleConfigured' -Because "Install-AdcsOnlineResponder refuses ('already installed') when the role is configured - the repair path must not blind-fire it"
Assert-Match   -Actual $srcRole -Pattern 'Uninstall-WindowsFeature ADCS-Online-Cert' -Because "when the /ocsp app can't be recreated, the guidance names the feature-level reset that actually recovered a corrupted role this session"

$srcCfg = (Get-Command New-CAOcspRevocationConfig).Definition
Assert-Match   -Actual $srcCfg -Pattern 'Invoke-CAStep' -Because "every registry write is dry-run aware"
Assert-Match   -Actual $srcCfg -Pattern 'OCSPSvc\\\\?Responder' -Because "writes under ...\OCSPSvc\Responder"
Assert-Match   -Actual $srcCfg -Pattern 'New-ItemProperty' -Because "direct registry writes"
Assert-Match   -Actual $srcCfg -Pattern '-PropertyType \$row\.Type' -Because "each value is written with the plan's declared registry type (incl. MultiString for BaseCrlUrls)"
Assert-Match   -Actual $srcCfg -Pattern 'Restart-Service' -Because "OCSPSvc is restarted to load the config"
Assert-Match   -Actual $srcCfg -Pattern 'Test-Path' -Because "idempotency check before create"
Assert-Match   -Actual $srcCfg -Pattern 'Get-CAOcspCACertBytes' -Because "the CA cert bytes come from the store"
Assert-NoMatch -Actual $srcCfg -Pattern 'reg add|reg\.exe' -Because "no shelling out to reg.exe"
Assert-Match   -Actual $srcCfg -Pattern 'Publish-CAOcspConfig' -Because "after the registry writes it pushes the config to the array + /ocsp proxy (registry + restart alone leaves the ISAPI serving a stale view -> HTTP 500)"
Assert-Match   -Actual $srcCfg -Pattern 'SigningCertificateHash' -Because "when SigningCertificateTemplate drifts, the stale signer binding is cleared so SigningFlags 861 re-enrolls (else OCSPSvc logs 0x80070490 could-not-locate)"

$srcPublish = (Get-Command Publish-CAOcspConfig).Definition
Assert-Match   -Actual $srcPublish -Pattern 'CertAdm\.OCSPAdmin' -Because "Publish-CAOcspConfig uses the same COM object ocsp.msc does"
Assert-Match   -Actual $srcPublish -Pattern 'SetConfiguration' -Because "SetConfiguration is the call that recompiles + republishes to the array/proxy"
Assert-Match   -Actual $srcPublish -Pattern 'ContinueOnError' -Because "the push is non-fatal - the config is already on disk"

$srcSign = (Get-Command Confirm-CAOcspSigningCertificate).Definition
Assert-Match   -Actual $srcSign -Pattern 'certutil' -Because "nudges auto-enrollment"
Assert-Match   -Actual $srcSign -Pattern '-pulse' -Because "certutil -pulse triggers auto-enrollment"
Assert-Match   -Actual $srcSign -Pattern 'LASTEXITCODE' -Because "the pulse exit code is checked"
Assert-Match   -Actual $srcSign -Pattern '1\.3\.6\.1\.5\.5\.7\.3\.9' -Because "probes for an OCSP-Signing EKU cert"
Assert-Match   -Actual $srcSign -Pattern 'SigningCertificate' -Because "probes the SigningCertificate reg value"
Assert-Match   -Actual $srcSign -Pattern 'Restart-Service' -Because "restarts OCSPSvc to bind the new signer"

$srcCaCert = (Get-Command Get-CAOcspCACertBytes).Definition
Assert-Match   -Actual $srcCaCert -Pattern 'Cert:\\LocalMachine' -Because "reads the CA cert from the machine store"
Assert-Match   -Actual $srcCaCert -Pattern '2\.5\.29\.19' -Because "filters on BasicConstraints (CA cert)"
Assert-Match   -Actual $srcCaCert -Pattern 'RawData' -Because "returns the DER bytes"

foreach ($fn in 'Test-CAOcsp', 'Test-CAOcspEndpoint', 'Test-CAOcspWebApp') {
    $d = (Get-Command $fn).Definition
    Assert-NoMatch -Actual $d -Pattern 'Invoke-CAStep|New-ItemProperty|Restart-Service|Install-WindowsFeature|Install-Adcs' -Because "$fn is read-only"
}
$srcWebApp = (Get-Command Test-CAOcspWebApp).Definition
Assert-Match   -Actual $srcWebApp -Pattern 'appcmd' -Because "Test-CAOcspWebApp checks for the /ocsp app via appcmd (ships with Web-Server)"
Assert-Match   -Actual $srcWebApp -Pattern '/ocsp' -Because "it looks for the /ocsp application specifically"
$srcTestOcsp = (Get-Command Test-CAOcsp).Definition
Assert-Match   -Actual $srcTestOcsp -Pattern 'Get-ChildItem -Path \$script:CAOcspResponderKey' -Because "Test-CAOcsp enumerates every Responder\* config, not just one named key"
Assert-Match   -Actual $srcTestOcsp -Pattern '\$_\.CAConfig -ieq \$wantCaConfig' -Because "it matches a config by its CAConfig value (the OCSP wizard names configs arbitrarily, e.g. 'Contoso')"

$srcCom = (Get-Command New-CAOcspRevocationConfigViaCom).Definition
Assert-Match   -Actual $srcCom -Pattern 'CertAdm\.OCSPAdmin' -Because "the COM fallback uses CertAdm.OCSPAdmin"
Assert-Match   -Actual $srcCom -Pattern 'CreateCAConfiguration' -Because "the COM fallback creates a CA configuration"

# --- hardening engines: auditing + IIS request-filtering limits ---
$srcAudit = (Get-Command Set-CAOcspAuditing).Definition
Assert-Match -Actual $srcAudit -Pattern 'Invoke-CAStep' -Because "Set-CAOcspAuditing is dry-run aware"
Assert-Match -Actual $srcAudit -Pattern 'AuditFilter' -Because "writes the AuditFilter registry value"
Assert-Match -Actual $srcAudit -Pattern '\$script:CAOcspResponderKey' -Because "at the Responder ROOT key, not a per-config subkey"
Assert-Match -Actual $srcAudit -Pattern 'auditpol' -Because "also enables the OS-level audit subcategory - the registry bit alone doesn't log anything"
Assert-Match -Actual $srcAudit -Pattern 'Restart-Service OCSPSvc -Force' -Because "restarts OCSPSvc to pick up the new AuditFilter"
Assert-Match -Actual $srcAudit -Pattern '-ContinueOnError' -Because "auditing is a hardening nicety, not load-bearing for OCSP answering requests"

$srcLimits = (Get-Command Set-CAOcspWebRequestLimits).Definition
Assert-Match -Actual $srcLimits -Pattern 'Invoke-CAStep' -Because "Set-CAOcspWebRequestLimits is dry-run aware"
Assert-Match -Actual $srcLimits -Pattern 'requestFiltering' -Because "targets the IIS requestFiltering section"
Assert-Match -Actual $srcLimits -Pattern 'requestLimits\.maxUrl' -Because "raises maxUrl (avoids HTTP 404.14 on long OCSP GET URLs)"
Assert-Match -Actual $srcLimits -Pattern 'requestLimits\.maxQueryString' -Because "raises maxQueryString (avoids HTTP 404.15)"
Assert-Match -Actual $srcLimits -Pattern 'appcmd' -Because "uses appcmd.exe, not Set-WebConfigurationProperty - no WebAdministration/PSModulePath dependency"
Assert-Match -Actual $srcLimits -Pattern '-ContinueOnError' -Because "a hardening nicety, not load-bearing"

$srcWebAppPath = (Get-Command Get-CAOcspWebAppPath).Definition
Assert-NoMatch -Actual $srcWebAppPath -Pattern 'Invoke-CAStep|New-ItemProperty' -Because "Get-CAOcspWebAppPath is read-only (list app, never set config)"

Assert-Match -Actual $srcTestOcsp -Pattern 'AuditFilterOk' -Because "Test-CAOcsp reports the audit-hardening state"
Assert-Match -Actual $srcTestOcsp -Pattern 'IisLimitsOk' -Because "and the IIS request-limit hardening state"
Assert-NoMatch -Actual $srcTestOcsp -Pattern 'Invoke-CAStep|New-ItemProperty|auditpol /set|appcmd.*set config' -Because "Test-CAOcsp only READS the hardening state, never sets it"

# ---------------------------------------------------------------------------
# 4. Menu wrapper + dashboard wiring
# ---------------------------------------------------------------------------
$srcMenu = (Get-Command Invoke-CAMenuOcsp).Definition
foreach ($needle in 'Write-CAHeader', 'Get-CAOcspPlan', 'Show-CAOcspPlan', 'Test-CAOcsp', 'Read-CAConfirm', 'Install-CAOcspRole', 'New-CAOcspRevocationConfig', 'Confirm-CAOcspSigningCertificate', 'Get-CAAnswerOrPrompt', 'Set-CAOcspAuditing', 'Set-CAOcspWebRequestLimits') {
    Assert-Match -Actual $srcMenu -Pattern ([regex]::Escape($needle)) -Because "Invoke-CAMenuOcsp calls $needle"
}

# 2026-09-11, per the maintainer's Y/N-defaults review: this is a one-time role-install step, safe to default
# Yes - a tech blank-Entering through it isn't accidentally skipping the OCSP install.
Assert-Match -Actual $srcMenu -Pattern "Install the Online Responder role \(if needed\) and create this revocation configuration\?`" -DefaultYes" -Because "the role-install/revocation-config confirm defaults to Yes"

$rawDash = Get-Content $Dashboard -Raw
Assert-Match   -Actual $rawDash -Pattern "'\^9\`$'\s*\{[\s\S]{0,80}?Invoke-CAMenuOcsp" -Because "menu 9 (2026-09-10 renumber - was menu 4) dispatches to the OCSP engine"
Assert-NoMatch -Actual $rawDash -Pattern "'\^9\`$'\s*\{\s*Invoke-CANotYetImplemented" -Because "menu 9 is no longer a stub"
Assert-True -Condition (Test-Path "$PKIModuleRoot\Private\CAOcsp.ps1") -Because "NSP.PKI: the module loader dot-sources every Private\*.ps1 (was: dashboard dot-sources CAOcsp)"
# NSP.PKI: the module loader dot-sources Private\*.ps1 alphabetically (function definitions only) - the zip-era load-order check no longer applies.
<#
$idxOcsp = $rawDash.IndexOf('Private\CAOcsp.ps1')
$idxApp  = $rawDash.IndexOf('Private\CAAppProxy.ps1')
$idxInt  = $rawDash.IndexOf('Private\CAInteractive.ps1')
Assert-True -Condition ($idxApp -lt $idxOcsp -and $idxOcsp -lt $idxInt) -Because "CAOcsp is dot-sourced after CAAppProxy and before CAInteractive"
#>

Write-TestSummary -Suite "CA Manager - menu 9 (Online Responder)"
