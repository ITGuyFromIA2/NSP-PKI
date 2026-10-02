# Ported from NSP-FGTIPSecTools Tests\CAManager.AppProxy.Tests.ps1 (2026-10-01): same assertions, paths re-pointed at
# this module's Private\ files. Run by Tests\Legacy.Tests.ps1 (Pester) in a child PowerShell.
<#
.SYNOPSIS
    Tests for CA Manager - menu 6 (2026-09-10 renumber - was menu 7; App Proxy connector + Entra
    apps): the pure helpers
    (Get-CAAppProxyFqdn, Get-CAUrlHost, Get-CAAppProxyPublishingBody, Get-CAAppProxyPlan,
    Get-CAWebEndpointPlan), Save-CAAnswers round-trip, and source-introspection that the engines
    route through Invoke-CAStep / Invoke-CAGraphStep and hit the right Graph/IIS surface.

    Repo convention (Tests\README.md) - NOT Pester. Whole modules are dot-sourced (no top-level
    side effects beyond a couple of $script: URL constants).
#>

. "$PSScriptRoot\..\Shared\TestAssertions.ps1"
$PKIModuleRoot = (Resolve-Path "$PSScriptRoot\..\..").Path
Reset-TestCounters

$Root = "C:\GitRepo\NSP-FGTIPSecTools"
$Mod  = "$PKIModuleRoot\Private"
$Dashboard  = "$PKIModuleRoot\Tests\Legacy\_CA-Manager.combined.ps1"
$CliBuilder = "$Root\IPSEC AIO\CLIBuilder\Interactive - IPSec_IKEV2- CLI Builder V2.ps1"
$FieldMeta  = "$Root\IPSEC AIO\CLIBuilder\Modules\FieldMetadata.ps1"

Test-ScriptParses -Path "$Mod\CAGraph.ps1"        -Because "CAGraph.ps1 parses"
Test-ScriptParses -Path "$Mod\CAWebEndpoints.ps1" -Because "CAWebEndpoints.ps1 parses"
Test-ScriptParses -Path "$Mod\CAAppProxy.ps1"     -Because "CAAppProxy.ps1 parses"
Test-ScriptParses -Path "$Mod\CAInteractive.ps1"  -Because "CAInteractive.ps1 parses after Invoke-CAMenuAppProxy"
Test-ScriptParses -Path "$Mod\CACore.ps1"         -Because "CACore.ps1 parses after Save-CAAnswers"
Test-ScriptParses -Path $Dashboard               -Because "CA-Manager.ps1 parses after menu-7 wiring"

. "$Mod\CACore.ps1"
. "$Mod\CAGraph.ps1"
. "$Mod\CAWebEndpoints.ps1"
. "$Mod\CAAppProxy.ps1"
. "$Mod\CAInteractive.ps1"

# ---------------------------------------------------------------------------
# 1. Get-CAAppProxyFqdn  (pure composer - placeholder host only)
# ---------------------------------------------------------------------------
Assert-Equal -Actual (Get-CAAppProxyFqdn -Prefix 'crl' -Tenant 'clientaindustries') -Expected 'crl-clientaindustries.msappproxy.net' -Because "prefix-tenant.msappproxy.net"
Assert-Equal -Actual (Get-CAAppProxyFqdn -Prefix 'CRL' -Tenant 'CLIENTAindustries') -Expected 'crl-clientaindustries.msappproxy.net' -Because "lowercased"
Assert-Equal -Actual (Get-CAAppProxyFqdn -Prefix 'ocsprelay' -Tenant 'clientaindustries.onmicrosoft.com') -Expected 'ocsprelay-clientaindustries.msappproxy.net' -Because "a full .onmicrosoft.com value is trimmed to the label"
Assert-Equal -Actual (Get-CAAppProxyFqdn -Prefix '-crl-' -Tenant '-contoso-') -Expected 'crl-contoso.msappproxy.net' -Because "leading/trailing dashes trimmed"

# ---------------------------------------------------------------------------
# 2. Get-CAUrlHost
# ---------------------------------------------------------------------------
Assert-Equal -Actual (Get-CAUrlHost 'http://crl-x.msappproxy.net/CertEnroll/') -Expected 'crl-x.msappproxy.net' -Because "host pulled out of an http url with a path"
Assert-Equal -Actual (Get-CAUrlHost 'https://a.b.c/') -Expected 'a.b.c' -Because "https + trailing slash"
Assert-Equal -Actual (Get-CAUrlHost '') -Expected '' -Because "blank in, blank out"

# ---------------------------------------------------------------------------
# 3. Get-CAAppProxyPublishingBody  (the CLIENTA onPremisesPublishing shape)
# ---------------------------------------------------------------------------
$crlBody = (Get-CAAppProxyPublishingBody -InternalUrl 'http://ca/CertEnroll/' -ExternalUrl 'http://crl-x.msappproxy.net/CertEnroll/' -BackendCertValidation $true).onPremisesPublishing
Assert-Equal -Actual $crlBody.externalAuthenticationType -Expected 'passthru' -Because "CRL/OCSP clients are anonymous - passthru, no pre-auth"
Assert-True  -Condition ($crlBody.isTranslateHostHeaderEnabled -eq $true)  -Because "host-header translation on (CLIENTA)"
Assert-True  -Condition ($crlBody.isTranslateLinksInBodyEnabled -eq $false) -Because "links-in-body translation off (CLIENTA)"
Assert-True  -Condition ($crlBody.isOnPremPublishingEnabled -eq $true)      -Because "publishing enabled"
Assert-Equal -Actual $crlBody.applicationServerTimeout -Expected 'Default' -Because "default backend timeout"
Assert-Equal -Actual $crlBody.singleSignOnSettings.singleSignOnMode -Expected 'none' -Because "no SSO"
Assert-True  -Condition ($crlBody.isBackendCertificateValidationEnabled -eq $true) -Because "CRL app: backend cert validation on (CLIENTA)"
$ocspBody = (Get-CAAppProxyPublishingBody -InternalUrl 'http://ca/ocsp/' -ExternalUrl 'http://ocsprelay-x.msappproxy.net/ocsp/' -BackendCertValidation $false).onPremisesPublishing
Assert-True  -Condition ($ocspBody.isBackendCertificateValidationEnabled -eq $false) -Because "OCSP app: backend cert validation off (CLIENTA)"

# ---------------------------------------------------------------------------
# 4. Get-CAAppProxyPlan
# ---------------------------------------------------------------------------
$ans = [pscustomobject]@{ CA_AppProxyConnectorGroup = ''; CA_AppProxyCrlAppName = ''; CA_AppProxyOcspAppName = ''; CA_AppProxyCrlFqdn = ''; CA_AppProxyOcspFqdn = '' }
$plan = Get-CAAppProxyPlan -CAAnswers $ans -CAHostFqdn 'contoso-ca.contoso.local' -TenantLabel 'contoso'
Assert-Equal -Actual $plan.ConnectorGroupName -Expected 'CertChecks' -Because "connector group default"
Assert-Equal -Actual $plan.Apps.Count -Expected 2 -Because "one CRL app + one OCSP app"
$crl  = $plan.Apps | Where-Object Key -eq 'CRL'
$ocsp = $plan.Apps | Where-Object Key -eq 'OCSP'
Assert-Equal -Actual $crl.DisplayName -Expected 'CRL Relay' -Because "CRL app name default (consistent '... Relay' naming)"
Assert-Equal -Actual $ocsp.DisplayName -Expected 'OCSP Relay' -Because "OCSP app name default (consistent '... Relay' naming)"
Assert-Equal -Actual $crl.InternalUrl -Expected 'http://contoso-ca.contoso.local/CertEnroll/' -Because "CRL internal = the CA's own CertEnroll vdir"
Assert-Equal -Actual $ocsp.InternalUrl -Expected 'http://contoso-ca.contoso.local/ocsp/' -Because "OCSP internal = the responder's ISAPI app"
Assert-Contains -Haystack $crl.ExternalUrlGuess -Needle 'crl-contoso.msappproxy.net' -Because "composed placeholder external host"
Assert-Contains -Haystack $ocsp.ExternalUrlGuess -Needle 'ocsprelay-contoso.msappproxy.net' -Because "composed placeholder OCSP host"
Assert-True  -Condition ($crl.BackendCertValidation -eq $true) -Because "CRL backend cert validation on"
Assert-True  -Condition ($ocsp.BackendCertValidation -eq $false) -Because "OCSP backend cert validation off"
# names + prefix override from saved answers
$ans2 = [pscustomobject]@{ CA_AppProxyConnectorGroup = 'MyGroup'; CA_AppProxyCrlAppName = 'AcmeCRL'; CA_AppProxyOcspAppName = 'AcmeOCSP'; CA_AppProxyCrlFqdn = 'revoke-acme.msappproxy.net'; CA_AppProxyOcspFqdn = '' }
$plan2 = Get-CAAppProxyPlan -CAAnswers $ans2 -CAHostFqdn 'ca.acme.local' -TenantLabel 'acme'
Assert-Equal -Actual $plan2.ConnectorGroupName -Expected 'MyGroup' -Because "connector group name honoured"
Assert-Equal -Actual ($plan2.Apps | Where-Object Key -eq 'CRL').DisplayName -Expected 'AcmeCRL' -Because "CRL app name honoured"
Assert-Contains -Haystack ($plan2.Apps | Where-Object Key -eq 'CRL').ExternalUrlGuess -Needle 'revoke-acme.msappproxy.net' -Because "the prefix is taken from a saved FQDN ('revoke-...')"

# ---------------------------------------------------------------------------
# 5. Get-CAWebEndpointPlan
# ---------------------------------------------------------------------------
$web = Get-CAWebEndpointPlan -CACommonName 'Contoso-CA'
Assert-Equal -Actual $web.VDirName -Expected 'CertEnroll' -Because "the vdir name"
Assert-Match -Actual $web.PhysicalPath -Pattern 'CertSrv\\CertEnroll' -Because "points at the CA's CertEnroll dir by default"
Assert-True  -Condition ($web.DirectoryBrowse -eq $true) -Because "directory browsing on"
$crlMime = $web.MimeTypes | Where-Object Ext -eq '.crl'
$crtMime = $web.MimeTypes | Where-Object Ext -eq '.crt'
Assert-Equal -Actual $crlMime.Mime -Expected 'application/pkix-crl' -Because ".crl MIME type"
Assert-Equal -Actual $crtMime.Mime -Expected 'application/x-x509-ca-cert' -Because ".crt MIME type"
Assert-Contains -Haystack $web.VerifyUrl -Needle 'localhost/CertEnroll/Contoso-CA.crl' -Because "verify url targets the CA's own CRL"
$webShare = Get-CAWebEndpointPlan -PhysicalPath 'D:\CRLShare'
Assert-Equal -Actual $webShare.PhysicalPath -Expected 'D:\CRLShare' -Because "a CRL-share deployment overrides the physical path"

# ---------------------------------------------------------------------------
# 6. Save-CAAnswers round-trip
# ---------------------------------------------------------------------------
Set-CADryRun -Enabled $false
$tmp = Join-Path $env:TEMP ("caanswers_test_{0}.json" -f ([guid]::NewGuid().ToString('N')))
try {
    $obj = [pscustomobject]@{ Company_Name = 'Acme'; CA_AppProxyCrlFqdn = 'crl-acme.msappproxy.net' }
    Save-CAAnswers -Path $tmp -Answers $obj
    Assert-True -Condition (Test-Path $tmp) -Because "Save-CAAnswers writes the file"
    $back = Get-Content $tmp -Raw | ConvertFrom-Json
    Assert-Equal -Actual $back.CA_AppProxyCrlFqdn -Expected 'crl-acme.msappproxy.net' -Because "the resolved FQDN round-trips through CAAnswers.json"
} finally { Remove-Item $tmp -ErrorAction SilentlyContinue }
Set-CADryRun -Enabled $true

# ---------------------------------------------------------------------------
# 7. Source-introspection: engines route through the dry-run engine + hit the right surface
# ---------------------------------------------------------------------------
$srcWeb = (Get-Command Set-CAWebEndpoint).Definition
Assert-Match   -Actual $srcWeb -Pattern 'New-WebVirtualDirectory' -Because "Set-CAWebEndpoint creates the vdir"
Assert-Match   -Actual $srcWeb -Pattern 'Install-WindowsFeature -Name Web-Server' -Because "installs the IIS role"
Assert-Match   -Actual $srcWeb -Pattern 'directoryBrowse' -Because "enables directory browsing"
Assert-Match   -Actual $srcWeb -Pattern 'allowDoubleEscaping' -Because "the App Proxy connector forwards /CertEnroll%2f<crl> - IIS 404s a double-escaped path without this"
Assert-Match   -Actual $srcWeb -Pattern 'Invoke-CAStep' -Because "every IIS mutation is dry-run aware"

$srcPub = (Get-Command Set-CAAppProxyPublishing).Definition
Assert-Match   -Actual $srcPub -Pattern 'CAGraphBeta/applications/' -Because "onPremisesPublishing is a beta PATCH"
Assert-Match   -Actual $srcPub -Pattern "Method PATCH" -Because "onPremisesPublishing is a PATCH"
Assert-Match   -Actual $srcPub -Pattern 'Invoke-CAGraphStep' -Because "routes through the dry-run Graph step"
Assert-NoMatch -Actual $srcPub -Pattern 'CAGraphV1./applications/.AppObjectId' -Because "the publishing PATCH is NOT a v1.0 call"

$srcNewApp = (Get-Command New-CAAppProxyApp).Definition
Assert-Match   -Actual $srcNewApp -Pattern '8adf8e6e-67b2-4cf2-a259-e3dc5476c621' -Because "instantiates the on-prem-app gallery template"
Assert-Match   -Actual $srcNewApp -Pattern 'instantiate' -Because "uses applicationTemplates/{id}/instantiate"

$srcGrp = (Get-Command New-CAAppProxyConnectorGroup).Definition
Assert-Match   -Actual $srcGrp -Pattern 'applicationProxy/connectorGroups' -Because "hits the connector-groups collection"
Assert-Match   -Actual $srcGrp -Pattern 'Invoke-CAGraphStep' -Because "create routes through the dry-run Graph step"

$srcAdd = (Get-Command Add-CAAppProxyConnectorToGroup).Definition
Assert-Match   -Actual $srcAdd -Pattern 'memberOf/.{0,2}\$ref' -Because "adds the connector to the group's memberOf ref"
Assert-Match   -Actual $srcAdd -Pattern '@odata.id' -Because "the ref body is an @odata.id"

$srcSp = (Get-Command Set-CAAppProxyServicePrincipal).Definition
Assert-Match   -Actual $srcSp -Pattern 'appRoleAssignmentRequired' -Because "makes the app anonymous"
Assert-Match   -Actual $srcSp -Pattern 'HideApp' -Because "hides the app from the portal like CLIENTA"
Assert-Match   -Actual $srcSp -Pattern 'ResourceNotFound|404' -Because "retries the SP PATCH when the id is not visible yet (post-instantiate replication lag)"
Assert-Match   -Actual $srcSp -Pattern 'Resolve-CAAppProxySpId' -Because "re-resolves the SP id from appId on a 404"
$srcRes = (Get-Command Resolve-CAAppProxySpId).Definition
Assert-Match   -Actual $srcRes -Pattern "filter=appId eq" -Because "resolves the SP by appId filter, polling past replication lag"

$srcGetApp = (Get-Command Get-CAAppProxyApp).Definition
Assert-Match   -Actual $srcGetApp -Pattern 'WindowsAzureActiveDirectoryOnPremApp' -Because "enumerates by the App Proxy SP tag"
Assert-Match   -Actual $srcGetApp -Pattern "appId eq" -Because "resolves the app object via a filter, never a key segment"

$srcInstall = (Get-Command Install-CAAppProxyConnector).Definition
Assert-Match   -Actual $srcInstall -Pattern 'REGISTERCONNECTOR="false"' -Because "silent install defers registration"
Assert-Match   -Actual $srcInstall -Pattern 'RegisterConnector\.ps1' -Because "registers via RegisterConnector.ps1"
Assert-Match   -Actual $srcInstall -Pattern 'Invoke-CAStep' -Because "download + install + register are dry-run aware"
Assert-Match   -Actual $srcInstall -Pattern 'Assert-CAValidExe' -Because "the installer is validated as a real PE before it runs"
Assert-Match   -Actual $srcInstall -Pattern 'InstallerPath' -Because "a pre-downloaded installer can be supplied"
Assert-Match   -Actual $srcInstall -Pattern 'AuthenticationMode Interactive' -Because "legacy branch uses RegisterConnector's own interactive sign-in"
Assert-NoMatch -Actual $srcInstall -Pattern 'AuthenticationMode Token' -Because "the token path is retired"
Assert-NoMatch -Actual $srcInstall -Pattern 'powershell\.exe -NoProfile.*RegisterScript' -Because "RegisterConnector is invoked directly, not via a child powershell.exe (that host breaks it)"
Assert-Match   -Actual $srcInstall -Pattern 'Read-Host' -Because "the run pauses for the tech when registration needs a sign-in"
Assert-Match   -Actual $srcInstall -Pattern 'RegisterFound' -Because "branches on whether RegisterConnector.ps1 exists (legacy) vs the modern wizard-registers installer"
Assert-Match   -Actual $srcInstall -Pattern '/passive' -Because "modern branch tries a /passive install (tenant-scoped installer may auto-register) before the wizard"
$srcPaths = (Get-Command Get-CAConnectorPaths).Definition
Assert-Match   -Actual $srcPaths -Pattern "Recurse -Filter 'RegisterConnector\.ps1'" -Because "RegisterConnector.ps1 is searched for recursively (newer builds move it / omit it)"

$srcDl = (Get-Command Get-CAConnectorInstaller).Definition
Assert-Match   -Actual $srcDl -Pattern 'Tls12' -Because "forces TLS 1.2 for the download"
Assert-Match   -Actual $srcDl -Pattern 'curl\.exe' -Because "curl.exe -L is the primary fetch (robust redirect handling)"
Assert-Match   -Actual $srcDl -Pattern 'Assert-CAValidExe' -Because "each candidate URL result is PE-validated"
$srcUrls = (Get-Command Get-CAConnectorInstallerUrls).Definition
Assert-Match   -Actual $srcUrls -Pattern 'download\.msappproxy\.net/Subscription/' -Because "the tenant-scoped portal URL is tried first"
Assert-Match   -Actual $srcUrls -Pattern 'aka\.ms/' -Because "the aka.ms short links are fallbacks"

$srcExe = (Get-Command Assert-CAValidExe).Definition
Assert-Match   -Actual $srcExe -Pattern "'MZ'" -Because "checks the DOS/PE header so an HTML redirect page is rejected"
Assert-Match   -Actual $srcExe -Pattern 'Download connector service' -Because "the failure message points at the manual download"


$srcStep = (Get-Command Invoke-CAGraphStep).Definition
Assert-Match   -Actual $srcStep -Pattern 'Invoke-CAStep' -Because "every mutating Graph call goes through the dry-run engine"

$srcGm = (Get-Command Install-CAGraphModule).Definition
Assert-Match   -Actual $srcGm -Pattern 'Tls12' -Because "bootstraps TLS 1.2 for the PowerShell Gallery"
Assert-Match   -Actual $srcGm -Pattern 'Install-PackageProvider -Name NuGet' -Because "bootstraps the NuGet provider"
Assert-Match   -Actual $srcGm -Pattern 'Scope AllUsers' -Because "installs machine-wide (elevated; survives the connector's PSModulePath rewrite)"
Assert-Match   -Actual $srcGm -Pattern 'Microsoft\.Graph\.Authentication' -Because "installs the Graph auth module"
Assert-Match   -Actual $srcGm -Pattern 'still not visible' -Because "verifies the module actually installed instead of silently continuing"
# 2026-09-10 live bug (Contoso-CA): the "is PowerShellGet loadable" probe used to live inside an
# Invoke-CAStep -Action block, which Invoke-CAStep skips entirely in DRY RUN - so a DRY RUN pass
# always reported "PowerShellGet is not present" regardless of the box's actual state (module +
# PSModulePath were both fine). The probe must run unconditionally and surface the real error.
$impIdx  = $srcGm.IndexOf("foreach (`$m in 'PackageManagement', 'PowerShellGet')")
$stepIdx = $srcGm.IndexOf('Invoke-CAStep -Description')   # the real call site, not the doc-comment prose mentioning it
Assert-True  -Condition ($impIdx -ge 0 -and $stepIdx -ge 0 -and $impIdx -lt $stepIdx) -Because "the PowerShellGet import probe runs BEFORE (outside) the first Invoke-CAStep call, not inside its dry-run-gated -Action"
Assert-Match -Actual $srcGm -Pattern '\$importErrors\.Add' -Because "the real Import-Module exception is captured, not silently swallowed"
Assert-Match -Actual $srcGm -Pattern 'LanguageMode' -Because "and surfaced alongside LanguageMode/PSModulePath diagnostics if PowerShellGet still isn't loadable"

$srcConn = (Get-Command Connect-CAGraph).Definition
Assert-Match   -Actual $srcConn -Pattern 'Repair-CAModulePath' -Because "self-heals PSModulePath (connector installer drops the CurrentUser dir) before the module check"
$srcRmp = (Get-Command Repair-CAModulePath).Definition
Assert-Match   -Actual $srcRmp -Pattern 'WindowsPowerShell\\Modules' -Because "re-asserts the per-user WinPS module dir"
Assert-Match   -Actual $srcRmp -Pattern 'Test-Path' -Because "rebuilds from validated real directories, not a naive string -split on the (possibly malformed) inherited value"
Assert-Match   -Actual (Get-Command Install-CAGraphModule).Definition -Pattern 'Repair-CAModulePath' -Because "re-asserts PSModulePath right before its own import probe too, not just once at CA-Manager startup"

# 2026-09-10 live bug (Contoso-CA): the inherited $env:PSModulePath had two entries glued together
# with no ';' between them - Import-Module PowerShellGet by NAME then failed to find it even though
# the real directory was on disk. Repair-CAModulePath must drop a malformed/non-existent entry
# instead of carrying it forward, while keeping any real directory that genuinely exists.
$savedPSMP = $env:PSModulePath
try {
    $glued = 'C:\NoSuchDir1_2026' + 'C:\NoSuchDir2_2026'   # simulates the missing-separator corruption
    $env:PSModulePath = "$glued;$($env:TEMP)"
    Repair-CAModulePath
    $rebuilt = @($env:PSModulePath -split ';')
    Assert-True     -Condition ($rebuilt -notcontains $glued) -Because "a glued/non-existent entry is dropped, not propagated forward"
    Assert-Contains -Haystack ($rebuilt -join '|') -Needle $env:TEMP.TrimEnd('\') -Because "a real, existing directory already in PSModulePath is kept"
    Assert-Contains -Haystack ($rebuilt -join '|') -Needle 'WindowsPowerShell\Modules' -Because "the standard want-list directories are always present after a repair"
} finally { $env:PSModulePath = $savedPSMP }
$rawDashMp = Get-Content $Dashboard -Raw
Assert-Match   -Actual $rawDashMp -Pattern 'Repair-CAModulePath' -Because "the dashboard re-asserts PSModulePath at startup too"
Assert-Match   -Actual $srcConn -Pattern 'Microsoft\.Graph\.Authentication' -Because "guards on the Graph auth module"
Assert-Match   -Actual $srcConn -Pattern 'Install-CAGraphModule' -Because "when the module is missing, menu 6 threads in the install itself rather than dead-ending"
Assert-Match   -Actual $srcConn -Pattern 'Application\.ReadWrite\.All' -Because "requests the app write scope"
Assert-Match   -Actual $srcConn -Pattern 'OnPremisesPublishingProfiles\.ReadWrite\.All' -Because "requests the App Proxy write scope"

# ---------------------------------------------------------------------------
# 8. Dashboard + menu wiring
# ---------------------------------------------------------------------------
$rawDash = Get-Content $Dashboard -Raw
Assert-Match   -Actual $rawDash -Pattern "'\^6\`$'\s*\{[\s\S]*?Invoke-CAMenuAppProxy" -Because "menu 6 (2026-09-10 renumber - was 7) dispatches to the App Proxy engine"
Assert-NoMatch -Actual $rawDash -Pattern "'\^6\`$'\s*\{\s*Invoke-CANotYetImplemented" -Because "menu 6 (2026-09-10 renumber - was menu 7) is no longer a stub"
Assert-Match   -Actual $rawDash -Pattern "Save-CAAnswers -Path \`$answersFile -Answers \`$script:CAAnswers" -Because "answers are persisted centrally once per menu-item completion (2026-09-10 persistence audit), covering menu 6 along with every other numbered item - not menu 6's own per-case call any more"
Assert-True -Condition (Test-Path "$PKIModuleRoot\Private\CAGraph.ps1") -Because "NSP.PKI: the module loader dot-sources every Private\*.ps1 (was: dashboard dot-sources CAGraph)"
Assert-True -Condition (Test-Path "$PKIModuleRoot\Private\CAWebEndpoints.ps1") -Because "NSP.PKI: the module loader dot-sources every Private\*.ps1 (was: dashboard dot-sources CAWebEndpoints)"
Assert-True -Condition (Test-Path "$PKIModuleRoot\Private\CAAppProxy.ps1") -Because "NSP.PKI: the module loader dot-sources every Private\*.ps1 (was: dashboard dot-sources CAAppProxy)"

$srcMenu = (Get-Command Invoke-CAMenuAppProxy).Definition
# 2026-09-11, per the maintainer's Y/N-defaults review: turning IE ESC off is virtually always what a tech
# wants here (it's WHY the prompt fired at all - ESC was detected ON), safe to default Yes.
Assert-Match -Actual $srcMenu -Pattern 'Turn IE ESC OFF now \(explorer restarts briefly; re-enable later via menu 6 or Server Manager\)\?" -DefaultYes' -Because "the IE ESC prompt defaults to Yes"
Assert-Match   -Actual $srcMenu -Pattern 'Connect-CAGraph' -Because "7a signs in to Graph"
Assert-Match   -Actual $srcMenu -Pattern 'Set-CAWebEndpoint' -Because "7b configures IIS"
Assert-Match   -Actual $srcMenu -Pattern 'Install-CAAppProxyConnector' -Because "7c installs the connector"
Assert-Match   -Actual $srcMenu -Pattern 'Publish-CAAppProxyApp' -Because "7e creates the apps"
Assert-Match   -Actual $srcMenu -Pattern 'CA_AppProxyCrlFqdn' -Because "7f writes the real host back onto the answers"
Assert-Match   -Actual $srcMenu -Pattern '(?i)menu 8' -Because "6f (2026-09-10 renumber - was 7f) tells the tech to re-run menu 8 (was menu 5)"

# ---------------------------------------------------------------------------
# 9. CLIBuilder field + FieldMetadata
# ---------------------------------------------------------------------------
$rawCli = Get-Content $CliBuilder -Raw
Assert-Match -Actual $rawCli -Pattern 'CA_MsAppProxyTenant\s*=\s*@\{' -Because "the new tenant-label field exists"
Assert-Match -Actual $rawCli -Pattern "CA_MsAppProxyTenant[\s\S]{0,400}?ReqChange = \`$false" -Because "it is a strong-default field, not a mandatory prompt"
$rawFm = Get-Content $FieldMeta -Raw
Assert-Match -Actual $rawFm -Pattern '"Certificate Authority"[\s\S]*?CA_MsAppProxyTenant' -Because "FieldMetadata groups it under Certificate Authority"

Write-TestSummary -Suite "CA Manager - menu 6 (App Proxy connector + Entra apps)"
