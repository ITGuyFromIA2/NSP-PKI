# Ported from NSP-FGTIPSecTools Tests\CAManager.Handoff.Tests.ps1 (2026-10-01): same assertions, paths re-pointed at
# this module's Private\ files. Run by Tests\Legacy.Tests.ps1 (Pester) in a child PowerShell.
<#
.SYNOPSIS
    Tests for CA Manager - menu 13 (2026-09-12 renumber - was menu 14; FortiGate cert hand-off /
    Orchestrator hand-back). The PURE Get-CAResponseObject + ConvertTo-CAPem, source-introspection
    that the engines route through Invoke-CAStep, reuse Request-VPNCertCore, and wait for manual
    CA approval, and (2026-09-30, Schema 4) the data-only hand-back plus reuse of the last FortiGate
    identity cert. The CA/peer CLI itself is CLIBuilder's now - see CLIBuilder.CAHandoffFoldIn.Tests.ps1.

    Repo convention (Tests\README.md) - NOT Pester.
#>

. "$PSScriptRoot\..\Shared\TestAssertions.ps1"
$PKIModuleRoot = (Resolve-Path "$PSScriptRoot\..\..").Path
Reset-TestCounters

$Root = "C:\GitRepo\NSP-FGTIPSecTools"
$Mod  = "$PKIModuleRoot\Private"
$Dashboard = "$PKIModuleRoot\Tests\Legacy\_CA-Manager.combined.ps1"

Test-ScriptParses -Path "$Mod\CAFortiGateHandoff.ps1" -Because "CAFortiGateHandoff.ps1 parses"
Test-ScriptParses -Path $Dashboard                    -Because "CA-Manager.ps1 parses after wiring menu 13"

. "$Mod\CACore.ps1"
. "$Mod\CATemplates.ps1"
. "$Mod\CATameMyCerts.ps1"
. "$Mod\CAOcsp.ps1"
. "$Mod\CAInteractive.ps1"
. "$Mod\CAFortiGateHandoff.ps1"

# ---------------------------------------------------------------------------
# 1. ConvertTo-CAPem - PURE
# ---------------------------------------------------------------------------
$pem = ConvertTo-CAPem -DerBytes ([byte[]](1..200)) -Label 'CERTIFICATE'
Assert-Match  -Actual $pem -Pattern '^-----BEGIN CERTIFICATE-----' -Because "PEM opens with the BEGIN line"
Assert-Match  -Actual $pem -Pattern '-----END CERTIFICATE-----$'   -Because "PEM closes with the END line"
$body = ($pem -split "`r?`n") | Where-Object { $_ -notmatch '-----' }
Assert-True   -Condition (($body | ForEach-Object { $_.Length } | Measure-Object -Maximum).Maximum -le 64) -Because "base64 body is wrapped at 64 cols"

# ---------------------------------------------------------------------------
# 2. New-CAHandoffPassword
# ---------------------------------------------------------------------------
$pw = New-CAHandoffPassword
Assert-Equal  -Actual $pw.Length -Expected 20 -Because "PFX password is 20 chars"
Assert-Match  -Actual $pw -Pattern '^[A-Za-z0-9!@#%^*\-_=+]+$' -Because "password stays CLI-paste friendly"

# ---------------------------------------------------------------------------
# 3. Get-CAResponseObject - PURE, the hand-back shape
# ---------------------------------------------------------------------------
$ans = [pscustomobject]@{
    Company_Name         = 'Contoso Ltd'
    Cert_CertificateName = 'Contoso-FGT'
    Cert_PeerName        = 'Contoso-peer'
    Cert_PeerSubjectFilter = 'OU=VPN Users'
    CA_IssuingModel      = 'SharedCAWithSubjectFilter'
    CA_AppProxyCrlFqdn   = 'crl-contoso.msappproxy.net'
    CA_AppProxyOcspFqdn  = 'ocsp-contoso.msappproxy.net'
    CA_AutoEnrollGPOName = 'NSP - Certificate Auto-Enrollment'
    CA_TemplateAuto      = 'IKEv2VPN-CorpLAN'
    CA_TemplateManual    = 'IKEv2VPN-CorpLAN-MANUAL'
    CA_TemplateFortiGate = 'FortiGate'
}
$fg = [pscustomobject]@{ PfxPath = 'C:\Admin\Handoff\Contoso\ContosoLtd_FortiGate.pfx'; Password = 'p@ss'; Thumbprint = 'ABC123'; SerialNumber = '01' }
$resp = Get-CAResponseObject -CAAnswers $ans -CACommonName 'Contoso-Issuing-CA' -CAConfigString 'ca.contoso.local\Contoso-Issuing-CA' `
    -CASanitizedName 'Contoso-Issuing-CA' -CACertPem "-----BEGIN CERTIFICATE-----`nAAAA`n-----END CERTIFICATE-----" `
    -FgCert $fg -PeerSubjectFilter 'OU=VPN Users' -CAManagerVersion '2026-09-09'

Assert-Equal -Actual $resp.Schema -Expected 4 -Because "hand-back schema version (Schema 2 adds FortiGatePfxBase64; Schema 3 adds CACertChain; 2026-09-30 Schema 4 drops the rendered CLI)"
Assert-False -Condition ([bool]$resp.Contains('FortiGateCertSetupText')) -Because "Schema 4 carries data only - no rendered CLI (CLIBuilder renders it from these fields)"
Assert-Equal -Actual $resp.CACertNameOnGate -Expected 'CA_Contoso-Issuing-CA' -Because "CA cert name on the gate = CA_<sanitized>"
Assert-Equal -Actual $resp.FortiGateCertName -Expected 'Contoso-FGT' -Because "FortiGate cert name comes from Cert_CertificateName"
Assert-Equal -Actual $resp.FortiGatePeerName -Expected 'Contoso-peer' -Because "peer name comes from Cert_PeerName"
Assert-Equal -Actual $resp.PeerSubjectFilter -Expected 'OU=VPN Users' -Because "the passed filter is carried through"
Assert-Equal -Actual $resp.FortiGatePfxFile -Expected 'ContosoLtd_FortiGate.pfx' -Because "only the PFX basename goes in the JSON"
Assert-Equal -Actual $resp.FortiGatePfxPassword -Expected 'p@ss' -Because "the PFX password rides in the hand-back (tech copies it into the client folder)"
Assert-Equal -Actual $resp.AppProxyCrlUrl -Expected 'http://crl-contoso.msappproxy.net/CertEnroll/Contoso-Issuing-CA.crl' -Because "CRL URL composed from CA_AppProxyCrlFqdn"
Assert-Equal -Actual $resp.AppProxyOcspUrl -Expected 'http://ocsp-contoso.msappproxy.net/ocsp' -Because "OCSP URL composed from CA_AppProxyOcspFqdn"
Assert-Equal -Actual ($resp.TemplatesPublished -join ',') -Expected 'IKEv2VPN-CorpLAN,IKEv2VPN-CorpLAN-MANUAL,FortiGate' -Because "the three user/device templates are listed"

# ---------------------------------------------------------------------------
# 3a. Schema 2 (2026-09-11) - the single-file hand-back: FortiGatePfxBase64 embedded directly in the
#     response object, so a tech can copy back just the ONE JSON file
# ---------------------------------------------------------------------------
$fakePfxBytes = [byte[]](1..64)
$fakePfxB64   = [Convert]::ToBase64String($fakePfxBytes)
$respB64 = Get-CAResponseObject -CAAnswers $ans -CACommonName 'Contoso-Issuing-CA' -CAConfigString 'ca.contoso.local\Contoso-Issuing-CA' `
    -CASanitizedName 'Contoso-Issuing-CA' -CACertPem "-----BEGIN CERTIFICATE-----`nAAAA`n-----END CERTIFICATE-----" `
    -FgCert $fg -PeerSubjectFilter 'OU=VPN Users' -CAManagerVersion '2026-09-09' -FortiGatePfxBase64 $fakePfxB64
Assert-Equal -Actual $respB64.FortiGatePfxBase64 -Expected $fakePfxB64 -Because "the PFX bytes ride along as base64 when the caller supplies them"

# blank/omitted -FortiGatePfxBase64 -> $null, not an empty string or error (the CSR/import paths
# never have a PFX at all - FortiGateCertPem is what rides inline for those)
Assert-True -Condition ($null -eq $resp.FortiGatePfxBase64) -Because "no -FortiGatePfxBase64 was passed for the original `$resp built above - stays `$null, doesn't error"

# blank filter -> empty string, not null; issuing model default
$resp2 = Get-CAResponseObject -CAAnswers ([pscustomobject]@{ Company_Name = 'Acme' }) -CACommonName 'Acme-CA' -CASanitizedName 'Acme-CA' -PeerSubjectFilter ''
Assert-Equal -Actual $resp2.PeerSubjectFilter -Expected '' -Because "blank filter normalises to empty string"
Assert-Equal -Actual $resp2.IssuingModel -Expected 'SharedCAWithSubjectFilter' -Because "issuing model defaults when not in the answers"
Assert-Equal -Actual $resp2.FortiGateCertName -Expected 'Acme-CA-FGT' -Because "cert name falls back to <sanitized>-FGT"
Assert-True  -Condition ($null -eq $resp2.AppProxyCrlUrl) -Because "no CRL URL when CA_AppProxyCrlFqdn is absent"

# ---------------------------------------------------------------------------
# 4. (retired 2026-09-30) Get-CAFortiGateCertSetupText - the CA box no longer renders CLI
# ---------------------------------------------------------------------------
Assert-False -Condition ([bool](Get-Command Get-CAFortiGateCertSetupText -ErrorAction SilentlyContinue)) -Because "the CA-side CLI renderer is gone - CLIBuilder renders the CA/peer block, the Orchestrator writes the identity-cert import note"

# ---------------------------------------------------------------------------
# 5. Engine source-introspection
# ---------------------------------------------------------------------------
$srcNew = (Get-Command New-CAFortiGateIdentityCert).Definition
Assert-Match -Actual $srcNew -Pattern 'Invoke-CAStep' -Because "the request is dry-run aware"
Assert-Match -Actual $srcNew -Pattern 'Get-Certificate' -Because "it submits via Get-Certificate against the server-auth template"
Assert-Match -Actual $srcNew -Pattern 'Complete-VPNCertRequest' -Because "it reuses the shared retrieve+export engine"
Assert-Match -Actual $srcNew -Pattern 'CA_TemplateFortiGate' -Because "it issues from the FortiGate template"
Assert-Match -Actual $srcNew -Pattern 'Pending Requests' -Because "it waits for a manual GUI approval"
Assert-Match -Actual $srcNew -Pattern 'Get-CADryRun' -Because "a dry run previews and issues nothing"

$srcWrite = (Get-Command Write-CAHandoffFiles).Definition
Assert-Match -Actual $srcWrite -Pattern 'Invoke-CAStep' -Because "the file writes are dry-run aware"
Assert-Match -Actual $srcWrite -Pattern '_CAResponse\.json' -Because "it writes the hand-back JSON"
Assert-NoMatch -Actual $srcWrite -Pattern 'Set-Content[^\r\n]*txt' -Because "it writes no CLI file any more (Schema 4)"
Assert-Match -Actual $srcWrite -Pattern 'Remove-Item -Path \$staleTxt' -Because "and removes an old _FortiGate_CertSetup.txt left by an earlier run, so it can't be applied by mistake"

$srcPure = (Get-Command Get-CAResponseObject).Definition
Assert-NoMatch -Actual $srcPure -Pattern 'Invoke-CAStep|Set-Content|New-Item|Get-Certificate|Restart-Service' -Because "Get-CAResponseObject is PURE"

$srcMenu = (Get-Command Invoke-CAMenuHandoff).Definition
foreach ($needle in 'Write-CAHeader', 'New-CAFortiGateIdentityCert', 'New-CAFortiGateCertFromCsr', 'Get-CAOcspCACertBytes', 'ConvertTo-CAPem', 'Get-CAResponseObject', 'Write-CAHandoffFiles', 'Get-CAAnswerOrPrompt') {
    Assert-Match -Actual $srcMenu -Pattern ([regex]::Escape($needle)) -Because "Invoke-CAMenuHandoff calls $needle"
}
Assert-Match -Actual $srcMenu -Pattern 'Path \(blank = generate a PFX\)' -Because "menu 13 takes a CSR / an issued cert / blank for the FortiGate identity"
Assert-Match -Actual $srcMenu -Pattern 'Import-CAFortiGateIssuedCert' -Because "an already-issued .cer/.pem is wrapped into the hand-off as-is"
Assert-Match -Actual $srcMenu -Pattern '\[Convert\]::ToBase64String\(\[System\.IO\.File\]::ReadAllBytes\(\$fg\.PfxPath\)\)' -Because "reads the generated PFX's own bytes and base64-encodes them for the single-file hand-back"
Assert-Match -Actual $srcMenu -Pattern '-FortiGatePfxBase64 \$fgPfxBase64' -Because "and threads that through to Get-CAResponseObject"
Assert-Match -Actual $srcMenu -Pattern 'Test-CAIsCsr -Path \$inPath.*Read-CAX509 -Path \$inPath' -Because "CSR markers win; otherwise anything that parses (DER or PEM) is the issued cert"

# ---------------------------------------------------------------------------
# 2a. 2026-09-15, per the maintainer: "can we add a 'back'/'main menu' option here? and anywhere else we've
#     missed it" - the company-name prompt (only reached when Company_Name isn't already known/
#     staged) is this wizard's own very first prompt, with nothing earlier to step back to WITHIN
#     the wizard - -AllowBack here must mean "cancel out of menu 13 entirely." Functional, using the
#     REAL Read-CANonEmpty/Test-CABackSignal (CAInteractive.ps1, already dot-sourced above) - not
#     just a source-pattern check - to prove it actually returns before doing anything else.
# ---------------------------------------------------------------------------
Assert-Match -Actual $srcMenu -Pattern "Read-CANonEmpty -Prompt `"Company name \(for the file names\)`" -AllowBack" -Because "the company-name prompt is back-aware"
Assert-Match -Actual $srcMenu -Pattern 'if \(Test-CABackSignal \$company\) \{[\s\S]{0,80}?return \}' -Because "and a 'B' answer there returns out of the whole menu, not just clearing the prompt"

$script:__peerPlanCalled = $false
function Get-CAFortiGatePeerPlan { param($CAAnswers) $script:__peerPlanCalled = $true; [pscustomobject]@{ Applicable = $false } }
function Write-CAHeader { param($Title) }
$script:__rhQ2 = [System.Collections.Generic.Queue[string]]::new()
$script:__rhQ2.Enqueue('B')
function Read-Host { param([string]$Prompt) if ($script:__rhQ2.Count -eq 0) { throw "Read-Host queue empty (prompt: '$Prompt')" } $script:__rhQ2.Dequeue() }
$noCompanyAnswers = [pscustomobject]@{}   # no Company_Name property at all
Invoke-CAMenuHandoff -CAAnswers $noCompanyAnswers -Status ([pscustomobject]@{ CACommonName = 'CONTOSO-VPN'; IssuanceReady = $true }) -CAManagerVersion '2026-09-15'
Assert-False -Condition $script:__peerPlanCalled -Because "'B' at the company-name prompt returns immediately - Get-CAFortiGatePeerPlan (and everything after it) never runs"
Assert-Equal -Actual $script:__rhQ2.Count -Expected 0 -Because "exactly the one prompt was consumed - cancelling doesn't fall through to any wizard step"
Remove-Item function:Get-CAFortiGatePeerPlan, function:Write-CAHeader, function:Read-Host -ErrorAction SilentlyContinue
# Removing a mock does NOT restore whatever it shadowed (PowerShell's function: drive isn't a stack) -
# every test section below this point needs the REAL Get-CAFortiGatePeerPlan, so re-dot-source it now.
. "$Mod\CAFortiGateHandoff.ps1"

# ---------------------------------------------------------------------------
# 2b. 2026-09-15 real live bug at CLIENTA - menu 13's wizard steps used .GetNewClosure(), which
#     detaches a scriptblock into its own session state that only chains up to GLOBAL scope (plus
#     its captured variables) - NOT through an intermediate SCRIPT scope. Invisible when
#     CA-Manager.ps1 is dot-sourced or run directly (as every other test in this suite does), but
#     the REAL shim (CA-Manager-Shim.ps1) launches the staged dashboard via the call operator
#     (`& $RealDashboard`) - a genuine extra scope boundary - and under THAT real invocation shape,
#     every closured step threw "Get-CAAnswerOrPrompt is not recognized" even though
#     Invoke-CAWizardSteps itself (same file, no GetNewClosure()) resolved fine. A static grep alone
#     can't prove the FIX works (it only proves the symptom-string is gone) - this repro actually
#     spawns a nested process wrapped in `&`, matching the shim's real invocation shape, using the
#     REAL Invoke-CAWizardSteps + Get-CAAnswerOrPrompt (CAInteractive.ps1) and a plain (non-closured)
#     step scriptblock - the exact pattern every wizard step in this file now follows.
# ---------------------------------------------------------------------------
$rawHandoff = Get-Content -Path "$Mod\CAFortiGateHandoff.ps1" -Raw
# The actual CALL SHAPE, not a bare substring - this file's own doc-comment above now explains the
# GetNewClosure() bug in prose (mentioning the word itself several times), which a bare substring
# check would false-fail against.
Assert-NoMatch -Actual $rawHandoff -Pattern '\}\.GetNewClosure\(\)' -Because "no wizard step in this file calls GetNewClosure() on itself any more - it's what broke every one of them under the real `&`-wrapped shim"

$reproDir = Join-Path $env:TEMP ("fgh_repro_" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $reproDir -Force | Out-Null
try {
    # The real engine, dot-sourced under its own real name/path - not reinvented.
    Copy-Item -Path "$Mod\CAInteractive.ps1" -Destination (Join-Path $reproDir 'CAInteractive.ps1') -Force
    Set-Content -Path (Join-Path $reproDir 'inner.ps1') -Value @'
. (Join-Path $PSScriptRoot "CAInteractive.ps1")
# Simulates a blank Enter at the prompt - Get-CAAnswerOrPrompt's -Default then supplies the value,
# so this never actually blocks on real console input.
function Read-Host { param($Prompt) '' }
function Invoke-TestWizard {
    $CAAnswers = [pscustomobject]@{}
    $steps = @(
        @{ Name = 'CertName'; Run = {
            param($CanGoBack)
            Get-CAAnswerOrPrompt -CAAnswers $CAAnswers -Field 'Cert_CertificateName' -Prompt "x" -Default 'DEFAULT_VAL' -AllowBack:$CanGoBack
        } }
    )
    Invoke-CAWizardSteps -Steps $steps
}
$r = Invoke-TestWizard
Write-Output "RESULT:$($r.CertName)"
'@ -Force
    Set-Content -Path (Join-Path $reproDir 'shim.ps1') -Value '& (Join-Path $PSScriptRoot "inner.ps1")' -Force

    $out = & powershell.exe -NoProfile -NonInteractive -File (Join-Path $reproDir 'shim.ps1') 2>&1
    $outText = ($out | Out-String)
    Assert-NoMatch -Actual $outText -Pattern 'is not recognized' -Because "under the REAL shim's `&`-wrapped invocation shape, the fixed (non-closured) wizard-step pattern must NOT throw 'term is not recognized' calling a sibling module's function - this is the exact live crash, reproduced and disproven"
    Assert-Match    -Actual $outText -Pattern 'RESULT:DEFAULT_VAL' -Because "and the step actually completes and returns the expected value, not just 'didn't crash'"
} finally {
    Remove-Item -Path $reproDir -Recurse -Force -ErrorAction SilentlyContinue
}

# Read-CAX509 handles a base64 PEM (WinPS X509Certificate2(string) is DER-only)
Invoke-Expression (Get-FunctionSource -Path "$Mod\CAFortiGateHandoff.ps1" -FunctionName 'Read-CAX509')
Invoke-Expression (Get-FunctionSource -Path "$Mod\CAFortiGateHandoff.ps1" -FunctionName 'Test-CAIsCsr')
$pemTmp = Join-Path $env:TEMP ("x_" + [guid]::NewGuid().ToString('N') + ".pem")
# a real self-signed cert -> PEM
$sc = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
        'CN=fc-test', [System.Security.Cryptography.RSA]::Create(2048),
        [System.Security.Cryptography.HashAlgorithmName]::SHA256,
        [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
      ).CreateSelfSigned([DateTimeOffset]::UtcNow.AddDays(-1), [DateTimeOffset]::UtcNow.AddDays(1))
$b64 = [Convert]::ToBase64String($sc.RawData) -replace '(.{64})', "`$1`n"
Set-Content -Path $pemTmp -Value "-----BEGIN CERTIFICATE-----`n$b64`n-----END CERTIFICATE-----" -Force
try {
    $back = Read-CAX509 -Path $pemTmp
    Assert-True  -Condition ([bool]$back -and $back.Subject -eq 'CN=fc-test') -Because "Read-CAX509 decodes a base64 PEM file"
    Assert-False -Condition (Test-CAIsCsr -Path $pemTmp) -Because "a cert PEM is not a CSR"
    $csrTmp = Join-Path $env:TEMP ("r_" + [guid]::NewGuid().ToString('N') + ".req")
    Set-Content -Path $csrTmp -Value "-----BEGIN NEW CERTIFICATE REQUEST-----`nAAAA`n-----END NEW CERTIFICATE REQUEST-----" -Force
    Assert-True  -Condition (Test-CAIsCsr -Path $csrTmp) -Because "a CSR is spotted by its request markers"
    Assert-True  -Condition ($null -eq (Read-CAX509 -Path $csrTmp)) -Because "a CSR does not parse as a certificate"
    Remove-Item $csrTmp -Force -ErrorAction SilentlyContinue
} finally {
    Remove-Item $pemTmp -Force -ErrorAction SilentlyContinue
}

# CSR flow: certreq submit/retrieve, PEM out, no PFX
$srcCsr = (Get-Command New-CAFortiGateCertFromCsr).Definition
Assert-Match -Actual $srcCsr -Pattern 'certreq\.exe -submit .*-attrib "CertificateTemplate:' -Because "submits the CSR with the template attribute (runs as the admin - works for a machine/admin-only template)"
Assert-Match -Actual $srcCsr -Pattern '''-config'', \$CAConfig' -Because "passes -config so certreq submits directly (the CA-picker GUI drops the -attrib -> CERTSRV_E_NO_CERT_TYPE)"
Assert-Match -Actual $srcCsr -Pattern 'certreq\.exe -retrieve' -Because "retrieves after approval"
Assert-Match -Actual $srcCsr -Pattern 'ConvertTo-CAPem' -Because "hands back the signed cert as PEM"
Assert-Match -Actual $srcCsr -Pattern 'Invoke-CAStep' -Because "dry-run aware"
Assert-NoMatch -Actual $srcCsr -Pattern 'Export-PfxCertificate|PfxPassword' -Because "no PFX / password - the private key never leaves the FortiGate"

$respPem = Get-CAResponseObject -CAAnswers $ans -CACommonName 'Contoso-Issuing-CA' -CASanitizedName 'Contoso-Issuing-CA' `
    -FgCert ([pscustomobject]@{ CertPem = "-----BEGIN CERTIFICATE-----`nQ0VSVA==`n-----END CERTIFICATE-----"; PfxPath = $null; Password = $null; Thumbprint = 'FE01' }) -PeerSubjectFilter ''
Assert-Equal  -Actual $respPem.FortiGateCertPem -Expected "-----BEGIN CERTIFICATE-----`nQ0VSVA==`n-----END CERTIFICATE-----" -Because "the signed-cert PEM rides in the hand-back"
Assert-True   -Condition ($null -eq $respPem.FortiGatePfxFile -and $null -eq $respPem.FortiGatePfxPassword) -Because "no PFX for the CSR flow"

# ---------------------------------------------------------------------------
# 6. Get-CAFortiGatePeerPlan (2026-09-15) - one config user peer per RadiusGroupPair, bundled into
#    one peergrp, per the maintainer's CLIENTA live-troubleshooting ask: "I want a peer for each of the groups,
#    but NOT the VPNFW groups."
# ---------------------------------------------------------------------------
$tmcAns = [pscustomobject]@{
    CA_SubjectStampMode = 'TameMyCerts'
    RadiusGroupPairs = @(
        [pscustomobject]@{ Label = 'CLIENTA';  UserGroupValue = 'ikev2_corplan_users' }
        [pscustomobject]@{ Label = 'Audit';  UserGroupValue = 'ikev2_audit_users' }
        [pscustomobject]@{ Label = 'DIv2-RedStone'; UserGroupValue = 'ikev2_redstone_users' }
        # The three VPNFW/AS400 pairs - IncludeInNPSImport:false, same signal
        # OrchestratorImport.ps1's own NPS-Manager import already uses to skip these (CLIBuilder's
        # Custom App-Access Rules flow defaults new pairs to this) - MUST be excluded from the peer plan.
        [pscustomobject]@{ Label = 'DIv2-BackupAS400'; UserGroupName = 'VPNFW_Hangar_AS400'; UserGroupValue = 'vpnfw_hangar_as400'; IncludeInNPSImport = $false }
        [pscustomobject]@{ Label = 'DIv2_AS400_ComEdge'; UserGroupValue = 'vpnfw_as400_comedge_fullaccess'; IncludeInNPSImport = $false }
        [pscustomobject]@{ Label = 'DIv2_AS400'; UserGroupValue = 'vpnfw_as400_fullaccess'; IncludeInNPSImport = $false }
    )
}
$peerPlan = Get-CAFortiGatePeerPlan -CAAnswers $tmcAns
Assert-True  -Condition $peerPlan.Applicable -Because "TameMyCerts + at least one qualifying RadiusGroupPair -> applicable"
Assert-Equal -Actual $peerPlan.PeerGroupName -Expected 'IKEv2_DIv2_AllowedPeers' -Because "The maintainer's own naming (2026-09-15), the default"
Assert-Equal -Actual $peerPlan.Peers.Count -Expected 3 -Because "3 qualifying pairs (CLIENTA/Audit/DIv2-RedStone) - the 3 VPNFW/AS400 pairs are excluded"
Assert-False -Condition ([bool]($peerPlan.Peers | Where-Object { $_.PeerName -like '*AS400*' -or $_.PeerName -like '*Hangar*' })) -Because "none of the excluded VPNFW pairs leaked through under any name"

$clientaPeer = $peerPlan.Peers | Where-Object GroupLabel -eq 'CLIENTA'
Assert-Equal -Actual $clientaPeer.PeerName -Expected 'P_IKEv2_DIv2_CLIENTA' -Because "default prefix 'P_IKEv2_DIv2_' (2026-09-15, per the maintainer: 'P_' marks a peer object at a glance, same spirit as CA certs' 'CA_') + the pair's own Label"
Assert-Equal -Actual $clientaPeer.OuValue  -Expected 'ikev2_corplan_users' -Because "OU token = the real AD group (UserGroupValue), matching TameMyCerts's own stamp exactly - unaffected by the peer NAME prefix"

$redstonePeer = $peerPlan.Peers | Where-Object GroupLabel -eq 'DIv2-RedStone'
Assert-Equal -Actual $redstonePeer.PeerName -Expected 'P_IKEv2_DIv2_RedStone' -Because "a Label that already carries its own 'DIv2-' marker has that redundant prefix stripped, not doubled into 'P_IKEv2_DIv2_DIv2-RedStone'"

# a pair saved before IncludeInNPSImport existed (the property is simply absent) is still included -
# same "absent = treat as true" rule OrchestratorImport.ps1 already established
$legacyPairAns = [pscustomobject]@{
    CA_SubjectStampMode = 'TameMyCerts'
    RadiusGroupPairs = @([pscustomobject]@{ Label = 'Legacy'; UserGroupValue = 'ikev2_legacy_users' })
}
$legacyPlan = Get-CAFortiGatePeerPlan -CAAnswers $legacyPairAns
Assert-Equal -Actual $legacyPlan.Peers.Count -Expected 1 -Because "a pair with no IncludeInNPSImport property at all (saved before that field existed) is still included, not silently dropped"

# not TameMyCerts, or no RadiusGroupPairs at all -> not applicable, empty peer list
Assert-False -Condition (Get-CAFortiGatePeerPlan -CAAnswers ([pscustomobject]@{ RadiusGroupPairs = $tmcAns.RadiusGroupPairs })).Applicable -Because "no CA_SubjectStampMode=TameMyCerts -> not applicable, even with real pairs present"
Assert-False -Condition (Get-CAFortiGatePeerPlan -CAAnswers ([pscustomobject]@{ CA_SubjectStampMode = 'TameMyCerts' })).Applicable -Because "no RadiusGroupPairs -> not applicable"
Assert-False -Condition (Get-CAFortiGatePeerPlan -CAAnswers $ans).Applicable -Because "a plain non-TameMyCerts client (this file's own `$ans, used throughout) is never applicable - the legacy single-peer path stays exactly as it was"

$srcPeerPlan = (Get-Command Get-CAFortiGatePeerPlan).Definition
Assert-Match   -Actual $srcPeerPlan -Pattern 'ConvertTo-CATameMyCertsToken' -Because "OU tokens are derived via the SAME function TameMyCerts itself uses - can never drift from the real stamp"
Assert-NoMatch -Actual $srcPeerPlan -Pattern 'Invoke-CAStep|New-Item|Set-ItemProperty|certutil' -Because "Get-CAFortiGatePeerPlan is PURE"

# ---------------------------------------------------------------------------
# 6b. The peer plan rides in the hand-back (CLIBuilder renders the peer/peergrp CLI from it)
# ---------------------------------------------------------------------------
$tmcResp = Get-CAResponseObject -CAAnswers $tmcAns -CACommonName 'CONTOSO-VPN' -CASanitizedName 'CONTOSO-VPN' -PeerSubjectFilter ''
Assert-True -Condition $tmcResp.PeerPlan.Applicable -Because "the response object carries the computed peer plan"
Assert-Equal -Actual (@($tmcResp.PeerPlan.Peers | ForEach-Object PeerName) -join ',') -Expected 'P_IKEv2_DIv2_CLIENTA,P_IKEv2_DIv2_Audit,P_IKEv2_DIv2_RedStone' -Because "the hand-back carries every qualifying pair's peer, in order, for CLIBuilder to render"



# ---------------------------------------------------------------------------
# 6c. Get-CAFortiGateParentCertChain (2026-09-15) - "capture the whole chain (public certs) for the
#     issuing CA (so if it's subordinate, get the parent CA cert too, make sure it's the latest
#     cert)". A real self-signed X509Certificate2 exercises the fast path with no cert-store I/O at
#     all (installing even a throwaway cert into a trust store pops a real Windows security prompt -
#     never do that from an automated test). The Build()-based parent-walk itself (unresolvable/
#     multi-tier cases) is covered by source-introspection instead, matching this file's own
#     established convention for raw-crypto/ADSI functions that "won't run [meaningfully] without a
#     live directory/store" (see section 3's own note in CAManager.Phase4Engines.Tests.ps1).
# ---------------------------------------------------------------------------
$selfSignedKey = [System.Security.Cryptography.RSA]::Create(2048)
$selfSignedReq = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
    'CN=Test Standalone Root CA', $selfSignedKey,
    [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
$selfSignedCert = $selfSignedReq.CreateSelfSigned([DateTimeOffset]::UtcNow.AddDays(-1), [DateTimeOffset]::UtcNow.AddYears(5))
$rootParents = Get-CAFortiGateParentCertChain -IssuingCert $selfSignedCert
Assert-Equal -Actual @($rootParents).Count -Expected 0 -Because "a self-signed (root/standalone) issuing CA has nothing above it - Subject equals Issuer, short-circuits before ever calling X509Chain.Build()"

$srcParentChain = (Get-Command Get-CAFortiGateParentCertChain).Definition
Assert-Match -Actual $srcParentChain -Pattern '\$IssuingCert\.Subject -eq \$IssuingCert\.Issuer' -Because "the self-signed fast-path check is really there, not just true by accident in the test above"
Assert-Match -Actual $srcParentChain -Pattern 'RevocationMode = \[System\.Security\.Cryptography\.X509Certificates\.X509RevocationMode\]::NoCheck' -Because "captures the structural chain of public certs - this is not a revocation check, and must never block/hang on CRL/OCSP network access"
Assert-Match -Actual $srcParentChain -Pattern 'AllowUnknownCertificateAuthority' -Because "an internal PKI's own root is never in the Windows trusted-root store - chain building must not refuse to walk past it for that reason alone"
Assert-Match -Actual $srcParentChain -Pattern '(?s)try \{.*chain\.Build\(\$IssuingCert\).*\} catch \{ return @\(\) \}' -Because "fails soft (empty array, not a thrown exception) if the parent can't be resolved locally at all - the hand-off is then no worse than before this function existed"
Assert-Match -Actual $srcParentChain -Pattern 'for \(\$i = 1;' -Because "starts at index 1, not 0 - ChainElements[0] is the issuing cert itself, which the caller already has via CACertPem/CACertNameOnGate and must not be duplicated here"
Assert-Match -Actual $srcParentChain -Pattern 'CA_Parent\$i' -Because "falls back to an index-based name if a tier's own CN can't be extracted, rather than failing the whole capture over one unreadable tier's display name"

# --- wiring: Get-CAResponseObject carries an EMPTY chain for the common root/standalone-CA case ---
$respNoChain = Get-CAResponseObject -CAAnswers $ans -CACommonName 'CONTOSO-VPN' -CASanitizedName 'CONTOSO-VPN' -PeerSubjectFilter ''
Assert-Equal -Actual @($respNoChain.CACertChain).Count -Expected 0 -Because "CACertChain defaults to empty when the caller doesn't pass one - Schema 3's new field is additive, never breaks an existing call site"

# --- wiring: a non-empty chain rides through with each parent's own Name + PEM ---
$fakeChain = @(
    [pscustomobject]@{ Name = 'CA_TestIntermediate'; Pem = '-----BEGIN CERTIFICATE-----INTERMEDIATE-----END CERTIFICATE-----' }
    [pscustomobject]@{ Name = 'CA_TestRoot';         Pem = '-----BEGIN CERTIFICATE-----ROOT-----END CERTIFICATE-----' }
)
$respChain = Get-CAResponseObject -CAAnswers $ans -CACommonName 'CONTOSO-VPN' -CASanitizedName 'CONTOSO-VPN' -CACertPem 'ISSUING-PEM' -CACertChain $fakeChain -PeerSubjectFilter ''
Assert-Equal -Actual @($respChain.CACertChain).Count -Expected 2 -Because "both parent tiers ride through Get-CAResponseObject unchanged"
Assert-Equal -Actual (@($respChain.CACertChain | ForEach-Object Name) -join ',') -Expected 'CA_TestIntermediate,CA_TestRoot' -Because "in order, each under its own resolved name"

# ---------------------------------------------------------------------------
# 6d. 2026-09-30, per the maintainer: "not being able to hit the other items without re-requesting a
#     FortiGate cert is my main concern" - re-running menu 13 reuses the identity cert from the last
#     hand-back in the output folder (Enter), or makes a new one (N). Warn-and-continue checks.
# ---------------------------------------------------------------------------
$now = Get-Date
$idOk = [pscustomobject]@{ Subject = 'CN=Contoso-FGT'; NotAfter = $now.AddYears(1) }
Assert-Equal -Actual @(Get-CAHandoffIdentityWarnings -Identity $idOk -CertName 'Contoso-FGT' -Now $now).Count -Expected 0 -Because "a current cert with the right CN reuses without warnings"
$idBad = [pscustomobject]@{ Subject = 'CN=Old-FGT'; NotAfter = $now.AddDays(-1) }
$badWarnings = @(Get-CAHandoffIdentityWarnings -Identity $idBad -CertName 'Contoso-FGT' -Now $now -Revoked $true)
Assert-Equal -Actual $badWarnings.Count -Expected 3 -Because "CN mismatch, expired, and revoked each warn"
Assert-Match -Actual ($badWarnings -join ' ') -Pattern 'not CN=Contoso-FGT.*expired.*REVOKED' -Because "...naming what's wrong"
Assert-Match -Actual ((Get-CAHandoffIdentityWarnings -Identity ([pscustomobject]@{ Subject = 'CN=Contoso-FGT'; NotAfter = $now.AddDays(10) }) -CertName 'Contoso-FGT' -Now $now) -join ' ') -Pattern 'within 30 days' -Because "a cert expiring within 30 days warns"
Assert-Match -Actual (Get-Command Test-CAHandoffCertRevoked).Definition -Pattern "'-view', '-restrict', `"SerialNumber=" -Because "revocation is read from this CA's database by serial number"

# Functional: an older (Schema 3) hand-back with a real PFX sits in the output folder, alongside the
# old CLI file. Only the CA-box lookups are stubbed; the wizard, reuse, response, and write are real.
$reuseDir = Join-Path $env:TEMP ("fgreuse_" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $reuseDir -Force | Out-Null
try {
    $fgKey = [System.Security.Cryptography.RSA]::Create(2048)
    $fgCert = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new('CN=Contoso-FGT', $fgKey,
        [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
    ).CreateSelfSigned([DateTimeOffset]::UtcNow.AddDays(-1), [DateTimeOffset]::UtcNow.AddYears(1))
    $pfxB64 = [Convert]::ToBase64String($fgCert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pkcs12, 'pw-123'))
    [pscustomobject]@{ Schema = 3; Company = 'Contoso Ltd'; FortiGateCertName = 'Contoso-FGT'; FortiGatePfxFile = 'ContosoLtd_FortiGate.pfx'
        FortiGatePfxPassword = 'pw-123'; FortiGatePfxBase64 = $pfxB64; FortiGateCertThumbprint = $fgCert.Thumbprint } |
        ConvertTo-Json | Set-Content -Path (Join-Path $reuseDir 'ContosoLtd_CAResponse.json') -Encoding UTF8
    Set-Content -Path (Join-Path $reuseDir 'ContosoLtd_FortiGate_CertSetup.txt') -Value 'old CLI'

    $prev = Get-CAHandoffIdentity -OutputDir $reuseDir -CompanyStem 'ContosoLtd'
    Assert-Equal -Actual $prev.Thumbprint -Expected $fgCert.Thumbprint -Because "the last hand-back's PFX is read back (from its embedded base64)"
    Assert-True -Condition (Test-Path (Join-Path $reuseDir 'ContosoLtd_FortiGate.pfx')) -Because "...and written out next to the JSON, so the reused PfxPath is real"
    Assert-Equal -Actual (Get-CAHandoffIdentity -OutputDir (Join-Path $reuseDir 'none') -CompanyStem 'ContosoLtd') -Expected $null -Because "no earlier hand-back -> nothing to reuse"

    $caKey = [System.Security.Cryptography.RSA]::Create(2048)
    $caCert = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new('CN=Contoso-Issuing-CA', $caKey,
        [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
    ).CreateSelfSigned([DateTimeOffset]::UtcNow.AddDays(-1), [DateTimeOffset]::UtcNow.AddYears(5))
    $script:__newIdentityCalls = 0
    function Write-CAHeader { param($Title) }
    function Get-CAActiveConfigName { 'Contoso-Issuing-CA' }
    function Get-CAOcspCACertBytes { param($CACommonName) $caCert.RawData }
    function Test-CAHandoffCertRevoked { param($SerialNumber) $false }
    function Resolve-VPNCertTemplateName { param($Name) $Name }
    function New-CAFortiGateIdentityCert { param($CAAnswers, $OutputDir, $CASanitizedName, $FortiGateFqdn) $script:__newIdentityCalls++; [pscustomobject]@{ PfxPath = $null; Password = 'new'; Thumbprint = 'NEW'; SerialNumber = '02'; Status = 'Issued' } }
    $script:__rhQ3 = [System.Collections.Generic.Queue[string]]::new()
    function Read-Host { param([string]$Prompt) if ($script:__rhQ3.Count -eq 0) { throw "Read-Host queue empty (prompt: '$Prompt')" } $script:__rhQ3.Dequeue() }
    $wasDry = Get-CADryRun
    Set-CADryRun -Enabled $false
    $reuseAnswers = [pscustomobject]@{ Company_Name = 'Contoso Ltd'; Cert_CertificateName = 'Contoso-FGT'; Cert_PeerName = 'Contoso-peer'; Cert_PeerSubjectFilter = 'OU=VPN Users' }
    try {
        # Enter at the reuse prompt: output folder, [Enter] reuse, Press Enter.
        foreach ($a in @($reuseDir, '', '')) { $script:__rhQ3.Enqueue($a) }
        Invoke-CAMenuHandoff -CAAnswers $reuseAnswers -Status ([pscustomobject]@{ CACommonName = 'Contoso-Issuing-CA'; IssuanceReady = $true }) -CAManagerVersion '1.1.0' *> $null
        Assert-Equal -Actual $script:__newIdentityCalls -Expected 0 -Because "reusing the last FortiGate cert requests nothing new"
        Assert-Equal -Actual $script:__rhQ3.Count -Expected 0 -Because "only the output folder and the reuse choice are asked (names + filter come from the answers)"
        $newResp = Get-Content (Join-Path $reuseDir 'ContosoLtd_CAResponse.json') -Raw | ConvertFrom-Json
        Assert-Equal -Actual $newResp.Schema -Expected 4 -Because "the rebuilt hand-back is Schema 4"
        Assert-Equal -Actual $newResp.FortiGatePfxBase64 -Expected $pfxB64 -Because "the same PFX rides in the rebuilt hand-back"
        Assert-Equal -Actual $newResp.FortiGatePfxPassword -Expected 'pw-123' -Because "...with its original password"
        Assert-Equal -Actual $newResp.FortiGateCertThumbprint -Expected $fgCert.Thumbprint -Because "...and thumbprint"
        Assert-Match -Actual $newResp.CACertPem -Pattern 'BEGIN CERTIFICATE' -Because "everything else is rebuilt from the CA (its cert is refreshed)"
        Assert-False -Condition ([bool]$newResp.PSObject.Properties['FortiGateCertSetupText']) -Because "no rendered CLI in the rebuilt hand-back"
        Assert-False -Condition (Test-Path (Join-Path $reuseDir 'ContosoLtd_FortiGate_CertSetup.txt')) -Because "the old CLI file is removed from the output folder"

        # N at the reuse prompt: output folder, N, blank path (generate), blank FQDN, Press Enter.
        foreach ($a in @($reuseDir, 'N', '', '', '')) { $script:__rhQ3.Enqueue($a) }
        Invoke-CAMenuHandoff -CAAnswers $reuseAnswers -Status ([pscustomobject]@{ CACommonName = 'Contoso-Issuing-CA'; IssuanceReady = $true }) -CAManagerVersion '1.1.0' *> $null
        Assert-Equal -Actual $script:__newIdentityCalls -Expected 1 -Because "N makes a new FortiGate cert (the FQDN is asked only on this path)"
        Assert-Equal -Actual $script:__rhQ3.Count -Expected 0 -Because "the new-cert path asks path + FQDN on top"
    } finally {
        Set-CADryRun -Enabled $wasDry
        Remove-Item function:Write-CAHeader, function:Get-CAActiveConfigName, function:Get-CAOcspCACertBytes, function:Test-CAHandoffCertRevoked, function:Resolve-VPNCertTemplateName, function:New-CAFortiGateIdentityCert, function:Read-Host -ErrorAction SilentlyContinue
    }
} finally {
    Remove-Item -Path $reuseDir -Recurse -Force -ErrorAction SilentlyContinue
}

# ---------------------------------------------------------------------------
# 7. Dashboard wiring
# ---------------------------------------------------------------------------
$rawDash = Get-Content $Dashboard -Raw
Assert-True -Condition (Test-Path "$PKIModuleRoot\Private\CAFortiGateHandoff.ps1") -Because "NSP.PKI: the module loader dot-sources every Private\*.ps1 (was: the dashboard dot-sources the module)"
Assert-Match -Actual $rawDash -Pattern "'\^13\`$'\s*\{[\s\S]*?Invoke-CAMenuHandoff" -Because "menu 13 (2026-09-12 renumber - was menu 14, shifted down after the GPO menu's removal) dispatches to Invoke-CAMenuHandoff"

Write-TestSummary -Suite "CA Manager - menu 13 (FortiGate cert hand-off)"
