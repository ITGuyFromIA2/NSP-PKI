# Ported from NSP-FGTIPSecTools Tests\CAManager.CrlShare.Tests.ps1 (2026-10-01): same assertions, paths re-pointed at
# this module's Private\ files. Run by Tests\Legacy.Tests.ps1 (Pester) in a child PowerShell.
<#
.SYNOPSIS
    Tests for CA Manager - menu 7 (2026-09-10 renumber - was menu 6; CRL distribution share). The
    PURE Get-CACrlSharePlan (mode gating + CLIENTA-verbatim ACL shape), and source-introspection that
    New-CACrlShare routes through Invoke-CAStep.

    Repo convention (Tests\README.md) - NOT Pester.
#>

. "$PSScriptRoot\..\Shared\TestAssertions.ps1"
$PKIModuleRoot = (Resolve-Path "$PSScriptRoot\..\..").Path
Reset-TestCounters

$Root = "C:\GitRepo\NSP-FGTIPSecTools"
$Mod  = "$PKIModuleRoot\Private"
$Dashboard = "$PKIModuleRoot\Tests\Legacy\_CA-Manager.combined.ps1"

Test-ScriptParses -Path "$Mod\CACrlShare.ps1" -Because "CACrlShare.ps1 parses"
Test-ScriptParses -Path $Dashboard            -Because "CA-Manager.ps1 parses after wiring menu 7"

. "$Mod\CACore.ps1"
. "$Mod\CACrlShare.ps1"

# ---------------------------------------------------------------------------
# 1. Get-CACrlSharePlan - mode gating
# ---------------------------------------------------------------------------
$none = Get-CACrlSharePlan -CAAnswers ([pscustomobject]@{ CA_CrlShareMode = 'None' })
Assert-False -Condition $none.Applicable -Because "CA_CrlShareMode None -> not applicable (single-tier co-located)"
Assert-Match -Actual $none.Reason -Pattern 'single-tier' -Because "the no-op reason names the topology"

$blank = Get-CACrlSharePlan -CAAnswers ([pscustomobject]@{})
Assert-False -Condition $blank.Applicable -Because "absent CA_CrlShareMode defaults to None"

# ---------------------------------------------------------------------------
# 2. Get-CACrlSharePlan - RootCrlPublish, CLIENTA-shaped
# ---------------------------------------------------------------------------
$ans = [pscustomobject]@{ CA_CrlShareMode = 'RootCrlPublish'; CA_CrlSharePath = 'C:\CRLShare'; CA_CrlShareWriteGroup = 'CA_MainCAServer' }
$p = Get-CACrlSharePlan -CAAnswers $ans -CAMachineName 'CONTOSO-RADIUS'
Assert-True  -Condition $p.Applicable -Because "split-tier -> applicable"
Assert-Equal -Actual $p.ShareName -Expected 'CRLShare' -Because "share name is the path leaf"
Assert-Equal -Actual $p.LocalPath -Expected 'C:\CRLShare' -Because "local path from CA_CrlSharePath"
Assert-Equal -Actual $p.UncPath -Expected '\\CONTOSO-RADIUS\CRLShare' -Because "UNC composed from the CA machine name + share"
Assert-Equal -Actual $p.WriteGroup -Expected 'CA_MainCAServer' -Because "write group from CA_CrlShareWriteGroup"
Assert-Equal -Actual $p.ShareAccess.Right -Expected 'Full' -Because "the write group gets Full at the share level (CLIENTA: the only non-default share ACE)"
$appPkg = $p.NtfsAces | Where-Object { $_.Account -eq 'ALL APPLICATION PACKAGES' }
Assert-True  -Condition ([bool]$appPkg) -Because "ALL APPLICATION PACKAGES gets an NTFS ACE (lets the co-located IIS/App Proxy worker read the .crl/.crt - CLIENTA)"
Assert-Match -Actual $appPkg.Right -Pattern 'RX' -Because "and it's read+execute only"
Assert-Equal -Actual $p.InfraGroupMember -Expected 'CONTOSO-RADIUS$' -Because "the publishing CA's machine account is the group member"
Assert-Equal -Actual $p.InfraGroupSamName -Expected 'CA_MainCAServer' -Because "sam-name is the sanitised write-group name"

# default write group when unset
$p2 = Get-CACrlSharePlan -CAAnswers ([pscustomobject]@{ CA_CrlShareMode = 'SegregatedProxy' })
Assert-Equal -Actual $p2.WriteGroup -Expected 'CA_CRLPublishers' -Because "write group defaults to CA_CRLPublishers"
Assert-Equal -Actual $p2.LocalPath -Expected 'C:\CRLShare' -Because "share path defaults to C:\CRLShare"

# bare-UNC answer -> LocalPath null (share lives elsewhere)
$p3 = Get-CACrlSharePlan -CAAnswers ([pscustomobject]@{ CA_CrlShareMode = 'RootCrlPublish'; CA_CrlSharePath = '\\OtherBox\CRLShare' })
Assert-True  -Condition ($null -eq $p3.LocalPath) -Because "a bare UNC path means the share is on another host"
Assert-Equal -Actual $p3.UncPath -Expected '\\OtherBox\CRLShare' -Because "the UNC is kept as given"

# ---------------------------------------------------------------------------
# 3. New-CACrlShare - source-introspection
# ---------------------------------------------------------------------------
$src = (Get-Command New-CACrlShare).Definition
Assert-Match -Actual $src -Pattern 'Invoke-CAStep' -Because "every mutation is dry-run aware"
Assert-Match -Actual $src -Pattern 'New-SmbShare' -Because "it creates the SMB share"
Assert-Match -Actual $src -Pattern 'Grant-SmbShareAccess' -Because "and grants the write group Full"
Assert-Match -Actual $src -Pattern 'icacls' -Because "NTFS ACEs applied via icacls (previewable)"
Assert-Match -Actual $src -Pattern 'New-ADGroup' -Because "it ensures the infra AD group"
Assert-Match -Actual $src -Pattern 'Add-ADGroupMember' -Because "and adds the CA machine account"
Assert-Match -Actual $src -Pattern 'if \(-not \$Plan\.Applicable\)' -Because "it no-ops for a non-applicable plan"

$srcPure = (Get-Command Get-CACrlSharePlan).Definition
Assert-NoMatch -Actual $srcPure -Pattern 'Invoke-CAStep|New-SmbShare|icacls|New-ADGroup|Set-Acl' -Because "Get-CACrlSharePlan is PURE"

# ---------------------------------------------------------------------------
# 4. Dashboard wiring
# ---------------------------------------------------------------------------
$rawDash = Get-Content $Dashboard -Raw
Assert-True -Condition (Test-Path "$PKIModuleRoot\Private\CACrlShare.ps1") -Because "NSP.PKI: the module loader dot-sources every Private\*.ps1 (was: the dashboard dot-sources CACrlShare)"
Assert-Match -Actual $rawDash -Pattern "'\^7\`$'\s*\{[\s\S]{0,80}?Invoke-CAMenuCrlShare" -Because "menu 7 (2026-09-10 renumber - was menu 6) dispatches to Invoke-CAMenuCrlShare"

Write-TestSummary -Suite "CA Manager - menu 7 (CRL distribution share)"
