<#
.SYNOPSIS
    Steps through the PFX files produced by CA-Manager menu 8 (New-CATestCertSuite) on a test box:
    for each cert it imports it, guides a FortiClient connect, records whether the tunnel came up and
    what the account could reach, then does an offline CRL/OCSP verification with certutil and writes
    a results report.

.DESCRIPTION
    Per PFX (stem "<user>_<label>_<valid|revoked>"):
      1. Import-PfxCertificate into Cert:\CurrentUser\My (or -CertStore LocalMachine).
      2. Show the cert (subject, OU path, validity, serial) and the EXPECTED outcome
         (valid -> should connect + full rights ; revoked -> FortiGate should reject at IKE phase 1).
      3. You connect FortiClient with this cert and clear MFA. The harness auto-detects the tunnel
         via a marker-host ping (there is no reliable scripted connect for FortiClient IPsec, and
         MFA is interactive - so the connect click stays manual; everything else is automated).
      4. If up: run the reachability matrix for this cert's group (Universal + group Endpoints +
         group CrossCheckBlocked) from the -TargetsPath file. Compare Verdict vs Expect.
      5. You disconnect; the harness confirms the tunnel dropped.
      6. Export the public cert and run  certutil -f -urlfetch -verify  -> Good / Revoked / Undetermined.
      7. Remove the imported cert (unless -KeepCerts).
    Then: a console table + <Company>_CertEval_<ts>.txt / .json always, plus an .xlsx with
    green/red conditional formatting when the ImportExcel module is present.

.PARAMETER PfxDir
    Folder holding the *.pfx files (CA-Manager menu 8 default was C:\Admin\TestPFX).

.PARAMETER TargetsPath
    <Company>_EvalTargets.psd1 from Build-VPNCertEvalTargets.ps1. If omitted, the reachability step
    is skipped (connect + certutil only).

.PARAMETER SummaryPath
    Optional <Company>_CertTestSuite_<ts>.txt - cross-references serial / thumbprint / revoked flag.

.PARAMETER MarkerHost
    An address reachable ONLY over the tunnel, used to detect up/down. Defaults to the first
    Universal endpoint in the targets file.

.EXAMPLE
    .\Invoke-VPNCertEval.ps1 -PfxDir C:\Admin\TestPFX -TargetsPath C:\Admin\TestPFX\EXAMPLE_EvalTargets.psd1 `
        -SummaryPath C:\Admin\TestPFX\EXAMPLE_CertTestSuite_20260909_101500.txt
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$PfxDir,
    [string]$TargetsPath,
    [string]$SummaryPath,
    [string]$OutDir,
    [string]$PfxPassword,
    [ValidateSet('CurrentUser', 'LocalMachine')][string]$CertStore = 'CurrentUser',
    [string]$MarkerHost,
    [int]$ConnectWaitSec = 240,
    [int]$TcpTimeoutMs = 500,
    [int]$PingTimeoutMs = 500,
    [switch]$SkipConnect,
    [switch]$AttemptCliConnect,
    [switch]$KeepCerts
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'VPNCertEval.Common.ps1')

if (-not (Test-Path $PfxDir)) { throw "PfxDir not found: $PfxDir" }
if (-not $OutDir) { $OutDir = Join-Path $PfxDir 'EvalResults' }
if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir -Force | Out-Null }

$stamp = Get-Date -Format 'yyyyMMdd_HHmmss'

# --- password ---------------------------------------------------------------------------------
$securePw = $null
if ($PfxPassword) {
    $securePw = ConvertTo-SecureString -String $PfxPassword -AsPlainText -Force
} else {
    $securePw = Read-Host "Shared PFX password for the test suite" -AsSecureString
}

# --- inventory -------------------------------------------------------------------------------
$inv = @(Get-EvalPfxInventory -PfxDir $PfxDir -SummaryPath $SummaryPath)
if ($inv.Count -eq 0) { throw "No PFX files with a '<user>_<label>_<valid|revoked>' name found in $PfxDir" }

# --- targets --------------------------------------------------------------------------------
$targets = $null
if ($TargetsPath) {
    $targets = Read-EvalTargets -Path $TargetsPath
    if (-not $MarkerHost -and $targets.Universal -and @($targets.Universal).Count -gt 0) {
        $MarkerHost = @($targets.Universal)[0].Host
    }
}
$company = if ($targets -and $targets.Company) { "$($targets.Company)" } else { 'VPN' }

Write-Host ""
Write-Host "==== VPN cert evaluation : $($inv.Count) PFX file(s) ====" -ForegroundColor Cyan
Write-Host ("  PFX dir     : {0}" -f $PfxDir)
Write-Host ("  Targets     : {0}" -f $(if ($TargetsPath) { $TargetsPath } else { '(none - reachability skipped)' }))
Write-Host ("  Marker host : {0}" -f $(if ($MarkerHost) { $MarkerHost } else { '(none - adapter heuristic only)' }))
Write-Host ("  Cert store  : Cert:\{0}\My" -f $CertStore)
Write-Host ("  Out dir     : {0}" -f $OutDir)
Write-Host ""

if ($MarkerHost) {
    $base = Get-EvalTunnelState -MarkerHost $MarkerHost -PingTimeoutMs $PingTimeoutMs
    if ($base.Up) {
        Write-Host "WARNING: marker host is reachable right now - a tunnel appears to already be UP." -ForegroundColor Yellow
        Write-Host "         Disconnect any VPN before starting so per-cert results aren't contaminated." -ForegroundColor Yellow
        Read-Host "Press Enter once disconnected (or Ctrl+C to abort)" | Out-Null
    }
}

function Read-KeyChoice {
    param([string]$Prompt, [string[]]$Valid)
    while ($true) {
        $r = (Read-Host $Prompt).Trim()
        if ([string]::IsNullOrEmpty($r) -and $Valid -contains '') { return '' }
        foreach ($v in $Valid) { if ($v -and $r -match "^[$v]") { return $r.Substring(0, 1).ToUpperInvariant() } }
        Write-Host "  (expected one of: $($Valid -join ', '))" -ForegroundColor DarkGray
    }
}

$results = New-Object System.Collections.Generic.List[object]
$reachRows = New-Object System.Collections.Generic.List[object]

foreach ($item in $inv) {
    Write-Host ""
    Write-Host ("------------------------------------------------------------" ) -ForegroundColor DarkCyan
    Write-Host ("  {0}   [{1} / {2}]" -f $item.FileName, $item.Label, $item.Kind) -ForegroundColor Cyan
    Write-Host ("------------------------------------------------------------" ) -ForegroundColor DarkCyan

    $row = [ordered]@{
        FileName       = $item.FileName
        Label          = $item.Label
        Kind           = $item.Kind
        ExpectRevoked  = $item.ExpectRevoked
        Subject        = $null
        OUPath         = $null
        Serial         = $null
        Thumbprint     = $null
        NotAfter       = $null
        Connected      = $null
        AssignedIP     = $null
        RightsAllowOK  = $null
        RightsAllowFail= $null
        RightsBlockOK  = $null
        RightsLeak     = $null
        RightsMatch    = $null
        RevocationVerdict = $null
        CrlChecked     = $null
        OcspChecked    = $null
        Outcome        = $null
        Notes          = $null
    }

    # 1. import -------------------------------------------------------------------------------
    $imp = $null
    try {
        $imp = Import-PfxCertificate -FilePath $item.PfxPath -CertStoreLocation ("Cert:\{0}\My" -f $CertStore) -Password $securePw -Exportable -ErrorAction Stop
    } catch {
        $row.Outcome = 'ERROR'
        $row.Notes = "import failed: $($_.Exception.Message)"
        Write-Host "  import FAILED: $($_.Exception.Message)" -ForegroundColor Red
        $results.Add([pscustomobject]$row)
        continue
    }
    $cert = Get-Item ("Cert:\{0}\My\{1}" -f $CertStore, $imp.Thumbprint)
    $row.Subject    = $cert.Subject
    $row.OUPath     = (Get-CertSubjectOU -Subject $cert.Subject) -join ' / '
    $row.Serial     = $cert.SerialNumber
    $row.Thumbprint = $cert.Thumbprint
    $row.NotAfter   = $cert.NotAfter.ToString('yyyy-MM-dd')

    Write-Host ("  Subject : {0}" -f $cert.Subject) -ForegroundColor Gray
    Write-Host ("  OU path : {0}" -f $(if ($row.OUPath) { $row.OUPath } else { '(none)' })) -ForegroundColor Gray
    Write-Host ("  Serial  : {0}   NotAfter : {1}" -f $cert.SerialNumber, $row.NotAfter) -ForegroundColor Gray
    if ($item.ExpectRevoked) {
        Write-Host "  EXPECTED: this cert is REVOKED - FortiGate phase 1 should FAIL (certificate revoked)." -ForegroundColor Yellow
    } else {
        Write-Host "  EXPECTED: this cert is VALID - tunnel should come up and reachability should match the group scope." -ForegroundColor Green
    }

    # 2. connect ---------------------------------------------------------------------------
    $grp = $null
    if ($targets) {
        $grp = @($targets.Groups) | Where-Object { $_.Label -ieq $item.Label } | Select-Object -First 1
        if (-not $grp) { $grp = @($targets.Groups) | Where-Object { "$($_.Label)".ToLower().Contains($item.Label.ToLower()) -or $item.Label.ToLower().Contains("$($_.Label)".ToLower()) } | Select-Object -First 1 }
        if (-not $grp) { Write-Host ("  NOTE: no group in the targets file matches label '{0}' - reachability will use Universal only." -f $item.Label) -ForegroundColor DarkYellow }
    }

    if ($SkipConnect) {
        Write-Host "  -SkipConnect: not testing the tunnel for this cert." -ForegroundColor DarkGray
        $row.Connected = $null
    } else {
        if ($AttemptCliConnect) {
            $fc = @("${env:ProgramFiles}\Fortinet\FortiClient\FortiClient.exe", "${env:ProgramFiles(x86)}\Fortinet\FortiClient\FortiClient.exe") | Where-Object { Test-Path $_ } | Select-Object -First 1
            if ($fc) {
                Write-Host "  (best-effort) launching FortiClient - complete the connect + MFA in its window..." -ForegroundColor DarkGray
                try { Start-Process -FilePath $fc | Out-Null } catch { }
            }
        }
        Write-Host ""
        Write-Host "  >> Connect FortiClient now using this certificate, and approve MFA if prompted." -ForegroundColor White
        $choice = Read-KeyChoice -Prompt "     Press ENTER when the tunnel is UP  |  F = it failed / was rejected  |  S = skip" -Valid @('', 'F', 'S')
        if ($choice -eq 'F') {
            $row.Connected = $false
            $row.Notes = 'tester reported connect failure / IKE rejection'
            Write-Host "     recorded: NOT connected (reported failure)" -ForegroundColor Yellow
        } elseif ($choice -eq 'S') {
            $row.Connected = $null
            $row.Notes = 'connect step skipped by tester'
            Write-Host "     recorded: skipped" -ForegroundColor DarkGray
        } else {
            $st = Wait-EvalTunnel -State up -MarkerHost $MarkerHost -TimeoutSec 25 -PollSec 3
            $row.Connected = [bool]$st.Up
            $row.AssignedIP = $st.AssignedIP
            if ($st.Up) {
                Write-Host ("     tunnel UP  (adapter {0}, IP {1})" -f $st.AdapterName, $st.AssignedIP) -ForegroundColor Green
            } else {
                Write-Host "     could not confirm the tunnel is up (marker host not answering)." -ForegroundColor Yellow
                $row.Notes = 'tester said UP but marker host did not respond'
            }
        }
    }

    # 3. reachability --------------------------------------------------------------------
    if ($row.Connected -eq $true -and $targets) {
        $eps = New-Object System.Collections.Generic.List[object]
        foreach ($e in @($targets.Universal)) { $eps.Add($e) }
        if ($grp) {
            foreach ($e in @($grp.Endpoints)) { $eps.Add($e) }
            foreach ($e in @($grp.CrossCheckBlocked)) { $eps.Add($e) }
        }
        $probeEps = @($eps | Where-Object { $_.Host -and $_.Host -notmatch 'RESOLVE-ME|CHANGE-ME' })
        Write-Host ("  probing {0} endpoint(s)..." -f $probeEps.Count) -ForegroundColor Gray
        $matrix = Invoke-EvalReachabilityMatrix -Endpoints $probeEps -ServiceChecks $targets.ServiceChecks -TimeoutMs $TcpTimeoutMs -PingTimeoutMs $PingTimeoutMs

        $allowOK = 0; $allowFail = 0; $blockOK = 0; $leak = 0
        foreach ($m in $matrix) {
            $reachRows.Add([pscustomobject]@{
                Cert = $item.FileName; Label = $item.Label; Kind = $item.Kind
                Endpoint = $m.Host; Name = $m.Name; Expect = $m.Expect; Verdict = $m.Verdict
                Match = $m.Match; Services = (($m.PerService.GetEnumerator() | ForEach-Object { "{0}={1}" -f $_.Key, $_.Value }) -join ' ')
            })
            if ($m.Expect -ieq 'Allow') { if ($m.Verdict -eq 'Allow') { $allowOK++ } else { $allowFail++ } }
            else { if ($m.Verdict -eq 'Block') { $blockOK++ } else { $leak++ } }
        }
        $row.RightsAllowOK = $allowOK; $row.RightsAllowFail = $allowFail
        $row.RightsBlockOK = $blockOK; $row.RightsLeak = $leak
        $row.RightsMatch = ($allowFail -eq 0 -and $leak -eq 0)
        $col = if ($row.RightsMatch) { 'Green' } else { 'Yellow' }
        Write-Host ("  rights: Allow {0}/{1} reachable, Block {2}/{3} correctly denied{4}" -f `
            $allowOK, ($allowOK + $allowFail), $blockOK, ($blockOK + $leak), $(if ($leak) { "  <-- $leak LEAK(S)" } else { '' })) -ForegroundColor $col
    }

    # 4. disconnect --------------------------------------------------------------------
    if (-not $SkipConnect -and $row.Connected -eq $true) {
        Write-Host ""
        Read-Host "  >> Disconnect FortiClient now, then press ENTER" | Out-Null
        $dn = Wait-EvalTunnel -State down -MarkerHost $MarkerHost -TimeoutSec 30 -PollSec 3
        if ($dn.Up) { Write-Host "     marker host still answering - tunnel may not be fully down." -ForegroundColor Yellow }
        else { Write-Host "     tunnel down." -ForegroundColor Gray }
    }

    # 5. certutil verify --------------------------------------------------------------
    $stem = "{0}_{1}_{2}" -f $item.User, $item.Label, $item.Kind
    $cerPath = Join-Path $OutDir "$stem.cer"
    try {
        Export-Certificate -Cert $cert -FilePath $cerPath -Type CERT -Force | Out-Null
        $vtext = (& certutil.exe -f -urlfetch -verify $cerPath 2>&1 | Out-String)
        Set-Content -Path (Join-Path $OutDir "${stem}_certutil.txt") -Value $vtext -Encoding UTF8
        $verdict = Get-CertUtilRevocationVerdict -Text $vtext
        $row.RevocationVerdict = $verdict.Verdict
        $row.CrlChecked = $verdict.CrlChecked
        $row.OcspChecked = $verdict.OcspChecked
        $vc = switch ($verdict.Verdict) { 'Good' { 'Green' } 'Revoked' { 'Yellow' } default { 'DarkYellow' } }
        Write-Host ("  certutil: {0}   (CRL checked={1}, OCSP checked={2})" -f $verdict.Verdict, $verdict.CrlChecked, $verdict.OcspChecked) -ForegroundColor $vc
    } catch {
        $row.RevocationVerdict = 'ERROR'
        Write-Host "  certutil verify FAILED: $($_.Exception.Message)" -ForegroundColor Red
    }

    # 6. cleanup --------------------------------------------------------------------
    if (-not $KeepCerts) {
        try { Remove-Item ("Cert:\{0}\My\{1}" -f $CertStore, $imp.Thumbprint) -Force -ErrorAction Stop; Write-Host "  removed cert from Cert:\$CertStore\My" -ForegroundColor DarkGray }
        catch { Write-Host "  could not remove cert (elevation? LocalMachine store): $($_.Exception.Message)" -ForegroundColor DarkYellow }
    }

    # 7. outcome --------------------------------------------------------------------
    if ($item.ExpectRevoked) {
        if ($row.Connected -eq $false -and $row.RevocationVerdict -eq 'Revoked') { $row.Outcome = 'PASS' }
        elseif ($row.Connected -eq $true) { $row.Outcome = 'FAIL'; $row.Notes = (@($row.Notes, 'revoked cert CONNECTED - FortiGate not enforcing revocation (CRL/OCSP cache?)') | Where-Object { $_ }) -join '; ' }
        elseif ($row.RevocationVerdict -ne 'Revoked') { $row.Outcome = 'WARN'; $row.Notes = (@($row.Notes, "certutil says '$($row.RevocationVerdict)' not 'Revoked'") | Where-Object { $_ }) -join '; ' }
        else { $row.Outcome = 'WARN' }
    } else {
        if ($row.Connected -eq $true -and $row.RevocationVerdict -eq 'Good' -and $row.RightsMatch -ne $false) { $row.Outcome = 'PASS' }
        elseif ($row.Connected -eq $false) { $row.Outcome = 'FAIL'; $row.Notes = (@($row.Notes, 'valid cert did NOT connect') | Where-Object { $_ }) -join '; ' }
        elseif ($row.RightsMatch -eq $false) { $row.Outcome = 'WARN'; $row.Notes = (@($row.Notes, 'reachability did not match expected scope') | Where-Object { $_ }) -join '; ' }
        elseif ($row.RevocationVerdict -ne 'Good') { $row.Outcome = 'WARN'; $row.Notes = (@($row.Notes, "certutil verdict '$($row.RevocationVerdict)'") | Where-Object { $_ }) -join '; ' }
        else { $row.Outcome = 'WARN' }
    }
    $oc = switch ($row.Outcome) { 'PASS' { 'Green' } 'FAIL' { 'Red' } default { 'Yellow' } }
    Write-Host ("  OUTCOME: {0}" -f $row.Outcome) -ForegroundColor $oc

    $results.Add([pscustomobject]$row)
}

# --- reports -----------------------------------------------------------------------------------
$txtPath  = Join-Path $OutDir ("{0}_CertEval_{1}.txt"  -f ($company -replace '[^A-Za-z0-9]', ''), $stamp)
$jsonPath = Join-Path $OutDir ("{0}_CertEval_{1}.json" -f ($company -replace '[^A-Za-z0-9]', ''), $stamp)

$lines = New-Object System.Collections.Generic.List[string]
$lines.Add("VPN certificate evaluation - $company")
$lines.Add("Generated : $(Get-Date)")
$lines.Add("PFX dir   : $PfxDir")
$lines.Add("Targets   : $(if ($TargetsPath) { $TargetsPath } else { '(none)' })")
$lines.Add("")
$lines.Add(("{0,-34} {1,-12} {2,-8} {3,-10} {4,-14} {5,-8} {6}" -f 'PFX', 'Label', 'Kind', 'Connected', 'Revocation', 'Rights', 'Outcome'))
$lines.Add(('-' * 110))
foreach ($r in $results) {
    $rights = if ($null -eq $r.RightsMatch) { '-' } elseif ($r.RightsMatch) { 'match' } else { "LEAK/$($r.RightsLeak)" }
    $lines.Add(("{0,-34} {1,-12} {2,-8} {3,-10} {4,-14} {5,-8} {6}" -f `
        $r.FileName, $r.Label, $r.Kind, "$($r.Connected)", "$($r.RevocationVerdict)", $rights, $r.Outcome))
    if ($r.Notes) { $lines.Add(("{0,-34} -> {1}" -f '', $r.Notes)) }
}
$lines.Add("")
$lines.Add("Per-endpoint reachability")
$lines.Add(('-' * 110))
$lines.Add(("{0,-24} {1,-10} {2,-8} {3,-8} {4,-6} {5}" -f 'Cert', 'Label', 'Expect', 'Verdict', 'OK', 'Endpoint'))
foreach ($m in $reachRows) {
    $lines.Add(("{0,-24} {1,-10} {2,-8} {3,-8} {4,-6} {5}  [{6}]" -f `
        [IO.Path]::GetFileNameWithoutExtension($m.Cert), $m.Label, $m.Expect, $m.Verdict, "$($m.Match)", $m.Endpoint, $m.Services))
}
$pass = @($results | Where-Object { $_.Outcome -eq 'PASS' }).Count
$fail = @($results | Where-Object { $_.Outcome -eq 'FAIL' }).Count
$warn = @($results | Where-Object { $_.Outcome -notin @('PASS', 'FAIL') }).Count
$lines.Add("")
$lines.Add("TOTALS:  $pass PASS   $fail FAIL   $warn WARN/other   ($($results.Count) certs)")
Set-Content -Path $txtPath -Value $lines -Encoding UTF8

[pscustomobject]@{
    Company = $company; GeneratedUtc = (Get-Date).ToUniversalTime().ToString('s') + 'Z'
    Summary = $results; Reachability = $reachRows
} | ConvertTo-Json -Depth 8 | Set-Content -Path $jsonPath -Encoding UTF8

# --- optional Excel --------------------------------------------------------------------------
$xlsxPath = Join-Path $OutDir ("{0}_CertEval_{1}.xlsx" -f ($company -replace '[^A-Za-z0-9]', ''), $stamp)
if (Get-Module -ListAvailable -Name ImportExcel) {
    try {
        Import-Module ImportExcel -ErrorAction Stop
        $results  | Select-Object FileName, Label, Kind, ExpectRevoked, Connected, AssignedIP, RightsAllowOK, RightsAllowFail, RightsBlockOK, RightsLeak, RightsMatch, RevocationVerdict, CrlChecked, OcspChecked, Outcome, Notes |
            Export-Excel -Path $xlsxPath -WorksheetName 'Summary' -AutoSize -AutoFilter -FreezeTopRow -BoldTopRow -TableStyle 'Medium6'
        if ($reachRows.Count) {
            $reachRows | Export-Excel -Path $xlsxPath -WorksheetName 'Reachability' -AutoSize -AutoFilter -FreezeTopRow -BoldTopRow -TableStyle 'Medium2'
        }
        $pkg = Open-ExcelPackage -Path $xlsxPath
        foreach ($wsName in @('Summary', 'Reachability')) {
            $ws = $pkg.Workbook.Worksheets[$wsName]
            if (-not $ws -or -not $ws.Dimension) { continue }
            $rng = [OfficeOpenXml.ExcelCellBase]::GetAddress(2, 1, $ws.Dimension.End.Row, $ws.Dimension.End.Column)
            foreach ($pair in @(@('"PASS"', 198, 239, 206, 0, 97, 0), @('"True"', 198, 239, 206, 0, 97, 0), @('"Allow"', 198, 239, 206, 0, 97, 0),
                                 @('"FAIL"', 255, 199, 206, 156, 0, 6), @('"False"', 255, 199, 206, 156, 0, 6))) {
                $cf = $ws.ConditionalFormatting.AddEqual($rng)
                $cf.Formula = $pair[0]
                $cf.Style.Fill.PatternType = [OfficeOpenXml.Style.ExcelFillStyle]::Solid
                $cf.Style.Fill.BackgroundColor.SetColor([System.Drawing.Color]::FromArgb($pair[1], $pair[2], $pair[3]))
                $cf.Style.Font.Color.SetColor([System.Drawing.Color]::FromArgb($pair[4], $pair[5], $pair[6]))
            }
        }
        Close-ExcelPackage $pkg
        Write-Host ""
        Write-Host "Excel : $xlsxPath" -ForegroundColor Green
    } catch {
        Write-Host "Excel export skipped: $($_.Exception.Message)" -ForegroundColor DarkYellow
    }
} else {
    Write-Host ""
    Write-Host "(ImportExcel module not installed - .xlsx skipped; .txt/.json written)" -ForegroundColor DarkGray
}

Write-Host ""
Write-Host "Report : $txtPath" -ForegroundColor Green
Write-Host "JSON   : $jsonPath" -ForegroundColor Green
$totColor = if ($fail -eq 0 -and $warn -eq 0) { 'Green' } elseif ($fail -eq 0) { 'Yellow' } else { 'Red' }
Write-Host ("TOTALS : {0} PASS   {1} FAIL   {2} WARN/other   ({3} certs)" -f $pass, $fail, $warn, $results.Count) -ForegroundColor $totColor
Write-Host ""
$results | Format-Table FileName, Label, Kind, Connected, RevocationVerdict, RightsMatch, Outcome -AutoSize
